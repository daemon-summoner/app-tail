// SPDX-License-Identifier: MIT

package fabric

// The four costs the fabric pays per packet, per flow and per reader: the inbound
// injection, the outbound write to the interface, the address lookup every flow makes
// once, and the counter update every chunk of every flow makes while the dashboard reads
// the same lock.

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// benchPayload is a typical carried packet rather than a maximum-sized one, so the copy
// costs below are the ones a real transfer pays.
const benchPayload = 1200

// BenchmarkStackInject is the inbound half of the packet path: what one packet costs
// between coming off the interface and being demultiplexed by the stack. The read syscall
// in front of it is the operating system's and is deliberately not in the measurement.
func BenchmarkStackInject(b *testing.B) {
	dev := newIdleDevice()
	s := benchStack(b, dev)
	packet := udpPacket(netip.MustParseAddrPort("100.64.0.9:40000"), netip.MustParseAddrPort("10.1.2.3:9"))

	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		s.inject(packet)
	}
}

// BenchmarkStackPumpOut is the outbound half: what one packet costs between the stack
// producing it and the interface accepting it. The per-packet [][]byte the write takes is
// inside this measurement; the benchmark's own enqueue is not free either, so read the
// allocations as a total to compare against rather than as the pump's alone.
func BenchmarkStackPumpOut(b *testing.B) {
	dev := newIdleDevice()
	s := benchStack(b, dev)

	held := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(make([]byte, benchPayload)),
	})
	defer held.DecRef()
	var batch stack.PacketBufferList
	batch.PushBack(held)

	b.SetBytes(benchPayload)
	b.ReportAllocs()
	sent := 0
	for b.Loop() {
		// The queue between the stack and the pump is finite, so a full one means the pump
		// is behind rather than that anything failed: yield and offer it again.
		for {
			n, err := s.ep.WritePackets(batch)
			if err != nil {
				b.Fatalf("hand a packet to the interface: %v", err)
			}
			if n == 1 {
				break
			}
			runtime.Gosched()
		}
		sent++
	}
	b.StopTimer()
	dev.awaitWrites(b, sent)
}

// BenchmarkTableLookup is the one decision every flow makes, at the table sizes a machine
// actually reaches. It scans linearly, so the shape of the curve across the three sizes is
// the point, not the absolute figure.
func BenchmarkTableLookup(b *testing.B) {
	for _, entries := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("%d-networks", entries), func(b *testing.B) {
			table := benchTable(b, entries)
			// The last network added, so the linear scan is walked in full: the worst case
			// is the honest one to optimise against.
			addr := netip.AddrFrom4([4]byte{10, byte(entries - 1), 0, 7})

			b.ReportAllocs()
			for b.Loop() {
				if _, ok := table.Lookup(addr); !ok {
					b.Fatal("the address belongs to no connection")
				}
			}
		})
	}
}

// BenchmarkFabricCount is the counter update netpipe's report callback makes for every
// chunk of every flow in both directions, run in parallel because contention is the whole
// question: every flow on the machine reports through this at once, and what it touches is
// also what a Status poll reads.
//
// The counters are found once, outside the timer, because that is where a flow finds them:
// begin runs when a flow opens and the reporting it returns is what runs per chunk.
func BenchmarkFabricCount(b *testing.B) {
	f := benchFabric(b)
	report := f.begin("tn_bench", 443, "tcp").up

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			report(benchPayload)
		}
	})
}

// BenchmarkFabricCountUnderStatus is the same update while a reader polls Status at the
// dashboard's own cadence, which is what the app does all day.
func BenchmarkFabricCountUnderStatus(b *testing.B) {
	f := benchFabric(b)
	report := f.begin("tn_bench", 443, "tcp").up

	stop := make(chan struct{})
	var polling sync.WaitGroup
	polling.Add(1)
	go func() {
		defer polling.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			f.Status("bench")
		}
	}()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			report(benchPayload)
		}
	})
	b.StopTimer()
	close(stop)
	polling.Wait()
}

// benchStack builds a stack over an interface that never hands anything over, for the
// benchmarks that drive the packet path themselves.
func benchStack(b *testing.B, dev tun.Device) *netStack {
	b.Helper()
	s, err := newStack(dev, testMTU, slog.New(slog.DiscardHandler),
		func(*tcp.ForwarderRequest) {}, func(*udp.ForwarderRequest) bool { return true })
	if err != nil {
		b.Fatalf("build the stack: %v", err)
	}
	b.Cleanup(func() {
		s.stop()
		dev.Close()
		s.wait()
		s.release()
	})
	return s
}

// benchFabric is a fabric over an interface that carries nothing, for the benchmarks about
// its bookkeeping rather than about its packets.
func benchFabric(b *testing.B) *Fabric {
	b.Helper()
	f, err := New(Options{
		Device:   newIdleDevice(),
		Carriers: carrierSet{},
		MTU:      testMTU,
		Table:    benchTable(b, 10),
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		b.Fatalf("build the fabric: %v", err)
	}
	b.Cleanup(func() { f.Close() })
	return f
}

// benchTable is a table of n distinct networks, one per connection.
func benchTable(b *testing.B, n int) *Table {
	b.Helper()
	mappings := make([]Mapping, 0, n)
	for i := range n {
		mappings = append(mappings, Mapping{
			TunnelID: fmt.Sprintf("tn_%d", i),
			Prefix:   netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16),
		})
	}
	table, err := NewTable(mappings)
	if err != nil {
		b.Fatalf("build the table: %v", err)
	}
	return table
}

// idleDevice is an interface that hands over nothing and accepts everything, so a
// benchmark measures the stack rather than whatever is on the other side of it.
type idleDevice struct {
	events chan tun.Event

	done      chan struct{}
	closeOnce sync.Once

	written atomic.Int64
}

var _ tun.Device = (*idleDevice)(nil)

func newIdleDevice() *idleDevice {
	return &idleDevice{events: make(chan tun.Event, 1), done: make(chan struct{})}
}

func (d *idleDevice) Read([][]byte, []int, int) (int, error) {
	<-d.done
	return 0, os.ErrClosed
}

func (d *idleDevice) Write(bufs [][]byte, _ int) (int, error) {
	d.written.Add(int64(len(bufs)))
	return len(bufs), nil
}

func (d *idleDevice) MTU() (int, error)        { return testMTU, nil }
func (d *idleDevice) Name() (string, error)    { return "bench", nil }
func (d *idleDevice) File() *os.File           { return nil }
func (d *idleDevice) Events() <-chan tun.Event { return d.events }
func (d *idleDevice) BatchSize() int           { return 1 }
func (d *idleDevice) Close() error {
	d.closeOnce.Do(func() { close(d.done) })
	return nil
}

// awaitWrites waits for the pump to drain what the benchmark queued, so a run that only
// looked fast because the packets were still in the queue fails instead.
func (d *idleDevice) awaitWrites(b *testing.B, want int) {
	b.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for d.written.Load() < int64(want) {
		if time.Now().After(deadline) {
			b.Fatalf("the interface took %d of %d packets", d.written.Load(), want)
		}
		runtime.Gosched()
	}
}

// udpPacket is one well-formed IPv4 datagram, which is what the inbound path expects to be
// given. The UDP checksum is left at zero, which IPv4 allows and means it was not computed.
func udpPacket(from, to netip.AddrPort) []byte {
	total := header.IPv4MinimumSize + header.UDPMinimumSize + benchPayload
	buf := make([]byte, total)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(from.Addr().As4()),
		DstAddr:     tcpip.AddrFrom4(to.Addr().As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	datagram := header.UDP(buf[header.IPv4MinimumSize:])
	datagram.Encode(&header.UDPFields{
		SrcPort: from.Port(),
		DstPort: to.Port(),
		Length:  uint16(header.UDPMinimumSize + benchPayload),
	})
	return buf
}
