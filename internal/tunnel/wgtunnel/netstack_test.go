// SPDX-License-Identifier: MIT

package wgtunnel

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// writeToStack pushes one raw packet into the stack's endpoint, the way the stack itself
// does when a socket on it sends.
func writeToStack(t *testing.T, ns *netStack, pkt []byte) {
	t.Helper()
	var list stack.PacketBufferList
	list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)}))
	defer list.DecRef()
	if n, err := ns.ep.WritePackets(list); err != nil || n != 1 {
		t.Fatalf("the endpoint took %d packets: %v", n, err)
	}
}

func TestTheDeviceReadsWhatTheStackWroteInOrder(t *testing.T) {
	ns, err := newNetStack([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()

	from := netip.AddrPortFrom(netip.MustParseAddr("10.9.0.2"), 40000)
	to := netip.AddrPortFrom(netip.MustParseAddr("10.9.0.1"), 53)
	for i := range 10 {
		pkt := benchUDPPacket(from, to)
		pkt[len(pkt)-1] = byte(i)
		writeToStack(t, ns, pkt)
	}

	bufs := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	for i := range 10 {
		n, err := ns.Read(bufs, sizes, 0)
		if err != nil || n != 1 {
			t.Fatalf("read %d: %d packets, %v", i, n, err)
		}
		if got := bufs[0][sizes[0]-1]; got != byte(i) {
			t.Fatalf("packet %d came out where %d should have", got, i)
		}
	}
	if s := ns.queueStats(); s.Enqueued != 10 || s.Dequeued != 10 || s.Dropped != 0 {
		t.Fatalf("queue stats after ten packets through: %+v", s)
	}
}

func TestClosingTheStackReleasesQueuedPacketsAndUnblocksTheDevice(t *testing.T) {
	ns, err := newNetStack([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	from := netip.AddrPortFrom(netip.MustParseAddr("10.9.0.2"), 40000)
	to := netip.AddrPortFrom(netip.MustParseAddr("10.9.0.1"), 53)
	for range 5 {
		writeToStack(t, ns, benchUDPPacket(from, to))
	}
	if s := ns.queueStats(); s.Backlog != 5 {
		t.Fatalf("backlog %d after five packets and no reads", s.Backlog)
	}

	// The device reads what is there and then sits in Read, the way wireguard-go's reader
	// goroutine does between packets. It has to come back when the stack goes away.
	type outcome struct {
		packets int
		err     error
	}
	read := make(chan outcome, 1)
	go func() {
		bufs, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
		packets := 0
		for {
			if _, err := ns.Read(bufs, sizes, 0); err != nil {
				read <- outcome{packets, err}
				return
			}
			packets++
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for ns.queueStats().Backlog != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the device did not drain the queue")
		}
		time.Sleep(time.Millisecond)
	}
	writeToStack(t, ns, benchUDPPacket(from, to))
	ns.Close()
	select {
	case got := <-read:
		if !errors.Is(got.err, os.ErrClosed) {
			t.Fatalf("Read returned %v after Close, want os.ErrClosed", got.err)
		}
		if got.packets < 5 {
			t.Fatalf("the device read %d packets before Close, five were queued first", got.packets)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after the stack was closed")
	}
	if s := ns.queueStats(); s.Backlog != 0 {
		t.Fatalf("backlog %d after Close", s.Backlog)
	}
	// Closing twice is what the device and the connection holding it both do.
	ns.Close()
}

// The endpoint notifies once per packet it queues, but a notification can find the endpoint
// already drained: Close empties it under the stack's goroutine while a notification is in
// flight. Such a notification must do nothing.
func TestANotificationWithNothingQueuedIsHarmless(t *testing.T) {
	ns, err := newNetStack([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ns.WriteNotify()
	if s := ns.queueStats(); s.Enqueued != 0 || s.Backlog != 0 {
		t.Fatalf("a notification with nothing queued produced a packet: %+v", s)
	}
}

// The stack can produce a packet after the device stopped reading: the two are torn down
// from different goroutines. Such a packet has nowhere to go and is released, not leaked
// and not left waiting on a reader that is gone.
func TestAPacketProducedAfterTheQueueClosedIsReleased(t *testing.T) {
	ns, err := newNetStack([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ns.outbound.Close()

	from := netip.AddrPortFrom(netip.MustParseAddr("10.9.0.2"), 40000)
	to := netip.AddrPortFrom(netip.MustParseAddr("10.9.0.1"), 53)
	wrote := make(chan error, 1)
	go func() {
		var list stack.PacketBufferList
		list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(benchUDPPacket(from, to))}))
		defer list.DecRef()
		_, err := ns.ep.WritePackets(list)
		if err != nil {
			wrote <- errors.New(err.String())
			return
		}
		wrote <- nil
	}()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stack's write blocked on a queue nobody reads")
	}
	if s := ns.queueStats(); s.Enqueued != 0 || s.Backlog != 0 {
		t.Fatalf("a closed queue took a packet: %+v", s)
	}
	if n := ns.ep.NumQueued(); n != 0 {
		t.Fatalf("%d packets left sitting in the endpoint", n)
	}
}
