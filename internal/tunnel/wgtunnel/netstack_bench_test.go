// SPDX-License-Identifier: MIT

package wgtunnel

// The cost of moving one packet from this connection's stack to the device that encrypts it.
//
// This is the hot path of every byte a WireGuard connection sends, so what it costs with
// nothing queued is the number to hold steady: a packet is written into the stack's endpoint
// and read straight back out, the way it happens whenever the device keeps up.

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// benchPayload is a typical carried packet rather than a maximum-sized one.
const benchPayload = 1200

func BenchmarkOutboundQueue(b *testing.B) {
	b.Run("1flow", func(b *testing.B) { benchOutbound(b, 1) })
	b.Run("64flows", func(b *testing.B) { benchOutbound(b, 64) })
}

// benchOutbound writes one packet and reads it back per iteration, rotating the source port
// across flows so a per-flow structure sees as many flows as asked.
func benchOutbound(b *testing.B, flows int) {
	ns, err := newNetStack([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, 1420)
	if err != nil {
		b.Fatal(err)
	}
	defer ns.Close()

	packets := make([][]byte, flows)
	for i := range packets {
		packets[i] = benchUDPPacket(
			netip.AddrPortFrom(netip.MustParseAddr("10.9.0.2"), uint16(40000+i)),
			netip.AddrPortFrom(netip.MustParseAddr("10.9.0.1"), 53),
		)
	}

	bufs := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		var list stack.PacketBufferList
		list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packets[i%flows]),
		}))
		if n, err := ns.ep.WritePackets(list); err != nil || n != 1 {
			b.Fatalf("the endpoint took %d packets: %v", n, err)
		}
		list.DecRef()
		if _, err := ns.Read(bufs, sizes, 0); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// benchUDPPacket is one well-formed IPv4 datagram. The UDP checksum is left at zero, which
// IPv4 allows and means it was not computed.
func benchUDPPacket(from, to netip.AddrPort) []byte {
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
