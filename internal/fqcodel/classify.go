// SPDX-License-Identifier: MIT

package fqcodel

import (
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Flow is what a packet is queued under: the two addresses, the protocol, and the ports
// when the protocol has them. Packets of one flow leave in the order they arrived; packets
// of different flows take turns.
//
// The zero Flow is a packet that could not be read -- too short for its own header, or not
// IP at all. Every such packet shares one queue, which is the right answer for something
// that will be dropped further along anyway.
type Flow struct {
	Proto uint8
	// Src and Dst hold an IPv4 address in the first four bytes and an IPv6 address in all
	// sixteen; the version is implied by Proto's namespace being the same for both, and two
	// packets with the same bytes here are the same flow either way.
	Src, Dst         [16]byte
	SrcPort, DstPort uint16
}

// Classify reads the flow off a raw IPv4 or IPv6 packet. It never panics: anything shorter
// than the header it is reading, or of a version it does not know, is the zero Flow.
//
// Fragments are keyed without ports, first fragment included, even though the first one
// carries them: every fragment of a datagram then shares a flow and keeps its order, where
// keying the first by port and the rest without would let them be reordered around each
// other. Extension headers other than the fragment header end the walk at the header itself,
// so such packets are keyed by (addresses, extension) -- rare through a tunnel, and still
// correctly ordered.
func Classify(pkt []byte) Flow {
	if len(pkt) == 0 {
		return Flow{}
	}
	switch pkt[0] >> 4 {
	case 4:
		return classify4(pkt)
	case 6:
		return classify6(pkt)
	}
	return Flow{}
}

func classify4(pkt []byte) Flow {
	if len(pkt) < header.IPv4MinimumSize {
		return Flow{}
	}
	ip := header.IPv4(pkt)
	hlen := int(ip.HeaderLength())
	if hlen < header.IPv4MinimumSize || len(pkt) < hlen {
		return Flow{}
	}
	var f Flow
	f.Proto = ip.Protocol()
	copy(f.Src[:4], pkt[12:16])
	copy(f.Dst[:4], pkt[16:20])
	if ip.FragmentOffset() != 0 || ip.More() {
		return f
	}
	f.SrcPort, f.DstPort = ports(f.Proto, pkt[hlen:])
	return f
}

func classify6(pkt []byte) Flow {
	if len(pkt) < header.IPv6MinimumSize {
		return Flow{}
	}
	ip := header.IPv6(pkt)
	var f Flow
	f.Proto = ip.NextHeader()
	copy(f.Src[:], pkt[8:24])
	copy(f.Dst[:], pkt[24:40])
	rest := pkt[header.IPv6MinimumSize:]
	if f.Proto == header.IPv6FragmentHeader {
		if len(rest) < header.IPv6FragmentHeaderSize {
			return f
		}
		f.Proto = header.IPv6Fragment(rest).NextHeader()
		return f
	}
	f.SrcPort, f.DstPort = ports(f.Proto, rest)
	return f
}

// ports reads the transport ports when the protocol has them and the header is present.
// TCP and UDP both keep the ports in their first four bytes.
func ports(proto uint8, transport []byte) (src, dst uint16) {
	switch proto {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return 0, 0
		}
		tcp := header.TCP(transport)
		return tcp.SourcePort(), tcp.DestinationPort()
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return 0, 0
		}
		udp := header.UDP(transport)
		return udp.SourcePort(), udp.DestinationPort()
	}
	return 0, 0
}
