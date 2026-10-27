// SPDX-License-Identifier: MIT

package fqcodel

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	src4 = netip.MustParseAddr("10.9.0.2")
	dst4 = netip.MustParseAddr("10.9.0.1")
	src6 = netip.MustParseAddr("fd00::2")
	dst6 = netip.MustParseAddr("fd00::1")
)

// v4 builds an IPv4 packet with the given protocol and transport bytes; flags and offset
// set the fragment fields.
func v4(proto uint8, flags uint8, offset uint16, transport []byte) []byte {
	buf := make([]byte, header.IPv4MinimumSize+len(transport))
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength:    uint16(len(buf)),
		TTL:            64,
		Protocol:       proto,
		Flags:          flags,
		FragmentOffset: offset,
		SrcAddr:        tcpip.AddrFrom4(src4.As4()),
		DstAddr:        tcpip.AddrFrom4(dst4.As4()),
	})
	copy(buf[header.IPv4MinimumSize:], transport)
	return buf
}

// v6 builds an IPv6 packet whose next header is the given number, followed by the bytes.
func v6(next uint8, rest []byte) []byte {
	buf := make([]byte, header.IPv6MinimumSize+len(rest))
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(rest)),
		TransportProtocol: tcpip.TransportProtocolNumber(next),
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(src6.As16()),
		DstAddr:           tcpip.AddrFrom16(dst6.As16()),
	})
	copy(buf[header.IPv6MinimumSize:], rest)
	return buf
}

func udpHeader(sport, dport uint16) []byte {
	buf := make([]byte, header.UDPMinimumSize)
	header.UDP(buf).Encode(&header.UDPFields{SrcPort: sport, DstPort: dport, Length: header.UDPMinimumSize})
	return buf
}

func tcpHeader(sport, dport uint16) []byte {
	buf := make([]byte, header.TCPMinimumSize)
	header.TCP(buf).Encode(&header.TCPFields{SrcPort: sport, DstPort: dport, DataOffset: header.TCPMinimumSize})
	return buf
}

func flow4(proto uint8, sport, dport uint16) Flow {
	var f Flow
	f.Proto = proto
	copy(f.Src[:4], src4.AsSlice())
	copy(f.Dst[:4], dst4.AsSlice())
	f.SrcPort, f.DstPort = sport, dport
	return f
}

func flow6(proto uint8, sport, dport uint16) Flow {
	var f Flow
	f.Proto = proto
	copy(f.Src[:], src6.AsSlice())
	copy(f.Dst[:], dst6.AsSlice())
	f.SrcPort, f.DstPort = sport, dport
	return f
}

func TestClassify(t *testing.T) {
	const tcp, udp, icmp4, icmp6, hopByHop = 6, 17, 1, 58, 0
	fragment6 := append([]byte{udp, 0, 0, 8, 0, 0, 0, 1}, udpHeader(1, 2)...)
	hopByHop6 := append([]byte{udp, 0, 0, 0, 0, 0, 0, 0}, udpHeader(1, 2)...)

	cases := []struct {
		name string
		pkt  []byte
		want Flow
	}{
		{"v4 tcp", v4(tcp, 0, 0, tcpHeader(40000, 22)), flow4(tcp, 40000, 22)},
		{"v4 udp", v4(udp, 0, 0, udpHeader(40000, 53)), flow4(udp, 40000, 53)},
		{"v6 tcp", v6(tcp, tcpHeader(40000, 22)), flow6(tcp, 40000, 22)},
		{"v6 udp", v6(udp, udpHeader(40000, 53)), flow6(udp, 40000, 53)},
		{"icmpv4", v4(icmp4, 0, 0, make([]byte, 8)), flow4(icmp4, 0, 0)},
		{"icmpv6", v6(icmp6, make([]byte, 8)), flow6(icmp6, 0, 0)},
		{"v4 first fragment has no ports", v4(udp, header.IPv4FlagMoreFragments, 0, udpHeader(40000, 53)), flow4(udp, 0, 0)},
		{"v4 later fragment has no ports", v4(udp, 0, 185, make([]byte, 8)), flow4(udp, 0, 0)},
		{"v6 fragment header keys by inner protocol without ports", v6(header.IPv6FragmentHeader, fragment6), flow6(udp, 0, 0)},
		{"v6 other extension header keys by the extension", v6(hopByHop, hopByHop6), flow6(hopByHop, 0, 0)},
		{"v4 udp truncated before the ports", v4(udp, 0, 0, udpHeader(40000, 53))[:24], flow4(udp, 0, 0)},
		{"v4 tcp truncated inside the transport header", v4(tcp, 0, 0, tcpHeader(40000, 22))[:30], flow4(tcp, 0, 0)},
		{"v4 truncated inside the header", v4(udp, 0, 0, nil)[:10], Flow{}},
		{"v4 header length beyond the packet", []byte{0x4f, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 0, 2, 10, 9, 0, 1}, Flow{}},
		{"v4 header length under the minimum", []byte{0x44, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 0, 2, 10, 9, 0, 1}, Flow{}},
		{"v6 truncated inside the header", v6(udp, nil)[:28], Flow{}},
		{"v6 fragment header truncated", v6(header.IPv6FragmentHeader, fragment6)[:44], flow6(header.IPv6FragmentHeader, 0, 0)},
		{"empty", nil, Flow{}},
		{"unknown version", []byte{0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Flow{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.pkt); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestTheReverseDirectionIsADifferentFlow(t *testing.T) {
	forward := Classify(v4(6, 0, 0, tcpHeader(40000, 22)))
	back := forward
	back.Src, back.Dst = forward.Dst, forward.Src
	back.SrcPort, back.DstPort = forward.DstPort, forward.SrcPort
	if forward == back {
		t.Fatal("the two directions of a connection classified the same")
	}
	if forward.SrcPort != 40000 || forward.DstPort != 22 {
		t.Fatalf("ports were read wrong: %+v", forward)
	}
}

func TestAllFragmentsOfADatagramShareAFlow(t *testing.T) {
	first := Classify(v4(17, header.IPv4FlagMoreFragments, 0, udpHeader(40000, 53)))
	later := Classify(v4(17, 0, 185, make([]byte, 8)))
	unfragmented := Classify(v4(17, 0, 0, udpHeader(40000, 53)))
	if first != later {
		t.Fatalf("first fragment %+v and later fragment %+v would be queued apart", first, later)
	}
	if first == unfragmented {
		t.Fatal("fragments took the ports of the unfragmented datagram")
	}
}
