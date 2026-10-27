// SPDX-License-Identifier: MIT

package wgtunnel

// One WireGuard connection's own network stack.
//
// A userspace WireGuard device hands over decrypted packets and expects packets back; it
// has no idea what a socket is. This is what turns that into connections: a network stack
// running inside this process, holding the addresses this device has on the network, so a
// dial through the connection becomes a TCP handshake this process performs and the packets
// it produces go out encrypted. Nothing here reaches the machine's own networking -- there
// is no interface, no route and no privilege involved, which is the whole reason this app
// can hold several private networks at once.
//
// wireguard-go ships a package that does this. It does not build against the version of
// gvisor this repository is pinned to (its packet-queue read returns a different type), and
// the pin is not ours to move: it comes from the Tailscale client. So the device is
// assembled here, against the gvisor API that is actually present.
//
// The packets waiting to be encrypted sit in a flow-fair queue rather than a plain FIFO.
// That queue only ever fills when the device is the slow part -- encryption bound by the
// CPU, or a connection carried inside another whose stack every packet must also cross --
// and in a FIFO that means one bulk transfer holds every other flow through the connection
// behind a thousand of its packets. The kernel's own fair queueing cannot help: it sees only
// the encrypted outside, one flow, and the device offers no way to mark the outside per
// packet. So the sorting happens here, while the packets can still be told apart.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"

	"github.com/sellitus/app-tail/internal/fqcodel"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// nicID is the one interface this stack has. There is exactly one per connection, so the
// number is a constant rather than something to keep track of.
const nicID = 1

// queueDepth is how many outbound packets may wait between the stack and the device. It
// bounds the memory one connection can hold when the device is slower than the programs
// using it; past it the queue drops from whichever flow holds the most, which is what a full
// link does anyway, aimed.
const queueDepth = 1024

// netStack is one connection's network stack and the device WireGuard drives it through.
type netStack struct {
	ep    *channel.Endpoint
	stack *stack.Stack
	// events is wireguard-go's device-state channel. It is written once, with EventUp:
	// this device is up from the moment it exists and only ever goes away entirely.
	events chan tun.Event
	// outbound carries packets the stack produced, waiting to be encrypted and sent. It
	// holds as many as the endpoint in front of it, so that the endpoint's own queue is
	// drained on every write and the device parks only when there is truly nothing to send.
	outbound  *fqcodel.Queue[*buffer.View]
	closeOnce sync.Once
	mtu       int
	hasV4     bool
	hasV6     bool
}

var (
	_ tun.Device           = (*netStack)(nil)
	_ channel.Notification = (*netStack)(nil)
)

// newNetStack builds the stack holding these addresses.
func newNetStack(addrs []netip.Addr, mtu int) (*netStack, error) {
	s := &netStack{
		ep: channel.New(queueDepth, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
			// Traffic between two sockets on this stack stays inside it rather than being
			// sent to the network and expected back.
			HandleLocal: true,
		}),
		events: make(chan tun.Event, 1),
		mtu:    mtu,
	}
	outbound, err := fqcodel.New(fqcodel.Options[*buffer.View]{
		Capacity: queueDepth,
		Quantum:  mtu,
		Drop:     func(view *buffer.View) { view.Release() },
	})
	if err != nil {
		return nil, fmt.Errorf("build this connection's outbound queue: %w", err)
	}
	s.outbound = outbound

	// Selective acknowledgement, which is off by default here and on everywhere else. A
	// single lost packet without it stalls the whole window, and every path through a
	// tunnel loses packets.
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("enable TCP selective acknowledgement: %v", err)
	}
	s.ep.AddNotify(s)
	if err := s.stack.CreateNIC(nicID, s.ep); err != nil {
		return nil, fmt.Errorf("create this connection's interface: %v", err)
	}
	for _, addr := range addrs {
		protocol := ipv6.ProtocolNumber
		if addr.Is4() {
			protocol = ipv4.ProtocolNumber
			s.hasV4 = true
		} else {
			s.hasV6 = true
		}
		held := tcpip.ProtocolAddress{
			Protocol:          protocol,
			AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
		}
		if err := s.stack.AddProtocolAddress(nicID, held, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("hold the address %s on this connection: %v", addr, err)
		}
	}
	// Everything goes out of the one interface. Which addresses actually cross is decided
	// by the WireGuard device's own allowed addresses, so a second route table here would
	// be a second place for that answer to live.
	if s.hasV4 {
		s.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if s.hasV6 {
		s.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	s.events <- tun.EventUp
	return s, nil
}

func (s *netStack) Name() (string, error) { return "wg", nil }

// File is the descriptor a real interface would have. There is none: this device exists
// only inside this process, which is what makes it need no privilege.
func (s *netStack) File() *os.File { return nil }

func (s *netStack) Events() <-chan tun.Event { return s.events }

func (s *netStack) MTU() (int, error) { return s.mtu, nil }

// BatchSize is one: this device carries packets one at a time between two in-process
// queues, so there is no syscall to amortize by batching.
func (s *netStack) BatchSize() int { return 1 }

// WriteNotify is called by the stack when it has produced a packet. It moves it onto the
// queue the device reads, under the flow it belongs to. The queue never blocks, so the
// stack's goroutine is never held here; a packet that arrives after the queue closed is
// released, since nothing will read it.
func (s *netStack) WriteNotify() {
	packet := s.ep.Read()
	if packet == nil {
		return
	}
	view := packet.ToView()
	packet.DecRef()
	if err := s.outbound.Enqueue(fqcodel.Classify(view.AsSlice()), view.Size(), view); err != nil {
		view.Release()
	}
}

// Read hands the device the next packet the stack produced, to be encrypted and sent.
func (s *netStack) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	view, err := s.outbound.Dequeue()
	if err != nil {
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	view.Release()
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write takes decrypted packets from the device into the stack, which is where they turn
// back into data on a connection.
func (s *netStack) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		held := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			s.ep.InjectInbound(header.IPv4ProtocolNumber, held)
		case 6:
			s.ep.InjectInbound(header.IPv6ProtocolNumber, held)
		default:
			held.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
		held.DecRef()
	}
	return len(bufs), nil
}

// Close tears the stack down. It is idempotent: the device closes it as part of its own
// shutdown, and so does the connection holding both.
func (s *netStack) Close() error {
	s.closeOnce.Do(func() {
		s.stack.RemoveNIC(nicID)
		s.ep.Close()
		// Nothing produces packets past ep.Close, so what is still queued is what this
		// connection will never send; closing the queue releases it and wakes the device.
		s.outbound.Close()
		close(s.events)
	})
	return nil
}

// fullAddr renders an address for the stack, which numbers protocols rather than naming
// them.
func fullAddr(addr netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	protocol := ipv6.ProtocolNumber
	if addr.Addr().Is4() {
		protocol = ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}, protocol
}

// dialTCP opens a TCP connection inside the network.
func (s *netStack) dialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	remote, protocol := fullAddr(addr)
	return gonet.DialContextTCP(ctx, s.stack, remote, protocol)
}

// dialUDP opens a UDP socket inside the network, already pointed at one address.
func (s *netStack) dialUDP(addr netip.AddrPort) (net.Conn, error) {
	remote, protocol := fullAddr(addr)
	return gonet.DialUDP(s.stack, nil, &remote, protocol)
}

// listenTCP accepts TCP inside the network, on one of this device's own addresses.
func (s *netStack) listenTCP(addr netip.AddrPort) (net.Listener, error) {
	local, protocol := fullAddr(addr)
	return gonet.ListenTCP(s.stack, local, protocol)
}

// listenPacket receives UDP inside the network, on one of this device's own addresses.
func (s *netStack) listenPacket(addr netip.AddrPort) (net.PacketConn, error) {
	local, protocol := fullAddr(addr)
	return gonet.DialUDP(s.stack, &local, nil, protocol)
}

// resolver looks names up through the resolvers this network publishes.
//
// It is Go's own resolver with its transport replaced: every query is sent inside this
// connection, to the addresses the server's configuration named, so a name that only exists
// on this network resolves and nothing about it reaches the machine's resolver. PreferGo is
// what makes the transport replaceable at all -- the platform resolver has no seam.
func (s *netStack) resolver(servers []netip.Addr) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The address Go picked is discarded: it comes from this machine's own
			// resolver configuration, which describes a different network entirely.
			var firstErr error
			for _, server := range servers {
				addr := netip.AddrPortFrom(server, 53)
				conn, err := s.dialResolver(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				if firstErr == nil {
					firstErr = err
				}
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("this connection has no resolvers configured")
			}
			return nil, firstErr
		},
	}
}

// dialResolver opens the transport one query travels over. Go asks for UDP first and
// retries over TCP when an answer comes back truncated, so both have to work.
func (s *netStack) dialResolver(ctx context.Context, network string, addr netip.AddrPort) (net.Conn, error) {
	if len(network) >= 3 && network[:3] == "tcp" {
		return s.dialTCP(ctx, addr)
	}
	return s.dialUDP(addr)
}

// queueStats is what the outbound queue has done, for the connection's report.
func (s *netStack) queueStats() fqcodel.Stats { return s.outbound.Stats() }
