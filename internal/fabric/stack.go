// SPDX-License-Identifier: MIT

package fabric

// The network stack that stands in for every private network at once.
//
// The interface this drives is a real one on the machine, so every program here reaches
// these networks with no per-program setup: the routing table sends the packets to the
// interface, this stack takes them off it and turns them back into connections, and those
// connections are re-dialled inside whichever network the address belonged to. Nothing is
// forwarded at the packet level, which is what makes several networks with the same
// addresses work: a flow is decided once, against the address it arrived on, and its
// packets never have to be routed anywhere afterwards.
//
// What that costs is stated where it is felt rather than discovered: see Limits.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// nicID is the one interface this stack has. There is exactly one, so it is a constant
// rather than something to keep track of.
const nicID = 1

// headroom is the free space left at the front of every packet buffer.
//
// It is the convention the interface's own driver expects rather than a number chosen here:
// macOS writes a four-byte address-family prefix in front of the packet and Linux writes a
// virtio header, and both do it in place. Sixteen is what wireguard-go itself passes, and
// passing less makes the write fail on macOS at run time.
const headroom = 16

// maxPacket bounds one read off the interface. Linux hands over several packets that
// arrived together as one 64-kilobyte block, so a buffer sized to the interface's own MTU
// would be too small for the read rather than for any packet in it.
const maxPacket = 65535

// queueDepth is how many packets may wait between the stack and the interface. It bounds
// what one slow direction can hold; past it the stack drops, which is what a full link does
// anyway.
const queueDepth = 512

// halfOpenLimit bounds connections this stack has accepted and not yet finished dialling
// out for. It is a whole-machine cap on the memory a burst of connection attempts can hold;
// what one connection is allowed is the per-connection budget in flows.go.
const halfOpenLimit = 1024

// netStack is the interface, the stack driving it, and the two pumps between them.
type netStack struct {
	dev tun.Device
	ep  *channel.Endpoint
	ip  *stack.Stack
	mtu int

	logger *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	closeOnce sync.Once

	mu sync.Mutex
	// failed is why the pumps stopped, which is the only way an interface that went away
	// under this process becomes something a person can be told about.
	failed error
}

// newStack builds the stack over an interface and starts carrying packets both ways.
//
// The handlers are given rather than registered afterwards because a stack with an
// interface attached and no handler on it answers every connection with a reset: there must
// be no moment where the machine's routes point here and nothing is listening.
func newStack(dev tun.Device, mtu int, logger *slog.Logger, onTCP func(*tcp.ForwarderRequest), onUDP udp.ForwarderHandler) (*netStack, error) {
	if dev == nil {
		return nil, fmt.Errorf("no network interface to carry traffic on")
	}
	if mtu <= 0 {
		return nil, fmt.Errorf("an interface cannot carry packets of %d bytes", mtu)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &netStack{
		dev:    dev,
		ep:     channel.New(queueDepth, uint32(mtu), ""),
		mtu:    mtu,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
	s.ip = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// Selective acknowledgement, which is off by default here and on everywhere else. A
	// single lost packet without it stalls the whole window, and every path through a
	// private network loses packets.
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.ip.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		cancel()
		return nil, fmt.Errorf("enable TCP selective acknowledgement: %v", err)
	}

	if err := s.ip.CreateNIC(nicID, s.ep); err != nil {
		cancel()
		return nil, fmt.Errorf("create the interface's network stack: %v", err)
	}
	// This stack holds no addresses of its own and answers for every address the machine
	// sends it, because the addresses it answers for are whole networks and they change
	// whenever a connection does. Spoofing is the other half of the same thing: the reply
	// leaves from the address the program dialled, which is not an address this stack was
	// ever given.
	if err := s.ip.SetPromiscuousMode(nicID, true); err != nil {
		cancel()
		return nil, fmt.Errorf("accept traffic for the networks this interface carries: %v", err)
	}
	if err := s.ip.SetSpoofing(nicID, true); err != nil {
		cancel()
		return nil, fmt.Errorf("answer from the addresses this interface carries: %v", err)
	}
	s.ip.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	s.ip.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})

	s.ip.SetTransportProtocolHandler(tcp.ProtocolNumber,
		tcp.NewForwarder(s.ip, 0, halfOpenLimit, onTCP).HandlePacket)
	s.ip.SetTransportProtocolHandler(udp.ProtocolNumber,
		udp.NewForwarder(s.ip, onUDP).HandlePacket)

	s.wg.Add(2)
	go s.pumpIn()
	go s.pumpOut()
	return s, nil
}

// pumpIn takes packets off the interface and hands them to the stack.
func (s *netStack) pumpIn() {
	defer s.wg.Done()

	batch := s.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, headroom+maxPacket)
	}
	sizes := make([]int, batch)

	for {
		n, err := s.dev.Read(bufs, sizes, headroom)
		if err != nil {
			s.stopped(fmt.Errorf("read from the network interface: %w", err))
			return
		}
		for i := 0; i < n; i++ {
			s.inject(bufs[i][headroom : headroom+sizes[i]])
		}
		if s.ctx.Err() != nil {
			return
		}
	}
}

// inject hands one packet to the stack, which is where it becomes a connection.
func (s *netStack) inject(packet []byte) {
	if len(packet) == 0 {
		return
	}
	var protocol tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		protocol = header.IPv4ProtocolNumber
	case 6:
		protocol = header.IPv6ProtocolNumber
	default:
		// Neither IPv4 nor IPv6. Nothing this stack understands travels in one, and the
		// alternative to dropping it is guessing at a header layout.
		return
	}
	held := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	s.ep.InjectInbound(protocol, held)
	held.DecRef()
}

// pumpOut takes packets the stack produced and writes them to the interface.
func (s *netStack) pumpOut() {
	defer s.wg.Done()

	buf := make([]byte, headroom+maxPacket)
	// One slice header, reused: Write takes a batch, this pump writes one packet at a time,
	// and a fresh [][]byte literal per packet escapes to the heap through the interface call.
	// It is safe to reuse because Write consumes the batch before it returns and this is the
	// only goroutine that touches it.
	batch := make([][]byte, 1)
	for {
		packet := s.ep.ReadContext(s.ctx)
		if packet == nil {
			// Only a cancelled context ends the read, and the shutdown that cancelled it
			// is already the reason: reporting one here would overwrite it.
			return
		}
		view := packet.ToView()
		packet.DecRef()
		n, err := view.Read(buf[headroom:])
		view.Release()
		if err != nil {
			s.stopped(fmt.Errorf("take a packet from the network stack: %w", err))
			return
		}
		batch[0] = buf[:headroom+n]
		if _, err := s.dev.Write(batch, headroom); err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.stopped(fmt.Errorf("write to the network interface: %w", err))
			return
		}
	}
}

// stopped records why the interface stopped carrying traffic and brings the rest of it
// down.
//
// An interface that has gone away is not something to retry around: the machine's routes
// still point at it, so every program reaching a private network fails from here on, and the
// reason has to reach the dashboard rather than a log nobody is reading. A close in progress
// is not a failure and is not recorded as one.
func (s *netStack) stopped(err error) {
	if s.ctx.Err() != nil || closedAlready(err) {
		s.cancel()
		return
	}
	s.mu.Lock()
	if s.failed == nil {
		s.failed = err
	}
	s.mu.Unlock()
	if s.logger != nil {
		s.logger.Error("the network interface stopped carrying traffic", "error", err)
	}
	s.cancel()
}

// Err is why this stack stopped, or nil while it is running.
func (s *netStack) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

// Done is closed once this stack has stopped carrying traffic, for whatever reason.
func (s *netStack) Done() <-chan struct{} { return s.ctx.Done() }

// stop tells both pumps to finish. It does not wait for them: the inbound one is blocked in
// a read on the interface, which nothing but closing that interface's descriptor interrupts,
// and the descriptor is the caller's to close.
func (s *netStack) stop() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.ep.Close()
	})
}

// wait blocks until both pumps have stopped, which needs the interface closed first.
func (s *netStack) wait() { s.wg.Wait() }

// release tears the stack down once nothing is driving it any more. Every endpoint it holds
// goes with it, which is what ends the flows that were still open.
func (s *netStack) release() {
	s.ip.RemoveNIC(nicID)
	s.ip.Close()
	s.ip.Wait()
	s.ip.Destroy()
}

// closedAlready reports the ordinary end of an interface whose descriptor has been closed,
// which arrives here as a read failure and is not one.
func closedAlready(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed)
}

// localAddr is the address a flow arrived at, which is the address the program on this
// machine dialled.
func localAddr(id stack.TransportEndpointID) netip.AddrPort {
	addr, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return netip.AddrPortFrom(addr.Unmap(), id.LocalPort)
}

// remoteAddr is the address on this machine the flow came from, which is only ever used to
// say who asked.
func remoteAddr(id stack.TransportEndpointID) netip.AddrPort {
	addr, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	return netip.AddrPortFrom(addr.Unmap(), id.RemotePort)
}
