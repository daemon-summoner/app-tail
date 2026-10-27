// SPDX-License-Identifier: MIT

// Carrying one WireGuard connection's own packets inside another one.
//
// A chain of connections is built by giving each one after the first a different way of
// reaching its server: instead of a socket on this machine, it gets a stream through the
// connection before it. Everything else about the connection is unchanged, which is what
// makes a chain cost nothing anywhere else in this package -- the device does not know it is
// chained, and neither does anything reading its status.

package wgtunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/tailscale/wireguard-go/conn"
)

// Carrier is a connection this one's own packets are sent through.
//
// It is the one method a chain needs, declared here rather than taken from the tunnel seam
// so this package keeps depending on nothing that depends on it.
type Carrier interface {
	// Dial opens a connection to an address reachable through the carrier. A chain uses it
	// for one UDP conversation with this connection's server, for the life of the device.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Packet overheads a carried connection pays, in bytes.
const (
	// wireGuardOverhead is the data-packet header the carrier adds to everything it moves:
	// the type and receiver fields, the counter, and the authentication tag.
	wireGuardOverhead = 32
	// udp4Overhead and udp6Overhead are the IP and UDP headers of the datagram this
	// connection sends to its own server, which the carrier moves as its payload.
	udp4Overhead = 28
	udp6Overhead = 48
	// minHopMTU is the smallest packet a connection may be built to carry. It is IPv6's own
	// minimum, below which a network is not required to carry anything at all -- and a
	// packet size nothing on the far side has to honour is a connection that works for
	// small requests and hangs on large ones.
	minHopMTU = 1280
)

// hopMTU is the largest packet a connection can carry when its own packets travel inside a
// carrier whose packets are carrierMTU bytes.
func hopMTU(carrierMTU int, server netip.Addr) int {
	outer := udp4Overhead
	if server.Is6() && !server.Is4In6() {
		outer = udp6Overhead
	}
	return carrierMTU - wireGuardOverhead - outer
}

// hopBind is the wireguard-go Bind that sends and receives through a carrier instead of
// through a socket on this machine.
//
// It holds one conversation with one server, which is what a client device needs and all it
// needs: this connection has exactly one peer, at an address settled before the device was
// built, and a client never has to answer a stranger. Everything the Bind interface offers
// beyond that -- listening on a chosen port, several sockets, marks -- has no meaning through
// a carrier and is answered as such rather than faked.
//
// The conversation belongs to a single Open and is ended by the matching Close, because that
// is the lifecycle the device drives: it closes its bind and opens it again whenever it is
// brought up or its port changes, and a conversation that did not come back from the second
// Open would leave a device that reports itself running and moves nothing.
type hopBind struct {
	// ctx outlives the call that built this connection. The device reopens its bind on its
	// own schedule, long after that call has returned, and a start context cancelled by then
	// would fail the reopen for a reason that has nothing to do with the network.
	ctx     context.Context
	carrier Carrier
	server  netip.AddrPort

	mu sync.Mutex
	// conn is the open conversation, and nil is the whole of "not open": there is one, and
	// its presence is what Open refuses to duplicate and what Close ends.
	conn net.Conn
}

var _ conn.Bind = (*hopBind)(nil)

func newHopBind(ctx context.Context, carrier Carrier, server netip.AddrPort) *hopBind {
	return &hopBind{ctx: ctx, carrier: carrier, server: server}
}

// Open opens the conversation with the server through the carrier and hands back the one
// receive path.
//
// The port is ignored and reported as zero: a carried connection has no port on this machine,
// and inventing one would put a number in the status that nothing is listening on.
func (b *hopBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	carried, err := b.carrier.Dial(b.ctx, "udp", b.server.String())
	if err != nil {
		return nil, 0, fmt.Errorf("reach this connection's server %s through the connection "+
			"carrying it: %w", b.server, err)
	}
	b.conn = carried
	return []conn.ReceiveFunc{b.receiveFrom(carried)}, 0, nil
}

// receiveFrom reads packets from one conversation. It is bound to that conversation rather
// than to whatever is open now, so a receive still running when the device reopens its bind
// reads from the conversation it was handed and ends with it.
//
// Every packet is reported as coming from the configured server, because through a carrier
// it can have come from nowhere else: the conversation reaches one address, and nothing else
// can write into it. That also settles roaming for a carried connection -- there is no
// address for the peer to roam to, so the device is never told the endpoint moved.
func (b *hopBind) receiveFrom(carried net.Conn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 {
			return 0, nil
		}
		n, err := carried.Read(packets[0])
		if err != nil {
			return 0, b.readError(err)
		}
		sizes[0] = n
		eps[0] = hopEndpoint(b.server)
		return 1, nil
	}
}

// readError reports a read that failed after Close as the closed-socket error the Bind
// contract requires, and everything else as it happened. A carrier that went down is a real
// failure and is passed through, which is what takes the device out of the connected state.
func (b *hopBind) readError(err error) error {
	b.mu.Lock()
	open := b.conn != nil
	b.mu.Unlock()
	if !open || errors.Is(err, net.ErrClosed) {
		return net.ErrClosed
	}
	return fmt.Errorf("read from the connection carrying this one: %w", err)
}

// Send writes packets to the server through the carrier. The offset is where the packet
// starts in each buffer: the space before it is room this Bind could have encapsulated in,
// and one carried through another connection needs none.
func (b *hopBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	carried := b.conn
	b.mu.Unlock()
	if carried == nil {
		return net.ErrClosed
	}
	if ep != nil && ep.DstToString() != b.server.String() {
		// Unreachable while receive reports one address, and refused rather than sent
		// anywhere: a datagram written to the carrier goes to the server this conversation
		// was opened with whatever endpoint the device believes it is using, so quietly
		// sending it would be this connection talking to a peer it does not think it is.
		return fmt.Errorf("this connection is carried to %s and cannot send to %s",
			b.server, ep.DstToString())
	}
	for _, buf := range bufs {
		if offset > len(buf) {
			return fmt.Errorf("a packet of %d bytes was offered starting at byte %d", len(buf), offset)
		}
		if _, err := carried.Write(buf[offset:]); err != nil {
			return fmt.Errorf("send through the connection carrying this one: %w", err)
		}
	}
	return nil
}

// ParseEndpoint accepts the one server this connection is carried to.
func (b *hopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("the server address %q is not an address and a port: %w", s, err)
	}
	if addr != b.server {
		return nil, fmt.Errorf("this connection is carried to %s and cannot reach %s", b.server, addr)
	}
	return hopEndpoint(addr), nil
}

// SetMark is a socket option on this machine's own network stack, and a carried connection
// has no socket of its own. Accepted rather than refused: wireguard-go sets a mark on every
// device it brings up on some platforms, and a chain has nothing to route around on this
// machine because its packets never reach this machine's routing table.
func (b *hopBind) SetMark(uint32) error { return nil }

// BatchSize is one: the carrier moves one datagram per write, so there is nothing to gather.
func (b *hopBind) BatchSize() int { return 1 }

// Close ends the conversation with the server. It is safe to call with none open, which the
// device does both before its first Open and again when it is brought down and closed.
func (b *hopBind) Close() error {
	b.mu.Lock()
	carried := b.conn
	b.conn = nil
	b.mu.Unlock()
	if carried == nil {
		return nil
	}
	if err := carried.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close the connection carrying this one: %w", err)
	}
	return nil
}

// hopEndpoint is the server a carried connection talks to. It has no source address: the
// packets leave through the carrier, whose own source is the carrier's business.
type hopEndpoint netip.AddrPort

var _ conn.Endpoint = hopEndpoint{}

func (e hopEndpoint) ClearSrc()           {}
func (e hopEndpoint) SrcToString() string { return "" }
func (e hopEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e hopEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e hopEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }

// DstToBytes is what the cookie calculation hashes. It is the address and port in their own
// bytes, which is what every other Bind here hands it.
func (e hopEndpoint) DstToBytes() []byte {
	addrPort := netip.AddrPort(e)
	out := addrPort.Addr().AsSlice()
	port := addrPort.Port()
	return append(out, byte(port), byte(port>>8))
}
