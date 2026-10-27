// SPDX-License-Identifier: MIT

package tunnel

// Capabilities only some kinds of tunnel have.
//
// These are discovered by type assertion rather than declared on Tunnel, because a method
// every implementation must answer is a method two implementations out of three answer
// with "not supported" -- and then every caller has to classify that answer. An absent
// capability is absent: the caller asks whether the tunnel has it, and renders the
// feature or does not.
//
// The technique is the one internal/hostnet/resolver.go already uses for the same reason.

import (
	"context"
	"net/netip"
	"time"
)

// Resolving is a tunnel whose network publishes its own names. A WireGuard peer with no
// DNS= line has no resolver at all, which is why this is a capability rather than a
// method that would have to invent a failure for it.
type Resolving interface {
	// LookupHost resolves a name through this network's own resolver. An answer with no
	// addresses and no error is a name this network does not serve, which is a fact about
	// the name rather than a failure to look it up: the caller goes on to ask the next
	// network, where the same name may well exist.
	LookupHost(ctx context.Context, host string) (Lookup, error)
}

// Lookup is what one network's resolver said about a name.
type Lookup struct {
	Addrs []netip.Addr
	// TTL is how long the answer holds. Zero means the resolver did not say, which a
	// caching caller reads as "use your own floor" rather than as "do not cache".
	TTL time.Duration
}

// Served reports that the network answered with an address.
func (l Lookup) Served() bool { return len(l.Addrs) > 0 }

// Pinger is a tunnel that can measure the round trip to an address inside it. What that
// costs and what it proves differ by kind, so the caller only ever asks whether it is
// offered.
type Pinger interface {
	Ping(ctx context.Context, addr netip.Addr) (Reachability, error)
}

// Reachability is one round-trip measurement.
type Reachability struct {
	// LatencyMs is the measured round trip. Zero means it was never measured, which is
	// why it is reported alongside OK rather than as a value that stands in for failure.
	LatencyMs float64
	OK        bool
	// Via names how the packet travelled -- direct, or through a named relay -- because
	// "works but feels slow" is almost always this and is not visible in the latency
	// alone.
	Via string
}

// Peered is a tunnel whose network is made of named devices rather than only address
// ranges. A tailnet is; a point-to-point WireGuard link is not.
type Peered interface {
	Peers(ctx context.Context) ([]Peer, error)
}

// Peer is one other device on the network.
type Peer struct {
	ID    string
	Name  string
	Addrs []string
	// RxBytes and TxBytes are cumulative totals from this device's point of view: Tx is
	// what this machine sent. They are counters, so a reader derives a rate from two
	// readings and treats a decrease as the peer having left rather than as negative
	// traffic.
	RxBytes, TxBytes int64
	Online           bool
	// Direct reports a connection that does not pass a relay, and Relay names the relay
	// when it does.
	Direct bool
	Relay  string
	// LatencyMs is the last measured round trip, or zero when nothing measured it.
	LatencyMs float64
}

// Metered is a tunnel that counts what it has carried.
//
// Only a kind that sees its own packets, or is told about them by whatever does, can answer:
// a tailnet's traffic is counted per device rather than per connection, and is reported that
// way on the activity screen instead. An absent capability is what stops a screen printing a
// confident zero for a connection nothing is counting.
type Metered interface {
	// Carried is what has crossed this connection, and how long it has been up.
	Carried() Carried
}

// Carried is one connection's own account of itself.
type Carried struct {
	// Up and Down are cumulative bytes since this connection was built, from this machine's
	// point of view: Up is what it sent. They are counters, so a reader derives a rate from
	// two readings, and a decrease is the connection having been rebuilt rather than
	// negative traffic.
	Up, Down int64
	// Since is when this connection was built. A connection that keeps coming back with a
	// short uptime is one that is failing and being retried, which reads as working on every
	// other screen: the state is "connected" every time somebody looks.
	Since time.Time
	// LastHandshake is when the two sides last agreed on keys, and is zero for a kind that
	// has no handshake or one that has never completed one. It is the difference between a
	// connection that is idle and one that is gone.
	LastHandshake time.Time
	// Dropped is how many packets this connection's own outbound queue discarded to keep its
	// delay and depth bounded while the device could not keep up. It is zero for a kind that
	// has no such queue. A count that keeps climbing is a connection whose encryption or
	// carrier is the slow part, not the network past it.
	Dropped int64
}

// SubnetServer is a tunnel this device can offer other devices a route into. Only a
// network with a membership model has anything to offer them.
type SubnetServer interface {
	// Advertised are the prefixes this device offers to carry.
	Advertised(ctx context.Context) ([]netip.Prefix, error)
	// Approved are the ones the network actually routes here, which is what a carried
	// connection is checked against. The gap between the two is the whole reason both
	// are reported: an advertised route nobody approved silently carries nothing.
	Approved(ctx context.Context) ([]netip.Prefix, error)
}

// ExitCarrier is a tunnel that can carry this machine's internet-facing traffic. For
// Tailscale that is a chosen peer; for WireGuard it is a peer with a default route in its
// allowed addresses; for OpenVPN it is a pushed redirect-gateway.
type ExitCarrier interface {
	// CanCarryExit reports whether this tunnel is able to carry internet traffic right
	// now, and why not when it cannot.
	CanCarryExit(ctx context.Context) (bool, string)
}

// Sized is a tunnel that states the largest packet its network carries.
//
// It matters to exactly one caller: the interface mode, whose own packet size has to be the
// smallest of every connected network's. A byte stream is re-segmented on the way through, so
// a stream over a network with a smaller packet size still works; a datagram is not, and one
// too big for the network it ends up on is dropped with nothing reporting why.
//
// A tunnel that does not offer this contributes nothing to that minimum, which is the honest
// answer for a kind whose packet size is not knowable rather than a number invented for it.
type Sized interface {
	// MTU is the largest packet this network carries, in bytes.
	MTU() int
}

// Anchored is a tunnel that says where its own packets go.
//
// It matters to exactly one caller: the interface mode, which points this machine's routing
// table at ranges the connections carry. A connection whose own server address falls inside
// one of those ranges would have its encrypted packets routed back into the interface that
// produced them, and the machine would lose every network it has at once -- including
// whatever was going to switch the mode off. Those addresses have to keep leaving through
// the machine's own network, and only the connection knows what they are.
//
// A tunnel that does not offer this is one whose transport addresses are not knowable: a
// tailnet talks to whichever relay and whichever peer address it is using this second, and a
// list read a moment ago would be wrong by the time it was installed.
type Anchored interface {
	// Anchors are the addresses this connection's own packets are sent to, right now.
	Anchors() []netip.Addr
}

// Addressed is a tunnel whose network addresses its own members from ranges of its own,
// separate from any route it carries to somewhere else.
//
// It matters to exactly one caller: the interface mode, which reaches a network by pointing
// this machine's routing table at the ranges that network occupies. A tailnet is the case
// that needs it -- its devices live in the tailnet's own allocation, which no peer ever
// advertises as a route because every member reaches every other by being a member -- so an
// interface built from carried routes alone carries the tailnet nowhere and every device on
// it is unreachable from this machine.
//
// A tunnel that does not offer this has no member range to reach: a point-to-point link's
// own address is one end of a wire, not a network anything else is found at.
type Addressed interface {
	// Networks are the ranges this network addresses its members from.
	Networks() []netip.Prefix
}
