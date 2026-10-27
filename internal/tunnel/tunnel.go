// SPDX-License-Identifier: MIT

// Package tunnel is the seam every private network this app connects to sits behind.
//
// A tunnel is one connection to one network: a tailnet, a WireGuard peer, an OpenVPN
// server. The three network methods are byte-identical to forward.Tailnet, which is what
// lets the forwarding engine, the proxy and the automatic mapper carry traffic for any of
// them without knowing which kind they were handed.
//
// The interface is deliberately small. Everything only one kind of tunnel can do is a
// capability discovered by type assertion (see capability.go) rather than a method every
// implementation has to answer -- a WireGuard peer has no exit nodes to suggest and no
// tailnet lock to report, and a method returning "not supported" for two kinds out of
// three is a shape every caller then has to classify.
package tunnel

import (
	"context"
	"net"
	"net/netip"

	"github.com/sellitus/app-tail/internal/config"
)

// Kind is what protocol a tunnel speaks. It is the variant the settings registry gates
// type-specific fields on, and the badge a list renders beside each connection.
//
// It is the stored type rather than a second enum beside it, because a running tunnel's
// kind and its stored type are the same fact: the configuration says what to connect and
// the tunnel is what connecting produced. Two enums would have to be kept in step by hand,
// and the failure of that is a stored type nothing can start with nothing reporting why.
type Kind = config.TunnelType

const (
	KindTailscale = config.TunnelTailscale
	KindWireGuard = config.TunnelWireGuard
	KindOpenVPN   = config.TunnelOpenVPN
)

// Tunnel is one live connection to one private network.
type Tunnel interface {
	// Dial opens a connection to an address inside this network, resolving whatever
	// names the network itself publishes.
	Dial(ctx context.Context, network, address string) (net.Conn, error)

	// Listen accepts TCP connections on this tunnel's own identity inside the network.
	Listen(network string, port uint16) (net.Listener, error)

	// ListenPacket receives UDP on this tunnel's own address. Implementations must
	// resolve the concrete address themselves: a bare ":port" is not enough to say
	// which of several networks the socket belongs to.
	ListenPacket(network string, port uint16) (net.PacketConn, error)

	// ID is the stable identifier the stored configuration names this tunnel by. It
	// survives renames and is never reused.
	ID() string

	// Kind is the protocol this tunnel speaks.
	Kind() Kind

	// Start brings the tunnel up. It returns once the attempt is under way rather than
	// once the network is reachable: a tunnel waiting on an interactive login is
	// started and not yet connected, and those are different states.
	Start(ctx context.Context) error

	// Close takes it down and releases everything it holds.
	Close() error

	// Status is the cached view of what this tunnel is doing. It must not block on the
	// network: it is read on every dashboard poll and on every tray menu open.
	Status() Status

	// Events signals that Status may have changed.
	Events() <-chan struct{}

	// Routes are the networks reachable through this tunnel. It is what decides which
	// tunnel carries a given address, so an implementation reports what it can actually
	// carry rather than what it was configured to want.
	Routes(ctx context.Context) ([]netip.Prefix, error)

	// Addrs are this tunnel's own addresses inside the network.
	Addrs() []netip.Addr
}
