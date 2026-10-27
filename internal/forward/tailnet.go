// SPDX-License-Identifier: MIT

// Package forward runs the port mappings: TCP accept loops and UDP session tables,
// their lifecycle, and their live status.
package forward

import (
	"context"
	"net"
)

// Tailnet is the tailnet-side network surface a Manager needs. Everything on the
// local side uses the standard net package directly.
//
// Keeping this an interface is what lets the whole forwarding engine be tested over
// loopback with no tailnet: tsnode.Node satisfies it in production, and the tests
// supply an implementation that maps targets to local echo servers.
//
// Implementations must be comparable -- a pointer, in every case there is -- because a
// running forward is rebuilt when the network under it is replaced, and identity is what
// tells a replacement from the same network reported again.
type Tailnet interface {
	// Dial opens a connection to a tailnet address, resolving MagicDNS names.
	// Used by to_local forwards of both protocols.
	Dial(ctx context.Context, network, address string) (net.Conn, error)

	// Listen accepts TCP connections on this node's tailnet identity.
	Listen(network string, port uint16) (net.Listener, error)

	// ListenPacket receives UDP on this node's tailnet IP. Implementations must
	// resolve the concrete address themselves: tsnet rejects a bare ":port".
	ListenPacket(network string, port uint16) (net.PacketConn, error)
}

// Tailnets resolves the network a forward crosses from the connection it names.
//
// It is asked on every reconcile rather than held, because the answer changes: a
// connection that is not carrying right now has no network to offer, and one that was
// rebuilt offers a different one. Both are the same question -- what carries this forward
// at this moment -- and asking it in one place is what lets a manager run forwards over
// several private networks without knowing there is more than one.
type Tailnets interface {
	// Tailnet returns the network for a connection id, and false when that connection is
	// not carrying traffic right now. A caller that gets false stops the forward rather
	// than dialling: a forward bound to a network that is down would accept connections
	// and fail every one of them.
	Tailnet(id string) (Tailnet, bool)
}
