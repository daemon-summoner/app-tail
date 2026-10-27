// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"net"
	"net/netip"

	"tailscale.com/client/local"
	"tailscale.com/tsd"
	"tailscale.com/tsnet"
)

// backend is the tailnet stack a Node is built on. There are two: tsnet's userspace
// server, which is what the app installs as, and a stack wired onto a real network
// interface.
//
// It is an interface because the two are built completely differently -- one is a
// struct literal, the other is an engine, a netstack, a backend and a local API server
// assembled by hand -- while everything above them is identical. Every method here is
// one tsnet.Server already has, so the userspace side satisfies it by being itself and
// only the TUN side is new code.
type backend interface {
	// Start brings the stack up. Past a successful return it holds resources,
	// including the lock on the state directory.
	Start() error
	// LocalClient talks to the backend over an in-process socket. It is the same
	// *local.Client on both stacks, which is what makes every operation above this
	// interface mode-independent.
	LocalClient() (*local.Client, error)
	// Sys is the engine's subsystem registry, which carries the dialer the address
	// classifier reads.
	Sys() *tsd.System
	// Dial opens a connection from the tailnet side, and is the data path both the
	// forwards and the proxy run on.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	// Listen accepts connections addressed to this node on the tailnet.
	Listen(network, addr string) (net.Listener, error)
	// ListenPacket is Listen's datagram half.
	ListenPacket(network, addr string) (net.PacketConn, error)
	// RegisterFallbackTCPHandler claims flows to addresses no listener owns, which is
	// what delivers a connection to a subnet this device carries. The returned function
	// removes the handler.
	RegisterFallbackTCPHandler(cb tsnet.FallbackTCPHandler) func()
	// Close releases everything Start took, including the state directory lock.
	Close() error
}

// tsnet.Server is the userspace stack. The assertion is here rather than at a use site
// so a signature change upstream fails this build with the reason attached.
var _ backend = (*tsnet.Server)(nil)

// interceptAll puts the caller's handler into the shape a backend registers, separate
// from the registration so the decision it carries is reachable without a stack.
//
// It always intercepts: this handler is the authority on a flow to a routed address, and
// declining would hand the flow to whatever else is registered rather than refusing it.
// A nil result is the refusal.
func interceptAll(h func(src, dst netip.AddrPort) func(net.Conn)) tsnet.FallbackTCPHandler {
	return func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		return h(src, dst), true
	}
}
