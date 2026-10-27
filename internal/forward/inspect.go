// SPDX-License-Identifier: MIT

package forward

// The inspector's seat on a port forward.
//
// A forward carries an address chosen in the settings rather than one a program asked for,
// so there is nothing here to refuse at setup time: the destination is the one the user
// typed. What the opening bytes carry is another matter -- a forward pointed at a proxy or a
// gateway carries connections for names nobody typed here, and those names are in the first
// bytes and nowhere else on this path.

import (
	"context"
	"net"
	"net/netip"
	"strconv"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// Inspector reads the opening bytes of the connections a forward carries. It is declared
// here rather than imported so this package keeps knowing nothing about where a rule came
// from or how it is compiled.
type Inspector interface {
	// Watch answers nil for a flow it has nothing to read, which is the switch being off
	// and every state before the first compile.
	Watch(f inspect.Flow) netpipe.Stream
	// Open decides whether an encrypted connection is opened so that Watch has something
	// to read, and answers the pair of connections to carry it between either way. For
	// almost every flow that is the pair it was handed, untouched.
	//
	// An error means this connection was going to be opened and could not be, which is a
	// connection that must not be carried: its opening bytes are gone, and the reason is
	// usually that the far end could not be verified. Nothing comes back with the error --
	// the caller cuts the two ends it already holds.
	Open(ctx context.Context, f inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error)
}

// SetInspector replaces what reads the flows these forwards carry. Nil reads nothing.
func (m *Manager) SetInspector(in Inspector) {
	if in == nil {
		m.inspector.Store(nil)
		return
	}
	m.inspector.Store(&in)
}

// watches asks for a reader of one forward's opening bytes, and answers none when there is
// no inspector.
func (m *Manager) watches(f config.Forward) netpipe.Stream {
	held := m.inspector.Load()
	if held == nil {
		return nil
	}
	return (*held).Watch(forwardFlow(f))
}

// opens asks whether one forward's connection is opened, and answers the pair to carry it
// between. No inspector is the pair it was handed.
func (m *Manager) opens(ctx context.Context, f config.Forward, client, upstream net.Conn) (net.Conn, net.Conn, error) {
	held := m.inspector.Load()
	if held == nil {
		return client, upstream, nil
	}
	return (*held).Open(ctx, forwardFlow(f), client, upstream)
}

// forwardFlow is one forward's target as inspection reads it.
//
// The target is the one the user typed, so a target written as a name is offered as one:
// the entries a user writes as domains are the entries that would match it, and reaching
// this seam with only an address would leave every one of them unable to.
func forwardFlow(f config.Forward) inspect.Flow {
	flow := inspect.Flow{Where: "a port forward", Protocol: "tcp"}
	host, port, err := net.SplitHostPort(f.Target)
	if err != nil {
		return flow
	}
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		flow.Port = uint16(n)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		flow.Addr = addr
		return flow
	}
	flow.Name = host
	return flow
}
