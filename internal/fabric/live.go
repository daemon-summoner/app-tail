// SPDX-License-Identifier: MIT

package fabric

// The interface and the stack behind it, as one thing.
//
// They are two halves of one state and neither is usable alone: an interface with nothing
// reading it is a black hole for every range pointed at it, and a stack with no interface
// has nothing to read. Handing them out separately would make every caller responsible for
// getting the order right, in both directions, including the failure paths.

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/sellitus/app-tail/internal/bytecount"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// LiveOptions are what a running fabric is built from.
type LiveOptions struct {
	// Name is what to call the interface, empty for the platform's default.
	Name string
	// Pool is the range presented networks are moved into. The interface takes its own
	// address from it, so the same pool goes to Allocate as one of this machine's own.
	Pool []netip.Prefix
	// Carriers is where the connection an address belongs to is looked up.
	Carriers Carriers
	// MTU is the largest packet the interface carries: the smallest of the connected
	// networks' own.
	MTU int
	// SessionBudget is how many flows one connection may hold at once.
	SessionBudget int
	// Seed is what a destination is hashed with when several connections carry this
	// machine's internet traffic together. It belongs to the machine and is derived from
	// its own install identity, so a site keeps the connection it left through.
	Seed uint64
	// Logger takes this side's own logging, Logf the privileged side's.
	Logger *slog.Logger
	Logf   func(format string, args ...any)
	// Grants hears whether each routing change the helper was asked for was refused for a
	// missing approval. Nil hears nothing.
	Grants grants.Observer

	// open is the privileged side, this machine's own when it is nil. See
	// InterfaceOptions.open.
	open func(ctx context.Context, opts hostnet.Options) (privileged, error)
}

// Live is a fabric that is up: the interface on this machine and the stack carrying it.
type Live struct {
	iface *Interface
	fab   *Fabric
	addrs []netip.Prefix
}

// Open creates the interface and starts carrying traffic on it.
//
// Nothing is routed to the interface yet. Carry is a separate step because the addressing is
// decided from what the connections carry, which is known only once they are up, and an
// interface that is routed to before anything is reading it is exactly the black hole this
// mode has to never be.
func Open(ctx context.Context, opts LiveOptions) (*Live, error) {
	addrs := InterfaceAddrs(opts.Pool)
	iface, err := OpenInterface(ctx, InterfaceOptions{
		Name:   opts.Name,
		Addrs:  addrs,
		Logf:   opts.Logf,
		Grants: opts.Grants,
		open:   opts.open,
	})
	if err != nil {
		return nil, err
	}

	fab, err := New(Options{
		Device:        iface.Device(),
		Carriers:      opts.Carriers,
		MTU:           opts.MTU,
		SessionBudget: opts.SessionBudget,
		Seed:          opts.Seed,
		Logger:        opts.Logger,
	})
	if err != nil {
		// The interface is closed through the fabric everywhere else, and there is no fabric
		// here to close it: the device goes first, then the privileged side that made it.
		return nil, errors.Join(err, iface.Device().Close(), iface.Close())
	}
	return &Live{iface: iface, fab: fab, addrs: addrs}, nil
}

// Name is what the operating system called the interface.
func (l *Live) Name() string { return l.iface.Name() }

// Addrs are the addresses the interface itself holds, which the allocator must be told about
// so no connection is ever presented at one of them.
func (l *Live) Addrs() []netip.Prefix { return l.addrs }

// SetTable replaces the addressing. Flows already open keep the answer they were given.
func (l *Live) SetTable(t *Table, names map[string]string) { l.fab.SetTable(t, names) }

// SetInspector replaces what examines the flows this interface carries. Flows already open
// keep the answer they were given, for the same reason the addressing does: a flow is
// decided once and re-deciding it halfway through could only ever end a live connection.
func (l *Live) SetInspector(in Inspector) { l.fab.SetInspector(in) }

// Carry points this machine's routing table at the interface. exclude are the ranges that
// must keep leaving through the machine's own network -- every connection's own server among
// them.
func (l *Live) Carry(ctx context.Context, routes, exclude []netip.Prefix, mtu int) error {
	return l.iface.Carry(ctx, routes, exclude, mtu)
}

// Withdraw takes every range off the interface, leaving it up and carrying nothing. It is
// what runs when the stack behind the interface stops.
func (l *Live) Withdraw(ctx context.Context) error { return l.iface.Withdraw(ctx) }

// MTU is the largest packet the interface carries.
func (l *Live) MTU() int { return l.fab.MTU() }

// Done is closed once the fabric has stopped carrying traffic, for any reason.
func (l *Live) Done() <-chan struct{} { return l.fab.Done() }

// Status is what the fabric is doing, named with the interface it is on.
func (l *Live) Status() Status { return l.fab.Status(l.iface.Name()) }

// Ports is what each port and transport carried, apart from Status because only the activity
// graphs ask for it.
func (l *Live) Ports() ([]bytecount.Row, bytecount.Row, int) { return l.fab.Ports() }

// Close stops carrying traffic and undoes every change this made to the machine. The fabric
// goes first because it owns the interface's descriptor; the privileged side is what takes
// the routes and the interface itself back off the machine.
func (l *Live) Close() error {
	return errors.Join(l.fab.Close(), l.iface.Close())
}
