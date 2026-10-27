// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"net/netip"

	"github.com/sellitus/app-tail/internal/hostnet"
)

// The tailnet-route repair's privilege boundary, in this package's own types.
//
// It is here for the reason the machine-wide resolver's is: internal/hostnet is what holds --
// or talks to what holds -- administrator rights, and the set of packages that may reach it is
// part of the design.
//
// Nothing here is about app-tail's own node. What it watches is whichever tailnet client this
// machine is running, which is usually not this one: an official client can lose the route for
// the tailnet's address range while keeping the interface, its addresses and its connection to
// every peer, and then nothing on the machine can reach the tailnet while every surface the
// client has says it is up.

// ErrTailnetRoutesUnsupported is a platform where the route cannot be checked or put back. A
// caller that sees it stops asking rather than retrying: the answer will not change.
var ErrTailnetRoutesUnsupported = hostnet.ErrTailnetRoutesUnsupported

// TailnetRouting is what this machine does with traffic aimed at the tailnet: the interface
// carrying its addresses, and the ranges that interface holds an address from which this
// machine does not actually send there.
type TailnetRouting struct {
	Interface string
	Unrouted  []netip.Prefix
}

// Broken reports a tailnet this machine is carrying and cannot reach.
func (r TailnetRouting) Broken() bool { return r.Interface != "" && len(r.Unrouted) > 0 }

// ReadTailnetRouting reports whether traffic aimed at the tailnet reaches the interface carrying
// it. It changes nothing and needs no privileges, so it does not go through the helper at all.
//
// own is the interface app-tail opened itself, empty when it has none.
func ReadTailnetRouting(ctx context.Context, own string) (TailnetRouting, error) {
	routing, err := hostnet.ReadTailnetRouting(ctx, own)
	if err != nil {
		return TailnetRouting{}, err
	}
	return TailnetRouting{Interface: routing.Interface, Unrouted: routing.Unrouted}, nil
}

// RepairTailnetRoutes sends the tailnet's ranges to the interface carrying them, and reports
// which ranges it had to install. An empty list with no error is the machine having been put
// right between the read and this call, which is a success rather than a failure to repair.
//
// The connection is opened for this one call and closed after it. Nothing here has to be put
// back when it drops, so there is no claim worth holding between repairs -- and a connection
// held open would be one more thing keeping a session gate taken for a feature that acts
// perhaps once in the life of a machine.
func RepairTailnetRoutes(ctx context.Context, iface string, logf func(format string, args ...any)) ([]netip.Prefix, error) {
	session, err := hostnet.OpenTailnetRoutes(ctx, hostnet.Options{Logf: logf})
	if err != nil {
		return nil, err
	}
	repaired, err := session.RepairTailnetRoutes(ctx, iface)
	// Joined rather than deferred away: a connection to the privileged side that would not
	// close is the session gate staying taken, which is the next repair being refused.
	return repaired, closeAlso(err, session.Close())
}
