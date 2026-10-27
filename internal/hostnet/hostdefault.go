// SPDX-License-Identifier: MIT

package hostnet

// Keeping this machine's own way out reachable while app-tail is carrying its traffic.
//
// A program that binds a socket to a network interface is saying "send this out of here and
// nowhere else", and the operating system answers it from that interface's own routing rather
// than from the machine's. macOS gives an interface no routing of its own until something
// installs some: until then a bound socket is answered from the machine's table, which works
// only while the best route for the destination happens to sit on the interface the socket is
// bound to.
//
// Carrying this machine's internet traffic breaks that. The address space is claimed in halves
// on app-tail's own interface, so for every internet destination the best route now belongs to
// an interface nothing is bound to, and every socket bound to the physical interface fails
// outright with "network is unreachable" -- including the tailnet node's own, which is bound
// there by the stack it is built on and is how it reaches its control server and its relays.
//
// This is what closes that gap: a copy of the machine's own default route, scoped to the
// interface that route already sits on. It says nothing new about where this machine's traffic
// goes -- the same interface, the same next hop -- and it is consulted only for traffic already
// bound there, which is traffic that was going to that interface or nowhere.

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// scopedHostRoute is one copy of this machine's own default route that this side installed:
// the interface it sits on, the next hop, and which address family it is for. Removing it
// again names the same three things, so they are kept rather than looked up a second time --
// the machine may have moved on by then, which is the case where looking again finds nothing
// and leaves the route behind.
type scopedHostRoute struct {
	iface   string
	gateway string
	v6      bool
}

// ScopeHostDefault gives the interface holding this machine's default route a scoped copy of
// it, for every address family that has one.
//
// It is asked for again every time the carried ranges change, because the machine may have
// changed underneath them: a laptop that moved from wireless to wired holds its default route
// on a different interface, with a different next hop. Each call reconciles -- what this side
// installed and no longer wants is removed, and what it wants is installed over whatever was
// there.
//
// A platform with no scoped routing at all reports ErrScopedRoutesUnsupported, which is a
// sentence about the machine rather than a failure of the request.
func (l *Local) ScopeHostDefault(ctx context.Context) error {
	if err := ScopedRoutesSupported(); err != nil {
		return err
	}

	l.mu.Lock()
	closed, driving, previous := l.closed, l.tunName, slices.Clone(l.hostScoped)
	l.mu.Unlock()
	if closed {
		return errors.New("this interface has already been torn down")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	wanted, errs := wantedHostDefaults(ctx, driving)

	// Everything that is on the machine or about to be, written down before either the removals
	// or the installations run. During the reconciliation below both sets are live -- the old
	// copies until they are removed, the new ones from the moment they go in -- so recording
	// only one of them would leave the other on this machine unrecorded if the process stopped
	// in the middle. The list is narrowed to what is actually held once the work is done.
	state := l.machineState()
	if err := state.setHostRoutes(union(previous, wanted)); err != nil {
		return errors.Join(append(errs, err)...)
	}

	// Kept rather than replaced: a route this side installed and failed to remove is still on
	// the machine, so it stays on the list the teardown works through.
	var held []scopedHostRoute
	for _, route := range previous {
		if slices.Contains(wanted, route) {
			continue
		}
		if err := l.unscopeRoute(ctx, route.iface, route.gateway, route.v6); err != nil {
			errs = append(errs, err)
			held = append(held, route)
		}
	}
	for _, route := range wanted {
		if err := l.scopeRoute(ctx, route.iface, route.gateway, route.v6); err != nil {
			errs = append(errs, err)
			continue
		}
		held = append(held, route)
	}

	l.mu.Lock()
	l.hostScoped = held
	l.mu.Unlock()
	if err := state.setHostRoutes(held); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// union is the copies named by either list, each once. It is what is on this machine while a
// reconciliation is part way through.
func union(previous, wanted []scopedHostRoute) []scopedHostRoute {
	out := slices.Clone(previous)
	for _, route := range wanted {
		if !slices.Contains(out, route) {
			out = append(out, route)
		}
	}
	return out
}

// UnscopeHostDefault removes every copy this side installed, leaving the interfaces they were
// on exactly as they were before.
//
// It is what the end of carrying asks for: with the machine's own table back to answering for
// every destination, a bound socket is answered from it again and the copy would only be
// another place for this machine's routing to be wrong.
func (l *Local) UnscopeHostDefault(ctx context.Context) error {
	l.mu.Lock()
	previous := slices.Clone(l.hostScoped)
	l.mu.Unlock()
	if len(previous) == 0 {
		return nil
	}

	var errs []error
	var held []scopedHostRoute
	for _, route := range previous {
		if err := l.unscopeRoute(ctx, route.iface, route.gateway, route.v6); err != nil {
			errs = append(errs, err)
			held = append(held, route)
		}
	}

	l.mu.Lock()
	l.hostScoped = held
	l.mu.Unlock()
	// After the removals, never before: the record shrinks only once what it named is off the
	// machine, so anything that could not be removed is still written down for the next start.
	if err := l.machineState().setHostRoutes(held); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// wantedHostDefaults is the set of copies this machine currently calls for: one per address
// family that has a default route, on the interface that route sits on.
//
// An interface app-tail opened itself is refused. Copying a default route that already belongs
// to app-tail's own interface would say that traffic bound to that interface reaches the whole
// internet through itself, which is a loop rather than a way out -- and it can only happen on a
// machine where something has already gone wrong, so it is reported rather than passed over.
func wantedHostDefaults(ctx context.Context, driving string) ([]scopedHostRoute, []error) {
	var wanted []scopedHostRoute
	var errs []error
	for _, v6 := range []bool{false, true} {
		iface, gateway, ok, err := hostDefaultRoute(ctx, v6)
		switch {
		case err != nil:
			errs = append(errs, err)
			continue
		case !ok:
			continue
		case driving != "" && iface == driving:
			errs = append(errs, fmt.Errorf(
				"this machine's own default route is on %s, which is the interface app-tail opened, "+
					"so there is no way out of this machine to keep reachable", iface))
			continue
		}
		wanted = append(wanted, scopedHostRoute{iface: iface, gateway: gateway, v6: v6})
	}
	return wanted, errs
}

// closeHostDefault removes the copies as part of a teardown.
//
// It runs before the teardown takes the lock, for the reason stopping the OpenVPN connections
// does: the work is a program run per route, and the failures belong in the list the teardown
// returns rather than in a log nobody reads.
func (l *Local) closeHostDefault() []error {
	ctx, cancel := context.WithTimeout(context.Background(), scopedRouteTimeout)
	defer cancel()
	if err := l.UnscopeHostDefault(ctx); err != nil {
		return []error{fmt.Errorf("take back this machine's own scoped default route: %w", err)}
	}
	return nil
}
