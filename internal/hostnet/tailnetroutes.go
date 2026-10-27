// SPDX-License-Identifier: MIT

package hostnet

// Noticing that this machine cannot reach its own tailnet, and putting the route back.
//
// A tailnet client holds two separate things on this machine. One is the interface: it carries
// the tailnet's addresses and its own encrypted connection to every peer, and it belongs to the
// client. The other is a route for the tailnet's whole range pointing at that interface, and it
// lives in the machine's routing table, where anything at all may remove it.
//
// When only the route goes, nothing reports a fault. The client is connected and its peers
// answer the probes it sends over its own connection, so every surface it has says the tailnet
// is up -- while every ordinary program on the machine sends tailnet traffic out of the physical
// interface instead, to a router that has never heard of the range, and the connection times out.
// That is a working tailnet nothing on the machine can use, and no part of it is visible from
// the place a user looks.
//
// This is what closes that gap: the range's route, put back on the interface already holding the
// tailnet's addresses. What makes it acceptable is that neither end is a value a caller sends.
// The destination is the tailnet's own range, fixed at compile time. The interface has to be one
// this side finds already carrying an address out of that range -- read again on the privileged
// side, not taken from the request. So the whole of what this can ask for is "send the tailnet's
// traffic to the interface that is already the tailnet", which is a statement about where that
// traffic was always going rather than a way to move any of it somewhere new.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// ErrTailnetRoutesUnsupported is a platform with no way for this side to read where the machine
// sends traffic, or to put a route back. It is a sentence about the machine rather than a
// failure of the request, and callers stop asking rather than retrying.
var ErrTailnetRoutesUnsupported = errors.New("this platform cannot check or repair the route to the tailnet")

// TailnetRouteRepairer puts the tailnet's route back. It is the privileged half of the feature;
// reading whether the route is missing needs nothing and is a plain function.
type TailnetRouteRepairer interface {
	// RepairTailnetRoutes sends the tailnet's ranges to the interface carrying them, and
	// reports which ranges it had to install.
	RepairTailnetRoutes(ctx context.Context, iface string) ([]netip.Prefix, error)
}

// TailnetRouteSession is a repair and the connection that carries it.
//
// It holds nothing that has to be put back, which is what makes it unlike the resolver's
// session: a route installed here is one the machine was meant to have, so there is no state
// for the connection dropping to restore. A caller opens one, repairs, and closes it, rather
// than holding it for as long as the feature is switched on.
type TailnetRouteSession interface {
	TailnetRouteRepairer
	Close() error
}

// OpenTailnetRoutes reaches the side that can change this machine's routing, in this process
// when it already holds the rights and over the helper socket when it does not.
func OpenTailnetRoutes(ctx context.Context, opts Options) (TailnetRouteSession, error) {
	host, err := Open(ctx, opts)
	if err != nil {
		return nil, err
	}
	session, ok := host.(TailnetRouteSession)
	if !ok {
		return nil, errors.Join(
			fmt.Errorf("this build's privileged side (%T) cannot repair the route to the tailnet", host),
			host.Close(),
		)
	}
	return session, nil
}

// tailnetRouteOps are the four things this file does that read or change the machine itself.
//
// They are values rather than direct calls for the reason the scoped-route changes are fields on
// Local: every branch worth having is one the machine has to be holding a particular state to
// reach -- an interface carrying a tailnet address, a routing table missing one range while
// holding the other, a routing tool that refuses -- and none of those can be arranged for on the
// machine a suite runs on, or arranged for without root.
type tailnetRouteOps struct {
	// supported is whether this platform can be asked the question at all.
	supported func() error
	// adapters is every interface on this machine and the addresses it holds.
	adapters func() []adapter
	// lookup is where this machine would send traffic aimed at one address: the interface, and
	// whether there was an answer at all.
	lookup func(ctx context.Context, addr netip.Addr) (string, bool, error)
	// add installs the route for one range on one interface.
	add func(ctx context.Context, iface string, prefix netip.Prefix) error
}

// defaultTailnetRouteOps reads and changes the machine this is running on.
func defaultTailnetRouteOps() tailnetRouteOps {
	return tailnetRouteOps{
		supported: TailnetRoutesSupported,
		adapters:  machineAdapters,
		lookup:    routeInterface,
		add:       addRangeRoute,
	}
}

// TailnetRouting is what this machine does with traffic aimed at the tailnet.
type TailnetRouting struct {
	// Interface carries the tailnet's addresses. Empty means no interface does, which is a
	// machine with no tailnet on it rather than a machine with something wrong.
	Interface string
	// Unrouted are the tailnet ranges Interface carries an address from that this machine does
	// not send traffic to. Empty is the healthy answer, and it is also the answer for a machine
	// with no tailnet: one that is missing nothing.
	Unrouted []netip.Prefix
}

// Broken reports a tailnet this machine is carrying and cannot reach.
func (r TailnetRouting) Broken() bool { return r.Interface != "" && len(r.Unrouted) > 0 }

// ReadTailnetRouting reports whether traffic aimed at the tailnet reaches the interface carrying
// it. It changes nothing and needs no privileges: reading which interfaces exist and asking the
// machine where it would send a packet are both things any process may do.
//
// own is the interface app-tail opened itself, empty when it has none. It is excluded because
// the routes on that interface are installed by app-tail's own engine from the netmap it holds:
// putting one back from here would be a second writer for routes that already have one.
func ReadTailnetRouting(ctx context.Context, own string) (TailnetRouting, error) {
	return readTailnetRouting(ctx, defaultTailnetRouteOps(), own)
}

func readTailnetRouting(ctx context.Context, ops tailnetRouteOps, own string) (TailnetRouting, error) {
	if err := ops.supported(); err != nil {
		return TailnetRouting{}, err
	}
	iface, carried, ok := tailnetCarrier(ops.adapters(), own)
	if !ok {
		return TailnetRouting{}, nil
	}
	unrouted, err := unroutedRanges(ctx, ops, iface, carried)
	if err != nil {
		return TailnetRouting{}, err
	}
	return TailnetRouting{Interface: iface, Unrouted: unrouted}, nil
}

// RepairTailnetRoutes puts back the route for every tailnet range the named interface carries an
// address from and this machine does not send traffic to. It reports the ranges it installed,
// which is empty when the machine was already routing all of them.
//
// The interface named by the caller is checked again here rather than trusted, for the reason
// every check on this boundary is doubled: this side holds the rights and the caller does not,
// and a check that only runs before the message is sent is a check on the well-behaved. What is
// checked is the thing that makes the operation narrow -- the interface has to be carrying a
// tailnet address right now.
//
// Nothing is written down for a later run to take back, and that is deliberate rather than an
// omission of what the scoped routes do. A route installed here is the one the machine was
// meant to have; removing it at the next start would break the tailnet again on a machine
// nothing else was going to fix. It also cannot outlive what it points at: routes go away with
// their interface, so a repair aimed at a client that has since stopped is gone with it.
func (l *Local) RepairTailnetRoutes(ctx context.Context, iface string) ([]netip.Prefix, error) {
	ops := l.tailnetRoutes
	if err := ops.supported(); err != nil {
		return nil, err
	}
	if err := validInterfaceName(iface); err != nil {
		return nil, err
	}

	l.mu.Lock()
	driving := l.tunName
	l.mu.Unlock()
	if driving != "" && iface == driving {
		return nil, fmt.Errorf(
			"%s is the interface app-tail opened, whose routes its own engine installs", iface)
	}

	name, carried, ok := tailnetCarrier(ops.adapters(), driving)
	if !ok || name != iface {
		return nil, fmt.Errorf(
			"%s is not carrying a tailnet on this machine, so no tailnet traffic belongs on it", iface)
	}

	var installed []netip.Prefix
	var errs []error
	for _, prefix := range carried {
		routed, err := rangeRoutedTo(ctx, ops, prefix, iface)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Already there: the caller read the machine a moment before this and the machine has
		// since been put right, by the client that owns the route or by another repair. Adding
		// it over the top would be a second writer for a route that already has one.
		if routed {
			continue
		}
		if err := ops.add(ctx, iface, prefix); err != nil {
			errs = append(errs, err)
			continue
		}
		installed = append(installed, prefix)
	}
	return installed, errors.Join(errs...)
}

// tailnetCarrier names the interface holding the tailnet's addresses and which of the tailnet's
// ranges it holds one from.
//
// A range the interface carries no address in is not one this machine is missing: there is
// nothing on that interface to send there, and a route for a family the interface has no address
// in is a route nothing can use. own is excluded for the reason tailnetHolder excludes it, and
// for one more: app-tail's own interface has an engine installing its routes already.
func tailnetCarrier(adapters []adapter, own string) (string, []netip.Prefix, bool) {
	for _, a := range adapters {
		if !a.up || (own != "" && a.name == own) {
			continue
		}
		var carried []netip.Prefix
		for _, prefix := range tailnetRanges {
			if slices.ContainsFunc(a.addrs, prefix.Contains) {
				carried = append(carried, prefix)
			}
		}
		if len(carried) > 0 {
			return a.name, carried, true
		}
	}
	return "", nil, false
}

// unroutedRanges are the ranges out of carried that this machine does not send to iface.
func unroutedRanges(ctx context.Context, ops tailnetRouteOps, iface string, carried []netip.Prefix) ([]netip.Prefix, error) {
	var unrouted []netip.Prefix
	for _, prefix := range carried {
		routed, err := rangeRoutedTo(ctx, ops, prefix, iface)
		if err != nil {
			return nil, err
		}
		if !routed {
			unrouted = append(unrouted, prefix)
		}
	}
	return unrouted, nil
}

// rangeRoutedTo asks the machine where it would send traffic aimed inside one range, and reports
// whether the answer is the given interface.
//
// The machine is asked rather than its routing table read and the answer worked out here: which
// route wins is the kernel's decision, and a second implementation of it would disagree with the
// kernel exactly where that matters. Traffic to a peer is what broke, so what is asked is where
// traffic to a peer would go.
//
// Both ends of the range are asked about, not one address. A client that installs a route per
// peer rather than one for the range would answer a single probe from whichever peer happened to
// sit at it, while the range itself -- which is what carries traffic to every other peer, and
// what this puts back -- was missing.
func rangeRoutedTo(ctx context.Context, ops tailnetRouteOps, prefix netip.Prefix, iface string) (bool, error) {
	for _, probe := range rangeEnds(prefix) {
		got, ok, err := ops.lookup(ctx, probe)
		if err != nil {
			return false, err
		}
		if !ok || got != iface {
			return false, nil
		}
	}
	return true, nil
}

// rangeEnds are two addresses inside a prefix, one at each end of it. The first is the one after
// the range's own base address, since the base itself is the network number rather than somewhere
// traffic goes.
func rangeEnds(prefix netip.Prefix) [2]netip.Addr {
	base := prefix.Masked().Addr()
	bytes := base.AsSlice()
	for bit := prefix.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	last, _ := netip.AddrFromSlice(bytes)
	return [2]netip.Addr{base.Next(), last}
}
