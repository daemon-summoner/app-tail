// SPDX-License-Identifier: MIT

package hostnet

// macOS keeps a routing table per interface alongside the machine's own, which is how a Mac
// on wired and wireless at once sends each service's traffic the right way. A route added
// with -ifscope lands in one of those, and is consulted only for traffic already bound to
// that interface -- so it is exactly the statement this needs to make and no more.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// routeBinary is the program that changes this machine's routing table. It is an absolute
// path rather than a name for the reason openvpn's own is: this runs as root, and a name
// would let whatever wrote PATH choose what gets run.
const routeBinary = "/sbin/route"

// routeMissing is what route says when asked to remove a route that is not there. Removing a
// route that is already gone is the outcome the caller wanted, so this one sentence is read
// as success and every other failure is reported.
const routeMissing = "not in table"

// scopeDefault gives one interface a default route of its own.
//
// The route is deleted before it is added rather than added and the "it is already there"
// failure interpreted: an interface that reconnected may hold a route to a gateway that has
// gone, and replacing it is what makes this the same operation whatever was there before.
//
// gateway is the next hop to send that traffic to, empty for an interface that needs none. An
// OpenVPN tun is point to point, so a packet put on it has one place to go and the far end
// routes it from there; the interface this machine's own default route sits on is usually a
// network with a router on it, and a route there that named no next hop would have the machine
// asking the destination itself for its hardware address.
func scopeDefault(ctx context.Context, iface, gateway string, v6 bool) error {
	if err := unscopeDefault(ctx, iface, gateway, v6); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, routeBinary, routeArgs("add", iface, gateway, v6)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("give %s a default route of its own: %w: %s",
			iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unscopeDefault takes that route back, reporting nothing amiss when it is not there.
//
// An interface that has gone away has already taken its routes with it -- which is the usual
// case here, since this runs when the openvpn program that opened the interface has exited.
// Asking route about a name no interface has is a failure with nothing behind it.
func unscopeDefault(ctx context.Context, iface, gateway string, v6 bool) error {
	if !interfaceExists(iface) {
		return nil
	}
	out, err := exec.CommandContext(ctx, routeBinary, routeArgs("delete", iface, gateway, v6)...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), routeMissing) {
		return fmt.Errorf("take back the default route on %s: %w: %s",
			iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// interfaceExists reports whether this machine has an interface with that name. An interface
// that has gone away has already taken its routes with it, which is what the removals ask.
// Reading which interfaces exist needs no privileges.
func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// routeArgs is one route command: the scoped default route for one interface and one family.
//
// The order is route's own grammar -- "route [flags] command [[modifiers] args]" -- so the
// family and the scope follow the command rather than leading it. A family flag put before it
// is read as a flag route does not have, and the command exits on its usage line without
// touching the routing table.
//
// The removal takes the same next hop the installation used rather than leaving it out: route
// matches a removal against what is there, and naming the same route both times is what makes
// the pair exact.
func routeArgs(command, iface, gateway string, v6 bool) []string {
	args := []string{"-n", command, familyFlag(v6), "-ifscope", iface, "default"}
	if gateway == "" {
		return append(args, "-interface", iface)
	}
	return append(args, gateway)
}

// hostDefaultRoute reports where this machine sends traffic it has no more specific route for:
// the interface holding the default route, and the next hop on it.
//
// It asks route for the entry under its own name rather than reading the whole table, so an
// interface app-tail is carrying traffic for -- which claims the address space in halves
// rather than by replacing this entry -- does not change the answer. A machine with no default
// route for that family reports ok false, and the caller has nothing to copy.
func hostDefaultRoute(ctx context.Context, v6 bool) (iface, gateway string, ok bool, err error) {
	return routeLookup(ctx, "default", v6)
}

// routeLookup asks the machine where it would send traffic to one destination: the interface it
// would leave through, and the next hop on it. destination is route's own grammar for one --
// "default", or an address.
//
// A destination the machine has no route for is not a failure: ok is false, and the caller has
// its answer. A next hop that is not an address is one too: a point-to-point link reports its
// own name there, and the empty gateway is what asks for the form that has no next hop.
func routeLookup(ctx context.Context, destination string, v6 bool) (iface, gateway string, ok bool, err error) {
	out, err := exec.CommandContext(ctx, routeBinary, "-n", "get", familyFlag(v6), destination).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), routeMissing) {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("read where this machine sends traffic to %s: %w: %s",
			destination, err, strings.TrimSpace(string(out)))
	}
	for line := range strings.Lines(string(out)) {
		name, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		switch value = strings.TrimSpace(value); name {
		case "interface":
			iface = value
		case "gateway":
			if addr, err := netip.ParseAddr(value); err == nil {
				gateway = addr.String()
			}
		}
	}
	if iface == "" {
		return "", "", false, nil
	}
	if err := validInterfaceName(iface); err != nil {
		return "", "", false, err
	}
	return iface, gateway, true, nil
}

// familyFlag is route's own name for one address family.
func familyFlag(v6 bool) string {
	if v6 {
		return "-inet6"
	}
	return "-inet"
}

// ScopedRoutesSupported reports whether this machine can give one interface a default route
// of its own. It can, as long as the program that does it is there: a Mac without /sbin/route
// is one where something has gone very wrong, and reporting that is better than failing at
// the point a connection is asked to carry traffic.
func ScopedRoutesSupported() error {
	if err := trustedRootProgram(routeBinary); err != nil {
		return errors.Join(ErrScopedRoutesUnsupported, err)
	}
	return nil
}
