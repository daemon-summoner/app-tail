// SPDX-License-Identifier: MIT

package hostnet

// Linux has no per-interface routing table of its own, so one is made: a routing table
// holding nothing but this interface's default route, and a rule sending traffic already
// bound to that interface to look it up. A socket bound with SO_BINDTODEVICE is what the rule
// matches, which is the same socket macOS's scoped route answers for.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ipBinaries is where the program that changes this machine's routing is looked for, in
// order. They are absolute paths rather than a name for the reason openvpn's own list is:
// this runs as root, and a name would let whatever wrote PATH choose what gets run. Several
// are listed because distributions disagree about where iproute2 installs to.
var ipBinaries = []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"}

// routeTableBase is where the tables this makes start. Each interface gets base plus its own
// index, so the table one connection uses is decided by the kernel's own numbering rather
// than by anything this side has to remember across a restart. It sits far above the tables
// with names of their own -- local, main and default are 255, 254 and 253 -- and far above
// where anything else is likely to put one.
const routeTableBase = 7300

// ruleMissing is what ip says when asked to remove a rule that is not there. Removing one
// that is already gone is the outcome the caller wanted, so this one sentence is read as
// success and every other failure is reported.
const ruleMissing = "No such file or directory"

// scopeDefault gives one interface a default route of its own.
//
// The table is emptied and the rule removed before either is written, so this is the same
// operation whatever was there before: an interface that reconnected reuses its index, and
// with it the table its last connection was using.
//
// gateway is the next hop to send that traffic to, empty for an interface that needs none. An
// OpenVPN tun is point to point, so a packet put on it has one place to go and the far end
// routes it from there; the interface this machine's own default route sits on is usually a
// network with a router on it, and a route there that named no next hop would have the machine
// asking the destination itself for its hardware address.
func scopeDefault(ctx context.Context, iface, gateway string, v6 bool) error {
	table, err := routeTableFor(iface)
	if err != nil {
		return err
	}
	if err := unscopeTable(ctx, iface, table, v6); err != nil {
		return err
	}
	family := familyFlag(v6)
	add := []string{family, "route", "add", "default"}
	if gateway != "" {
		add = append(add, "via", gateway)
	}
	add = append(add, "dev", iface, "table", table)
	if out, err := runIP(ctx, add...); err != nil {
		return fmt.Errorf("give %s a default route of its own: %w: %s", iface, err, out)
	}
	if out, err := runIP(ctx, family, "rule", "add", "oif", iface, "table", table, "priority", table); err != nil {
		return errors.Join(
			fmt.Errorf("send %s's own traffic to its own routing table: %w: %s", iface, err, out),
			unscopeTable(ctx, iface, table, v6),
		)
	}
	return nil
}

// unscopeDefault takes that route back, reporting nothing amiss when it is not there.
//
// The next hop plays no part: the whole table this side made for the interface is emptied, so
// what was in it does not have to be named.
func unscopeDefault(ctx context.Context, iface, _ string, v6 bool) error {
	found, err := net.InterfaceByName(iface)
	if err != nil {
		// The interface has gone, which is the ordinary way a connection ends. Its index went
		// with it, so the table it was using cannot be worked out from here -- but the routes
		// in that table went with the interface too, and the rule is removed by matching the
		// name rather than the table.
		return unscopeByName(ctx, iface, v6)
	}
	return unscopeTable(ctx, iface, routeTable(found.Index), v6)
}

// unscopeTable removes the rule pointing at one table and empties it.
func unscopeTable(ctx context.Context, iface, table string, v6 bool) error {
	family := familyFlag(v6)
	if err := unscopeByName(ctx, iface, v6); err != nil {
		return err
	}
	if out, err := runIP(ctx, family, "route", "flush", "table", table); err != nil && !strings.Contains(out, ruleMissing) {
		return fmt.Errorf("empty the routing table %s was using: %w: %s", iface, err, out)
	}
	return nil
}

// unscopeByName removes every rule this side installed for one interface.
//
// It repeats until the removal reports there is none left rather than removing one: a rule is
// added once per start, and a start that failed between adding the rule and recording it
// would otherwise leave one behind for every attempt.
func unscopeByName(ctx context.Context, iface string, v6 bool) error {
	family := familyFlag(v6)
	for range maxScopedRules {
		out, err := runIP(ctx, family, "rule", "del", "oif", iface)
		switch {
		case err == nil:
			continue
		case strings.Contains(out, ruleMissing):
			return nil
		}
		return fmt.Errorf("stop sending %s's own traffic to its own routing table: %w: %s", iface, err, out)
	}
	return fmt.Errorf("more than %d routing rules name %s, which is not something this side installed", maxScopedRules, iface)
}

// maxScopedRules bounds the removal loop. It is a loop over an external state this side did
// not write on its own, so it is bounded: without it a rule that will not go away is a
// teardown that never returns.
const maxScopedRules = 16

// hostDefaultRoute reports where this machine sends traffic it has no more specific route for:
// the interface holding the default route, and the next hop on it.
//
// The main table is what is asked, so the tables this side makes for individual interfaces are
// not among the answers. A machine with no default route for that family is not a failure: ok
// is false, and the caller has nothing to copy. Where several are installed the first is taken,
// which is the one with the lowest metric -- ip lists them in the order the kernel would use.
func hostDefaultRoute(ctx context.Context, v6 bool) (iface, gateway string, ok bool, err error) {
	out, err := runIP(ctx, familyFlag(v6), "route", "show", "default", "table", "main")
	if err != nil {
		return "", "", false, fmt.Errorf("read this machine's own default route: %w: %s", err, out)
	}
	for line := range strings.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		iface, gateway = "", ""
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dev":
				iface = fields[i+1]
			case "via":
				// A next hop that is not an address is one this side will not pass on: the
				// route command takes an address there, and anything else came from a form of
				// the output this does not understand.
				if addr, parseErr := netip.ParseAddr(fields[i+1]); parseErr == nil {
					gateway = addr.String()
				}
			}
		}
		if iface == "" {
			continue
		}
		if err := validInterfaceName(iface); err != nil {
			return "", "", false, err
		}
		return iface, gateway, true, nil
	}
	return "", "", false, nil
}

// routeTableFor is the routing table one interface's default route lives in.
func routeTableFor(iface string) (string, error) {
	found, err := net.InterfaceByName(iface)
	if err != nil {
		return "", fmt.Errorf("read the network interface %s: %w", iface, err)
	}
	return routeTable(found.Index), nil
}

// routeTable is the table number an interface index gets.
func routeTable(index int) string { return strconv.Itoa(routeTableBase + index) }

// familyFlag is ip's own name for one address family.
func familyFlag(v6 bool) string {
	if v6 {
		return "-6"
	}
	return "-4"
}

// runIP runs one iproute2 command, returning what it said so the caller can report it. A
// variable so a test can stand in for the program and say what it would have said.
var runIP = execIP

func execIP(ctx context.Context, args ...string) (string, error) {
	binary, err := ipBinary()
	if err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ipBinary is the iproute2 program this side will run, or a refusal naming where it looked.
// It has to be one no account but root can change -- the file, every directory on the way to
// it and every library it loads (trustedRootProgram) -- for the reason openvpn's own does: a
// program another account can rewrite is that account's program.
func ipBinary() (string, error) {
	var refused []error
	for _, path := range ipBinaries {
		err := trustedRootProgram(path)
		switch {
		case err == nil:
			return path, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			refused = append(refused, fmt.Errorf("found %s and will not run it as root: %w", path, err))
		}
	}
	if len(refused) > 0 {
		return "", errors.Join(append([]error{ErrScopedRoutesUnsupported}, refused...)...)
	}
	return "", fmt.Errorf("%w: looked for the ip program in %s",
		ErrScopedRoutesUnsupported, strings.Join(ipBinaries, ", "))
}

// ScopedRoutesSupported reports whether this machine can give one interface a default route
// of its own, which here means whether iproute2 is installed where this side will run it.
func ScopedRoutesSupported() error {
	_, err := ipBinary()
	return err
}
