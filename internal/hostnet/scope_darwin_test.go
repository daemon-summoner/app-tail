// SPDX-License-Identifier: MIT

package hostnet

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// route's grammar puts modifiers after the command, so a family flag written before it is read
// as a flag route does not have. The command then exits on its usage line having touched
// nothing -- a connection reported as carrying this machine's internet traffic while its
// interface holds no route at all.
//
// This runs the real program to settle it. It cannot alter the routing table without root, and
// the refusal it gives instead is the proof: "must be root" is route having parsed the whole
// command, where a usage line is route having refused to.
func TestTheRouteCommandIsSpeltTheWayRouteReadsIt(t *testing.T) {
	if os.Geteuid() == 0 {
		// The refusal is what makes running the real command safe here. A suite running as root
		// would install these routes on the machine it is running on instead.
		t.Skip("this suite is running as root, so route would alter this machine's routing table")
	}
	for _, command := range []string{"add", "delete"} {
		for _, v6 := range []bool{false, true} {
			// Both next-hop forms: the one an OpenVPN tun gets, which is point to point and needs
			// none, and the one the interface holding this machine's own default route gets,
			// which is a network with a router on it.
			for _, gateway := range []string{"", gatewayFor(v6)} {
				args := routeArgs(command, "utun9", gateway, v6)
				if at := slices.Index(args, command); at < 0 || slices.Index(args, familyFlag(v6)) < at {
					t.Errorf("%v puts the address family before the command, which route reads as a flag", args)
				}

				out, err := exec.Command(routeBinary, args...).CombinedOutput()
				said := string(out)
				if err == nil {
					t.Fatalf("%v altered this machine's routing table from a test", args)
				}
				if strings.Contains(said, "usage:") || strings.Contains(said, "illegal option") {
					t.Errorf("route would not parse %v: %s", args, strings.TrimSpace(said))
				}
				if !strings.Contains(said, "must be root") {
					t.Errorf("route answered %v with %q, want the refusal a parsed command gets",
						args, strings.TrimSpace(said))
				}
			}
		}
	}
}

// gatewayFor is a documentation address of the right family to stand in for a next hop.
func gatewayFor(v6 bool) string {
	if v6 {
		return "2001:db8::1"
	}
	return "192.0.2.1"
}

// This machine's own way out is read from the routing table rather than assumed, and what is
// read is fed straight back to route as an interface name and a next hop. So the two things
// that matter are that the answer describes this machine and that it is made of values route
// will take: a name no interface has, or a next hop that is not an address, would be a route
// command built from whatever the output happened to contain.
func TestThisMachinesOwnWayOutIsReadAsAnInterfaceAndANextHop(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		iface, gateway, ok, err := hostDefaultRoute(t.Context(), v6)
		if err != nil {
			t.Fatalf("reading this machine's own default route failed: %v", err)
		}
		if !ok {
			// A machine with no default route for a family is ordinary -- most have no IPv6 one.
			if iface != "" || gateway != "" {
				t.Errorf("no default route was reported, yet it named %q via %q", iface, gateway)
			}
			continue
		}
		if err := validInterfaceName(iface); err != nil {
			t.Errorf("the default route named %q, which is not an interface name: %v", iface, err)
		}
		if _, err := net.InterfaceByName(iface); err != nil {
			t.Errorf("the default route named %q, which is not an interface on this machine: %v", iface, err)
		}
		if gateway == "" {
			continue
		}
		addr, err := netip.ParseAddr(gateway)
		if err != nil {
			t.Errorf("the default route's next hop %q is not an address: %v", gateway, err)
			continue
		}
		if addr.Is4() == v6 {
			t.Errorf("the next hop for the %s route is %q, which is the other address family",
				familyFlag(v6), gateway)
		}
	}
}
