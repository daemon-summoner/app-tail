// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// resolvingReachingTunnel is a connection that both says where destinations are and
// publishes a resolver of its own, which is what an egress connection has to be for a name
// lookup to stop reaching this machine's own network.
type resolvingReachingTunnel struct {
	*reachingTunnel
	answers map[string][]netip.Addr
	// unreachable is the resolver inside the network failing to be reached at all, which is
	// a different state from one that answered and knew nothing.
	unreachable error
	asked       []string
}

func (r *resolvingReachingTunnel) LookupHost(_ context.Context, host string) (Lookup, error) {
	r.asked = append(r.asked, host)
	if r.unreachable != nil {
		return Lookup{}, r.unreachable
	}
	return Lookup{Addrs: r.answers[host], TTL: time.Minute}, nil
}

func resolvingEgress(id string, answers map[string][]netip.Addr) *resolvingReachingTunnel {
	return &resolvingReachingTunnel{reachingTunnel: reaching(id, nil), answers: answers}
}

// The point of the setting: a destination no connection carries leaves through the
// connection chosen to carry internet traffic, while the rules still see it as this
// machine's own network. Conflating the two would turn a rule granting one connection into
// a grant of the whole internet the moment somebody pointed egress at it.
func TestInternetTrafficLeavesThroughTheChosenConnectionWithoutBecomingItsTraffic(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", nil)
	office.resolves = map[string]netip.AddrPort{"example.test:443": mustAddrPort(t, "93.184.216.34:443")}
	mustAdd(t, r, office)
	r.SetEgress("tn_office")

	route, err := r.Resolve(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != ThisMachine {
		t.Errorf("TunnelID = %q, want the destination still read as this machine's own network", route.TunnelID)
	}
	if !route.Direct() {
		t.Error("Direct is false, so a rule about this machine would no longer match the destination")
	}
	if route.Via() != Tunnel(office) {
		t.Error("Via is not the egress connection, so the traffic would leave this machine directly")
	}
}

// Without a connection chosen, nothing changes: the traffic leaves this machine the way it
// always has and a caller has no tunnel to dial through.
func TestInternetTrafficLeavesThisMachineWhenNoConnectionIsChosen(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", nil)
	office.resolves = map[string]netip.AddrPort{"example.test:443": mustAddrPort(t, "93.184.216.34:443")}
	mustAdd(t, r, office)

	route, err := r.Resolve(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Via() != nil {
		t.Error("Via names a connection when none was chosen to carry internet traffic")
	}
}

// A destination a connection carries goes through that connection, whatever internet
// traffic is set to. Sending it through the egress connection instead would take every
// private network off the machine the moment somebody chose one.
func TestAConnectionsOwnDestinationStillGoesThroughIt(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", map[string]netip.AddrPort{
		"db.corp:5432": mustAddrPort(t, "10.0.0.5:5432"),
	})
	vpn := reaching("tn_vpn", nil)
	mustAdd(t, r, office, vpn)
	r.SetEgress("tn_vpn")

	route, err := r.Resolve(context.Background(), "tcp", "db.corp:5432")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Via() != Tunnel(office) {
		t.Errorf("Via = %v, want the connection that carries the destination", route.Via())
	}
	if route.Egress != nil {
		t.Error("a carried destination carries an egress connection, which reads as it going somewhere else")
	}
}

// The leak this setting exists to close. Traffic that leaves through a connection with a
// name looked up here first tells this network's resolver every address being visited,
// which is most of what the traffic would have said.
func TestANameForTheInternetIsLookedUpThroughTheConnectionCarryingIt(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", map[string][]netip.Addr{
		"example.test": {netip.MustParseAddr("203.0.113.9")},
	})
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("the lookup reached this machine's own resolver")
		return mustAddrPort(t, "93.184.216.34:443"), nil
	})

	route, err := r.Resolve(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Addr != mustAddrPort(t, "203.0.113.9:443") {
		t.Errorf("Addr = %v, want the address the egress connection resolved", route.Addr)
	}
	if len(vpn.asked) != 1 || vpn.asked[0] != "example.test" {
		t.Errorf("the egress connection was asked %v, want the bare name once", vpn.asked)
	}
}

// A name the egress connection's resolver does not serve fails there rather than falling
// back to this machine's resolver: falling back is the lookup this arm exists to prevent,
// and it would happen for exactly the names the connection could not answer.
func TestANameTheEgressConnectionCannotResolveDoesNotFallBackToThisMachine(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", nil)
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("the lookup fell back to this machine's own resolver")
		return netip.AddrPort{}, nil
	})

	_, err := r.Resolve(context.Background(), "tcp", "example.test:443")

	if err == nil {
		t.Fatal("a name the egress connection could not resolve was answered anyway")
	}
	if !strings.Contains(err.Error(), "example.test") {
		t.Errorf("error = %v, want the name in it", err)
	}
}

// The resolver inside the network being unreachable is not permission to ask this one. A
// connection that is up while its resolver is not is the ordinary shape of a network still
// coming up, and falling back then would leak exactly while the leak was least expected.
func TestAnEgressResolverThatCannotBeReachedDoesNotSendTheLookupHere(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", nil)
	vpn.unreachable = errors.New("no route to the resolver")
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("the lookup fell back to this machine's own resolver")
		return netip.AddrPort{}, nil
	})

	_, err := r.Resolve(context.Background(), "tcp", "example.test:443")

	if err == nil {
		t.Fatal("a name went unresolved and the dial was answered anyway")
	}
	if !strings.Contains(err.Error(), "no route to the resolver") {
		t.Errorf("error = %v, want the resolver's own failure carried out", err)
	}
}

// An answer in the wrong address family is no answer to the dial that was asked. Using it
// would hand a caller dialling tcp4 an address it cannot open, and falling back to this
// machine's resolver to find a usable one is the leak again.
func TestAnEgressAnswerInAnotherAddressFamilyIsNotUsedForTheDial(t *testing.T) {
	for _, tc := range []struct {
		network string
		answer  string
		want    string
	}{
		{network: "tcp4", answer: "2001:db8::9", want: "ip4"},
		{network: "tcp6", answer: "203.0.113.9", want: "ip6"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			r := NewRegistry()
			vpn := resolvingEgress("tn_vpn", map[string][]netip.Addr{
				"example.test": {netip.MustParseAddr(tc.answer)},
			})
			mustAdd(t, r, vpn)
			r.SetEgress("tn_vpn")
			r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
				t.Error("the lookup fell back to this machine's own resolver")
				return netip.AddrPort{}, nil
			})

			_, err := r.Resolve(context.Background(), tc.network, "example.test:443")

			if err == nil {
				t.Fatalf("%s was returned for a dial that can only open %s", tc.answer, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want the family that was asked for named", err)
			}
		})
	}
}

// A destination that is not a host and a port is malformed rather than leaky, and it is
// reported in the terms every other malformed destination gets. Naming the egress connection
// in it would send someone looking at their VPN over a typed port.
func TestAMalformedDestinationIsReportedWithoutNamingTheEgressConnection(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", nil)
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")

	_, err := r.Resolve(context.Background(), "tcp", "example.test:https")

	if err == nil {
		t.Fatal("a destination whose port is not a number was resolved anyway")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error = %v, want the port that could not be read named", err)
	}
	if strings.Contains(err.Error(), "tn_vpn") {
		t.Errorf("error = %v, want no mention of the egress connection in a typed port", err)
	}
	if len(vpn.asked) != 0 {
		t.Errorf("the egress connection was asked to resolve %v for a destination with no usable port", vpn.asked)
	}
}

// An address is not a name, so there is nothing to leak and nothing to ask. Asking anyway
// would put a lookup of something that is not a name in front of every dial to an address.
func TestAnAddressForTheInternetIsNotLookedUpAnywhere(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", nil)
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")
	r.SetHostResolver(func(_ context.Context, _, address string) (netip.AddrPort, error) {
		return mustAddrPort(t, address), nil
	})

	route, err := r.Resolve(context.Background(), "tcp", "203.0.113.9:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(vpn.asked) != 0 {
		t.Errorf("the egress connection was asked to resolve %v, none of which is a name", vpn.asked)
	}
	if route.Via() != Tunnel(vpn) {
		t.Error("Via is not the egress connection, so the traffic would leave this machine directly")
	}
}

// A connection that publishes no resolver of its own cannot be asked, so the lookup stays
// here. That is the limit the mode screen states rather than a leak to close: there is
// nothing at the other end to ask, and refusing the name would take the machine off the
// internet instead.
func TestAnEgressConnectionWithNoResolverOfItsOwnLeavesTheLookupHere(t *testing.T) {
	r := NewRegistry()
	vpn := reaching("tn_vpn", nil)
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")
	asked := 0
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		asked++
		return mustAddrPort(t, "203.0.113.9:443"), nil
	})

	route, err := r.Resolve(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if asked != 1 {
		t.Errorf("this machine's resolver was asked %d times, want once: nothing else can answer", asked)
	}
	if route.Via() != Tunnel(vpn) {
		t.Error("Via is not the egress connection, so the traffic would leave this machine directly")
	}
}

// A destination that is not a host and a port at all never reaches the egress resolver:
// there is no name in it to ask about, and the ordinary path is what says so.
func TestADestinationWithNoPortIsNotAskedOfTheEgressResolver(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", nil)
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")

	_, err := r.Resolve(context.Background(), "tcp", "example.test")

	if err == nil {
		t.Fatal("a destination naming no port was resolved anyway")
	}
	if len(vpn.asked) != 0 {
		t.Errorf("the egress connection was asked to resolve %v, none of which is a destination", vpn.asked)
	}
}

// A connection named as the egress that is not running is reported as nothing carrying the
// traffic. The alternative is a route through a connection that is not there, which fails
// as a dial timeout against whatever was being reached.
func TestAnEgressConnectionThatIsNotRunningCarriesNothing(t *testing.T) {
	r := NewRegistry()
	r.SetEgress("tn_vpn")

	if _, ok := r.Egress(); ok {
		t.Error("a connection that was never registered is reported as carrying internet traffic")
	}
}
