// SPDX-License-Identifier: MIT

package app

// The per-destination exceptions as the interface carries them: which ranges go through
// which connection, which keep leaving through this machine, and which are refused.
//
// A rule about a host is not here at all, and that is the point of most of these: the
// interface sees an address and never a name, so half the rule language cannot reach it and
// must be left out rather than approximated.

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/routing"
)

func routeRule(id string, action routing.Action, cidr, tunnel string) routing.Rule {
	r := routing.Rule{ID: id, Action: action, Tunnel: tunnel}
	if cidr != "" {
		r.CIDR = netip.MustParsePrefix(cidr)
	}
	return r
}

// mappedTo is the connection an interface built from these mappings hands an address to,
// empty when nothing carries it.
func mappedTo(t *testing.T, mapped []fabric.Mapping, addr string) string {
	t.Helper()
	table, err := fabric.NewTable(mapped)
	if err != nil {
		t.Fatalf("building the addressing: %v", err)
	}
	dest, ok := table.Lookup(netip.MustParseAddr(addr))
	if !ok {
		return ""
	}
	return dest.TunnelID
}

// The feature at its simplest: one range goes through one connection, and the interface
// carries it.
func TestARangeRuleSendsThatRangeThroughTheConnectionItNames(t *testing.T) {
	rules := []routing.Rule{routeRule("r1", routing.Via, "198.51.100.0/24", "tn_vpn")}

	mapped, direct := routeMappings(rules, nil, []string{"tn_vpn"})

	if len(direct) != 0 {
		t.Errorf("kept off the interface = %v, want nothing", direct)
	}
	if got := mappedTo(t, mapped, "198.51.100.7"); got != "tn_vpn" {
		t.Errorf("an address in the range is carried by %q, want tn_vpn", got)
	}
}

// A rule about a host cannot be honoured by an interface, so it must not become a range it
// never stated. Guessing one would send every address a name happens to resolve to today
// through a connection the user named one name for.
func TestARuleAboutAHostPutsNothingOnTheInterface(t *testing.T) {
	rules := []routing.Rule{
		{ID: "r1", Action: routing.Via, Host: "**.corp.example", Tunnel: "tn_vpn"},
		{ID: "r2", Action: routing.Direct, Host: "bank.example"},
	}

	mapped, direct := routeMappings(rules, nil, []string{"tn_vpn"})

	if len(mapped) != 0 || len(direct) != 0 {
		t.Errorf("routeMappings = %v / %v, want nothing: the interface sees no names", mapped, direct)
	}
}

// The rule is the user saying this destination leaves the machine directly, and the only
// way an interface honours that is by keeping the range off itself.
func TestADirectRuleKeepsItsRangeOffTheInterface(t *testing.T) {
	rules := []routing.Rule{routeRule("r1", routing.Direct, "203.0.113.0/24", "")}

	mapped, direct := routeMappings(rules, nil, nil)

	if len(mapped) != 0 {
		t.Errorf("mapped = %v, want a direct rule to map nothing", mapped)
	}
	if want := netip.MustParsePrefix("203.0.113.0/24"); !slices.Contains(direct, want) {
		t.Errorf("kept off the interface = %v, want %s", direct, want)
	}
}

// A blocked range is carried by the interface and by nothing behind it, which is what makes
// the block a block: the interface goes on claiming the traffic and refuses it. Leaving the
// range off instead would send it out over this machine's own network.
func TestABlockedRangeIsClaimedByTheInterfaceAndCarriedByNothing(t *testing.T) {
	rules := []routing.Rule{routeRule("r1", routing.Block, "192.0.2.0/24", "")}

	mapped, direct := routeMappings(rules, nil, nil)

	if len(direct) != 0 {
		t.Errorf("kept off the interface = %v, want a blocked range claimed rather than excluded", direct)
	}
	if got := mappedTo(t, mapped, "192.0.2.44"); got != fabric.Blocked {
		t.Errorf("an address in the blocked range is carried by %q, want nothing to be registered for it", got)
	}
}

// The same refusal for a rule whose connection is not running. Dropping the range instead
// would let it fall through to whatever carries everything else, which is precisely the
// leak the rule was written to prevent.
func TestARangeRuleWhoseConnectionIsDownIsRefusedRatherThanDropped(t *testing.T) {
	rules := []routing.Rule{routeRule("r1", routing.Via, "198.51.100.0/24", "tn_vpn")}

	mapped, _ := routeMappings(rules, nil, []string{"tn_other"})

	if got := mappedTo(t, mapped, "198.51.100.7"); got != fabric.Blocked {
		t.Errorf("an address in the range is carried by %q, want it refused while the connection is down", got)
	}
}

// A rule about a range a private network already reaches is left alone, exactly as it is on
// the proxy path. Without this, one rule about 10.0.0.0/8 would take every private network
// on the machine with it.
func TestARuleDoesNotTakeARangeAConnectionAlreadyReaches(t *testing.T) {
	carried := []fabric.Mapping{{TunnelID: "tn_office", Prefix: netip.MustParsePrefix("10.0.0.0/8")}}
	rules := []routing.Rule{
		routeRule("r1", routing.Via, "10.1.0.0/16", "tn_vpn"),
		routeRule("r2", routing.Direct, "10.2.0.0/16", ""),
	}

	mapped, direct := routeMappings(rules, carried, []string{"tn_vpn"})

	if len(mapped) != 0 || len(direct) != 0 {
		t.Errorf("routeMappings = %v / %v, want nothing: both ranges are inside a network a connection carries",
			mapped, direct)
	}
}

// A rule wider than a network a connection carries is not a rule about that network: the
// narrower entry still wins in the table, and the rest of the range is the rule's.
func TestARuleWiderThanACarriedNetworkStillCoversTheRestOfItsRange(t *testing.T) {
	carried := []fabric.Mapping{{TunnelID: "tn_office", Prefix: netip.MustParsePrefix("10.1.0.0/16")}}
	rules := []routing.Rule{routeRule("r1", routing.Via, "10.0.0.0/8", "tn_vpn")}

	mapped, _ := routeMappings(rules, carried, []string{"tn_vpn"})

	whole := append(slices.Clone(carried), mapped...)
	if got := mappedTo(t, whole, "10.1.0.5"); got != "tn_office" {
		t.Errorf("an address the connection carries is handed to %q, want tn_office", got)
	}
	if got := mappedTo(t, whole, "10.9.0.5"); got != "tn_vpn" {
		t.Errorf("an address only the rule covers is handed to %q, want tn_vpn", got)
	}
}

// The whole wiring, through a running agent: a stored rule reaches the interface and the
// interface routes that range at the connection the rule names.
func TestAStoredRuleReachesTheInterface(t *testing.T) {
	vpnRange := netip.MustParsePrefix("198.51.100.0/24")
	_, fabrics := carryingFabricWith(t, labRange, func(c *config.Config) {
		c.Routes = []routing.Rule{{
			ID: "rt_1", Action: routing.Via, Tunnel: labTunnelID, CIDR: vpnRange,
		}}
	})

	waitFor(t, 5*time.Second, "the rule's range to be on the interface", func() bool {
		routes, _, _ := fabrics.all()[len(fabrics.all())-1].carrying()
		return slices.Contains(routes, vpnRange)
	})

	table := fabrics.all()[len(fabrics.all())-1].addressing()
	if got := carriedBy(table, netip.MustParseAddr("198.51.100.7")); got != labTunnelID {
		t.Errorf("an address in the rule's range is carried by %q, want %q", got, labTunnelID)
	}
}

// And a stored rule keeping a range off the interface, which is the only way an interface
// can honour "this one leaves the machine directly".
func TestAStoredDirectRuleKeepsItsRangeOffTheInterface(t *testing.T) {
	bank := netip.MustParsePrefix("203.0.113.0/24")
	_, fabrics := carryingFabricWith(t, labRange, func(c *config.Config) {
		c.Routes = []routing.Rule{{ID: "rt_1", Action: routing.Direct, CIDR: bank}}
	})

	waitFor(t, 5*time.Second, "the rule's range to be kept off the interface", func() bool {
		_, exclude, _ := fabrics.all()[len(fabrics.all())-1].carrying()
		return slices.Contains(exclude, bank)
	})
}

// The interface is one of two places a rule has to reach. The other is the registry, which
// is what the proxies and every app-scoped dial route through -- a rule that reached only
// the interface would apply in one mode and silently not in the others.
func TestAStoredRuleReachesTheRegistryTheProxiesRouteThrough(t *testing.T) {
	h, _ := carryingFabricWith(t, labRange, func(c *config.Config) {
		c.Routes = []routing.Rule{{
			ID: "rt_1", Action: routing.Via, Tunnel: labTunnelID, Host: "**.corp.example",
		}}
	})

	waitFor(t, 5*time.Second, "the rule to reach the registry", func() bool {
		return len(h.agent.tunnels.Routes()) == 1
	})

	got := h.agent.tunnels.RouteFor(routing.Request{Host: "db.corp.example"})
	if !got.Decided || got.Tunnel != labTunnelID {
		t.Errorf("the registry routes db.corp.example as %+v, want it through %q", got, labTunnelID)
	}
}

// A rule that is added while the app is running has to reach the interface on the next
// pass, or every edit would need a restart.
func TestAddingARuleMovesTheRangeOnTheNextPass(t *testing.T) {
	blocked := netip.MustParsePrefix("192.0.2.0/24")
	h, fabrics := carryingFabric(t, labRange)

	if _, err := h.agent.store.Update(func(c *config.Config) error {
		c.Routes = []routing.Rule{{ID: "rt_1", Action: routing.Block, CIDR: blocked}}
		return nil
	}); err != nil {
		t.Fatalf("storing the rule: %v", err)
	}
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the blocked range to be claimed by the interface", func() bool {
		table := fabrics.all()[len(fabrics.all())-1].addressing()
		return carriedBy(table, netip.MustParseAddr("192.0.2.44")) == fabric.Blocked
	})
}
