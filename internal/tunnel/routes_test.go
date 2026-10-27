// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/routing"
)

// resolvesTo builds a registry holding one connection that carries nothing and can say
// where one public destination is, which is the whole setup every routing test needs: a
// destination no connection carries, so the rules are what decide where it leaves.
func resolvesTo(t *testing.T, address, addr string) (*Registry, *reachingTunnel) {
	t.Helper()
	r := NewRegistry()
	office := reaching("tn_office", nil)
	office.resolves = map[string]netip.AddrPort{address: mustAddrPort(t, addr)}
	mustAdd(t, r, office)
	return r, office
}

// The point of the feature: one destination goes another way while everything else keeps
// following the egress setting.
func TestARuleSendsOneDestinationThroughTheConnectionItNames(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", nil)
	office.resolves = map[string]netip.AddrPort{
		"db.corp.example:443": mustAddrPort(t, "93.184.216.34:443"),
		"news.example:443":    mustAddrPort(t, "93.184.216.35:443"),
	}
	vpn := reaching("tn_vpn", nil)
	mustAdd(t, r, office, vpn)
	r.SetRoutes([]routing.Rule{{ID: "r1", Action: routing.Via, Host: "**.corp.example", Tunnel: "tn_vpn"}})

	route, err := r.Resolve(context.Background(), "tcp", "db.corp.example:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Via() != Tunnel(vpn) {
		t.Errorf("Via = %v, want the connection the rule names", route.Via())
	}
	if route.TunnelID != ThisMachine {
		t.Errorf("TunnelID = %q, want the destination still read as this machine's own network", route.TunnelID)
	}

	// Everything the rule does not name is untouched, which is what makes these exceptions
	// rather than a second egress setting.
	other, err := r.Resolve(context.Background(), "tcp", "news.example:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if other.Via() != nil {
		t.Errorf("Via = %v for a destination no rule names, want this machine's own network", other.Via())
	}
}

// A rule is the whole point of choosing an egress at all: it has to beat the setting, or
// the exception a user wrote would silently do nothing the moment they turned egress on.
func TestARuleBeatsTheEgressSetting(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", nil)
	office.resolves = map[string]netip.AddrPort{"bank.example:443": mustAddrPort(t, "203.0.113.9:443")}
	vpn := reaching("tn_vpn", nil)
	mustAdd(t, r, office, vpn)
	r.SetEgress("tn_vpn")
	r.SetRoutes([]routing.Rule{{ID: "r1", Action: routing.Direct, Host: "bank.example"}})

	route, err := r.Resolve(context.Background(), "tcp", "bank.example:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Via() != nil {
		t.Errorf("Via = %v, want the rule's direct answer rather than the egress connection", route.Via())
	}
}

// The fail-closed hold exists so nothing leaks out over the ISP link by accident. A rule
// saying one destination goes out directly is the user naming the exception on purpose, so
// the hold must not override it -- otherwise the exception is unwritable.
func TestADirectRuleIsHonouredWhileTheRestOfTheTrafficIsHeld(t *testing.T) {
	r, _ := resolvesTo(t, "bank.example:443", "203.0.113.9:443")
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		return mustAddrPort(t, "203.0.113.9:443"), nil
	})
	// Members chosen but none of them running, which is the held state.
	r.SetEgressMembers([]string{"tn_gone"}, 0)
	r.SetRoutes([]routing.Rule{{ID: "r1", Action: routing.Direct, Host: "bank.example"}})

	route, err := r.Resolve(context.Background(), "tcp", "bank.example:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Via() != nil {
		t.Errorf("Via = %v, want this machine's own network", route.Via())
	}

	// And the hold still holds everything the rule does not name.
	if _, err := r.Resolve(context.Background(), "tcp", "news.example:443"); !errors.Is(err, ErrEgressHeld) {
		t.Errorf("a destination no rule names gave %v, want the traffic to stay held", err)
	}
}

// A blocked destination has to fail before anything looks it up: hiding the traffic while
// broadcasting the query about it is the same leak by another road.
func TestABlockedDestinationIsRefusedWithoutBeingResolved(t *testing.T) {
	r := NewRegistry()
	office := resolvingEgress("tn_office", map[string][]netip.Addr{
		"telemetry.example": {netip.MustParseAddr("192.0.2.44")},
	})
	mustAdd(t, r, office)
	asked := false
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		asked = true
		return netip.AddrPort{}, errors.New("this machine's resolver was asked")
	})
	r.SetRoutes([]routing.Rule{{ID: "r1", Action: routing.Block, Host: "telemetry.example"}})

	_, err := r.Resolve(context.Background(), "tcp", "telemetry.example:443")

	if !errors.Is(err, ErrRouteBlocked) {
		t.Fatalf("Resolve gave %v, want the destination refused by the rule", err)
	}
	if asked {
		t.Error("this machine's resolver was asked about a blocked name")
	}
	if len(office.asked) != 0 {
		t.Errorf("a connection's resolver was asked about a blocked name: %v", office.asked)
	}
	// Where the leak actually is: asking a connection where a destination would go puts
	// the name to that network's own resolver, so a blocked destination must not reach
	// even that question.
	if len(office.reached) != 0 {
		t.Errorf("a connection was asked where a blocked destination goes: %v", office.reached)
	}
	if !strings.Contains(err.Error(), "rule 1") {
		t.Errorf("error = %q, want it to name the rule that refused", err)
	}
}

// A rule pointing at a connection that is down must refuse rather than fall back. Falling
// back would send the destination out over whatever else was available, which is exactly
// what the rule was written to stop.
func TestARuleNamingAConnectionThatIsNotRunningRefuses(t *testing.T) {
	r, _ := resolvesTo(t, "db.corp.example:443", "93.184.216.34:443")
	r.SetRoutes([]routing.Rule{{ID: "r1", Action: routing.Via, Host: "**.corp.example", Tunnel: "tn_gone"}})

	_, err := r.Resolve(context.Background(), "tcp", "db.corp.example:443")

	if !errors.Is(err, ErrRouteDown) {
		t.Fatalf("Resolve gave %v, want a refusal naming the connection that is down", err)
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("error = %q, want it to say the connection is not running", err)
	}
}

// A rule about a range cannot be matched against a name until something resolves it, so it
// is applied again once the address is known. Without the second pass a range rule would
// work for an address literal and quietly do nothing for every name that lands in it --
// the half-applied shape that makes a feature look flaky rather than off.
func TestARuleAboutARangeIsAppliedToANameOnceItResolves(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", nil)
	office.resolves = map[string]netip.AddrPort{"streaming.example:443": mustAddrPort(t, "198.51.100.7:443")}
	vpn := reaching("tn_vpn", nil)
	mustAdd(t, r, office, vpn)
	r.SetRoutes([]routing.Rule{{
		ID: "r1", Action: routing.Via, Tunnel: "tn_vpn", CIDR: netip.MustParsePrefix("198.51.100.0/24"),
	}})

	route, err := r.Resolve(context.Background(), "tcp", "streaming.example:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Via() != Tunnel(vpn) {
		t.Errorf("Via = %v, want the connection the range rule names", route.Via())
	}

	// The same rule against a literal, which the first pass can already decide.
	literal, err := r.Resolve(context.Background(), "tcp", "198.51.100.7:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if literal.Via() != Tunnel(vpn) {
		t.Errorf("Via = %v for the address itself, want the same answer as for the name", literal.Via())
	}
}

// A range rule that turns out to block, discovered only after the name resolved, still has
// to refuse -- the traffic is what the rule is about, and it has not left yet.
func TestARangeThatBlocksRefusesEvenWhenOnlyTheResolvedAddressSaysSo(t *testing.T) {
	r, _ := resolvesTo(t, "tracker.example:443", "192.0.2.44:443")
	r.SetRoutes([]routing.Rule{{
		ID: "r1", Action: routing.Block, CIDR: netip.MustParsePrefix("192.0.2.0/24"),
	}})

	_, err := r.Resolve(context.Background(), "tcp", "tracker.example:443")

	if !errors.Is(err, ErrRouteBlocked) {
		t.Fatalf("Resolve gave %v, want the resolved address refused by the range rule", err)
	}
}

// The rules are about where this machine's own traffic leaves. A destination a private
// network carries is already routed by that network, and letting a rule about a range
// override it would break every private network the moment somebody wrote a rule about
// 10.0.0.0/8.
func TestARuleDoesNotMoveADestinationAConnectionAlreadyCarries(t *testing.T) {
	r := NewRegistry()
	office := reaching("tn_office", map[string]netip.AddrPort{
		"db.corp:5432": mustAddrPort(t, "10.0.0.5:5432"),
	})
	vpn := reaching("tn_vpn", nil)
	mustAdd(t, r, office, vpn)
	r.SetRoutes([]routing.Rule{{
		ID: "r1", Action: routing.Via, Tunnel: "tn_vpn", CIDR: netip.MustParsePrefix("10.0.0.0/8"),
	}})

	route, err := r.Resolve(context.Background(), "tcp", "db.corp:5432")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != "tn_office" {
		t.Errorf("TunnelID = %q, want the connection that carries the network", route.TunnelID)
	}
}

// A name a rule sends through a connection is resolved by that connection, or the traffic
// is hidden and the list of what it was for is not.
func TestANameSentThroughAConnectionIsResolvedByThatConnection(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", map[string][]netip.Addr{
		"news.example": {netip.MustParseAddr("93.184.216.34")},
	})
	mustAdd(t, r, vpn)
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("this machine's resolver was asked about a name a rule routes elsewhere")
		return netip.AddrPort{}, errors.New("this machine's resolver was asked")
	})
	r.SetRoutes([]routing.Rule{{ID: "r1", Action: routing.Via, Host: "news.example", Tunnel: "tn_vpn"}})

	route, err := r.Resolve(context.Background(), "tcp", "news.example:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Addr != mustAddrPort(t, "93.184.216.34:443") {
		t.Errorf("Addr = %v, want the address the routed connection's resolver gave", route.Addr)
	}
	if len(vpn.asked) != 1 || vpn.asked[0] != "news.example" {
		t.Errorf("the routed connection was asked %v, want the name once", vpn.asked)
	}
}

// The rules are the user's own list and a caller must never be handed the slice the
// registry routes by, or reordering a snapshot would reorder where the machine sends its
// traffic.
func TestTheStoredRulesAreNotTheOnesACallerReadsBack(t *testing.T) {
	r := NewRegistry()
	rules := []routing.Rule{
		{ID: "r1", Action: routing.Direct, Host: "a.example"},
		{ID: "r2", Action: routing.Direct, Host: "b.example"},
	}
	r.SetRoutes(rules)

	rules[0].Host = "changed.example"
	read := r.Routes()
	read[1].Host = "also-changed.example"

	if got := r.Routes(); got[0].Host != "a.example" || got[1].Host != "b.example" {
		t.Errorf("Routes = %+v, want the list the registry was given", got)
	}
}

// Asking which way a destination would go has to be the same function a dial uses, or the
// dashboard's answer and the machine's behaviour can disagree.
func TestAskingWhichWayADestinationGoesUsesTheRulesAsStored(t *testing.T) {
	r := NewRegistry()
	r.SetRoutes([]routing.Rule{{ID: "r1", Action: routing.Via, Host: "**.corp.example", Tunnel: "tn_vpn"}})

	got := r.RouteFor(routing.Request{Host: "db.corp.example"})

	if !got.Decided || got.Tunnel != "tn_vpn" || got.Rule != "r1" {
		t.Errorf("RouteFor = %+v, want the rule that names the connection", got)
	}
	if undecided := r.RouteFor(routing.Request{Host: "news.example"}); undecided.Decided {
		t.Errorf("RouteFor = %+v for a destination no rule names, want no decision", undecided)
	}
}
