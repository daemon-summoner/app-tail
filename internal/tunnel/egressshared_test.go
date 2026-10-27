// SPDX-License-Identifier: MIT

package tunnel

// Internet traffic shared across several connections, from the registry's side: which of
// them a destination leaves through, and what happens to a destination when none of them is
// there to carry it.

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// The whole of sharing: two destinations far enough apart go out through different
// connections, so the set is actually being used rather than one member carrying everything.
func TestDestinationsAreSharedBetweenTheChosenConnections(t *testing.T) {
	r := NewRegistry()
	mustAdd(t, r, reaching("tn_a", nil), reaching("tn_b", nil), reaching("tn_c", nil))
	r.SetEgressMembers([]string{"tn_a", "tn_b", "tn_c"}, 0)

	seen := map[string]bool{}
	for _, addr := range []string{"93.184.216.34", "1.1.1.1", "8.8.8.8", "203.0.113.9", "198.51.100.7"} {
		out, ok := r.EgressFor(netip.MustParseAddr(addr))
		if !ok {
			t.Fatalf("%s got no connection to leave through", addr)
		}
		seen[out.ID()] = true
	}
	if len(seen) < 2 {
		t.Errorf("every destination left through %v, so the set is not being shared", seen)
	}
}

// The stickiness contract, at the registry. Everything one site is made of has to leave the
// same way or the site sees a different visitor per request.
func TestOneSiteAlwaysLeavesTheSameWay(t *testing.T) {
	r := NewRegistry()
	mustAdd(t, r, reaching("tn_a", nil), reaching("tn_b", nil), reaching("tn_c", nil))
	r.SetEgressMembers([]string{"tn_a", "tn_b", "tn_c"}, 99)

	first, ok := r.EgressForName("www.example.test")
	if !ok {
		t.Fatal("the name got no connection to leave through")
	}
	for _, host := range []string{"www.example.test", "api.example.test", "cdn.example.test", "EXAMPLE.TEST", "example.test."} {
		out, ok := r.EgressForName(host)
		if !ok {
			t.Fatalf("%s got no connection to leave through", host)
		}
		if out.ID() != first.ID() {
			t.Errorf("%s leaves through %s, want %s -- one site seen from two addresses",
				host, out.ID(), first.ID())
		}
	}
}

// A member that is not running carries nothing, and the rest carry on. This is the failure
// behaviour the whole feature rests on: losing one connection must not move the destinations
// that were on the others.
func TestAMemberThatIsNotRunningIsSkippedAndTheOthersKeepTheirDestinations(t *testing.T) {
	full := NewRegistry()
	mustAdd(t, full, reaching("tn_a", nil), reaching("tn_b", nil), reaching("tn_c", nil))
	full.SetEgressMembers([]string{"tn_a", "tn_b", "tn_c"}, 5)

	partial := NewRegistry()
	mustAdd(t, partial, reaching("tn_a", nil), reaching("tn_c", nil))
	partial.SetEgressMembers([]string{"tn_a", "tn_b", "tn_c"}, 5)

	var moved, stayed int
	for i := range 60 {
		addr := netip.AddrFrom4([4]byte{203, 0, byte(i), 1})
		before, ok := full.EgressFor(addr)
		if !ok {
			t.Fatalf("%s got no connection to leave through", addr)
		}
		after, ok := partial.EgressFor(addr)
		if !ok {
			t.Fatalf("%s got no connection to leave through with one member down", addr)
		}
		if after.ID() == "tn_b" {
			t.Fatalf("%s left through the connection that is not running", addr)
		}
		if before.ID() == after.ID() {
			stayed++
			continue
		}
		moved++
		if before.ID() != "tn_b" {
			t.Errorf("%s moved from %s to %s, but %s is still running",
				addr, before.ID(), after.ID(), before.ID())
		}
	}
	if moved == 0 || stayed == 0 {
		t.Errorf("%d destinations moved and %d stayed, want the ones on the lost member to move "+
			"and the rest to stay", moved, stayed)
	}
}

// Fail closed. With every chosen connection down, a destination none of them carries has
// nowhere to go -- and this machine's own network is the one answer the setting excludes.
func TestADestinationIsHeldRatherThanSentOutOverThisMachineWhenNoMemberIsRunning(t *testing.T) {
	r := NewRegistry()
	mustAdd(t, r, reaching("tn_local", map[string]netip.AddrPort{
		"db.corp:5432": mustAddrPort(t, "10.0.0.5:5432"),
	}))
	r.SetEgressMembers([]string{"tn_a", "tn_b"}, 0)
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("the lookup reached this machine's own resolver while the traffic was held")
		return mustAddrPort(t, "93.184.216.34:443"), nil
	})

	if _, err := r.Resolve(context.Background(), "tcp", "example.test:443"); !errors.Is(err, ErrEgressHeld) {
		t.Errorf("Resolve = %v, want ErrEgressHeld -- the traffic left over this machine's own network", err)
	}

	// A destination a connection does carry is untouched: holding internet traffic is about
	// the traffic nothing carries, and refusing the rest would take every private network
	// away the moment the internet connections went down.
	route, err := r.Resolve(context.Background(), "tcp", "db.corp:5432")
	if err != nil {
		t.Fatalf("Resolve on a carried destination: %v", err)
	}
	if route.TunnelID != "tn_local" {
		t.Errorf("TunnelID = %q, want the connection that carries it", route.TunnelID)
	}
}

// The address an unrelated connection already resolved takes the same road: it is still a
// destination nothing carries, so it is held for the same reason.
func TestAnAlreadyResolvedDestinationIsHeldToo(t *testing.T) {
	r := NewRegistry()
	other := reaching("tn_other", nil)
	other.resolves = map[string]netip.AddrPort{"example.test:443": mustAddrPort(t, "93.184.216.34:443")}
	mustAdd(t, r, other)
	r.SetEgressMembers([]string{"tn_a"}, 0)

	if _, err := r.Resolve(context.Background(), "tcp", "example.test:443"); !errors.Is(err, ErrEgressHeld) {
		t.Errorf("Resolve = %v, want ErrEgressHeld", err)
	}
}

// Choosing one connection is a route, not a hold: a connection that is down leaves the
// machine on the network it was already on, which is what it was on before the setting was
// touched. Switching from shared back to one connection has to restore that.
func TestChoosingOneConnectionStopsHoldingTheTraffic(t *testing.T) {
	r := NewRegistry()
	mustAdd(t, r, reaching("tn_a", nil))
	r.SetEgressMembers([]string{"tn_b"}, 0)
	if !r.EgressHeld() {
		t.Fatal("EgressHeld is false while the traffic is shared")
	}

	r.SetEgress("tn_b")
	if r.EgressHeld() {
		t.Error("EgressHeld stayed true after one connection was chosen, so a connection that is " +
			"down would take this machine off the internet")
	}
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		return mustAddrPort(t, "93.184.216.34:443"), nil
	})
	route, err := r.Resolve(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Via() != nil {
		t.Error("Via names a connection that is not running")
	}
}

// A name is resolved through the same member that will carry the traffic. Resolving through
// one and dialling through another is the split that has a site load its page from one
// country and its API from another.
func TestANameIsResolvedThroughTheMemberThatWillCarryIt(t *testing.T) {
	r := NewRegistry()
	answers := map[string][]netip.Addr{"example.test": {netip.MustParseAddr("203.0.113.9")}}
	a := resolvingEgress("tn_a", answers)
	b := resolvingEgress("tn_b", answers)
	c := resolvingEgress("tn_c", answers)
	mustAdd(t, r, a, b, c)
	r.SetEgressMembers([]string{"tn_a", "tn_b", "tn_c"}, 3)
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		t.Error("the lookup reached this machine's own resolver")
		return netip.AddrPort{}, nil
	})

	route, err := r.Resolve(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	via := route.Via()
	if via == nil {
		t.Fatal("Via names no connection, so the traffic would leave this machine directly")
	}
	for _, member := range []*resolvingReachingTunnel{a, b, c} {
		asked := len(member.asked) > 0
		if asked != (member.ID() == via.ID()) {
			t.Errorf("%s was asked=%v while the traffic goes through %s -- the lookup and the dial "+
				"took different connections", member.ID(), asked, via.ID())
		}
	}
}
