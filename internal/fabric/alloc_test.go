// SPDX-License-Identifier: MIT

package fabric

import (
	"net/netip"
	"strings"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func carries(id, prefix string) Network { return Network{TunnelID: id, Prefix: p(prefix)} }

// placementFor is the answer for one connection's network, which is what every assertion
// here is about.
func placementFor(t *testing.T, plan Plan, id, prefix string) Placement {
	t.Helper()
	for _, placed := range plan.Placements {
		if placed.TunnelID == id && placed.Prefix == p(prefix) {
			return placed
		}
	}
	t.Fatalf("no placement for %s %s in %+v", id, prefix, plan.Placements)
	return Placement{}
}

// The ordinary case, and the one that must never grow a surprise: nothing collides, so
// every network is reached at its own addresses. Moving one anyway would break every
// address a user has written down, to solve a problem they do not have.
func TestANetworkNothingElseClaimsKeepsItsOwnAddresses(t *testing.T) {
	plan := Allocate([]Network{carries("tn_a", "10.1.0.0/16"), carries("tn_b", "192.168.9.0/24")}, nil, nil)

	if plan.Moves() != 0 {
		t.Errorf("%d networks were moved, want none: %+v", plan.Moves(), plan.Placements)
	}
	if len(plan.Collisions) != 0 {
		t.Errorf("collisions = %+v, want none", plan.Collisions)
	}
	for _, placed := range plan.Placements {
		if placed.PresentedAs.IsValid() || placed.Reason != "" {
			t.Errorf("%+v was moved with nothing in its way", placed)
		}
	}
}

// The headline case: two networks carrying the same addresses. One is reachable at them
// and the other is not, so the second gets somewhere else to live -- inside the pool, and
// the same size, because a /16 presented as a /24 would leave most of it unreachable.
func TestTheSecondNetworkClaimingARangeIsPresentedElsewhere(t *testing.T) {
	plan := Allocate([]Network{carries("tn_work", "10.0.0.0/16"), carries("tn_lab", "10.0.0.0/16")}, nil, nil)

	kept := placementFor(t, plan, "tn_work", "10.0.0.0/16")
	if kept.Moved() {
		t.Errorf("the first connection lost its own addresses: %+v", kept)
	}
	moved := placementFor(t, plan, "tn_lab", "10.0.0.0/16")
	if !moved.Moved() {
		t.Fatal("the second connection was left claiming addresses the first one answers for")
	}
	if !moved.PresentedAs.IsValid() {
		t.Fatalf("nowhere to present it: %+v", moved)
	}
	if moved.PresentedAs.Bits() != 16 {
		t.Errorf("presented as %s, want a range the same size as %s", moved.PresentedAs, moved.Prefix)
	}
	if !DefaultPool[0].Overlaps(moved.PresentedAs) {
		t.Errorf("presented as %s, which is outside the pool %s", moved.PresentedAs, DefaultPool[0])
	}
	if moved.Reason == "" {
		t.Error("a moved network with no reason leaves the dashboard with nothing to explain")
	}
}

// The sentence a plan carries is read by a person, so it names the connection the way that
// person named it. An identifier in it would be a report about "tn_a1b2c3" holding an
// address, which nobody can act on without looking the id up first.
func TestTheReasonNamesTheConnectionHoldingTheRange(t *testing.T) {
	networks := []Network{
		{TunnelID: "tn_work", Name: "office", Prefix: p("10.0.0.0/16")},
		{TunnelID: "tn_lab", Name: "lab", Prefix: p("10.0.0.0/16")},
	}

	plan := Allocate(networks, nil, nil)

	moved := placementFor(t, plan, "tn_lab", "10.0.0.0/16")
	if !strings.Contains(moved.Reason, "office") {
		t.Errorf("reason = %q, want it to name the connection that holds the range", moved.Reason)
	}
	if len(plan.Collisions) != 1 {
		t.Fatalf("collisions = %+v, want one", plan.Collisions)
	}
	if got := plan.Collisions[0]; got.Holder != "tn_work" || got.HolderName != "office" {
		t.Errorf("holder = %q/%q, want the id and the name of the connection that holds it",
			got.Holder, got.HolderName)
	}
}

// The user's own network wins. Presenting the LAN they are sitting on somewhere else to
// make room for a VPN would cut them off from their own printer, and the machine's routes
// are not this app's to move anyway.
func TestAConnectionCollidingWithThisMachinesOwnNetworkIsTheOneThatMoves(t *testing.T) {
	plan := Allocate([]Network{carries("tn_work", "192.168.1.0/24")}, []netip.Prefix{p("192.168.1.0/24")}, nil)

	moved := placementFor(t, plan, "tn_work", "192.168.1.0/24")
	if !moved.Moved() || !moved.PresentedAs.IsValid() {
		t.Fatalf("placement = %+v, want it presented somewhere else", moved)
	}
	if len(plan.Collisions) != 1 {
		t.Fatalf("collisions = %+v, want the one with this machine", plan.Collisions)
	}
	if plan.Collisions[0].Holder != "" {
		t.Errorf("holder = %q, want this machine itself rather than a connection", plan.Collisions[0].Holder)
	}
}

// An overlap is a collision even when the ranges are not identical: a /24 inside another
// connection's /16 is unreachable at its own addresses just the same, and reporting only
// exact matches would leave the commonest real case silent.
func TestARangeInsideAnotherConnectionsRangeCollides(t *testing.T) {
	plan := Allocate([]Network{carries("tn_work", "10.0.0.0/8"), carries("tn_lab", "10.4.5.0/24")}, nil, nil)

	moved := placementFor(t, plan, "tn_lab", "10.4.5.0/24")
	if !moved.Moved() {
		t.Errorf("placement = %+v, want it moved out of the /8 the other connection carries", moved)
	}
	if len(plan.Collisions) != 1 || plan.Collisions[0].Holder != "tn_work" {
		t.Fatalf("collisions = %+v, want one held by tn_work", plan.Collisions)
	}
}

// Nothing is handed out twice. Two networks moved out of the way must not be presented at
// the same address, which would swap one silent collision for another.
func TestTwoMovedNetworksArePresentedAtDifferentAddresses(t *testing.T) {
	plan := Allocate([]Network{
		carries("tn_work", "10.0.0.0/16"),
		carries("tn_lab", "10.0.0.0/16"),
		carries("tn_dc", "10.0.0.0/16"),
	}, nil, nil)

	lab := placementFor(t, plan, "tn_lab", "10.0.0.0/16")
	dc := placementFor(t, plan, "tn_dc", "10.0.0.0/16")
	if !lab.PresentedAs.IsValid() || !dc.PresentedAs.IsValid() {
		t.Fatalf("lab = %+v, dc = %+v, want both presented somewhere", lab, dc)
	}
	if lab.PresentedAs.Overlaps(dc.PresentedAs) {
		t.Errorf("both are presented at %s and %s, which overlap", lab.PresentedAs, dc.PresentedAs)
	}
}

// Every connection claiming one range is reported as one collision naming all of them.
// One report per latecomer would say the same thing three times and hide that they are all
// about a single range.
func TestOneRangeClaimedByManyConnectionsIsReportedOnce(t *testing.T) {
	plan := Allocate([]Network{
		carries("tn_work", "10.0.0.0/16"),
		carries("tn_lab", "10.0.0.0/16"),
		carries("tn_dc", "10.0.0.0/16"),
	}, nil, nil)

	if len(plan.Collisions) != 1 {
		t.Fatalf("collisions = %+v, want one", plan.Collisions)
	}
	claimants := plan.Collisions[0].Claimants
	if len(claimants) != 2 || claimants[0] != "tn_lab" || claimants[1] != "tn_dc" {
		t.Errorf("claimants = %v, want both connections that cannot be reached at it, in order", claimants)
	}
}

// A network too big for the pool cannot be moved at all, and saying so is the point: the
// alternative is a plan that quietly presents a /8 as a /15 and loses most of it.
func TestANetworkTooLargeForThePoolIsReportedRatherThanShrunk(t *testing.T) {
	plan := Allocate([]Network{carries("tn_work", "10.0.0.0/8"), carries("tn_lab", "10.0.0.0/8")}, nil, nil)

	moved := placementFor(t, plan, "tn_lab", "10.0.0.0/8")
	if moved.PresentedAs.IsValid() {
		t.Fatalf("presented as %s, which cannot hold a /8", moved.PresentedAs)
	}
	if !moved.Moved() {
		t.Fatal("a network that cannot be reached at its own addresses was reported as fine")
	}
	if !strings.Contains(moved.Reason, "address range you choose") {
		t.Errorf("reason = %q, want it to say what the user has to do about it", moved.Reason)
	}
}

// The pool is IPv4 today, so an IPv6 collision has nowhere to go. It must still be
// reported: a stated limit costs an afternoon less than one discovered while debugging.
func TestAnIPv6CollisionIsReportedEvenThoughThePoolCannotHoldIt(t *testing.T) {
	plan := Allocate([]Network{carries("tn_work", "fd00:1::/48"), carries("tn_lab", "fd00:1::/48")}, nil, nil)

	moved := placementFor(t, plan, "tn_lab", "fd00:1::/48")
	if !moved.Moved() {
		t.Fatal("an IPv6 range claimed twice was reported as reachable at its own addresses")
	}
	if moved.PresentedAs.IsValid() {
		t.Errorf("presented as %s, from a pool that holds no IPv6", moved.PresentedAs)
	}
	if len(plan.Collisions) != 1 {
		t.Errorf("collisions = %+v, want the IPv6 one", plan.Collisions)
	}
}

// A connection whose range merely sits inside one of this machine's own says so, and names
// the range it is inside. "192.168.1.0/24 is a network this machine is already on" would be
// wrong for a /24 inside the LAN's /16, and the user would go looking for a network of that
// exact size that does not exist.
func TestOverlappingThisMachinesOwnNetworkNamesTheRangeItOverlaps(t *testing.T) {
	plan := Allocate([]Network{carries("tn_work", "10.4.5.0/24")}, []netip.Prefix{p("10.0.0.0/8")}, nil)

	if len(plan.Collisions) != 1 {
		t.Fatalf("collisions = %+v, want the one with this machine", plan.Collisions)
	}
	detail := plan.Collisions[0].Detail
	if !strings.Contains(detail, "overlaps 10.0.0.0/8") || !strings.Contains(detail, "this machine is already on") {
		t.Errorf("detail = %q, want it to name the range of this machine's own that it overlaps", detail)
	}
}

// A connection with no range configured is skipped rather than planned for. A zero range
// overlaps nothing and would be recorded as a placement carrying nothing, which the
// interface would then be asked to route.
func TestAConnectionCarryingNoRangeAtAllIsNotPlanned(t *testing.T) {
	plan := Allocate([]Network{
		{TunnelID: "tn_empty"},
		carries("tn_work", "10.1.0.0/16"),
	}, nil, nil)

	if len(plan.Placements) != 1 || plan.Placements[0].TunnelID != "tn_work" {
		t.Errorf("placements = %+v, want only the connection that carries something", plan.Placements)
	}
}

// Moves is what decides whether there is anything to tell the user at all, so it has to
// count the networks that were actually moved rather than every one that collided: a network
// that collided and had nowhere to go is still not reachable at another address.
func TestTheCountOfMovedNetworksIsTheCountOfMovedNetworks(t *testing.T) {
	plan := Allocate([]Network{
		carries("tn_work", "10.0.0.0/16"),
		carries("tn_lab", "10.0.0.0/16"),
		carries("tn_dc", "192.168.9.0/24"),
	}, nil, nil)

	if plan.Moves() != 1 {
		t.Errorf("%d networks moved, want the one that collided: %+v", plan.Moves(), plan.Placements)
	}
}

// The walk stops at the end of the address family rather than wrapping to zero. A pool at
// the very top of the space is where that is decided, and wrapping would hand out an address
// from the bottom of the space that nothing routes here.
func TestAPoolAtTheEndOfTheAddressSpaceStopsRatherThanWrapping(t *testing.T) {
	pool := []netip.Prefix{p("255.255.255.0/24")}
	host := []netip.Prefix{p("10.0.0.0/24"), p("255.255.255.0/24")}

	plan := Allocate([]Network{carries("tn_work", "10.0.0.0/24")}, host, pool)

	moved := placementFor(t, plan, "tn_work", "10.0.0.0/24")
	if moved.PresentedAs.IsValid() {
		t.Errorf("presented as %s, from past the end of the pool", moved.PresentedAs)
	}
}

// A pool of the whole address space has no range after its first, and the walk has to stop
// there too rather than step off the end of a prefix that covers everything.
func TestAPoolOfEverythingStillRunsOutRatherThanLooping(t *testing.T) {
	pool := []netip.Prefix{p("0.0.0.0/0")}
	host := []netip.Prefix{p("0.0.0.0/0")}

	plan := Allocate([]Network{carries("tn_work", "0.0.0.0/0")}, host, pool)

	moved := placementFor(t, plan, "tn_work", "0.0.0.0/0")
	if moved.PresentedAs.IsValid() {
		t.Errorf("presented as %s out of a pool holding one range that is already claimed", moved.PresentedAs)
	}
}

// The same inputs must produce the same answer twice running, because the addresses in it
// are what a user writes down and what a later run has to keep giving them.
func TestTheSameNetworksProduceTheSamePlan(t *testing.T) {
	networks := []Network{carries("tn_work", "10.0.0.0/16"), carries("tn_lab", "10.0.0.0/16")}

	first := Allocate(networks, []netip.Prefix{p("192.168.1.0/24")}, nil)
	second := Allocate(networks, []netip.Prefix{p("192.168.1.0/24")}, nil)

	if len(first.Placements) != len(second.Placements) {
		t.Fatalf("plans differ in size: %+v vs %+v", first.Placements, second.Placements)
	}
	for i := range first.Placements {
		if first.Placements[i] != second.Placements[i] {
			t.Errorf("placement %d = %+v then %+v", i, first.Placements[i], second.Placements[i])
		}
	}
}

// A pool already in use is not free space. Presenting a network at an address this machine
// is on would move the collision rather than resolve it.
func TestThePoolSkipsRangesThisMachineIsAlreadyOn(t *testing.T) {
	host := []netip.Prefix{p("10.0.0.0/16"), p("198.18.0.0/16")}

	plan := Allocate([]Network{carries("tn_work", "10.0.0.0/16")}, host, nil)

	moved := placementFor(t, plan, "tn_work", "10.0.0.0/16")
	if !moved.PresentedAs.IsValid() {
		t.Fatalf("placement = %+v, want the second half of the pool", moved)
	}
	for _, taken := range host {
		if taken.Overlaps(moved.PresentedAs) {
			t.Errorf("presented as %s, which this machine is already on (%s)", moved.PresentedAs, taken)
		}
	}
}

// The walk through the pool has to stop at its end rather than wrap around and hand out an
// address from the start a second time.
func TestAFullPoolRunsOutRatherThanRepeatingItself(t *testing.T) {
	pool := []netip.Prefix{p("198.18.0.0/24")}
	host := []netip.Prefix{p("10.0.0.0/24"), p("198.18.0.0/24")}

	plan := Allocate([]Network{carries("tn_work", "10.0.0.0/24")}, host, pool)

	moved := placementFor(t, plan, "tn_work", "10.0.0.0/24")
	if moved.PresentedAs.IsValid() {
		t.Errorf("presented as %s out of a pool with nothing free in it", moved.PresentedAs)
	}
	if !moved.Moved() {
		t.Error("a network with nowhere to go was reported as reachable")
	}
}
