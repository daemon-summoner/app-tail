// SPDX-License-Identifier: MIT

package fabric

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/spread"
)

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

// tableOf builds the lookup or fails the test, since a refused mapping is the subject of its
// own tests below.
func tableOf(t *testing.T, mappings ...Mapping) *Table {
	t.Helper()
	table, err := NewTable(mappings)
	if err != nil {
		t.Fatalf("building the addressing: %v", err)
	}
	return table
}

func at(id, prefix string) Mapping { return Mapping{TunnelID: id, Prefix: p(prefix)} }

func moved(id, prefix, presented string) Mapping {
	return Mapping{TunnelID: id, Prefix: p(prefix), PresentedAs: p(presented)}
}

// The ordinary case: a network nothing collided with is reached at its own addresses, and
// what leaves this machine is the address that was dialled.
func TestAnAddressOnAnUnmovedNetworkIsDialledAsItStands(t *testing.T) {
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))

	dest, ok := table.Lookup(a("10.1.2.3"))
	if !ok {
		t.Fatal("10.1.2.3 belongs to no connection, but tn_office carries 10.1.0.0/16")
	}
	if dest.TunnelID != "tn_office" {
		t.Errorf("carried by %q, want tn_office", dest.TunnelID)
	}
	if dest.Addr != a("10.1.2.3") {
		t.Errorf("dialling %s, want the address that was asked for", dest.Addr)
	}
}

// And the reverse for the same network: a name on a network nothing moved is answered with
// the address the network's own resolver gave, unchanged. Translating it anyway would send
// the program somewhere no route points at, which is a name that resolves and never connects.
func TestANameOnAnUnmovedNetworkIsAnsweredWithItsOwnAddress(t *testing.T) {
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))

	here, ok := table.Present("tn_office", a("10.1.2.3"))
	if !ok {
		t.Fatal("10.1.2.3 on tn_office is reached nowhere on this machine")
	}
	if here != a("10.1.2.3") {
		t.Errorf("reached at %s, want the address the network itself uses", here)
	}
}

// The whole point of the mode. A network reached somewhere else keeps every bit below its
// prefix, so an address a person reads off this machine is recognisable on the network it
// came from -- and, more importantly, is the address the host actually has there.
func TestAMovedNetworkKeepsEveryHostBit(t *testing.T) {
	tests := []struct {
		name              string
		prefix, presented string
		here, inside      string
	}{
		{"a whole byte of prefix", "10.0.0.0/8", "198.0.0.0/8", "198.19.2.3", "10.19.2.3"},
		{"a prefix ending inside a byte", "100.64.0.0/12", "198.16.0.0/12", "198.20.5.6", "100.68.5.6"},
		{"an exact range", "192.168.1.0/24", "198.18.7.0/24", "198.18.7.42", "192.168.1.42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := tableOf(t, moved("tn_lab", tt.prefix, tt.presented))

			dest, ok := table.Lookup(a(tt.here))
			if !ok {
				t.Fatalf("%s belongs to no connection, but tn_lab is reached at %s", tt.here, tt.presented)
			}
			if dest.Addr != a(tt.inside) {
				t.Errorf("dialling %s inside the network, want %s", dest.Addr, tt.inside)
			}

			// And back again, which is what a name lookup is answered with. The two have to
			// agree or a name resolves to an address the packets are not routed to.
			back, ok := table.Present("tn_lab", a(tt.inside))
			if !ok {
				t.Fatalf("%s on tn_lab is reached nowhere on this machine", tt.inside)
			}
			if back != a(tt.here) {
				t.Errorf("%s on tn_lab is reached at %s, want %s", tt.inside, back, tt.here)
			}
		})
	}
}

// Two networks with the same addresses, both reachable at once, which is the requirement the
// whole module exists for. The same address means two different hosts, and which one it
// means is decided by which range on this machine it was dialled at.
func TestTheSameAddressOnTwoNetworksIsTwoDifferentDestinations(t *testing.T) {
	table := tableOf(t,
		at("tn_prod", "10.0.0.0/8"),
		moved("tn_staging", "10.0.0.0/8", "198.0.0.0/8"),
	)

	prod, ok := table.Lookup(a("10.1.2.3"))
	if !ok || prod.TunnelID != "tn_prod" || prod.Addr != a("10.1.2.3") {
		t.Errorf("10.1.2.3 went to %+v, want 10.1.2.3 on tn_prod", prod)
	}
	staging, ok := table.Lookup(a("198.1.2.3"))
	if !ok || staging.TunnelID != "tn_staging" || staging.Addr != a("10.1.2.3") {
		t.Errorf("198.1.2.3 went to %+v, want 10.1.2.3 on tn_staging", staging)
	}
}

// A connection carrying a range inside another's is reached through the narrower one. Taking
// the first or the widest match instead would send a whole subnet to the wrong network while
// every address around it went to the right one -- the hardest shape of this bug to see.
func TestTheNarrowestRangeDecidesWhichConnectionCarriesAnAddress(t *testing.T) {
	wide := at("tn_wide", "10.0.0.0/8")
	narrow := at("tn_narrow", "10.5.0.0/16")

	for _, order := range [][]Mapping{{wide, narrow}, {narrow, wide}} {
		table := tableOf(t, order...)

		inside, ok := table.Lookup(a("10.5.1.1"))
		if !ok || inside.TunnelID != "tn_narrow" {
			t.Errorf("with %s first, 10.5.1.1 went to %q, want tn_narrow", order[0].TunnelID, inside.TunnelID)
		}
		outside, ok := table.Lookup(a("10.6.1.1"))
		if !ok || outside.TunnelID != "tn_wide" {
			t.Errorf("with %s first, 10.6.1.1 went to %q, want tn_wide", order[0].TunnelID, outside.TunnelID)
		}
	}
}

// An address on no connected network is not this module's to answer for. Claiming it would
// take every address on the machine's own network away from the machine.
func TestAnAddressNoConnectionCarriesBelongsToNone(t *testing.T) {
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))

	if dest, ok := table.Lookup(a("192.0.2.7")); ok {
		t.Errorf("192.0.2.7 was claimed by %q", dest.TunnelID)
	}
	if _, ok := table.Present("tn_office", a("192.0.2.7")); ok {
		t.Error("an address outside tn_office's own network was given a place on this machine")
	}
	if _, ok := table.Present("tn_nowhere", a("10.1.2.3")); ok {
		t.Error("a connection with no mapping was given a place on this machine")
	}
}

// A move to a range of a different size cannot be carried out: the substitution keeps every
// host bit, so a /16 presented from a /24 would produce addresses outside what this machine
// routes and the flows would leave through its own network instead.
func TestAMoveToADifferentNumberOfAddressesIsRefused(t *testing.T) {
	tests := []struct {
		name string
		bad  Mapping
		says string
	}{
		{"a different size", moved("tn_a", "10.0.0.0/16", "198.18.7.0/24"), "different number of addresses"},
		{"the other kind of address", Mapping{
			TunnelID: "tn_a", Prefix: p("10.0.0.0/8"), PresentedAs: p("fd00::/8"),
		}, "other kind of address"},
		{"no connection at all", Mapping{Prefix: p("10.0.0.0/8")}, "mapped to no connection"},
		{"no range at all", Mapping{TunnelID: "tn_a"}, "not an address range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTable([]Mapping{tt.bad})
			if err == nil {
				t.Fatalf("%+v was accepted", tt.bad)
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("refused with %q, which does not say %q", err, tt.says)
			}
		})
	}
}

// The routes are what this machine's routing table has to point at the interface. A range
// missing from them is a network that is mapped, dialable and never reached, because nothing
// on the machine sends it here.
func TestTheRoutesAreWhereTheMachineReachesEachNetwork(t *testing.T) {
	table := tableOf(t,
		at("tn_office", "10.1.0.0/16"),
		moved("tn_lab", "10.1.0.0/16", "198.18.0.0/16"),
	)

	routes := table.Routes()
	want := []netip.Prefix{p("10.1.0.0/16"), p("198.18.0.0/16")}
	if len(routes) != len(want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	for _, prefix := range want {
		found := false
		for _, held := range routes {
			if held == prefix {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is carried by a connection and is not routed to the interface: %v", prefix, routes)
		}
	}
}

// A network the allocator found nowhere to move is carried by nothing, and the caller is
// handed it rather than left to notice that it is missing.
func TestANetworkWithNowhereToGoIsReportedRatherThanDropped(t *testing.T) {
	// A /8 does not fit in the default /15 pool, so the second claimant has nowhere to go.
	plan := Allocate([]Network{carries("tn_first", "10.0.0.0/8"), carries("tn_second", "10.0.0.0/8")}, nil, nil)

	mapped, unreachable := MappingsOf(plan)

	if len(unreachable) != 1 || unreachable[0].TunnelID != "tn_second" {
		t.Fatalf("unreachable = %+v, want tn_second alone", unreachable)
	}
	if len(mapped) != 1 || mapped[0].TunnelID != "tn_first" {
		t.Fatalf("mapped = %+v, want tn_first alone", mapped)
	}
	if mapped[0].Moved() {
		t.Errorf("the connection that kept its addresses was mapped as moved: %+v", mapped[0])
	}
}

// The empty table answers for nothing rather than for everything. It is what the fabric runs
// with before any connection is up, and a lookup that succeeded there would send a program's
// first connection into whichever network happened to be registered first.
func TestATableWithNoNetworksCarriesNothing(t *testing.T) {
	var none *Table

	if dest, ok := none.Lookup(a("10.1.2.3")); ok {
		t.Errorf("an empty table claimed 10.1.2.3 for %q", dest.TunnelID)
	}
	if _, ok := none.Present("tn_a", a("10.1.2.3")); ok {
		t.Error("an empty table gave an address a place on this machine")
	}
	if routes := none.Routes(); len(routes) != 0 {
		t.Errorf("an empty table routes %v", routes)
	}
	if held := none.Mappings(); len(held) != 0 {
		t.Errorf("an empty table maps %+v", held)
	}
}

// The translation refuses what it cannot do rather than producing an address. Every one of
// these is a caller that looked an address up against one range and translated it with
// another, and each would otherwise hand back a plausible address on the wrong network --
// the exact failure the addressing exists to prevent.
func TestTranslatingBetweenRangesThatDoNotMatchIsRefused(t *testing.T) {
	tests := []struct {
		name       string
		addr       netip.Addr
		from, to   netip.Prefix
		wantMoved  bool
		wantResult netip.Addr
	}{
		{
			name:       "the same size, so every host bit is kept",
			addr:       a("10.1.2.3"),
			from:       p("10.1.0.0/16"),
			to:         p("198.18.0.0/16"),
			wantMoved:  true,
			wantResult: a("198.18.2.3"),
		},
		{
			name: "a range of a different size, which has no one-to-one answer",
			addr: a("10.1.2.3"),
			from: p("10.1.0.0/16"),
			to:   p("198.18.0.0/24"),
		},
		{
			name: "a range of the other family, which has no answer at all",
			addr: a("10.1.2.3"),
			from: p("10.1.0.0/16"),
			to:   p("fd7a::/16"),
		},
		{
			name: "an address the range being moved from does not contain",
			addr: a("172.16.0.9"),
			from: p("10.1.0.0/16"),
			to:   p("198.18.0.0/16"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := remap(tt.addr, tt.from, tt.to)
			if ok != tt.wantMoved {
				t.Fatalf("remap(%s, %s, %s) succeeded = %v, want %v", tt.addr, tt.from, tt.to, ok, tt.wantMoved)
			}
			if ok && got != tt.wantResult {
				t.Errorf("remap(%s, %s, %s) = %s, want %s", tt.addr, tt.from, tt.to, got, tt.wantResult)
			}
			if !ok && got.IsValid() {
				t.Errorf("a refused translation still produced %s, which a caller would dial", got)
			}
		})
	}
}

// Several connections carrying internet traffic together: one destination gets one of them,
// and asking again gives the same one. A page that opened a second connection to the same
// origin leaving through a different provider is what breaks IP-pinned sessions.
func TestADestinationCarriedBySeveralConnectionsAlwaysGetsTheSameOne(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_a", "tn_b", "tn_c"}, Prefix: p("0.0.0.0/0")})

	first, ok := table.Choose(a("93.184.216.34"), spread.Key(7, a("93.184.216.34")))
	if !ok {
		t.Fatal("93.184.216.34 belongs to no connection, but three carry everything")
	}
	if first.TunnelID != "tn_a" && first.TunnelID != "tn_b" && first.TunnelID != "tn_c" {
		t.Fatalf("carried by %q, which is none of the three members", first.TunnelID)
	}
	for i := 0; i < 20; i++ {
		again, _ := table.Choose(a("93.184.216.34"), spread.Key(7, a("93.184.216.34")))
		if again.TunnelID != first.TunnelID {
			t.Fatalf("the same destination went to %q and then to %q", first.TunnelID, again.TunnelID)
		}
	}
}

// The stickiness is per block rather than per address: the dozen addresses one origin
// resolves to are one site, and giving each its own way out is the failure this key exists
// to prevent.
func TestEveryAddressInABlockLeavesTheSameWay(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_a", "tn_b", "tn_c", "tn_d"}, Prefix: p("0.0.0.0/0")})

	want, _ := table.Choose(a("93.184.216.1"), spread.Key(11, a("93.184.216.1")))
	for _, addr := range []string{"93.184.216.7", "93.184.216.99", "93.184.216.254"} {
		got, _ := table.Choose(a(addr), spread.Key(11, a(addr)))
		if got.TunnelID != want.TunnelID {
			t.Errorf("%s leaves through %q while 93.184.216.1 leaves through %q, "+
				"and both are the same site", addr, got.TunnelID, want.TunnelID)
		}
	}
}

// Two blocks far apart are allowed to differ, or the mode is spreading nothing.
func TestDifferentBlocksCanLeaveThroughDifferentConnections(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_a", "tn_b", "tn_c"}, Prefix: p("0.0.0.0/0")})

	seen := make(map[string]bool)
	for _, addr := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "93.184.216.34",
		"151.101.1.140", "142.250.72.14", "104.16.132.229", "203.0.113.5"} {
		dest, _ := table.Choose(a(addr), spread.Key(3, a(addr)))
		seen[dest.TunnelID] = true
	}
	if len(seen) < 2 {
		t.Errorf("eight destinations all left through %v, so nothing is being spread", seen)
	}
}

// A member that comes back must not move a flow that is already working: the answer is
// checked for still being one of the members, never for being the one they would be given now.
func TestAnAnswerStandsAsLongAsItsConnectionIsStillAMember(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_a", "tn_b", "tn_c"}, Prefix: p("0.0.0.0/0")})

	for _, id := range []string{"tn_a", "tn_b", "tn_c"} {
		held := Destination{TunnelID: id, Addr: a("93.184.216.34")}
		if !table.Still(a("93.184.216.34"), held) {
			t.Errorf("a flow on %q was cut, though %q still carries internet traffic", id, id)
		}
	}
	gone := Destination{TunnelID: "tn_d", Addr: a("93.184.216.34")}
	if table.Still(a("93.184.216.34"), gone) {
		t.Error("a flow on tn_d was kept, though tn_d is not one of the connections carrying anything")
	}
}

// One connection carrying a range on its own keeps the identity test it always had.
func TestAFlowOnASingleConnectionIsCutWhenThatRangeMoves(t *testing.T) {
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))

	if !table.Still(a("10.1.2.3"), Destination{TunnelID: "tn_office", Addr: a("10.1.2.3")}) {
		t.Error("a flow was cut though nothing about its network changed")
	}
	if table.Still(a("10.1.2.3"), Destination{TunnelID: "tn_home", Addr: a("10.1.2.3")}) {
		t.Error("a flow kept a connection that no longer carries the range it is on")
	}
}

// An entry naming only members still answers a caller with no flow to speak for -- a refusal
// being counted, a test reading the table back -- and always with the same one.
func TestARangeWithNoSingleConnectionStillHasAnUnkeyedAnswer(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_b", "tn_a"}, Prefix: p("0.0.0.0/0")})

	dest, ok := table.Lookup(a("93.184.216.34"))
	if !ok {
		t.Fatal("the range several connections carry answered nothing at all")
	}
	if dest.TunnelID != "tn_a" && dest.TunnelID != "tn_b" {
		t.Fatalf("carried by %q, which is neither member", dest.TunnelID)
	}
	if again, _ := table.Lookup(a("93.184.216.34")); again.TunnelID != dest.TunnelID {
		t.Errorf("the unkeyed answer was %q and then %q", dest.TunnelID, again.TunnelID)
	}
}

// Nothing is ever registered under the blocked id, so an entry carrying it keeps the route
// installed and refuses every flow -- which is the difference between traffic stopping and
// traffic quietly going out over this machine's own network.
func TestTheBlockedEntryStillClaimsTheTrafficItRefuses(t *testing.T) {
	table := tableOf(t, Mapping{TunnelID: Blocked, Prefix: p("0.0.0.0/0")})

	routes := table.Routes()
	if len(routes) != 1 || routes[0] != p("0.0.0.0/0") {
		t.Fatalf("the machine routes %v at the interface, want the default route so the traffic is claimed", routes)
	}
	dest, ok := table.Lookup(a("93.184.216.34"))
	if !ok {
		t.Fatal("the default route is installed but nothing answers for an address on it")
	}
	if dest.TunnelID != Blocked {
		t.Errorf("carried by %q, want the id no connection is registered under", dest.TunnelID)
	}
}
