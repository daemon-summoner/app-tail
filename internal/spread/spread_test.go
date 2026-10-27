// SPDX-License-Identifier: MIT

package spread

import (
	"net/netip"
	"testing"
)

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

// The property the whole failure behaviour rests on. Losing one of several connections must
// move only what was on it: a destination that moved is a live connection cut, so a scheme
// that reshuffled the rest would cut everything on the machine when one connection dropped.
func TestLosingOneMemberLeavesEveryOtherDestinationWhereItWas(t *testing.T) {
	all := []string{"tn_a", "tn_b", "tn_c", "tn_d", "tn_e"}
	fewer := []string{"tn_a", "tn_b", "tn_c", "tn_d"}

	moved, onLost := 0, 0
	for i := range 256 {
		key := Key(5, netip.AddrFrom4([4]byte{198, 51, byte(i), 7}))
		before, after := Pick(all, key), Pick(fewer, key)
		if before == "tn_e" {
			onLost++
			continue
		}
		if before != after {
			moved++
		}
	}
	if onLost == 0 {
		t.Fatal("no destination was on the member that went away, so nothing was tested")
	}
	if moved != 0 {
		t.Errorf("%d destinations that were not on the lost member moved anyway, and every "+
			"one of those is a live connection cut for no reason", moved)
	}
}

// A member coming back is the same property from the other side: only what it takes back
// moves, and it takes back exactly what it had.
func TestAMemberComingBackTakesBackOnlyWhatItHad(t *testing.T) {
	fewer := []string{"tn_a", "tn_b", "tn_c"}
	all := []string{"tn_a", "tn_b", "tn_c", "tn_d"}

	took := 0
	for i := range 256 {
		key := Key(9, netip.AddrFrom4([4]byte{203, 0, byte(i), 7}))
		before, after := Pick(fewer, key), Pick(all, key)
		switch {
		case after == "tn_d":
			took++
		case before != after:
			t.Fatalf("a destination moved from %q to %q when an unrelated member came back", before, after)
		}
	}
	if took == 0 {
		t.Error("the member that came back was given nothing at all, so it carries no traffic")
	}
}

// The order the members arrived in must decide nothing, or the same set of connections would
// spread differently depending on how the list happened to be sorted.
func TestTheOrderTheMembersWereListedInChangesNothing(t *testing.T) {
	one := []string{"tn_a", "tn_b", "tn_c"}
	other := []string{"tn_c", "tn_a", "tn_b"}

	for i := range 64 {
		key := Key(2, netip.AddrFrom4([4]byte{198, 51, byte(i), 7}))
		if first, second := Pick(one, key), Pick(other, key); first != second {
			t.Fatalf("a destination went to %q listed one way and %q the other", first, second)
		}
	}
}

// Every member has to carry some of it. A hash that piled everything on one of them would
// pass every stickiness test above and spread nothing.
func TestEveryMemberIsGivenSomeOfTheTraffic(t *testing.T) {
	members := []string{"tn_a", "tn_b", "tn_c", "tn_d"}
	got := make(map[string]int)
	for i := range 1024 {
		key := Key(0, netip.AddrFrom4([4]byte{byte(1 + i/256), 51, byte(i), 7}))
		got[Pick(members, key)]++
	}
	for _, id := range members {
		if got[id] == 0 {
			t.Errorf("%q was given none of 1024 destinations", id)
		}
	}
}

// Nothing to pick from is the ordinary single-connection case and has no member to name.
func TestNoMembersNamesNoConnection(t *testing.T) {
	if got := Pick(nil, 7); got != "" {
		t.Errorf("an empty member list named %q", got)
	}
}

// The pin is per block, not per address: the addresses one origin resolves to are one site,
// and giving each its own way out is the failure this key exists to prevent.
func TestEveryAddressInABlockHashesTheSame(t *testing.T) {
	same := Key(4, a("93.184.216.1"))
	for _, addr := range []string{"93.184.216.7", "93.184.216.99", "93.184.216.254"} {
		if got := Key(4, a(addr)); got != same {
			t.Errorf("%s hashed differently from 93.184.216.1, and both are the same site", addr)
		}
	}
	if elsewhere := Key(4, a("93.184.217.1")); elsewhere == same {
		t.Error("two different blocks hashed the same, so nothing would ever be spread")
	}
}

// Both address families pin by the block a routing table actually carries.
func TestTheSixthVersionOfTheInternetPinsByItsOwnBlockSize(t *testing.T) {
	same := Key(4, a("2606:2800:220:1::1"))
	if other := Key(4, a("2606:2800:220:1:ffff::9")); other != same {
		t.Error("two addresses in one /48 hashed differently, so a site on it would be split across connections")
	}
	if elsewhere := Key(4, a("2a00:1450:4009:81f::200e")); elsewhere == same {
		t.Error("two unrelated /48s hashed the same, so nothing would ever be spread")
	}
}

// An address written the other family's way is the same address, so it must pin the same way:
// a v4 destination reached over a v6 socket must not be given a second way out.
func TestAnAddressWrittenTheOtherWayPinsTheSame(t *testing.T) {
	bare := Key(6, a("93.184.216.34"))
	if mapped := Key(6, netip.AddrFrom16(a("93.184.216.34").As16())); mapped != bare {
		t.Error("93.184.216.34 hashed differently written as ::ffff:93.184.216.34, so one site would have two ways out")
	}
}

// The seed is what keeps this machine's spread its own, and it is persisted so a restart does
// not reshuffle which site leaves where.
func TestTwoMachinesWithDifferentSeedsSpreadDifferently(t *testing.T) {
	members := []string{"tn_a", "tn_b", "tn_c", "tn_d"}
	for i := range 64 {
		addr := netip.AddrFrom4([4]byte{198, 51, byte(i), 7})
		if Pick(members, Key(1, addr)) != Pick(members, Key(2, addr)) {
			return
		}
	}
	t.Error("64 destinations landed identically under two seeds, so the seed decides nothing")
}

// The answer has to survive a rebuild of the app: a site that changed which connection it left
// through because the binary was replaced would log people out for no reason. These are the
// values this build produces, pinned so a change to the hash cannot pass unnoticed.
func TestTheAnswerIsTheSameOnEveryBuild(t *testing.T) {
	members := []string{"tn_a", "tn_b", "tn_c"}
	for _, tt := range []struct {
		addr string
		seed uint64
		want string
	}{
		{"93.184.216.34", 0, "tn_c"},
		{"1.1.1.1", 0, "tn_a"},
		{"8.8.8.8", 7, "tn_c"},
		{"2606:2800:220:1::1", 0, "tn_a"},
	} {
		if got := Pick(members, Key(tt.seed, a(tt.addr))); got != tt.want {
			t.Errorf("%s with seed %d goes to %q, want %q -- if the hash was changed on purpose, "+
				"every stored session on every install moves with it", tt.addr, tt.seed, got, tt.want)
		}
	}
}

// A page and the API it calls are separate hosts under one name, and a provider that sees
// them arrive from two addresses treats them as two visitors. Every host under one site has
// to key the same or the mode breaks the sites it is meant to be invisible to.
func TestEveryHostUnderOneSiteIsKeyedTheSame(t *testing.T) {
	want := KeyName(7, "example.test")
	for _, host := range []string{
		"www.example.test",
		"api.example.test",
		"a.b.c.example.test",
		"EXAMPLE.test",
		"www.EXAMPLE.TEST",
		"example.test.",
	} {
		if got := KeyName(7, host); got != want {
			t.Errorf("KeyName(%q) = %d, want %d -- this host would leave a different way "+
				"from the rest of its site", host, got, want)
		}
	}
}

// Different sites are free to leave different ways, which is the whole point of sharing.
func TestDifferentSitesAreKeyedDifferently(t *testing.T) {
	if KeyName(7, "example.test") == KeyName(7, "other.test") {
		t.Error("two different sites share a key, so nothing would ever be shared")
	}
}

// A bare name with no dot in it -- a machine on the local network, or a search-domain
// shorthand -- is still one destination and still keys to something stable.
func TestABareNameIsKeyedAsItStands(t *testing.T) {
	if KeyName(7, "fileserver") != KeyName(7, "FILESERVER") {
		t.Error("one bare name keyed two ways")
	}
	if KeyName(7, "fileserver") == KeyName(7, "printer") {
		t.Error("two bare names share a key")
	}
}

// The seed is what makes one machine's answers its own. Two machines sharing the same set of
// connections should not agree on which site leaves where.
func TestTheMachineSeedChangesWhichWayANameLeaves(t *testing.T) {
	if KeyName(1, "example.test") == KeyName(2, "example.test") {
		t.Error("the seed does not reach the key, so every machine would spread identically")
	}
}

// The seed is derived from the machine's own install identity rather than stored beside it,
// so it survives every restart and differs between machines without a second thing to keep.
func TestTheSeedIsTheMachinesOwnAndIsStableForIt(t *testing.T) {
	machine := "m_abc"
	first := SeedFrom(machine)
	// The same identity read again, which is what a restart does. A seed that came out
	// differently would reshuffle which site leaves where on every start.
	if again := SeedFrom(machine); again != first {
		t.Errorf("SeedFrom(%q) = %d then %d", machine, first, again)
	}
	if SeedFrom("m_abc") == SeedFrom("m_xyz") {
		t.Error("two machines share a seed, so they would spread identically")
	}
}
