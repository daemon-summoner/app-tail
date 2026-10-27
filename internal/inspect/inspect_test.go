// SPDX-License-Identifier: MIT

package inspect

import (
	"net/netip"
	"strings"
	"testing"
)

// compile builds a matcher or fails the test, so the cases below read as the rules they
// are about rather than as error handling.
func compile(t *testing.T, sources ...Source) *Rules {
	t.Helper()
	rules, err := Compile(sources)
	if err != nil {
		t.Fatalf("compile the sources: %v", err)
	}
	return rules
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

// A matcher with nothing in it carries everything. This is the whole difference between
// this package and package access, and getting it backwards would stop every flow on a
// machine whose sources have not downloaded yet.
func TestAMatcherWithNothingInItCarriesEverything(t *testing.T) {
	rules := compile(t)
	if found, ok := rules.Check("example.com", addr(t, "203.0.113.7")); ok {
		t.Errorf("an empty matcher stopped a flow: %+v", found)
	}
	if rules.Count() != 0 {
		t.Errorf("an empty matcher holds %d entries", rules.Count())
	}

	// A nil matcher is what the runner holds before the first compile, and it has to
	// answer the same way rather than panic on the data path. Every reader of the matcher
	// is checked, because a flow reaches whichever one its own path has a value for.
	var absent *Rules
	if _, ok := absent.Check("example.com", addr(t, "203.0.113.7")); ok {
		t.Error("a matcher that has not been built yet stopped a flow")
	}
	if _, ok := absent.Name("example.com"); ok {
		t.Error("a matcher that has not been built yet stopped a name")
	}
	if _, ok := absent.Destination(addr(t, "203.0.113.7")); ok {
		t.Error("a matcher that has not been built yet stopped an address")
	}
	if absent.Count() != 0 || absent.Sources() != nil {
		t.Errorf("a matcher that has not been built yet reports %d entries from %d sources",
			absent.Count(), len(absent.Sources()))
	}
}

// An address inside a denied network is found, and the reason names the network the user
// wrote rather than the single address that hit it -- which is what they have to edit.
func TestAnAddressInsideADeniedNetworkIsFoundAndTheReasonNamesTheNetwork(t *testing.T) {
	rules := compile(t, Source{ID: "manual", Name: "your own entries", Deny: []string{"10.0.0.0/8"}})

	found, ok := rules.Destination(addr(t, "10.4.5.6"))
	if !ok {
		t.Fatal("an address inside a denied network was carried")
	}
	if found.Signal != SignalDestination {
		t.Errorf("the match reports signal %q, want %q", found.Signal, SignalDestination)
	}
	if found.Value != "10.0.0.0/8" {
		t.Errorf("the match names %q, want the network that was written", found.Value)
	}
	if found.Source != "your own entries" {
		t.Errorf("the match credits %q, want the source that carries it", found.Source)
	}
	if !strings.Contains(found.Reason(), "10.0.0.0/8") {
		t.Errorf("the reason is %q, want it to name the network", found.Reason())
	}

	if _, ok := rules.Destination(addr(t, "203.0.113.7")); ok {
		t.Error("an address outside every denied network was stopped")
	}
}

// A bare address is the network holding only it, so a user does not have to write /32 to
// stop one host.
func TestABareAddressStopsThatAddressAndNothingBesideIt(t *testing.T) {
	rules := compile(t, Source{ID: "manual", Deny: []string{"198.51.100.9"}})

	if _, ok := rules.Destination(addr(t, "198.51.100.9")); !ok {
		t.Error("the address that was written was carried")
	}
	if _, ok := rules.Destination(addr(t, "198.51.100.10")); ok {
		t.Error("an address beside the one that was written was stopped")
	}
}

// Two networks holding one address is the ordinary case once there are feeds, and the
// reason has to name the one that actually decided rather than whichever sorted first.
func TestTheMostSpecificDeniedNetworkIsTheOneTheReasonNames(t *testing.T) {
	rules := compile(t,
		Source{ID: "broad", Name: "the broad source", Deny: []string{"10.0.0.0/8"}},
		Source{ID: "narrow", Name: "the narrow source", Deny: []string{"10.1.2.0/24"}},
	)

	found, ok := rules.Destination(addr(t, "10.1.2.3"))
	if !ok {
		t.Fatal("an address two sources both name was carried")
	}
	if found.Value != "10.1.2.0/24" {
		t.Errorf("the match names %q, want the narrower network that actually holds it", found.Value)
	}
	if found.Source != "the narrow source" {
		t.Errorf("the match credits %q, want the source that wrote the network it matched", found.Source)
	}
}

// A resolver answering ::ffff:10.0.0.5 must not slip past an entry naming 10.0.0.0/8:
// the same address, carried or stopped depending on which form the lookup returned, is
// exactly the hole this unmapping exists to close. bart does not unmap on its own.
func TestAnIPv4MappedAddressIsMatchedAsTheIPv4AddressItStandsFor(t *testing.T) {
	rules := compile(t, Source{ID: "manual", Deny: []string{"10.0.0.0/8"}})

	mapped := netip.AddrFrom16(addr(t, "10.0.0.5").As16())
	if !mapped.Is4In6() {
		t.Fatalf("%v is not the mapped form this case is about, so it proves nothing", mapped)
	}
	if _, ok := rules.Destination(mapped); !ok {
		t.Errorf("%v was carried while 10.0.0.5 is stopped", mapped)
	}
}

// An entry can name an IPv4 network in its IPv6-mapped form, which settings accept. It is
// the IPv4 network it stands for, or an exception written that way is never honoured.
func TestANetworkWrittenInItsIPv6MappedFormCoversTheIPv4AddressesInIt(t *testing.T) {
	rules := compile(t, Source{ID: "manual", Deny: []string{"::ffff:10.0.0.0/104"}})
	if _, ok := rules.Destination(addr(t, "10.0.0.5")); !ok {
		t.Error("10.0.0.5 was carried while ::ffff:10.0.0.0/104 is stopped")
	}
	if _, ok := rules.Destination(addr(t, "11.0.0.5")); ok {
		t.Error("11.0.0.5 was stopped by an entry covering only 10.0.0.0/8")
	}
}

// Allow has to beat deny outright rather than by being more specific. A broad allow over
// a narrow deny is the shape a false-positive fix takes once feeds are writing the deny
// entries, and a fix a source could override by being narrower would not be one.
func TestAnAllowedNetworkIsCarriedEvenWhenANarrowerEntryDeniesIt(t *testing.T) {
	rules := compile(t, Source{
		ID:    "manual",
		Allow: []string{"10.0.0.0/8"},
		Deny:  []string{"10.1.2.0/24"},
	})

	if found, ok := rules.Destination(addr(t, "10.1.2.3")); ok {
		t.Errorf("a broad allow lost to a narrower deny: %+v", found)
	}
	// The deny is still real for anything the allow does not cover.
	if _, ok := rules.Destination(addr(t, "192.0.2.1")); ok {
		t.Error("an address no entry names was stopped")
	}
}

// A user typing a domain into a list of things to stop means that domain and what is
// under it, so a subdomain nobody enumerated is still stopped.
func TestADeniedNameCoversWhatIsUnderIt(t *testing.T) {
	rules := compile(t, Source{ID: "manual", Name: "your own entries", Deny: []string{"bad.example"}})

	for _, name := range []string{"bad.example", "c2.bad.example", "deep.c2.bad.example"} {
		found, ok := rules.Name(name)
		if !ok {
			t.Errorf("%q was carried, want it stopped by the name above it", name)
			continue
		}
		if found.Signal != SignalName {
			t.Errorf("%q reports signal %q, want %q", name, found.Signal, SignalName)
		}
		// The reason for a name says the name itself, where the reason for an address says
		// the network the address sits in. Reading the address sentence here would tell a
		// user their name is inside something.
		if want := name + " is named by your own entries"; found.Reason() != want {
			t.Errorf("the reason is %q, want %q", found.Reason(), want)
		}
	}
	if _, ok := rules.Name("notbad.example"); ok {
		t.Error("a name that merely ends with the same text was stopped")
	}
	if _, ok := rules.Name("example"); ok {
		t.Error("the parent of the denied name was stopped")
	}
}

// The same allow-beats-everything rule the resolver's blocklists use, reached through
// the matcher they share rather than through a second set of semantics.
func TestAnAllowedNameIsCarriedEvenWhenADeniedNameCoversIt(t *testing.T) {
	rules := compile(t, Source{
		ID:    "manual",
		Allow: []string{"good.bad.example"},
		Deny:  []string{"bad.example"},
	})

	if found, ok := rules.Name("good.bad.example"); ok {
		t.Errorf("an allowed name was stopped: %+v", found)
	}
	if _, ok := rules.Name("c2.bad.example"); !ok {
		t.Error("the allow took the rest of the denied subtree with it")
	}
}

// Check asks the name first, so a stopped name is stopped before it is resolved and the
// reason names the thing the user typed rather than an address they have never seen.
func TestCheckAnswersWithTheNameBeforeTheAddress(t *testing.T) {
	rules := compile(t, Source{
		ID:   "manual",
		Deny: []string{"bad.example", "10.0.0.0/8"},
	})

	found, ok := rules.Check("bad.example", addr(t, "10.1.1.1"))
	if !ok {
		t.Fatal("a flow both entries name was carried")
	}
	if found.Signal != SignalName {
		t.Errorf("the match reports %q, want the name to answer first", found.Signal)
	}

	// With no name -- which is all the fabric ever has -- the address still answers.
	found, ok = rules.Check("", addr(t, "10.1.1.1"))
	if !ok {
		t.Fatal("a flow with no name was carried past a denied address")
	}
	if found.Signal != SignalDestination {
		t.Errorf("the match reports %q, want the address to answer", found.Signal)
	}

	// With neither, there is nothing to answer and the flow is carried.
	if _, ok := rules.Check("", netip.Addr{}); ok {
		t.Error("a flow with neither a name nor an address was stopped")
	}
}

// An entry that is neither a name nor an address is counted rather than dropped quietly:
// a source that contributed almost nothing has to be able to say so, and validation is
// what stops these being entered in the first place.
func TestEntriesThatAreNeitherANameNorAnAddressAreCounted(t *testing.T) {
	// Both lists are walked, so junk in either has to be counted. A list whose unparseable
	// entries went uncounted would report a source as complete while part of it is missing.
	rules := compile(t, Source{
		ID: "manual",
		Deny: []string{
			"good.example",
			"10.0.0.0/8",
			"not a domain",
			"http://example.com/path",
			"",
			"   ",
		},
		Allow: []string{
			"fine.example",
			"192.0.2.0/24",
			"not a domain either",
			" ",
		},
	})

	stats := rules.Sources()
	if len(stats) != 1 {
		t.Fatalf("the matcher reports %d sources, want the one it was given", len(stats))
	}
	got := stats[0]
	if got.Names != 2 {
		t.Errorf("the source contributed %d names, want the one in each list", got.Names)
	}
	if got.Prefixes != 2 {
		t.Errorf("the source contributed %d networks, want the one in each list", got.Prefixes)
	}
	if got.Skipped != 6 {
		t.Errorf("the source skipped %d entries, want the 6 that are neither", got.Skipped)
	}
	if rules.Count() != 4 {
		t.Errorf("the matcher holds %d entries, want the 4 that parsed", rules.Count())
	}
}

// A match is attributed by an owner byte, so a byte no source stands behind is a build that
// went wrong. It reads as a source that cannot be named rather than as an index off the end
// of the sources, which on the data path is the inspector taking the connection with it.
func TestAMatchWhoseSourceCannotBeNamedSaysSoRatherThanPanicking(t *testing.T) {
	rules := compile(t, Source{ID: "manual", Name: "your own entries"})

	if got := rules.sourceName(uint8(len(rules.sources))); got == "" {
		t.Error("a source past the end of the sources is named by nothing at all")
	}
}

// A network written with bits below its own prefix length is the network the user meant.
// Left unmasked it is an entry bart refuses, which would lose the whole compile.
func TestANetworkWrittenWithHostBitsIsTheNetworkItNames(t *testing.T) {
	rules := compile(t, Source{ID: "manual", Deny: []string{"10.1.2.3/8"}})

	found, ok := rules.Destination(addr(t, "10.9.9.9"))
	if !ok {
		t.Fatal("an address inside the network was carried")
	}
	if found.Value != "10.0.0.0/8" {
		t.Errorf("the match names %q, want the masked network", found.Value)
	}
}

// More sources than the owner byte can name is a build error, not something to truncate:
// silently dropping the sources past the ceiling would stop reporting matches the user
// asked for and never say it had.
func TestMoreSourcesThanTheMatcherCanNameIsRefused(t *testing.T) {
	sources := make([]Source, MaxSources+1)
	for i := range sources {
		sources[i] = Source{ID: "s", Deny: []string{"bad.example"}}
	}
	if _, err := Compile(sources); err == nil {
		t.Error("compiling more sources than the matcher can name succeeded")
	}
}

// A source with no name of its own is still nameable in a reason, because a reason that
// credits nothing tells the user nothing about what to change.
func TestASourceWithNoNameIsCreditedByItsID(t *testing.T) {
	rules := compile(t, Source{ID: "feed_01", Deny: []string{"10.0.0.0/8"}})

	found, ok := rules.Destination(addr(t, "10.0.0.1"))
	if !ok {
		t.Fatal("an address inside the denied network was carried")
	}
	if found.Source != "feed_01" {
		t.Errorf("the match credits %q, want the source's id", found.Source)
	}
}
