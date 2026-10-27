// SPDX-License-Identifier: MIT

package dnsblock

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// build compiles one list under a name, which is what every test here starts from.
func build(t *testing.T, id, name string, entries ...Entry) *Set {
	t.Helper()
	var b Builder
	if err := b.Add(id, name, entries, 0); err != nil {
		t.Fatalf("Add(%s): %v", id, err)
	}
	return b.Build()
}

func exact(names ...string) []Entry {
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		out = append(out, Entry{Name: n, Match: Exact})
	}
	return out
}

func subtree(names ...string) []Entry {
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		out = append(out, Entry{Name: n, Match: Subtree})
	}
	return out
}

// The two match modes are the difference between a hosts file and a filter list, and
// getting one wrong either blocks a domain nobody listed or fails to block the tracker
// under one that was.
func TestBlocksReachesExactlyAsFarAsTheRuleSays(t *testing.T) {
	set := build(t, "test", "Test list",
		append(exact("ads.example.com"), subtree("doubleclick.net")...)...)

	tests := []struct {
		name  string
		query string
		want  bool
		about string
	}{
		{"the exact name", "ads.example.com", true, "the rule names it"},
		{"under an exact name", "img.ads.example.com", false, "a hosts file lists what it wants stopped"},
		{"the parent of an exact name", "example.com", false, "nobody listed the parent"},
		{"the subtree apex", "doubleclick.net", true, "||name^ covers the name itself"},
		{"under a subtree", "ad.g.doubleclick.net", true, "and everything under it"},
		{"the parent of a subtree", "net", false, "a child never blocks its parent"},
		{"a lookalike", "notdoubleclick.net", false, "suffixes match by label, not by text"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			list, ok := set.Blocks(tc.query)
			if ok != tc.want {
				t.Errorf("Blocks(%q) = %v, want %v -- %s", tc.query, ok, tc.want, tc.about)
			}
			if ok && list != "Test list" {
				t.Errorf("Blocks(%q) named %q, want the list a reason can print", tc.query, list)
			}
		})
	}
}

func TestBlocksIgnoresTheCaseAndTrailingDotsAQueryArrivesWith(t *testing.T) {
	set := build(t, "test", "Test list", subtree("doubleclick.net")...)

	for _, query := range []string{"DoubleClick.NET", "doubleclick.net.", "AD.DoubleClick.Net."} {
		if _, ok := set.Blocks(query); !ok {
			t.Errorf("Blocks(%q) = false; a query arrives in whatever case the program used", query)
		}
	}
}

// An allow entry is what a wrongly blocked site is fixed with. A fix a list could override
// would not be one, so it beats every list including the user's own deny entries.
func TestAnAllowEntryBeatsEveryListThatBlocksTheName(t *testing.T) {
	var b Builder
	if err := b.Add("list", "Big list", subtree("example.com"), 0); err != nil {
		t.Fatalf("Add(list): %v", err)
	}
	if err := b.Add("manual", "your own list", []Entry{
		{Name: "cdn.example.com", Match: Subtree, Allow: true},
		{Name: "ads.example.net", Match: Subtree},
	}, 0); err != nil {
		t.Fatalf("Add(manual): %v", err)
	}
	set := b.Build()

	if _, ok := set.Blocks("cdn.example.com"); ok {
		t.Error("Blocks(cdn.example.com) = true; the allow entry has to win or it fixes nothing")
	}
	if _, ok := set.Blocks("img.cdn.example.com"); ok {
		t.Error("Blocks(img.cdn.example.com) = true; an allow entry covers what is under it")
	}
	if _, ok := set.Blocks("www.example.com"); !ok {
		t.Error("Blocks(www.example.com) = false; only the allowed branch is spared")
	}
	if _, ok := set.Blocks("ads.example.net"); !ok {
		t.Error("Blocks(ads.example.net) = false; the manual deny entry still blocks")
	}
}

// The reason names a list, and the list it names decides where somebody goes to switch the
// block off. The first list to carry a name owns it, which is the order the user holds.
func TestTheFirstListToCarryANameIsTheOneTheReasonNames(t *testing.T) {
	var b Builder
	if err := b.Add("first", "First list", subtree("ads.example.com"), 0); err != nil {
		t.Fatalf("Add(first): %v", err)
	}
	if err := b.Add("second", "Second list", subtree("ads.example.com"), 0); err != nil {
		t.Fatalf("Add(second): %v", err)
	}

	list, ok := b.Build().Blocks("ads.example.com")

	if !ok || list != "First list" {
		t.Errorf("Blocks = %q, %v; want the first list that carried the name", list, ok)
	}
}

func TestASetCountsTheNamesItHoldsOnceHoweverManyListsCarryThem(t *testing.T) {
	var b Builder
	if err := b.Add("first", "First", subtree("a.example.com", "b.example.com"), 3); err != nil {
		t.Fatalf("Add(first): %v", err)
	}
	if err := b.Add("second", "Second", subtree("b.example.com", "c.example.com"), 0); err != nil {
		t.Fatalf("Add(second): %v", err)
	}
	set := b.Build()

	if got := set.Rules(); got != 3 {
		t.Errorf("Rules() = %d, want 3: b.example.com is one name however many lists carry it", got)
	}
	stats := set.Lists()
	if len(stats) != 2 {
		t.Fatalf("Lists() returned %d entries, want 2", len(stats))
	}
	if stats[0].Rules != 2 || stats[0].Skipped != 3 {
		t.Errorf("first list reported %+v, want 2 rules and 3 skipped: the card reads this", stats[0])
	}
}

// A nil Set is what every consumer holds before the first list has been read, and the
// switch reads as on the whole time. Panicking there would take the resolver down on the
// first query after a restart.
func TestANilSetBlocksNothingRatherThanPanicking(t *testing.T) {
	var set *Set

	if list, ok := set.Blocks("doubleclick.net"); ok || list != "" {
		t.Errorf("Blocks on a nil set = %q, %v; want nothing blocked", list, ok)
	}
	if !set.Empty() || set.Rules() != 0 || set.Lists() != nil {
		t.Error("a nil set has to report itself as empty rather than as a set of unknown size")
	}
}

func TestABuilderRefusesMoreListsThanTheMatcherCanCredit(t *testing.T) {
	var b Builder
	for i := 0; i < MaxLists; i++ {
		if err := b.Add(fmt.Sprintf("list-%d", i), "List", subtree("example.com"), 0); err != nil {
			t.Fatalf("Add(%d): %v", i, err)
		}
	}

	err := b.Add("one-too-many", "List", subtree("example.com"), 0)

	if err == nil {
		t.Fatal("Add past the ceiling succeeded; the owner byte cannot name that list")
	}
	if !strings.Contains(err.Error(), fmt.Sprint(MaxLists)) {
		t.Errorf("error %q does not say what the limit is", err)
	}
}

// One name being the start of another is what orders the arena at all, and a search that
// stops at the shorter one would block whichever name happened to be packed first.
func TestANameThatIsTheStartOfAnotherIsStillTheOtherName(t *testing.T) {
	set := build(t, "test", "Test list", exact("ab.example", "abc.example")...)

	for _, name := range []string{"ab.example", "abc.example"} {
		if _, ok := set.Blocks(name); !ok {
			t.Errorf("Blocks(%q) = false, but the list carries it", name)
		}
	}
	for _, name := range []string{"a.example", "abcd.example"} {
		if _, ok := set.Blocks(name); ok {
			t.Errorf("Blocks(%q) = true, but no rule carries it", name)
		}
	}

	// One name being every byte of another plus more is where a comparison that stopped at
	// the shorter one would call them equal.
	longer := build(t, "test", "Test list", exact("ads.example")...)
	if _, ok := longer.Blocks("ads.examples"); ok {
		t.Error("Blocks(ads.examples) = true; the rule names a shorter name")
	}
	shorter := build(t, "test", "Test list", exact("ads.examples")...)
	if _, ok := shorter.Blocks("ads.example"); ok {
		t.Error("Blocks(ads.example) = true; the rule names a longer name")
	}
}

// A query arrives as whatever a program passed to the resolver, and a root query normalizes
// to nothing at all. Searching for it would probe the arena with an empty name.
func TestANameThatNormalizesToNothingBlocksNothing(t *testing.T) {
	set := build(t, "test", "Test list", subtree("doubleclick.net")...)

	for _, query := range []string{"", "   ", "."} {
		if list, ok := set.Blocks(query); ok {
			t.Errorf("Blocks(%q) = %q, %v; want nothing blocked", query, list, ok)
		}
	}
}

// The reason is where somebody goes to switch a block off, so it has to name something
// even for a list that arrived without a name.
func TestTheReasonNamesTheListEvenWhenItHasNoNameOfItsOwn(t *testing.T) {
	set := build(t, "work", "   ", subtree("ads.example.com")...)

	list, ok := set.Blocks("ads.example.com")

	if !ok || list != "work" {
		t.Errorf("Blocks = %q, %v; want the list's id when it carries no name", list, ok)
	}
}

// A name credited to a list the set does not hold is a build that went wrong. Saying so is
// what keeps it from reading as a name blocked by nothing.
func TestANameCreditedToAListTheSetLostSaysSo(t *testing.T) {
	set := build(t, "test", "Test list", subtree("ads.example.com")...)
	set.lists = nil

	list, ok := set.Blocks("ads.example.com")

	if !ok {
		t.Fatal("the name stopped being blocked because its list could not be named")
	}
	if !strings.Contains(list, "could not name") {
		t.Errorf("reason names %q, want it to say the list could not be named", list)
	}
}

// A list is entitled to carry a line that normalizes to nothing -- a lone dot, a stray
// space -- and counting it would credit the list with a rule that blocks no name.
func TestAnEntryThatNormalizesToNothingIsNotCountedAsARule(t *testing.T) {
	set := build(t, "test", "Test list",
		Entry{Name: ".", Match: Subtree},
		Entry{Name: "ads.example.com", Match: Subtree})

	if got := set.Rules(); got != 1 {
		t.Errorf("Rules() = %d, want 1: only one line named anything", got)
	}
	if _, ok := set.Blocks("anything.example.org"); ok {
		t.Error("a line that named nothing became a rule blocking everything")
	}
}

// The arena is a binary search over packed bytes rather than a map, and a search that
// disagrees with a map on one name in a million is a name that silently stops being
// blocked. This is the assertion that the packing and the search agree.
func TestTheArenaAgreesWithAPlainMapOverAGeneratedCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(20260831))
	const corpus = 5000

	names := make([]string, 0, corpus)
	want := make(map[string]bool, corpus)
	for i := 0; i < corpus; i++ {
		name := fmt.Sprintf("%s%d.%s.example", string(rune('a'+rng.Intn(26))), rng.Intn(1<<20), string(rune('a'+rng.Intn(26))))
		names = append(names, name)
		want[name] = true
	}
	set := build(t, "corpus", "Corpus", exact(names...)...)

	for _, name := range names {
		if _, ok := set.Blocks(name); !ok {
			t.Fatalf("Blocks(%q) = false, but the corpus carries it", name)
		}
	}
	for i := 0; i < corpus; i++ {
		miss := fmt.Sprintf("miss%d.%s.example", rng.Intn(1<<20), string(rune('a'+rng.Intn(26))))
		if want[miss] {
			continue
		}
		if _, ok := set.Blocks(miss); ok {
			t.Fatalf("Blocks(%q) = true, but no rule carries it", miss)
		}
	}
}
