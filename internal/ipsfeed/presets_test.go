// SPDX-License-Identifier: MIT

package ipsfeed

import (
	"slices"
	"strings"
	"testing"
)

// A rung naming a feed the catalog does not carry is a rung that switches nothing on, and the
// settings write behind it would name a feed nothing can download.
func TestEveryPresetNamesFeedsThatShip(t *testing.T) {
	for _, p := range Presets() {
		if len(p.Feeds) == 0 {
			t.Errorf("preset %q turns nothing on", p.ID)
		}
		for _, id := range p.Feeds {
			if !IsBuiltIn(id) {
				t.Errorf("preset %q names %q, which does not ship in the catalog", p.ID, id)
			}
		}
		if len(slices.Compact(slices.Clone(p.Feeds))) != len(p.Feeds) {
			t.Errorf("preset %q names a feed twice: %v", p.ID, p.Feeds)
		}
	}
}

// The ladder is only a ladder if a rung keeps what the rung below it matches. The one
// exception is a feed a wider tier from the same publisher replaces, which is why the
// superseded feed has to be gone rather than merely allowed to be.
func TestEachRungKeepsWhatTheRungBelowItMatches(t *testing.T) {
	all := Presets()
	for i := 1; i < len(all); i++ {
		lower, higher := all[i-1], all[i]
		superseded := presetSteps[i].supersedes
		for _, id := range lower.Feeds {
			switch {
			case slices.Contains(superseded, id):
				if slices.Contains(higher.Feeds, id) {
					t.Errorf("%s says it supersedes %q and carries it anyway", higher.ID, id)
				}
			case !slices.Contains(higher.Feeds, id):
				t.Errorf("%s drops %q, which %s matches", higher.ID, id, lower.ID)
			}
		}
		for _, id := range superseded {
			if !slices.Contains(lower.Feeds, id) {
				t.Errorf("%s supersedes %q, which %s does not carry", higher.ID, id, lower.ID)
			}
		}
		if len(higher.Feeds) < len(lower.Feeds) {
			t.Errorf("%s turns on %d feeds, fewer than %s's %d",
				higher.ID, len(higher.Feeds), lower.ID, len(lower.Feeds))
		}
	}
}

// The rule the whole ladder is curated against. Every shipped feed is either on the top rung,
// replaced there by a wider tier of itself, or deliberately in no rung at all -- and the third
// case is a decision with a reason, never a feed somebody forgot to place. A feed added to the
// catalog and left out of this list fails here rather than quietly belonging to no level.
func TestEveryShippedFeedIsPlacedOnTheLadderOrDeliberatelyLeftOff(t *testing.T) {
	// Feeds a wider tier on the top rung already holds.
	replaced := map[string]string{"ipsum-5": "ipsum-3"}
	// Feeds no rung carries, each with the reason it is a choice rather than protection.
	never := map[string]string{
		"tor-exits": "refusing Tor exits stops Tor working from this machine, and nothing on " +
			"the list is malicious",
	}

	top := Presets()[len(Presets())-1]
	for _, f := range BuiltIn() {
		switch {
		case slices.Contains(top.Feeds, f.ID):
		case replaced[f.ID] != "":
			if !slices.Contains(top.Feeds, replaced[f.ID]) {
				t.Errorf("%q is left off for %q, which the top rung does not carry either",
					f.ID, replaced[f.ID])
			}
		case never[f.ID] != "":
		default:
			t.Errorf("%q is on no rung of the ladder and is not one of the feeds deliberately left off",
				f.ID)
		}
	}

	for _, p := range Presets() {
		for _, id := range p.Feeds {
			if why, banned := never[id]; banned {
				t.Errorf("preset %q turns on %q, and %s", p.ID, id, why)
			}
		}
	}
}

// The widest tiers refuse traffic somebody wanted, which is a bargain only the top rung
// states. A rung below it carrying one would reset connections for somebody who chose the
// level that promised not to.
func TestOnlyTheTopRungCarriesTheFeedsThatRefuseWorkingTraffic(t *testing.T) {
	// Each wide feed against the lowest rung allowed to carry it.
	notBelow := map[string]string{
		"ipsum-3":      "ultimate",
		"blocklist-de": "ultimate",
	}
	all := Presets()
	rung := map[string]int{}
	for i, p := range all {
		rung[p.ID] = i
	}
	for _, p := range all {
		for _, id := range p.Feeds {
			if lowest, wide := notBelow[id]; wide && rung[p.ID] < rung[lowest] {
				t.Errorf("preset %q turns on %q, a feed wide enough to refuse working traffic and named for %q upwards",
					p.ID, id, lowest)
			}
		}
	}
	top := all[len(all)-1]
	for id := range notBelow {
		if !slices.Contains(top.Feeds, id) {
			t.Errorf("the top rung %q does not carry %q, so nothing in the ladder does", top.ID, id)
		}
	}
}

// The lowest rung is what somebody switches inspection on with, and it is the one rung that
// has to be safe to run in prevent mode without reading anything: only networks that are what
// they are for years.
func TestTheLowestRungCarriesOnlyTheFeedsThatDoNotAgeOut(t *testing.T) {
	minimum, ok := PresetByID("minimum")
	if !ok {
		t.Fatal("the ladder has no rung called minimum")
	}
	for _, id := range []string{DefaultFeedID, "spamhaus-drop", "feodo"} {
		if !slices.Contains(minimum.Feeds, id) {
			t.Errorf("the lowest rung does not carry %q", id)
		}
	}
	// Every one of these is somebody's address today and somebody else's next month, which is
	// exactly what the lowest rung may not hold.
	for _, id := range []string{
		"firehol-level2", "firehol-level3", "blocklist-de", "greensnow", "ipsum-3", "ipsum-5",
	} {
		if slices.Contains(minimum.Feeds, id) {
			t.Errorf("the lowest rung carries %q, a feed of addresses that attacked recently rather than networks", id)
		}
	}
}

// The recommended rung is the answer somebody takes without reading the other five. Two of
// them, or none, is the picker back to being a research project.
func TestExactlyOneRungIsRecommended(t *testing.T) {
	var named []string
	for _, p := range Presets() {
		if p.Recommended {
			named = append(named, p.ID)
		}
	}
	if len(named) != 1 {
		t.Fatalf("the rungs marked recommended are %v, want exactly one", named)
	}
	if named[0] != "high" {
		t.Errorf("the recommended rung is %q, want high", named[0])
	}
	if one, ok := PresetByID("high"); !ok || !one.Recommended {
		t.Error("PresetByID dropped the recommended mark, so the card never sees it")
	}
}

// What the recommended rung is for, stated as the feeds it must carry: the independent
// sources it stacks. A rung that quietly loses one of them is a weaker recommendation wearing
// the same name.
func TestTheRecommendedRungCarriesEverySourceItPromises(t *testing.T) {
	high, ok := PresetByID("high")
	if !ok {
		t.Fatal("the ladder has no rung called high")
	}
	for _, id := range []string{
		DefaultFeedID, "spamhaus-drop", "spamhaus-edrop", "feodo", "dshield",
		"emerging-compromised", "firehol-level2", "cins-badguys", "alienvault",
		"binarydefense", "ipsum-5",
	} {
		if !slices.Contains(high.Feeds, id) {
			t.Errorf("the recommended rung does not carry %q", id)
		}
	}
	for _, id := range []string{"firehol-level3", "ipsum-3", "blocklist-de", "tor-exits"} {
		if slices.Contains(high.Feeds, id) {
			t.Errorf("the recommended rung carries %q, which belongs to a wider rung or to no rung", id)
		}
	}
}

// The card says which rung is on by comparing what is switched on against the ladder, so the
// comparison has to be about membership. A user who switched the same feeds on one at a time
// is on that rung.
func TestMatchPresetNamesTheRungASetOfFeedsIs(t *testing.T) {
	medium, ok := PresetByID("medium")
	if !ok {
		t.Fatal("the ladder has no rung called medium")
	}

	shuffled := slices.Clone(medium.Feeds)
	slices.Reverse(shuffled)
	if id, ok := MatchPreset(shuffled); !ok || id != "medium" {
		t.Errorf("MatchPreset returned %q/%t for medium's own feeds in another order", id, ok)
	}

	if id, ok := MatchPreset(append(slices.Clone(medium.Feeds), "tor-exits")); ok {
		t.Errorf("MatchPreset called a set with an extra feed %q", id)
	}
	if id, ok := MatchPreset(medium.Feeds[1:]); ok {
		t.Errorf("MatchPreset called a set missing a feed %q", id)
	}
	if id, ok := MatchPreset(nil); ok {
		t.Errorf("MatchPreset called an empty set %q", id)
	}
}

// An unknown id has to be refused: treated as the empty preset it would switch every feed
// off, which is a typo turning inspection into nothing.
func TestPresetByIDReportsAnIdTheLadderDoesNotCarry(t *testing.T) {
	if _, ok := PresetByID("paranoid"); ok {
		t.Error("PresetByID accepted a rung the ladder does not carry")
	}
	got, ok := PresetByID("ultimate")
	if !ok {
		t.Fatal("PresetByID did not find the top rung")
	}
	if got.Name == "" || got.Summary == "" {
		t.Errorf("rung %q came back without a name or a summary", got.ID)
	}
}

// Every rung is a sentence somebody reads in a picker before choosing it, so an empty or
// duplicated one is a rung nobody can tell from its neighbour.
func TestEveryRungSaysWhatItIsInItsOwnWords(t *testing.T) {
	seen := map[string]string{}
	for _, p := range Presets() {
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Summary) == "" {
			t.Errorf("rung %q has no name or no summary", p.ID)
		}
		if other, dup := seen[p.Summary]; dup {
			t.Errorf("rungs %q and %q say the same thing", other, p.ID)
		}
		seen[p.Summary] = p.ID
	}
}

// The ladder hands out copies. A caller that sorts or appends to what it was given must not
// reorder the rung every other surface reads.
func TestTheLadderHandsOutCopiesRatherThanItsOwnSlices(t *testing.T) {
	first, ok := PresetByID("high")
	if !ok {
		t.Fatal("the ladder has no rung called high")
	}
	held := slices.Clone(first.Feeds)
	slices.Reverse(first.Feeds)
	first.Feeds = append(first.Feeds, "tor-exits")

	again, ok := PresetByID("high")
	if !ok {
		t.Fatal("the ladder lost a rung between two reads")
	}
	if !slices.Equal(again.Feeds, held) {
		t.Errorf("the rung reads back as %v after a caller edited its copy, want %v", again.Feeds, held)
	}

	fromList := Presets()[3]
	slices.Reverse(fromList.Feeds)
	if again, _ := PresetByID(fromList.ID); !slices.Equal(again.Feeds, Presets()[3].Feeds) {
		t.Error("editing what Presets returned changed the ladder")
	}
}
