// SPDX-License-Identifier: MIT

package dnsblock

import (
	"slices"
	"strings"
	"testing"
)

// A rung naming a list the catalog does not carry is a rung that switches nothing on, and
// the settings write behind it would name a list nothing can download.
func TestEveryPresetNamesListsThatShip(t *testing.T) {
	for _, p := range Presets() {
		if len(p.Lists) == 0 {
			t.Errorf("preset %q turns nothing on", p.ID)
		}
		for _, id := range p.Lists {
			if !IsBuiltIn(id) {
				t.Errorf("preset %q names %q, which does not ship in the catalog", p.ID, id)
			}
		}
		if len(slices.Compact(slices.Clone(p.Lists))) != len(p.Lists) {
			t.Errorf("preset %q names a list twice: %v", p.ID, p.Lists)
		}
	}
}

// The ladder is only a ladder if a rung keeps what the rung below it blocks. The one
// exception is a list a wider tier from the same publisher replaces, which is why the
// superseded list has to be gone rather than merely allowed to be.
func TestEachRungKeepsWhatTheRungBelowItBlocks(t *testing.T) {
	all := Presets()
	for i := 1; i < len(all); i++ {
		lower, higher := all[i-1], all[i]
		superseded := presetSteps[i].supersedes
		for _, id := range lower.Lists {
			switch {
			case slices.Contains(superseded, id):
				if slices.Contains(higher.Lists, id) {
					t.Errorf("%s says it supersedes %q and carries it anyway", higher.ID, id)
				}
			case !slices.Contains(higher.Lists, id):
				t.Errorf("%s drops %q, which %s blocks", higher.ID, id, lower.ID)
			}
		}
		for _, id := range superseded {
			if !slices.Contains(lower.Lists, id) {
				t.Errorf("%s supersedes %q, which %s does not carry", higher.ID, id, lower.ID)
			}
		}
		if len(higher.Lists) < len(lower.Lists) {
			t.Errorf("%s turns on %d lists, fewer than %s's %d",
				higher.ID, len(higher.Lists), lower.ID, len(lower.Lists))
		}
	}
}

// The rule the whole ladder is curated against: a rung protects, and a rung never decides
// what somebody is allowed to visit or breaks software that works. These nine lists are the
// ones that do one of those, and they stay one switch away in the catalog instead.
func TestNoRungBlocksACategoryOrBreaksWorkingSoftware(t *testing.T) {
	never := map[string]string{
		"hagezi-gambling":      "a category of site rather than a threat",
		"oisd-nsfw":            "a category of site rather than a threat",
		"stevenblack-gambling": "a category of site rather than a threat",
		"stevenblack-porn":     "a category of site rather than a threat",
		"stevenblack-social":   "a category of site rather than a threat",
		"stevenblack-fakenews": "a category of site rather than a threat",
		"hagezi-hoster":        "blocks every site on a hoster, including the working ones",
		"hagezi-dyndns":        "blocks the dynamic-DNS names home servers answer on",
		"hagezi-doh-bypass":    "blocks the endpoints other VPN and proxy software needs",
	}
	for _, p := range Presets() {
		for _, id := range p.Lists {
			if why, banned := never[id]; banned {
				t.Errorf("preset %q turns on %q, which %s", p.ID, id, why)
			}
		}
	}
}

// The widest tiers accept breakage, which is a bargain only the top rung states. A rung
// below it carrying one would break sites for somebody who chose the level that promised
// not to.
func TestOnlyTheTopRungCarriesTheTiersThatBreakSites(t *testing.T) {
	// Each wide tier against the lowest rung allowed to carry it.
	notBelow := map[string]string{
		"hblock":          "pro",
		"onehosts-xtra":   "ultimate",
		"hagezi-ultimate": "ultimate",
	}
	all := Presets()
	rung := map[string]int{}
	for i, p := range all {
		rung[p.ID] = i
	}
	for _, p := range all {
		for _, id := range p.Lists {
			if lowest, wide := notBelow[id]; wide && rung[p.ID] < rung[lowest] {
				t.Errorf("preset %q turns on %q, a tier wide enough to break working sites and named for %q upwards",
					p.ID, id, lowest)
			}
		}
	}
	top := all[len(all)-1]
	for id := range notBelow {
		if !slices.Contains(top.Lists, id) {
			t.Errorf("the top rung %q does not carry %q, so nothing in the ladder does", top.ID, id)
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
		t.Error("PresetByID dropped the recommended mark, so the card and the CLI never see it")
	}
}

// What the recommended rung is for, stated as the lists it must carry: the eight publishers
// it stacks. A rung that quietly loses one of them is a weaker recommendation wearing the
// same name.
func TestTheRecommendedRungCarriesEveryPublisherItPromises(t *testing.T) {
	high, ok := PresetByID("high")
	if !ok {
		t.Fatal("the ladder has no rung called high")
	}
	for _, id := range []string{
		"oisd-big", "hagezi-normal", "adguard-dns", "easylist", "stevenblack", "easyprivacy",
		"fanboy-annoyance", "someonewhocares", "onehosts-lite", "notrack", "yoyo",
	} {
		if !slices.Contains(high.Lists, id) {
			t.Errorf("the recommended rung does not carry %q", id)
		}
	}
	for _, id := range []string{"oisd-small", "hagezi-proplus", "hagezi-ultimate", "onehosts-xtra"} {
		if slices.Contains(high.Lists, id) {
			t.Errorf("the recommended rung carries %q, which a wider or narrower tier beside it replaces", id)
		}
	}
}

// The card and `app-tail dns block` both say which rung is on by comparing what is
// switched on against the ladder, so the comparison has to be about membership. A user who
// switched the same lists on one at a time is on that rung.
func TestMatchPresetNamesTheRungASetOfListsIs(t *testing.T) {
	medium, ok := PresetByID("medium")
	if !ok {
		t.Fatal("the ladder has no rung called medium")
	}

	shuffled := slices.Clone(medium.Lists)
	slices.Reverse(shuffled)
	if id, ok := MatchPreset(shuffled); !ok || id != "medium" {
		t.Errorf("MatchPreset returned %q/%t for medium's own lists in another order", id, ok)
	}

	if id, ok := MatchPreset(append(slices.Clone(medium.Lists), "easylist")); ok {
		t.Errorf("MatchPreset called a set with an extra list %q", id)
	}
	if id, ok := MatchPreset(medium.Lists[1:]); ok {
		t.Errorf("MatchPreset called a set missing a list %q", id)
	}
	if id, ok := MatchPreset(nil); ok {
		t.Errorf("MatchPreset called an empty set %q", id)
	}
}

// An unknown id has to be refused: treated as the empty preset it would switch every list
// off, which is a typo turning blocking into nothing.
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
