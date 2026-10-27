// SPDX-License-Identifier: MIT

package ipsfeed

import (
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// Every shipped feed is named, grouped and described, because the card shows all three. A feed
// missing any of them is one a user is asked to switch on with nothing to go on.
func TestEveryShippedFeedIsNamedGroupedAndDescribed(t *testing.T) {
	seenID := make(map[string]bool)
	seenName := make(map[string]bool)
	for _, f := range BuiltIn() {
		switch {
		case f.ID == "":
			t.Errorf("a shipped feed has no id: %+v", f)
		case f.Name == "":
			t.Errorf("%s has no name", f.ID)
		case !f.BuiltIn:
			t.Errorf("%s is in the shipped catalog and is not marked as shipped", f.ID)
		case Note(f.ID) == "":
			t.Errorf("%s has no note saying what it is for", f.ID)
		case Provider(f) == UserProvider:
			t.Errorf("%s is in the shipped catalog and is grouped as one of the user's", f.ID)
		}
		if seenID[f.ID] {
			t.Errorf("%s appears twice in the catalog", f.ID)
		}
		seenID[f.ID] = true
		if seenName[strings.ToLower(f.Name)] {
			t.Errorf("two shipped feeds are called %q", f.Name)
		}
		seenName[strings.ToLower(f.Name)] = true

		if err := ValidateURL(f.URL); err != nil {
			t.Errorf("%s ships with a URL it would refuse from a user: %v", f.ID, err)
		}
	}
	if !IsBuiltIn(DefaultFeedID) {
		t.Errorf("the feed a fresh install turns on, %s, is not in the catalog", DefaultFeedID)
	}
}

// A stored copy of a shipped feed would let an old download decide where a shipped id points,
// which is how an edit that was refused lands anyway through the config file.
func TestAStoredCopyOfAShippedFeedNeverShadowsTheShippedOne(t *testing.T) {
	catalog := Catalog([]config.IPSFeed{
		{ID: DefaultFeedID, Name: "Mine", URL: "https://example.test/mine.txt"},
	})

	if len(catalog) != len(BuiltIn()) {
		t.Fatalf("catalog holds %d feeds, want the %d shipped ones", len(catalog), len(BuiltIn()))
	}
	f, ok := ByID(nil, DefaultFeedID)
	if !ok {
		t.Fatalf("%s is missing from the catalog", DefaultFeedID)
	}
	if f.Name == "Mine" {
		t.Error("a stored entry replaced a shipped feed")
	}
}

// The picker is read top to bottom, so the order has to be the same on every load.
func TestTheUsersOwnFeedsFollowTheShippedOnesInAStableOrder(t *testing.T) {
	user := []config.IPSFeed{
		{ID: "b", Name: "beta", URL: "https://example.test/b.txt"},
		{ID: "a", Name: "Alpha", URL: "https://example.test/a.txt"},
	}

	catalog := Catalog(user)

	own := catalog[len(BuiltIn()):]
	if len(own) != 2 {
		t.Fatalf("the user's feeds = %d, want 2", len(own))
	}
	if own[0].ID != "a" || own[1].ID != "b" {
		t.Errorf("order = %s, %s, want alpha then beta regardless of case", own[0].ID, own[1].ID)
	}
	for _, f := range own {
		if f.BuiltIn {
			t.Errorf("%s is the user's and is marked as shipped, which would make it undeletable", f.ID)
		}
		if Provider(f) != UserProvider {
			t.Errorf("%s is grouped under %q, want %q", f.ID, Provider(f), UserProvider)
		}
		if Note(f.ID) != "" {
			t.Errorf("%s carries a note nobody wrote", f.ID)
		}
	}
}

// The body decides which connections this machine refuses, so a feed served in the clear is
// one anybody on the path chooses the contents of.
func TestAFeedFetchedInTheClearIsRefusedAndSaysWhy(t *testing.T) {
	err := ValidateURL("http://example.test/bad.txt")
	if err == nil {
		t.Fatal("a http:// feed was accepted")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error = %q, want it to name what to use instead", err)
	}
}

func TestWhatAFeedMayBeFetchedFrom(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		ok   bool
	}{
		{name: "an ordinary https feed", url: "https://example.test/list.txt", ok: true},
		{name: "nothing at all", url: ""},
		{name: "only spaces", url: "   "},
		{name: "a file on this machine", url: "file:///etc/passwd"},
		{name: "ftp", url: "ftp://example.test/list.txt"},
		{name: "https with no host", url: "https:///list.txt"},
		{name: "not a URL", url: "https://exa mple.test/list.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateURL(tc.url)
			if tc.ok && err != nil {
				t.Errorf("ValidateURL(%q) = %v, want it accepted", tc.url, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("ValidateURL(%q) was accepted", tc.url)
			}
		})
	}
}

func TestAFeedWithoutANameOrWithTooLongAOneIsRefused(t *testing.T) {
	if err := Validate(config.IPSFeed{URL: "https://example.test/list.txt"}); err == nil {
		t.Error("a feed with no name was accepted")
	}
	long := config.IPSFeed{Name: strings.Repeat("n", MaxNameLen+1), URL: "https://example.test/list.txt"}
	if err := Validate(long); err == nil {
		t.Errorf("a name of %d characters was accepted", MaxNameLen+1)
	}
	ok := config.IPSFeed{Name: strings.Repeat("n", MaxNameLen), URL: "https://example.test/list.txt"}
	if err := Validate(ok); err != nil {
		t.Errorf("a name of exactly %d characters was refused: %v", MaxNameLen, err)
	}
}

// The CLI and the card name a feed by what the user called it, so two feeds called "Work"
// make every command naming one a coin flip.
func TestANameAlreadyInUseIsTakenExceptForTheFeedBeingEdited(t *testing.T) {
	user := []config.IPSFeed{{ID: "mine", Name: "Work", URL: "https://example.test/w.txt"}}

	if !NameTaken(user, "work", "") {
		t.Error("a name differing only in case was reported as free")
	}
	if NameTaken(user, "Work", "mine") {
		t.Error("a feed's own name was taken from it while it was being edited")
	}
	if !NameTaken(nil, "FireHOL Level 1", "") {
		t.Error("a shipped feed's name was reported as free")
	}
}

func TestAnIdIsDerivedFromTheNameAndNeverCollides(t *testing.T) {
	free := func(string) bool { return false }

	if got := NewID("Bad  hosts-feed", free); got != "bad-hosts-feed" {
		t.Errorf("NewID = %q, want bad-hosts-feed", got)
	}
	// A name of nothing an id can be made of still has to produce one.
	if got := NewID("!!!", free); got != "feed" {
		t.Errorf("NewID = %q, want feed", got)
	}
	// A name that derives exactly onto a shipped id: taking it would put a user feed where a
	// shipped one already is, and the catalog drops the shadowing entry.
	if got := NewID("firehol level2", free); got != "firehol-level2-2" {
		t.Errorf("NewID = %q, want firehol-level2-2", got)
	}
	taken := func(id string) bool { return id == "work" }
	if got := NewID("Work", taken); got != "work-2" {
		t.Errorf("NewID = %q, want work-2", got)
	}
}
