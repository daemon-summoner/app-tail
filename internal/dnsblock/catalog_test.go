// SPDX-License-Identifier: MIT

package dnsblock

import (
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// Every shipped entry is a URL somebody has to be able to fetch and a format the parser
// knows. A typo here is a list that silently never downloads.
func TestEveryShippedListIsOneTheFetcherAndTheParserBothAccept(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range BuiltIn() {
		if l.ID == "" || seen[l.ID] {
			t.Errorf("%q is a duplicate or empty id, and the id is what the settings point at", l.ID)
		}
		seen[l.ID] = true
		if !l.BuiltIn {
			t.Errorf("%s is in the shipped catalog but does not say it is built in", l.ID)
		}
		if err := Validate(l); err != nil {
			t.Errorf("%s: %v", l.ID, err)
		}
		if !strings.HasPrefix(l.URL, "https://") {
			t.Errorf("%s downloads over %q; a list decides what resolves, so it comes over HTTPS", l.ID, l.URL)
		}
		if l.Format != string(FormatHosts) && l.Format != string(FormatABP) {
			t.Errorf("%s declares format %q; a shipped entry states its shape rather than guessing", l.ID, l.Format)
		}
	}
	if !IsBuiltIn(DefaultListID) {
		t.Errorf("the default list %q is not in the shipped catalog", DefaultListID)
	}
}

// A filter list written for a browser contributes only a fraction of its rules. The note
// is where that is said before somebody switches it on and wonders why nothing changed.
func TestTheListsWrittenForBrowsersCarryANoteSayingSo(t *testing.T) {
	for _, id := range []string{"easylist", "adguard-dns"} {
		if _, ok := ByID(nil, id); !ok {
			t.Fatalf("%s is not in the catalog", id)
		}
		if strings.TrimSpace(Note(id)) == "" {
			t.Errorf("%s carries no note; the caveat has to be on the card, not discovered", id)
		}
	}
}

// Every surface groups the catalog by provider, and a shipped list with no provider would
// land in the group the user's own lists share -- read as something the user added.
func TestEveryShippedListNamesWhoPublishesIt(t *testing.T) {
	for _, l := range BuiltIn() {
		provider := Provider(l)
		if strings.TrimSpace(provider) == "" {
			t.Errorf("%s names no provider", l.ID)
		}
		if provider == UserProvider {
			t.Errorf("%s is grouped with the user's own lists, but it ships with the binary", l.ID)
		}
	}
	if got := Provider(config.Blocklist{ID: "work", Name: "Work list"}); got != UserProvider {
		t.Errorf("a list the user added is grouped under %q, want %q", got, UserProvider)
	}
}

// The catalog is shown in the order it holds, so one provider's lists are next to each
// other only if they are stored that way. A tier that drifted away from its siblings would
// print a second heading for a provider already shown.
func TestTheShippedListsOfOneProviderStayNextToEachOther(t *testing.T) {
	var order []string
	seen := map[string]bool{}
	for _, l := range BuiltIn() {
		provider := Provider(l)
		if len(order) > 0 && order[len(order)-1] == provider {
			continue
		}
		if seen[provider] {
			t.Errorf("%s puts %q back after the catalog had moved on to another provider", l.ID, provider)
		}
		seen[provider] = true
		order = append(order, provider)
	}
	if len(order) < 2 {
		t.Fatalf("the shipped catalog holds %d provider groups, want the several it ships with", len(order))
	}
}

func TestCatalogPutsTheUsersOwnListsAfterTheShippedOnesAndInOneOrder(t *testing.T) {
	user := []config.Blocklist{
		{ID: "zebra", Name: "Zebra"},
		{ID: "apple", Name: "apple"},
	}

	got := Catalog(user)

	if len(got) != len(BuiltIn())+2 {
		t.Fatalf("Catalog returned %d entries, want the shipped ones plus 2", len(got))
	}
	tail := got[len(got)-2:]
	if tail[0].Name != "apple" || tail[1].Name != "Zebra" {
		t.Errorf("user lists came back as %q then %q, want them ordered by name ignoring case", tail[0].Name, tail[1].Name)
	}
	for _, l := range tail {
		if l.BuiltIn {
			t.Errorf("%s came back marked built-in, which is what refuses an edit", l.ID)
		}
	}
}

// A stored list carrying a shipped id would shadow the shipped one, and the shipped one is
// what an edit and a delete are refused against.
func TestCatalogNeverLetsAStoredListShadowAShippedOne(t *testing.T) {
	got := Catalog([]config.Blocklist{{ID: DefaultListID, Name: "Not Hagezi", URL: "https://example.test/x.txt"}})

	for _, l := range got {
		if l.ID == DefaultListID && l.Name == "Not Hagezi" {
			t.Fatal("a stored list replaced the shipped entry it shares an id with")
		}
	}
	if len(got) != len(BuiltIn()) {
		t.Errorf("Catalog returned %d entries, want only the shipped ones", len(got))
	}
}

// An id nothing in the catalog carries is what a stored setting naming a list the user
// deleted looks like. The caller has to hear "not found" rather than a zero list, which it
// would go on to fetch from an empty URL.
func TestByIDFindsAShippedListAndReportsAnIdNothingCarries(t *testing.T) {
	got, ok := ByID(nil, DefaultListID)
	if !ok {
		t.Fatalf("ByID did not find %q, which ships in the catalog", DefaultListID)
	}
	if got.URL == "" {
		t.Errorf("ByID returned %q with no URL", got.ID)
	}

	if _, ok := ByID(nil, "no-such-list"); ok {
		t.Error("ByID claimed to find a list no catalog carries")
	}
}

func TestValidateRefusesAListTheFetcherCouldNotUse(t *testing.T) {
	tests := []struct {
		name string
		list config.Blocklist
		says string
	}{
		{"no name", config.Blocklist{URL: "https://example.test/l.txt"}, "name"},
		{"a name nothing could show", config.Blocklist{Name: strings.Repeat("x", MaxNameLen+1), URL: "https://example.test/l.txt"}, "characters"},
		{"no URL", config.Blocklist{Name: "Mine"}, "URL"},
		{"a scheme nothing fetches", config.Blocklist{Name: "Mine", URL: "ftp://example.test/l.txt"}, "http"},
		{"no host", config.Blocklist{Name: "Mine", URL: "https:///l.txt"}, "host"},
		{"a format the parser does not know", config.Blocklist{Name: "Mine", URL: "https://example.test/l.txt", Format: "rpz"}, "rpz"},
		{"an address that is not a URL at all", config.Blocklist{Name: "Mine", URL: "https://example.test/l%zz.txt"}, "not a URL"},
		{"a list served in the clear", config.Blocklist{Name: "Mine", URL: "http://example.test/l.txt"}, "https://"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.list)

			if err == nil {
				t.Fatalf("Validate(%s) = nil; the agent would store a list nothing can fetch", tc.name)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("Validate(%s) said %q, which does not name what to fix", tc.name, err)
			}
		})
	}
}

// A blocklist decides what the machine stops resolving, so a list fetched in the clear hands
// that decision to anyone on the path: they can drop the entries stopping a threat domain, or
// add ones stopping an update server. The scheme is the only thing standing in the way, so it
// is refused however the URL is spelled.
func TestAListFetchedInTheClearIsRefusedWhicheverWayItIsWritten(t *testing.T) {
	for _, raw := range []string{
		"http://example.test/l.txt",
		"HTTP://example.test/l.txt",
		"  http://example.test/l.txt  ",
		"http://example.test:8080/l.txt",
	} {
		err := ValidateURL(raw)
		if err == nil {
			t.Fatalf("ValidateURL(%q) = nil; the list would be fetched over a connection anyone could rewrite", raw)
		}
		if !strings.Contains(err.Error(), "https://") {
			t.Errorf("ValidateURL(%q) said %q, which does not say what to write instead", raw, err)
		}
	}
}

func TestValidateAcceptsAListThatOnlySaysItsNameAndWhereToGetIt(t *testing.T) {
	if err := Validate(config.Blocklist{Name: "Mine", URL: "https://example.test/l.txt"}); err != nil {
		t.Fatalf("Validate(a list with no format) = %v; auto is what a pasted URL gets", err)
	}
}

func TestNewIDMakesAnIdNothingElseHasAlreadyTaken(t *testing.T) {
	tests := []struct {
		name  string
		from  string
		taken map[string]bool
		want  string
	}{
		{"a plain name", "Work list", nil, "work-list"},
		{"punctuation and runs", "Ad  block-list!", nil, "ad-block-list"},
		{"a name with nothing usable in it", "!!!", nil, "list"},
		{"a name already taken", "Work list", map[string]bool{"work-list": true}, "work-list-2"},
		{"a shipped id", "Hagezi Pro", nil, "hagezi-pro-2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewID(tc.from, func(id string) bool { return tc.taken[id] })

			if got != tc.want {
				t.Errorf("NewID(%q) = %q, want %q", tc.from, got, tc.want)
			}
		})
	}
}

// Two lists with one name leave every row, every reason and every CLI argument ambiguous.
func TestNameTakenIgnoresCaseAndTheListBeingEdited(t *testing.T) {
	user := []config.Blocklist{{ID: "work", Name: "Work list"}}

	if !NameTaken(user, "work LIST", "") {
		t.Error("NameTaken said no to a name that differs only in case")
	}
	if NameTaken(user, "Work list", "work") {
		t.Error("NameTaken said yes to a list's own name, which refuses every edit that keeps it")
	}
	if !NameTaken(nil, "Hagezi Pro", "") {
		t.Error("NameTaken said no to a shipped list's name")
	}
}
