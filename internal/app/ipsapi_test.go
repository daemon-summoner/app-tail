// SPDX-License-Identifier: MIT

package app

// Traffic inspection as the dashboard and the CLI read it: what the switches add up to,
// and what the rules say about one destination before a connection is made to find out.

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/feeds"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/ipsfeed"
)

// newIPSAPI builds the inspection API over a throwaway store seeded with settings, with the
// rules already reconciled: every case here reads what the agent holds after a pass, which
// is the only state a client can ever see.
func newIPSAPI(t *testing.T, seed func(*config.Settings)) ipsAPI {
	t.Helper()
	return newIPSAPIAt(t, nil, seed)
}

// newIPSAPIWith is the same agent reading its approvals from loadGrants.
func newIPSAPIWith(t *testing.T, loadGrants func() (grants.Document, error), seed func(*config.Settings)) ipsAPI {
	t.Helper()
	api := newUnreconciledIPSAPIWith(t, nil, loadGrants, seed)
	api.a.reconcileIPS()
	return api
}

// newIPSAPIAt is the same with the clock in the case's hands, for the parts of the view that
// are about when something happened rather than what it was.
func newIPSAPIAt(t *testing.T, now *time.Time, seed func(*config.Settings)) ipsAPI {
	t.Helper()
	api := newUnreconciledIPSAPI(t, now, seed)
	api.a.reconcileIPS()
	return api
}

// newUnreconciledIPSAPI is the same agent before the first pass over the settings, which is
// the window between the process starting and the rules being built. A nil clock is the real
// one.
func newUnreconciledIPSAPI(t *testing.T, now *time.Time, seed func(*config.Settings)) ipsAPI {
	t.Helper()
	return newUnreconciledIPSAPIWith(t, now, interceptionApproved, seed)
}

// interceptionApproved is an approvals file in which an administrator approved traffic
// interception, which every case not about the approval itself runs with.
func interceptionApproved() (grants.Document, error) {
	return grants.Document{Version: grants.Version, TLSInterception: true}, nil
}

// newUnreconciledIPSAPIWith is the same agent reading its approvals from loadGrants.
func newUnreconciledIPSAPIWith(t *testing.T, now *time.Time, loadGrants func() (grants.Document, error), seed func(*config.Settings)) ipsAPI {
	t.Helper()
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if seed != nil {
		if _, err := store.Update(func(c *config.Config) error {
			seed(&c.Settings)
			return nil
		}); err != nil {
			t.Fatalf("seed settings: %v", err)
		}
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	opts := Options{Store: store, Runtime: runtime, Getenv: emptyEnv, Logger: quietLogger(), LoadGrants: loadGrants}
	if now != nil {
		opts.Clock = func() time.Time { return *now }
	}
	agent, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ipsAPI{a: agent}
}

// inspecting is the settings of a machine with inspection on and both signals reading, so a
// case only has to say what it is changing about that.
func inspecting(s *config.Settings) {
	s.IPSEnabled = true
	s.IPSMode = config.IPSModeDetect
	s.IPSNames = true
	s.IPSDestinations = true
}

// notMatchingLists switches off the two signals that match against the lists, which a fresh
// install has on. A test describing a machine that runs one signal on its own has to say so:
// left at the default it would describe a machine running that signal and two more, matching
// against lists the test never filled.
func notMatchingLists(s *config.Settings) {
	s.IPSNames = false
	s.IPSDestinations = false
}

func TestInspectionOffSaysSoAndStillStatesWhatItWouldNotCover(t *testing.T) {
	view := newIPSAPI(t, nil).View()

	if view.Enabled {
		t.Error("inspection is on for a fresh install")
	}
	if view.Capability.Degraded {
		t.Error("a module that is off reads as broken rather than as off")
	}
	if !strings.Contains(view.Capability.Reason, "off") {
		t.Errorf("reason = %q, want it to say inspection is off", view.Capability.Reason)
	}
	// The limits are what somebody reads before turning this on, so they hold in every
	// state rather than only in the ones that happen to show a warning.
	if len(view.Capability.Limits) == 0 {
		t.Error("nothing states what inspection does not reach, so a user learns it by hitting it")
	}
}

func TestInspectionOnWithNothingNamedSaysThereIsNothingToMatch(t *testing.T) {
	view := newIPSAPI(t, inspecting).View()

	if view.Rules != 0 {
		t.Errorf("rules = %d, want none from an empty pair of lists", view.Rules)
	}
	if !view.Capability.Degraded {
		t.Fatal("inspection with no entries reads as working")
	}
}

// Reading the start of every connection costs a window per connection, and with the names in
// it not inspected nothing it finds can match. That is the one combination that pays the whole
// price for none of the result, so it is named rather than left to be discovered.
func TestReadingConnectionsWithTheNamesInThemNotInspectedSaysSo(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSNames = false
		s.IPSHandshake = true
		s.IPSDeny = []string{"10.1.2.0/24"}
	}).View()

	if !view.Capability.Degraded {
		t.Fatal("reading connections whose names are not inspected reads as working")
	}
	if !strings.Contains(view.Capability.Reason, "names") {
		t.Errorf("reason = %q, want it to name the switch that is off", view.Capability.Reason)
	}
}

// The switch with nothing written under it is a switch waiting for its first pattern, not a
// fault: the lists go on matching, and nothing is held for a set that matches nothing. A
// machine reported as degraded for it would send somebody to fix a control that is doing all
// it can, on the card of a feature that is working.
func TestBytePatternsSwitchedOnWithNoneWrittenStillReadAsWorking(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSDeny = []string{"bad.example"}
		s.IPSHandshake = true
		s.IPSPayload = true
	})
	view := api.View()

	if !view.Payload {
		t.Fatal("the patterns read as off with the switch on")
	}
	if view.Signatures != 0 {
		t.Errorf("signatures = %d, want none from an empty list", view.Signatures)
	}
	if view.Capability.Degraded {
		t.Errorf("patterns switched on with none written reads as degraded: %s", view.Capability.Reason)
	}
	if api.a.ipsTarget().payload {
		t.Error("the runner is asked to hold a window for an empty pattern set")
	}
}

// With the names not inspected, an empty pattern set leaves the opening bytes read against
// nothing at all, which is the same wasted window as no patterns switch, and is said the same
// way.
func TestBytePatternsSwitchedOnWithNoneWrittenDoNotStandInForTheNames(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSNames = false
		s.IPSDeny = []string{"10.1.2.0/24"}
		s.IPSHandshake = true
		s.IPSPayload = true
	}).View()

	if !view.Capability.Degraded {
		t.Fatal("reading connections against no names and no patterns reads as working")
	}
	if !strings.Contains(view.Capability.Reason, "names") {
		t.Errorf("reason = %q, want it to name the switch that is off", view.Capability.Reason)
	}
}

// The patterns read the same opening bytes against something of their own, so a machine
// running only those is doing exactly what it was set up to do. Reporting it as degraded would
// send somebody to fix a list they deliberately left empty.
func TestBytePatternsAloneReadAsWorking(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		s.IPSEnabled = true
		s.IPSMode = config.IPSModeDetect
		notMatchingLists(s)
		s.IPSHandshake = true
		s.IPSPayload = true
		s.IPSSignatures = []string{`a token that must not leave = "hunter2-9f3a1c"`}
	}).View()

	if view.Signatures != 1 {
		t.Fatalf("signatures = %d, want the one that was written", view.Signatures)
	}
	if view.Capability.Degraded {
		t.Errorf("a machine matching only its own patterns reads as degraded: %s",
			view.Capability.Reason)
	}
}

// The patterns are read out of the same window the start of each connection is read from, so
// without that switch there is nothing to read them against and the setting says so.
func TestBytePatternsAreOffWithoutTheOpeningBytesBeingRead(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSDeny = []string{"bad.example"}
		s.IPSPayload = true
		s.IPSSignatures = []string{`a token that must not leave = "hunter2-9f3a1c"`}
	}).View()

	if view.Payload {
		t.Error("the patterns read as on with the opening bytes not being read")
	}
	if view.Signatures != 0 {
		t.Errorf("signatures = %d, want none compiled while the patterns are off", view.Signatures)
	}
	if view.Capability.Degraded {
		t.Errorf("inspection reads as degraded: %s", view.Capability.Reason)
	}
}

func TestEntriesInForceReadAsWorkingAndAreCounted(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSDeny = []string{"bad.example", "10.1.2.0/24"}
		s.IPSAllow = []string{"good.example"}
	}).View()

	if view.Rules != 3 {
		t.Errorf("rules = %d, want the three entries that were typed", view.Rules)
	}
	if view.Capability.Degraded {
		t.Errorf("inspection with entries in force reads as degraded: %s", view.Capability.Reason)
	}
	if view.CompiledAt == "" {
		t.Error("nothing says when the rules were built")
	}
	if len(view.Deny) != 2 || len(view.Allow) != 1 {
		t.Errorf("view carries %d deny and %d allow entries, want what the settings hold", len(view.Deny), len(view.Allow))
	}
}

func TestAPausedInspectorSaysEveryConnectionIsBeingCarried(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSDeny = []string{"bad.example"}
	})

	api.Pause(15 * time.Minute)
	view := api.View()

	if view.PausedUntil == "" {
		t.Fatal("a pause is in force and nothing says until when")
	}
	if !view.Capability.Degraded || !strings.Contains(view.Capability.Reason, "paused") {
		t.Errorf("capability = %+v, want it to say inspection is paused", view.Capability)
	}

	api.Resume()
	if after := api.View(); after.PausedUntil != "" {
		t.Errorf("pausedUntil = %q after resuming, want it cleared", after.PausedUntil)
	}
}

// The check has to answer what a connection would actually get, which is why it reads the
// mode: a destination that matches in detect mode is carried, and a check reporting it as
// stopped would send somebody looking for a connection failure that never happened.
func TestCheckingADestinationAnswersWithWhatWouldHappenToIt(t *testing.T) {
	detecting := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSDeny = []string{"10.1.2.0/24"}
	})

	carried := detecting.Check("10.1.2.9")
	if !carried.Matched {
		t.Fatal("an address inside a denied network does not match")
	}
	if carried.Refused {
		t.Error("a match in detect mode reads as refused")
	}
	if carried.Value != "10.1.2.0/24" || carried.Source == "" {
		t.Errorf("check = %+v, want the network that matched and what named it", carried)
	}

	preventing := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSMode = config.IPSModePrevent
		s.IPSDeny = []string{"10.1.2.0/24"}
	})
	if stopped := preventing.Check("10.1.2.9"); !stopped.Refused {
		t.Errorf("check = %+v, want it refused while the mode is prevent", stopped)
	}
	if clean := preventing.Check("10.9.9.9"); clean.Matched || clean.Refused {
		t.Errorf("check = %+v, want an address no rule names carried", clean)
	}
}

// A name is only ever inspected on the path that has one, so the check has to answer for the
// switch as it stands rather than for the rules on their own.
func TestCheckingANameWhileNamesAreNotInspectedSaysItIsCarried(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSNames = false
		s.IPSDeny = []string{"bad.example"}
	})

	got := api.Check("bad.example")

	if got.Matched || got.Refused {
		t.Errorf("check = %+v, want it carried while names are not inspected", got)
	}
	if !strings.Contains(got.Reason, "Names") {
		t.Errorf("reason = %q, want it to name the switch that is off", got.Reason)
	}
}

// The same rule as for names, on the other switch: an address is only inspected where the
// addresses connections are bound for are being read.
func TestCheckingAnAddressWhileAddressesAreNotInspectedSaysItIsCarried(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSDestinations = false
		s.IPSDeny = []string{"10.1.2.0/24"}
	})

	got := api.Check("10.1.2.9")

	if got.Matched || got.Refused {
		t.Errorf("check = %+v, want it carried while addresses are not inspected", got)
	}
	if !strings.Contains(got.Reason, "Addresses") {
		t.Errorf("reason = %q, want it to name the switch that is off", got.Reason)
	}
}

// A check answers for the machine as it stands. On an install where inspection was never
// turned on, every destination asked about is carried.
func TestCheckingWhileInspectionIsOffSaysEverythingIsCarried(t *testing.T) {
	api := newIPSAPI(t, nil)

	got := api.Check("bad.example")

	if got.Matched || got.Refused {
		t.Errorf("check = %+v, want it carried while inspection is off", got)
	}
	if !strings.Contains(got.Reason, "off") {
		t.Errorf("reason = %q, want it to say inspection is off", got.Reason)
	}
}

// Between the process starting and the first pass over the settings the module is on and
// there is nothing to match with. Answering "no rule names this" there would be a check
// reporting on rules that do not exist yet.
func TestCheckingBeforeTheRulesAreBuiltSaysThereAreNone(t *testing.T) {
	api := newUnreconciledIPSAPI(t, nil, func(s *config.Settings) {
		inspecting(s)
		s.IPSDeny = []string{"bad.example"}
	})

	got := api.Check("bad.example")

	if got.Matched || got.Refused {
		t.Errorf("check = %+v, want it carried before any rules are compiled", got)
	}
	if !strings.Contains(got.Reason, "compiled") {
		t.Errorf("reason = %q, want it to say no rules are compiled yet", got.Reason)
	}
}

// The ring is the whole of what the card shows on an install where telemetry is off, so a
// match has to reach the view rather than only the counters.
func TestAMatchReachesTheViewWithWhatItWasAndWhereItWasCarried(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSMode = config.IPSModePrevent
		s.IPSDeny = []string{"bad.example"}
	})

	api.a.currentIPS().Refuse(inspect.Flow{
		Name: "bad.example", Where: "the proxy", Protocol: "tcp", Peer: "someone@example",
	})
	view := api.View()

	if view.Matched != 1 || view.Refused != 1 {
		t.Errorf("view counts %d matched and %d refused, want the one connection that was stopped",
			view.Matched, view.Refused)
	}
	if len(view.Recent) != 1 {
		t.Fatalf("the view carries %d recent matches, want the one that happened", len(view.Recent))
	}
	got := view.Recent[0]
	if got.Value != "bad.example" || got.Signal != string(inspect.SignalName) {
		t.Errorf("recent match = %+v, want the name that matched and the signal it matched on", got)
	}
	if !got.Refused || got.Where != "the proxy" || got.Protocol != "tcp" || got.Peer != "someone@example" {
		t.Errorf("recent match = %+v, want what was carried, where, and that it was stopped", got)
	}
	if got.At == "" || got.Reason == "" || got.Source == "" {
		t.Errorf("recent match = %+v, want when it happened and what named it", got)
	}
}

// A pause is why a connection somebody expects to be stopped is carried, so the check has to
// say so rather than report the match as though it were being acted on.
func TestCheckingWhileInspectionIsPausedSaysTheMatchIsCarriedAnyway(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSMode = config.IPSModePrevent
		s.IPSDeny = []string{"bad.example"}
	})
	api.Pause(15 * time.Minute)

	got := api.Check("bad.example")

	if !got.Matched {
		t.Fatal("a denied name does not match while inspection is paused")
	}
	if got.Refused {
		t.Error("a match reads as refused while inspection is paused, so nothing says why it was carried")
	}
	if !strings.Contains(got.Reason, "paused") {
		t.Errorf("reason = %q, want it to say the pause is what carried it", got.Reason)
	}
}

// newIPSFeedAPI is the same API over a store seeded with a whole document rather than only
// settings, for the cases that are about the catalog of feeds rather than the switches.
func newIPSFeedAPI(t *testing.T, seed func(*config.Config)) (ipsAPI, *config.Store) {
	t.Helper()
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if seed != nil {
		if _, err := store.Update(func(c *config.Config) error {
			seed(c)
			return nil
		}); err != nil {
			t.Fatalf("seed feeds: %v", err)
		}
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	agent, err := New(Options{Store: store, Runtime: runtime, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ipsAPI{a: agent}, store
}

func userFeed(id, name, url string) config.IPSFeed {
	return config.IPSFeed{ID: id, Name: name, URL: url}
}

func TestAddingAFeedGivesItAnIdOfItsOwnAndStoresIt(t *testing.T) {
	api, store := newIPSFeedAPI(t, nil)

	created, err := api.CreateFeed(config.IPSFeed{
		Name: "  Work feed  ", URL: " https://feeds.example/work.txt ",
	})

	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	if created.ID == "" || ipsfeed.IsBuiltIn(created.ID) {
		t.Errorf("id = %q, want one of the user's own", created.ID)
	}
	if created.Name != "Work feed" || created.URL != "https://feeds.example/work.txt" {
		t.Errorf("stored %+v, want the name and address trimmed", created)
	}
	if created.BuiltIn {
		t.Error("a feed the user added says it ships with app-tail, so the card would refuse to edit it")
	}
	stored := store.Get().IPSFeeds
	if len(stored) != 1 || stored[0].ID != created.ID {
		t.Errorf("stored %+v, want the one feed that was added", stored)
	}
}

// The card and the CLI name a feed by what the user called it, and two feeds called "Work"
// make every one of those references a coin flip.
func TestAFeedCalledWhatAnotherOneIsCalledIsRefused(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
	})

	_, err := api.CreateFeed(config.IPSFeed{Name: "work FEED", URL: "https://feeds.example/other.txt"})

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("CreateFeed = %v, want a validation failure", err)
	}
	if !strings.Contains(invalid.Message, "already exists") {
		t.Errorf("refusal = %q, which does not say what is wrong", invalid.Message)
	}
	if stored := store.Get().IPSFeeds; len(stored) != 1 {
		t.Errorf("stored %+v, want the refused feed not to have been written", stored)
	}
}

// What a feed holds decides which connections are refused, so a feed fetched over anything
// that can be rewritten in transit hands that decision to whoever can rewrite it.
func TestAFeedNothingCouldFetchSafelyIsRefusedBeforeItIsStored(t *testing.T) {
	api, store := newIPSFeedAPI(t, nil)

	cases := []struct {
		name string
		feed config.IPSFeed
		says string
	}{
		{"no address", config.IPSFeed{Name: "Mine"}, "URL"},
		{"no name", config.IPSFeed{URL: "https://feeds.example/f.txt"}, "name"},
		{"fetched in the clear", config.IPSFeed{Name: "Mine", URL: "http://feeds.example/f.txt"}, "https"},
		{"a scheme nothing fetches", config.IPSFeed{Name: "Mine", URL: "ftp://feeds.example/f.txt"}, "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := api.CreateFeed(tc.feed)

			var invalid *config.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("CreateFeed(%s) = %v, want a validation failure", tc.name, err)
			}
			if !strings.Contains(invalid.Message, tc.says) {
				t.Errorf("refusal = %q, which does not name what to fix", invalid.Message)
			}
		})
	}
	if stored := store.Get().IPSFeeds; len(stored) != 0 {
		t.Errorf("stored %+v, want nothing written for a refused feed", stored)
	}
}

// A shipped feed is what the switch on the card turns on and off. Editing one would leave the
// name "FireHOL level 1" pointing wherever somebody redirected it, and a feed that decides
// which connections are refused is the worst thing to be able to redirect.
func TestAShippedFeedCanBeSwitchedOffButNotEditedOrDeleted(t *testing.T) {
	api, store := newIPSFeedAPI(t, nil)

	_, editErr := api.UpdateFeed(ipsfeed.DefaultFeedID, config.IPSFeed{
		Name: "Not FireHOL", URL: "https://feeds.example/mine.txt",
	})
	deleteErr := api.DeleteFeed(context.Background(), ipsfeed.DefaultFeedID)

	for _, tc := range []struct {
		what string
		err  error
		says string
	}{
		{"edit", editErr, "cannot be edited"},
		{"delete", deleteErr, "switch it off instead"},
	} {
		var invalid *config.ValidationError
		if !errors.As(tc.err, &invalid) {
			t.Fatalf("%s of a shipped feed = %v, want a validation failure", tc.what, tc.err)
		}
		if !strings.Contains(invalid.Message, tc.says) {
			t.Errorf("%s refusal = %q, which does not say what to do instead", tc.what, invalid.Message)
		}
	}
	if stored := store.Get().IPSFeeds; len(stored) != 0 {
		t.Errorf("stored %+v, want a refused write on a shipped feed to store nothing", stored)
	}
}

// The id is what ips.lists names, so an edit that changed it would switch the feed off as a
// side effect of renaming it.
func TestEditingAFeedKeepsItsIdSoTheSettingNamingItStaysValid(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		c.Settings.IPSLists = []string{"work"}
	})

	updated, err := api.UpdateFeed("work", config.IPSFeed{
		ID: "something-else", Name: "Work feed", URL: "https://feeds.example/work-v2.txt",
	})

	if err != nil {
		t.Fatalf("UpdateFeed: %v", err)
	}
	if updated.ID != "work" {
		t.Errorf("id = %q, want it unchanged so the setting still names this feed", updated.ID)
	}
	stored := store.Get().IPSFeeds
	if len(stored) != 1 || stored[0].URL != "https://feeds.example/work-v2.txt" {
		t.Errorf("stored %+v, want the edited address", stored)
	}
}

func TestEditingAFeedThatIsNotThereIsRefusedRatherThanCreatingIt(t *testing.T) {
	api, store := newIPSFeedAPI(t, nil)

	_, err := api.UpdateFeed("ghost", config.IPSFeed{Name: "Ghost", URL: "https://feeds.example/g.txt"})

	if !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("UpdateFeed = %v, want it refused as missing", err)
	}
	if stored := store.Get().IPSFeeds; len(stored) != 0 {
		t.Errorf("stored %+v, want an edit of nothing to have created nothing", stored)
	}
}

// An address that changed is a different feed, so what was downloaded under this id is
// dropped: keeping it would leave the old feed's addresses refusing traffic under the new
// feed's name.
func TestEditingTheAddressOfAFeedDropsTheCopyDownloadedForTheOldOne(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		c.Settings.IPSLists = []string{"work"}
	})
	api.a.ipsFeeds = testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	if err := api.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if api.a.ipsFeeds.stateOf("work").Rules == 0 {
		t.Fatal("nothing was downloaded, so the edit below would prove nothing")
	}

	if _, err := api.UpdateFeed("work", config.IPSFeed{
		Name: "Work feed", URL: "https://feeds.example/work-v2.txt",
	}); err != nil {
		t.Fatalf("UpdateFeed: %v", err)
	}

	if st := api.a.ipsFeeds.stateOf("work"); st.Rules != 0 || !st.FetchedAt.IsZero() {
		t.Errorf("state = %+v, want the copy downloaded for the old address forgotten", st)
	}
}

// The edit is what the user asked for; dropping the copy downloaded for the old address is
// bookkeeping the next round redoes. A copy that will not go away must therefore not turn a
// stored edit into a failure the user has to retry.
func TestEditingAFeedWhoseOldCopyWillNotGoAwayStillStoresTheEdit(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		c.Settings.IPSLists = []string{"work"}
	})
	api.a.ipsFeeds = testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	if err := api.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	jamTheCopy(t, api.a.ipsFeeds, "work")

	if _, err := api.UpdateFeed("work", config.IPSFeed{
		Name: "Work feed", URL: "https://feeds.example/work-v2.txt",
	}); err != nil {
		t.Fatalf("UpdateFeed = %v, want the edit stored regardless of the old copy", err)
	}

	stored := store.Get().IPSFeeds
	if len(stored) != 1 || stored[0].URL != "https://feeds.example/work-v2.txt" {
		t.Errorf("stored feeds = %+v, want the new address", stored)
	}
}

// Deleting a feed removes the copy downloaded for it. One that cannot be removed leaves a file
// on disk under an id nothing points at any more, and the caller has to be told rather than
// shown a delete that reported success.
func TestDeletingAFeedWhoseCopyWillNotGoAwayIsReportedRatherThanReportedDone(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		c.Settings.IPSLists = []string{"work"}
	})
	api.a.ipsFeeds = testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	if err := api.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Switched off, because a feed in use is refused the delete before the copy is reached.
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.IPSLists = nil
		return nil
	}); err != nil {
		t.Fatalf("switch the feed off: %v", err)
	}
	jamTheCopy(t, api.a.ipsFeeds, "work")

	err := api.DeleteFeed(context.Background(), "work")

	if err == nil {
		t.Fatal("DeleteFeed reported success while the downloaded copy is still on disk")
	}
	if !strings.Contains(err.Error(), "remove the downloaded copy of work") {
		t.Errorf("error = %q, which does not name what is still there", err)
	}
}

// Deleting a feed that is switched on would leave ips.lists naming something nothing can
// download, and the first place that shows up is inspection quietly missing a feed.
func TestDeletingAFeedThatIsSwitchedOnIsRefused(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		inspecting(&c.Settings)
		c.Settings.IPSLists = []string{"work"}
	})

	resp, body := h.request(http.MethodDelete, "/api/ips/feeds/work", nil)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DELETE /api/ips/feeds/work = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "switch it off before deleting it") {
		t.Errorf("body = %s, want it to say how to get out of the refusal", body)
	}
	if stored := h.store.Get().IPSFeeds; len(stored) != 1 {
		t.Errorf("stored %+v, want the refused delete to have kept the feed", stored)
	}
}

func TestDeletingAFeedNothingIsUsingRemovesIt(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds,
			userFeed("work", "Work feed", "https://feeds.example/work.txt"),
			userFeed("spare", "Spare", "https://feeds.example/spare.txt"))
		inspecting(&c.Settings)
		c.Settings.IPSLists = []string{"work"}
	})

	resp, body := h.request(http.MethodDelete, "/api/ips/feeds/spare", nil)

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/ips/feeds/spare = %d, want 204: %s", resp.StatusCode, body)
	}
	stored := h.store.Get().IPSFeeds
	if len(stored) != 1 || stored[0].ID != "work" {
		t.Errorf("stored %+v, want only the feed that was left alone", stored)
	}
}

// The card renders the shipped catalog and the user's own together, because a switch that
// showed only one of them would leave the other unreachable.
func TestTheFeedsTheCardRendersAreTheShippedCatalogAndTheUsersOwn(t *testing.T) {
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		c.Settings.IPSLists = []string{ipsfeed.DefaultFeedID}
	})

	view := api.View()

	if len(view.Feeds) != len(ipsfeed.BuiltIn())+1 {
		t.Fatalf("feeds = %d, want the shipped catalog and the one feed added", len(view.Feeds))
	}
	var shipped, mine bool
	for _, f := range view.Feeds {
		if f.ID == ipsfeed.DefaultFeedID {
			shipped = true
			if !f.BuiltIn || !f.Enabled || f.Provider == "" {
				t.Errorf("feed = %+v, want the shipped one reported as switched on and attributed", f)
			}
		}
		if f.ID == "work" {
			mine = true
			if f.BuiltIn || f.Enabled {
				t.Errorf("feed = %+v, want the user's own reported as theirs and switched off", f)
			}
		}
	}
	if !shipped || !mine {
		t.Errorf("feeds = %+v, want both catalogs on the card", view.Feeds)
	}
	if view.RefreshHours != config.DefaultIPSRefreshHours {
		t.Errorf("refreshHours = %d, want the default when the setting was never written",
			view.RefreshHours)
	}
}

// A card with a feed switched on and nothing downloaded says a download is owed rather than
// telling somebody to name something: the two are different states and only one of them is
// theirs to fix.
func TestAFeedSwitchedOnWithNothingDownloadedSaysADownloadIsOwed(t *testing.T) {
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.Settings.IPSLists = []string{ipsfeed.DefaultFeedID}
	})

	view := api.View()

	if view.Rules != 0 {
		t.Fatalf("rules = %d, want nothing in force before anything is downloaded", view.Rules)
	}
	if !view.Capability.Degraded || !strings.Contains(view.Capability.Reason, "Refresh") {
		t.Errorf("capability = %+v, want it to say the chosen feeds have not been downloaded",
			view.Capability)
	}
}

// A round that could not download anything has to reach the card. Every feed keeps the copy
// it already has, so nothing else on the card changes, and a user with no way to see the
// failure is a user whose feeds quietly stop being updated.
func TestARoundOfFeedsThatFailedIsOnTheCardUntilOneSucceeds(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.IPSFeeds = append(c.IPSFeeds, testFeed())
		c.Settings.IPSLists = []string{"test"}
	})
	down := true
	api.a.ipsFeeds = testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			if down {
				return feeds.Fetched{}, errors.New("the network is down")
			}
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})

	if err := api.Refresh(context.Background()); err == nil {
		t.Fatal("a refresh that downloaded nothing reported success")
	}
	if got := api.View().Error; !strings.Contains(got, "the network is down") {
		t.Errorf("the card carries %q, want the reason the round failed", got)
	}

	down = false
	if err := api.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh once the network is back: %v", err)
	}
	view := api.View()
	if view.Error != "" {
		t.Errorf("the card still carries %q after a round that succeeded", view.Error)
	}
	if view.NextRefresh == "" {
		t.Error("nothing says when the feeds are fetched again, so a stale copy reads as a fresh one")
	}
}

func TestEditingAFeedIntoOneNothingCouldFetchIsRefused(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
	})

	_, err := api.UpdateFeed("work", config.IPSFeed{Name: "Work feed", URL: "http://feeds.example/work.txt"})

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("UpdateFeed = %v, want a validation failure", err)
	}
	if !strings.Contains(invalid.Message, "https") {
		t.Errorf("refusal = %q, which does not name what to fix", invalid.Message)
	}
	if stored := store.Get().IPSFeeds; stored[0].URL != "https://feeds.example/work.txt" {
		t.Errorf("stored %+v, want the refused edit not to have been written", stored)
	}
}

// Renaming a feed to what another one is already called is the same coin flip as adding one
// under that name, and the feed being edited is not its own conflict.
func TestRenamingAFeedOntoAnotherOnesNameIsRefused(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds,
			userFeed("work", "Work feed", "https://feeds.example/work.txt"),
			userFeed("spare", "Spare", "https://feeds.example/spare.txt"))
	})

	_, err := api.UpdateFeed("spare", config.IPSFeed{Name: "work FEED", URL: "https://feeds.example/spare.txt"})

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("UpdateFeed = %v, want a validation failure", err)
	}
	if !strings.Contains(invalid.Message, "already exists") {
		t.Errorf("refusal = %q, which does not say what is wrong", invalid.Message)
	}

	// The same name on the same feed is not a conflict, or nothing could ever be edited.
	if _, err := api.UpdateFeed("spare", config.IPSFeed{
		Name: "Spare", URL: "https://feeds.example/spare-v2.txt",
	}); err != nil {
		t.Fatalf("UpdateFeed keeping its own name: %v", err)
	}
	if stored := store.Get().IPSFeeds; stored[1].URL != "https://feeds.example/spare-v2.txt" {
		t.Errorf("stored %+v, want the edit that kept its own name written", stored)
	}
}

// An id is the catalog's to hand out. A feed added under one something else already holds gets
// its own, or the switch on the card would move traffic between two feeds.
func TestAFeedAddedUnderAnIdSomethingElseHoldsGetsItsOwn(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
	})

	created, err := api.CreateFeed(config.IPSFeed{
		ID: "work", Name: "Other feed", URL: "https://feeds.example/other.txt",
	})

	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	if created.ID == "work" {
		t.Error("a feed was added under an id another one holds, so one of them is unreachable")
	}
	stored := store.Get().IPSFeeds
	if len(stored) != 2 || stored[0].URL != "https://feeds.example/work.txt" {
		t.Errorf("stored %+v, want the feed that was already there left alone", stored)
	}
}

func TestDeletingAFeedNothingHasHeardOfIsRefused(t *testing.T) {
	api, _ := newIPSFeedAPI(t, nil)

	err := api.DeleteFeed(context.Background(), "ghost")

	if !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("DeleteFeed = %v, want it refused as missing", err)
	}
}

// A settings document written before the interval existed carries it back-filled, and a card
// showing an interval of zero would describe a schedule that does not exist.
func TestTheCardShowsTheDefaultIntervalWhenTheSettingWasWrittenWithoutIt(t *testing.T) {
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.Settings.IPSRefreshHours = 0
	})

	if got := api.View().RefreshHours; got != config.DefaultIPSRefreshHours {
		t.Errorf("refreshHours = %d, want %d", got, config.DefaultIPSRefreshHours)
	}
}

// One copy nothing can read is not the other feeds' problem: what is left still compiles, and
// the failure is already recorded against the feed it belongs to.
func TestACopyThatCannotBeReadLeavesTheOtherFeedsMatching(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.IPSFeeds = append(c.IPSFeeds,
			config.IPSFeed{ID: "broken", Name: "Broken feed", URL: "https://feeds.example/broken.txt"},
			testFeed())
		c.Settings.IPSLists = []string{"broken", "test"}
	})
	runner := testFeedRunner(t, func() time.Time { return clock },
		func(_ context.Context, rawURL string, _ feeds.State) (feeds.Fetched, error) {
			if strings.Contains(rawURL, "broken") {
				return feeds.Fetched{Body: []byte("203.0.113.9\n")}, nil
			}
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	api.a.ipsFeeds = runner
	if err := api.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// A directory where the copy should be: the file is there and unreadable, which is the
	// state a half-written disk leaves behind.
	replaceCopyWithADirectory(t, runner, "broken")

	api.a.reconcileIPS()

	view := api.View()
	if view.Rules == 0 {
		t.Error("one unreadable copy left nothing in force, so a single bad file switched inspection off")
	}
}

// A level is the whole point of the ladder: one click replaces the shipped feeds that are on.
// What it must not do is switch off a feed the user went and found -- no rung names those, and
// losing one to a level change is losing something app-tail never offered.
func TestSwitchingInspectionToALevelTurnsOnItsFeedsAndKeepsTheUsersOwn(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		inspecting(&c.Settings)
		c.Settings.IPSLists = []string{"tor-exits", "work"}
	})
	medium, ok := ipsfeed.PresetByID("medium")
	if !ok {
		t.Fatal("the ladder has no rung called medium")
	}

	if err := api.ApplyPreset(context.Background(), "medium"); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}

	got := store.Get().Settings.IPSLists
	want := append(slices.Clone(medium.Feeds), "work")
	if !slices.Equal(got, want) {
		t.Errorf("the feeds switched on are %v, want %v", got, want)
	}
	if slices.Contains(got, "tor-exits") {
		t.Error("tor-exits stayed on, so the level added to what was there rather than replacing it")
	}
	if view := api.View(); view.Preset != "medium" {
		t.Errorf("the card says the level is %q, want medium: a feed the user added is not a rung of its own", view.Preset)
	}
}

// A rung nothing carries applied as the empty set would switch every feed off, which is a typo
// reading as inspection that is on and matching nothing.
func TestALevelOfInspectionTheLadderDoesNotCarryIsRefusedAndLeavesTheFeedsAlone(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.Settings.IPSLists = []string{ipsfeed.DefaultFeedID}
	})

	err := api.ApplyPreset(context.Background(), "paranoid")

	if err == nil {
		t.Fatal("a level nothing carries was accepted")
	}
	if !strings.Contains(err.Error(), "ultimate") {
		t.Errorf("the refusal reads %q, want it to name the levels there are", err)
	}
	if got := store.Get().Settings.IPSLists; !slices.Equal(got, []string{ipsfeed.DefaultFeedID}) {
		t.Errorf("the feeds switched on are %v, want the ones that were on before the refusal", got)
	}
}

// The card marks the level in force, and a set that is nobody's level has to read as exactly
// that rather than as the nearest one.
func TestTheCardCallsASetOfFeedsThatIsNobodysLevelNothing(t *testing.T) {
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		inspecting(&c.Settings)
		c.Settings.IPSLists = []string{ipsfeed.DefaultFeedID, "tor-exits"}
	})

	view := api.View()

	if view.Preset != "" {
		t.Errorf("the card says the level is %q, want no level: those feeds are nobody's rung", view.Preset)
	}
	if len(view.Presets) != len(ipsfeed.Presets()) {
		t.Errorf("the card carries %d levels, want the whole ladder", len(view.Presets))
	}
	var recommended int
	for _, p := range view.Presets {
		if p.Summary == "" || len(p.Feeds) == 0 {
			t.Errorf("level %q reaches the card without what it turns on or why", p.ID)
		}
		if p.Recommended {
			recommended++
		}
	}
	if recommended != 1 {
		t.Errorf("%d levels reach the card marked recommended, want exactly one", recommended)
	}
}
