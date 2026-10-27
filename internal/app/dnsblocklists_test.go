// SPDX-License-Identifier: MIT

package app

// The catalog of lists as the dashboard and the CLI see it: what may be edited, what may
// be deleted, and what the card is told about the state blocking is actually in.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsblock"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/feeds"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// newDNSBlockAPI builds the blocking API over a throwaway store seeded with the user's own
// lists. The agent behind it is never started, which every case here wants except the ones
// whose write ends in a reconcile; those go through the harness instead.
func newDNSBlockAPI(t *testing.T, seed func(*config.Config)) (dnsBlockAPI, *config.Store) {
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
			t.Fatalf("seed blocklists: %v", err)
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
	return dnsBlockAPI{a: agent}, store
}

func userList(id, name, url string) config.Blocklist {
	return config.Blocklist{ID: id, Name: name, URL: url, Format: string(dnsblock.FormatAuto)}
}

func TestAddingAListGivesItAnIdOfItsOwnAndStoresIt(t *testing.T) {
	api, store := newDNSBlockAPI(t, nil)

	created, err := api.CreateList(config.Blocklist{
		Name: "  Work list  ", URL: " https://lists.example/work.txt ", Format: "hosts",
	})

	if err != nil {
		t.Fatalf("CreateList: %v", err)
	}
	if created.ID == "" || dnsblock.IsBuiltIn(created.ID) {
		t.Errorf("id = %q, want one of the user's own", created.ID)
	}
	if created.Name != "Work list" || created.URL != "https://lists.example/work.txt" {
		t.Errorf("stored %+v, want the name and address trimmed", created)
	}
	if created.BuiltIn {
		t.Error("a list the user added says it ships with app-tail, so the card would refuse to edit it")
	}
	stored := store.Get().Blocklists
	if len(stored) != 1 || stored[0].ID != created.ID {
		t.Errorf("stored %+v, want the one list that was added", stored)
	}
}

// The card and the CLI name a list by what the user called it, and two lists called "Work"
// make every one of those references a coin flip.
func TestAListCalledWhatAnotherOneIsCalledIsRefused(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists, userList("work", "Work list", "https://lists.example/work.txt"))
	})

	_, err := api.CreateList(config.Blocklist{Name: "work LIST", URL: "https://lists.example/other.txt"})

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("CreateList = %v, want a validation failure", err)
	}
	if !strings.Contains(invalid.Message, "already exists") {
		t.Errorf("refusal = %q, which does not say what is wrong", invalid.Message)
	}
	if stored := store.Get().Blocklists; len(stored) != 1 {
		t.Errorf("stored %+v, want the refused list not to have been written", stored)
	}
}

func TestAListNothingCouldDownloadIsRefusedBeforeItIsStored(t *testing.T) {
	api, store := newDNSBlockAPI(t, nil)

	cases := []struct {
		name string
		list config.Blocklist
		says string
	}{
		{"no address", config.Blocklist{Name: "Mine"}, "URL"},
		{"a scheme nothing fetches", config.Blocklist{Name: "Mine", URL: "ftp://lists.example/l.txt"}, "http"},
		{"a format the parser does not know", config.Blocklist{
			Name: "Mine", URL: "https://lists.example/l.txt", Format: "rpz",
		}, "rpz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := api.CreateList(tc.list)

			var invalid *config.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("CreateList(%s) = %v, want a validation failure", tc.name, err)
			}
			if !strings.Contains(invalid.Message, tc.says) {
				t.Errorf("refusal = %q, which does not name what to fix", invalid.Message)
			}
		})
	}
	if stored := store.Get().Blocklists; len(stored) != 0 {
		t.Errorf("stored %+v, want nothing written for a refused list", stored)
	}
}

// A shipped list is what the switch on the card turns on and off. Editing one would leave
// the name "Hagezi Pro" pointing wherever somebody redirected it, and every reason printed
// against it would be wrong.
func TestAShippedListCanBeSwitchedOffButNotEditedOrDeleted(t *testing.T) {
	api, store := newDNSBlockAPI(t, nil)

	_, editErr := api.UpdateList(dnsblock.DefaultListID, config.Blocklist{
		Name: "Not Hagezi", URL: "https://lists.example/mine.txt",
	})
	deleteErr := api.DeleteList(context.Background(), dnsblock.DefaultListID)

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
			t.Fatalf("%s of a shipped list = %v, want a validation failure", tc.what, tc.err)
		}
		if !strings.Contains(invalid.Message, tc.says) {
			t.Errorf("%s refusal = %q, which does not say what to do instead", tc.what, invalid.Message)
		}
	}
	if stored := store.Get().Blocklists; len(stored) != 0 {
		t.Errorf("stored %+v, want a refused write on a shipped list to store nothing", stored)
	}
}

// The id is what dnsBlock.lists names, so an edit that changed it would switch the list off
// as a side effect of renaming it.
func TestEditingAListKeepsItsIdSoTheSettingNamingItStaysValid(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists, userList("work", "Work list", "https://lists.example/work.txt"))
		c.Settings.DNSBlockLists = []string{"work"}
	})

	updated, err := api.UpdateList("work", config.Blocklist{
		Name: "Work list", URL: "https://lists.example/work-v2.txt", Format: "abp",
	})

	if err != nil {
		t.Fatalf("UpdateList: %v", err)
	}
	if updated.ID != "work" {
		t.Errorf("id = %q, want it unchanged so the setting still names this list", updated.ID)
	}
	stored := store.Get().Blocklists
	if len(stored) != 1 || stored[0].URL != "https://lists.example/work-v2.txt" || stored[0].Format != "abp" {
		t.Errorf("stored %+v, want the edited address and format", stored)
	}
}

func TestEditingAListThatIsNotThereIsRefusedRatherThanCreatingIt(t *testing.T) {
	api, store := newDNSBlockAPI(t, nil)

	_, err := api.UpdateList("ghost", config.Blocklist{Name: "Ghost", URL: "https://lists.example/g.txt"})

	if !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("UpdateList = %v, want it refused as missing", err)
	}
	if stored := store.Get().Blocklists; len(stored) != 0 {
		t.Errorf("stored %+v, want an edit of nothing to have created nothing", stored)
	}
}

// Deleting a list that is switched on would leave dnsBlock.lists naming something nothing
// can download, and the first place that shows up is a blocker quietly missing a list.
func TestDeletingAListThatIsSwitchedOnIsRefused(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists, userList("work", "Work list", "https://lists.example/work.txt"))
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockLists = []string{"work"}
	})

	resp, body := h.request(http.MethodDelete, "/api/dns/block/lists/work", nil)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DELETE /api/dns/block/lists/work = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "switch it off before deleting it") {
		t.Errorf("body = %s, want it to say how to get out of the refusal", body)
	}
	if stored := h.store.Get().Blocklists; len(stored) != 1 {
		t.Errorf("stored %+v, want the refused delete to have kept the list", stored)
	}
}

func TestDeletingAListNothingIsUsingRemovesIt(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists,
			userList("work", "Work list", "https://lists.example/work.txt"),
			userList("spare", "Spare", "https://lists.example/spare.txt"))
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockLists = []string{"work"}
	})

	resp, body := h.request(http.MethodDelete, "/api/dns/block/lists/spare", nil)

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/dns/block/lists/spare = %d, want 204: %s", resp.StatusCode, body)
	}
	stored := h.store.Get().Blocklists
	if len(stored) != 1 || stored[0].ID != "work" {
		t.Errorf("stored %+v, want only the list that was left alone", stored)
	}
}

// Every state the card renders comes from this one verdict, and the point of the ladder is
// that a switch that is on while nothing is filtered says so rather than showing green.
func TestTheCardIsToldWhenBlockingIsOnAndStillFilteringNothing(t *testing.T) {
	tests := []struct {
		name     string
		view     httpapi.DNSBlockView
		degraded bool
		says     string
	}{
		{
			"switched off entirely",
			httpapi.DNSBlockView{},
			false, "Blocking is off",
		},
		{
			"on with neither switch under it",
			httpapi.DNSBlockView{Enabled: true, Rules: 100},
			true, "neither switch under it",
		},
		{
			"paused",
			httpapi.DNSBlockView{Enabled: true, System: true, Rules: 100, PausedUntil: "2026-08-31T12:15:00Z"},
			true, "paused",
		},
		{
			"nothing downloaded yet",
			httpapi.DNSBlockView{Enabled: true, Own: true},
			true, "No list has been downloaded yet",
		},
		{
			"undone by the retry setting",
			httpapi.DNSBlockView{Enabled: true, System: true, Rules: 100, RetryOnNXDOMAIN: true},
			true, "retry",
		},
		{
			"blocking",
			httpapi.DNSBlockView{Enabled: true, Own: true, System: true, Rules: 100},
			false, "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsBlockCapability(tc.view)

			if !got.Available {
				t.Error("blocking reported itself unavailable, which is a state it never has")
			}
			if got.Degraded != tc.degraded {
				t.Errorf("Degraded = %v, want %v -- reason %q", got.Degraded, tc.degraded, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.says) {
				t.Errorf("reason = %q, want it to say %q", got.Reason, tc.says)
			}
			if len(got.Limits) == 0 {
				t.Error("no limits were stated, so the scope of blocking would have to be discovered")
			}
		})
	}
}

// Every answer has to say why, including the ones that are not about a list at all:
// somebody asking why a name is not blocked is asking about the switches as often as
// about the lists.
func TestCheckingANameSaysWhyItIsOrIsNotBlocked(t *testing.T) {
	tests := []struct {
		name    string
		seed    func(*config.Config)
		ask     string
		blocked bool
		says    string
	}{
		{
			"not a name at all",
			nil, "   ", false, "not a name",
		},
		{
			"blocking switched off",
			nil, "doubleclick.net", false, "switched off",
		},
		{
			"on with neither switch under it",
			func(c *config.Config) {
				c.Settings.DNSBlockEnabled = true
				// Named rather than left to the default, which is on: the state under
				// test is the one where no scope is selected at all.
				c.Settings.DNSBlockSystem = false
				c.Settings.DNSBlockOwn = false
			},
			"doubleclick.net", false, "neither app-tail's own resolution nor this machine's",
		},
		{
			"the lists not loaded yet",
			func(c *config.Config) {
				c.Settings.DNSBlockEnabled = true
				c.Settings.DNSBlockOwn = true
			},
			"doubleclick.net", false, "have not been loaded yet",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api, _ := newDNSBlockAPI(t, tc.seed)

			got := api.Check(tc.ask)

			if got.Blocked != tc.blocked {
				t.Errorf("Blocked = %v, want %v", got.Blocked, tc.blocked)
			}
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(tc.says)) {
				t.Errorf("reason = %q, want it to say %q", got.Reason, tc.says)
			}
		})
	}
}

// The answer somebody actually came for: which list stopped this name, so they know where
// to go and switch it off. The states around it -- paused, and a name nothing carries --
// have to be distinguishable from it rather than all reading as "not blocked".
func TestCheckingANameNamesTheListThatStopsIt(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockOwn = true
	})
	runner := newBlocklistRunner(quietLogger(), t.TempDir(), func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	api.a.blocklists = runner
	if err := runner.refresh(context.Background(), []config.Blocklist{testList()}, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	blocked := api.Check("DoubleClick.net.")
	if !blocked.Blocked || blocked.List != "Test list" {
		t.Fatalf("Check(a blocked name) = %+v, want it blocked and the list named", blocked)
	}
	if blocked.Name != "doubleclick.net" {
		t.Errorf("Name = %q, want the name as the matcher reads it", blocked.Name)
	}

	allowed := api.Check("example.org")
	if allowed.Blocked {
		t.Errorf("Check(a name no list carries) = %+v, want it not blocked", allowed)
	}
	if !strings.Contains(allowed.Reason, "2") {
		t.Errorf("reason = %q, want it to say how many names were searched", allowed.Reason)
	}

	runner.pause(15 * time.Minute)
	paused := api.Check("doubleclick.net")
	if paused.Blocked {
		t.Error("a name was reported blocked while blocking was paused")
	}
	if !strings.Contains(paused.Reason, "paused") {
		t.Errorf("reason = %q, want it to say blocking is paused rather than that the name is not on a list", paused.Reason)
	}
}

// A round that could not download anything has to reach the card. Every list keeps the
// copy it already has, so nothing else on the card changes, and a user with no way to see
// the failure is a user whose lists quietly stop being updated.
func TestARoundThatFailedIsOnTheCardUntilOneSucceeds(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockOwn = true
		c.Settings.DNSBlockLists = []string{"test"}
		c.Blocklists = append(c.Blocklists, testList())
	})
	down := true
	api.a.blocklists = newBlocklistRunner(quietLogger(), t.TempDir(), func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			if down {
				return feeds.Fetched{}, errors.New("the network is down")
			}
			return feeds.Fetched{Body: []byte(testListBody)}, nil
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
	if got := api.View().Error; got != "" {
		t.Errorf("the card still carries %q after a round that succeeded", got)
	}
}

// A settings document written before these two settings existed carries neither, and a card
// showing an empty answer shape and an interval of zero would describe a resolver that does
// not exist.
func TestTheCardShowsTheDefaultsWhenTheSettingsWereWrittenWithoutThem(t *testing.T) {
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockAnswer = ""
		c.Settings.DNSBlockRefreshHours = 0
	})

	view := api.View()

	if view.Answer != config.DefaultDNSBlockAnswer {
		t.Errorf("Answer = %q, want %q", view.Answer, config.DefaultDNSBlockAnswer)
	}
	if view.RefreshHours != config.DefaultDNSBlockRefreshHours {
		t.Errorf("RefreshHours = %d, want %d", view.RefreshHours, config.DefaultDNSBlockRefreshHours)
	}
}

// A pause is asked for because something is broken right now, so the card has to show that
// it is on and until when -- a pause nothing reports is a blocker that looks broken.
func TestPausingIsOnTheCardUntilItIsResumed(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockOwn = true
	})
	api.a.blocklists = newBlocklistRunner(quietLogger(), t.TempDir(), func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})

	until := api.Pause(15 * time.Minute)

	if !until.After(clock) {
		t.Fatalf("Pause returned %s, want a deadline after the clock it paused at", until)
	}
	view := api.View()
	if view.PausedUntil == "" {
		t.Fatal("the card carries no pause, so a resolver answering everything would look like a broken one")
	}
	if !view.Capability.Degraded || !strings.Contains(view.Capability.Reason, "paused") {
		t.Errorf("capability = %+v, want it degraded and saying blocking is paused", view.Capability)
	}

	api.Resume()

	if got := api.View().PausedUntil; got != "" {
		t.Errorf("the card still carries a pause until %q after it was resumed", got)
	}
}

// Names looked up while blocking was paused stay cached as allowed, and names looked up
// before it stay cached as blocked, until the machine's resolver moves -- which only a
// reconcile does. So a pause, the end of one and a resume each ask for a reconcile.
func TestPausingAndResumingAskTheMachineResolverToCatchUp(t *testing.T) {
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockSystem = true
	})
	api.a.blocklists = newBlocklistRunner(quietLogger(), t.TempDir(), time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	drain := func() {
		select {
		case <-api.a.reconcile:
		default:
		}
	}

	drain()
	api.Pause(50 * time.Millisecond)
	select {
	case <-api.a.reconcile:
	default:
		t.Fatal("pausing queued no reconcile, so the machine keeps answering blocked names from its cache")
	}
	select {
	case <-api.a.reconcile:
	case <-time.After(5 * time.Second):
		t.Fatal("the pause ending queued no reconcile, so names looked up during it stay cached as allowed")
	}

	api.Pause(time.Hour)
	drain()
	api.Resume()
	select {
	case <-api.a.reconcile:
	default:
		t.Error("resuming queued no reconcile, so names looked up during the pause stay cached as allowed")
	}
}

// The machine-wide resolver reads the blocked names off the runner on every pass, and reads
// nothing when blocking is not meant for this machine's resolver.
func TestTheMachineResolverIsToldWhichNamesAreBlocked(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockSystem = true
	})
	runner := newBlocklistRunner(quietLogger(), t.TempDir(), time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	if err := runner.refresh(context.Background(), []config.Blocklist{testList()}, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	api.a.blocklists = runner

	if got, want := api.a.systemDNSTarget(context.Background()).blocking, runner.blocking(); got != want || got == 0 {
		t.Fatalf("the resolver was told %d, want the runner's %d", got, want)
	}

	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.DNSBlockSystem = false
		return nil
	}); err != nil {
		t.Fatalf("switch blocking off for the machine: %v", err)
	}
	if got := api.a.systemDNSTarget(context.Background()).blocking; got != 0 {
		t.Errorf("the resolver was told %d with blocking switched off for this machine, want 0", got)
	}
}

// Both controls are reachable from the dashboard before the first round has built a runner,
// and a pause that panicked there would take the API down with it.
func TestPausingBeforeTheListsExistIsRefusedRatherThanFatal(t *testing.T) {
	api, _ := newDNSBlockAPI(t, nil)

	if until := api.Pause(15 * time.Minute); !until.IsZero() {
		t.Errorf("Pause = %s, want no deadline: there is nothing to pause yet", until)
	}
	api.Resume()
}

// The counter on the card is the machine-wide resolver's, and it is the only evidence a
// user has that blocking is doing anything at all.
func TestTheCardCountsTheNamesThisMachinesResolverRefused(t *testing.T) {
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockSystem = true
	})
	set := blockingSet(t, "doubleclick.net")
	fwd := dnsfwd.New(dnsfwd.Config{Rules: dnsfwd.Rules{HaveLocal: true, Block: set}})
	t.Cleanup(func() {
		if err := fwd.Close(); err != nil {
			t.Errorf("close the forwarder: %v", err)
		}
	})
	runner := newSystemDNSRunner(quietLogger(), func(context.Context, func(string, ...any)) (tsnode.SystemDNSRights, error) {
		return nil, errors.New("this test never claims the machine's resolution")
	}, nil)
	runner.fwd = fwd
	api.a.systemDNS = runner

	if answer := fwd.Answer(context.Background(), blockQuery(t, "doubleclick.net"), false); len(answer) == 0 {
		t.Fatal("the resolver returned nothing for a blocked name")
	}

	if got := api.View().Blocked; got != 1 {
		t.Errorf("Blocked = %d, want 1: the card reads the resolver's own counter", got)
	}
}

// The runner exists from startup, so the first thing a user asking about a name after a
// restart gets is this: the lists are here, nothing has been read yet.
func TestCheckingANameBeforeAnythingHasBeenDownloadedSaysSo(t *testing.T) {
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockOwn = true
	})
	api.a.blocklists = newBlocklistRunner(quietLogger(), t.TempDir(), time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{}, errors.New("this test never downloads")
		})

	got := api.Check("doubleclick.net")

	if got.Blocked {
		t.Error("a name was reported blocked by lists that have not been read")
	}
	if !strings.Contains(got.Reason, "no list has been downloaded") {
		t.Errorf("reason = %q, want it to say nothing has been downloaded yet", got.Reason)
	}
}

// An id arrives from whoever called the API, and one that is already taken would leave two
// lists the card cannot tell apart and a setting naming either.
func TestAListAddedUnderAnIdSomethingElseHoldsGetsItsOwn(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists, userList("work", "Work list", "https://lists.example/work.txt"))
	})

	created, err := api.CreateList(config.Blocklist{
		ID: "work", Name: "Home list", URL: "https://lists.example/home.txt",
	})

	if err != nil {
		t.Fatalf("CreateList: %v", err)
	}
	if created.ID == "work" {
		t.Error("the new list took the id the existing one is stored under")
	}
	stored := store.Get().Blocklists
	if len(stored) != 2 || stored[0].ID != "work" || stored[1].ID != created.ID {
		t.Errorf("stored %+v, want both lists under ids of their own", stored)
	}
}

// An edit goes through the same refusals as an addition: the card offers the same form for
// both, and a list edited into one nothing can fetch would stop blocking at the next round.
func TestEditingAListIntoOneNothingCouldUseIsRefused(t *testing.T) {
	tests := []struct {
		name string
		edit config.Blocklist
		says string
	}{
		{"nothing to fetch it from", config.Blocklist{Name: "Work list"}, "URL"},
		{"the name another list has", config.Blocklist{
			Name: "Home LIST", URL: "https://lists.example/work.txt",
		}, "already exists"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api, store := newDNSBlockAPI(t, func(c *config.Config) {
				c.Blocklists = append(c.Blocklists,
					userList("home", "Home list", "https://lists.example/home.txt"),
					userList("work", "Work list", "https://lists.example/work.txt"))
			})

			_, err := api.UpdateList("work", tc.edit)

			var invalid *config.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("UpdateList = %v, want a validation failure", err)
			}
			if !strings.Contains(invalid.Message, tc.says) {
				t.Errorf("refusal = %q, which does not name what to fix", invalid.Message)
			}
			if stored := store.Get().Blocklists; stored[1].URL != "https://lists.example/work.txt" {
				t.Errorf("the list is now %+v, want the refused edit not to have been written", stored[1])
			}
		})
	}
}

// The stored entry is already the new one, so a cached copy that cannot be deleted is a
// stale download rather than a reason to refuse the edit: the next round re-fetches it.
func TestEditingAListWhoseCachedCopyCannotBeRemovedStillStoresTheEdit(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists,
			userList("home", "Home list", "https://lists.example/home.txt"), testList())
	})
	attachRunnerWithAnUndeletableCopy(t, api.a)

	edited, err := api.UpdateList("test", config.Blocklist{
		Name: "Test list", URL: "https://lists.example/moved.txt", Format: "hosts",
	})

	if err != nil {
		t.Fatalf("UpdateList: %v", err)
	}
	if edited.URL != "https://lists.example/moved.txt" {
		t.Errorf("stored %+v, want the new address", edited)
	}
	stored := store.Get().Blocklists
	if stored[1].URL != "https://lists.example/moved.txt" {
		t.Errorf("the store holds %+v, want the edit", stored[1])
	}
	if stored[0].URL != "https://lists.example/home.txt" {
		t.Errorf("the other list is now %+v; editing one list moved another", stored[0])
	}
}

func TestDeletingAListNothingHasHeardOfIsRefused(t *testing.T) {
	api, _ := newDNSBlockAPI(t, nil)

	err := api.DeleteList(context.Background(), "nothing-by-that-name")

	if !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("DeleteList = %v, want it to report the list is not there", err)
	}
}

// Deleting the entry while its downloaded copy stays behind would leave a file nothing
// tracks in the state directory, so the failure is reported rather than logged.
func TestDeletingAListWhoseCachedCopyCannotBeRemovedIsReported(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists, testList())
	})
	attachRunnerWithAnUndeletableCopy(t, api.a)

	err := api.DeleteList(context.Background(), "test")

	if err == nil {
		t.Fatal("a list whose downloaded copy could not be removed was deleted silently")
	}
	if !strings.Contains(err.Error(), "test") {
		t.Errorf("error = %q, want it to name the list whose copy is still on disk", err)
	}
	if stored := store.Get().Blocklists; len(stored) != 0 {
		t.Errorf("the catalog still holds %+v; the entry was removed before the copy was", stored)
	}
}

// attachRunnerWithAnUndeletableCopy gives the agent a runner holding one downloaded list
// whose file cannot be removed, which is what a state directory somebody made read-only or
// a copy replaced by a directory looks like from here.
func attachRunnerWithAnUndeletableCopy(t *testing.T, a *Agent) *blocklistRunner {
	t.Helper()
	runner := newBlocklistRunner(quietLogger(), t.TempDir(), time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	if err := runner.refresh(context.Background(), []config.Blocklist{testList()}, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	path := runner.cache.Path("test")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove the downloaded copy: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(path, "in-the-way"), config.DirMode); err != nil {
		t.Fatalf("put a directory where the downloaded copy was: %v", err)
	}
	a.blocklists = runner
	return runner
}

// blockingSet compiles one list holding the names given, as the resolver holds it.
func blockingSet(t *testing.T, names ...string) *dnsblock.Set {
	t.Helper()
	entries := make([]dnsblock.Entry, 0, len(names))
	for _, n := range names {
		entries = append(entries, dnsblock.Entry{Name: n, Match: dnsblock.Subtree})
	}
	var b dnsblock.Builder
	if err := b.Add("test", "Test list", entries, 0); err != nil {
		t.Fatalf("compile the test list: %v", err)
	}
	return b.Build()
}

// blockQuery is one A query for name, as a client sends it.
func blockQuery(t *testing.T, name string) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name + "."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("build the question: %v", err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatalf("finish the query: %v", err)
	}
	return query
}

// Shutdown reports the agent stopped, and the caller is then entitled to delete the state
// directory. A loop still downloading a list would write into it afterwards.
func TestShutdownSaysSoWhenTheBlocklistLoopWillNotStop(t *testing.T) {
	stuck := make(chan struct{})

	err := waitForDownloadLoop("blocklist", stuck, 10*time.Millisecond)

	if err == nil {
		t.Fatal("a loop that never stopped was reported as stopped")
	}
	if !strings.Contains(err.Error(), "state directory") {
		t.Errorf("error = %q, want it to say what is still being written to", err)
	}

	close(stuck)
	if err := waitForDownloadLoop("blocklist", stuck, time.Minute); err != nil {
		t.Errorf("waiting on a loop that has returned = %v, want no error", err)
	}
	if err := waitForDownloadLoop("blocklist", nil, time.Minute); err != nil {
		t.Errorf("waiting with no loop to wait for = %v, want no error", err)
	}
}

// And the whole agent says it too: a loop that will not stop is a failure Run reports
// rather than a wait that ends quietly with the directory still being written to.
func TestAnAgentWhoseBlocklistLoopWillNotStopSaysSoWhenItStops(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	node := newFakeNode()
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	// The node starts before Run publishes the loop's channel, so waiting on the node
	// alone would sometimes swap a channel Run then overwrites with its own.
	waitFor(t, 5*time.Second, "the agent to start its blocklist loop", func() bool {
		agent.mu.Lock()
		defer agent.mu.Unlock()
		return agent.blocklistsDone != nil
	})

	// The loop's own channel is replaced with one nothing ever closes, which is what a
	// download that will not abandon its request looks like from here.
	agent.mu.Lock()
	agent.blocklistsDone = make(chan struct{})
	agent.mu.Unlock()
	cancel()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run reported a clean exit over a loop that never stopped")
		}
		if !strings.Contains(err.Error(), "state directory") {
			t.Errorf("err = %v, want it to say what is still being written to", err)
		}
	case <-time.After(shutdownStep + 15*time.Second):
		t.Fatal("Run never returned")
	}
}

// The picker is what a list is switched on from, so it has to carry the shipped catalog and
// the user's own together -- and mark which is which, since only one of them can be edited.
func TestTheListsTheCardRendersAreTheShippedCatalogAndTheUsersOwn(t *testing.T) {
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists, userList("work", "Work list", "https://lists.example/work.txt"))
		c.Settings.DNSBlockLists = []string{dnsblock.DefaultListID}
	})

	view := api.View()

	if len(view.Lists) != len(dnsblock.BuiltIn())+1 {
		t.Fatalf("the card renders %d lists, want the %d shipped ones plus the user's",
			len(view.Lists), len(dnsblock.BuiltIn()))
	}
	byID := make(map[string]httpapi.DNSBlockListView, len(view.Lists))
	for _, l := range view.Lists {
		byID[l.ID] = l
	}
	shipped, ok := byID[dnsblock.DefaultListID]
	if !ok {
		t.Fatalf("%s is missing from the card", dnsblock.DefaultListID)
	}
	if !shipped.BuiltIn || !shipped.Enabled {
		t.Errorf("%s = %+v, want it shipped and switched on", shipped.ID, shipped)
	}
	mine, ok := byID["work"]
	if !ok {
		t.Fatal("the user's own list is missing from the card")
	}
	if mine.BuiltIn || mine.Enabled {
		t.Errorf("work = %+v, want the user's own list, switched off", mine)
	}
	if byID["easylist"].Note == "" {
		t.Error("EasyList carries no note, so the caveat about browser-filter lists would have to be discovered")
	}
	if shipped.Provider != dnsblock.Provider(config.Blocklist{ID: shipped.ID}) {
		t.Errorf("%s came back under provider %q, want the one the catalog names", shipped.ID, shipped.Provider)
	}
	if mine.Provider != dnsblock.UserProvider {
		t.Errorf("the user's own list came back under provider %q, want %q", mine.Provider, dnsblock.UserProvider)
	}
}

// A level is the whole point of the ladder: one click replaces the shipped lists that are
// on. What it must not do is switch off a list the user went and found -- no rung names
// those, and losing one to a level change is losing something app-tail never offered.
func TestSwitchingToALevelTurnsOnItsListsAndKeepsTheUsersOwn(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = append(c.Blocklists, userList("work", "Work list", "https://lists.example/work.txt"))
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockLists = []string{"easylist", "work"}
	})
	medium, ok := dnsblock.PresetByID("medium")
	if !ok {
		t.Fatal("the ladder has no rung called medium")
	}

	if err := api.ApplyPreset(context.Background(), "medium"); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}

	got := store.Get().Settings.DNSBlockLists
	want := append(slices.Clone(medium.Lists), "work")
	if !slices.Equal(got, want) {
		t.Errorf("the lists switched on are %v, want %v", got, want)
	}
	if slices.Contains(got, "easylist") {
		t.Error("easylist stayed on, so the level added to what was there rather than replacing it")
	}
	if view := api.View(); view.Preset != "medium" {
		t.Errorf("the card says the level is %q, want medium: a list the user added is not a rung of its own", view.Preset)
	}
}

// A rung nothing carries applied as the empty set would switch every list off, which is a
// typo reading as blocking that is on and filtering nothing.
func TestALevelTheLadderDoesNotCarryIsRefusedAndLeavesTheListsAlone(t *testing.T) {
	api, store := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockLists = []string{dnsblock.DefaultListID}
	})

	err := api.ApplyPreset(context.Background(), "paranoid")

	if err == nil {
		t.Fatal("a level nothing carries was accepted")
	}
	if !strings.Contains(err.Error(), "ultimate") {
		t.Errorf("the refusal reads %q, want it to name the levels there are", err)
	}
	if got := store.Get().Settings.DNSBlockLists; !slices.Equal(got, []string{dnsblock.DefaultListID}) {
		t.Errorf("the lists switched on are %v, want the ones that were on before the refusal", got)
	}
}

// The card marks the level in force, and a set that is nobody's level has to read as
// exactly that rather than as the nearest one.
func TestTheCardCallsASetThatIsNobodysLevelNothing(t *testing.T) {
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockLists = []string{dnsblock.DefaultListID, "stevenblack-porn"}
	})

	view := api.View()

	if view.Preset != "" {
		t.Errorf("the card says the level is %q, want no level named for a set nobody's rung is", view.Preset)
	}
	if len(view.Presets) != len(dnsblock.Presets()) {
		t.Errorf("the card was sent %d levels, want the whole ladder to choose from", len(view.Presets))
	}
}

// The wait above is only worth having if shutdown carries what it found. A list still being
// written while the process exits is the failure it exists to name, and a shutdown that
// reported success anyway would tell the caller the state directory is theirs to delete.
func TestShutdownCarriesTheBlocklistLoopThatWouldNotStop(t *testing.T) {
	agent := newQuietAgent(t, func(tsnode.Options) NodeController { return newFakeNode() })
	agent.mu.Lock()
	agent.blocklistsDone = make(chan struct{})
	agent.mu.Unlock()

	err := agent.Shutdown(context.Background())

	if err == nil || !strings.Contains(err.Error(), "blocklist update did not stop") {
		t.Fatalf("shutdown reported %v, want the update that was still running", err)
	}
}

// runBlocklistLoop starts the update loop over a runner that reports every download, and
// stops it when the case ends.
//
// The channel is buffered so a round is never held up waiting to be read: a case that has
// seen what it came for stops reading, and the loop has to be free to keep going.
func runBlocklistLoop(t *testing.T, a *Agent) <-chan struct{} {
	t.Helper()
	fetched := make(chan struct{}, 8)
	a.blocklists = newBlocklistRunner(quietLogger(), t.TempDir(), time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			fetched <- struct{}{}
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		a.runBlocklists(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	return fetched
}

// waitForDownload waits for the loop to download something. The wait is far longer than the
// round needs and far shorter than the tick, so it separates "the poke woke the loop" from
// "the loop got there on its own eventually".
func waitForDownload(t *testing.T, fetched <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-fetched:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s was not downloaded; the loop waited out its %s tick instead", what, blocklistCheckInterval)
	}
}

// What the user sees until a round has run is the card saying nothing is being blocked, so a
// switch that only takes effect on the next tick reads as a switch that did not work, and the
// download button gets pressed for something the app was about to do by itself.
func TestSwitchingBlockingOnDownloadsWithoutWaitingForTheTick(t *testing.T) {
	// Seeded with nothing: naming a list here is a stored value the module does not have by
	// default, which is enough for the loader to decide blocking was already in use and
	// switch it on -- and the case is about the moment it goes on.
	api, store := newDNSBlockAPI(t, nil)
	fetched := runBlocklistLoop(t, api.a)

	select {
	case <-fetched:
		t.Fatal("a list was downloaded while blocking was switched off")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.DNSBlockEnabled = true
		return nil
	}); err != nil {
		t.Fatalf("switch blocking on: %v", err)
	}
	api.a.pokeBlocklists()

	waitForDownload(t, fetched, "the list blocking was switched on for")
}

// Editing the address drops the copy downloaded under the old one, so between the edit and
// the next round the list is switched on with nothing behind it.
func TestEditingAListsAddressDownloadsTheNewOneWithoutWaitingForTheTick(t *testing.T) {
	api, _ := newDNSBlockAPI(t, func(c *config.Config) {
		c.Blocklists = []config.Blocklist{testList()}
		c.Settings.DNSBlockEnabled = true
		c.Settings.DNSBlockLists = []string{"test"}
	})
	fetched := runBlocklistLoop(t, api.a)
	waitForDownload(t, fetched, "the list the loop starts with")

	moved := testList()
	moved.URL = "https://lists.example/moved.txt"
	if _, err := api.UpdateList("test", moved); err != nil {
		t.Fatalf("UpdateList: %v", err)
	}

	waitForDownload(t, fetched, "the list at its new address")
}
