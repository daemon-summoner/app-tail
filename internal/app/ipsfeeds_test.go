// SPDX-License-Identifier: MIT

package app

// Keeping the downloaded address feeds current: what a refresh does with what came back, what
// keeps matching when one fails, and what the matcher is rebuilt from. The downloading itself
// is internal/feeds and the parsing is internal/ipsfeed.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/feeds"
)

const testFeedBody = "# a feed\n203.0.113.0/24\n198.51.100.7\n"

// testFeedRunner is a runner over a throwaway state directory whose downloads and clock the
// test drives.
func testFeedRunner(t *testing.T, now func() time.Time,
	fetch func(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error)) *ipsFeedRunner {

	t.Helper()
	return newIPSFeedRunner(quietLogger(), t.TempDir(), now, fetch)
}

func testFeed() config.IPSFeed {
	return config.IPSFeed{ID: "test", Name: "Test feed", URL: "https://feeds.example/bad.txt"}
}

func TestADownloadedFeedBecomesTheNetworksTheMatcherHolds(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody), ETag: `"v1"`}, nil
		})
	want := []config.IPSFeed{testFeed()}

	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	st := r.stateOf("test")
	if st.Rules != 2 {
		t.Errorf("rules = %d, want 2", st.Rules)
	}
	if st.ETag != `"v1"` {
		t.Errorf("etag = %q, want it kept for the next request", st.ETag)
	}
	if !st.FetchedAt.Equal(clock) {
		t.Errorf("fetchedAt = %v, want %v", st.FetchedAt, clock)
	}

	sources, err := r.sources(want)
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(sources))
	}
	if len(sources[0].Deny) != 2 || sources[0].ID != "test" || sources[0].Name != "Test feed" {
		t.Errorf("source = %+v, want the feed's id and name with both networks", sources[0])
	}
	if len(sources[0].Allow) != 0 {
		t.Error("a downloaded feed contributed entries that let traffic through")
	}
}

// The cache is what makes this survive a network that is down: a feed that cannot be
// re-downloaded keeps matching from the copy already on disk.
func TestAFeedThatFailsToRefreshKeepsMatchingFromTheCopyOnDisk(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	fail := false
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			if fail {
				return feeds.Fetched{}, errors.New("the network is down")
			}
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	want := []config.IPSFeed{testFeed()}

	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	fail = true
	clock = clock.Add(2 * time.Hour)
	err := r.refresh(context.Background(), want, time.Hour, false)

	if err == nil {
		t.Fatal("a refresh that could not download anything reported success")
	}
	sources, sourceErr := r.sources(want)
	if sourceErr != nil {
		t.Fatalf("sources: %v", sourceErr)
	}
	if len(sources) != 1 || len(sources[0].Deny) != 2 {
		t.Error("a failed refresh stopped the cached copy matching, which is the network taking inspection down with it")
	}
	if st := r.stateOf("test"); st.Error == "" {
		t.Error("nothing was recorded against the feed, so the card would show it as up to date")
	}
}

// A captive portal answers every request with its own sign-in page. Storing that as a feed
// would replace what was matching with nothing at all, silently.
func TestASignInPageIsNotStoredOverTheFeedItInterrupted(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	portal := false
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			if portal {
				return feeds.Fetched{Body: []byte("<html><body>Sign in to use this network</body></html>")}, nil
			}
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	want := []config.IPSFeed{testFeed()}

	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	portal = true
	clock = clock.Add(2 * time.Hour)
	err := r.refresh(context.Background(), want, time.Hour, false)

	if err == nil {
		t.Fatal("a sign-in page was accepted as a feed")
	}
	if !strings.Contains(err.Error(), "no address") {
		t.Errorf("error = %q, want it to say what was wrong with the body", err)
	}
	sources, sourceErr := r.sources(want)
	if sourceErr != nil {
		t.Fatalf("sources: %v", sourceErr)
	}
	if len(sources) != 1 || len(sources[0].Deny) != 2 {
		t.Error("the sign-in page replaced the copy that was matching")
	}
}

// Every feed of this kind carries the private ranges on purpose -- they are lists of networks
// that must never appear on the public internet -- and app-tail carries traffic to exactly
// those. A feed applied literally would refuse the tailnet and the LAN within seconds.
func TestAFeedCarryingThePrivateRangesNeverPutsThemInForce(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	body := "10.0.0.0/8\n127.0.0.0/8\n100.64.0.0/10\n192.168.0.0/16\n203.0.113.0/24\n"
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(body)}, nil
		})
	want := []config.IPSFeed{testFeed()}

	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	st := r.stateOf("test")
	if st.Rules != 1 {
		t.Errorf("rules = %d, want 1: only the network that is not one this machine carries traffic to", st.Rules)
	}
	if st.Skipped != 4 {
		t.Errorf("skipped = %d, want 4, so the card says why the feed holds less than the file does", st.Skipped)
	}
	sources, err := r.sources(want)
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(sources) != 1 || len(sources[0].Deny) != 1 || sources[0].Deny[0] != "203.0.113.0/24" {
		t.Errorf("entries in force = %+v, want only 203.0.113.0/24", sources)
	}
}

// A feed that is switched on and has never downloaded is not a failure: the download either
// has not happened yet or failed, and both are already recorded against the feed.
func TestAFeedWithNothingDownloadedContributesNothingAndIsNotAFailure(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{}, errors.New("not reached")
		})

	sources, err := r.sources([]config.IPSFeed{testFeed()})

	if err != nil {
		t.Errorf("sources = %v, want no error for a feed nothing has been downloaded for", err)
	}
	if len(sources) != 0 {
		t.Errorf("sources = %+v, want none", sources)
	}
}

// The key is what decides whether the matcher is rebuilt, and it is read without touching a
// downloaded copy: the entries add up to hundreds of thousands of lines, and reading them
// every reconcile would cost more than the compile the key exists to avoid.
func TestTheKeyMovesWhenACopyChangesAndNotOtherwise(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	body := testFeedBody
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(body)}, nil
		})
	want := []config.IPSFeed{testFeed()}

	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	first := r.sourcesKey(want)
	if first == r.sourcesKey(nil) {
		t.Fatal("a feed switched on reads the same as no feeds at all")
	}
	if second := r.sourcesKey(want); second != first {
		t.Errorf("the key moved with nothing downloaded in between: %q then %q", first, second)
	}

	body += "192.0.2.0/24\n"
	clock = clock.Add(2 * time.Hour)
	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("second refresh: %v", err)
	}

	if r.sourcesKey(want) == first {
		t.Error("a new copy left the key unchanged, so the matcher would keep the old entries")
	}
}

// A feed that answers 304 is unchanged, so the copy stays and only the time it was confirmed
// current moves. A key that moved here would rebuild the matcher every refresh interval for
// nothing.
func TestAFeedThatHasNotChangedKeepsItsCopyAndItsPlaceInTheKey(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	unchanged := false
	r := testFeedRunner(t, func() time.Time { return clock },
		func(_ context.Context, _ string, prev feeds.State) (feeds.Fetched, error) {
			if unchanged {
				if prev.ETag != `"v1"` {
					t.Errorf("the request carried etag %q, want the one the server gave", prev.ETag)
				}
				return feeds.Fetched{NotModified: true}, nil
			}
			return feeds.Fetched{Body: []byte(testFeedBody), ETag: `"v1"`}, nil
		})
	want := []config.IPSFeed{testFeed()}

	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	before := r.sourcesKey(want)

	unchanged = true
	clock = clock.Add(2 * time.Hour)
	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("second refresh: %v", err)
	}

	if r.sourcesKey(want) != before {
		t.Error("a feed that had not changed rebuilt the matcher")
	}
	if st := r.stateOf("test"); !st.FetchedAt.Equal(clock) {
		t.Errorf("fetchedAt = %v, want %v: the copy was confirmed current", st.FetchedAt, clock)
	}
	sources, err := r.sources(want)
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(sources) != 1 || len(sources[0].Deny) != 2 {
		t.Error("a 304 threw away the copy it was answering about")
	}
}

// One feed that will not download must not take the others off the air.
func TestOneFeedThatWillNotDownloadLeavesTheOthersDownloading(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := testFeedRunner(t, func() time.Time { return clock },
		func(_ context.Context, rawURL string, _ feeds.State) (feeds.Fetched, error) {
			if strings.Contains(rawURL, "broken") {
				return feeds.Fetched{}, errors.New("the server said no")
			}
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	want := []config.IPSFeed{
		{ID: "broken", Name: "Broken feed", URL: "https://feeds.example/broken.txt"},
		testFeed(),
	}

	err := r.refresh(context.Background(), want, time.Hour, false)

	if err == nil {
		t.Fatal("a round holding a failure reported success")
	}
	if !strings.Contains(err.Error(), "Broken feed") {
		t.Errorf("error = %q, want it to name the feed that failed", err)
	}
	if st := r.stateOf("test"); st.Rules != 2 {
		t.Error("the feed that was fine did not download because another one failed")
	}
}

// Forgetting is what an edited or deleted feed goes through, and it has to take the copy with
// it: the old feed's addresses would otherwise keep matching under the new feed's name.
func TestForgettingAFeedTakesItsDownloadedCopy(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	want := []config.IPSFeed{testFeed()}
	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if err := r.forget("test"); err != nil {
		t.Fatalf("forget: %v", err)
	}

	sources, err := r.sources(want)
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("sources = %+v, want none after the copy was forgotten", sources)
	}
	if st := r.stateOf("test"); st.Rules != 0 || !st.FetchedAt.IsZero() {
		t.Errorf("state = %+v, want nothing known about a forgotten feed", st)
	}
}

// The refresh button downloads whether or not anything is due, which is the whole reason it
// exists: a feed that failed an hour into a day-long interval is one somebody is watching.
func TestForcingARoundDownloadsAFeedThatIsNotDueYet(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	downloads := 0
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			downloads++
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	want := []config.IPSFeed{testFeed()}

	if err := r.refresh(context.Background(), want, 24*time.Hour, false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if err := r.refresh(context.Background(), want, 24*time.Hour, false); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if downloads != 1 {
		t.Fatalf("downloads = %d, want 1: nothing was due", downloads)
	}

	if err := r.refresh(context.Background(), want, 24*time.Hour, true); err != nil {
		t.Fatalf("forced refresh: %v", err)
	}

	if downloads != 2 {
		t.Errorf("downloads = %d, want 2: the refresh button ignores what is due", downloads)
	}
}

// replaceCopyWithADirectory puts something unreadable where one feed's downloaded copy is, for
// the cases about a file that is there and cannot be read.
func replaceCopyWithADirectory(t *testing.T, r *ipsFeedRunner, id string) {
	t.Helper()
	path := r.cache.Path(id)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove the downloaded copy: %v", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("put a directory where the downloaded copy was: %v", err)
	}
}

// jamTheCopy leaves a directory that is not empty where one feed's downloaded copy lives, so
// removing that copy fails the way a file somebody else holds open would.
func jamTheCopy(t *testing.T, r *ipsFeedRunner, id string) {
	t.Helper()
	replaceCopyWithADirectory(t, r, id)
	if err := os.WriteFile(filepath.Join(r.cache.Path(id), "held"), []byte("x"), config.FileMode); err != nil {
		t.Fatalf("fill the directory: %v", err)
	}
}

// A copy that is there and cannot be read is a failure named against the feed it belongs to,
// not a silent gap: the feed reads as switched on and matching nothing otherwise.
func TestACopyThatCannotBeReadIsReportedRatherThanSkipped(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	want := []config.IPSFeed{testFeed()}
	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	replaceCopyWithADirectory(t, r, "test")

	sources, err := r.sources(want)

	if err == nil {
		t.Fatal("a copy nothing could read was reported as nothing to read")
	}
	if !strings.Contains(err.Error(), "Test feed") {
		t.Errorf("failure = %q, want it to name the feed whose copy could not be read", err)
	}
	if len(sources) != 0 {
		t.Errorf("sources = %+v, want nothing from a copy that could not be read", sources)
	}
}

// The directory the copies live in is made before anything is downloaded. One that cannot
// exist stops the round rather than letting every feed fail separately with the same reason.
func TestARoundIntoADirectoryThatCannotExistStopsBeforeDownloading(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("in the way"), config.FileMode); err != nil {
		t.Fatalf("write the blocking file: %v", err)
	}
	var downloads int
	r := newIPSFeedRunner(quietLogger(), filepath.Join(blocked, "feeds"), time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			downloads++
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})

	err := r.refresh(context.Background(), []config.IPSFeed{testFeed()}, time.Hour, false)

	if err == nil {
		t.Fatal("a round reported success with nowhere to put what it downloaded")
	}
	if downloads != 0 {
		t.Errorf("%d downloads were made before the directory failed", downloads)
	}
}

// A round is called off when the agent is shutting down. What it already collected has to
// reach the caller with the reason it stopped, rather than the round reporting success on a
// list of feeds it never looked at.
func TestARoundCalledOffPartWayThroughSaysSoRatherThanReportingSuccess(t *testing.T) {
	r := testFeedRunner(t, time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.refresh(ctx, []config.IPSFeed{testFeed()}, time.Hour, false)

	if err == nil {
		t.Fatal("a round that was called off reported success")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want the reason the round stopped", err)
	}
}

// A download that cannot be written keeps the previous copy and records the failure against
// the feed: what was there still matches, and the card says why it is not current.
func TestAFeedWhoseCopyCannotBeStoredKeepsWhatWasThereAndSaysWhy(t *testing.T) {
	clock := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := testFeedRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testFeedBody), ETag: `"v1"`}, nil
		})
	want := []config.IPSFeed{testFeed()}
	if err := r.refresh(context.Background(), want, time.Hour, false); err != nil {
		t.Fatalf("the first round: %v", err)
	}
	first := r.stateOf("test")
	jamTheCopy(t, r, "test")

	err := r.refresh(context.Background(), want, time.Hour, true)

	if err == nil {
		t.Fatal("a round reported success while the copy it downloaded went nowhere")
	}
	if !strings.Contains(err.Error(), "update Test feed") {
		t.Errorf("error = %q, which does not name the feed that could not be written", err)
	}
	st := r.stateOf("test")
	if st.Error == "" {
		t.Error("the failure was not recorded against the feed, so the card would call it current")
	}
	if st.Rules != first.Rules || !st.FetchedAt.Equal(first.FetchedAt) {
		t.Errorf("state = %+v, want what the round before it recorded", st)
	}
}

// A copy holding no addresses contributes no source rather than an empty one, which is what a
// copy left by an older build or edited by hand looks like: a download could not have stored
// it, and an empty source in the matcher is a feed the card would call switched on and holding
// nothing.
func TestACopyThatHoldsNoAddressesContributesNoSource(t *testing.T) {
	r := testFeedRunner(t, time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{}, errors.New("not reached")
		})
	if err := r.cache.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := r.cache.Store("test", []byte("# nothing but a comment\n\n")); err != nil {
		t.Fatalf("store a copy holding nothing: %v", err)
	}

	sources, err := r.sources([]config.IPSFeed{testFeed()})

	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("sources = %+v, want nothing from a copy holding no addresses", sources)
	}
}

// The address is checked before the download rather than at the route alone: the refresh loop
// re-fetches a stored feed every round, and a stored address is the one nobody re-checks.
func TestAStoredFeedAddressIsCheckedAgainBeforeEveryDownload(t *testing.T) {
	a := newUnstartedAgent(t)

	_, err := a.fetchIPSFeed(context.Background(), "http://feeds.example/list.txt", feeds.State{})

	if err == nil {
		t.Fatal("a feed was downloaded over an address the catalog would refuse")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error = %q, which does not say what is wrong with the address", err)
	}
}

// Reconciling before the runner exists is the ordinary state during start-up, not a failure:
// the settings are read again as soon as the runner is there.
func TestReconcilingTheFeedsBeforeTheRunnerExistsDoesNothing(t *testing.T) {
	a := newUnstartedAgent(t)

	if err := a.reconcileIPSFeeds(context.Background(), true); err != nil {
		t.Errorf("reconcileIPSFeeds without a runner = %v, want nothing to have gone wrong", err)
	}
}

// A round downloads the feeds the settings switched on and leaves the rest alone. Downloading
// a feed nobody asked for would put its addresses one compile away from being enforced, and
// would fetch from a server the user never chose.
func TestOnlyTheFeedsSwitchedOnAreTheOnesARoundLooksAt(t *testing.T) {
	api, _ := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds,
			userFeed("work", "Work feed", "https://feeds.example/work.txt"),
			userFeed("spare", "Spare feed", "https://feeds.example/spare.txt"))
		c.Settings.IPSLists = []string{"work"}
		c.Settings.IPSRefreshHours = 6
	})

	target := api.a.ipsFeedTarget()

	if len(target.feeds) != 1 || target.feeds[0].ID != "work" {
		var ids []string
		for _, f := range target.feeds {
			ids = append(ids, f.ID)
		}
		t.Fatalf("a round would download %v, want only the feed that is switched on", ids)
	}
	if target.every != 6*time.Hour {
		t.Errorf("feeds are re-downloaded every %s, want the 6 hours the settings ask for", target.every)
	}
}

// What the user sees until a round has run is the card saying the feed holds nothing, so a feed
// that only starts downloading on the next tick reads as a switch that did not work -- and the
// refresh button gets pressed for something the app was about to do by itself.
func TestSwitchingAFeedOnDownloadsItWithoutWaitingForTheTick(t *testing.T) {
	api, store := newIPSFeedAPI(t, func(c *config.Config) {
		c.IPSFeeds = append(c.IPSFeeds, userFeed("work", "Work feed", "https://feeds.example/work.txt"))
		c.Settings.IPSEnabled = true
	})
	fetched := make(chan struct{}, 8)
	api.a.ipsFeeds = testFeedRunner(t, time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			fetched <- struct{}{}
			return feeds.Fetched{Body: []byte(testFeedBody)}, nil
		})

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		api.a.runIPSFeeds(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	select {
	case <-fetched:
		t.Fatal("a feed was downloaded while none was switched on")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.IPSLists = []string{"work"}
		return nil
	}); err != nil {
		t.Fatalf("switch the feed on: %v", err)
	}
	api.a.pokeIPSFeeds()

	// Far longer than the round needs and far shorter than the tick, so this separates "the
	// poke woke the loop" from "the loop got there on its own eventually".
	select {
	case <-fetched:
	case <-time.After(10 * time.Second):
		t.Fatalf("the feed was not downloaded; the loop waited out its %s tick instead",
			ipsFeedCheckInterval)
	}
}
