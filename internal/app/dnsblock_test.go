// SPDX-License-Identifier: MIT

package app

// Keeping the lists current: what a refresh does with what came back, and what keeps
// applying when one fails. The downloading itself is internal/feeds.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/feeds"
)

const testListBody = "0.0.0.0 doubleclick.net\n0.0.0.0 ads.example.com\n"

// testRunner is a runner over a throwaway state directory whose downloads and clock the
// test drives.
func testRunner(t *testing.T, now func() time.Time,
	fetch func(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error)) *blocklistRunner {

	t.Helper()
	return newBlocklistRunner(quietLogger(), t.TempDir(), now, fetch)
}

func testList() config.Blocklist {
	return config.Blocklist{ID: "test", Name: "Test list", URL: "https://lists.example/pro.txt", Format: "hosts"}
}

// The cache is what makes this survive a network that is down or an exit node that is
// gone: a list that cannot be re-downloaded keeps blocking from the copy already on disk.
func TestAListThatFailsToRefreshKeepsBlockingFromTheCopyOnDisk(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	fail := false
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			if fail {
				return feeds.Fetched{}, errors.New("the network is down")
			}
			return feeds.Fetched{Body: []byte(testListBody), ETag: `"v1"`}, nil
		})
	want := []config.Blocklist{testList()}

	if err := r.refresh(context.Background(), want, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Fatal("the list did not block after it was downloaded")
	}

	fail = true
	clock = clock.Add(2 * time.Hour)
	err := r.refresh(context.Background(), want, nil, nil, time.Hour, false)

	if err == nil {
		t.Fatal("a refresh that could not download anything reported success")
	}
	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Error("a failed refresh stopped the cached copy blocking, which is the network taking the blocker down with it")
	}
	if st := r.stateOf("test"); st.Error == "" {
		t.Error("nothing was recorded against the list, so the card would show it as up to date")
	}
}

// A captive portal answers every request with its own sign-in page. Storing that as a list
// would replace what was blocking with a few dozen English words.
func TestASignInPageIsNotStoredOverTheListItInterrupted(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	portal := false
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			if portal {
				return feeds.Fetched{Body: []byte("<html><body>Sign in to use this network</body></html>")}, nil
			}
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	want := []config.Blocklist{testList()}

	if err := r.refresh(context.Background(), want, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	portal = true
	clock = clock.Add(2 * time.Hour)
	err := r.refresh(context.Background(), want, nil, nil, time.Hour, false)

	if err == nil {
		t.Fatal("a sign-in page was accepted as a blocklist")
	}
	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Error("the cached list stopped blocking after a captive portal answered instead of the server")
	}
	body, readErr := os.ReadFile(filepath.Join(r.cache.Dir(), "test.txt"))
	if readErr != nil {
		t.Fatalf("read the cached copy: %v", readErr)
	}
	if string(body) != testListBody {
		t.Errorf("the copy on disk is now %q, want the list that was there before", body)
	}
}

// A list already downloaded and still current costs nothing, or every reconcile a minute
// apart would re-download tens of megabytes.
func TestARefreshOnlyDownloadsTheListsThatAreDue(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	var downloads int
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			downloads++
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	want := []config.Blocklist{testList()}

	for i := 0; i < 3; i++ {
		if err := r.refresh(context.Background(), want, nil, nil, 24*time.Hour, false); err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		clock = clock.Add(time.Minute)
	}
	if downloads != 1 {
		t.Errorf("downloaded %d times in three minutes, want once", downloads)
	}

	// The refresh button, which is the user saying they know it is not due.
	if err := r.refresh(context.Background(), want, nil, nil, 24*time.Hour, true); err != nil {
		t.Fatalf("forced refresh: %v", err)
	}
	if downloads != 2 {
		t.Errorf("downloaded %d times, want the forced round to have downloaded again", downloads)
	}

	clock = clock.Add(25 * time.Hour)
	if err := r.refresh(context.Background(), want, nil, nil, 24*time.Hour, false); err != nil {
		t.Fatalf("refresh after the interval: %v", err)
	}
	if downloads != 3 {
		t.Errorf("downloaded %d times, want a list past its interval to be downloaded again", downloads)
	}
}

// The two settings lists are what an over-blocking list is fixed with, and they have to
// work without any list being downloaded at all.
func TestTheNamesTheUserTypedBlockAndUnblockWithoutAnyListAtAll(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})

	if err := r.refresh(context.Background(), []config.Blocklist{testList()},
		[]string{"ads.example.com"}, []string{"metrics.example.net"}, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if list, ok := r.Blocks("metrics.example.net"); !ok {
		t.Error("a name in dnsBlock.deny was not blocked")
	} else if list != manualListName {
		t.Errorf("it was blocked by %q, want the user's own list named so the card can say where it came from", list)
	}
	if _, ok := r.Blocks("ads.example.com"); ok {
		t.Error("a name in dnsBlock.allow stayed blocked, so an allow entry fixes nothing")
	}
	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Error("the downloaded list stopped blocking when the user's own names were added")
	}
}

// A pause is asked for because something is broken right now, and it has to end on its own:
// a pause that outlives its deadline is a blocker that quietly stopped blocking.
func TestAPauseEndsOnItsOwnWithoutAnythingHavingToClearIt(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	if err := r.refresh(context.Background(), []config.Blocklist{testList()}, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	until := r.pause(15 * time.Minute)

	if !until.Equal(clock.Add(15 * time.Minute)) {
		t.Errorf("pause ends at %s, want %s", until, clock.Add(15*time.Minute))
	}
	if _, ok := r.Blocks("doubleclick.net"); ok {
		t.Fatal("a name was still blocked while blocking was paused")
	}
	if _, paused := r.paused(); !paused {
		t.Error("the pause does not report itself, so nothing could say so on the card")
	}

	clock = clock.Add(16 * time.Minute)

	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Error("blocking did not resume when the pause ran out")
	}
	if _, paused := r.paused(); paused {
		t.Error("an expired pause still reports itself as in force")
	}
}

func TestResumingEndsAPauseImmediately(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	if err := r.refresh(context.Background(), []config.Blocklist{testList()}, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	r.pause(time.Hour)

	r.resume()

	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Error("blocking did not come back when the pause was ended")
	}
}

// Switching blocking off gives the memory back, and the downloaded copies are what makes
// switching it back on instant rather than another download of tens of megabytes.
func TestSwitchingBlockingOffDropsTheMatcherAndKeepsTheDownloads(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	var downloads int
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			downloads++
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	want := []config.Blocklist{testList()}
	if err := r.refresh(context.Background(), want, nil, nil, 24*time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	r.clear()

	if _, ok := r.Blocks("doubleclick.net"); ok {
		t.Fatal("a name was still blocked after blocking was switched off")
	}

	if err := r.refresh(context.Background(), want, nil, nil, 24*time.Hour, false); err != nil {
		t.Fatalf("refresh after switching back on: %v", err)
	}
	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Error("switching blocking back on did not restore the matcher")
	}
	if downloads != 1 {
		t.Errorf("downloaded %d times, want the copy on disk to have been enough", downloads)
	}
}

// The machine-wide resolver moves this machine to a new address whenever the names being
// blocked change, which is what makes every cache on it drop names it looked up under the
// old ones. So the number it reads changes with every new set of names, stays put for a round
// that compiles nothing, and reads zero whenever nothing is being blocked.
func TestTheBlockedNamesAreNamedAnewEachTimeTheyChange(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	r := testRunner(t, func() time.Time { return clock },
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})
	ctx := context.Background()
	want := []config.Blocklist{testList()}

	if got := r.blocking(); got != 0 {
		t.Fatalf("blocking() = %d before anything was compiled, want 0", got)
	}
	if err := r.refresh(ctx, want, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	first := r.blocking()
	if first == 0 {
		t.Fatal("blocking() = 0 with a list compiled, so switching it off would move nothing")
	}
	if err := r.refresh(ctx, want, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := r.blocking(); got != first {
		t.Errorf("blocking() went from %d to %d on a round that changed no name", first, got)
	}
	if err := r.refresh(ctx, want, nil, []string{"metrics.example.net"}, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	second := r.blocking()
	if second == first || second == 0 {
		t.Errorf("blocking() = %d after a name was added to %d, want a different, nonzero number", second, first)
	}

	r.pause(time.Hour)
	if got := r.blocking(); got != 0 {
		t.Errorf("blocking() = %d while paused, want 0", got)
	}
	r.resume()
	if got := r.blocking(); got != second {
		t.Errorf("blocking() = %d after resuming, want %d back", got, second)
	}
	r.clear()
	if got := r.blocking(); got != 0 {
		t.Errorf("blocking() = %d after blocking was switched off, want 0", got)
	}
}

// A list server answering "not modified" is the common case for every round after the
// first. Each such round recompiles, and a new number there would move this machine to the
// other resolver address every hour for nothing.
func TestAListTheServerSaysIsUnchangedKeepsTheBlockedNamesNamedTheSame(t *testing.T) {
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	body := testListBody
	r := testRunner(t, func() time.Time { return clock },
		func(_ context.Context, _ string, prev feeds.State) (feeds.Fetched, error) {
			if prev.FetchedAt.IsZero() || body != testListBody {
				return feeds.Fetched{Body: []byte(body)}, nil
			}
			return feeds.Fetched{NotModified: true}, nil
		})
	ctx := context.Background()
	want := []config.Blocklist{testList()}

	if err := r.refresh(ctx, want, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	first := r.blocking()
	clock = clock.Add(2 * time.Hour)
	if err := r.refresh(ctx, want, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh answered not modified: %v", err)
	}
	if got := r.blocking(); got != first {
		t.Errorf("blocking() went from %d to %d on a round the server said changed nothing", first, got)
	}
	if _, blocked := r.Blocks("doubleclick.net"); !blocked {
		t.Error("doubleclick.net is not blocked after a not-modified round, want the list still applying")
	}

	// Same length as before, so only what the names are tells the two copies apart.
	body = "0.0.0.0 doubleclick.net\n0.0.0.0 ads.example.org\n"
	clock = clock.Add(2 * time.Hour)
	if err := r.refresh(ctx, want, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh with a changed list: %v", err)
	}
	if got := r.blocking(); got == first || got == 0 {
		t.Errorf("blocking() = %d after the list changed a name, want a nonzero number other than %d", got, first)
	}
}

// The index describes files that can be downloaded again, so a corrupt one must not stop
// the agent starting -- and must not be read as "every list is current" either.
func TestAnUnreadableIndexStartsOverRatherThanRefusingToStart(t *testing.T) {
	stateDir := t.TempDir()
	dir := filepath.Join(stateDir, blocklistDirName)
	if err := os.MkdirAll(dir, config.DirMode); err != nil {
		t.Fatalf("create the blocklist directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, feeds.IndexName), []byte("{not json"), config.FileMode); err != nil {
		t.Fatalf("write a corrupt index: %v", err)
	}

	r := newBlocklistRunner(quietLogger(), stateDir, time.Now,
		func(context.Context, string, feeds.State) (feeds.Fetched, error) {
			return feeds.Fetched{Body: []byte(testListBody)}, nil
		})

	if st := r.stateOf("test"); !st.FetchedAt.IsZero() {
		t.Errorf("the corrupt index was read as knowledge about a list: %+v", st)
	}
	if err := r.refresh(context.Background(), []config.Blocklist{testList()}, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh over a corrupt index: %v", err)
	}
	if _, ok := r.Blocks("doubleclick.net"); !ok {
		t.Error("the lists were not downloaded again after the index could not be read")
	}
}

// Deleting a list has to take its download with it, or the disk keeps a copy of a list
// nothing points at any more.
func TestForgettingAListRemovesItsDownloadedCopy(t *testing.T) {
	r := testRunner(t, time.Now, func(context.Context, string, feeds.State) (feeds.Fetched, error) {
		return feeds.Fetched{Body: []byte(testListBody)}, nil
	})
	if err := r.refresh(context.Background(), []config.Blocklist{testList()}, nil, nil, time.Hour, false); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	path := filepath.Join(r.cache.Dir(), "test.txt")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the list was not written: %v", err)
	}

	if err := r.forget("test"); err != nil {
		t.Fatalf("forget: %v", err)
	}

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the downloaded copy is still there: %v", err)
	}
	if st := r.stateOf("test"); st != (feeds.State{}) {
		t.Errorf("what was known about the list survived it: %+v", st)
	}
}
