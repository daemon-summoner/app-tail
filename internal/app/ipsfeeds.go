// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/feeds"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/ipsfeed"
	"github.com/sellitus/app-tail/internal/telemetry"
)

const (
	// ipsFeedDirName is the directory under the state directory holding one downloaded copy
	// per feed, plus the index describing them. It is separate from the blocklists' directory
	// because the two catalogs assign ids independently, and a user feed called "work" in each
	// would otherwise be one file.
	ipsFeedDirName = "ipsfeeds"

	// maxIPSFeedBytes is the most one address feed may be. The largest shipped entry is a few
	// hundred kilobytes, so this leaves a wide margin while staying far below the blocklists'
	// cap: a cap is a parse budget as much as a download limit, and every line here becomes an
	// entry in a routing table rather than a name in an arena.
	maxIPSFeedBytes = 8 << 20

	// ipsFeedCheckInterval is how often the refresh loop looks at the clock. It is not how
	// often a feed is downloaded -- that is ips.refreshHours -- and it is short because the
	// same pass is what notices a feed being switched on.
	ipsFeedCheckInterval = time.Minute
)

// ipsFeedRunner owns the downloaded address feeds: the copies on disk and what is known
// about each. It does not hold the matcher -- ipsRunner does -- because the feeds are one of
// two things compiled into it and the entries the user typed are the other.
type ipsFeedRunner struct {
	logger *slog.Logger
	// cache is the copies on disk and the index describing them, the same machinery the
	// domain blocklists use so the two cannot disagree about what a current copy is.
	cache *feeds.Cache
	now   func() time.Time
	// fetch downloads one feed. It is a seam because the real one dials the internet at a
	// pinned address, and a test suite must do neither.
	fetch func(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error)
}

// newIPSFeedRunner reads the index for a state directory.
func newIPSFeedRunner(logger *slog.Logger, stateDir string, now func() time.Time,
	fetch func(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error)) *ipsFeedRunner {

	dir := filepath.Join(stateDir, ipsFeedDirName)
	return &ipsFeedRunner{
		logger: logger,
		cache:  feeds.NewCache(logger, dir, now),
		now:    now,
		fetch:  fetch,
	}
}

// stateOf returns what is known about one feed.
func (r *ipsFeedRunner) stateOf(id string) feeds.State { return r.cache.StateOf(id) }

// snapshot returns the whole index.
func (r *ipsFeedRunner) snapshot() map[string]feeds.State { return r.cache.Snapshot() }

// forget drops what is known about a feed and deletes its cached copy, for a feed the user
// removed from the catalog.
func (r *ipsFeedRunner) forget(id string) error { return r.cache.Forget(id) }

// refresh downloads whatever is due.
//
// Every failure is recorded against its feed and carried into the report rather than stopping
// the round: one feed that will not download must not take the others off the air, and the
// cached copy of the one that failed keeps matching.
func (r *ipsFeedRunner) refresh(ctx context.Context, want []config.IPSFeed, every time.Duration, force bool) error {
	if err := r.cache.Prepare(); err != nil {
		return err
	}

	var failures []error
	for _, f := range want {
		prev := r.stateOf(f.ID)
		if !force && !r.cache.Due(f.ID, prev, every) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := r.download(ctx, f, prev); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// download fetches one feed, checks that what came back is a feed, and replaces the cached
// copy. A body that yields no entry at all is refused and the previous copy kept: a captive
// portal's sign-in page parses as a file of comments, and a feed that has quietly become one
// would otherwise replace a working copy with nothing.
func (r *ipsFeedRunner) download(ctx context.Context, f config.IPSFeed, prev feeds.State) error {
	fetchCtx, cancel := context.WithTimeout(ctx, feedFetchTimeout)
	defer cancel()

	got, err := r.fetch(fetchCtx, f.URL, prev)
	if err != nil {
		st := prev
		st.Error = err.Error()
		r.cache.SetState(f.ID, st)
		return fmt.Errorf("update %s: %w", f.Name, err)
	}

	st := prev
	st.Error = ""
	st.FetchedAt = r.now()
	if got.NotModified {
		r.cache.SetState(f.ID, st)
		return nil
	}

	entries, skipped := ipsfeed.Parse(got.Body)
	if len(entries) == 0 {
		st = prev
		st.Error = fmt.Sprintf("what %s answered with holds no address at all", f.URL)
		r.cache.SetState(f.ID, st)
		return fmt.Errorf("update %s: %s", f.Name, st.Error)
	}

	if err := r.cache.Store(f.ID, got.Body); err != nil {
		st = prev
		st.Error = err.Error()
		r.cache.SetState(f.ID, st)
		return fmt.Errorf("update %s: %w", f.Name, err)
	}
	if got.ETag != "" || got.LastModified != "" {
		st.ETag, st.LastModified = got.ETag, got.LastModified
	}
	st.StoredAt = st.FetchedAt
	st.Bytes, st.Rules, st.Skipped = len(got.Body), len(entries), skipped
	r.cache.SetState(f.ID, st)
	return nil
}

// sources reads every cached copy into one matcher source each.
//
// A feed that has not been downloaded yet contributes nothing and is not a failure: the
// download either has not happened or failed, and both are already recorded against the feed.
func (r *ipsFeedRunner) sources(want []config.IPSFeed) ([]inspect.Source, error) {
	out := make([]inspect.Source, 0, len(want))
	var failures []error
	for _, f := range want {
		body, err := r.cache.Read(f.ID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			failures = append(failures, fmt.Errorf("read the downloaded copy of %s: %w", f.Name, err))
			continue
		}
		entries, _ := ipsfeed.Parse(body)
		if len(entries) == 0 {
			continue
		}
		out = append(out, inspect.Source{ID: f.ID, Name: f.Name, Deny: entries})
	}
	return out, errors.Join(failures...)
}

// sourcesKey is what the feed half of the matcher is built from, without reading a byte of
// it.
//
// It keys on what each cached copy is rather than on what it holds, which is the whole point:
// the entries add up to hundreds of thousands of lines, and building a key out of them every
// reconcile would cost more than the compile it exists to avoid.
//
// When the copy was stored rather than when it was last confirmed current: a feed that answers
// 304 has the file already in force, and rebuilding then would re-parse hundreds of thousands
// of lines into an identical matcher once per refresh interval.
func (r *ipsFeedRunner) sourcesKey(want []config.IPSFeed) string {
	var b strings.Builder
	for _, f := range want {
		st := r.stateOf(f.ID)
		b.WriteString(f.ID)
		b.WriteByte(0)
		b.WriteString(f.Name)
		b.WriteByte(0)
		b.WriteString(strconv.FormatInt(st.StoredAt.UnixNano(), 10))
		b.WriteByte(0)
		b.WriteString(strconv.Itoa(st.Bytes))
		b.WriteByte('\n')
	}
	return b.String()
}

// fetchIPSFeed is the runner's real downloader.
//
// The URL is checked here and not only where a feed is added: a feed stored before this side
// asked the question is still fetched every refresh, and the answer is the same either way.
func (a *Agent) fetchIPSFeed(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error) {
	if err := ipsfeed.ValidateURL(rawURL); err != nil {
		return feeds.Fetched{}, err
	}
	return a.fetchFeed(ctx, rawURL, prev, maxIPSFeedBytes)
}

// currentIPSFeeds returns the runner, which exists for the life of the agent.
func (a *Agent) currentIPSFeeds() *ipsFeedRunner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ipsFeeds
}

// ipsFeedTarget is which feeds the settings ask for and how often they are re-downloaded.
type ipsFeedTarget struct {
	feeds []config.IPSFeed
	every time.Duration
}

// ipsFeedTarget reads the settings and the catalog into what the runner should do.
func (a *Agent) ipsFeedTarget() ipsFeedTarget {
	c := a.store.Get()
	s := c.Settings

	// Read as stored: a document written before the setting existed, or one holding a zero,
	// carries the default by the time the store hands it back.
	target := ipsFeedTarget{every: time.Duration(s.IPSRefreshHours) * time.Hour}

	// Order is the user's: the first source to carry an address is the one a match names, so
	// the catalog's order is what decides which feed gets the credit.
	for _, f := range ipsfeed.Catalog(c.IPSFeeds) {
		if slices.Contains(s.IPSLists, f.ID) {
			target.feeds = append(target.feeds, f)
		}
	}
	return target
}

// runIPSFeeds keeps the downloaded address feeds current for the life of the agent.
//
// Like the blocklist loop it reads the settings on each round rather than being started and
// stopped as the switch moves, and a round that fails does not end it: the feeds would then
// stay frozen at whatever one bad network moment downloaded.
func (a *Agent) runIPSFeeds(ctx context.Context) {
	a.noteIPSFeedRound(a.reconcileIPSFeeds(ctx, false))
	tick := time.NewTicker(ipsFeedCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-a.ipsFeedWake:
		}
		a.noteIPSFeedRound(a.reconcileIPSFeeds(ctx, false))
	}
}

// pokeIPSFeeds asks the feed loop to look now rather than at its next tick, for the reason
// pokeBlocklists exists: switching a feed on is a download the user is watching for.
func (a *Agent) pokeIPSFeeds() {
	select {
	case a.ipsFeedWake <- struct{}{}:
	default:
	}
}

// noteIPSFeedRound records how the last round ended, for the card to show. A round that
// succeeds clears it, so a failure that has since been recovered from does not stay on screen
// naming a network that has come back.
func (a *Agent) noteIPSFeedRound(err error) {
	if err == nil {
		a.ipsFeedRound.Store(nil)
		return
	}
	message := err.Error()
	a.ipsFeedRound.Store(&message)
}

// ipsFeedRoundError is what the last round ended with, empty when it ended cleanly.
func (a *Agent) ipsFeedRoundError() string {
	if message := a.ipsFeedRound.Load(); message != nil {
		return *message
	}
	return ""
}

// reconcileIPSFeeds downloads what is due and rebuilds the matcher if anything changed.
// force downloads every feed whether it is due or not, which is what the refresh button does.
//
// Nothing is downloaded while inspection is off: a feed is fetched to be matched against, and
// a machine with the module switched off has nothing to match.
func (a *Agent) reconcileIPSFeeds(ctx context.Context, force bool) error {
	runner := a.currentIPSFeeds()
	if runner == nil {
		return nil
	}
	if !a.store.Get().Settings.IPSEnabled {
		return nil
	}

	target := a.ipsFeedTarget()
	err := runner.refresh(ctx, target.feeds, target.every, force)
	if err != nil {
		a.recordEvent(telemetry.CodeIPSFailed,
			"An inspection feed could not be updated; the copy already downloaded is still matching.",
			map[string]string{"error": err.Error()})
		a.logger.Warn("updating the traffic-inspection feeds failed", "error", err)
	}

	// The rules are compiled by the reconcile, which is the one place the feeds and the
	// entries the user typed are put together. Nothing else would tell it a new copy exists.
	a.pokeReconcile()
	return err
}

// ipsFeedState is one catalog entry and what is known about its downloaded copy.
type ipsFeedState struct {
	config.IPSFeed
	Enabled   bool
	Rules     int
	Skipped   int
	Bytes     int
	UpdatedAt time.Time
	Error     string
	Note      string
	Provider  string
}

// ipsFeedStates is the catalog with what is known about each cached copy attached, in the
// order the catalog holds them. It is what the card, the CLI and the API all report from.
func (a *Agent) ipsFeedStates() []ipsFeedState {
	c := a.store.Get()
	catalog := ipsfeed.Catalog(c.IPSFeeds)
	on := c.Settings.IPSLists

	var (
		index    map[string]feeds.State
		compiled map[string]inspect.SourceStat
	)
	if runner := a.currentIPSFeeds(); runner != nil {
		index = runner.snapshot()
	}
	if rules := a.currentIPS().rules.Load(); rules != nil {
		compiled = make(map[string]inspect.SourceStat)
		for _, stat := range rules.Sources() {
			compiled[stat.ID] = stat
		}
	}

	out := make([]ipsFeedState, 0, len(catalog))
	for _, f := range catalog {
		st := index[f.ID]
		entry := ipsFeedState{
			IPSFeed:  f,
			Enabled:  slices.Contains(on, f.ID),
			Rules:    st.Rules,
			Skipped:  st.Skipped,
			Bytes:    st.Bytes,
			Error:    st.Error,
			Note:     ipsfeed.Note(f.ID),
			Provider: ipsfeed.Provider(f),
		}
		if !st.FetchedAt.IsZero() {
			entry.UpdatedAt = st.FetchedAt
		}
		if stat, live := compiled[f.ID]; live {
			// What the live matcher holds beats what the index remembers: a feed switched on a
			// moment ago has an index entry and no entries in force yet.
			entry.Rules, entry.Skipped = stat.Prefixes+stat.Names, stat.Skipped
		}
		out = append(out, entry)
	}
	return out
}
