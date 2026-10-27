// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsblock"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/feeds"
	"github.com/sellitus/app-tail/internal/telemetry"
)

const (
	// blocklistDirName is the directory under the state directory holding one downloaded
	// copy per list, plus the index describing them.
	blocklistDirName = "blocklists"

	// maxListBytes is the most one list may be. Hagezi Ultimate is around 40 MB of text,
	// so this leaves headroom while still refusing a download that is not a list at all.
	maxListBytes = 64 << 20

	// blocklistCheckInterval is how often the refresh loop looks at the clock. It is not
	// how often a list is downloaded -- that is dnsBlock.refreshHours -- and it is short
	// because the same pass is what notices a list being switched on.
	blocklistCheckInterval = time.Minute

	// manualListID is the id the two settings lists compile under. It is not a catalog
	// entry and never appears in the stored document; it exists so a name stopped by
	// dnsBlock.deny can say what stopped it.
	manualListID   = "manual"
	manualListName = "your own list"
)

// blocklistRunner owns the downloaded lists: the copies on disk, what is known about each,
// and the one compiled matcher both consumers ask.
//
// Both of them -- the machine-wide forwarder and app-tail's own resolution -- hold this
// same value through a one-method interface, so the two switches can never disagree about
// what a list says. It answers nothing while blocking is paused, which is what makes a
// pause take effect on the next query rather than on the next reconcile.
type blocklistRunner struct {
	logger *slog.Logger
	// cache is the copies on disk and the index describing them, shared with traffic
	// inspection's feeds so the two cannot disagree about what a current copy is.
	cache *feeds.Cache
	now   func() time.Time
	// fetch downloads one list. It is a seam because the real one dials the internet at a
	// pinned address, and a test suite must do neither.
	fetch func(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error)

	// set is the live matcher, replaced whole. Nil is blocking switched off and every
	// state before the first compile.
	set atomic.Pointer[dnsblock.Set]
	// version counts the matchers compiled, so a caller can tell one set of blocked names
	// from the next without comparing a million of them.
	version atomic.Uint64
	// pausedUntil is unix nanoseconds; zero is running. Deliberately not persisted: a
	// blocker that comes back paused after a restart is the one failure this must not have.
	pausedUntil atomic.Int64

	mu sync.Mutex
	// built is what the live matcher was compiled from, so an unchanged round costs no
	// parse of a million names.
	built string
	// compiledAt is when that happened, for the card.
	compiledAt time.Time
	// content is a digest of what the live matcher blocks. A round that compiles the same
	// names again -- a list the server answered "not modified" for -- leaves version alone.
	content string
}

// newBlocklistRunner reads the index for a state directory.
func newBlocklistRunner(logger *slog.Logger, stateDir string, now func() time.Time,
	fetch func(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error)) *blocklistRunner {

	dir := filepath.Join(stateDir, blocklistDirName)
	return &blocklistRunner{
		logger: logger,
		cache:  feeds.NewCache(logger, dir, now),
		now:    now,
		fetch:  fetch,
	}
}

// Blocks reports the list that stops a name, and whether one does. It is the whole of both
// dnsfwd.Blocklist and tunnel.Blocklist.
func (r *blocklistRunner) Blocks(name string) (string, bool) {
	if r == nil {
		return "", false
	}
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return "", false
	}
	set := r.set.Load()
	if set == nil {
		return "", false
	}
	return set.Blocks(name)
}

// pause stops blocking for a while and returns when it ends. A pause while already paused
// replaces the deadline rather than adding to it.
func (r *blocklistRunner) pause(d time.Duration) time.Time {
	until := r.now().Add(d)
	r.pausedUntil.Store(until.UnixNano())
	return until
}

// resume ends a pause now.
func (r *blocklistRunner) resume() { r.pausedUntil.Store(0) }

// paused reports when a pause ends, and whether one is in force. An expired deadline reads
// as running without anything having had to clear it.
func (r *blocklistRunner) paused() (time.Time, bool) {
	until := r.pausedUntil.Load()
	if until == 0 {
		return time.Time{}, false
	}
	end := time.Unix(0, until)
	if !r.now().Before(end) {
		return time.Time{}, false
	}
	return end, true
}

// blocking names the set of names being stopped right now, and is zero while none are:
// switched off, before the first compile, or paused. Two calls that return the same number
// stop the same names.
func (r *blocklistRunner) blocking() uint64 {
	if _, paused := r.paused(); paused {
		return 0
	}
	if r.set.Load() == nil {
		return 0
	}
	return r.version.Load()
}

// stateOf returns what is known about one list.
func (r *blocklistRunner) stateOf(id string) feeds.State { return r.cache.StateOf(id) }

// snapshot returns the index and when the matcher was last compiled.
func (r *blocklistRunner) snapshot() (map[string]feeds.State, time.Time) {
	index := r.cache.Snapshot()
	r.mu.Lock()
	defer r.mu.Unlock()
	return index, r.compiledAt
}

// forget drops what is known about a list and deletes its cached copy, for a list the user
// removed from the catalog.
func (r *blocklistRunner) forget(id string) error { return r.cache.Forget(id) }

// clear drops the matcher, which is what switching blocking off does. The downloaded copies
// stay: they are what makes switching it back on instant.
func (r *blocklistRunner) clear() {
	r.set.Store(nil)
	r.mu.Lock()
	r.built, r.compiledAt = "", time.Time{}
	r.mu.Unlock()
}

// refresh downloads whatever is due and compiles the result.
//
// Every failure is recorded against its list and carried into the report rather than
// stopping the round: one list that will not download must not take the other five off the
// air, and the cached copy of the one that failed keeps blocking.
func (r *blocklistRunner) refresh(ctx context.Context, want []config.Blocklist, allow, deny []string,
	every time.Duration, force bool) error {

	if err := r.cache.Prepare(); err != nil {
		return err
	}

	var failures []error
	for _, l := range want {
		prev := r.stateOf(l.ID)
		if !force && !r.cache.Due(l.ID, prev, every) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := r.download(ctx, l, prev); err != nil {
			failures = append(failures, err)
		}
	}

	if err := r.compile(want, allow, deny); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// download fetches one list, checks that what came back is a list, and replaces the cached
// copy. A body that does not read like a blocklist -- a captive portal's sign-in page is
// the one that happens -- is refused, and the previous copy is kept.
func (r *blocklistRunner) download(ctx context.Context, l config.Blocklist, prev feeds.State) error {
	fetchCtx, cancel := context.WithTimeout(ctx, feedFetchTimeout)
	defer cancel()

	got, err := r.fetch(fetchCtx, l.URL, prev)
	if err != nil {
		st := prev
		st.Error = err.Error()
		r.cache.SetState(l.ID, st)
		return fmt.Errorf("update %s: %w", l.Name, err)
	}

	st := prev
	st.Error = ""
	st.FetchedAt = r.now()
	if got.NotModified {
		r.cache.SetState(l.ID, st)
		return nil
	}

	entries, skipped, err := dnsblock.Parse(dnsblock.Format(l.Format), got.Body)
	if err != nil {
		st = prev
		st.Error = fmt.Sprintf("what %s answered with is not a blocklist: %v", l.URL, err)
		r.cache.SetState(l.ID, st)
		return fmt.Errorf("update %s: %w", l.Name, err)
	}

	if err := r.cache.Store(l.ID, got.Body); err != nil {
		st = prev
		st.Error = err.Error()
		r.cache.SetState(l.ID, st)
		return fmt.Errorf("update %s: %w", l.Name, err)
	}
	if got.ETag != "" || got.LastModified != "" {
		st.ETag, st.LastModified = got.ETag, got.LastModified
	}
	st.Bytes, st.Rules, st.Skipped = len(got.Body), len(entries), skipped
	r.cache.SetState(l.ID, st)
	return nil
}

// compile builds one matcher from every cached copy plus the user's own two lists, and
// swaps it in. A round that would compile exactly what is already live does nothing, which
// is what keeps a reconcile every few seconds from re-parsing a million names.
func (r *blocklistRunner) compile(want []config.Blocklist, allow, deny []string) error {
	key := r.compileKey(want, allow, deny)
	r.mu.Lock()
	unchanged := key == r.built && r.set.Load() != nil
	r.mu.Unlock()
	if unchanged {
		return nil
	}

	var (
		builder  dnsblock.Builder
		failures []error
		content  = sha256.New()
	)
	for _, l := range want {
		body, err := r.cache.Read(l.ID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Not downloaded yet. The download either has not happened or failed, and
				// both of those are already recorded against the list.
				continue
			}
			failures = append(failures, fmt.Errorf("read the downloaded copy of %s: %w", l.Name, err))
			continue
		}
		entries, skipped, err := dnsblock.Parse(dnsblock.Format(l.Format), body)
		if err != nil {
			st := r.stateOf(l.ID)
			st.Error = fmt.Sprintf("the downloaded copy is not a blocklist: %v", err)
			r.cache.SetState(l.ID, st)
			failures = append(failures, fmt.Errorf("read %s: %w", l.Name, err))
			continue
		}
		if err := builder.Add(l.ID, l.Name, entries, skipped); err != nil {
			failures = append(failures, err)
			break
		}
		fmt.Fprintf(content, "%s\x00%s\x00%d\x00", l.ID, l.Format, len(body))
		content.Write(body)
	}

	if manual := manualEntries(allow, deny); len(manual) > 0 {
		if err := builder.Add(manualListID, manualListName, manual, 0); err != nil {
			failures = append(failures, err)
		}
	}
	fmt.Fprintf(content, "\x01%q\x02%q", allow, deny)
	digest := string(content.Sum(nil))

	r.set.Store(builder.Build())
	r.mu.Lock()
	changed := digest != r.content
	r.built, r.compiledAt, r.content = key, r.now(), digest
	r.mu.Unlock()
	if changed {
		// After the store: a reader that sees the new number is sure to see the new matcher.
		r.version.Add(1)
	}
	return errors.Join(failures...)
}

// compileKey is everything the matcher is built from: which lists, what each cached copy
// is, and the two lists the user typed.
func (r *blocklistRunner) compileKey(want []config.Blocklist, allow, deny []string) string {
	var b strings.Builder
	for _, l := range want {
		st := r.stateOf(l.ID)
		b.WriteString(l.ID)
		b.WriteByte(0)
		b.WriteString(l.Name)
		b.WriteByte(0)
		b.WriteString(l.Format)
		b.WriteByte(0)
		b.WriteString(strconv.FormatInt(st.FetchedAt.UnixNano(), 10))
		b.WriteByte(0)
		b.WriteString(strconv.Itoa(st.Bytes))
		b.WriteByte('\n')
	}
	b.WriteByte(1)
	for _, name := range allow {
		b.WriteString(name)
		b.WriteByte(0)
	}
	b.WriteByte(2)
	for _, name := range deny {
		b.WriteString(name)
		b.WriteByte(0)
	}
	return b.String()
}

// manualEntries turns the two settings lists into rules. Both reach everything under the
// name written, because somebody typing a domain by hand means the domain and its hosts.
func manualEntries(allow, deny []string) []dnsblock.Entry {
	out := make([]dnsblock.Entry, 0, len(allow)+len(deny))
	for _, name := range deny {
		out = append(out, dnsblock.Entry{Name: name, Match: dnsblock.Subtree})
	}
	for _, name := range allow {
		out = append(out, dnsblock.Entry{Name: name, Match: dnsblock.Subtree, Allow: true})
	}
	return out
}

// fetchBlocklist is the runner's real downloader.
//
// The URL is checked here and not only where a list is added: a list stored before this
// side asked the question is still fetched every refresh, and the answer is the same
// either way.
func (a *Agent) fetchBlocklist(ctx context.Context, rawURL string, prev feeds.State) (feeds.Fetched, error) {
	if err := dnsblock.ValidateURL(rawURL); err != nil {
		return feeds.Fetched{}, err
	}
	return a.fetchFeed(ctx, rawURL, prev, maxListBytes)
}

// currentBlocklists returns the runner, which exists for the life of the agent.
func (a *Agent) currentBlocklists() *blocklistRunner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.blocklists
}

// blocklistTarget is what the settings ask the runner for.
type blocklistTarget struct {
	// on is blocking switched on at all. Off empties the matcher, which is what gives the
	// memory back; the downloaded copies stay so switching it back on is instant.
	on    bool
	lists []config.Blocklist
	allow []string
	deny  []string
	every time.Duration
	// answer is what a blocked name is answered with by the machine-wide resolver.
	answer dnsfwd.BlockAnswer
	// own and system are the two switches: app-tail's own resolution, and this machine's.
	own    bool
	system bool
}

// blocklistTarget reads the settings and the catalog into what the runner should do.
func (a *Agent) blocklistTarget() blocklistTarget {
	c := a.store.Get()
	s := c.Settings

	target := blocklistTarget{
		on:     s.DNSBlockEnabled,
		allow:  slices.Clone(s.DNSBlockAllow),
		deny:   slices.Clone(s.DNSBlockDeny),
		answer: dnsfwd.ParseBlockAnswer(s.DNSBlockAnswer),
		own:    s.DNSBlockEnabled && s.DNSBlockOwn,
		system: s.DNSBlockEnabled && s.DNSBlockSystem,
	}

	hours := s.DNSBlockRefreshHours
	if hours <= 0 {
		hours = config.DefaultDNSBlockRefreshHours
	}
	target.every = time.Duration(hours) * time.Hour

	// Order is the user's: the first list to carry a name is the one a blocked name names,
	// so the catalog's order is what decides which list gets the credit.
	for _, l := range dnsblock.Catalog(c.Blocklists) {
		if slices.Contains(s.DNSBlockLists, l.ID) {
			target.lists = append(target.lists, l)
		}
	}
	return target
}

// runBlocklists keeps the downloaded lists current for the life of the agent.
//
// Like the latency probes it reads the settings on each round rather than being started
// and stopped as the switch moves: a loop that is started by a setting is a loop that has
// to be stopped by one, and every path that forgets leaves either a blocker that stopped
// updating or two of them running.
// A round that fails does not end the loop: the lists would then stay frozen at whatever
// one bad network moment downloaded. What the round ended with goes to the card instead.
// A settings edit wakes it rather than waiting for the next tick: switching blocking on is a
// download the user is watching for, and a minute of the card saying nothing is being blocked
// is a minute in which the app looks like it needs to be told to do what it was already doing.
func (a *Agent) runBlocklists(ctx context.Context) {
	a.noteBlocklistRound(a.reconcileBlocklists(ctx, false))
	tick := time.NewTicker(blocklistCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-a.blocklistWake:
		}
		a.noteBlocklistRound(a.reconcileBlocklists(ctx, false))
	}
}

// waitForDownloadLoop waits for one of the loops keeping downloaded files current to return
// during shutdown. Those loops are the background goroutines writing to the state directory,
// so a caller told the agent has stopped is entitled to consider the directory finished with.
func waitForDownloadLoop(what string, done <-chan struct{}, within time.Duration) error {
	if done == nil {
		return nil
	}
	timer := time.NewTimer(within)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("the " + what + " update did not stop within " + within.String() +
			"; it may still be writing to the state directory")
	}
}

// noteBlocklistRound records how the last round ended, for the card to show. A round that
// succeeds clears it, so a failure that has since been recovered from does not stay on
// screen naming a network that has come back.
func (a *Agent) noteBlocklistRound(err error) {
	if err == nil {
		a.blocklistRound.Store(nil)
		return
	}
	message := err.Error()
	a.blocklistRound.Store(&message)
}

// blocklistRoundError is what the last round ended with, empty when it ended cleanly.
func (a *Agent) blocklistRoundError() string {
	if message := a.blocklistRound.Load(); message != nil {
		return *message
	}
	return ""
}

// reconcileBlocklists brings the matcher to what the settings ask for and hands it to both
// consumers. force downloads every list whether it is due or not, which is what the refresh
// button does.
func (a *Agent) reconcileBlocklists(ctx context.Context, force bool) error {
	runner := a.currentBlocklists()
	if runner == nil {
		return nil
	}
	target := a.blocklistTarget()

	if !target.on {
		runner.clear()
		a.applyBlocklistToTunnels(false)
		return nil
	}

	before := runner.set.Load()
	err := runner.refresh(ctx, target.lists, target.allow, target.deny, target.every, force)
	after := runner.set.Load()

	if err != nil {
		a.recordEvent(telemetry.CodeDNSBlockFailed,
			"A blocklist could not be updated; the copy already downloaded is still blocking.",
			map[string]string{"error": err.Error()})
		a.logger.Warn("updating the blocklists failed", "error", err)
	} else if after != nil && after != before {
		a.recordEvent(telemetry.CodeDNSBlockRefreshed,
			fmt.Sprintf("Blocklists compiled: %d names from %d lists.", after.Rules(), len(after.Lists())),
			map[string]string{"rules": strconv.Itoa(after.Rules())})
	}

	a.applyBlocklistToTunnels(target.own)
	if after != before {
		// The machine-wide resolver holds the matcher in its rules, and the rules are built
		// by the reconcile. Nothing else would tell it a new one exists.
		a.pokeReconcile()
	}
	return err
}

// applyBlocklistToTunnels hands the matcher to app-tail's own resolution, or takes it away.
func (a *Agent) applyBlocklistToTunnels(on bool) {
	if a.tunnels == nil {
		return
	}
	if !on {
		a.tunnels.SetBlocklist(nil)
		return
	}
	a.tunnels.SetBlocklist(a.currentBlocklists())
}

// blocklistLists is the catalog with what is known about each cached copy attached, in the
// order the catalog holds them. It is what the card, the CLI and the API all report from.
func (a *Agent) blocklistLists() []blocklistListState {
	c := a.store.Get()
	catalog := dnsblock.Catalog(c.Blocklists)
	on := c.Settings.DNSBlockLists

	var (
		index    map[string]feeds.State
		compiled map[string]dnsblock.ListStat
	)
	if runner := a.currentBlocklists(); runner != nil {
		index, _ = runner.snapshot()
		if set := runner.set.Load(); set != nil {
			compiled = make(map[string]dnsblock.ListStat)
			for _, stat := range set.Lists() {
				compiled[stat.ID] = stat
			}
		}
	}

	out := make([]blocklistListState, 0, len(catalog))
	for _, l := range catalog {
		st := index[l.ID]
		entry := blocklistListState{
			Blocklist: l,
			Enabled:   slices.Contains(on, l.ID),
			Rules:     st.Rules,
			Skipped:   st.Skipped,
			Bytes:     st.Bytes,
			Error:     st.Error,
			Note:      dnsblock.Note(l.ID),
			Provider:  dnsblock.Provider(l),
		}
		if !st.FetchedAt.IsZero() {
			entry.UpdatedAt = st.FetchedAt
		}
		if stat, live := compiled[l.ID]; live {
			// What the live matcher holds beats what the index remembers: a list switched
			// on a moment ago has an index entry and no rules in force yet.
			entry.Rules, entry.Skipped = stat.Rules, stat.Skipped
		}
		out = append(out, entry)
	}
	return out
}

// blocklistListState is one catalog entry and what is known about its downloaded copy.
type blocklistListState struct {
	config.Blocklist
	Enabled   bool
	Rules     int
	Skipped   int
	Bytes     int
	UpdatedAt time.Time
	Error     string
	Note      string
	Provider  string
}
