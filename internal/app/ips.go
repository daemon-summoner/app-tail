// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/tlsmint"
)

// manualSourceID and manualSourceName are what the entries typed into the settings compile
// as. They are one source rather than two so a match reads back as the thing the user
// edits, which is one settings card holding both lists.
const (
	manualSourceID   = "manual"
	manualSourceName = "your own entries"
)

// recentDetections is how many matches the runner keeps in memory for the card.
//
// It exists because the durable record is the telemetry log, and telemetry is off until
// the user turns it on: without this, a fresh install would inspect traffic, match it, and
// show an empty card. A hundred is what fits on a screen a user scrolls once, and the ring
// is what keeps the memory a fixed cost rather than one that grows with a scan.
const recentDetections = 100

// Detection is one match the runner recorded, in the shape the card and the CLI read it.
type Detection struct {
	At       time.Time `json:"at"`
	Signal   string    `json:"signal"`
	Value    string    `json:"value"`
	Source   string    `json:"source"`
	Reason   string    `json:"reason"`
	Where    string    `json:"where"`
	Peer     string    `json:"peer,omitempty"`
	Refused  bool      `json:"refused"`
	Protocol string    `json:"protocol,omitempty"`
	// Fingerprint is which family of TLS software opened the connection, on a finding read
	// from the opening bytes with fingerprinting on. It is a note beside the match rather
	// than part of it: nothing is ever matched on this.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ipsRunner owns traffic inspection: the compiled rules, the mode, and the ring of what has
// matched recently. Every place app-tail carries traffic holds this same value through a
// one-method interface, so no two of them can disagree about what a rule says.
//
// It answers "carry it" while inspection is paused, which is what makes a pause take effect
// on the next connection rather than on the next reconcile. That is the property that
// matters most here: an inspector a user cannot un-break without restarting the app is one
// whose first false positive costs them their working machine.
type ipsRunner struct {
	now func() time.Time
	// record is how a match reaches the log. It is a seam rather than a direct call so the
	// runner can be tested without an agent, and so the one caller on the data path is a
	// function pointer rather than a package dependency.
	record func(code telemetry.EventCode, message string, fields map[string]string)
	// log is where a failure that is nobody's connection lands: a set of entries that will
	// not compile is an operator's problem, not one a carried connection reports.
	log *slog.Logger

	// rules is the live matcher, replaced whole. Nil is inspection switched off and every
	// state before the first compile.
	rules atomic.Pointer[inspect.Rules]
	// prevent is whether a match is refused rather than only recorded. Separate from the
	// rules so switching the mode does not recompile them.
	prevent atomic.Bool
	// names and destinations are the two setup-time signal switches, read per connection.
	names        atomic.Bool
	destinations atomic.Bool
	// handshake is whether the opening bytes of a connection are read, and fingerprints
	// whether the software that sent them is noted alongside the name they carried. The
	// second is separate because it describes the program rather than the destination.
	handshake    atomic.Bool
	fingerprints atomic.Bool
	// signatures is the live byte-pattern set, nil while payload signatures are off. It is a
	// pointer rather than a switch beside a fixed set for the reason watch is: off has to
	// mean the patterns are not in memory, since they are the one part of inspection whose
	// contents are a secret the user is watching for.
	signatures atomic.Pointer[inspect.Signatures]
	// watch is the flow ledger the sweep reads, nil while the anomaly signal is off. It is
	// a pointer rather than a switch beside a fixed ledger because off has to mean the
	// record of where traffic went is gone, not merely unread.
	watch atomic.Pointer[inspect.Watch]
	// authority is the root interception presents with, nil until one has been generated or
	// read back, and nil forever while interception is off. It is held here rather than
	// beside the settings because the data path reads it per connection and must not take a
	// lock to do so.
	authority atomic.Pointer[tlsmint.Authority]
	// scope is which connections are opened, nil while none are. Both must be set for a
	// connection to be opened, which is what makes "off" one comparison rather than several.
	scope atomic.Pointer[tlsmint.Scope]
	// rootMu orders everything that reads, generates or deletes the root's files, so a removal
	// can never land between a reconcile finding no files and it writing new ones.
	rootMu sync.Mutex
	// rootOutgrown is whether the list being intercepted reaches past what the root in use was
	// made for, so the event saying so is recorded once per change rather than per reconcile.
	rootOutgrown atomic.Bool
	// intercepted and interceptFailures are how many connections were opened and how many
	// were stopped because they could not be. The second is the number that matters: it is
	// the count of connections interception broke.
	intercepted       atomic.Int64
	interceptFailures atomic.Int64
	// pausedUntil is unix nanoseconds; zero is running. Deliberately not persisted: an
	// inspector that comes back paused after a restart is the one failure this must not
	// have.
	pausedUntil atomic.Int64
	// matched and refused are the running totals of rule matches, which survive the ring
	// wrapping, and anomalies is the same for what the sweep found. The two are counted
	// apart because they answer different questions: one is how much of what you named is
	// being reached, the other is how this machine has been behaving.
	matched   atomic.Int64
	refusals  atomic.Int64
	anomalies atomic.Int64

	mu sync.Mutex
	// built is what the live rules were compiled from, so an unchanged round costs no
	// second compile, and builtPatterns is the same for the signatures.
	built         string
	builtPatterns string
	// compiledAt is when that happened, for the card.
	compiledAt time.Time
	// recent is the ring of findings, oldest first once it has wrapped.
	recent []Detection
	// next is where the following finding is written, which is what makes the ring a ring.
	next int
}

// newIPSRunner builds a runner that records through record, logs through log and reads the
// clock through now.
func newIPSRunner(now func() time.Time,
	record func(code telemetry.EventCode, message string, fields map[string]string),
	log *slog.Logger) *ipsRunner {

	return &ipsRunner{
		now:    now,
		record: record,
		log:    log,
		recent: make([]Detection, 0, recentDetections),
	}
}

// Refuse reports why a connection must not be carried, and whether it must not.
//
// It is the whole of what every carrying path asks, and it records the match itself: a
// caller that had to remember to report what it was told would be a caller that can forget,
// and the paths asking this are four different packages that share nothing else.
//
// A match while inspection is only recording answers false. The match is real and is in the
// log; carrying it is what recording means.
func (r *ipsRunner) Refuse(f inspect.Flow) (string, bool) {
	if r == nil {
		return "", false
	}
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return "", false
	}

	// The ledger is written before the rules are asked, because the two signals are
	// independent: what a run of connections adds up to is a question with an answer on a
	// machine where nothing has been typed into either list.
	r.watch.Load().Note(f, r.now())

	rules := r.rules.Load()
	if rules == nil {
		return "", false
	}

	// Each signal is asked only while its switch is on, so a user who turned one off is not
	// paying for it and is not seeing matches from it.
	name, addr := f.Name, f.Addr
	if !r.names.Load() {
		name = ""
	}
	if !r.destinations.Load() {
		addr = netip.Addr{}
	}
	found, ok := rules.Check(name, addr)
	if !ok {
		return "", false
	}

	refuse := r.prevent.Load()
	r.note(Detection{
		At:       r.now(),
		Signal:   string(found.Signal),
		Value:    found.Value,
		Source:   found.Source,
		Reason:   found.Reason(),
		Where:    f.Where,
		Peer:     f.Peer,
		Protocol: f.Protocol,
		Refused:  refuse,
	})
	if !refuse {
		return "", false
	}
	return found.Reason(), true
}

// push writes one finding to the ring the card reads. Counting it is the caller's, because
// a rule match and an anomaly are counted apart.
func (r *ipsRunner) push(d Detection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.recent) < recentDetections {
		r.recent = append(r.recent, d)
	} else {
		r.recent[r.next] = d
	}
	r.next = (r.next + 1) % recentDetections
}

// note writes one match to the ring, to the totals, and to the log.
func (r *ipsRunner) note(d Detection) {
	r.push(d)
	r.matched.Add(1)
	if d.Refused {
		r.refusals.Add(1)
	}

	code, verb := telemetry.CodeIPSDetected, "was carried"
	if d.Refused {
		code, verb = telemetry.CodeIPSBlocked, "was refused"
	}
	fields := map[string]string{
		"signal": d.Signal,
		"value":  d.Value,
		"source": d.Source,
		"where":  d.Where,
	}
	if d.Protocol != "" {
		fields["protocol"] = d.Protocol
	}
	if d.Fingerprint != "" {
		fields["fingerprint"] = d.Fingerprint
	}
	if d.Peer != "" {
		fields["peer"] = d.Peer
	}
	r.record(code, fmt.Sprintf("A connection %s: %s.", verb, d.Reason), fields)
}

// recentMatches returns the ring newest first, which is the order it is read in.
func (r *ipsRunner) recentMatches() []Detection {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]Detection, 0, len(r.recent))
	// Walk backwards from the write cursor, so the newest entry comes out first whether or
	// not the ring has wrapped.
	for i := 0; i < len(r.recent); i++ {
		at := (r.next - 1 - i + len(r.recent)*2) % len(r.recent)
		out = append(out, r.recent[at])
	}
	return out
}

// totals are how many connections have matched, how many of those were refused, and how
// many runs of connections the sweep has found something in.
func (r *ipsRunner) totals() (matched, refused, anomalies int64) {
	return r.matched.Load(), r.refusals.Load(), r.anomalies.Load()
}

// pause stops inspection for a while and returns when it ends. A pause while already paused
// replaces the deadline rather than adding to it.
func (r *ipsRunner) pause(d time.Duration) time.Time {
	until := r.now().Add(d)
	r.pausedUntil.Store(until.UnixNano())
	return until
}

// resume ends a pause now.
func (r *ipsRunner) resume() { r.pausedUntil.Store(0) }

// paused reports when a pause ends, and whether one is in force. An expired deadline reads
// as running without anything having had to clear it.
func (r *ipsRunner) paused() (time.Time, bool) {
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

// clear drops the rules, which is what switching inspection off does. The ring stays: what
// matched while it was on is still what the user turned it off to look at.
func (r *ipsRunner) clear() {
	r.rules.Store(nil)
	r.mu.Lock()
	r.built, r.compiledAt = "", time.Time{}
	r.mu.Unlock()
}

// compiled reports when the live rules were built, zero when there are none.
func (r *ipsRunner) compiled() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.compiledAt
}

// needsCompile reports whether the matcher would be rebuilt from key, so a caller can skip
// the work of producing the sources for a round that would compile what is already live.
//
// It exists because that work is not free once feeds are involved: reading and parsing every
// downloaded copy is hundreds of thousands of lines, and the reconcile runs whenever any
// setting changes.
func (r *ipsRunner) needsCompile(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return key != r.built || r.rules.Load() == nil
}

// compile builds the matcher from sources, under the key that says what they were built
// from. An unchanged key is a no-op, so the reconcile can run as often as it likes without
// re-parsing what it already holds.
//
// The key is the caller's rather than derived from the entries, because the entries are the
// expensive thing: a feed source is keyed on which copy it came from, and only the entries
// somebody typed are short enough to key on themselves.
//
// A set that will not compile leaves the rules already in force applying and is reported as
// a failed event rather than handed back: switching inspection off because one edit did not
// build is the failure a user reads as the feature having quietly stopped working, and the
// caller has nothing else it could do with the error.
func (r *ipsRunner) compile(key string, sources []inspect.Source) {
	if !r.needsCompile(key) {
		return
	}

	rules, err := inspect.Compile(sources)
	if err != nil {
		r.record(telemetry.CodeIPSFailed,
			"The traffic-inspection rules could not be built; the rules already in force still apply.",
			map[string]string{"error": err.Error()})
		r.log.Warn("building the traffic-inspection rules failed", "error", err)
		return
	}

	r.rules.Store(rules)
	r.mu.Lock()
	r.built, r.compiledAt = key, r.now()
	r.mu.Unlock()
}

// ipsCompileKey is every entry in the sources given, so an edit to any of them is a
// different key and anything else is the same one.
//
// Only the entries the user typed go through this. A downloaded feed is keyed on which copy
// it came from instead, by ipsFeedRunner.sourcesKey: a hundred thousand addresses would
// otherwise be concatenated into a multi-megabyte string on every reconcile, to answer a
// question the feed's fetch time already answers.
func ipsCompileKey(sources []inspect.Source) string {
	var b strings.Builder
	for _, source := range sources {
		b.WriteString(source.ID)
		b.WriteByte(2)
		for _, entry := range source.Allow {
			b.WriteString(entry)
			b.WriteByte(0)
		}
		b.WriteByte(1)
		for _, entry := range source.Deny {
			b.WriteString(entry)
			b.WriteByte(0)
		}
		b.WriteByte(3)
	}
	return b.String()
}

// currentIPS returns the runner, which exists for the life of the agent.
func (a *Agent) currentIPS() *ipsRunner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ips
}

// ipsTarget is what the settings ask the runner for.
type ipsTarget struct {
	// on is inspection switched on at all. Off drops the rules, which is what gives the
	// memory back.
	on bool
	// prevent is whether a match is refused rather than only recorded.
	prevent bool
	// names, destinations and anomaly are the signals. All off is inspection switched on
	// and applied to nothing, which the capability reports as degraded rather than as
	// working.
	names        bool
	destinations bool
	anomaly      bool
	// handshake reads the opening bytes, and fingerprints notes what sent them. The second
	// needs the first: there are no opening bytes to fingerprint without it.
	handshake    bool
	fingerprints bool
	// payload reads the same window against signatures, and patterns are what it reads
	// against. It needs the handshake for the same reason fingerprints does: there is no
	// window to read without it. With no pattern written it stays off whatever the switch
	// says: holding the window costs memory per connection, and an empty set matches nothing.
	payload  bool
	patterns []string
	allow    []string
	deny     []string
}

// ipsTarget reads the settings into what the runner should do.
func (a *Agent) ipsTarget() ipsTarget {
	s := a.store.Get().Settings
	return ipsTarget{
		on:           s.IPSEnabled,
		prevent:      s.IPSMode == config.IPSModePrevent,
		names:        s.IPSEnabled && s.IPSNames,
		destinations: s.IPSEnabled && s.IPSDestinations,
		anomaly:      s.IPSEnabled && s.IPSAnomaly,
		handshake:    s.IPSEnabled && s.IPSHandshake,
		fingerprints: s.IPSEnabled && s.IPSHandshake && s.IPSFingerprints,
		payload:      s.IPSEnabled && s.IPSHandshake && s.IPSPayload && len(s.IPSSignatures) > 0,
		patterns:     slices.Clone(s.IPSSignatures),
		allow:        slices.Clone(s.IPSAllow),
		deny:         slices.Clone(s.IPSDeny),
	}
}

// reconcileIPS brings the matcher to what the settings ask for and hands it to every path
// that carries traffic.
//
// It is called from the same reconcile that applies every other setting, rather than from a
// loop of its own: there is nothing to download here, so the rules change only when the
// settings do, and a ticker would be a timer waking up to find nothing to do.
func (a *Agent) reconcileIPS() {
	runner := a.currentIPS()
	target := a.ipsTarget()

	// The switches are stored before the rules, so a connection arriving during the compile
	// is measured against the mode the user has asked for rather than the previous one.
	runner.prevent.Store(target.prevent)
	runner.names.Store(target.names)
	runner.destinations.Store(target.destinations)
	runner.handshake.Store(target.handshake)
	runner.fingerprints.Store(target.fingerprints)
	runner.watchFor(target.anomaly)
	// Before the switch below, so turning inspection off takes the patterns out of memory
	// rather than leaving a set nothing reads.
	if target.payload {
		runner.compileSignatures(manualSourceName, target.patterns)
	} else {
		runner.clearSignatures()
	}
	// After the signals and before the switch below, for the same reason: off has to take the
	// root out of memory, not merely stop reaching it.
	a.reconcileIPSIntercept(runner)

	if !target.on {
		runner.clear()
		a.applyIPS(false)
		return
	}

	manual := inspect.Source{
		ID:    manualSourceID,
		Name:  manualSourceName,
		Allow: target.allow,
		Deny:  target.deny,
	}
	// The user's own entries come first so a match names them rather than a feed: they are
	// what somebody typed, and a reason pointing at a downloaded file would send them looking
	// in the wrong place for the line to remove.
	sources := []inspect.Source{manual}

	feedTarget := a.ipsFeedTarget()
	feedRunner := a.currentIPSFeeds()
	key := ipsCompileKey(sources)
	if feedRunner != nil {
		key += feedRunner.sourcesKey(feedTarget.feeds)
	}
	if !runner.needsCompile(key) {
		a.applyIPS(true)
		return
	}
	if feedRunner != nil {
		fromFeeds, err := feedRunner.sources(feedTarget.feeds)
		if err != nil {
			// One unreadable copy is not the other feeds' problem, and it is already recorded
			// against the feed it belongs to. What is left still compiles.
			a.logger.Warn("reading a downloaded traffic-inspection feed failed", "error", err)
		}
		sources = append(sources, fromFeeds...)
	}

	before := runner.rules.Load()
	runner.compile(key, sources)
	if after := runner.rules.Load(); after != nil && after != before {
		a.recordEvent(telemetry.CodeIPSCompiled,
			fmt.Sprintf("Traffic-inspection rules compiled: %d entries.", after.Count()),
			map[string]string{"entries": strconv.Itoa(after.Count())})
	}
	a.applyIPS(true)
}

// applyIPS hands the inspector to every path that carries traffic, or takes it away.
//
// One value reaches all of them, so the mode and the pause cannot be in force on one path
// and not another. Nil is the switch being off, and every path reads nil as carrying
// everything.
func (a *Agent) applyIPS(on bool) {
	var inspector *ipsRunner
	if on {
		inspector = a.currentIPS()
	}

	if a.proxies != nil {
		a.proxies.SetInspector(inspector)
	}
	if a.subnets != nil {
		a.subnets.SetInspector(inspector)
	}
	if manager := a.currentManager(); manager != nil {
		manager.SetInspector(inspector)
	}
	if fabric := a.currentFabric(); fabric != nil {
		fabric.SetInspector(inspector)
	}
}
