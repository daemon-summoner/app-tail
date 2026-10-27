// SPDX-License-Identifier: MIT

package inspect

// The second thing inspection can see: not what one flow is bound for, but the shape a
// series of them makes. A rule matches a destination somebody already knew was bad; this
// notices a machine behaving in a way no ordinary program does, against no list at all.
//
// Everything here reads a ledger that is written on the data path and swept on a timer, so
// the cost a carried connection pays is one bounded append and nothing else. The sweep runs
// where no connection is waiting for it.

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// SignalPortScan is one source reaching many ports on a single destination.
	SignalPortScan Signal = "port-scan"
	// SignalFanOut is one source reaching many destinations at once.
	SignalFanOut Signal = "fan-out"
	// SignalDNSTunnel is a stream of machine-made names under one parent domain, which is
	// what data leaving inside DNS queries looks like from here.
	SignalDNSTunnel Signal = "dns-tunnel"
)

const (
	// watchedFlows and watchedQuestions bound the ledger. Both are rings: the memory is a
	// fixed cost rather than one a scan can grow, which matters most precisely when
	// something is scanning.
	watchedFlows     = 4096
	watchedQuestions = 2048
	// watchedMarks bounds how many findings are being held back at once, for the same
	// reason. A machine with more than this many distinct anomalies in one window has one
	// problem, not sixty-four.
	watchedMarks = 64
	// watchedPairs bounds how many source-and-destination pairs the beacon table follows.
	// Least recently seen is evicted, so a machine reaching thousands of addresses keeps
	// the ones it keeps going back to, which is the only kind this measures.
	watchedPairs = 512
)

// beaconWindow is how far back the beacon table looks. It is far longer than Limits.Window
// because regularity is the thing being measured and a minute holds too few connections to
// tell a rhythm from a coincidence. The table is a fixed number of small rows rather than a
// ring of connections, so the longer span costs nothing that grows.
const beaconWindow = 30 * time.Minute

const (
	// beaconMinSamples is how many intervals must be seen before regularity is reported at
	// all. Three connections give two intervals, and two intervals are equal by accident
	// often enough to mean nothing.
	beaconMinSamples = 6
	// beaconJitter is how much the intervals may vary, as a fraction of their mean, and
	// still read as a rhythm. Anything above this is a program being used rather than a
	// program checking in.
	beaconJitter = 0.15
	// beaconMinInterval is how far apart connections must be. Below this a rhythm is a
	// retry loop or a keepalive, which every long-lived client has.
	beaconMinInterval = 5 * time.Second
)

// LocalSource is what a flow with no peer is called. Only the subnet router knows which
// device asked; everything else app-tail carries was asked for by this machine.
const LocalSource = "this machine"

// Limits are the thresholds a sweep decides with. They are deliberately conservative:
// every one of these fires on a machine that is doing nothing wrong if it is set low
// enough, and a user who stops believing the alerts has an inspector that does nothing.
type Limits struct {
	// Window is how far back a sweep looks. Everything below is counted inside it.
	Window time.Duration
	// Destinations is how many distinct addresses one source reaches before that reads as
	// fanning out. High: one web page is dozens of hosts.
	Destinations int
	// Ports is how many distinct ports one source reaches on a single destination before
	// that reads as a port scan. This is the high-signal one -- no ordinary program walks
	// the ports of one host -- so it is much lower than Destinations.
	Ports int
	// Names is how many distinct names under one parent must be asked about, and Entropy
	// how random their leftmost labels must look, before that reads as data leaving inside
	// DNS. Both must hold: a busy CDN answers the first and fails the second.
	Names   int
	Entropy float64
	// MinLabel is how long a label has to be to count toward Entropy at all. Short labels
	// score high on randomness for arithmetic reasons rather than real ones.
	MinLabel int
}

// DefaultLimits are what the switch turns on. They are set where an ordinary desktop does
// not reach them: a port scan and a DNS tunnel are both far outside anything a browser,
// a package manager or a backup client does.
func DefaultLimits() Limits {
	return Limits{
		Window:       time.Minute,
		Destinations: 120,
		Ports:        20,
		Names:        40,
		Entropy:      3.4,
		MinLabel:     12,
	}
}

// Anomaly is one thing a sweep found: which shape, what it was about, and how much of it
// there was. It carries the window it was seen in so the sentence can say "in the last
// minute" rather than leaving the reader to guess the scale.
type Anomaly struct {
	Signal Signal `json:"signal"`
	// Peer is the device that did it, empty for this machine's own traffic.
	Peer string `json:"peer,omitempty"`
	// Value is what it was done to: the destination for a port scan, the parent domain for
	// a DNS tunnel, and the source itself for fanning out, which is about no one target.
	Value string `json:"value"`
	// Count is how many of the thing there were -- ports, destinations, or names.
	Count int `json:"count"`
	// Since and Until are the first and last of them.
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// Source is what the anomaly calls whoever caused it.
func (a Anomaly) Source() string {
	if a.Peer == "" {
		return LocalSource
	}
	return a.Peer
}

// Reason is the sentence the event and the card carry. It names the count, because "a port
// scan was detected" is an alert a user can do nothing with and "22 ports on 10.1.2.9 in
// 60 seconds" is one they can recognise or dismiss on sight.
func (a Anomaly) Reason() string {
	over := a.Until.Sub(a.Since).Round(time.Second)
	switch a.Signal {
	case SignalPortScan:
		return fmt.Sprintf("%s reached %d different ports on %s in %s",
			a.Source(), a.Count, a.Value, over)
	case SignalFanOut:
		return fmt.Sprintf("%s opened connections to %d different addresses in %s",
			a.Source(), a.Count, over)
	case SignalDNSTunnel:
		return fmt.Sprintf("%d names under %s were looked up in %s, and they do not read "+
			"like names anything published", a.Count, a.Value, over)
	}
	return fmt.Sprintf("%s did something %s %d times in %s", a.Source(), a.Signal, a.Count, over)
}

// Watch is the ledger and the sweep over it. It is safe for the data path to write to from
// every carrying goroutine at once, and for the sweep to read from at the same time.
type Watch struct {
	limits Limits

	mu        sync.Mutex
	flows     [watchedFlows]flowRecord
	flowsHeld int
	flowsNext int
	names     [watchedQuestions]questionRecord
	namesHeld int
	namesNext int
	// marks is when each finding was last reported, so a scan still inside the window is
	// not reported again on every sweep. Bounded, oldest evicted.
	marks map[string]time.Time
	// pairs is the beacon table: one small row per source and destination, rather than a
	// ring of connections, because regularity is measured over half an hour and no ring
	// that size would be a fixed cost.
	pairs map[beaconKey]*beaconRow
}

// beaconKey is one source reaching one destination. The port is not part of it: a program
// checking in does so on one port, and folding the ports together would turn a scan into a
// rhythm.
type beaconKey struct {
	peer string
	addr netip.Addr
}

// beaconRow is how regularly one pair has been seen. The intervals are accumulated by
// Welford's method rather than kept, so the row is a fixed handful of numbers however many
// connections it has counted.
type beaconRow struct {
	first, last time.Time
	// samples is how many intervals have been counted, and mean and m2 are Welford's
	// running mean and sum of squared deviations over them.
	samples int
	mean    float64
	m2      float64
}

// Beacon is one pair whose connections arrive on a rhythm.
//
// It is an observation, never an alert: on one machine the regular things are Slack, a
// backup client, certificate checks and app-tail's own list refresh, and no threshold
// separates those from a check-in. It is reported so somebody who already suspects
// something can look for it, and it never refuses anything and never raises an event.
type Beacon struct {
	// Peer is the device doing it, empty for this machine's own traffic, and Addr what it
	// keeps going back to.
	Peer string `json:"peer,omitempty"`
	Addr string `json:"addr"`
	// Every is the average gap between connections, and Jitter how much they vary as a
	// fraction of that: nearer zero is more regular.
	Every  time.Duration `json:"every"`
	Jitter float64       `json:"jitter"`
	// Count is how many connections the rhythm was measured over, and Since when the first
	// of them was.
	Count int       `json:"count"`
	Since time.Time `json:"since"`
}

// Source is what the observation calls whoever made the connections.
func (b Beacon) Source() string {
	if b.Peer == "" {
		return LocalSource
	}
	return b.Peer
}

// flowRecord is one connection the ledger saw. It holds no name and no reason: this is
// about the shape of a series, and everything a single flow means is decided elsewhere.
type flowRecord struct {
	at   time.Time
	peer string
	addr netip.Addr
	port uint16
}

// questionRecord is one name this machine's resolver was asked about, split where the
// interesting part is: the parent is what a tunnel is run under, and the label is the part
// that carries the data.
type questionRecord struct {
	at     time.Time
	parent string
	label  string
}

// NewWatch builds a ledger. Zero values in limits are filled from DefaultLimits, so a
// caller that wants one threshold changed does not have to restate the rest.
func NewWatch(limits Limits) *Watch {
	def := DefaultLimits()
	if limits.Window <= 0 {
		limits.Window = def.Window
	}
	if limits.Destinations <= 0 {
		limits.Destinations = def.Destinations
	}
	if limits.Ports <= 0 {
		limits.Ports = def.Ports
	}
	if limits.Names <= 0 {
		limits.Names = def.Names
	}
	if limits.Entropy <= 0 {
		limits.Entropy = def.Entropy
	}
	if limits.MinLabel <= 0 {
		limits.MinLabel = def.MinLabel
	}
	return &Watch{
		limits: limits,
		marks:  make(map[string]time.Time, watchedMarks),
		pairs:  make(map[beaconKey]*beaconRow, watchedPairs),
	}
}

// Limits reports the thresholds in force, for the card.
func (w *Watch) Limits() Limits { return w.limits }

// Note records one flow. It is called for every connection app-tail carries, so it does
// the least it possibly can: no allocation, no clock read, no parsing.
func (w *Watch) Note(f Flow, at time.Time) {
	if w == nil || !f.Addr.IsValid() {
		return
	}
	w.mu.Lock()
	w.flows[w.flowsNext] = flowRecord{at: at, peer: f.Peer, addr: f.Addr, port: f.Port}
	w.flowsNext = (w.flowsNext + 1) % watchedFlows
	if w.flowsHeld < watchedFlows {
		w.flowsHeld++
	}
	w.noteRhythm(beaconKey{peer: f.Peer, addr: f.Addr}, at)
	w.mu.Unlock()
}

// noteRhythm folds one connection into how regularly its pair is seen. The caller holds the
// lock.
func (w *Watch) noteRhythm(key beaconKey, at time.Time) {
	row, held := w.pairs[key]
	if !held {
		w.evictPair(at)
		w.pairs[key] = &beaconRow{first: at, last: at}
		return
	}
	// A gap longer than the whole window is a pair coming back after being away, which is
	// a new run rather than one enormous interval in the middle of the old one.
	gap := at.Sub(row.last)
	if gap <= 0 || gap > beaconWindow {
		*row = beaconRow{first: at, last: at}
		return
	}
	row.last = at
	// Welford: the running mean and the sum of squared deviations, so the row stays a fixed
	// size however many connections it counts.
	row.samples++
	delta := gap.Seconds() - row.mean
	row.mean += delta / float64(row.samples)
	row.m2 += delta * (gap.Seconds() - row.mean)
}

// evictPair makes room in the beacon table, dropping everything already past the window and
// then, if that freed nothing, the pair seen longest ago. The caller holds the lock.
func (w *Watch) evictPair(now time.Time) {
	if len(w.pairs) < watchedPairs {
		return
	}
	cutoff := now.Add(-beaconWindow)
	for key, row := range w.pairs {
		if row.last.Before(cutoff) {
			delete(w.pairs, key)
		}
	}
	if len(w.pairs) < watchedPairs {
		return
	}
	oldestKey, oldest := beaconKey{}, now
	for key, row := range w.pairs {
		if !row.last.After(oldest) {
			oldestKey, oldest = key, row.last
		}
	}
	delete(w.pairs, oldestKey)
}

// Beacons reports the pairs whose connections arrive on a rhythm, most regular first.
//
// It is read by the card rather than by the sweep: these never become findings, never raise
// an event and never refuse anything. See Beacon for why.
func (w *Watch) Beacons(now time.Time) []Beacon {
	if w == nil {
		return nil
	}
	cutoff := now.Add(-beaconWindow)

	w.mu.Lock()
	defer w.mu.Unlock()

	var out []Beacon
	for key, row := range w.pairs {
		if row.samples < beaconMinSamples || row.last.Before(cutoff) {
			continue
		}
		if row.mean < beaconMinInterval.Seconds() {
			continue
		}
		jitter := math.Sqrt(row.m2/float64(row.samples)) / row.mean
		if jitter > beaconJitter {
			continue
		}
		out = append(out, Beacon{
			Peer:   key.peer,
			Addr:   key.addr.String(),
			Every:  time.Duration(row.mean * float64(time.Second)),
			Jitter: jitter,
			Count:  row.samples + 1,
			Since:  row.first,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Jitter != out[j].Jitter {
			return out[i].Jitter < out[j].Jitter
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

// Question records one name the resolver was asked about.
//
// It is only ever this machine's own resolver, which serves loopback: every question here
// came from something on this machine and there is no way to tell which program. That is
// why the finding says "this machine" and not more -- claiming otherwise would be inventing
// an attribution the data does not carry.
func (w *Watch) Question(name string, at time.Time) {
	if w == nil {
		return
	}
	parent, label := splitName(name)
	if parent == "" || label == "" {
		return
	}
	w.mu.Lock()
	w.names[w.namesNext] = questionRecord{at: at, parent: parent, label: label}
	w.namesNext = (w.namesNext + 1) % watchedQuestions
	if w.namesHeld < watchedQuestions {
		w.namesHeld++
	}
	w.mu.Unlock()
}

// Held reports how much the ledger is holding, for the card. A ledger that is always full
// is one whose window is longer than the ring can carry, and that is worth being able to
// see rather than having to infer from findings that stop arriving.
func (w *Watch) Held() (flows, questions int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flowsHeld, w.namesHeld
}

// Reset empties the ledger, which is what switching the anomaly signal off does. What was
// already reported stays reported: those are findings, and they live in the ring the card
// reads rather than here.
func (w *Watch) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flows, w.flowsHeld, w.flowsNext = [watchedFlows]flowRecord{}, 0, 0
	w.names, w.namesHeld, w.namesNext = [watchedQuestions]questionRecord{}, 0, 0
	clear(w.marks)
	clear(w.pairs)
}

// Sweep reports what the ledger looks like now, and takes responsibility for not saying the
// same thing twice: a scan still inside the window would otherwise be found again by every
// sweep until it aged out, which is one alert turned into twenty.
//
// The findings come back in a stable order, because two sweeps of the same ledger reporting
// the same things in a different order is a difference a reader would have to check.
func (w *Watch) Sweep(now time.Time) []Anomaly {
	if w == nil {
		return nil
	}
	cutoff := now.Add(-w.limits.Window)

	w.mu.Lock()
	defer w.mu.Unlock()

	found := append(w.sweepFlows(cutoff), w.sweepNames(cutoff)...)
	sort.Slice(found, func(i, j int) bool {
		if found[i].Signal != found[j].Signal {
			return found[i].Signal < found[j].Signal
		}
		if found[i].Value != found[j].Value {
			return found[i].Value < found[j].Value
		}
		return found[i].Peer < found[j].Peer
	})

	out := found[:0]
	for _, a := range found {
		key := string(a.Signal) + "\x00" + a.Peer + "\x00" + a.Value
		if last, held := w.marks[key]; held && now.Sub(last) < w.limits.Window {
			continue
		}
		w.mark(key, now)
		out = append(out, a)
	}
	return out
}

// mark records that a finding was reported, evicting the oldest when the table is full.
func (w *Watch) mark(key string, now time.Time) {
	if len(w.marks) >= watchedMarks {
		oldestKey, oldest := "", now
		for k, at := range w.marks {
			if !at.After(oldest) {
				oldestKey, oldest = k, at
			}
		}
		delete(w.marks, oldestKey)
	}
	w.marks[key] = now
}

// sourceTally is what one source did inside the window.
type sourceTally struct {
	dests map[netip.Addr]map[uint16]struct{}
	first map[netip.Addr]time.Time
	last  map[netip.Addr]time.Time
	// firstAny and lastAny span everything the source did, which is what fanning out is
	// measured over -- it is about no single destination.
	firstAny, lastAny time.Time
}

// sweepFlows finds the two shapes a series of connections can make. The caller holds the
// lock.
func (w *Watch) sweepFlows(cutoff time.Time) []Anomaly {
	sources := make(map[string]*sourceTally)
	for i := range w.flowsHeld {
		rec := w.flows[i]
		if rec.at.Before(cutoff) {
			continue
		}
		tally, held := sources[rec.peer]
		if !held {
			tally = &sourceTally{
				dests:    make(map[netip.Addr]map[uint16]struct{}),
				first:    make(map[netip.Addr]time.Time),
				last:     make(map[netip.Addr]time.Time),
				firstAny: rec.at,
				lastAny:  rec.at,
			}
			sources[rec.peer] = tally
		}
		ports, held := tally.dests[rec.addr]
		if !held {
			ports = make(map[uint16]struct{})
			tally.dests[rec.addr] = ports
		}
		ports[rec.port] = struct{}{}
		// The ledger is a ring, so once it has wrapped these arrive in whatever order the ring
		// holds them rather than the order they happened. The span is the earliest and the
		// latest, never the first and last seen here.
		if first, held := tally.first[rec.addr]; !held || rec.at.Before(first) {
			tally.first[rec.addr] = rec.at
		}
		if rec.at.After(tally.last[rec.addr]) {
			tally.last[rec.addr] = rec.at
		}
		if rec.at.Before(tally.firstAny) {
			tally.firstAny = rec.at
		}
		if rec.at.After(tally.lastAny) {
			tally.lastAny = rec.at
		}
	}

	var out []Anomaly
	for peer, tally := range sources {
		if len(tally.dests) >= w.limits.Destinations {
			out = append(out, Anomaly{
				Signal: SignalFanOut,
				Peer:   peer,
				Value:  sourceLabel(peer),
				Count:  len(tally.dests),
				Since:  tally.firstAny,
				Until:  tally.lastAny,
			})
		}
		for addr, ports := range tally.dests {
			if len(ports) < w.limits.Ports {
				continue
			}
			out = append(out, Anomaly{
				Signal: SignalPortScan,
				Peer:   peer,
				Value:  addr.String(),
				Count:  len(ports),
				Since:  tally.first[addr],
				Until:  tally.last[addr],
			})
		}
	}
	return out
}

// parentTally is what was asked under one parent domain inside the window.
type parentTally struct {
	labels      map[string]struct{}
	entropy     float64
	scored      int
	first, last time.Time
}

// sweepNames finds names that carry data rather than name anything. The caller holds the
// lock.
func (w *Watch) sweepNames(cutoff time.Time) []Anomaly {
	parents := make(map[string]*parentTally)
	for i := range w.namesHeld {
		rec := w.names[i]
		if rec.at.Before(cutoff) {
			continue
		}
		tally, held := parents[rec.parent]
		if !held {
			tally = &parentTally{labels: make(map[string]struct{}), first: rec.at, last: rec.at}
			parents[rec.parent] = tally
		}
		if _, seen := tally.labels[rec.label]; !seen {
			tally.labels[rec.label] = struct{}{}
			if len(rec.label) >= w.limits.MinLabel {
				tally.entropy += entropy(rec.label)
				tally.scored++
			}
		}
		if rec.at.Before(tally.first) {
			tally.first = rec.at
		}
		if rec.at.After(tally.last) {
			tally.last = rec.at
		}
	}

	var out []Anomaly
	for parent, tally := range parents {
		// Every one of the three has to hold. A busy CDN clears the count and fails the
		// randomness; a single long random name clears the randomness and fails the count.
		if len(tally.labels) < w.limits.Names || tally.scored == 0 {
			continue
		}
		if tally.entropy/float64(tally.scored) < w.limits.Entropy {
			continue
		}
		out = append(out, Anomaly{
			Signal: SignalDNSTunnel,
			Value:  parent,
			Count:  len(tally.labels),
			Since:  tally.first,
			Until:  tally.last,
		})
	}
	return out
}

// sourceLabel is the source as a value a card can show in a column of its own.
func sourceLabel(peer string) string {
	if peer == "" {
		return LocalSource
	}
	return peer
}

// splitName cuts a name into the parent a tunnel would be run under and the labels that
// would carry its data. The parent is the last two labels, which is not the registrable
// domain -- it is wrong for co.uk and every other multi-label suffix -- and that is
// deliberate: the alternative is shipping and refreshing the public suffix list to sharpen
// a threshold that is already counting dozens of names, and being wrong here splits one
// finding into a few rather than missing it.
func splitName(name string) (parent, label string) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	labels := strings.Split(name, ".")
	if len(labels) < 3 {
		return "", ""
	}
	cut := len(labels) - 2
	return strings.Join(labels[cut:], "."), strings.Join(labels[:cut], ".")
}

// entropy is Shannon entropy over the bytes of s, in bits per character. Random-looking
// text scores near 4 for the characters a name may hold; a word scores well under 3.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	total := float64(len(s))
	sum := 0.0
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / total
		sum -= p * math.Log2(p)
	}
	return sum
}
