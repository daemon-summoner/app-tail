// SPDX-License-Identifier: MIT

package tsproxy

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// maxDestinations is how many distinct destinations are tracked by name.
//
// Destinations are whatever a program asks the proxy for, so the set is unbounded and
// attacker-adjacent: a browser pointed at the PAC file will name every host it visits.
// Past this many, further destinations are summed into one bucket rather than growing a
// map forever. The dashboard says when that has happened -- a list silently cut short
// reads as a complete one.
const maxDestinations = 64

// destEntry is what one destination has cost. Every field is atomic because the byte
// counters are written from each connection's own goroutine while the dashboard reads
// them from another; the table's mutex guards which entries exist, not their contents.
type destEntry struct {
	upBytes atomic.Int64
	rxBytes atomic.Int64
	opened  atomic.Int64
	active  atomic.Int64
	refused atomic.Int64
	failed  atomic.Int64
	// lastAt is when a connection to this destination was last opened or closed, in unix
	// nanoseconds. It picks the eviction victim. It is deliberately not updated per read
	// or write: a clock read on every byte would be the most expensive thing in the copy
	// loop, and connection edges are granular enough to choose a victim by.
	lastAt atomic.Int64
	// route is how this destination was last reached: which connection carried it and over
	// which transport. It is what lets the activity graphs filter a destination or a port by
	// the connection carrying it, which is the question the port graph exists to answer.
	//
	// Latest rather than a set, because the entry is keyed by address alone: a destination
	// whose routing rule changed is reported the way it is reached now. A pointer swap keeps
	// the pair consistent -- reading a connection from one dial and a transport from another
	// would name a combination nothing used.
	route atomic.Pointer[destRoute]
}

// destRoute is how a destination was reached, as one indivisible fact.
type destRoute struct {
	tunnelID string
	protocol string
}

// DestCounters is one destination's traffic as a value, for the API and the dashboard.
type DestCounters struct {
	// Address is the destination as the program asked for it -- a name and port, not the
	// address it resolved to. It is what someone reading the dashboard recognises, and it
	// stays stable when a peer's address changes.
	Address   string `json:"address"`
	BytesUp   int64  `json:"bytesUp"`
	BytesDown int64  `json:"bytesDown"`
	Opened    int64  `json:"opened"`
	Active    int64  `json:"active"`
	Refused   int64  `json:"refused"`
	Failed    int64  `json:"failed"`
	// Via is the connection that carried this destination when it was last dialled, empty
	// for one that left through this machine's own network or was never reached at all.
	Via string `json:"via,omitempty"`
	// Protocol is the transport it was last reached over, in the words a rule uses.
	Protocol string `json:"protocol,omitempty"`
}

// total orders the table: the destinations worth showing first are the ones that moved
// the most, and a destination that only ever failed still has to rank above silence.
func (d DestCounters) total() int64 {
	return d.BytesUp + d.BytesDown + d.Refused + d.Failed
}

// Counters is every running instance's traffic summed, which is what a machine-wide
// traffic graph is about: how much left this machine through a proxy, not which listener
// it happened to leave through.
//
// Destinations are merged by name, because one destination reached through two instances is
// one destination. The merged list is re-capped at maxDestinations for the same reason each
// instance's own is: the set is whatever programs on this machine ask for, so it is
// unbounded, and what the cap leaves out is reported rather than dropped.
func (s *Set) Counters() Counters {
	var (
		out    Counters
		merged = map[string]DestCounters{}
	)
	for _, inst := range s.All() {
		c := inst.countersOf()
		out.Opened += c.Opened
		out.Active += c.Active
		out.Refused += c.Refused
		out.Failed += c.Failed
		out.BytesUp += c.BytesUp
		out.BytesDown += c.BytesDown
		out.Other = addDest(out.Other, c.Other)
		out.Folded += c.Folded
		for _, d := range c.Destinations {
			merged[d.Address] = addDest(merged[d.Address], d)
		}
	}

	named := make([]DestCounters, 0, len(merged))
	for address, d := range merged {
		d.Address = address
		named = append(named, d)
	}
	// Busiest first, then by name so a tie does not reshuffle the table on every poll.
	sort.Slice(named, func(i, j int) bool {
		if a, b := named[i].total(), named[j].total(); a != b {
			return a > b
		}
		return named[i].Address < named[j].Address
	})
	if len(named) > maxDestinations {
		for _, d := range named[maxDestinations:] {
			out.Other = addDest(out.Other, d)
			out.Folded++
		}
		named = named[:maxDestinations]
	}
	// The shared bucket is many destinations reached many ways, so it names none of them:
	// carrying the last one folded into it would label the whole bucket by one member.
	out.Other.Via, out.Other.Protocol = "", ""
	out.Destinations = named
	return out
}

// addDest sums one destination's figures into another. The address is the caller's to set:
// the shared bucket has none, and a merged entry takes its own.
//
// The route is taken rather than summed: one destination reached through two instances is
// still reached over one connection, and an instance that has not reached it yet knows
// nothing about it rather than knowing it goes nowhere.
func addDest(into, from DestCounters) DestCounters {
	into.BytesUp += from.BytesUp
	into.BytesDown += from.BytesDown
	into.Opened += from.Opened
	into.Active += from.Active
	into.Refused += from.Refused
	into.Failed += from.Failed
	if from.Via != "" {
		into.Via = from.Via
	}
	if from.Protocol != "" {
		into.Protocol = from.Protocol
	}
	return into
}

// destTable attributes proxy traffic per destination, within a fixed budget.
type destTable struct {
	mu    sync.Mutex
	byKey map[string]*destEntry
	// other absorbs everything past the cap, including the totals of entries evicted to
	// make room. Folding rather than dropping is what keeps the per-destination figures
	// summing to the proxy's own totals.
	other destEntry
	// folded counts the distinct destinations that ended up in other, so the dashboard
	// can say how much it is not naming.
	folded int
	clock  func() time.Time
}

func (t *destTable) now() time.Time {
	if t.clock != nil {
		return t.clock()
	}
	return time.Now()
}

// entry returns the counters for one destination, making room if the table is full.
//
// A destination that cannot be given a slot is answered with the shared bucket, so a
// caller never has to handle a nil and traffic is never simply uncounted.
func (t *destTable) entry(address string) *destEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.byKey == nil {
		t.byKey = make(map[string]*destEntry, maxDestinations)
	}
	if e, ok := t.byKey[address]; ok {
		return e
	}
	if len(t.byKey) >= maxDestinations && !t.evictOneLocked() {
		// Every slot is in use by a live connection. The new destination is still
		// counted, just not named.
		t.folded++
		return &t.other
	}

	e := &destEntry{}
	e.lastAt.Store(t.now().UnixNano())
	t.byKey[address] = e
	return e
}

// evictOneLocked frees the slot held by the destination that has been idle longest,
// folding its totals into the shared bucket so nothing is lost from the sums. A
// destination with a connection still open is never evicted: its active count would be
// stranded and the gauge would drift away from reality for as long as the process lives.
func (t *destTable) evictOneLocked() bool {
	var (
		victimKey string
		victim    *destEntry
		oldest    int64
	)
	for key, e := range t.byKey {
		if e.active.Load() > 0 {
			continue
		}
		if at := e.lastAt.Load(); victim == nil || at < oldest {
			victimKey, victim, oldest = key, e, at
		}
	}
	if victim == nil {
		return false
	}

	t.other.upBytes.Add(victim.upBytes.Load())
	t.other.rxBytes.Add(victim.rxBytes.Load())
	t.other.opened.Add(victim.opened.Load())
	t.other.refused.Add(victim.refused.Load())
	t.other.failed.Add(victim.failed.Load())
	delete(t.byKey, victimKey)
	t.folded++
	return true
}

// touch records activity at a connection edge, for the eviction order.
func (t *destTable) touch(e *destEntry) { e.lastAt.Store(t.now().UnixNano()) }

// snapshot is every named destination, busiest first, plus what was left unnamed.
func (t *destTable) snapshot() ([]DestCounters, DestCounters, int) {
	t.mu.Lock()
	out := make([]DestCounters, 0, len(t.byKey))
	for address, e := range t.byKey {
		d := DestCounters{
			Address:   address,
			BytesUp:   e.upBytes.Load(),
			BytesDown: e.rxBytes.Load(),
			Opened:    e.opened.Load(),
			Active:    e.active.Load(),
			Refused:   e.refused.Load(),
			Failed:    e.failed.Load(),
		}
		if route := e.route.Load(); route != nil {
			d.Via, d.Protocol = route.tunnelID, route.protocol
		}
		out = append(out, d)
	}
	other := DestCounters{
		Address:   "",
		BytesUp:   t.other.upBytes.Load(),
		BytesDown: t.other.rxBytes.Load(),
		Opened:    t.other.opened.Load(),
		Active:    t.other.active.Load(),
		Refused:   t.other.refused.Load(),
		Failed:    t.other.failed.Load(),
	}
	folded := t.folded
	t.mu.Unlock()

	// Busiest first, then by name so a tie does not reshuffle the table on every poll.
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].total(), out[j].total(); a != b {
			return a > b
		}
		return out[i].Address < out[j].Address
	})
	return out, other, folded
}
