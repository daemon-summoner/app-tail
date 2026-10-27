// SPDX-License-Identifier: MIT

package traffic

import (
	"sort"
	"sync"
	"time"
)

// A keyed lane is the same history the flat samples hold, broken down by whatever the
// dashboard wants to name: a tailnet device, a connection, a destination, a port.
//
// It is stored a column per tick rather than a map per tick. A map of every key, allocated
// once a second for every lane, is a few hundred small allocations a second for a history
// nobody may be looking at; a fixed slice per key is one allocation when the key first
// appears. Every key in a Table shares one cursor, so two keys read at the same tick land at
// the same index by construction -- which is what lets one hovered column on the dashboard
// mean the same instant on every chart.

// Pair is one key's cumulative bytes in each direction, as its own counters read them.
//
// Cumulative rather than a rate, for the reason Sample is: what the counters actually said
// keeps rounding from compounding across a series, and leaves a missed tick visible as a gap
// rather than averaged into a plausible-looking number nobody measured.
type Pair struct {
	Up   int64
	Down int64
}

// Row is one key's reading at one tick, together with the names the dashboard labels it by.
// The names are carried on every reading because they can change under a stable key -- a
// device is renamed, a connection moves to another tunnel -- and the latest is the true one.
type Row struct {
	Label string
	// Detail is the aside beside the label: "relay nyc", "wireguard", "tcp". Never the only
	// place a fact appears, because it is the first thing a narrow layout drops.
	Detail string
	// Via is the connection carrying this key, and Peer the tailnet device it belongs to.
	// Both are empty where the seam that counted the bytes could not attribute them: this
	// machine's own outbound traffic has no tailnet device, and a lane outside every tunnel
	// has no connection. They are what the dashboard's filters read.
	Via  string
	Peer string
	Pair
}

// Series is one key's whole window, oldest reading first.
type Series struct {
	Key    string
	Label  string
	Detail string
	Via    string
	Peer   string
	// Vals is the cumulative reading at each tick, and Seen which of those ticks the key was
	// present for at all. A key absent from a tick is not a key that carried nothing: a
	// device that was offline never reported a counter, and drawing that as zero invents a
	// quiet stretch it was not measured across.
	Vals []Pair
	Seen []bool
}

// Movement is what one key carried over one interval, in bytes a second.
type Movement struct {
	Up   float64
	Down float64
	// Gap marks an interval this key's rate could not be derived over: it was absent at
	// either end, its counters went backwards, or the tick itself was missed.
	Gap bool
}

// Table is a bounded set of keyed counters sharing one window and one cursor.
//
// The key set is whatever the network produces -- every port a program opens, every host it
// asks for -- so it is unbounded and attacker-adjacent in exactly the way the proxy's
// destination table is, and it is bounded the same way.
type Table struct {
	mu   sync.Mutex
	size int
	max  int
	// at is the slot the current tick writes to, and ticks how many have ever been written.
	// Together they give both the window's length and where its oldest reading is, without a
	// separate wrapped flag to keep in step with them.
	at    int
	ticks int
	when  []time.Time
	rows  map[string]*krow
	// folded is how many distinct keys the cap has dropped, so a chart drawn from a list cut
	// short can say so. A list silently cut short reads as a complete one.
	folded int
}

type krow struct {
	Row
	vals []Pair
	seen []bool
}

// NewTable builds a table holding at most max keys over a window of size ticks. Both are
// clamped to one: a zero-length window would silently record nothing.
func NewTable(size, max int) *Table {
	if size < 1 {
		size = 1
	}
	if max < 1 {
		max = 1
	}
	return &Table{size: size, max: max, when: make([]time.Time, size), rows: map[string]*krow{}}
}

// Advance opens the next tick at the given instant. Every key is marked absent for it, so a
// key that is not Set before the following Advance is recorded as one nothing reported --
// which is the truth about a device that went offline, not a second in which it was idle.
func (t *Table) Advance(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.at = t.ticks % t.size
	t.ticks++
	t.when[t.at] = at
	for _, r := range t.rows {
		r.seen[t.at] = false
		r.vals[t.at] = Pair{}
	}
}

// Set records one key's reading at the tick Advance opened.
//
// A key the table has no room for is dropped rather than displacing a busier one, and counted
// in folded. Nothing is silently uncounted: the flat lanes still hold every byte, and the
// breakdown says how much of itself it is not naming.
func (t *Table) Set(key string, row Row) {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, ok := t.rows[key]
	if !ok {
		if len(t.rows) >= t.max && !t.evictLocked() {
			t.folded++
			return
		}
		r = &krow{vals: make([]Pair, t.size), seen: make([]bool, t.size)}
		t.rows[key] = r
	}
	r.Row = row
	r.vals[t.at] = row.Pair
	r.seen[t.at] = true
}

// evictLocked frees a slot by dropping the key that has moved the least across the window,
// and never a live one -- a key that is still reporting is the one a reader is most likely
// watching, and a full table of them folds the newcomer instead.
//
// The dropped key's history goes with it rather than being folded into a shared bucket. These
// are rates over a window, and folding one key's cumulative total into another's makes the
// sum jump by everything the dropped key ever carried -- drawn as a spike of traffic that
// never happened, at the moment of an eviction nobody can see.
func (t *Table) evictLocked() bool {
	var (
		victimKey string
		least     int64
		found     bool
	)
	for key, r := range t.rows {
		if t.liveLocked(r) {
			continue
		}
		if moved := r.movedLocked(); !found || moved < least {
			victimKey, least, found = key, moved, true
		}
	}
	if !found {
		return false
	}
	delete(t.rows, victimKey)
	t.folded++
	return true
}

// liveLocked reports a key still in use, which is one that reported at this tick or the one
// before it.
//
// The previous tick is what makes this answer the same however the sampler orders its keys.
// Judging on the current tick alone would make a key evictable purely because its own Set
// had not been reached yet, so a newcomer could displace a live key on one tick and be
// displaced by it on the next, depending on nothing but map iteration order.
func (t *Table) liveLocked(r *krow) bool {
	if r.seen[t.at] {
		return true
	}
	return r.seen[(t.at-1+t.size)%t.size]
}

// movedLocked is how many bytes a key accounts for across the window, which is both what
// ranks it and what decides whether it is the one to drop. Counters are cumulative, so this
// is the span between its first and last reading rather than the sum of them.
func (r *krow) movedLocked() int64 {
	var (
		first Pair
		last  Pair
		open  bool
	)
	for i, seen := range r.seen {
		if !seen {
			continue
		}
		if !open {
			first, open = r.vals[i], true
		}
		last = r.vals[i]
	}
	if !open {
		return 0
	}
	// A counter that went backwards was reset, not run in reverse. Its span is unknowable, so
	// it ranks as nothing rather than as a negative that would make it the first to be
	// dropped.
	up, down := last.Up-first.Up, last.Down-first.Down
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	return up + down
}

// length is how many ticks the window currently holds.
func (t *Table) length() int {
	if t.ticks < t.size {
		return t.ticks
	}
	return t.size
}

// slots is the window's tick indices in order, oldest first.
func (t *Table) slots() []int {
	n := t.length()
	out := make([]int, n)
	if t.ticks <= t.size {
		for i := range out {
			out[i] = i
		}
		return out
	}
	start := t.ticks % t.size
	for i := range out {
		out[i] = (start + i) % t.size
	}
	return out
}

// Times is the instant each tick in the window was opened at, oldest first.
func (t *Table) Times() []time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()

	slots := t.slots()
	out := make([]time.Time, len(slots))
	for i, slot := range slots {
		out[i] = t.when[slot]
	}
	return out
}

// Snapshot is every key the table holds, busiest first, and how many it is not naming. The
// slices are freshly built, so a caller may hold them while the sampler keeps writing.
func (t *Table) Snapshot() ([]Series, int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	slots := t.slots()
	out := make([]Series, 0, len(t.rows))
	moved := make(map[string]int64, len(t.rows))
	for key, r := range t.rows {
		s := Series{
			Key:    key,
			Label:  r.Label,
			Detail: r.Detail,
			Via:    r.Via,
			Peer:   r.Peer,
			Vals:   make([]Pair, len(slots)),
			Seen:   make([]bool, len(slots)),
		}
		for i, slot := range slots {
			s.Vals[i], s.Seen[i] = r.vals[slot], r.seen[slot]
		}
		moved[key] = r.movedLocked()
		out = append(out, s)
	}

	// Busiest first, then by key so a tie does not reshuffle the chart on every poll.
	sort.Slice(out, func(i, j int) bool {
		if a, b := moved[out[i].Key], moved[out[j].Key]; a != b {
			return a > b
		}
		return out[i].Key < out[j].Key
	})
	return out, t.folded
}

// Rates turns one key's window of cumulative readings into per-interval movement, on the same
// rules the flat lanes use -- except that a reset or an absence is this key's own. A device
// leaving the tailnet must not blank the chart for every device that stayed.
func (s Series) Rates(when []time.Time, interval time.Duration) []Movement {
	if len(s.Vals) < 2 {
		return nil
	}
	out := make([]Movement, 0, len(s.Vals)-1)
	for i := 1; i < len(s.Vals); i++ {
		out = append(out, s.rateAt(i, when, interval))
	}
	return out
}

func (s Series) rateAt(i int, when []time.Time, interval time.Duration) Movement {
	// A key absent at either end of the interval was not measured across it.
	if !s.Seen[i-1] || !s.Seen[i] {
		return Movement{Gap: true}
	}
	if i >= len(when) {
		return Movement{Gap: true}
	}

	elapsed := when[i].Sub(when[i-1])
	if elapsed <= 0 || elapsed > time.Duration(maxGapFactor)*interval {
		return Movement{Gap: true}
	}

	secs := elapsed.Seconds()
	up, upOK := perSecond(s.Vals[i-1].Up, s.Vals[i].Up, secs)
	down, downOK := perSecond(s.Vals[i-1].Down, s.Vals[i].Down, secs)
	if !upOK || !downOK {
		return Movement{Gap: true}
	}
	return Movement{Up: up, Down: down}
}

// Fold sums a set of series into the one row that stands for everything a chart is not
// drawing by name.
//
// It sums the rates rather than the counters. Summing cumulative counters would make the
// total jump by a key's whole history the moment that key first appears, drawn as a burst of
// traffic at a second nothing happened. A tick is a gap only where every contributor is one:
// what could be measured is reported, and an interval nobody could be measured across is not
// reported as quiet.
func Fold(rates [][]Movement) []Movement {
	if len(rates) == 0 {
		return nil
	}
	width := 0
	for _, r := range rates {
		if len(r) > width {
			width = len(r)
		}
	}

	out := make([]Movement, width)
	for i := range out {
		out[i].Gap = true
		for _, r := range rates {
			if i >= len(r) || r[i].Gap {
				continue
			}
			out[i].Up += r[i].Up
			out[i].Down += r[i].Down
			out[i].Gap = false
		}
	}
	return out
}
