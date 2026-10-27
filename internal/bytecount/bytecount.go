// SPDX-License-Identifier: MIT

// Package bytecount is a bounded set of byte counters keyed by whatever names a flow.
//
// Several parts of app-tail carry traffic and can say something about each flow they carry
// -- the port it went to, the device it came from, the connection carrying it -- but each of
// them counts bytes on the copy loop itself, where an unbounded map is a memory leak driven
// by whatever the network asks for. A browser pointed at the PAC file names every host it
// visits; a port scan names every port there is.
//
// So the shape is always the same: atomic counters so a copy loop never takes a lock, a hard
// cap on distinct keys, eviction of the quietest idle key, and everything past the cap summed
// into one bucket that is reported rather than dropped. This is that shape, once.
package bytecount

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one key's counters. Every field is atomic because the byte counters are written
// from each flow's own goroutine while a poll reads them from another; the table's mutex
// guards which entries exist, not their contents.
type Entry struct {
	up     atomic.Int64
	down   atomic.Int64
	active atomic.Int64
	// lastAt is when a flow on this key was last opened or closed, in unix nanoseconds. It
	// picks the eviction victim, and is deliberately not touched per byte: a clock read on
	// every chunk would be the most expensive thing in the copy loop.
	lastAt atomic.Int64
}

// Up and Down fold one instalment into the counters, from this machine's point of view.
// Both take the byte count a copy reported, which is never negative.
func (e *Entry) Up(n int64)   { e.up.Add(n) }
func (e *Entry) Down(n int64) { e.down.Add(n) }

// Open and Close mark a flow starting and ending on this key. They are what keeps a key with
// a flow still on it from being evicted, and what dates it for eviction once it is idle.
func (e *Entry) Open()  { e.active.Add(1) }
func (e *Entry) Close() { e.active.Add(-1) }

// Meta names a key for whatever draws it.
type Meta struct {
	// Label is the name a reader recognises and Detail the aside beside it.
	Label  string
	Detail string
	// Via is the connection carrying this key and Peer the device it belongs to, each empty
	// where the seam that counted the bytes cannot attribute them.
	Via  string
	Peer string
}

// Row is one key's counters as a value.
type Row struct {
	Key string
	Meta
	Up     int64
	Down   int64
	Active int64
}

// moved orders the table: the keys worth naming first are the ones that carried the most.
func (r Row) moved() int64 { return r.Up + r.Down }

// Table is a bounded set of keyed counters.
type Table struct {
	mu    sync.Mutex
	max   int
	byKey map[string]*keyed
	// other absorbs everything past the cap, including the totals of evicted keys. Folding
	// rather than dropping is what keeps the per-key figures summing to the whole.
	other keyed
	// folded counts the distinct keys that ended up in other, so a reader can say how much
	// it is not naming.
	folded int
	// clock is the table's own, so a test drives eviction order rather than racing it.
	clock func() time.Time
}

type keyed struct {
	Entry
	meta Meta
}

// New builds a table naming at most max keys. A max below one is treated as one: a table
// that can name nothing would fold every key into the shared bucket.
func New(max int) *Table {
	if max < 1 {
		max = 1
	}
	return &Table{max: max, byKey: make(map[string]*keyed, max)}
}

func (t *Table) now() time.Time {
	if t.clock != nil {
		return t.clock()
	}
	return time.Now()
}

// Entry is the counters for one key, making room if the table is full.
//
// A key the table has no room for is answered with the shared bucket, so a caller never has
// to handle a nil and traffic is never simply uncounted. The names are refreshed on every
// call: a device is renamed and a connection moves, and the latest is the true one.
//
// It is called once per flow rather than once per chunk, which is what makes the mutex here
// affordable while the counters themselves stay atomic.
func (t *Table) Entry(key string, meta Meta) *Entry {
	t.mu.Lock()
	defer t.mu.Unlock()

	if e, ok := t.byKey[key]; ok {
		e.meta = meta
		return &e.Entry
	}
	if len(t.byKey) >= t.max && !t.evictOneLocked() {
		// Every slot is held by a key with a flow still on it. The new key is still counted,
		// just not named.
		t.folded++
		return &t.other.Entry
	}

	e := &keyed{meta: meta}
	e.lastAt.Store(t.now().UnixNano())
	t.byKey[key] = e
	return &e.Entry
}

// evictOneLocked frees the slot held by the key idle longest, folding its totals into the
// shared bucket so nothing is lost from the sums. A key with a flow still open is never
// evicted: its active count would be stranded and the gauge would drift away from reality
// for as long as the process lives.
func (t *Table) evictOneLocked() bool {
	var (
		victimKey string
		victim    *keyed
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

	t.other.up.Add(victim.up.Load())
	t.other.down.Add(victim.down.Load())
	delete(t.byKey, victimKey)
	t.folded++
	return true
}

// Touch dates a key for the eviction order, at a flow's edges.
func (t *Table) Touch(e *Entry) { e.lastAt.Store(t.now().UnixNano()) }

// Snapshot is every named key, busiest first, what was left unnamed, and how many distinct
// keys that bucket stands for. The slice is freshly built, so a caller may hold it while the
// counters keep moving.
func (t *Table) Snapshot() (rows []Row, other Row, folded int) {
	t.mu.Lock()
	rows = make([]Row, 0, len(t.byKey))
	for key, e := range t.byKey {
		rows = append(rows, Row{
			Key:    key,
			Meta:   e.meta,
			Up:     e.up.Load(),
			Down:   e.down.Load(),
			Active: e.active.Load(),
		})
	}
	other = Row{Up: t.other.up.Load(), Down: t.other.down.Load(), Active: t.other.active.Load()}
	folded = t.folded
	t.mu.Unlock()

	// Busiest first, then by key so a tie does not reshuffle a table on every poll.
	sort.Slice(rows, func(i, j int) bool {
		if a, b := rows[i].moved(), rows[j].moved(); a != b {
			return a > b
		}
		return rows[i].Key < rows[j].Key
	})
	return rows, other, folded
}
