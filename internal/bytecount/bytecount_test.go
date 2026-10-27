// SPDX-License-Identifier: MIT

package bytecount

import (
	"sync"
	"testing"
	"time"
)

// at builds a table whose clock a test drives, so the eviction order is decided rather than
// raced: two entries made in the same nanosecond would otherwise evict arbitrarily.
func at(max int, ticks *int64) *Table {
	t := New(max)
	t.clock = func() time.Time {
		*ticks++
		return time.Unix(0, *ticks)
	}
	return t
}

func find(t *testing.T, rows []Row, key string) Row {
	t.Helper()
	for _, r := range rows {
		if r.Key == key {
			return r
		}
	}
	t.Fatalf("no row for %q in %d rows", key, len(rows))
	return Row{}
}

func TestTableCountsEachKeySeparately(t *testing.T) {
	var ticks int64
	tbl := at(8, &ticks)

	tbl.Entry("445/tcp", Meta{Label: "445", Detail: "tcp"}).Up(100)
	tbl.Entry("445/tcp", Meta{Label: "445", Detail: "tcp"}).Down(900)
	tbl.Entry("53/udp", Meta{Label: "53", Detail: "udp"}).Up(7)

	rows, _, folded := tbl.Snapshot()
	if folded != 0 {
		t.Errorf("folded %d keys with room for both, want none", folded)
	}
	smb := find(t, rows, "445/tcp")
	if smb.Up != 100 || smb.Down != 900 {
		t.Errorf("445/tcp carried up/down = %d/%d, want 100/900", smb.Up, smb.Down)
	}
	if smb.Label != "445" || smb.Detail != "tcp" {
		t.Errorf("445/tcp named %q/%q, want the names it was counted under", smb.Label, smb.Detail)
	}
	// Busiest first, or the list cut short by a cap would cut off the wrong end.
	if rows[0].Key != "445/tcp" {
		t.Errorf("the first row was %q, want the busiest key", rows[0].Key)
	}
}

// Two keys carrying the same amount have to come back in the same order poll after poll.
// Left to map iteration they would swap places every second, and a table or a chart whose
// rows trade places as you watch it cannot be read at all.
func TestSnapshotOrdersATieByKeyRatherThanAtRandom(t *testing.T) {
	var ticks int64
	tbl := at(8, &ticks)
	for _, key := range []string{"c/tcp", "a/tcp", "b/tcp"} {
		tbl.Entry(key, Meta{}).Up(100)
	}

	for range 8 {
		rows, _, _ := tbl.Snapshot()
		if got := []string{rows[0].Key, rows[1].Key, rows[2].Key}; got[0] != "a/tcp" ||
			got[1] != "b/tcp" || got[2] != "c/tcp" {
			t.Fatalf("the tied keys came back as %v, want them in key order every time", got)
		}
	}
}

// A key is a port, a host, a device -- whatever the network produced. Growing a map for
// every one of them is a memory leak driven by whatever anything on the network asks for.
func TestTableFoldsEverythingPastTheCapRatherThanGrowing(t *testing.T) {
	var ticks int64
	tbl := at(2, &ticks)

	tbl.Entry("a", Meta{}).Up(10)
	tbl.Entry("b", Meta{}).Up(20)
	tbl.Entry("c", Meta{}).Up(5)

	rows, other, folded := tbl.Snapshot()
	if len(rows) != 2 {
		t.Fatalf("the table named %d keys with room for 2, want 2", len(rows))
	}
	if folded != 1 {
		t.Errorf("folded %d keys, want 1 -- a list cut short has to say so", folded)
	}
	// The bytes are still counted, or the breakdown would stop summing to the machine-wide
	// total with nothing on screen explaining the difference.
	if total := rows[0].Up + rows[1].Up + other.Up; total != 35 {
		t.Errorf("the table accounts for %d bytes, want all 35 that were counted", total)
	}
}

// A key with a flow still on it has an active count nothing else would ever decrement.
// Evicting it strands that count, and the gauge drifts for as long as the process lives.
func TestTableNeverEvictsAKeyWithAFlowStillOpen(t *testing.T) {
	var ticks int64
	tbl := at(1, &ticks)

	held := tbl.Entry("held", Meta{})
	held.Open()
	tbl.Entry("newcomer", Meta{}).Up(500)

	rows, other, folded := tbl.Snapshot()
	if len(rows) != 1 || rows[0].Key != "held" {
		t.Fatalf("the table named %v, want the key still carrying a flow", rows)
	}
	if folded != 1 || other.Up != 500 {
		t.Errorf("the newcomer folded to %d bytes over %d keys, want its 500 counted in the "+
			"shared bucket", other.Up, folded)
	}
}

// The idle key is the one there is room to drop, and its bytes move to the shared bucket
// rather than disappearing from the sums.
func TestTableEvictsTheKeyIdleLongestAndKeepsItsBytes(t *testing.T) {
	var ticks int64
	tbl := at(2, &ticks)

	tbl.Entry("oldest", Meta{}).Up(11)
	newer := tbl.Entry("newer", Meta{})
	newer.Up(22)
	// Touched after both were made, so it is no longer the oldest.
	tbl.Touch(newer)
	tbl.Entry("newcomer", Meta{}).Up(33)

	rows, other, folded := tbl.Snapshot()
	for _, r := range rows {
		if r.Key == "oldest" {
			t.Fatalf("the table kept the key idle longest and dropped a fresher one: %v", rows)
		}
	}
	if folded != 1 {
		t.Errorf("folded %d keys, want 1", folded)
	}
	if other.Up != 11 {
		t.Errorf("the shared bucket holds %d bytes, want the evicted key's 11", other.Up)
	}
}

// A device is renamed and a routing rule moves a destination to another connection. The key
// is the same key; what it is called now is what a chart must label it.
func TestTableKeepsTheLatestNamesForAKey(t *testing.T) {
	var ticks int64
	tbl := at(4, &ticks)

	tbl.Entry("d1", Meta{Label: "old-name", Via: "wg1"}).Up(1)
	tbl.Entry("d1", Meta{Label: "new-name", Via: "wg2"}).Up(1)

	rows, _, _ := tbl.Snapshot()
	got := find(t, rows, "d1")
	if got.Label != "new-name" || got.Via != "wg2" {
		t.Errorf("d1 named %q via %q, want the latest", got.Label, got.Via)
	}
	if got.Up != 2 {
		t.Errorf("d1 carried %d bytes, want both instalments -- a rename is not a new key", got.Up)
	}
}

// The counters are written from every carried flow's own goroutine at once. A count that
// only adds up when the flows are serialised is a count the dashboard cannot trust.
func TestTableCountsCorrectlyUnderConcurrentFlows(t *testing.T) {
	tbl := New(4)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := tbl.Entry("shared", Meta{Label: "shared"})
			e.Open()
			for range 100 {
				e.Up(1)
				e.Down(2)
			}
			e.Close()
			tbl.Touch(e)
		}()
	}
	wg.Wait()

	rows, _, _ := tbl.Snapshot()
	got := find(t, rows, "shared")
	if got.Up != 800 || got.Down != 1600 {
		t.Errorf("counted up/down = %d/%d, want 800/1600", got.Up, got.Down)
	}
	if got.Active != 0 {
		t.Errorf("%d flows left open after every one closed, want 0", got.Active)
	}
}

func TestNewRefusesATableThatCouldNameNothing(t *testing.T) {
	tbl := New(0)
	tbl.Entry("a", Meta{}).Up(1)

	rows, _, folded := tbl.Snapshot()
	if len(rows) != 1 || folded != 0 {
		t.Fatalf("a clamped table named %d keys and folded %d, want one named key", len(rows), folded)
	}
}
