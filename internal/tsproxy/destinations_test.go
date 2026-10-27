// SPDX-License-Identifier: MIT

package tsproxy

import (
	"fmt"
	"testing"
	"time"
)

// find returns the named destination from a snapshot, or fails the test naming what was
// actually there -- an assertion against a silently absent entry proves nothing.
func find(t *testing.T, rows []DestCounters, address string) DestCounters {
	t.Helper()
	for _, r := range rows {
		if r.Address == address {
			return r
		}
	}
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.Address)
	}
	t.Fatalf("no destination %q in the snapshot; it holds %v", address, names)
	return DestCounters{}
}

func TestTrafficIsAttributedToTheDestinationItWentTo(t *testing.T) {
	var table destTable

	nas := table.entry("nas:445")
	nas.upBytes.Add(300)
	nas.rxBytes.Add(1200)
	gpu := table.entry("gpu-box:8100")
	gpu.upBytes.Add(7)

	rows, _, folded := table.snapshot()
	if folded != 0 {
		t.Errorf("folded = %d with room to spare, want 0", folded)
	}
	if got := find(t, rows, "nas:445"); got.BytesUp != 300 || got.BytesDown != 1200 {
		t.Errorf("nas up/down = %d/%d, want 300/1200", got.BytesUp, got.BytesDown)
	}
	if got := find(t, rows, "gpu-box:8100"); got.BytesUp != 7 {
		t.Errorf("gpu-box up = %d, want 7", got.BytesUp)
	}
}

// The busiest destination is the one worth reading first, and a tie must not reshuffle
// the table on every poll -- a list that reorders under the cursor is unusable.
func TestTheSnapshotLeadsWithTheBusiestAndBreaksTiesByName(t *testing.T) {
	var table destTable

	table.entry("quiet:1").upBytes.Add(1)
	table.entry("loud:2").upBytes.Add(9_000)
	table.entry("alpha:3").upBytes.Add(1)

	rows, _, _ := table.snapshot()
	if rows[0].Address != "loud:2" {
		t.Errorf("first row is %q, want the busiest", rows[0].Address)
	}
	if rows[1].Address != "alpha:3" || rows[2].Address != "quiet:1" {
		t.Errorf("tied rows are %q then %q, want alphabetical", rows[1].Address, rows[2].Address)
	}
}

// A destination that only ever failed is exactly what someone opens this view to find, so
// it has to outrank the destinations that did nothing at all.
func TestARefusedDestinationOutranksASilentOne(t *testing.T) {
	var table destTable

	table.entry("silent:1")
	table.entry("refused:2").refused.Add(3)

	rows, _, _ := table.snapshot()
	if rows[0].Address != "refused:2" {
		t.Errorf("first row is %q, want the refused destination", rows[0].Address)
	}
}

// Destinations are whatever a program asks for, so the set is unbounded -- a browser on
// the PAC file names every host it visits. The table has to stop growing.
func TestTheTableStopsGrowingAtTheCap(t *testing.T) {
	var table destTable

	for i := range maxDestinations * 3 {
		table.entry(fmt.Sprintf("host-%d:80", i)).upBytes.Add(1)
	}

	rows, other, folded := table.snapshot()
	if len(rows) > maxDestinations {
		t.Errorf("the table names %d destinations, want at most %d", len(rows), maxDestinations)
	}
	if folded == 0 {
		t.Error("nothing was reported as folded, so the dashboard would show a cut-off list as complete")
	}
	if other.BytesUp == 0 {
		t.Error("the folded destinations' bytes were dropped rather than summed into the bucket")
	}
}

// Evicting to make room must not lose the bytes: the per-destination figures are read
// beside the proxy's own totals, and a table that quietly drops traffic makes the two
// disagree with no way to tell which is wrong.
func TestEvictedTrafficIsFoldedRatherThanDropped(t *testing.T) {
	var table destTable

	var total int64
	for i := range maxDestinations * 2 {
		table.entry(fmt.Sprintf("host-%d:80", i)).upBytes.Add(10)
		total += 10
	}

	rows, other, _ := table.snapshot()
	var named int64
	for _, r := range rows {
		named += r.BytesUp
	}
	if named+other.BytesUp != total {
		t.Errorf("named %d + folded %d = %d, want the %d that actually crossed",
			named, other.BytesUp, named+other.BytesUp, total)
	}
}

// A destination with a connection still open cannot be evicted: its active count would be
// stranded at one forever and the gauge would drift for the life of the process.
func TestADestinationWithALiveConnectionIsNeverEvicted(t *testing.T) {
	var table destTable

	held := table.entry("held:22")
	held.active.Add(1)
	held.upBytes.Add(5)

	// Fill well past the cap, so eviction is forced many times over.
	for i := range maxDestinations * 3 {
		table.entry(fmt.Sprintf("host-%d:80", i))
	}

	rows, _, _ := table.snapshot()
	got := find(t, rows, "held:22")
	if got.Active != 1 {
		t.Errorf("the held destination reports %d active, want 1", got.Active)
	}
}

// When every slot is held by a live connection there is nothing to evict, and the new
// destination still has to be counted somewhere rather than dropped or crashing.
func TestANewDestinationIsStillCountedWhenNothingCanBeEvicted(t *testing.T) {
	var table destTable

	for i := range maxDestinations {
		table.entry(fmt.Sprintf("busy-%d:80", i)).active.Add(1)
	}

	overflow := table.entry("late:443")
	overflow.upBytes.Add(64)

	_, other, folded := table.snapshot()
	if other.BytesUp != 64 {
		t.Errorf("the overflow bucket holds %d bytes, want 64", other.BytesUp)
	}
	if folded == 0 {
		t.Error("the overflow was not reported as folded")
	}
}

// runningSet is two bound instances whose counters the caller then writes into directly,
// which is what the byte path does from each connection's own goroutine.
func runningSet(t *testing.T) (*Set, *Instance, *Instance) {
	t.Helper()
	set := newSet(t, newFakeNetwork(t))
	mustApplySet(t,
		set,
		heldInstance("px_one", "one", "One", nil),
		heldInstance("px_two", "two", "Two", nil),
	)
	one, ok := set.Get("px_one")
	if !ok {
		t.Fatal("the first instance is not running after a successful apply")
	}
	two, ok := set.Get("px_two")
	if !ok {
		t.Fatal("the second instance is not running after a successful apply")
	}
	return set, one, two
}

// One destination reached through two instances is one destination. The machine-wide graph
// is about how much left this machine, not which listener it happened to leave through, so
// a merge that named it twice would show a program's traffic split across rows that each
// look like half of what actually crossed.
func TestOneDestinationReachedThroughTwoInstancesIsOneDestination(t *testing.T) {
	set, one, two := runningSet(t)

	one.stats.opened.Add(1)
	one.stats.upBytes.Add(100)
	one.dests.entry("nas:445").upBytes.Add(100)

	two.stats.opened.Add(1)
	two.stats.refused.Add(2)
	two.stats.upBytes.Add(40)
	two.stats.rxBytes.Add(900)
	two.dests.entry("nas:445").upBytes.Add(40)
	two.dests.entry("nas:445").rxBytes.Add(900)
	two.dests.entry("gpu-box:8100").failed.Add(1)

	got := set.Counters()
	if got.Opened != 2 || got.Refused != 2 || got.BytesUp != 140 || got.BytesDown != 900 {
		t.Errorf("totals = opened %d, refused %d, up %d, down %d; want 2/2/140/900",
			got.Opened, got.Refused, got.BytesUp, got.BytesDown)
	}
	if len(got.Destinations) != 2 {
		t.Fatalf("the merged table names %d destinations, want 2 -- one host reached twice is one row",
			len(got.Destinations))
	}
	nas := find(t, got.Destinations, "nas:445")
	if nas.BytesUp != 140 || nas.BytesDown != 900 {
		t.Errorf("nas up/down = %d/%d, want 140/900 summed across both instances", nas.BytesUp, nas.BytesDown)
	}
	// Busiest first survives the merge: the row that only failed still outranks nothing,
	// but it does not outrank the one that moved a megabit.
	if got.Destinations[0].Address != "nas:445" {
		t.Errorf("the merged table leads with %q, want the busiest", got.Destinations[0].Address)
	}
}

// A destination reached through two instances is reached over one connection, and the graphs
// filter ports and destinations by exactly that. An instance that has not reached it yet knows
// nothing about the route rather than knowing it goes nowhere, so its blank must not erase the
// one that does -- otherwise the filter loses the row on whichever order the merge happened in.
func TestMergingKeepsTheRouteFromTheInstanceThatKnowsIt(t *testing.T) {
	routed := DestCounters{Address: "nas:445", BytesUp: 100, Via: "wg1", Protocol: "tcp"}
	blank := DestCounters{Address: "nas:445", BytesUp: 40}

	// Both orders, because the instances are merged in whatever order the set holds them.
	for _, c := range []struct {
		name       string
		into, from DestCounters
	}{
		{"the route first", routed, blank},
		{"the route second", blank, routed},
	} {
		got := addDest(c.into, c.from)
		if got.Via != "wg1" || got.Protocol != "tcp" {
			t.Errorf("%s: merged to via %q over %q, want wg1 over tcp -- the instance that knows "+
				"the route is the one that answers", c.name, got.Via, got.Protocol)
		}
		if got.BytesUp != 140 {
			t.Errorf("%s: merged to %d up, want both instances summed", c.name, got.BytesUp)
		}
	}
}

// The merged list is capped for the same reason each instance's own is -- the set is
// whatever programs on this machine ask for -- and what the cap leaves out is reported
// rather than dropped, or the per-destination rows stop summing to the totals beside them.
func TestTheMergedTableIsRecappedAndSaysWhatItLeftOut(t *testing.T) {
	set, one, two := runningSet(t)

	// Each instance stays under the cap on its own; together they are over it.
	var total int64
	for i := range maxDestinations {
		one.dests.entry(fmt.Sprintf("one-%d:80", i)).upBytes.Add(10)
		two.dests.entry(fmt.Sprintf("two-%d:80", i)).upBytes.Add(10)
		total += 20
	}

	got := set.Counters()
	if len(got.Destinations) != maxDestinations {
		t.Errorf("the merged table names %d destinations, want at most %d",
			len(got.Destinations), maxDestinations)
	}
	if got.Folded != maxDestinations {
		t.Errorf("folded = %d, want the %d the cap left out -- a list cut short reads as complete",
			got.Folded, maxDestinations)
	}
	var named int64
	for _, d := range got.Destinations {
		named += d.BytesUp
	}
	if named+got.Other.BytesUp != total {
		t.Errorf("named %d + folded %d = %d, want the %d that actually crossed",
			named, got.Other.BytesUp, named+got.Other.BytesUp, total)
	}
}

// An instance that already folded destinations of its own carries that bucket up into the
// machine-wide figures. Starting the merge from zero would silently drop every byte the
// busiest instance had stopped naming.
func TestWhatOneInstanceAlreadyFoldedIsCarriedIntoTheWholeMachinesFigures(t *testing.T) {
	set, one, _ := runningSet(t)

	for i := range maxDestinations * 2 {
		one.dests.entry(fmt.Sprintf("host-%d:80", i)).upBytes.Add(5)
	}

	got := set.Counters()
	if got.Folded == 0 {
		t.Fatal("the instance's own folded count did not reach the machine-wide figures")
	}
	if got.Other.BytesUp == 0 {
		t.Error("the bytes the instance had already folded were dropped rather than carried up")
	}
}

// The victim is the one idle longest, not an arbitrary map entry: evicting the
// destination someone is watching right now while an hours-old one survives is the
// difference between a useful table and a random one.
func TestTheLongestIdleDestinationIsEvictedFirst(t *testing.T) {
	now := time.Unix(0, 0)
	table := destTable{clock: func() time.Time { return now }}

	for i := range maxDestinations {
		now = now.Add(time.Second)
		table.entry(fmt.Sprintf("host-%d:80", i))
	}
	// Touch the oldest so it is no longer the oldest.
	first := table.entry("host-0:80")
	now = now.Add(time.Minute)
	table.touch(first)

	now = now.Add(time.Second)
	table.entry("new:443")

	rows, _, _ := table.snapshot()
	find(t, rows, "host-0:80") // survived, because it was touched most recently
	for _, r := range rows {
		if r.Address == "host-1:80" {
			t.Error("host-1 survived while a more recently used entry was evicted")
		}
	}
}
