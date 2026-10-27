// SPDX-License-Identifier: MIT

package traffic

import (
	"testing"
	"time"
)

// tick opens one tick and records the given keys at it, which is the order the sampler
// drives a table in.
func tick(t *Table, at time.Time, rows map[string]Row) {
	t.Advance(at)
	for key, row := range rows {
		t.Set(key, row)
	}
}

func base() time.Time { return time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC) }

func seconds(n int) time.Time { return base().Add(time.Duration(n) * time.Second) }

// find is one key's series out of a snapshot, so a test names what it is asserting on rather
// than depending on the order the busiest-first sort happened to produce.
func find(t *testing.T, series []Series, key string) Series {
	t.Helper()
	for _, s := range series {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("no series for %q in %d rows", key, len(series))
	return Series{}
}

func TestTableKeepsEachKeyOnTheSameTicks(t *testing.T) {
	tbl := NewTable(4, 8)
	for i := range 3 {
		tick(tbl, seconds(i), map[string]Row{
			"a": {Pair: Pair{Up: int64(100 * i), Down: 0}},
			"b": {Pair: Pair{Up: int64(10 * i), Down: 0}},
		})
	}

	series, _ := tbl.Snapshot()
	if len(series) != 2 {
		t.Fatalf("snapshot held %d series, want both keys", len(series))
	}
	// The whole point of one shared cursor: index i is the same instant for every key, which
	// is what lets one hovered column mean one moment across every chart.
	a, b := find(t, series, "a"), find(t, series, "b")
	if len(a.Vals) != 3 || len(b.Vals) != 3 {
		t.Fatalf("windows were %d and %d long, want 3 each", len(a.Vals), len(b.Vals))
	}
	if a.Vals[2].Up != 200 || b.Vals[2].Up != 20 {
		t.Errorf("last readings were %d and %d, want 200 and 20", a.Vals[2].Up, b.Vals[2].Up)
	}
}

func TestTableWindowDropsTheOldestTick(t *testing.T) {
	tbl := NewTable(3, 8)
	for i := range 5 {
		tick(tbl, seconds(i), map[string]Row{"a": {Pair: Pair{Up: int64(i)}}})
	}

	series, _ := tbl.Snapshot()
	got := find(t, series, "a")
	if len(got.Vals) != 3 {
		t.Fatalf("window held %d ticks, want 3", len(got.Vals))
	}
	// Oldest first, and the two ticks that fell out of the window are gone rather than
	// reappearing somewhere in the middle of it.
	if got.Vals[0].Up != 2 || got.Vals[2].Up != 4 {
		t.Errorf("window ran %d..%d, want 2..4", got.Vals[0].Up, got.Vals[2].Up)
	}
	when := tbl.Times()
	if !when[0].Equal(seconds(2)) || !when[2].Equal(seconds(4)) {
		t.Errorf("times ran %v..%v, want %v..%v", when[0], when[2], seconds(2), seconds(4))
	}
}

// A device that was offline never reported a counter. Recording that as a zero would draw a
// quiet stretch the agent never measured, which is the one thing the gap flag exists to stop.
func TestTableMarksATickAKeyDidNotReportAsUnseen(t *testing.T) {
	tbl := NewTable(4, 8)
	tick(tbl, seconds(0), map[string]Row{"a": {Pair: Pair{Up: 100}}})
	tick(tbl, seconds(1), map[string]Row{})
	tick(tbl, seconds(2), map[string]Row{"a": {Pair: Pair{Up: 300}}})

	series, _ := tbl.Snapshot()
	got := find(t, series, "a")
	if got.Seen[0] != true || got.Seen[1] != false || got.Seen[2] != true {
		t.Fatalf("presence was %v, want the middle tick absent", got.Seen)
	}

	rates := got.Rates(tbl.Times(), time.Second)
	// Both intervals touch the tick nothing reported, so neither can be a rate.
	if !rates[0].Gap || !rates[1].Gap {
		t.Errorf("rates were %+v, want a gap either side of the missing tick", rates)
	}
}

func TestSeriesRatesArePerSecondAcrossTheInterval(t *testing.T) {
	tbl := NewTable(4, 8)
	tick(tbl, seconds(0), map[string]Row{"a": {Pair: Pair{Up: 1000, Down: 2000}}})
	tick(tbl, seconds(2), map[string]Row{"a": {Pair: Pair{Up: 3000, Down: 2000}}})

	series, _ := tbl.Snapshot()
	rates := find(t, series, "a").Rates(tbl.Times(), time.Second)
	if len(rates) != 1 {
		t.Fatalf("derived %d rates from 2 readings, want 1", len(rates))
	}
	// Two seconds apart, so 2000 bytes is 1000 a second -- not 2000. A series stays
	// comparable across a tick the sampler missed only if the elapsed time is what divides.
	if rates[0].Up != 1000 || rates[0].Down != 0 {
		t.Errorf("rate was %+v, want 1000 up and nothing down", rates[0])
	}
}

// The flat lanes blank every lane when any counter resets, because one restart makes the
// whole sample suspect. Per key that rule would be wrong: a connection reconnecting is
// ordinary, and it must not blank the chart for every key that was measured perfectly.
func TestSeriesResetGapsOnlyTheKeyThatReset(t *testing.T) {
	tbl := NewTable(4, 8)
	tick(tbl, seconds(0), map[string]Row{
		"a": {Pair: Pair{Up: 5000}},
		"b": {Pair: Pair{Up: 100}},
	})
	tick(tbl, seconds(1), map[string]Row{
		"a": {Pair: Pair{Up: 10}},
		"b": {Pair: Pair{Up: 200}},
	})

	series, _ := tbl.Snapshot()
	when := tbl.Times()
	reset := find(t, series, "a").Rates(when, time.Second)
	steady := find(t, series, "b").Rates(when, time.Second)

	if !reset[0].Gap {
		t.Errorf("the reset key derived %+v, want a gap", reset[0])
	}
	if steady[0].Gap || steady[0].Up != 100 {
		t.Errorf("the steady key derived %+v, want 100 up and no gap", steady[0])
	}
}

func TestSeriesGapsAnIntervalTooLongToAverageAcross(t *testing.T) {
	tbl := NewTable(4, 8)
	tick(tbl, seconds(0), map[string]Row{"a": {Pair: Pair{Up: 100}}})
	// A laptop resumed with the lid closed comes back with two readings far apart. Averaging
	// the bytes across it would draw a long flat rate nobody experienced.
	tick(tbl, seconds(600), map[string]Row{"a": {Pair: Pair{Up: 1_000_000}}})

	series, _ := tbl.Snapshot()
	rates := find(t, series, "a").Rates(tbl.Times(), time.Second)
	if !rates[0].Gap {
		t.Errorf("derived %+v across a ten-minute interval, want a gap", rates[0])
	}
}

func TestTableDropsTheQuietestKeyWhenFull(t *testing.T) {
	tbl := NewTable(6, 2)
	tick(tbl, seconds(0), map[string]Row{
		"busy":  {Pair: Pair{Up: 0}},
		"quiet": {Pair: Pair{Up: 0}},
	})
	tick(tbl, seconds(1), map[string]Row{
		"busy":  {Pair: Pair{Up: 100_000}},
		"quiet": {Pair: Pair{Up: 1}},
	})
	// The quiet key stops reporting, which is what makes it the one there is room to drop.
	tick(tbl, seconds(2), map[string]Row{"busy": {Pair: Pair{Up: 200_000}}})
	tick(tbl, seconds(3), map[string]Row{
		"busy":  {Pair: Pair{Up: 300_000}},
		"third": {Pair: Pair{Up: 5}},
	})

	series, folded := tbl.Snapshot()
	if folded != 1 {
		t.Errorf("folded %d keys, want 1 -- a list cut short has to say so", folded)
	}
	for _, s := range series {
		if s.Key == "quiet" {
			t.Errorf("kept the quiet key and dropped a busier one")
		}
	}
	find(t, series, "busy")
	find(t, series, "third")
}

// A key still reporting is the one a reader is most likely watching. Dropping it to seat a
// newcomer would blank a live line on the chart; the newcomer waits instead.
func TestTableFoldsANewcomerRatherThanDropALiveKey(t *testing.T) {
	tbl := NewTable(4, 1)
	tick(tbl, seconds(0), map[string]Row{"live": {Pair: Pair{Up: 10}}})
	tick(tbl, seconds(1), map[string]Row{"live": {Pair: Pair{Up: 20}}, "new": {Pair: Pair{Up: 5}}})

	series, folded := tbl.Snapshot()
	if len(series) != 1 || series[0].Key != "live" {
		t.Fatalf("snapshot held %v, want only the live key", keysOf(series))
	}
	if folded != 1 {
		t.Errorf("folded %d keys, want the one there was no room for", folded)
	}
}

// The sampler reads its sources in whatever order it holds them, so which key is recorded
// first within a tick must not decide which key survives. Judging liveness on the current
// tick alone would make a key evictable purely because its own reading had not been taken
// yet, and the surviving key would come down to map iteration order.
func TestTableSurvivalDoesNotDependOnTheOrderWithinATick(t *testing.T) {
	for range 50 {
		tbl := NewTable(4, 1)
		tick(tbl, seconds(0), map[string]Row{"live": {Pair: Pair{Up: 10}}})
		tick(tbl, seconds(1), map[string]Row{
			"live": {Pair: Pair{Up: 20}},
			"new":  {Pair: Pair{Up: 5}},
		})

		series, _ := tbl.Snapshot()
		if len(series) != 1 || series[0].Key != "live" {
			t.Fatalf("snapshot held %v, want the live key every time", keysOf(series))
		}
	}
}

func keysOf(series []Series) []string {
	out := make([]string, 0, len(series))
	for _, s := range series {
		out = append(out, s.Key)
	}
	return out
}

func TestTableKeepsTheLatestNamesForAKey(t *testing.T) {
	tbl := NewTable(4, 8)
	tick(tbl, seconds(0), map[string]Row{"n1": {Label: "old-name", Via: "wg", Pair: Pair{Up: 1}}})
	tick(tbl, seconds(1), map[string]Row{"n1": {Label: "new-name", Via: "wg", Pair: Pair{Up: 2}}})

	series, _ := tbl.Snapshot()
	// A device renamed mid-window is one device. The chart labels it by what it is called
	// now, not by what it was called when the window opened.
	if got := find(t, series, "n1"); got.Label != "new-name" || got.Via != "wg" {
		t.Errorf("labelled %q via %q, want the latest name", got.Label, got.Via)
	}
}

func TestFoldSumsTheRatesRatherThanTheCounters(t *testing.T) {
	// The second key's counter starts high and appears a tick late. Summing counters would
	// make the total jump by its whole history at the tick it arrives -- a burst of traffic
	// at a second nothing happened.
	early := []Movement{{Up: 10}, {Up: 10}}
	late := []Movement{{Gap: true}, {Up: 5}}

	got := Fold([][]Movement{early, late})
	if got[0].Gap || got[0].Up != 10 {
		t.Errorf("first tick folded to %+v, want the one measured contributor", got[0])
	}
	if got[1].Gap || got[1].Up != 15 {
		t.Errorf("second tick folded to %+v, want both contributors summed", got[1])
	}
}

// What could be measured is reported. Only an interval nobody could be measured across is a
// gap, or a busy chart would blank every time one contributor reset.
func TestFoldGapsOnlyWhereEveryContributorIsAGap(t *testing.T) {
	got := Fold([][]Movement{
		{{Gap: true}, {Up: 7}},
		{{Gap: true}, {Gap: true}},
	})
	if !got[0].Gap {
		t.Errorf("first tick folded to %+v, want a gap", got[0])
	}
	if got[1].Gap || got[1].Up != 7 {
		t.Errorf("second tick folded to %+v, want the one contributor that was measured", got[1])
	}
}

// Two keys that carried the same amount have to keep the same order poll after poll. Left to
// map iteration they would swap places every second, and a chart whose lines trade colours as
// you watch it cannot be read at all.
func TestSnapshotOrdersATieByKeyRatherThanAtRandom(t *testing.T) {
	tbl := NewTable(4, 8)
	for i := range 2 {
		tick(tbl, seconds(i), map[string]Row{
			"b": {Pair: Pair{Up: int64(100 * i)}},
			"a": {Pair: Pair{Up: int64(100 * i)}},
			"c": {Pair: Pair{Up: int64(100 * i)}},
		})
	}

	for range 8 {
		series, _ := tbl.Snapshot()
		if got := []string{series[0].Key, series[1].Key, series[2].Key}; got[0] != "a" ||
			got[1] != "b" || got[2] != "c" {
			t.Fatalf("the tied keys came back as %v, want them in key order every time", got)
		}
	}
}

// A key whose counter went backwards was reset, not run in reverse. Ranking it as a negative
// would make the key that just reconnected the first one evicted.
func TestAKeyThatResetRanksAsNothingRatherThanAsNegative(t *testing.T) {
	tbl := NewTable(4, 2)
	tick(tbl, seconds(0), map[string]Row{
		"reset": {Pair: Pair{Up: 10_000, Down: 10_000}},
		"busy":  {Pair: Pair{Up: 0}},
	})
	tick(tbl, seconds(1), map[string]Row{
		"reset": {Pair: Pair{Up: 5, Down: 5}},
		"busy":  {Pair: Pair{Up: 900}},
	})

	series, _ := tbl.Snapshot()
	if series[0].Key != "busy" {
		t.Errorf("the busiest key was %q, want busy -- the reset key's span is unknowable, not huge",
			series[0].Key)
	}
	// It ranks last rather than being dropped: the bytes it carried before the reset are still
	// bytes the machine moved.
	if series[1].Key != "reset" {
		t.Errorf("the second key was %q, want the one that reset", series[1].Key)
	}
}

// A key that stopped reporting a whole window ago accounts for nothing across the window it
// is ranked over, so it is the one dropped to make room. Ranking it by what it carried before
// the window opened would let a device that left the tailnet hold a slot indefinitely.
func TestAKeyAbsentForTheWholeWindowIsTheOneDropped(t *testing.T) {
	tbl := NewTable(2, 2)
	tick(tbl, seconds(0), map[string]Row{
		"gone": {Pair: Pair{Up: 900_000, Down: 900_000}},
		"here": {Pair: Pair{Up: 1}},
	})
	tick(tbl, seconds(1), map[string]Row{"here": {Pair: Pair{Up: 2}}})
	tick(tbl, seconds(2), map[string]Row{"here": {Pair: Pair{Up: 3}}})

	tick(tbl, seconds(3), map[string]Row{
		"here": {Pair: Pair{Up: 4}},
		"new":  {Pair: Pair{Up: 5}},
	})

	series, _ := tbl.Snapshot()
	keys := []string{}
	for _, s := range series {
		keys = append(keys, s.Key)
	}
	if len(series) != 2 {
		t.Fatalf("the table held %v, want the cap of two", keys)
	}
	for _, s := range series {
		if s.Key == "gone" {
			t.Errorf("the table held %v, want the departed key dropped for the newcomer", keys)
		}
	}
}

// One reading is a dot, and a rate needs two. Deriving one anyway would draw the whole of a
// counter's history as traffic in a single second.
func TestASeriesTooShortToDeriveARateDrawsNothing(t *testing.T) {
	tbl := NewTable(4, 8)
	tick(tbl, seconds(0), map[string]Row{"a": {Pair: Pair{Up: 10}}})

	series, _ := tbl.Snapshot()
	if got := series[0].Rates(tbl.Times(), time.Second); got != nil {
		t.Errorf("one reading derived %+v, want no rate at all", got)
	}
}

// Fold is handed whatever survived the cap, and past the cap there may be nothing left.
func TestFoldingNothingIsNothing(t *testing.T) {
	if got := Fold(nil); got != nil {
		t.Errorf("folding no series gave %+v, want nothing", got)
	}
}

// The times and the readings are read separately while the sampler keeps writing, so the two
// can arrive one tick apart. An interval with no instant to measure across is a gap rather
// than a rate divided by whatever the previous tick happened to be.
func TestARateWithNoTimeToMeasureAcrossIsAGap(t *testing.T) {
	s := Series{
		Vals: []Pair{{Up: 0}, {Up: 100}, {Up: 200}},
		Seen: []bool{true, true, true},
	}

	got := s.Rates([]time.Time{seconds(0), seconds(1)}, time.Second)

	if len(got) != 2 {
		t.Fatalf("derived %d rates, want one per interval", len(got))
	}
	if got[0].Gap || got[0].Up != 100 {
		t.Errorf("the interval the clock covers came back as %+v, want 100 up", got[0])
	}
	if !got[1].Gap {
		t.Errorf("the interval the clock does not reach came back as %+v, want a gap", got[1])
	}
}

// Every lane the sampler names has a table. The breakdown endpoint checks a request against
// this same set and then reads the table without a nil guard, so a lane named here and not
// built would be a nil dereference on the dashboard's own poll.
func TestEveryLaneTheSamplerNamesHasATable(t *testing.T) {
	s := NewSampler(nil, time.Second, time.Minute)

	for _, lane := range Lanes {
		if s.Lane(lane) == nil {
			t.Errorf("the sampler names lane %q and holds no table for it", lane)
		}
	}
	if s.Lane("a lane nothing serves") != nil {
		t.Error("the sampler answered for a lane it does not know")
	}
}

func TestNewTableRefusesAWindowThatWouldRecordNothing(t *testing.T) {
	tbl := NewTable(0, 0)
	tick(tbl, seconds(0), map[string]Row{"a": {Pair: Pair{Up: 1}}})

	series, _ := tbl.Snapshot()
	if len(series) != 1 || len(series[0].Vals) != 1 {
		t.Fatalf("a clamped table recorded %d series, want one reading held", len(series))
	}
}
