// SPDX-License-Identifier: MIT

package telemetry

import (
	"slices"
	"testing"
)

// The ring is the memory floor every log sits on, and its whole point is that a machine
// recording forever costs a fixed amount of memory. A ring that grew, or that returned
// its rows in storage order rather than oldest first, would break both the bound and the
// order the log screen reads in.
func TestAFullRingKeepsTheNewestRowsAndReturnsThemOldestFirst(t *testing.T) {
	r := newRing[int](3)
	for i := 1; i <= 5; i++ {
		r.add(i)
	}
	if got := r.all(); !slices.Equal(got, []int{3, 4, 5}) {
		t.Errorf("the window holds %v, want the newest three oldest-first", got)
	}
}

// Before it wraps, the ring must report only what it holds. Returning the whole backing
// slice would hand a reader the zero value of every unwritten slot as though those were
// real rows.
func TestAPartlyFilledRingReportsOnlyTheRowsActuallyWritten(t *testing.T) {
	r := newRing[int](4)
	r.add(1)
	r.add(2)
	if got := r.all(); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("the window holds %v, want just the two rows written", got)
	}
	if got := r.all(); len(got) != 2 {
		t.Errorf("reading twice changed the window: %v", got)
	}
}

// The count of rows ever taken is what lets the dashboard tell "nothing has happened"
// apart from "the window has moved past it". If it counted only what is still held, a
// busy machine would report the same number as an idle one.
func TestTheRingCountsEveryRowItEverTookIncludingTheOnesItOverwrote(t *testing.T) {
	r := newRing[int](2)
	for i := range 7 {
		r.add(i)
	}
	added, capacity := r.stats()
	if added != 7 {
		t.Errorf("the ring reports %d rows ever taken, want 7", added)
	}
	if capacity != 2 {
		t.Errorf("the ring reports a capacity of %d, want 2", capacity)
	}
}

// Retention runs through keep, and it has to leave a usable ring behind: the surviving
// rows in order, and room to write more without losing them again immediately.
func TestRetentionDropsTheRejectedRowsAndLeavesTheRestWritable(t *testing.T) {
	r := newRing[int](5)
	for i := 1; i <= 5; i++ {
		r.add(i)
	}
	dropped := r.keep(func(v int) bool { return v > 3 })
	if dropped != 3 {
		t.Fatalf("keep reported %d rows dropped, want 3", dropped)
	}
	if got := r.all(); !slices.Equal(got, []int{4, 5}) {
		t.Fatalf("after retention the window holds %v, want [4 5]", got)
	}

	r.add(6)
	if got := r.all(); !slices.Equal(got, []int{4, 5, 6}) {
		t.Errorf("a row written after retention landed wrong: %v", got)
	}
}

// Dropping nothing must not disturb the window. A retention pass that rebuilt the ring
// every minute regardless would reorder rows on a machine whose log is inside the window,
// which is the ordinary case.
func TestARetentionPassThatDropsNothingLeavesTheWindowExactlyAsItWas(t *testing.T) {
	r := newRing[int](3)
	for i := 1; i <= 4; i++ {
		r.add(i)
	}
	before := r.all()
	if dropped := r.keep(func(int) bool { return true }); dropped != 0 {
		t.Fatalf("keep dropped %d rows when the predicate accepted everything", dropped)
	}
	if got := r.all(); !slices.Equal(got, before) {
		t.Errorf("the window changed from %v to %v with nothing dropped", before, got)
	}
}

// Retention that rejects everything is how turning a log off clears it, so it has to
// leave a ring that still works rather than one that has to be rebuilt.
func TestARetentionPassThatRejectsEverythingEmptiesTheRingAndItStillRecords(t *testing.T) {
	r := newRing[int](3)
	r.add(1)
	r.add(2)
	if dropped := r.keep(func(int) bool { return false }); dropped != 2 {
		t.Fatalf("keep dropped %d rows, want 2", dropped)
	}
	if got := r.all(); len(got) != 0 {
		t.Fatalf("the window still holds %v after everything was rejected", got)
	}
	r.add(9)
	if got := r.all(); !slices.Equal(got, []int{9}) {
		t.Errorf("the emptied ring recorded %v, want [9]", got)
	}
}

// A ring sized zero or negative would silently record nothing while every add reported
// success, which is the worst failure this package could have: a log that looks on and
// holds nothing.
func TestARingAskedForNoRoomStillHoldsOneRowRatherThanSilentlyDiscarding(t *testing.T) {
	for _, size := range []int{0, -4} {
		r := newRing[int](size)
		r.add(42)
		if got := r.all(); !slices.Equal(got, []int{42}) {
			t.Errorf("a ring of size %d holds %v, want [42]", size, got)
		}
	}
}
