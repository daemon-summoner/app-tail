// SPDX-License-Identifier: MIT

package inspect

// What the ledger does at its own edges: the tables filling up, the records arriving out of
// order, and the orderings two sweeps of the same ledger have to agree on. All of it is
// bounded memory on a machine that runs for months, so the eviction paths are the ones a
// long-lived process actually takes.

import (
	"fmt"
	"testing"
	"time"
)

// A finding names the device that caused it in a column of its own, and a connection this
// machine made has no device to name.
func TestAFindingNamesTheDeviceOrSaysItWasThisMachine(t *testing.T) {
	w := NewWatch(tightLimits())
	for port := range uint16(6) {
		note(w, "", "10.1.2.9", 20+port, time.Duration(port)*time.Second)
	}
	for addr := range 6 {
		note(w, "100.64.0.9", fmt.Sprintf("10.9.0.%d", addr), 443, time.Duration(addr)*time.Second)
	}

	found := w.Sweep(anomalyStart.Add(30 * time.Second))
	fan, ok := find(found, SignalFanOut)
	if !ok {
		t.Fatalf("no fan-out was found in %+v", found)
	}
	if fan.Value != "100.64.0.9" {
		t.Errorf("the fan-out names %q, want the device that caused it", fan.Value)
	}

	local := NewWatch(tightLimits())
	for addr := range 6 {
		note(local, "", fmt.Sprintf("10.9.0.%d", addr), 443, time.Duration(addr)*time.Second)
	}
	fan, ok = find(local.Sweep(anomalyStart.Add(30*time.Second)), SignalFanOut)
	if !ok {
		t.Fatal("no fan-out was found for connections this machine made")
	}
	if fan.Value != LocalSource {
		t.Errorf("the fan-out names %q, want %q for connections with no device behind them", fan.Value, LocalSource)
	}
}

// Two sweeps of the same ledger reporting the same findings in a different order is a
// difference somebody has to read and check, so the order is fixed on every field the
// findings can differ in.
func TestFindingsComeBackInAnOrderThatDoesNotMove(t *testing.T) {
	w := NewWatch(tightLimits())
	// Two devices scanning the same address, which differ only in which device it was.
	for _, peer := range []string{"100.64.0.9", "100.64.0.2"} {
		for port := range uint16(6) {
			note(w, peer, "10.1.2.9", 20+port, time.Duration(port)*time.Second)
		}
	}
	// And a run of random names under one parent, which is a finding of another shape.
	for i := range 6 {
		w.Question(fmt.Sprintf("%s.tunnel.example", tunnelLabels[i]), anomalyStart)
	}

	found := w.Sweep(anomalyStart.Add(30 * time.Second))
	if len(found) < 3 {
		t.Fatalf("the sweep found %+v, want the two scans and the run of names", found)
	}
	for i := 1; i < len(found); i++ {
		before, after := found[i-1], found[i]
		if before.Signal > after.Signal {
			t.Fatalf("finding %d is a %s and follows a %s", i, after.Signal, before.Signal)
		}
		if before.Signal == after.Signal && before.Value > after.Value {
			t.Fatalf("%s findings are ordered %q then %q", after.Signal, before.Value, after.Value)
		}
		if before.Signal == after.Signal && before.Value == after.Value && before.Peer > after.Peer {
			t.Fatalf("two %s findings for %q are ordered %q then %q",
				after.Signal, after.Value, before.Peer, after.Peer)
		}
	}
}

// The table of what has already been reported is bounded, and a machine that finds more
// distinct things than it holds must keep reporting rather than stop at the cap.
func TestHoldingBackRepeatsNeverStopsNewFindingsFromBeingReported(t *testing.T) {
	w := NewWatch(tightLimits())
	at := anomalyStart

	// More distinct scans than the table of held-back findings can hold, each far enough
	// apart that they are separate sweeps rather than one.
	const scans = watchedMarks + 8
	for i := range scans {
		peer := fmt.Sprintf("100.64.1.%d", i%200)
		addr := fmt.Sprintf("10.5.%d.%d", i/200, i%200)
		for port := range uint16(6) {
			w.Note(flowTo(peer, addr, 20+port), at.Add(time.Duration(port)*time.Second))
		}
		found := w.Sweep(at.Add(30 * time.Second))
		if _, ok := find(found, SignalPortScan); !ok {
			t.Fatalf("scan %d of %d was not reported once the table filled", i, scans)
		}
		at = at.Add(2 * time.Minute)
	}
}

// The beacon table is bounded too, and what it drops first is what is already past the window
// it looks over: dropping a live rhythm to make room for one that ended an hour ago would
// lose the only rows worth keeping.
func TestTheRhythmTableDropsWhatHasAgedOutBeforeWhatIsStillRunning(t *testing.T) {
	w := NewWatch(tightLimits())

	// Fill it with pairs that then age out entirely.
	for i := range watchedPairs {
		w.Note(flowTo("", fmt.Sprintf("10.20.%d.%d", i/256, i%256), 443), anomalyStart)
	}
	// A steady rhythm recorded well after all of those aged out.
	later := anomalyStart.Add(2 * beaconWindow)
	for i := range beaconMinSamples + 1 {
		w.Note(flowTo("", "10.99.0.1", 443), later.Add(time.Duration(i)*time.Minute))
	}

	beacons := w.Beacons(later.Add(time.Duration(beaconMinSamples) * time.Minute))
	if len(beacons) != 1 || beacons[0].Addr != "10.99.0.1" {
		t.Fatalf("the rhythms are %+v, want the one still running", beacons)
	}
	// And the aged-out rows are gone rather than held for the life of the process.
	w.mu.Lock()
	held := len(w.pairs)
	w.mu.Unlock()
	if held >= watchedPairs {
		t.Errorf("the rhythm table holds %d pairs, want the ones past the window dropped", held)
	}
}

// Rhythms are shown most regular first, and two that are equally regular are ordered by
// address: a list that reordered itself between two polls is a list nobody can read.
func TestRhythmsThatAreEquallyRegularAreOrderedByAddress(t *testing.T) {
	w := NewWatch(tightLimits())
	for i := range beaconMinSamples + 1 {
		at := anomalyStart.Add(time.Duration(i) * time.Minute)
		w.Note(flowTo("", "10.0.0.9", 443), at)
		w.Note(flowTo("", "10.0.0.2", 443), at)
	}

	beacons := w.Beacons(anomalyStart.Add(time.Duration(beaconMinSamples) * time.Minute))
	if len(beacons) != 2 {
		t.Fatalf("the rhythms are %+v, want both pairs", beacons)
	}
	if beacons[0].Addr != "10.0.0.2" || beacons[1].Addr != "10.0.0.9" {
		t.Errorf("the rhythms are ordered %q then %q, want the addresses in order",
			beacons[0].Addr, beacons[1].Addr)
	}
}

// The ledger is a ring, so the records inside it are not in the order they happened once it
// has wrapped. A tally that assumed they were would report a run as having started at
// whichever record the ring happened to hold first.
func TestARunIsMeasuredFromWhenItStartedWhateverOrderTheRecordsAreIn(t *testing.T) {
	w := NewWatch(tightLimits())
	// The later connections first, then the earlier ones, which is what a wrapped ring hands
	// the sweep.
	for port := range uint16(3) {
		note(w, "", "10.1.2.9", 30+port, 20*time.Second+time.Duration(port)*time.Second)
	}
	for port := range uint16(3) {
		note(w, "", "10.1.2.9", 20+port, time.Duration(port)*time.Second)
	}

	scan, ok := find(w.Sweep(anomalyStart.Add(30*time.Second)), SignalPortScan)
	if !ok {
		t.Fatal("no scan was found for six ports on one address")
	}
	if !scan.Since.Equal(anomalyStart) {
		t.Errorf("the scan says it started at %s, want %s", scan.Since, anomalyStart)
	}
	if want := anomalyStart.Add(22 * time.Second); !scan.Until.Equal(want) {
		t.Errorf("the scan says it ran until %s, want %s", scan.Until, want)
	}
}

// The same for the questions, which are the same shape of ring: the finding says when the run
// of names began, and out-of-order records must not move it.
func TestARunOfNamesIsMeasuredFromWhenItStartedWhateverOrderTheRecordsAreIn(t *testing.T) {
	w := NewWatch(tightLimits())
	for i := range 3 {
		w.Question(fmt.Sprintf("%s.tunnel.example", tunnelLabels[i+3]), anomalyStart.Add(20*time.Second))
	}
	for i := range 3 {
		w.Question(fmt.Sprintf("%s.tunnel.example", tunnelLabels[i]), anomalyStart)
	}
	// One from before the window, which is not part of the run at all.
	w.Question("old."+tunnelLabels[6]+".tunnel.example", anomalyStart.Add(-10*time.Minute))

	tunnel, ok := find(w.Sweep(anomalyStart.Add(30*time.Second)), SignalDNSTunnel)
	if !ok {
		t.Fatal("no run of random names was found")
	}
	if !tunnel.Since.Equal(anomalyStart) {
		t.Errorf("the run says it started at %s, want %s", tunnel.Since, anomalyStart)
	}
}

// Long labels are not random labels. A parent whose names are long and orderly is a naming
// scheme somebody chose, and reporting one as data leaving inside DNS is the false positive
// that makes a user turn the whole detector off.
func TestManyLongOrderlyNamesUnderOneParentAreNotATunnel(t *testing.T) {
	w := NewWatch(tightLimits())
	// Each is well past MinLabel, so each is scored, and each carries almost no randomness.
	for _, label := range []string{
		"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc",
		"dddddddddddddddd", "eeeeeeeeeeeeeeee", "ffffffffffffffff",
	} {
		w.Question(label+".build.example", anomalyStart)
	}

	if found, ok := find(w.Sweep(anomalyStart.Add(30*time.Second)), SignalDNSTunnel); ok {
		t.Errorf("orderly names were reported as a tunnel: %+v", found)
	}
}

// tunnelLabels are the long random labels a tunnel's names carry: long enough to be scored
// for randomness, and random enough to score high.
var tunnelLabels = []string{
	"k7fj2qmx9wzp4vbn", "q3hd8sxr1tcy6wkm", "z9vb4nkq7mfx2sdh",
	"x2mc6rtv8jqp5wnz", "b8kq3zxw7ndf1hmv", "j4wr9ptc2xkb6vqm",
	"m5nx8vqz3hdf7ycp",
}
