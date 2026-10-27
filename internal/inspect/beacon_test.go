// SPDX-License-Identifier: MIT

package inspect

// Beaconing is the one thing here that is reported without ever being acted on, so these
// cases are as much about what it refuses to call a rhythm as about what it finds.

import (
	"fmt"
	"testing"
	"time"
)

// rhythm records one pair reached at the given gaps, and answers when the last of them was,
// which is what the case then asks Beacons about.
func rhythm(w *Watch, peer, addr string, gaps ...time.Duration) time.Time {
	at := anomalyStart
	w.Note(flowTo(peer, addr, 443), at)
	for _, gap := range gaps {
		at = at.Add(gap)
		w.Note(flowTo(peer, addr, 443), at)
	}
	return at
}

// evenly is the shape of a check-in: the same gap, enough times to measure.
func evenly(gap time.Duration, times int) []time.Duration {
	gaps := make([]time.Duration, times)
	for i := range gaps {
		gaps[i] = gap
	}
	return gaps
}

func TestConnectionsArrivingOnTheSameGapReadAsARhythm(t *testing.T) {
	w := NewWatch(Limits{})

	last := rhythm(w, "", "93.184.216.34", evenly(time.Minute, beaconMinSamples)...)

	found := w.Beacons(last)
	if len(found) != 1 {
		t.Fatalf("found %d rhythms, want the one that was recorded: %+v", len(found), found)
	}
	got := found[0]
	if got.Addr != "93.184.216.34" {
		t.Errorf("rhythm address = %q, want the destination it kept going back to", got.Addr)
	}
	if got.Every != time.Minute {
		t.Errorf("rhythm gap = %s, want the minute between connections", got.Every)
	}
	if got.Jitter != 0 {
		t.Errorf("rhythm jitter = %v, want none: every gap was the same", got.Jitter)
	}
	if got.Count != beaconMinSamples+1 {
		t.Errorf("rhythm counted %d connections, want the %d that were made",
			got.Count, beaconMinSamples+1)
	}
	if !got.Since.Equal(anomalyStart) {
		t.Errorf("rhythm started at %s, want the first connection at %s", got.Since, anomalyStart)
	}
	if got.Source() != LocalSource {
		t.Errorf("rhythm source = %q, want %q for this machine's own traffic", got.Source(), LocalSource)
	}
}

// The point of the jitter threshold: a human opening the same site through the day does it at
// gaps that have no rhythm, and reporting that would bury the shape this is looking for.
func TestConnectionsAtUnevenGapsAreNotARhythm(t *testing.T) {
	w := NewWatch(Limits{})

	last := rhythm(w, "", "93.184.216.34",
		time.Minute, 9*time.Minute, 2*time.Minute, 11*time.Minute, time.Minute, 6*time.Minute)

	if found := w.Beacons(last); len(found) != 0 {
		t.Errorf("found %+v, want nothing: the gaps are nothing like each other", found)
	}
}

// Anything this fast is a program working rather than a program checking in, and every one of
// them would be reported forever.
func TestConnectionsCloserTogetherThanTheFloorAreNotARhythm(t *testing.T) {
	w := NewWatch(Limits{})

	last := rhythm(w, "", "93.184.216.34", evenly(time.Second, beaconMinSamples)...)

	if found := w.Beacons(last); len(found) != 0 {
		t.Errorf("found %+v, want nothing: a gap of a second is not a check-in", found)
	}
}

// Two gaps that happen to match is a coincidence. The minimum is what makes the measurement
// mean anything.
func TestTooFewConnectionsAreNotYetARhythm(t *testing.T) {
	w := NewWatch(Limits{})

	last := rhythm(w, "", "93.184.216.34", evenly(time.Minute, beaconMinSamples-1)...)

	if found := w.Beacons(last); len(found) != 0 {
		t.Errorf("found %+v, want nothing until there are enough gaps to measure", found)
	}
}

// A pair coming back after being away is a new run. Folding the silence in as one enormous
// interval would put a rhythm nobody kept in the middle of the record.
func TestAPairComingBackAfterALongSilenceStartsAgain(t *testing.T) {
	w := NewWatch(Limits{})
	rhythm(w, "", "93.184.216.34", evenly(time.Minute, beaconMinSamples)...)

	back := anomalyStart.Add(time.Duration(beaconMinSamples)*time.Minute + beaconWindow + time.Minute)
	w.Note(flowTo("", "93.184.216.34", 443), back)

	if found := w.Beacons(back); len(found) != 0 {
		t.Errorf("found %+v, want the measurement started again from the connection that came back", found)
	}
}

// The rhythm is only worth reporting while it is still happening: one that stopped half an
// hour ago is a record of something over, and the table drops it.
func TestARhythmThatStoppedIsNoLongerReported(t *testing.T) {
	w := NewWatch(Limits{})
	last := rhythm(w, "", "93.184.216.34", evenly(time.Minute, beaconMinSamples)...)

	if found := w.Beacons(last.Add(beaconWindow + time.Minute)); len(found) != 0 {
		t.Errorf("found %+v, want nothing once the rhythm is past the window", found)
	}
}

// The device is what makes the observation worth anything on a machine that routes for others:
// "something is checking in" is a different sentence from "that phone is checking in".
func TestARhythmNamesTheDeviceThatKeptTheTime(t *testing.T) {
	w := NewWatch(Limits{})

	last := rhythm(w, "100.64.0.9", "93.184.216.34", evenly(time.Minute, beaconMinSamples)...)

	found := w.Beacons(last)
	if len(found) != 1 {
		t.Fatalf("found %d rhythms, want the one that was recorded", len(found))
	}
	if found[0].Peer != "100.64.0.9" || found[0].Source() != "100.64.0.9" {
		t.Errorf("rhythm source = %q, want the device the connections came from", found[0].Source())
	}
}

func TestTheMostRegularRhythmComesFirst(t *testing.T) {
	w := NewWatch(Limits{})
	rhythm(w, "", "93.184.216.34", time.Minute, time.Minute, time.Minute, time.Minute, time.Minute, 66*time.Second)
	last := rhythm(w, "", "93.184.216.35", evenly(time.Minute, beaconMinSamples)...)

	found := w.Beacons(last)
	if len(found) != 2 {
		t.Fatalf("found %d rhythms, want both that were recorded: %+v", len(found), found)
	}
	if found[0].Addr != "93.184.216.35" {
		t.Errorf("the first rhythm is %s at jitter %v, want the perfectly regular one first",
			found[0].Addr, found[0].Jitter)
	}
}

// A rhythm is an observation and nothing else: it must never turn up among the findings,
// because everything there is something somebody is being asked to look at.
func TestARhythmIsNeverAFinding(t *testing.T) {
	w := NewWatch(Limits{})
	last := rhythm(w, "", "93.184.216.34", evenly(time.Minute, beaconMinSamples)...)

	if found := w.Sweep(last); len(found) != 0 {
		t.Errorf("the sweep reported %+v, want a rhythm kept out of the findings", found)
	}
	if len(w.Beacons(last)) != 1 {
		t.Error("the rhythm was not observed either, so nothing recorded it at all")
	}
}

// The table is one row per pair and a scan reaches thousands of them, so the bound is what
// stops the observation from being the way memory grows.
func TestTheBeaconTableHoldsAFixedNumberOfPairs(t *testing.T) {
	w := NewWatch(Limits{})

	for i := range watchedPairs + 200 {
		w.Note(flowTo("", fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), 443),
			anomalyStart.Add(time.Duration(i)*time.Second))
	}

	w.mu.Lock()
	held := len(w.pairs)
	w.mu.Unlock()
	if held > watchedPairs {
		t.Errorf("the beacon table holds %d pairs, want no more than %d", held, watchedPairs)
	}
}

// Turning the watch off has to take the rhythms with it: they are the same record of where
// traffic went that the switch exists to stop keeping.
func TestTurningTheLedgerOffEmptiesTheRhythmsToo(t *testing.T) {
	w := NewWatch(Limits{})
	last := rhythm(w, "", "93.184.216.34", evenly(time.Minute, beaconMinSamples)...)

	w.Reset()

	if found := w.Beacons(last); len(found) != 0 {
		t.Errorf("found %+v after the ledger was emptied", found)
	}
}

func TestALedgerThatWasNeverBuiltReportsNoRhythms(t *testing.T) {
	var w *Watch

	if found := w.Beacons(anomalyStart); found != nil {
		t.Errorf("found %+v from a ledger that does not exist", found)
	}
}
