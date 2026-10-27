// SPDX-License-Identifier: MIT

package inspect

// The second signal: what a series of connections adds up to. Every case here is about the
// difference between a machine doing something and a machine doing something odd, so the
// ordinary shapes are as important as the alarming ones.

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

var anomalyStart = time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)

// tightLimits are small enough that a case can reach them in a readable number of lines and
// still exercise the same comparisons the shipped thresholds do.
func tightLimits() Limits {
	return Limits{Window: time.Minute, Destinations: 5, Ports: 4, Names: 4, Entropy: 3.4, MinLabel: 12}
}

// note records one connection at an offset from the start, which is what every case here is
// really saying: this many, this close together.
func note(w *Watch, peer, addr string, port uint16, after time.Duration) {
	w.Note(flowTo(peer, addr, port), anomalyStart.Add(after))
}

func flowTo(peer, addr string, port uint16) Flow {
	return Flow{Addr: netip.MustParseAddr(addr), Port: port, Peer: peer, Protocol: "tcp"}
}

// find is what a case asserts on: the one anomaly of a shape, or nothing.
func find(found []Anomaly, signal Signal) (Anomaly, bool) {
	for _, a := range found {
		if a.Signal == signal {
			return a, true
		}
	}
	return Anomaly{}, false
}

func TestOneSourceReachingManyPortsOnOneAddressReadsAsAScan(t *testing.T) {
	w := NewWatch(tightLimits())
	for port := range uint16(6) {
		note(w, "", "10.1.2.9", 20+port, time.Duration(port)*time.Second)
	}

	got, held := find(w.Sweep(anomalyStart.Add(10*time.Second)), SignalPortScan)

	if !held {
		t.Fatal("six ports on one address in six seconds is not reported as a scan")
	}
	if got.Value != "10.1.2.9" || got.Count != 6 {
		t.Errorf("anomaly = %+v, want the address that was scanned and how many ports", got)
	}
	if got.Source() != LocalSource {
		t.Errorf("source = %q, want a flow with no peer attributed to this machine", got.Source())
	}
	// The sentence is the whole of what a user acts on, so the numbers have to be in it.
	if reason := got.Reason(); !strings.Contains(reason, "6") || !strings.Contains(reason, "10.1.2.9") {
		t.Errorf("reason = %q, want the count and the address in it", reason)
	}
}

// The same address reached many times is a program that reconnects, which is every long-lived
// client there is. Counting connections rather than distinct ports would report all of them.
func TestManyConnectionsToOnePortAreNotAScan(t *testing.T) {
	w := NewWatch(tightLimits())
	for i := range 50 {
		note(w, "", "10.1.2.9", 443, time.Duration(i)*time.Second)
	}

	if got, held := find(w.Sweep(anomalyStart.Add(time.Minute)), SignalPortScan); held {
		t.Errorf("anomaly = %+v, want reconnecting to one port read as ordinary", got)
	}
}

func TestOneSourceReachingManyAddressesReadsAsFanningOut(t *testing.T) {
	w := NewWatch(tightLimits())
	for i := range 6 {
		note(w, "", fmt.Sprintf("10.1.2.%d", i+1), 443, time.Duration(i)*time.Second)
	}

	got, held := find(w.Sweep(anomalyStart.Add(10*time.Second)), SignalFanOut)

	if !held {
		t.Fatal("six addresses in six seconds is not reported as fanning out")
	}
	if got.Count != 6 || got.Value != LocalSource {
		t.Errorf("anomaly = %+v, want the count and the source it is about", got)
	}
}

// Only the subnet router knows which device asked. A finding that lost the peer would send
// somebody looking on this machine for something another device on the tailnet did.
func TestAFindingKeepsTheDeviceThatCausedItAndCountsDevicesApart(t *testing.T) {
	w := NewWatch(tightLimits())
	for port := range uint16(6) {
		note(w, "laptop@example", "10.1.2.9", 20+port, time.Duration(port)*time.Second)
	}
	// The same address, reached by a different device on one port each: neither device is
	// scanning, and only summing the two would say otherwise.
	for port := range uint16(3) {
		note(w, "phone@example", "10.1.2.9", 20+port, time.Duration(port)*time.Second)
	}

	found := w.Sweep(anomalyStart.Add(10 * time.Second))

	if len(found) != 1 {
		t.Fatalf("sweep found %d anomalies, want the one device that scanned: %+v", len(found), found)
	}
	if found[0].Peer != "laptop@example" || found[0].Source() != "laptop@example" {
		t.Errorf("anomaly = %+v, want it to name the device that did it", found[0])
	}
	if !strings.Contains(found[0].Reason(), "laptop@example") {
		t.Errorf("reason = %q, want the device named in the sentence", found[0].Reason())
	}
}

// The window is what makes any of these thresholds mean anything: six ports over an hour is
// a machine being used, and reporting it would make every finding worthless.
func TestConnectionsSpreadPastTheWindowAreNotCountedTogether(t *testing.T) {
	w := NewWatch(tightLimits())
	for port := range uint16(6) {
		note(w, "", "10.1.2.9", 20+port, time.Duration(port)*30*time.Second)
	}

	if found := w.Sweep(anomalyStart.Add(3 * time.Minute)); len(found) != 0 {
		t.Errorf("sweep found %+v, want nothing from connections spread past the window", found)
	}
}

// A scan lasts longer than one sweep, and a sweep that reported it every time would turn one
// event into as many alerts as the ticker fires.
func TestTheSameScanIsNotReportedTwiceWhileItIsStillInTheWindow(t *testing.T) {
	w := NewWatch(tightLimits())
	for port := range uint16(6) {
		note(w, "", "10.1.2.9", 20+port, time.Duration(port)*time.Second)
	}

	first := w.Sweep(anomalyStart.Add(10 * time.Second))
	again := w.Sweep(anomalyStart.Add(30 * time.Second))

	if len(first) != 1 {
		t.Fatalf("the first sweep found %d anomalies, want the one scan", len(first))
	}
	if len(again) != 0 {
		t.Errorf("the second sweep found %+v, want the same scan reported once", again)
	}

	// A scan that starts again after the window has passed is a new thing happening, and
	// suppressing that would make the second alert depend on how long ago the first was.
	for port := range uint16(6) {
		note(w, "", "10.1.2.9", 20+port, 2*time.Minute+time.Duration(port)*time.Second)
	}
	if third := w.Sweep(anomalyStart.Add(2*time.Minute + 10*time.Second)); len(third) != 1 {
		t.Errorf("a scan after the window found %+v, want it reported again", third)
	}
}

func TestManyRandomNamesUnderOneParentReadAsDataLeavingInsideDNS(t *testing.T) {
	w := NewWatch(tightLimits())
	labels := []string{
		"k7fj2qmx9wzp4vbn", "q3hd8sxr1tcy6wkm", "z9vb4nkq7mfx2sdh",
		"x2mc6rtv8jqp5wnz", "b8kq3zxw7ndf1hmv",
	}
	for i, label := range labels {
		w.Question(label+".tunnel.example", anomalyStart.Add(time.Duration(i)*time.Second))
	}

	got, held := find(w.Sweep(anomalyStart.Add(10*time.Second)), SignalDNSTunnel)

	if !held {
		t.Fatal("five random names under one parent are not reported as a tunnel")
	}
	if got.Value != "tunnel.example" || got.Count != 5 {
		t.Errorf("anomaly = %+v, want the parent domain and how many names were asked about", got)
	}
	// There is no client identity on the resolver path, so the sentence must not imply one.
	if got.Peer != "" {
		t.Errorf("anomaly names the peer %q, and the resolver knows no peer", got.Peer)
	}
	if reason := got.Reason(); !strings.Contains(reason, "tunnel.example") {
		t.Errorf("reason = %q, want the parent domain in it", reason)
	}
}

// A CDN or a bucket answers the count and nothing else. Reporting it would make the signal
// fire on ordinary browsing, which is the way a detector stops being read.
func TestManyOrdinaryNamesUnderOneParentAreNotATunnel(t *testing.T) {
	w := NewWatch(tightLimits())
	for i, label := range []string{"images", "static", "assets", "video", "download", "uploads"} {
		w.Question(label+".cdn.example", anomalyStart.Add(time.Duration(i)*time.Second))
	}

	if got, held := find(w.Sweep(anomalyStart.Add(10*time.Second)), SignalDNSTunnel); held {
		t.Errorf("anomaly = %+v, want ordinary subdomains read as ordinary", got)
	}
}

// One long random name is a session token in a hostname, which plenty of services use. The
// count is what separates that from a stream of them carrying data out.
func TestOneRandomNameIsNotATunnel(t *testing.T) {
	w := NewWatch(tightLimits())
	w.Question("k7fj2qmx9wzp4vbn.tunnel.example", anomalyStart)

	if found := w.Sweep(anomalyStart.Add(time.Second)); len(found) != 0 {
		t.Errorf("sweep found %+v, want one random name read as ordinary", found)
	}
}

// The same name asked about repeatedly is a cache expiring, not data leaving: a tunnel needs
// new labels because the label is what carries the payload.
func TestTheSameNameAskedRepeatedlyIsNotATunnel(t *testing.T) {
	w := NewWatch(tightLimits())
	for i := range 40 {
		w.Question("k7fj2qmx9wzp4vbn.tunnel.example", anomalyStart.Add(time.Duration(i)*time.Second))
	}

	if found := w.Sweep(anomalyStart.Add(time.Minute)); len(found) != 0 {
		t.Errorf("sweep found %+v, want one name asked many times read as ordinary", found)
	}
}

// Short labels score high on randomness for arithmetic reasons: every character is distinct
// in a four-character label, so it looks maximally random however ordinary it is.
func TestShortLabelsDoNotCountTowardRandomness(t *testing.T) {
	w := NewWatch(tightLimits())
	for i, label := range []string{"a1b2", "c3d4", "e5f6", "g7h8", "i9j0"} {
		w.Question(label+".short.example", anomalyStart.Add(time.Duration(i)*time.Second))
	}

	if found := w.Sweep(anomalyStart.Add(10 * time.Second)); len(found) != 0 {
		t.Errorf("sweep found %+v, want short labels not scored as random", found)
	}
}

// A bare two-label name has no label to carry anything, and treating the whole name as one
// would make every root domain its own parent with one name under it.
func TestANameWithNothingUnderItIsNotRecorded(t *testing.T) {
	w := NewWatch(tightLimits())
	for _, name := range []string{"example.com", "localhost", "", ".", "  "} {
		w.Question(name, anomalyStart)
	}

	if _, questions := w.Held(); questions != 0 {
		t.Errorf("the ledger holds %d questions, want none from names with no label under them", questions)
	}
}

// Names arrive from the resolver in whatever case and with whatever trailing dot the client
// sent. Two spellings of one name counted apart would be two names in the tunnel count.
func TestANameIsCountedTheSameHoweverItWasSpelled(t *testing.T) {
	w := NewWatch(tightLimits())
	for i, name := range []string{"One.Tunnel.Example", "one.tunnel.example.", " one.tunnel.example "} {
		w.Question(name, anomalyStart.Add(time.Duration(i)*time.Second))
	}

	if found := w.Sweep(anomalyStart.Add(10 * time.Second)); len(found) != 0 {
		t.Errorf("sweep found %+v, want three spellings of one name counted as one", found)
	}
}

// A flow with no address is one that was refused before anything resolved it. Recording it
// would put a zero address in the ledger and count every such flow as one destination.
func TestAFlowWithNoAddressIsNotRecorded(t *testing.T) {
	w := NewWatch(tightLimits())
	w.Note(Flow{Name: "bad.example", Where: "the proxy"}, anomalyStart)

	if flows, _ := w.Held(); flows != 0 {
		t.Errorf("the ledger holds %d flows, want none from a flow with no address", flows)
	}
}

// The switch turning off has to empty the ledger: leaving it would mean turning the signal
// back on reports a scan that happened while nothing was watching.
func TestTurningTheLedgerOffEmptiesIt(t *testing.T) {
	w := NewWatch(tightLimits())
	for port := range uint16(6) {
		note(w, "", "10.1.2.9", 20+port, time.Duration(port)*time.Second)
	}
	w.Question("k7fj2qmx9wzp4vbn.tunnel.example", anomalyStart)

	w.Reset()

	if flows, questions := w.Held(); flows != 0 || questions != 0 {
		t.Errorf("the ledger holds %d flows and %d questions after being emptied", flows, questions)
	}
	if found := w.Sweep(anomalyStart.Add(10 * time.Second)); len(found) != 0 {
		t.Errorf("sweep found %+v after the ledger was emptied", found)
	}
}

// The ring is the whole memory story: a scan is exactly the traffic that would grow an
// unbounded ledger, so the one thing that must not happen is the ledger growing with it.
func TestTheLedgerHoldsAFixedAmountHoweverMuchItIsGiven(t *testing.T) {
	w := NewWatch(tightLimits())
	for i := range watchedFlows * 2 {
		note(w, "", "10.1.2.9", uint16(i%65535), time.Duration(i)*time.Millisecond)
	}
	for i := range watchedQuestions * 2 {
		w.Question(fmt.Sprintf("n%d.tunnel.example", i), anomalyStart)
	}

	flows, questions := w.Held()

	if flows != watchedFlows {
		t.Errorf("the ledger holds %d flows, want it capped at %d", flows, watchedFlows)
	}
	if questions != watchedQuestions {
		t.Errorf("the ledger holds %d questions, want it capped at %d", questions, watchedQuestions)
	}
}

// The table that stops a finding being reported twice is itself keyed by what the network
// did, so it is the one structure here an attacker could otherwise grow without limit.
func TestTheTableOfWhatWasAlreadyReportedIsBounded(t *testing.T) {
	w := NewWatch(tightLimits())
	for i := range watchedMarks * 3 {
		addr := netip.AddrFrom4([4]byte{10, byte(i / 250), byte(i % 250), 9})
		for port := range uint16(6) {
			w.Note(Flow{Addr: addr, Port: 20 + port}, anomalyStart)
		}
		if found := w.Sweep(anomalyStart.Add(time.Second)); len(found) == 0 {
			t.Fatalf("the sweep for %s found nothing, want the scan it was given", addr)
		}
		w.Reset()
	}

	if len(w.marks) > watchedMarks {
		t.Errorf("the table holds %d findings, want it capped at %d", len(w.marks), watchedMarks)
	}
}

// Every carrying goroutine writes to the ledger and the ticker reads it. A race here is a
// crash on the data path, which is the one failure this whole design is arranged to avoid.
func TestTheLedgerIsWrittenFromEveryCarryingGoroutineAtOnce(t *testing.T) {
	w := NewWatch(tightLimits())
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				w.Note(Flow{
					Addr: netip.AddrFrom4([4]byte{10, 1, byte(worker), byte(i % 250)}),
					Port: uint16(i % 65535),
				}, anomalyStart.Add(time.Duration(i)*time.Millisecond))
				w.Question(fmt.Sprintf("n%d.w%d.example", i, worker), anomalyStart)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			w.Sweep(anomalyStart.Add(time.Second))
			w.Held()
		}
	}()
	wg.Wait()
}

// Nothing set is the signal switched off, and every path calls the same methods either way.
// A nil ledger that panicked would take the connection that called it down with it.
func TestALedgerThatWasNeverBuiltCarriesEverythingWithoutPanicking(t *testing.T) {
	var w *Watch

	w.Note(flowTo("", "10.1.2.9", 443), anomalyStart)
	w.Question("bad.example", anomalyStart)

	if found := w.Sweep(anomalyStart); found != nil {
		t.Errorf("sweep = %+v, want nothing from a ledger that was never built", found)
	}
}

// A caller that wants one threshold changed says that one thing, and the rest have to stay
// at the shipped values: a zero reaching a comparison would fire on the first connection.
func TestAThresholdLeftUnsetKeepsTheShippedValue(t *testing.T) {
	w := NewWatch(Limits{Ports: 3})

	got, def := w.Limits(), DefaultLimits()

	if got.Ports != 3 {
		t.Errorf("ports = %d, want the value that was asked for", got.Ports)
	}
	if got.Window != def.Window || got.Destinations != def.Destinations ||
		got.Names != def.Names || got.Entropy != def.Entropy || got.MinLabel != def.MinLabel {
		t.Errorf("limits = %+v, want everything unset left at %+v", got, def)
	}
}

// Two sweeps of the same ledger reporting the same findings in a different order is a
// difference a reader has to check, and a card that reorders itself between polls.
func TestFindingsComeBackInTheSameOrderEveryTime(t *testing.T) {
	build := func() *Watch {
		w := NewWatch(tightLimits())
		for _, addr := range []string{"10.1.2.9", "10.1.2.8", "10.1.2.7"} {
			for port := range uint16(6) {
				note(w, "", addr, 20+port, time.Duration(port)*time.Second)
			}
		}
		return w
	}

	first, second := build().Sweep(anomalyStart.Add(time.Minute)), build().Sweep(anomalyStart.Add(time.Minute))

	if len(first) == 0 {
		t.Fatal("the sweep found nothing, want the three scans it was given")
	}
	for i := range first {
		if first[i].Signal != second[i].Signal || first[i].Value != second[i].Value {
			t.Fatalf("sweep order differs at %d: %+v then %+v", i, first[i], second[i])
		}
	}
}

// The sentence is written per signal, and a signal with no arm would reach the card as an
// empty string -- an alert saying nothing at all.
func TestEverySignalHasASentence(t *testing.T) {
	for _, signal := range []Signal{SignalPortScan, SignalFanOut, SignalDNSTunnel, "something-new"} {
		a := Anomaly{Signal: signal, Value: "10.1.2.9", Count: 7,
			Since: anomalyStart, Until: anomalyStart.Add(time.Minute)}
		reason := a.Reason()
		if reason == "" || !strings.Contains(reason, "7") {
			t.Errorf("reason for %s = %q, want a sentence carrying the count", signal, reason)
		}
	}
}

func TestRandomTextScoresHigherThanAWord(t *testing.T) {
	random, word := entropy("k7fj2qmx9wzp4vbn"), entropy("downloadserver")

	if random <= word {
		t.Errorf("entropy: random %.2f, word %.2f, want random text to score higher", random, word)
	}
	if entropy("") != 0 {
		t.Errorf("entropy(\"\") = %.2f, want nothing to score nothing", entropy(""))
	}
}
