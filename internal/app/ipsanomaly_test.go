// SPDX-License-Identifier: MIT

package app

// The runner's half of the second signal: the switch that decides whether the ledger exists,
// the questions the resolver hands it, and what a sweep turns a finding into.

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// scan drives a run of connections past the shipped port threshold, which is what every case
// here needs before there is anything for a sweep to find.
func scan(runner *ipsRunner, at *time.Time, addr string, start time.Time) {
	limit := inspect.DefaultLimits().Ports
	for port := range limit + 1 {
		*at = start.Add(time.Duration(port) * time.Second)
		runner.Refuse(inspect.Flow{
			Addr:     netip.MustParseAddr(addr),
			Port:     uint16(1000 + port),
			Where:    "the network interface",
			Protocol: "tcp",
		})
	}
}

// A machine with nothing typed into either list is the state a fresh install is in, and the
// signal that works there is the whole reason this one exists.
func TestASweepReportsAScanOnAMachineWithNoEntriesAtAll(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.watchFor(true)

	start := at
	scan(runner, &at, "10.1.2.9", start)
	at = start.Add(30 * time.Second)
	found := runner.sweep(at)

	if found != 1 {
		t.Fatalf("the sweep found %d things, want the one scan it was given", found)
	}
	if _, _, anomalies := runner.totals(); anomalies != 1 {
		t.Errorf("anomalies = %d, want the one the sweep found", anomalies)
	}
	if matched, refused, _ := runner.totals(); matched != 0 || refused != 0 {
		t.Errorf("totals count %d matched and %d refused, want a finding no rule named counted apart",
			matched, refused)
	}

	recent := runner.recentMatches()
	if len(recent) != 1 {
		t.Fatalf("the ring holds %d findings, want the one the sweep made", len(recent))
	}
	if recent[0].Signal != string(inspect.SignalPortScan) || recent[0].Value != "10.1.2.9" {
		t.Errorf("finding = %+v, want the shape it was and the address it was about", recent[0])
	}
	if recent[0].Refused {
		t.Error("a finding about connections that have already happened reads as refused")
	}
	if recent[0].Where == "" || recent[0].Source == "" || recent[0].Reason == "" {
		t.Errorf("finding = %+v, want it to say what was seen and where", recent[0])
	}

	if len(*events) != 1 {
		t.Fatalf("the sweep recorded %d events, want the one finding", len(*events))
	}
	got := (*events)[0]
	if got.code != telemetry.CodeIPSAnomaly {
		t.Errorf("event code = %q, want the anomaly code rather than a rule match", got.code)
	}
	if got.fields["count"] == "" || got.fields["over"] == "" || got.fields["signal"] == "" {
		t.Errorf("event fields = %v, want how many, over how long, and of what shape", got.fields)
	}
}

// The switch off has to mean the record of where traffic went is gone, not merely unread:
// that record is the one thing this feature keeps that a VPN app exists not to keep.
func TestTurningTheWatchOffDropsWhatItRecorded(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, nil)
	runner.watchFor(true)

	start := at
	scan(runner, &at, "10.1.2.9", start)
	held := runner.watch.Load()
	runner.watchFor(false)

	if flows, _ := held.Held(); flows != 0 {
		t.Errorf("the ledger still holds %d flows after the watch was turned off", flows)
	}
	at = start.Add(30 * time.Second)
	if found := runner.sweep(at); found != 0 {
		t.Errorf("a sweep with the watch off found %d things, want none", found)
	}
}

// Turning the watch on twice must not replace the ledger: a reconcile runs on every settings
// change, and a ledger rebuilt each time is one that never reaches a threshold.
func TestTheLedgerSurvivesAReconcileThatChangesNothing(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, nil)
	runner.watchFor(true)

	start := at
	scan(runner, &at, "10.1.2.9", start)
	runner.watchFor(true)

	at = start.Add(30 * time.Second)
	if found := runner.sweep(at); found != 1 {
		t.Errorf("the sweep found %d things after a second pass over the settings, want the scan", found)
	}
}

// A pause is asked for because inspection is producing something the user does not want. A
// sweep that kept reporting through it would be the one part of the feature it did not reach.
func TestAPausedInspectorNeitherRecordsNorSweeps(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, nil)
	runner.watchFor(true)
	start := at
	runner.pause(time.Hour)

	scan(runner, &at, "10.1.2.9", start)
	runner.question("k7fj2qmx9wzp4vbn.tunnel.example")
	at = start.Add(30 * time.Second)

	if flows, questions := runner.watch.Load().Held(); flows != 0 || questions != 0 {
		t.Errorf("the ledger holds %d flows and %d questions recorded while paused", flows, questions)
	}
	if found := runner.sweep(at); found != 0 {
		t.Errorf("a sweep while paused found %d things, want none", found)
	}
}

// Nothing set is the switch off, and the data path calls the same methods either way. A nil
// ledger that panicked would take the connection that called it down with it.
func TestTheDataPathIsCarriedWhileTheWatchIsOff(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})

	start := at
	scan(runner, &at, "10.1.2.9", start)
	runner.question("bad.example")
	at = start.Add(30 * time.Second)

	if found := runner.sweep(at); found != 0 {
		t.Errorf("a sweep with no ledger found %d things, want none", found)
	}
	// The other signal is unaffected: the two are independent switches over one runner.
	if _, refuse := runner.Refuse(inspect.Flow{Name: "bad.example"}); refuse {
		t.Error("a rule match was refused while the mode is detect")
	}
	if matched, _, _ := runner.totals(); matched != 1 {
		t.Error("the rules stopped matching because the watch is off")
	}
}

// The resolver is the only path that sees a name nothing ever connected to, which is the
// whole of what a DNS tunnel is: data leaves in the question and no connection follows.
func TestNamesTheResolverWasAskedAboutReachTheSweep(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.watchFor(true)

	start := at
	labels := []string{
		"k7fj2qmx9wzp4vbn", "q3hd8sxr1tcy6wkm", "z9vb4nkq7mfx2sdh", "x2mc6rtv8jqp5wnz",
		"b8kq3zxw7ndf1hmv", "m4wq8zvx2ktp7nrb", "j5nxb3qwz9mfr7kt", "v7ktm2xqz8bnw4jh",
		"c9zqx4mwt7nkb2vf", "h3bnq7wzx5mtk9vr", "t6mkx9qwz3bnv7hf", "p2vnq8zxw4mtk6br",
		"r8ktw3qxz7mnb5vf", "d4mnq9zxw2ktb6vh", "g7bkx2qwz9mnt4vr", "l5qtw8mxz3knb7vf",
		"s9nkq4wxz6mtb2vh", "y3mtx7qwz5knb9vf", "f6bnq2wxz8mtk4vr", "w8ktq5mxz9bnt3vh",
		"a2vnx6qwz4mtk8br", "e7mkq3wxz2bnt9vf", "i4btx8qwz6mnk5vr", "o9nkw2mxz7btq4vh",
		"u5mtq9wxz3knb8vf", "n7bkx4qwz2mtv6hr", "z3ntq8mxz5bkw9vf", "q6mkx2wzt7bnv4hr",
		"k9btw5qxz3mnt8vf", "x4nkq7wzm2btv9hr", "b6mtx3qwz8knv5hf", "v2ktq9mxz4bnw7hr",
		"m8bkx5qwz2mnt6vf", "j3ntw7qxz9bkv4hr", "c5mkq2wxz6bnt8vf", "h9btx4qwz3mnk7vr",
		"t2nkw8mxz5btq6vh", "p7mtq3wxz9knb4vf", "r4bkx6qwz2mnv8hr", "d8ntq5mxz7bkw3vf",
		"g2mkx9qwz4bnt6vh",
	}
	for i, label := range labels {
		at = start.Add(time.Duration(i) * time.Second)
		runner.question(label + ".tunnel.example")
	}

	at = start.Add(50 * time.Second)
	if found := runner.sweep(at); found != 1 {
		t.Fatalf("the sweep found %d things, want the one run of names it was given", found)
	}

	recent := runner.recentMatches()
	if recent[0].Signal != string(inspect.SignalDNSTunnel) || recent[0].Value != "tunnel.example" {
		t.Errorf("finding = %+v, want the shape it was and the domain it was under", recent[0])
	}
	// The resolver serves loopback, so nothing on this path knows which program asked. A
	// finding that named a peer would be an attribution the data does not carry.
	if recent[0].Peer != "" {
		t.Errorf("finding names the peer %q, and the resolver knows no peer", recent[0].Peer)
	}
	if (*events)[0].code != telemetry.CodeIPSAnomaly {
		t.Errorf("event code = %q, want the anomaly code", (*events)[0].code)
	}
}

// The seam is nil on a runner built without inspection, and the resolver calls it for every
// query it answers: a nil that panicked would take name resolution down with it.
func TestARunnerThatWasNeverBuiltAnswersAQuestionWithoutPanicking(t *testing.T) {
	var runner *ipsRunner

	runner.question("bad.example")
}

// Nothing sweeps the ledger unless the loop does. A ledger that recorded everything and was
// never read is the whole feature doing nothing, and it would pass every test above.
func TestTheLoopReadsTheLedgerWithoutBeingAsked(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	api := newIPSAPIAt(t, &at, func(s *config.Settings) {
		inspecting(s)
		s.IPSAnomaly = true
	})

	start := at
	scan(api.a.currentIPS(), &at, "10.1.2.9", start)
	at = start.Add(30 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		api.a.sweepEvery(ctx, time.Millisecond)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for len(api.a.currentIPS().recentMatches()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the loop never read the ledger, so the scan it holds was never reported")
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop never returned after its context was cancelled")
	}
}

// And the loop the agent actually starts is that loop, at the interval this ships with: a
// shell wired to nothing would leave every machine recording and never reporting.
func TestTheLoopTheAgentStartsStopsWithIt(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	api := newIPSAPIAt(t, &at, inspecting)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		api.a.runIPSAnomaly(ctx)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop the agent starts did not stop with its context")
	}
}

// The resolver hands every name it answers to the agent rather than to the runner, because the
// resolver outlives a node rebuild. A seam that dropped them would leave the tunnel detector
// reading an empty ledger on the one machine it is for.
func TestTheNamesTheResolverAnswersReachTheLedgerThroughTheAgent(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	api := newIPSAPIAt(t, &at, func(s *config.Settings) {
		inspecting(s)
		s.IPSAnomaly = true
	})

	api.a.noteQuestion("k7fj2qmx9wzp4vbn.tunnel.example")

	if _, questions := api.a.currentIPS().watch.Load().Held(); questions != 1 {
		t.Errorf("the ledger holds %d questions, want the one the resolver answered", questions)
	}
}

// The sentence a finding is written into starts with whatever the finding said. A finding
// that said nothing must come back as nothing rather than as an index into an empty string.
func TestASentenceStartedFromNothingIsNothing(t *testing.T) {
	if got := capitalise(""); got != "" {
		t.Errorf("capitalise of nothing = %q, want nothing", got)
	}
	if got := capitalise("100.64.0.9 reached 22 ports"); got != "100.64.0.9 reached 22 ports" {
		t.Errorf("capitalise = %q, want a sentence already starting with a digit left alone", got)
	}
	if got := capitalise("this machine opened connections"); got != "This machine opened connections" {
		t.Errorf("capitalise = %q, want the first letter raised", got)
	}
}

// checkIn drives one destination reached at a steady gap, enough times for the rhythm to be
// measurable, which is what the observation needs before there is anything to report.
func checkIn(runner *ipsRunner, at *time.Time, addr string, start time.Time, gap time.Duration) {
	for i := range 8 {
		*at = start.Add(time.Duration(i) * gap)
		runner.Refuse(inspect.Flow{
			Addr:     netip.MustParseAddr(addr),
			Port:     443,
			Where:    "the network interface",
			Protocol: "tcp",
		})
	}
}

// A rhythm is an observation and only that: it is reported so somebody who already suspects
// something can look for it, and every ordinary machine keeps several, so anything that turned
// one into a finding would bury the findings that mean something.
func TestARhythmIsObservedWithoutBeingReportedAsAFinding(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.watchFor(true)

	start := at
	checkIn(runner, &at, "10.1.2.9", start, time.Minute)

	found := runner.beacons(at)
	if len(found) != 1 {
		t.Fatalf("observed %d rhythms, want the one that was made: %+v", len(found), found)
	}
	if found[0].Addr != "10.1.2.9" || found[0].Every != time.Minute {
		t.Errorf("rhythm = %+v, want the destination and the gap the connections were made at", found[0])
	}

	if swept := runner.sweep(at); swept != 0 {
		t.Errorf("the sweep reported %d findings, want a rhythm kept out of them", swept)
	}
	if _, _, anomalies := runner.totals(); anomalies != 0 {
		t.Errorf("anomalies = %d, want a rhythm counted as nothing", anomalies)
	}
	if len(*events) != 0 {
		t.Errorf("the runner recorded %v, want a rhythm raising no event", *events)
	}
	if len(runner.recentMatches()) != 0 {
		t.Error("a rhythm reached the list of findings the card shows")
	}
}

// The rhythms come off the same ledger the watch keeps, so the switch that drops the ledger
// has to take them with it.
func TestNoRhythmIsObservedWhileTheWatchIsOff(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, nil)

	start := at
	checkIn(runner, &at, "10.1.2.9", start, time.Minute)

	if found := runner.beacons(at); len(found) != 0 {
		t.Errorf("observed %+v on a machine where nothing is being recorded", found)
	}
}

func TestARunnerThatWasNeverBuiltObservesNoRhythms(t *testing.T) {
	var runner *ipsRunner

	if found := runner.beacons(time.Now()); found != nil {
		t.Errorf("observed %+v from a runner that does not exist", found)
	}
}

// The view is where the observation is actually read, and one that stopped at the runner would
// be a record kept and shown to nobody.
func TestARhythmReachesTheViewSayingWhatKeepsItAndHowOften(t *testing.T) {
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	api := newIPSAPIAt(t, &at, func(s *config.Settings) {
		inspecting(s)
		s.IPSAnomaly = true
	})

	start := at
	checkIn(api.a.currentIPS(), &at, "10.1.2.9", start, 5*time.Minute)
	view := api.View()

	if len(view.Beacons) != 1 {
		t.Fatalf("the view carries %d rhythms, want the one that was made: %+v", len(view.Beacons), view.Beacons)
	}
	got := view.Beacons[0]
	if got.Addr != "10.1.2.9" || got.Every != (5*time.Minute).Seconds() {
		t.Errorf("rhythm = %+v, want the destination and the gap it was reached at", got)
	}
	if got.Source == "" || got.Count != 8 || got.Since == "" {
		t.Errorf("rhythm = %+v, want it to say who, how many, and since when", got)
	}
	if len(view.Recent) != 0 || view.Anomalies != 0 {
		t.Error("a rhythm was counted or listed among the findings, which are things to look at")
	}
}

// The settings are the only thing that turns the watch on, and a field that never reached the
// runner is a switch that reads as on and records nothing.
func TestTheSettingIsWhatTurnsTheWatchOn(t *testing.T) {
	api := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSAnomaly = true
	})

	if api.a.currentIPS().watch.Load() == nil {
		t.Fatal("the setting is on and no ledger was built, so nothing is being recorded")
	}
	if view := api.View(); !view.Anomaly {
		t.Error("the view says the watch is off while the setting says it is on")
	}
}

// Off is the default, and a ledger built anyway would be this feature keeping a record of
// where traffic went on a machine that never asked for it.
func TestTheWatchIsOffUntilItIsTurnedOn(t *testing.T) {
	api := newIPSAPI(t, inspecting)

	if api.a.currentIPS().watch.Load() != nil {
		t.Error("a ledger was built on a machine where the watch is off")
	}
	if view := api.View(); view.Anomaly {
		t.Error("the view says the watch is on while the setting says it is off")
	}
}

// An empty list is the state a machine running only the watch is meant to be in. Telling that
// user to add an entry is telling them to fix something that is not broken.
func TestTheWatchAloneIsNotReportedAsHavingNothingToMatch(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		s.IPSEnabled = true
		s.IPSMode = config.IPSModeDetect
		notMatchingLists(s)
		s.IPSAnomaly = true
	}).View()

	if view.Capability.Degraded {
		t.Errorf("capability = %+v, want the watch on its own read as working", view.Capability)
	}
}

// The other half of the same rule: a signal that does match against the lists, with nothing
// in them, is a switch that is on and doing nothing.
func TestASignalThatMatchesListsWithNothingInThemIsStillReported(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		inspecting(s)
		s.IPSAnomaly = true
	}).View()

	if !view.Capability.Degraded {
		t.Fatal("inspection matching names against an empty list reads as working")
	}
	if !strings.Contains(view.Capability.Reason, "nothing to match") {
		t.Errorf("reason = %q, want it to say the lists are empty", view.Capability.Reason)
	}
}

// Every switch off is inspection compiled and applied to nothing, and the reason has to name
// all three or a user turns on the two it mentions and still sees nothing.
func TestInspectionWithNoSignalAtAllNamesEverySwitchThatIsOff(t *testing.T) {
	view := newIPSAPI(t, func(s *config.Settings) {
		s.IPSEnabled = true
		s.IPSMode = config.IPSModeDetect
		notMatchingLists(s)
	}).View()

	if !view.Capability.Degraded {
		t.Fatal("inspection with no signal on reads as working")
	}
	for _, want := range []string{"names", "addresses", "unusual patterns"} {
		if !strings.Contains(view.Capability.Reason, want) {
			t.Errorf("reason = %q, want it to name the %s switch", view.Capability.Reason, want)
		}
	}
}
