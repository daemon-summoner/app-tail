// SPDX-License-Identifier: MIT

package app

// What the runner does with the byte patterns somebody typed: when they are built, what a
// match is reported as, and what happens to the ones already in force when a new line will not
// compile.

import (
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// theToken is the pattern every test here watches for, in the shape the feature exists for: a
// value the user knows and wants to hear about if it ever leaves in the clear.
const theToken = "hunter2-9f3a1c"

// tokenEntry is that pattern as it is written in the setting.
var tokenEntry = []string{`a token that must not leave = "` + theToken + `"`}

// carryingTheToken is a connection whose opening bytes hold the token, long enough that the window
// fills and the patterns are read.
func carryingTheToken() []byte {
	return []byte("POST /upload HTTP/1.1\r\nHost: files.example\r\n\r\n" +
		"payload=" + theToken + strings.Repeat("&x=1", 1200))
}

func TestSomethingTheUserIsWatchingForIsRecordedWhereItLeaves(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.compileSignatures(manualSourceName, tokenEntry)

	watch := runner.Watch(handshakeFlow)
	if watch == nil {
		t.Fatal("nothing was reading a connection with patterns compiled")
	}
	if watch.Up(carryingTheToken()) {
		t.Error("a connection was stopped while the mode is detect")
	}
	watch.Close()

	matched, refused, _ := runner.totals()
	if matched != 1 || refused != 0 {
		t.Fatalf("totals = %d matched, %d refused; want the match counted and nothing stopped",
			matched, refused)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSDetected {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSDetected)
	}
	if got := (*events)[0].fields["signal"]; got != string(inspect.SignalPayload) {
		t.Errorf("event signal = %q, want %q", got, inspect.SignalPayload)
	}
	// What the connection turned out to be goes with the match: a token leaving over a plain
	// web request and one leaving over something unreadable are different findings.
	if got := (*events)[0].fields["protocol"]; got != inspect.ProtocolHTTP {
		t.Errorf("event protocol = %q, want %q", got, inspect.ProtocolHTTP)
	}

	recent := runner.recentMatches()
	if len(recent) != 1 {
		t.Fatalf("the ring holds %d detections, want one", len(recent))
	}
	if recent[0].Value != "a token that must not leave" {
		t.Errorf("the detection names %q", recent[0].Value)
	}
	// The pattern is the secret. A detection carrying the bytes that matched would copy it into
	// the card, the log and every event that reaches the hub.
	for _, text := range []string{recent[0].Value, recent[0].Source, recent[0].Reason} {
		if strings.Contains(text, theToken) {
			t.Fatalf("a detection carried the pattern's own bytes: %q", text)
		}
	}
	for field, text := range (*events)[0].fields {
		if strings.Contains(text, theToken) {
			t.Fatalf("event field %q carried the pattern's own bytes: %q", field, text)
		}
	}
}

func TestAConnectionCarryingAPatternIsStoppedWhileTheModeIsPrevent(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.prevent.Store(true)
	runner.compileSignatures(manualSourceName, tokenEntry)

	if !runner.Watch(handshakeFlow).Up(carryingTheToken()) {
		t.Fatal("a connection carrying a pattern was carried on while the mode is prevent")
	}
	if _, refused, _ := runner.totals(); refused != 1 {
		t.Errorf("refused = %d, want the refusal counted", refused)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSBlocked {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSBlocked)
	}
}

// A datagram flow carries the same patterns to the same place. It is a second set of switches
// read in a second place, so a pattern honoured on connections and not on datagrams is a user
// watching for a value that leaves over UDP unwatched.
func TestSomethingTheUserIsWatchingForIsRecordedWhereItLeavesOverDatagrams(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.prevent.Store(true)
	runner.compileSignatures(manualSourceName, tokenEntry)

	flow := inspect.Flow{Where: "the network interface", Protocol: "udp"}
	watch := runner.WatchDatagrams(flow)
	if watch == nil {
		t.Fatal("nothing was reading a datagram flow with patterns compiled")
	}
	if !watch.Up([]byte("carrying " + theToken + " along")) {
		t.Fatal("a datagram carrying a pattern was carried on while the mode is prevent")
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSBlocked {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSBlocked)
	}
	if got := (*events)[0].fields["signal"]; got != string(inspect.SignalPayload) {
		t.Errorf("event signal = %q, want %q", got, inspect.SignalPayload)
	}
}

// A connection carrying nothing anybody wrote a pattern for is carried, and the stream still
// read it: a match that only ever fired on the token would pass the tests above unchanged.
func TestAConnectionCarryingNoPatternIsCarried(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.prevent.Store(true)
	runner.compileSignatures(manualSourceName, tokenEntry)

	ordinary := []byte("POST /upload HTTP/1.1\r\nHost: files.example\r\n\r\n" +
		strings.Repeat("&x=1", 1200))
	if runner.Watch(handshakeFlow).Up(ordinary) {
		t.Fatal("a connection carrying no pattern was stopped")
	}
	if matched, _, _ := runner.totals(); matched != 0 {
		t.Errorf("matched = %d, want nothing counted", matched)
	}
	if len(*events) != 0 {
		t.Errorf("events = %+v, want none", *events)
	}
}

// A pause reaches a connection that is already being read, because that is the one somebody is
// staring at when they click pause.
func TestAPausedRunnerCarriesAConnectionThatMatchedAPattern(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.prevent.Store(true)
	runner.compileSignatures(manualSourceName, tokenEntry)

	watch := runner.Watch(handshakeFlow)
	runner.pause(15 * time.Minute)

	if watch.Up(carryingTheToken()) {
		t.Fatal("a connection already being read was stopped after inspection was paused")
	}
	if matched, _, _ := runner.totals(); matched != 0 {
		t.Errorf("matched = %d, want nothing counted while inspection is paused", matched)
	}
	if len(*events) != 0 {
		t.Errorf("events = %+v, want none while inspection is paused", *events)
	}
}

// The patterns are the whole reason to read a connection when nothing else could match it, so
// a runner with names off and nothing compiled still hands out a stream.
func TestPatternsAloneAreReasonEnoughToReadAConnection(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.names.Store(false)
	runner.clear()

	if watch := runner.Watch(handshakeFlow); watch != nil {
		t.Fatal("a connection is being read with nothing that could match it")
	}
	runner.compileSignatures(manualSourceName, tokenEntry)
	if watch := runner.Watch(handshakeFlow); watch == nil {
		t.Fatal("nothing reads a connection with patterns compiled and everything else off")
	}
	if watch := runner.WatchDatagrams(handshakeFlow); watch == nil {
		t.Fatal("nothing reads a datagram flow with patterns compiled and everything else off")
	}

	// And switching them off takes the reason away again, which is what makes the window stop
	// being held on every connection the machine opens.
	runner.clearSignatures()
	if watch := runner.Watch(handshakeFlow); watch != nil {
		t.Error("a connection is still being read after the patterns were cleared")
	}
	if runner.signatureCount() != 0 {
		t.Errorf("%d patterns are still in force after they were cleared", runner.signatureCount())
	}
}

// One mistyped line must not silently take a control the user asked for out of service: what
// was already matching goes on matching, and the failure is said out loud.
func TestALineThatWillNotCompileLeavesTheOnesAlreadyInForceMatching(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.prevent.Store(true)
	runner.compileSignatures(manualSourceName, tokenEntry)

	runner.compileSignatures(manualSourceName, append(tokenEntry, "this is not a signature"))

	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSFailed {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSFailed)
	}
	if runner.signatureCount() != 1 {
		t.Fatalf("%d patterns are in force, want the one that was already matching",
			runner.signatureCount())
	}
	if !runner.Watch(handshakeFlow).Up(carryingTheToken()) {
		t.Fatal("the pattern that was already in force stopped matching")
	}
}

// Rebuilding the matcher on every reconcile would be a walk over every pattern once a second
// for as long as the app runs, so an unchanged set of entries is left alone -- and a changed
// one is not.
func TestTheMatcherIsBuiltOnlyWhenWhatIsWrittenChanges(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, nil)
	runner.compileSignatures(manualSourceName, tokenEntry)
	if runner.signatureCount() != 1 {
		t.Fatalf("%d patterns are in force after the first build, want 1", runner.signatureCount())
	}

	// Take the built matcher away underneath: the same entries must not put it back, which is
	// only true if the build was skipped rather than repeated.
	runner.signatures.Store(nil)
	runner.compileSignatures(manualSourceName, tokenEntry)
	if runner.signatureCount() != 0 {
		t.Error("the matcher was rebuilt from entries that had not changed")
	}

	runner.compileSignatures(manualSourceName, append(tokenEntry, `another = "second-pattern"`))
	if runner.signatureCount() != 2 {
		t.Fatalf("%d patterns are in force after the entries changed, want 2",
			runner.signatureCount())
	}
}

func TestARunnerWithNoPatternsCountsNone(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, nil)
	if runner.signatureCount() != 0 {
		t.Errorf("a runner that compiled nothing counts %d patterns", runner.signatureCount())
	}

	// And a runner that is not there at all, which is what every path holds while the module is
	// off.
	var none *ipsRunner
	if none.signatureCount() != 0 {
		t.Errorf("no runner at all counts %d patterns", none.signatureCount())
	}
}
