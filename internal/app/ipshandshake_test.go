// SPDX-License-Identifier: MIT

package app

// Whether the runner reads a connection's opening bytes at all, and what it does with what
// they said. The nil answers matter as much as the matches: every path that carries bytes
// compares what this hands back against nil, so a stream handed out when nothing could match
// is a window held open for every connection on the machine.

import (
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// helloFor is a client hello asking for one name, which is what the paths that carry bytes
// hand the stream.
func helloFor(name string) []byte {
	var body []byte
	appendU16 := func(v int) { body = append(body, byte(v>>8), byte(v)) }

	var sni []byte
	sni = append(sni, byte((len(name)+3)>>8), byte(len(name)+3))
	sni = append(sni, 0x00, byte(len(name)>>8), byte(len(name)))
	sni = append(sni, name...)

	var extensions []byte
	extensions = append(extensions, 0x00, 0x00, byte(len(sni)>>8), byte(len(sni)))
	extensions = append(extensions, sni...)

	appendU16(0x0303)
	for i := 0; i < 32; i++ {
		body = append(body, 0x11)
	}
	body = append(body, 0x00)
	appendU16(2)
	appendU16(0x1301)
	body = append(body, 0x01, 0x00)
	appendU16(len(extensions))
	body = append(body, extensions...)

	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

// The flow every test here reads, which is a connection dialled at an address: no name was
// asked for, so the opening bytes are the only thing that can name it.
var handshakeFlow = inspect.Flow{Where: "the network interface", Protocol: "tcp"}

func TestANameReadOffTheWireIsRecordedAsOneThatWas(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.handshake.Store(true)
	runner.fingerprints.Store(true)

	watch := runner.Watch(handshakeFlow)
	if watch == nil {
		t.Fatal("nothing was reading a connection with the switch on and rules compiled")
	}
	if watch.Up(helloFor("bad.example")) {
		t.Error("a connection was stopped while the mode is detect")
	}
	watch.Close()

	matched, refused, _ := runner.totals()
	if matched != 1 || refused != 0 {
		t.Fatalf("totals = %d matched, %d refused; want the match counted and nothing stopped", matched, refused)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSDetected {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSDetected)
	}
	// The signal is what the user reads, and it has to say the name came off the wire rather
	// than from a program that asked app-tail for it.
	if got := (*events)[0].fields["signal"]; got != string(inspect.SignalHandshake) {
		t.Errorf("event signal = %q, want %q", got, inspect.SignalHandshake)
	}

	recent := runner.recentMatches()
	if len(recent) != 1 {
		t.Fatalf("the ring holds %d detections, want one", len(recent))
	}
	if recent[0].Protocol != inspect.ProtocolTLS {
		t.Errorf("the detection reads as %q, want %q", recent[0].Protocol, inspect.ProtocolTLS)
	}
	if recent[0].Fingerprint == "" {
		t.Error("the detection carries no fingerprint with fingerprinting switched on")
	}
	if recent[0].Where != handshakeFlow.Where {
		t.Errorf("the detection says it happened at %q, want %q", recent[0].Where, handshakeFlow.Where)
	}
}

func TestANameReadOffTheWireIsStoppedWhileTheModeIsPrevent(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.handshake.Store(true)
	runner.prevent.Store(true)

	watch := runner.Watch(handshakeFlow)
	if !watch.Up(helloFor("bad.example")) {
		t.Fatal("a denied name was carried while the mode is prevent")
	}
	if _, refused, _ := runner.totals(); refused != 1 {
		t.Errorf("refused = %d, want the refusal counted", refused)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSBlocked {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSBlocked)
	}
}

// A name nothing denies is carried, and the stream is still the thing that read it: a match
// that only ever fired on the denied name would pass every other test here.
func TestANameNothingDeniesIsCarried(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.handshake.Store(true)
	runner.prevent.Store(true)

	watch := runner.Watch(handshakeFlow)
	if watch.Up(helloFor("fine.example")) {
		t.Fatal("a name nothing denies was stopped")
	}
	if matched, _, _ := runner.totals(); matched != 0 {
		t.Errorf("matched = %d, want nothing counted for a name nothing denies", matched)
	}
	if len(*events) != 0 {
		t.Errorf("events = %+v, want none", *events)
	}
}

// Every state in which reading a connection could not change what happens to it, each of
// which has to hand back nothing rather than a window.
func TestNothingReadsAConnectionWhenNothingCouldMatchIt(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		setup func(*ipsRunner)
	}{
		{"the switch is off", func(r *ipsRunner) { r.handshake.Store(false) }},
		{"inspection is paused", func(r *ipsRunner) { r.pause(15 * time.Minute) }},
		{"names are switched off", func(r *ipsRunner) { r.names.Store(false) }},
		{"nothing is compiled", func(r *ipsRunner) { r.clear() }},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})
			runner.handshake.Store(true)
			held.setup(runner)

			// Nil the interface, not a stream inside one: the paths that carry bytes compare
			// what they are handed against nil, and a typed nil reads as an inspector to every
			// one of them.
			if watch := runner.Watch(handshakeFlow); watch != nil {
				t.Errorf("a connection is being read with %s", held.name)
			}
		})
	}

	// And a runner that is not there at all, which is what every path holds while the module
	// is off.
	var none *ipsRunner
	if watch := none.Watch(handshakeFlow); watch != nil {
		t.Error("a connection is being read with no runner at all")
	}
	if watch := none.WatchDatagrams(handshakeFlow); watch != nil {
		t.Error("a datagram flow is being read with no runner at all")
	}
}

// A pause has to reach a connection that is already open, because that is the one somebody is
// staring at when they click pause.
func TestAPauseStopsAConnectionAlreadyBeingRead(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.handshake.Store(true)
	runner.prevent.Store(true)

	watch := runner.Watch(handshakeFlow)
	runner.pause(15 * time.Minute)

	if watch.Up(helloFor("bad.example")) {
		t.Fatal("a connection already being read was stopped after inspection was paused")
	}
	if matched, _, _ := runner.totals(); matched != 0 {
		t.Errorf("matched = %d, want nothing counted while inspection is paused", matched)
	}
}

// The set a user edited while a connection was still opening is the set that connection is
// measured against, because the window between the two is long enough for that to happen.
func TestAConnectionIsMeasuredAgainstTheRulesInForceWhenItsBytesArrive(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"other.example"})
	runner.handshake.Store(true)
	runner.prevent.Store(true)

	watch := runner.Watch(handshakeFlow)
	compileFrom(runner, manualSource(nil, []string{"late.example"}))

	if !watch.Up(helloFor("late.example")) {
		t.Fatal("a name denied by the rules now in force was carried")
	}
}

// The datagram side, where a name is one somebody else's resolver was asked for. That is the
// case the name path cannot reach: app-tail's own resolver never saw it.
func TestANameAskedOfAnotherResolverIsStillMatched(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.handshake.Store(true)
	runner.prevent.Store(true)

	watch := runner.WatchDatagrams(inspect.Flow{Where: "the network interface", Protocol: "udp"})
	if watch == nil {
		t.Fatal("nothing was reading a datagram flow with the switch on and rules compiled")
	}
	if !watch.Up(dnsQueryFor("bad.example")) {
		t.Fatal("a denied name asked of another resolver was carried while the mode is prevent")
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSBlocked {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSBlocked)
	}
	if got := (*events)[0].fields["protocol"]; got != inspect.ProtocolDNS {
		t.Errorf("event protocol = %q, want %q", got, inspect.ProtocolDNS)
	}
}

// The datagram side answers nothing in the same states the connection side does. It is a
// second set of switches read in a second place, so a switch honoured on one and not the
// other is a user who turned the start of each connection off and kept paying for it over UDP.
func TestNothingReadsADatagramFlowWhenNothingCouldMatchIt(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	flow := inspect.Flow{Where: "the network interface", Protocol: "udp"}

	cases := []struct {
		name  string
		setup func(*ipsRunner)
	}{
		{"the switch is off", func(r *ipsRunner) { r.handshake.Store(false) }},
		{"inspection is paused", func(r *ipsRunner) { r.pause(15 * time.Minute) }},
		{"names are switched off", func(r *ipsRunner) { r.names.Store(false) }},
		{"nothing is compiled", func(r *ipsRunner) { r.clear() }},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})
			runner.handshake.Store(true)
			held.setup(runner)

			if watch := runner.WatchDatagrams(flow); watch != nil {
				t.Errorf("a datagram flow is being read with %s", held.name)
			}
		})
	}
}

// The ledger reads the questions even where no rule could match one, because a run of long
// random names is a finding on a machine with nothing typed into any list.
func TestQuestionsAreStillReadForTheLedgerWithNothingToMatchThemAgainst(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, nil)
	runner.handshake.Store(true)
	runner.names.Store(false)
	runner.clear()
	runner.watch.Store(inspect.NewWatch(inspect.Limits{}))

	watch := runner.WatchDatagrams(inspect.Flow{Where: "the network interface", Protocol: "udp"})
	if watch == nil {
		t.Fatal("nothing was reading the questions with the ledger running")
	}
	if watch.Up(dnsQueryFor("tunnelled.example")) {
		t.Error("a question was stopped with nothing compiled to stop it")
	}
	if len(*events) != 0 {
		t.Errorf("events = %+v, want none: nothing was compiled to match", *events)
	}
	watch.Close()
}

// Every state in which a name that was read is carried anyway. Each is read again when the
// bytes arrive rather than captured when the stream was made, so each is a state a user can
// reach while a connection is still opening.
func TestANameReadOffTheWireIsCarriedWhenNothingCanActOnIt(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		setup func(*ipsRunner)
	}{
		{"names are switched off", func(r *ipsRunner) { r.names.Store(false) }},
		{"nothing is compiled", func(r *ipsRunner) { r.clear() }},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})
			runner.handshake.Store(true)
			runner.prevent.Store(true)

			watch := runner.Watch(handshakeFlow)
			held.setup(runner)

			if watch.Up(helloFor("bad.example")) {
				t.Errorf("a denied name was stopped with %s", held.name)
			}
			if len(*events) != 0 {
				t.Errorf("events = %+v, want none with %s", *events, held.name)
			}
		})
	}

	// And opening bytes that named nothing at all, which is every connection whose hello
	// carried no name and every one this cannot read.
	runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.handshake.Store(true)
	runner.prevent.Store(true)
	if runner.opened(handshakeFlow, inspect.Handshake{Protocol: inspect.ProtocolTLS}) {
		t.Error("a connection that named nothing was stopped")
	}
	if len(*events) != 0 {
		t.Errorf("events = %+v, want none for a connection that named nothing", *events)
	}
}

// dnsQueryFor is a query for one name, as a program that brought its own resolver sends it.
func dnsQueryFor(name string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	start := 0
	for at := 0; at <= len(name); at++ {
		if at == len(name) || name[at] == '.' {
			msg = append(msg, byte(at-start))
			msg = append(msg, name[start:at]...)
			start = at + 1
		}
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01)
	return msg
}
