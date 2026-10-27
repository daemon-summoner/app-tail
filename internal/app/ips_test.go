// SPDX-License-Identifier: MIT

package app

// What traffic inspection does with a connection: whether it is recorded, whether it is
// stopped, and what the card is told afterwards.

import (
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// recordedIPSEvent is one line the runner wrote to the log, kept so a test can assert what
// a match was reported as rather than only what it returned.
type recordedIPSEvent struct {
	code    telemetry.EventCode
	message string
	fields  map[string]string
}

// newTestIPS builds a runner on a clock the test moves, with the rules compiled from the
// entries given. The events it records are collected rather than dropped: what a match is
// reported as is half of what this feature does.
func newTestIPS(t *testing.T, now *time.Time, allow, deny []string) (*ipsRunner, *[]recordedIPSEvent) {
	t.Helper()
	var events []recordedIPSEvent
	runner := newIPSRunner(
		func() time.Time { return *now },
		func(code telemetry.EventCode, message string, fields map[string]string) {
			events = append(events, recordedIPSEvent{code: code, message: message, fields: fields})
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	compileFrom(runner, manualSource(allow, deny))
	runner.names.Store(true)
	runner.destinations.Store(true)
	return runner, &events
}

// compileFrom builds the rules the way a reconcile does. The key is what decides whether a
// rebuild happens at all, and a reconcile derives it from the sources, so a test that passed
// its own key would be testing a rule nothing else follows.
func compileFrom(r *ipsRunner, sources []inspect.Source) {
	r.compile(ipsCompileKey(sources), sources)
}

// manualSource is the one source the settings compile as, which is what every path that
// builds rules here passes.
func manualSource(allow, deny []string) []inspect.Source {
	return []inspect.Source{{ID: manualSourceID, Name: manualSourceName, Allow: allow, Deny: deny}}
}

func TestAMatchIsRecordedAndCarriedWhileTheModeIsDetect(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})

	reason, refuse := runner.Refuse(inspect.Flow{Name: "bad.example", Where: "the proxy"})

	if refuse || reason != "" {
		t.Errorf("Refuse = %q, %v, want the connection carried while the mode is detect", reason, refuse)
	}
	matched, refused, _ := runner.totals()
	if matched != 1 || refused != 0 {
		t.Errorf("totals = %d matched, %d refused; want the match counted and nothing stopped", matched, refused)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSDetected {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSDetected)
	}
	if got := (*events)[0].fields["value"]; got != "bad.example" {
		t.Errorf("event value = %q, want the name that matched", got)
	}
}

func TestAMatchIsRefusedWhileTheModeIsPrevent(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, []string{"10.1.2.0/24"})
	runner.prevent.Store(true)

	reason, refuse := runner.Refuse(inspect.Flow{
		Addr: netip.MustParseAddr("10.1.2.9"), Where: "the network interface", Protocol: "tcp",
	})

	if !refuse {
		t.Fatal("a denied address was carried while the mode is prevent")
	}
	if reason == "" {
		t.Error("the refusal carries no reason, so nothing downstream can say why the connection failed")
	}
	if _, refused, _ := runner.totals(); refused != 1 {
		t.Errorf("refused = %d, want the refusal counted", refused)
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSBlocked {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSBlocked)
	}
}

// The two signals are separate switches, and a path that hands over a name is not the same
// path that hands over an address. A switch that was read as a pair would inspect what its
// owner turned off.
func TestASignalThatIsSwitchedOffIsNotAsked(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"bad.example", "10.1.2.0/24"})
	runner.prevent.Store(true)
	runner.names.Store(false)

	flow := inspect.Flow{
		Name: "bad.example", Addr: netip.MustParseAddr("10.1.2.9"), Where: "the proxy",
	}
	if _, refuse := runner.Refuse(flow); !refuse {
		t.Fatal("the address was carried, so switching names off switched addresses off too")
	}

	runner.destinations.Store(false)
	if _, refuse := runner.Refuse(flow); refuse {
		t.Error("a flow was refused with both signals off, so a switch nobody turned on is inspecting")
	}
}

// A pause has to reach the next connection rather than the next reconcile: it is asked for
// because something is broken right now, and inspection somebody cannot un-break in one
// click is what makes a false positive cost them their machine.
func TestAPauseCarriesTheNextConnectionAndResumingStopsItAgain(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.prevent.Store(true)
	flow := inspect.Flow{Name: "bad.example", Where: "the proxy"}

	until := runner.pause(15 * time.Minute)
	if _, refuse := runner.Refuse(flow); refuse {
		t.Fatal("a connection was refused while inspection is paused")
	}
	if matched, _, _ := runner.totals(); matched != 0 {
		t.Errorf("matched = %d, want a paused connection not counted as a match", matched)
	}

	// A pause ends by itself, without anything having had to clear it.
	at = until.Add(time.Second)
	if _, refuse := runner.Refuse(flow); !refuse {
		t.Fatal("a connection was carried after the pause ran out")
	}

	at = at.Add(time.Second)
	runner.pause(15 * time.Minute)
	runner.resume()
	if _, refuse := runner.Refuse(flow); !refuse {
		t.Error("a connection was carried after the pause was ended early")
	}
}

// The card reads the pause from the same place the data path does, so a deadline that has
// passed has to read as running there too: a card that still says "paused" after the pause
// ran out is somebody clicking resume on a pause that is already over.
func TestAPauseThatHasRunOutIsReportedAsRunningAgain(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})

	until := runner.pause(15 * time.Minute)
	if end, paused := runner.paused(); !paused || !end.Equal(until) {
		t.Fatalf("paused = %s, %v; want the pause in force until %s", end, paused, until)
	}

	at = until.Add(time.Second)
	if end, paused := runner.paused(); paused {
		t.Errorf("paused = %s, %v; want a deadline that has passed to read as running", end, paused)
	}
}

func TestTheRingKeepsTheNewestMatchesAndDropsTheOldest(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})

	// One more than the ring holds, so the wrap is what is being read rather than the
	// straight case that happens to fit.
	const made = recentDetections + 5
	for i := range made {
		runner.Refuse(inspect.Flow{
			Name: "bad.example", Where: "a network this device routes", Peer: strconv.Itoa(i),
		})
	}

	recent := runner.recentMatches()
	if len(recent) != recentDetections {
		t.Fatalf("recent = %d entries, want the ring's %d", len(recent), recentDetections)
	}
	if recent[0].Peer != strconv.Itoa(made-1) {
		t.Errorf("newest = %q, want the last connection made", recent[0].Peer)
	}
	if last := recent[len(recent)-1].Peer; last != strconv.Itoa(made-recentDetections) {
		t.Errorf("oldest kept = %q, want the %dth connection", last, made-recentDetections)
	}
	if matched, _, _ := runner.totals(); matched != made {
		t.Errorf("matched = %d, want the total to survive the ring wrapping", matched)
	}
}

// The reconcile runs on every pass over the settings, so a compile that ran again each time
// would re-parse every entry for nothing and hand the data path a new matcher it has no
// reason to read.
func TestCompilingTheSameEntriesAgainKeepsTheRulesAlreadyInForce(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, []string{"good.example"}, []string{"bad.example"})
	before := runner.rules.Load()
	builtAt := runner.compiled()

	at = at.Add(time.Hour)
	compileFrom(runner, manualSource([]string{"good.example"}, []string{"bad.example"}))
	if runner.rules.Load() != before {
		t.Error("the same entries built a second matcher")
	}
	if !runner.compiled().Equal(builtAt) {
		t.Error("the card was told the rules were rebuilt when nothing changed")
	}

	compileFrom(runner, manualSource(nil, []string{"bad.example", "worse.example"}))
	if runner.rules.Load() == before {
		t.Error("an edited list left the old matcher in force")
	}
}

// Switching inspection off has to give the memory back, and has to leave the matches that
// are the reason somebody is looking at the card.
func TestClearingTheRulesKeepsWhatAlreadyMatched(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, _ := newTestIPS(t, &at, nil, []string{"bad.example"})
	runner.Refuse(inspect.Flow{Name: "bad.example", Where: "the proxy"})

	runner.clear()

	if runner.rules.Load() != nil {
		t.Error("the rules are still in force after inspection was switched off")
	}
	if !runner.compiled().IsZero() {
		t.Error("the card still reports rules built at a time nothing is compiled")
	}
	if len(runner.recentMatches()) != 1 {
		t.Error("switching inspection off threw away the matches somebody turned it off to read")
	}
	if _, refuse := runner.Refuse(inspect.Flow{Name: "bad.example"}); refuse {
		t.Error("a connection was refused with no rules compiled")
	}
}

// A set of sources that will not compile must leave the rules already in force applying:
// switching inspection off because one edit did not build is the failure a user reads as
// the feature having quietly stopped working. It is reported rather than swallowed.
func TestASetThatWillNotCompileKeepsTheRulesInForceAndSaysSo(t *testing.T) {
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	runner, events := newTestIPS(t, &at, nil, []string{"bad.example"})
	before := runner.rules.Load()
	builtAt := runner.compiled()

	// More sources than the matcher can attribute a match to, which is the one thing
	// Compile refuses.
	tooMany := make([]inspect.Source, inspect.MaxSources+1)
	for i := range tooMany {
		tooMany[i] = inspect.Source{ID: strconv.Itoa(i), Name: "a list", Deny: []string{"worse.example"}}
	}
	at = at.Add(time.Hour)
	compileFrom(runner, tooMany)

	if runner.rules.Load() != before {
		t.Error("a set that would not compile replaced the rules already in force")
	}
	if !runner.compiled().Equal(builtAt) {
		t.Error("the card was told the rules were rebuilt by a compile that failed")
	}
	if len(*events) != 1 || (*events)[0].code != telemetry.CodeIPSFailed {
		t.Fatalf("events = %+v, want one %s", *events, telemetry.CodeIPSFailed)
	}
	if (*events)[0].fields["error"] == "" {
		t.Error("the failure carries no reason, so nobody can tell what would not build")
	}
	if _, refuse := runner.Refuse(inspect.Flow{Name: "bad.example", Where: "the proxy"}); refuse {
		t.Error("the mode is detect, so the entry still in force must be carried")
	}
}

// Every carrying path holds the inspector through an interface, and holds nothing when the
// module is off. A nil runner answering anything but "carry it" would take the data path
// down with the switch.
func TestARunnerThatIsNotThereCarriesEverything(t *testing.T) {
	var runner *ipsRunner

	reason, refuse := runner.Refuse(inspect.Flow{
		Name: "bad.example", Addr: netip.MustParseAddr("10.1.2.9"),
	})

	if refuse || reason != "" {
		t.Errorf("Refuse = %q, %v, want everything carried when inspection is not running", reason, refuse)
	}
}
