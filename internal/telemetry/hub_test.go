// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// testHub builds a hub on a clock the test drives, so a retention window is exercised by
// moving the clock rather than by waiting one out.
func testHub(t *testing.T, cfg Config, now *time.Time) *Hub {
	t.Helper()
	return New(Options{
		Config: cfg,
		Now:    func() time.Time { return *now },
	})
}

// runHub starts the drain goroutine and guarantees it is stopped, so a test that records
// something can read it back through the same barrier the agent's shutdown uses.
func runHub(t *testing.T, h *Hub) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	go h.Run(ctx)
	t.Cleanup(func() {
		h.Stop()
		cancel()
	})
}

// eventsOf reads the whole log back, newest first, and fails rather than returning an
// error so the assertions below stay about the log's contents.
func eventsOf(t *testing.T, h *Hub) []Event {
	t.Helper()
	page, err := h.Events(t.Context(), EventQuery{})
	if err != nil {
		t.Fatalf("read the event log: %v", err)
	}
	return page.Events
}

// Recording is opt-in, and off is the state a fresh install runs in. A hub that collected
// while switched off would make the setting a display preference rather than a switch,
// which is the whole promise this package makes.
func TestAHubThatIsSwitchedOffRecordsNothingAtAll(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{}, &now)
	runHub(t, h)

	h.RecordEvent(CodeAppStart, "app-tail started.", nil)
	h.Stop()

	if got := h.events.all(); len(got) != 0 {
		t.Fatalf("a switched-off hub recorded %d events", len(got))
	}
	if _, err := h.Events(t.Context(), EventQuery{}); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("reading a switched-off log returned %v, want ErrNotEnabled", err)
	}
}

// The code decides the category and the severity, not the call site. Two places recording
// the same code with different classifications would make the dashboard's facet filters
// mean nothing, so the hub takes both from the catalog.
func TestARecordedEventIsClassifiedFromTheCatalogRatherThanFromTheCallSite(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)
	runHub(t, h)

	h.RecordEvent(CodeForwardError, "The forward web could not start.",
		map[string]string{"forward": "f_a"})
	h.Stop()

	got := eventsOf(t, h)
	if len(got) != 1 {
		t.Fatalf("the log holds %d events, want 1", len(got))
	}
	e := got[0]
	if e.Category != CategoryNetwork || e.Severity != SeverityError {
		t.Errorf("forward.error was filed as %v/%v, want network/error", e.Category, e.Severity)
	}
	if e.At != now {
		t.Errorf("the event is stamped %v, want the hub's clock reading %v", e.At, now)
	}
	if e.Seq == 0 {
		t.Error("the event carries no sequence number, so pagination cannot resume inside a tick")
	}
	if e.Fields["forward"] != "f_a" {
		t.Errorf("the event lost its fields: %v", e.Fields)
	}
}

// A code outside the catalog is a bug in the calling code rather than a fact about the
// machine. Recording it would put a row in the very list it corrupts and hide the mistake
// in the place people go to find mistakes.
func TestACodeThatIsNotInTheCatalogIsRefusedInsteadOfRecorded(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)
	runHub(t, h)

	h.RecordEvent(EventCode("forward.exploded"), "Something happened.", nil)
	h.RecordEvent(CodeAppStart, "app-tail started.", nil)
	h.Stop()

	got := eventsOf(t, h)
	if len(got) != 1 {
		t.Fatalf("the log holds %d events, want only the one with a known code", len(got))
	}
	if got[0].Code != CodeAppStart {
		t.Errorf("the log kept %q, want the catalogued code", got[0].Code)
	}
}

// Every event is stamped with a sequence number in the order it was recorded, which is
// what makes the keyset cursor able to resume exactly inside a group of rows sharing one
// clock reading.
func TestEventsRecordedInsideOneClockTickStillCarryATotalOrder(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)
	runHub(t, h)

	for range 3 {
		h.RecordEvent(CodeAppStart, "app-tail started.", nil)
	}
	h.Stop()

	got := eventsOf(t, h)
	if len(got) != 3 {
		t.Fatalf("the log holds %d events, want 3", len(got))
	}
	// Newest first, so the sequence numbers descend.
	for i := 1; i < len(got); i++ {
		if got[i-1].Seq <= got[i].Seq {
			t.Fatalf("sequence numbers are not a total order: %d then %d",
				got[i-1].Seq, got[i].Seq)
		}
	}
}

// The data path is called from inside a DNS answer and a proxy connection close. A
// recorder that blocked when nothing was draining it would stall real traffic to keep a
// graph honest, which is the wrong trade; it drops and counts instead.
func TestARecorderThatFallsBehindDropsRowsRatherThanStallingTheCaller(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	// Deliberately not run: nothing is draining the queue, which is the condition a
	// burst faster than the drain produces.
	h := testHub(t, Config{Enabled: true}, &now)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range queueDepth + 25 {
			h.RecordEvent(CodeAppStart, "app-tail started.", nil)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recording blocked once the queue filled, which would stall the data path")
	}

	if got := h.Dropped(); got != 25 {
		t.Errorf("the hub dropped %d rows, want the 25 that did not fit", got)
	}
}

// A log silently missing rows reads exactly like a quiet machine. The drop counter is
// turned into an event of its own so the gap is visible in the list rather than inferred
// from a counter nobody looks at.
func TestRowsThatWereDroppedAreAdmittedToInTheLogItself(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)
	for range queueDepth + 3 {
		h.RecordEvent(CodeAppStart, "app-tail started.", nil)
	}

	// maintain is what the once-a-minute tick runs; calling it directly is what lets the
	// test see a minute's worth of housekeeping without waiting one.
	h.maintain()

	got := h.events.all()
	if len(got) != 1 {
		t.Fatalf("the ring holds %d events, want the one report about the drops", len(got))
	}
	if got[0].Code != CodeTelemetryDropped {
		t.Fatalf("the recorded event is %q, want %q", got[0].Code, CodeTelemetryDropped)
	}
	if got[0].Fields["dropped"] != "3" {
		t.Errorf("the report names %q dropped rows, want 3", got[0].Fields["dropped"])
	}

	// A second pass with nothing new dropped must stay quiet, or the log fills with one
	// report a minute forever after a single burst.
	h.maintain()
	if got := h.events.all(); len(got) != 1 {
		t.Errorf("a second housekeeping pass re-reported the same drops: %d events", len(got))
	}
}

// Retention is what keeps a long-running agent's log inside its window. The pass has to
// say what it removed: a log that quietly shortened itself would read as a machine that
// had been idle.
func TestEventsOlderThanTheRetentionWindowAreRemovedAndTheRemovalIsRecorded(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true, EventRetention: time.Hour}, &now)

	h.store(Event{Seq: 1, At: now.Add(-2 * time.Hour), Code: CodeAppStart})
	h.store(Event{Seq: 2, At: now.Add(-30 * time.Minute), Code: CodeAppStart})
	h.maintain()

	got := h.events.all()
	if len(got) != 2 {
		t.Fatalf("the ring holds %d events, want the recent one plus the report", len(got))
	}
	if got[0].Seq != 2 {
		t.Errorf("the surviving event is seq %d, want the one inside the window", got[0].Seq)
	}
	if got[1].Code != CodeTelemetryTrimmed {
		t.Fatalf("the removal was not recorded, the second event is %q", got[1].Code)
	}
	if got[1].Fields["removed"] != "1" {
		t.Errorf("the report names %q removed, want 1", got[1].Fields["removed"])
	}
}

// A retention setting of zero means "use the default" everywhere else in this app's
// settings, so a hub configured with zero must not treat every row as already expired.
func TestARetentionWindowOfZeroFallsBackToTheDefaultRatherThanExpiringEverything(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)

	h.store(Event{Seq: 1, At: now.Add(-24 * time.Hour), Code: CodeAppStart})
	h.maintain()

	if got := h.events.all(); len(got) != 1 {
		t.Fatalf("a day-old event was removed under the default window: %d events left", len(got))
	}
	if got := h.Config().retention(); got != DefaultEventRetention {
		t.Errorf("the applied window is %v, want the default %v", got, DefaultEventRetention)
	}
}

// Turning the switch off has to clear what was recorded. A switch that stopped collection
// but kept the collection would leave a user who opted out with a log they can still be
// asked for, and the label on the switch would not be true.
func TestTurningRecordingOffClearsWhatWasAlreadyRecorded(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)
	runHub(t, h)

	h.RecordEvent(CodeAppStart, "app-tail started.", nil)
	h.Stop()
	if len(h.events.all()) != 1 {
		t.Fatal("nothing was recorded, so the test cannot show it being cleared")
	}

	h.SetConfig(Config{})
	if got := h.events.all(); len(got) != 0 {
		t.Errorf("switching recording off left %d events behind", len(got))
	}
}

// Turning it on when it was already on must not clear the log: a settings save that
// changed the retention days would otherwise throw away the history the user is looking
// at, with nothing on screen saying why it went.
func TestASettingsSaveThatLeavesRecordingOnKeepsTheHistory(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)
	h.store(Event{Seq: 1, At: now, Code: CodeAppStart})

	h.SetConfig(Config{Enabled: true, EventRetention: 7 * 24 * time.Hour})

	if got := h.events.all(); len(got) != 1 {
		t.Errorf("a save that kept recording on cleared the log: %d events left", len(got))
	}
}

// Exactly one goroutine owns the rings. A second Run would give two goroutines what this
// design says one owns, which the race detector would only catch on the run that happened
// to interleave.
func TestASecondRunDoesNothingRatherThanRacingTheFirstForTheRings(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)
	runHub(t, h)

	// The second call only means anything once the first has taken ownership, and
	// starting a goroutine is not the same moment as entering it.
	deadline := time.Now().Add(5 * time.Second)
	for !h.started.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the first Run never took ownership of the rings")
		}
		time.Sleep(time.Millisecond)
	}

	// Returns immediately rather than blocking, which is the observable difference.
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Run(t.Context())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a second Run took ownership instead of standing down")
	}
}

// Stop is a real barrier so shutdown can record app.stop and know it was kept. It is also
// called from a shutdown path that may run before Run ever started, and from more than one
// place, so neither may block or panic.
func TestStopIsSafeBeforeRunAndOnASecondCall(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := testHub(t, Config{Enabled: true}, &now)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Stop()
		h.Stop()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked on a hub that was never run")
	}
}

// Every call site holds the hub through the agent, and an agent built without telemetry
// hands them nil. A nil hub has to behave like a switched-off one so no call site needs a
// guard of its own -- the guards are what get forgotten.
func TestANilHubAcceptsEveryCallAndRecordsNothing(t *testing.T) {
	var h *Hub

	h.RecordEvent(CodeAppStart, "app-tail started.", nil)
	h.SetConfig(Config{Enabled: true})
	h.Run(t.Context())
	h.Stop()

	if got := h.Config(); got.Enabled {
		t.Error("a nil hub reported itself as recording")
	}
	if got := h.Dropped(); got != 0 {
		t.Errorf("a nil hub reported %d dropped rows", got)
	}
	if got := h.Stats(); got != (Stats{}) {
		t.Errorf("a nil hub reported %+v, want the zero value", got)
	}
	if _, err := h.Events(t.Context(), EventQuery{}); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("reading a nil hub returned %v, want ErrNotEnabled", err)
	}
}
