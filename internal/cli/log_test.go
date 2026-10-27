// SPDX-License-Identifier: MIT

package cli

// What `app-tail log` shows, and what it refuses.
//
// The agent has recorded events since long before anything could read one, so these are
// about the reader: the order it prints in, the difference between a quiet log and a log
// nobody switched on, and whether a filter typed on the command line actually reaches the
// agent rather than being accepted and dropped.

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// logRecordedAt is a fixed instant so a rendered row is the same on every machine.
var logRecordedAt = time.Date(2026, 8, 30, 9, 15, 0, 0, time.UTC)

// telemetryOn is the module reporting that it is recording.
func telemetryOn() httpapi.TelemetryView {
	codes, categories, severities := httpapi.TelemetryFilterVocabulary()
	return httpapi.TelemetryView{
		Enabled: true, SwitchKey: "telemetry",
		Codes: codes, Categories: categories, Severities: severities,
		Stats: telemetry.Stats{Events: 2, EventCapacity: 5000},
	}
}

// logRoutes serves the module state and one fixed page.
func logRoutes(t *testing.T, view httpapi.TelemetryView, page telemetry.EventPage) map[string]http.HandlerFunc {
	t.Helper()
	return map[string]http.HandlerFunc{
		"GET /api/telemetry": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, view)
		},
		"GET /api/telemetry/events": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, page)
		},
	}
}

// A terminal is read downwards and a follow appends to the bottom, so the newest row has to
// be the last line. The agent answers newest first, which is the order a scrolling screen
// wants; printing that straight through would put the newest event above every older one and
// make the same command read in two directions depending on the flag.
func TestTheLogPrintsTheNewestRowLast(t *testing.T) {
	page := telemetry.EventPage{
		Total: 2,
		Events: []telemetry.Event{
			{Seq: 2, At: logRecordedAt.Add(time.Minute), Code: telemetry.CodeConnectionDown,
				Category: telemetry.CategoryNetwork, Severity: telemetry.SeverityNotice,
				Message: "A connection was stopped."},
			{Seq: 1, At: logRecordedAt, Code: telemetry.CodeConnectionUp,
				Category: telemetry.CategoryNetwork, Severity: telemetry.SeverityInfo,
				Message: "A connection was started.", Fields: map[string]string{"connection": "office"}},
		},
	}
	h := newHarness(t, logRoutes(t, telemetryOn(), page))

	if err := h.run("log"); err != nil {
		t.Fatalf("reading the log: %v", err)
	}

	out := h.out()
	up, down := strings.Index(out, "A connection was started."), strings.Index(out, "A connection was stopped.")
	if up < 0 || down < 0 {
		t.Fatalf("the log did not print both rows:\n%s", out)
	}
	if up > down {
		t.Errorf("the newest row is not last:\n%s", out)
	}
	if !strings.Contains(out, "connection=office") {
		t.Errorf("the values behind the sentence were dropped:\n%s", out)
	}
}

// An empty screen means two opposite things: a machine that has done nothing, and a switch
// nobody turned on. A reader told the first when the second is true concludes the app is
// broken and goes looking for a fault that does not exist.
func TestALogNobodyTurnedOnSaysSoAndNamesTheSwitch(t *testing.T) {
	view := httpapi.TelemetryView{
		Enabled:   false,
		SwitchKey: "telemetry",
		Reason:    "Recording is switched off, so nothing is being kept.",
	}
	h := newHarness(t, logRoutes(t, view, telemetry.EventPage{}))

	if err := h.run("log"); err != nil {
		t.Fatalf("reading a log that is switched off: %v", err)
	}

	out := h.out()
	if !strings.Contains(out, "switched off") {
		t.Errorf("the reason recording is off was not reported:\n%s", out)
	}
	if !strings.Contains(out, "settings set telemetry true") {
		t.Errorf("the command that turns recording on was not named:\n%s", out)
	}
	if strings.Contains(out, "Nothing matched") {
		t.Errorf("a log that is off was reported as a log with nothing in it:\n%s", out)
	}
	for _, req := range h.recorded() {
		if strings.HasSuffix(req.Path, "/events") {
			t.Error("the events were read from a module that is not recording any")
		}
	}
}

// A filter accepted on the command line and never sent is the worst outcome available here:
// the reader gets the whole log and believes it is the narrow one they asked for.
func TestEveryFilterReachesTheAgent(t *testing.T) {
	h := newHarness(t, logRoutes(t, telemetryOn(), telemetry.EventPage{}))

	if err := h.run("log", "--severity", "error,warning", "--category", "network",
		"--code", "connection.error", "--grep", "office", "--limit", "5", "--since", "30m"); err != nil {
		t.Fatalf("reading the log with filters: %v", err)
	}

	var query url.Values
	for _, req := range h.recorded() {
		if strings.HasSuffix(req.Path, "/events") {
			query = req.Query
		}
	}
	if query == nil {
		t.Fatal("the log was never read")
	}
	for name, want := range map[string][]string{
		"severity": {"error", "warning"},
		"category": {"network"},
		"code":     {"connection.error"},
		"q":        {"office"},
		"limit":    {"5"},
	} {
		got := query[name]
		if len(got) != len(want) {
			t.Errorf("%s reached the agent as %v, want %v", name, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s reached the agent as %v, want %v", name, got, want)
				break
			}
		}
	}
	since := query.Get("since")
	if since == "" {
		t.Fatal("--since did not reach the agent, so the whole log was read")
	}
	at, err := time.Parse(time.RFC3339, since)
	if err != nil {
		t.Fatalf("since reached the agent as %q, which is not the RFC 3339 it parses: %v", since, err)
	}
	if window := time.Since(at); window < 29*time.Minute || window > 31*time.Minute {
		t.Errorf("--since 30m asked for the last %s", window)
	}
}

// A word the log cannot match on has to stop the command. Sending it and letting the agent
// refuse would work too, but the message here can list what is available -- and a filter
// silently ignored would show a full log as a filtered one.
func TestAWordTheLogCannotMatchOnIsRefusedBeforeAnythingIsRead(t *testing.T) {
	h := newHarness(t, logRoutes(t, telemetryOn(), telemetry.EventPage{}))

	err := h.run("log", "--severity", "catastrophic")

	if err == nil {
		t.Fatal("a severity the log does not have was accepted")
	}
	if !strings.Contains(err.Error(), "catastrophic") {
		t.Errorf("the refusal does not name the word that was wrong: %v", err)
	}
	if !strings.Contains(err.Error(), "error") {
		t.Errorf("the refusal does not list the severities that exist: %v", err)
	}
	if len(h.recorded()) != 0 {
		t.Errorf("a refused filter still made %d requests", len(h.recorded()))
	}
}

// A page that stopped at its limit looks exactly like a log that ends there. Saying nothing
// leaves the reader concluding the agent did nothing before that point.
func TestALogCutShortSaysHowMuchItLeftOut(t *testing.T) {
	page := telemetry.EventPage{
		Total: 431,
		Events: []telemetry.Event{{
			Seq: 431, At: logRecordedAt, Code: telemetry.CodeAppStart,
			Category: telemetry.CategorySystem, Severity: telemetry.SeverityInfo,
			Message: "The agent started.",
		}},
	}
	h := newHarness(t, logRoutes(t, telemetryOn(), page))

	if err := h.run("log", "--limit", "1"); err != nil {
		t.Fatalf("reading the log: %v", err)
	}

	out := h.out()
	if !strings.Contains(out, "431") {
		t.Errorf("the log did not say how many rows matched:\n%s", out)
	}
	if !strings.Contains(out, "--limit") {
		t.Errorf("the log did not say how to see the rest:\n%s", out)
	}
}

// Following polls the newest page, so every poll hands back rows already on screen. Printing
// them again would fill the terminal with the same handful of lines for as long as it runs.
func TestFollowingTheLogPrintsEachRowOnce(t *testing.T) {
	first := telemetry.Event{
		Seq: 1, At: logRecordedAt, Code: telemetry.CodeConnectionUp,
		Category: telemetry.CategoryNetwork, Severity: telemetry.SeverityInfo,
		Message: "A connection was started.",
	}
	// Recorded in the same instant as the first, which is routine: one reconcile settles a
	// connection and its routes together. Only the sequence number tells them apart.
	second := telemetry.Event{
		Seq: 2, At: logRecordedAt, Code: telemetry.CodeRoutesChanged,
		Category: telemetry.CategoryNetwork, Severity: telemetry.SeverityInfo,
		Message: "The routes this device carries changed.",
	}

	polls := make(chan struct{}, 8)
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/telemetry": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, telemetryOn())
		},
		"GET /api/telemetry/events": func(w http.ResponseWriter, _ *http.Request) {
			select {
			case polls <- struct{}{}:
			default:
			}
			// The same two rows every time, which is what the newest page of a quiet log is.
			writeJSONResponse(t, w, http.StatusOK, telemetry.EventPage{
				Total: 2, Events: []telemetry.Event{second, first},
			})
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, []string{"log", "--config", h.configPath, "--follow"}, h.env())
	}()

	// The first read, then two polls: enough that a row printed again would have been
	// printed at least twice more.
	for range 3 {
		select {
		case <-polls:
		case <-time.After(30 * time.Second):
			cancel()
			t.Fatal("the log was not polled while following")
		}
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("following the log: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("following the log did not stop when it was interrupted")
	}

	out := h.out()
	if got := strings.Count(out, "A connection was started."); got != 1 {
		t.Errorf("a row already on screen was printed %d times:\n%s", got, out)
	}
	if got := strings.Count(out, "The routes this device carries changed."); got != 1 {
		t.Errorf("a row already on screen was printed %d times:\n%s", got, out)
	}
}

// --follow and --json describe different things: one never ends and the other is a document.
// Accepting both would produce a stream of JSON documents nothing can parse as one.
func TestFollowingAndJSONCannotBeAskedForTogether(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run(context.Background(), []string{"log", "--follow", "--json"},
		Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})

	if err == nil {
		t.Fatal("--follow --json was accepted")
	}
	if out.Len() != 0 {
		t.Errorf("a refused invocation still printed %q", out.String())
	}
}
