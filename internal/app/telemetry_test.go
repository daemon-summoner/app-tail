// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// recordingHarness is the ordinary agent with the log switched on from the start, which is
// what makes the reconcile's first pass the baseline rather than a burst of entries saying
// every module is in the state it starts in.
func recordingHarness(t *testing.T, seed func(*config.Config)) *harness {
	t.Helper()
	return newHarness(t, func(c *config.Config) {
		c.Settings.TelemetryEnabled = true
		if seed != nil {
			seed(c)
		}
	})
}

// logOf reads the whole log back through the same interface the dashboard uses.
func logOf(h *harness) []telemetry.Event {
	h.t.Helper()
	page, err := h.agent.TelemetryAPI().Events(context.Background(), telemetry.EventQuery{})
	if err != nil {
		h.t.Fatalf("read the event log: %v", err)
	}
	return page.Events
}

// eventsWithCode is every entry carrying one code, so a count assertion says how many
// times something was reported rather than how long the log is.
func eventsWithCode(h *harness, code telemetry.EventCode) []telemetry.Event {
	h.t.Helper()
	var out []telemetry.Event
	for _, e := range logOf(h) {
		if e.Code == code {
			out = append(out, e)
		}
	}
	return out
}

// waitForEvent blocks until the log holds an entry with the given code. The hub drains its
// queue on its own goroutine, so a record is not readable the instant it is made.
func waitForEvent(h *harness, code telemetry.EventCode) telemetry.Event {
	h.t.Helper()
	var found telemetry.Event
	waitFor(h.t, 5*time.Second, "the log to hold a "+string(code)+" entry", func() bool {
		for _, e := range logOf(h) {
			if e.Code == code {
				found = e
				return true
			}
		}
		return false
	})
	return found
}

// Recording is opt-in, and a fresh install has it off. An agent that recorded anyway would
// make the setting a display preference rather than a switch, and the first thing a user
// would find on turning it on is a history they never agreed to keep.
func TestAFreshInstallRecordsNothingUntilTheLogIsSwitchedOn(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	if _, err := h.agent.TelemetryAPI().Events(context.Background(), telemetry.EventQuery{}); !errors.Is(err, telemetry.ErrNotEnabled) {
		t.Fatalf("reading the log of a fresh install returned %v, want ErrNotEnabled", err)
	}

	view := h.agent.TelemetryAPI().View(context.Background())
	if view.Enabled {
		t.Error("a fresh install reports the log as recording")
	}
	if view.Reason == "" {
		t.Error("no reason is given, so an empty log screen reads as a failed read")
	}
	if view.SwitchKey != "telemetry.enabled" {
		t.Errorf("switchKey = %q, want the setting that turns recording on", view.SwitchKey)
	}
	if view.Stats.Events != 0 || view.Stats.EventsRecorded != 0 {
		t.Errorf("a switched-off log reports %+v held, want nothing", view.Stats)
	}
}

// The log's first entry has to be the run starting. Without it every other entry is
// undated relative to the process, and a log that begins in the middle reads as one that
// lost its beginning.
func TestARunThatStartsWithTheLogOnRecordsThatItStarted(t *testing.T) {
	h := recordingHarness(t, nil)
	h.bringUp()

	start := waitForEvent(h, telemetry.CodeAppStart)
	if start.Category != telemetry.CategorySystem {
		t.Errorf("app.start was filed under %v, want system", start.Category)
	}
	if start.Message == "" {
		t.Error("app.start carries no sentence, so the screen has nothing to render")
	}
}

// The reconcile is idempotent and runs on every poke, so most passes reach exactly the
// conclusion the last one did. Recording per pass rather than per change would fill the
// log with one entry a second saying the proxy is still listening.
func TestAModuleComingUpIsRecordedOnceHoweverManyTimesTheReconcileRuns(t *testing.T) {
	h := recordingHarness(t, nil)
	h.bringUp()

	patchSettings(h, map[string]any{
		"proxy.enabled":    true,
		"proxy.listenAddr": "127.0.0.1:0",
	})
	h.agent.reconcileNow(context.Background())

	up := waitForEvent(h, telemetry.CodeProxyUp)
	if up.Fields["address"] == "" {
		t.Error("proxy.up does not say where the proxy is listening")
	}
	if up.Category != telemetry.CategoryNetwork {
		t.Errorf("proxy.up was filed under %v, want network", up.Category)
	}

	// Five more passes over a state nothing changed in.
	for range 5 {
		h.agent.reconcileNow(context.Background())
	}
	if got := eventsWithCode(h, telemetry.CodeProxyUp); len(got) != 1 {
		t.Errorf("the proxy coming up was recorded %d times, want once", len(got))
	}
}

// The other half of the same rule: a module going away is its own entry. A log that
// recorded starts but not stops would show a proxy that has been listening since the
// moment it was turned off.
func TestAModuleGoingAwayIsRecordedAsItsOwnEntry(t *testing.T) {
	h := recordingHarness(t, nil)
	h.bringUp()

	patchSettings(h, map[string]any{
		"proxy.enabled":    true,
		"proxy.listenAddr": "127.0.0.1:0",
	})
	h.agent.reconcileNow(context.Background())
	waitForEvent(h, telemetry.CodeProxyUp)

	patchSettings(h, map[string]any{"proxy.enabled": false})
	h.agent.reconcileNow(context.Background())

	down := waitForEvent(h, telemetry.CodeProxyDown)
	if down.Severity != telemetry.SeverityInfo {
		t.Errorf("proxy.down was filed at %v, want info: a module the user turned off is not a fault",
			down.Severity)
	}
}

// The tailnet node dropping off is the single most common thing a user comes to this log
// to explain, and it is a transition rather than a state: the entry has to say what it
// moved to.
func TestTheTailnetNodeChangingStateIsRecordedWithTheStateItReached(t *testing.T) {
	h := recordingHarness(t, nil)
	h.bringUp()

	h.node.setState(tsnode.StateNeedsLogin)
	h.agent.reconcileNow(context.Background())

	waitFor(h.t, 5*time.Second, "the log to report the node leaving the running state", func() bool {
		for _, e := range eventsWithCode(h, telemetry.CodeNodeState) {
			if e.Fields["state"] == tsnode.StateNeedsLogin {
				return true
			}
		}
		return false
	})
}

// A settings write is recorded one entry per setting, because the log is filtered by code
// and read a row at a time: a save that changed four things is four facts, not one.
func TestASettingsWriteIsRecordedAsOneEntryPerSettingItMoved(t *testing.T) {
	h := recordingHarness(t, nil)
	h.bringUp()

	patchSettings(h, map[string]any{
		"traffic.latency":      true,
		"udpSessionTimeoutSec": 120,
	})

	waitFor(h.t, 5*time.Second, "both settings to be reported", func() bool {
		keys := map[string]bool{}
		for _, e := range eventsWithCode(h, telemetry.CodeSettingsChanged) {
			keys[e.Fields["key"]] = true
		}
		return keys["traffic.latency"] && keys["udpSessionTimeoutSec"]
	})

	for _, e := range eventsWithCode(h, telemetry.CodeSettingsChanged) {
		if e.Fields["key"] != "udpSessionTimeoutSec" {
			continue
		}
		if e.Fields["to"] != "120" {
			t.Errorf("the number's new value was recorded as %q, want 120", e.Fields["to"])
		}
		if e.Severity != telemetry.SeverityNotice {
			t.Errorf("a settings change was filed at %v, want notice", e.Severity)
		}
	}
}

// This is the rule the whole log rests on. A hostname is the user's rather than the app's,
// so the entry says the setting changed and stops there -- and it still has to say that
// much, or a change nobody can see is a change nobody can explain later.
func TestASettingWhoseValueBelongsToTheUserIsRecordedWithoutTheValue(t *testing.T) {
	h := recordingHarness(t, nil)
	h.bringUp()

	patchSettings(h, map[string]any{"hostname": "the-laptop-in-the-study"})

	// Under the connection it renamed: a device name belongs to a connection, and with
	// more than one of them "hostname changed" would not say whose.
	wantKey := "connection." + config.PrimaryTunnelID + ".hostname"
	waitFor(h.t, 5*time.Second, "the hostname change to be reported", func() bool {
		for _, e := range eventsWithCode(h, telemetry.CodeSettingsChanged) {
			if e.Fields["key"] == wantKey {
				return true
			}
		}
		return false
	})

	for _, e := range logOf(h) {
		for name, value := range e.Fields {
			if value == "the-laptop-in-the-study" {
				t.Fatalf("the hostname reached the log in field %q of %q", name, e.Code)
			}
		}
		if strings.Contains(e.Message, "the-laptop-in-the-study") {
			t.Fatalf("the hostname reached the log in the sentence of %q", e.Code)
		}
	}
}

// Turning the switch off clears what was recorded rather than freezing it. A user who
// opts out and is left with the collection has not opted out of anything that matters.
func TestTurningTheLogOffThroughTheAPIClearsWhatWasRecorded(t *testing.T) {
	h := recordingHarness(t, nil)
	h.bringUp()
	waitForEvent(h, telemetry.CodeAppStart)

	patchSettings(h, map[string]any{"telemetry.enabled": false})

	if _, err := h.agent.TelemetryAPI().Events(context.Background(), telemetry.EventQuery{}); !errors.Is(err, telemetry.ErrNotEnabled) {
		t.Fatalf("reading the log after switching it off returned %v, want ErrNotEnabled", err)
	}
	if got := h.agent.TelemetryAPI().View(context.Background()).Stats.Events; got != 0 {
		t.Errorf("switching the log off left %d events held", got)
	}
}

// Turning the switch on has to start recording without a restart, since it is a
// RestartNone setting and the settings screen says so. A hub that only read its
// configuration at construction would leave the user staring at an empty screen.
func TestTurningTheLogOnThroughTheAPIStartsRecordingWithoutARestart(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	patchSettings(h, map[string]any{"telemetry.enabled": true})

	// The write that turned it on is itself a change worth recording, and it is the
	// first thing that happens after the switch flips.
	waitFor(h.t, 5*time.Second, "the log to start holding entries", func() bool {
		page, err := h.agent.TelemetryAPI().Events(context.Background(), telemetry.EventQuery{})
		if err != nil {
			return false
		}
		return len(page.Events) > 0
	})
}

// A run on the defaults because the stored document could not be used looks exactly like a
// first run from every screen: every setting reads as valid, and none of them is what this
// machine was set up with. The log is where that is said out loud.
func TestAConfigThatCouldNotBeUsedIsReportedInTheLog(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, config.ConfigFileName), []byte("{not json"), config.FileMode); err != nil {
		t.Fatal(err)
	}
	h := newHarnessIn(t, stateDir, func(c *config.Config) { c.Settings.TelemetryEnabled = true }, nil)
	h.bringUp()

	event := waitForEvent(h, telemetry.CodeConfigQuarantined)
	if event.Severity != telemetry.SeverityError {
		t.Errorf("config.quarantined was filed as %v, want an error: losing the settings is not routine", event.Severity)
	}
	if !strings.Contains(event.Fields["reason"], "JSON") {
		t.Errorf("reason = %q, want it to say the document could not be read as JSON", event.Fields["reason"])
	}
	kept := event.Fields["kept"]
	if kept == "" {
		t.Fatal("the entry does not say where the document was kept, so nothing can be restored from it")
	}
	held, err := os.ReadFile(kept)
	if err != nil {
		t.Fatalf("read the document the entry points at: %v", err)
	}
	if string(held) != "{not json" {
		t.Errorf("the kept document holds %q, want the document that was replaced", held)
	}
}

// The same fact reaches the dashboard, which polls the status and has no other way to know
// that every value on screen is a default.
func TestTheStatusSaysTheConfigurationWasReplaced(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, config.ConfigFileName), []byte("{not json"), config.FileMode); err != nil {
		t.Fatal(err)
	}
	h := newHarnessIn(t, stateDir, nil, nil)

	status := statusOf(h)
	if status.ConfigQuarantine == nil {
		t.Fatal("the status says nothing about the configuration that had to be replaced")
	}
	if !strings.Contains(status.ConfigQuarantine.Reason, "JSON") {
		t.Errorf("reason = %q, want it to say what was wrong", status.ConfigQuarantine.Reason)
	}
	if status.ConfigQuarantine.Path == "" {
		t.Error("the status does not say where the document was kept")
	}
}

// statusOf reads the status the dashboard polls, decoded.
func statusOf(h *harness) httpapi.StatusView {
	h.t.Helper()
	resp, raw := h.get("/api/status")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /api/status: status %d", resp.StatusCode)
	}
	var status httpapi.StatusView
	if err := json.Unmarshal(raw, &status); err != nil {
		h.t.Fatalf("decode the status: %v", err)
	}
	return status
}

// A configuration that loads must not raise the alarm: a notice on every screen of every
// normal run is a notice nobody reads on the run that matters.
func TestTheStatusIsSilentWhenTheConfigurationLoaded(t *testing.T) {
	h := newHarness(t, nil)

	status := statusOf(h)
	if status.ConfigQuarantine != nil {
		t.Errorf("a configuration that loaded cleanly reported %+v", status.ConfigQuarantine)
	}
}
