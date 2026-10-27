// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/telemetry"
)

// The filter vocabulary is served rather than hard-coded in the client, so a code added
// to the catalog shows up in the facet rail without a second edit. A view that served
// only some of it would leave rows nobody can filter to.
func TestTheLogViewServesTheWholeFilterVocabularyAndTheSwitchThatTurnsItOn(t *testing.T) {
	h := newHarness(t)

	view := decode[TelemetryView](t, h.do(t, http.MethodGet, "/api/telemetry", nil))

	if !view.Enabled {
		t.Error("the view reports recording off, but the harness has it on")
	}
	if view.SwitchKey != "telemetry.enabled" {
		t.Errorf("switchKey = %q, want the setting that turns recording on", view.SwitchKey)
	}
	codes, categories, severities := TelemetryFilterVocabulary()
	if !slices.Equal(view.Codes, codes) {
		t.Errorf("the view offers %d codes, the catalog holds %d", len(view.Codes), len(codes))
	}
	if !slices.Equal(view.Categories, categories) {
		t.Errorf("categories = %v, want %v", view.Categories, categories)
	}
	if !slices.Equal(view.Severities, severities) {
		t.Errorf("severities = %v, want %v", view.Severities, severities)
	}
	if view.Stats.EventCapacity == 0 {
		t.Error("the view reports no capacity, so a client cannot say how much history it holds")
	}
}

// A memory-only log starts empty on every run, and a dashboard that did not say so would
// read as a log that lost its history. The limit travels on the capability, which is the
// field every other optional module already uses for exactly this.
func TestTheLogViewSaysWhatTheMemoryOnlyStoreCannotDo(t *testing.T) {
	h := newHarness(t)

	view := decode[TelemetryView](t, h.do(t, http.MethodGet, "/api/telemetry", nil))

	if !view.Capability.Available {
		t.Fatal("the log reports itself unavailable while it is switched on")
	}
	if len(view.Capability.Limits) == 0 {
		t.Error("no limit is stated, so a log that empties on restart looks like one that lost rows")
	}
}

// The log answers newest first with the events as the dashboard renders them, including
// the fields behind each sentence. Dropping the fields would leave a table with nothing
// to filter or sort on beyond the message text.
func TestTheEventEndpointServesThePageWithItsFieldsIntact(t *testing.T) {
	h := newHarness(t)

	page := decode[telemetry.EventPage](t, h.do(t, http.MethodGet, "/api/telemetry/events", nil))

	if len(page.Events) != 2 {
		t.Fatalf("the page holds %d events, want 2", len(page.Events))
	}
	if page.Events[0].Code != telemetry.CodeProxyUp {
		t.Errorf("the first event is %q, want the newest one", page.Events[0].Code)
	}
	if page.Events[0].Fields["address"] != "127.0.0.1:1080" {
		t.Errorf("the event lost its fields: %v", page.Events[0].Fields)
	}
	if page.Total != 2 {
		t.Errorf("total = %d, want the number of rows that matched", page.Total)
	}
}

// The wire shape of an event is what the dashboard's generated types are written against.
// Serialising the enums as the integers they are stored as would hand a client 3 where it
// expects "error", which typechecks on both sides and renders as nothing.
func TestAnEventReachesTheClientWithItsCategoryAndSeverityAsWords(t *testing.T) {
	h := newHarness(t)

	body := decode[struct {
		Events []map[string]any `json:"events"`
	}](t, h.do(t, http.MethodGet, "/api/telemetry/events", nil))

	if len(body.Events) == 0 {
		t.Fatal("no events were served")
	}
	first := body.Events[0]
	if first["category"] != "network" {
		t.Errorf("category = %v, want %q", first["category"], "network")
	}
	if first["severity"] != "info" {
		t.Errorf("severity = %v, want %q", first["severity"], "info")
	}
}

// Every filter in the query string has to reach the store as the filter it names. One
// that was parsed and dropped would show a reader the full log while the rail says it is
// filtered, which is the kind of wrong answer nobody double-checks.
func TestEveryFilterInTheQueryStringReachesTheLog(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet,
		"/api/telemetry/events?category=network&category=dns&severity=error&code=forward.error"+
			"&q=web&limit=25&since=2026-08-23T12:00:00Z&until=2026-08-23T13:00:00Z", nil)
	requireStatus(t, rec, http.StatusOK)

	asked := h.telemetry.asked
	if !slices.Equal(asked.Categories, []telemetry.Category{telemetry.CategoryNetwork, telemetry.CategoryDNS}) {
		t.Errorf("categories reached the log as %v, want network then dns", asked.Categories)
	}
	if !slices.Equal(asked.Severities, []telemetry.Severity{telemetry.SeverityError}) {
		t.Errorf("severities reached the log as %v, want error", asked.Severities)
	}
	if !slices.Equal(asked.Codes, []telemetry.EventCode{telemetry.CodeForwardError}) {
		t.Errorf("codes reached the log as %v, want forward.error", asked.Codes)
	}
	if asked.Text != "web" {
		t.Errorf("the search text reached the log as %q, want %q", asked.Text, "web")
	}
	if asked.Limit != 25 {
		t.Errorf("the limit reached the log as %d, want 25", asked.Limit)
	}
	if want := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC); !asked.Since.Equal(want) {
		t.Errorf("since reached the log as %v, want %v", asked.Since, want)
	}
	if want := time.Date(2026, 8, 23, 13, 0, 0, 0, time.UTC); !asked.Until.Equal(want) {
		t.Errorf("until reached the log as %v, want %v", asked.Until, want)
	}
}

// A word the log cannot match on is refused rather than ignored. A mistyped severity that
// silently matched everything would show a full log to a reader who believes it is the
// filtered one.
func TestAFilterWordTheLogDoesNotKnowIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		target string
		names  string
	}{
		{"category", "/api/telemetry/events?category=networking", "networking"},
		{"severity", "/api/telemetry/events?severity=debug", "debug"},
		{"code", "/api/telemetry/events?code=forward.exploded", "forward.exploded"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)

			rec := h.do(t, http.MethodGet, c.target, nil)
			body := requireError(t, rec, http.StatusBadRequest, c.names)

			if h.telemetry.queries != 0 {
				t.Error("the log was queried with a filter the request should have been refused for")
			}
			if body.Error == "" {
				t.Error("the refusal carried no reason")
			}
		})
	}
}

// The window bounds and the page size are parsed rather than passed through, so a
// malformed one is a 400 with the reason. Coercing them to zero would quietly answer a
// different question than the one asked.
func TestAMalformedWindowOrPageSizeIsRefusedWithTheReason(t *testing.T) {
	cases := []struct {
		name   string
		target string
		names  string
	}{
		{"since", "/api/telemetry/events?since=yesterday", "since"},
		{"until", "/api/telemetry/events?until=12%3A00", "until"},
		{"limit is not a number", "/api/telemetry/events?limit=lots", "limit"},
		{"limit is out of range", "/api/telemetry/events?limit=100000", "limit"},
		{"limit is zero", "/api/telemetry/events?limit=0", "limit"},
		{"the window is empty", "/api/telemetry/events?since=2026-08-23T13:00:00Z&until=2026-08-23T12:00:00Z", "until"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)

			rec := h.do(t, http.MethodGet, c.target, nil)
			requireError(t, rec, http.StatusBadRequest, c.names)

			if h.telemetry.queries != 0 {
				t.Error("the log was queried for a request that should have been refused")
			}
		})
	}
}

// Recording being off is not a fault: a fresh install has it off by choice. Answering an
// error status would put a red banner in front of every new user, so the endpoint answers
// 200 with the reason and the switch that turns it on.
func TestALogThatIsSwitchedOffAnswersWithTheSwitchRatherThanAnError(t *testing.T) {
	h := newHarness(t)
	h.telemetry.err = telemetry.ErrNotEnabled
	h.telemetry.view.Enabled = false
	h.telemetry.view.Reason = "Nothing is being recorded."

	rec := h.do(t, http.MethodGet, "/api/telemetry/events", nil)
	requireStatus(t, rec, http.StatusOK)

	body := decode[struct {
		Enabled   bool   `json:"enabled"`
		Reason    string `json:"reason"`
		SwitchKey string `json:"switchKey"`
	}](t, rec)
	if body.Enabled {
		t.Error("the answer says recording is on while it is off")
	}
	if body.Reason == "" {
		t.Error("the answer gives no reason, so the empty screen reads as a failed read")
	}
	if body.SwitchKey != "telemetry.enabled" {
		t.Errorf("switchKey = %q, want the setting the empty screen offers", body.SwitchKey)
	}
}

// A cursor the store cannot read is a 400 rather than a silent restart. Handing a caller
// halfway through a log the top of it again, with nothing saying the position was lost,
// is a correctness bug in a log people read for security reasons.
func TestACursorTheLogCannotReadIsRefusedRatherThanIgnored(t *testing.T) {
	h := newHarness(t)
	h.telemetry.err = telemetry.ErrBadCursor

	rec := h.do(t, http.MethodGet, "/api/telemetry/events?cursor=nonsense", nil)
	requireError(t, rec, http.StatusBadRequest, "cursor")

	if h.telemetry.asked.Cursor != "nonsense" {
		t.Errorf("the cursor reached the log as %q, want it passed through", h.telemetry.asked.Cursor)
	}
}

// Recording is off on a fresh install, so a client asking with no filters at all is the
// ordinary first request. It has to reach the log as an unfiltered query rather than as
// one narrowed by whatever the parser left behind.
func TestARequestWithNoFiltersReachesTheLogAsAnUnfilteredQuery(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodGet, "/api/telemetry/events", nil), http.StatusOK)

	asked := h.telemetry.asked
	if len(asked.Categories) != 0 || len(asked.Severities) != 0 || len(asked.Codes) != 0 {
		t.Errorf("an unfiltered request reached the log as %+v", asked)
	}
	if asked.Text != "" || asked.Cursor != "" || asked.Limit != 0 {
		t.Errorf("an unfiltered request carried %q/%q/%d", asked.Text, asked.Cursor, asked.Limit)
	}
	if !asked.Since.IsZero() || !asked.Until.IsZero() {
		t.Errorf("an unfiltered request bounded the window at %v..%v", asked.Since, asked.Until)
	}
}
