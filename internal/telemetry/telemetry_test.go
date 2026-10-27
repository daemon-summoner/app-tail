// SPDX-License-Identifier: MIT

package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The category and severity words are a wire contract: a dashboard filter sends them back
// as query parameters and a user learns them. A rename that changed only the String side
// would leave every saved filter matching nothing, so both directions are pinned here.
func TestEveryCategoryAndSeverityWordSurvivesARoundTrip(t *testing.T) {
	categories := []Category{
		CategorySystem, CategoryNetwork, CategoryDevice,
		CategoryDNS, CategorySecurity, CategorySettings,
	}
	seen := map[string]bool{}
	for _, want := range categories {
		word := want.String()
		if seen[word] {
			t.Fatalf("two categories both render as %q", word)
		}
		seen[word] = true
		got, ok := ParseCategory(word)
		if !ok || got != want {
			t.Errorf("ParseCategory(%q) = %v, %v; want %v, true", word, got, ok, want)
		}
	}

	severities := []Severity{SeverityInfo, SeverityNotice, SeverityWarning, SeverityError}
	seen = map[string]bool{}
	for _, want := range severities {
		word := want.String()
		if seen[word] {
			t.Fatalf("two severities both render as %q", word)
		}
		seen[word] = true
		got, ok := ParseSeverity(word)
		if !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v, true", word, got, ok, want)
		}
	}
}

// A filter word that is not one of ours has to be refused rather than ignored. A parser
// that answered "system" for an unknown category would turn a typed filter into a silent
// one showing rows the caller did not ask for.
func TestAWordThatIsNotAFacetIsRefusedRatherThanTreatedAsTheFirstOne(t *testing.T) {
	if _, ok := ParseCategory("networking"); ok {
		t.Error("ParseCategory accepted a word that is not a category")
	}
	if _, ok := ParseSeverity("debug"); ok {
		t.Error("ParseSeverity accepted a word that is not a severity")
	}
	if _, ok := ParseCategory(""); ok {
		t.Error("ParseCategory accepted an empty word")
	}
}

// EventCodes is what a client renders its filter list from, so it has to name every code
// the agent can record. A code declared in the catalog but missing from the list would be
// a row nobody can filter to; the sort makes the list stable across runs.
func TestTheOfferedCodeListNamesEveryCodeInTheCatalogInAStableOrder(t *testing.T) {
	codes := EventCodes()
	if len(codes) != len(eventCatalog) {
		t.Fatalf("EventCodes returned %d codes, the catalog holds %d", len(codes), len(eventCatalog))
	}
	for _, code := range codes {
		if _, _, ok := Classify(code); !ok {
			t.Errorf("EventCodes offered %q, which Classify does not know", code)
		}
	}
	for i := 1; i < len(codes); i++ {
		if codes[i-1] >= codes[i] {
			t.Fatalf("EventCodes is not sorted: %q came before %q", codes[i-1], codes[i])
		}
	}
}

// Classify has to report an unknown code as unknown rather than as the zero category,
// because RecordEvent uses that boolean to refuse it. A silent zero would file a
// mistyped code under "system" and corrupt the very list it was meant to describe.
func TestAnUnknownCodeIsReportedAsUnknownRatherThanClassifiedAsSystem(t *testing.T) {
	category, severity, ok := Classify(EventCode("nothing.likethis"))
	if ok {
		t.Fatal("Classify accepted a code that is not in the catalog")
	}
	if category != CategorySystem || severity != SeverityInfo {
		t.Errorf("the refused answer should be the zero value, got %v/%v", category, severity)
	}
}

// The enums are stored as integers and rendered as words. Serialising the integers would
// hand the dashboard 3 where it expects "error", so the custom marshaller is pinned by
// reading the JSON back as a generic map rather than into the typed struct.
func TestAnEventSerialisesItsCategoryAndSeverityAsWordsNotNumbers(t *testing.T) {
	at := time.Date(2026, 8, 23, 10, 30, 0, 0, time.UTC)
	raw, err := json.Marshal(Event{
		Seq: 7, At: at, Code: CodeForwardError,
		Category: CategoryNetwork, Severity: SeverityError,
		Message: "The forward web could not start.",
		Fields:  map[string]string{"forward": "f_a"},
	})
	if err != nil {
		t.Fatalf("marshal the event: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("read the event back: %v", err)
	}
	if got["category"] != "network" {
		t.Errorf("category serialised as %v, want %q", got["category"], "network")
	}
	if got["severity"] != "error" {
		t.Errorf("severity serialised as %v, want %q", got["severity"], "error")
	}
	if got["code"] != "forward.error" {
		t.Errorf("code serialised as %v, want %q", got["code"], "forward.error")
	}
	if got["seq"] != float64(7) {
		t.Errorf("seq serialised as %v, want 7", got["seq"])
	}
}

// The wire shape is a contract in both directions. A word that only ever went out could
// be renamed on the way in without anything noticing, and a category read back as the
// zero value would file the row under the wrong facet rather than fail.
func TestAnEventReadBackFromTheWireCarriesTheSameFacetsItWentOutWith(t *testing.T) {
	want := Event{
		Seq: 4, At: time.Date(2026, 8, 23, 10, 30, 0, 0, time.UTC),
		Code: CodeDNSHealth, Category: CategoryDNS, Severity: SeverityWarning,
		Message: "The chosen resolvers stopped answering.",
		Fields:  map[string]string{"healthy": "false"},
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal the event: %v", err)
	}

	var got Event
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("read the event back: %v", err)
	}
	if got.Category != want.Category || got.Severity != want.Severity {
		t.Errorf("the event came back as %v/%v, want %v/%v",
			got.Category, got.Severity, want.Category, want.Severity)
	}
	if got.Code != want.Code || got.Message != want.Message || got.Seq != want.Seq {
		t.Errorf("the event came back as %+v, want %+v", got, want)
	}
	if !got.At.Equal(want.At) {
		t.Errorf("the event came back stamped %v, want %v", got.At, want.At)
	}
	if got.Fields["healthy"] != "false" {
		t.Errorf("the event came back with fields %v", got.Fields)
	}
}

// A facet word that is not one of ours has to fail the read rather than decode to the
// zero value, which would silently file the row under "system" and "info".
func TestAnEventCarryingAFacetWordWeDoNotKnowFailsToRead(t *testing.T) {
	cases := []string{
		`{"seq":1,"at":"2026-08-23T10:30:00Z","code":"app.start","category":"networking","severity":"info"}`,
		`{"seq":1,"at":"2026-08-23T10:30:00Z","code":"app.start","category":"system","severity":"debug"}`,
	}
	for _, raw := range cases {
		var got Event
		if err := json.Unmarshal([]byte(raw), &got); err == nil {
			t.Errorf("reading %s succeeded, giving %v/%v", raw, got.Category, got.Severity)
		}
	}
}

// An event with no fields must not carry an empty object on the wire, because the
// dashboard renders a fields row whenever the key is present and an empty one reads as
// "this event had details that were lost".
func TestAnEventWithNoFieldsLeavesTheFieldsKeyOffTheWireEntirely(t *testing.T) {
	raw, err := json.Marshal(Event{Seq: 1, At: time.Now(), Code: CodeAppStart,
		Message: "app-tail started."})
	if err != nil {
		t.Fatalf("marshal the event: %v", err)
	}
	if strings.Contains(string(raw), "fields") {
		t.Errorf("an event with no fields still serialised a fields key: %s", raw)
	}
}

// The field map is copied and bounded at record time. Without the copy a call site that
// reuses one map across two events would have the ring holding a value that changes
// underneath a reader, which is a data race the tests would only ever see under -race.
func TestRecordedFieldsAreACopySoALaterEditByTheCallerCannotReachTheLog(t *testing.T) {
	live := map[string]string{"device": "one"}
	kept := truncateFields(live)
	live["device"] = "two"
	if kept["device"] != "one" {
		t.Errorf("the recorded field followed the caller's later edit: got %q", kept["device"])
	}
}

// Both bounds exist so that one call site looping over something unbounded cannot make a
// single event dominate the ring. The cap keeps the first keys in sorted order so which
// ones survive is deterministic rather than map-iteration luck.
func TestAnEventCarryingTooManyOrTooLongFieldsIsCutDownRatherThanKeptWhole(t *testing.T) {
	fields := map[string]string{}
	for i := range maxEventFields + 5 {
		fields[string(rune('a'+i))] = "short"
	}
	fields["a"] = strings.Repeat("x", maxFieldValueLen+50)

	got := truncateFields(fields)
	if len(got) != maxEventFields {
		t.Errorf("kept %d fields, want the cap of %d", len(got), maxEventFields)
	}
	value, ok := got["a"]
	if !ok {
		t.Fatal("the first key in sorted order was dropped, so the cap is not deterministic")
	}
	if len([]rune(value)) != maxFieldValueLen+1 {
		t.Errorf("an over-long value was kept at %d runes, want %d plus the marker",
			len([]rune(value)), maxFieldValueLen)
	}
	if !strings.HasSuffix(value, "…") {
		t.Error("a truncated value does not say it was truncated")
	}
}

// An absent field map is a different thing from an empty one only at the call site: both
// have to come out as nil, because a non-nil empty map serialises and a nil one does not.
func TestAnAbsentOrEmptyFieldMapBecomesNilRatherThanAnEmptyMap(t *testing.T) {
	if got := truncateFields(nil); got != nil {
		t.Errorf("a nil field map became %v", got)
	}
	if got := truncateFields(map[string]string{}); got != nil {
		t.Errorf("an empty field map became %v", got)
	}
}
