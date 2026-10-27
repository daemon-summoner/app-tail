// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// logOf builds a hub holding the given events, in the order given, without going through
// the queue -- the ordering these tests are about is the read side's.
func logOf(t *testing.T, events ...Event) *Hub {
	t.Helper()
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	h := New(Options{Config: Config{Enabled: true}, Now: func() time.Time { return at }})
	for _, e := range events {
		h.store(e)
	}
	return h
}

// event is one row for the tests below, stamped a fixed number of minutes into a fixed
// day so an ordering assertion reads as a sequence rather than as arithmetic.
func event(minute int, code EventCode, message string, fields map[string]string) Event {
	spec := eventCatalog[code]
	return Event{
		Seq:      uint64(minute),
		At:       time.Date(2026, 8, 23, 12, minute, 0, 0, time.UTC),
		Code:     code,
		Category: spec.Category,
		Severity: spec.Severity,
		Message:  message,
		Fields:   fields,
	}
}

// Every log screen reads newest first, and the ring holds oldest first. Serving the ring's
// own order would put the row a user came to see at the bottom of the last page.
func TestTheEventLogIsAnsweredNewestFirst(t *testing.T) {
	h := logOf(t,
		event(1, CodeAppStart, "app-tail started.", nil),
		event(2, CodeProxyUp, "The tailnet proxy is listening on 127.0.0.1:1080.", nil),
		event(3, CodeAppStop, "app-tail is stopping.", nil),
	)

	page, err := h.Events(t.Context(), EventQuery{})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 3 {
		t.Fatalf("the page holds %d events, want 3", len(page.Events))
	}
	if page.Events[0].Code != CodeAppStop || page.Events[2].Code != CodeAppStart {
		t.Errorf("the page is not newest first: %q then %q",
			page.Events[0].Code, page.Events[2].Code)
	}
}

// The facet rails on the Logs screen OR within a facet and AND between facets, so a reader
// picking two categories and one severity gets rows in either category that also carry
// that severity. A filter that AND-ed within a facet would answer nothing.
func TestFacetsWidenWithinThemselvesAndNarrowAgainstEachOther(t *testing.T) {
	h := logOf(t,
		event(1, CodeAppStart, "app-tail started.", nil),
		event(2, CodeForwardError, "The forward web could not start.", nil),
		event(3, CodeNodeAuth, "The tailnet node is waiting to be signed in.", nil),
		event(4, CodeProxyUp, "The tailnet proxy is listening.", nil),
	)

	page, err := h.Events(t.Context(), EventQuery{
		Categories: []Category{CategoryNetwork, CategoryDevice},
	})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 3 {
		t.Fatalf("two categories matched %d events, want 3", len(page.Events))
	}

	page, err = h.Events(t.Context(), EventQuery{
		Categories: []Category{CategoryNetwork, CategoryDevice},
		Severities: []Severity{SeverityError},
	})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].Code != CodeForwardError {
		t.Errorf("adding a severity gave %d events, want only forward.error", len(page.Events))
	}
}

// The search box searches what a reader can see: the sentence and the field values. It
// deliberately does not search the code, which has its own filter -- searching it would
// make "dns" also return every event whose code merely starts that way.
func TestTheSearchBoxMatchesTheSentenceAndTheFieldsButNotTheCode(t *testing.T) {
	h := logOf(t,
		event(1, CodeForwardUp, "The forward web is listening.", map[string]string{"name": "web"}),
		event(2, CodeDNSHealth, "The chosen resolvers stopped answering.",
			map[string]string{"healthy": "false"}),
		event(3, CodeProxyUp, "The tailnet proxy is listening.", nil),
	)

	page, err := h.Events(t.Context(), EventQuery{Text: "WEB"})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].Code != CodeForwardUp {
		t.Errorf("a case-insensitive search for a field value gave %d events", len(page.Events))
	}

	page, err = h.Events(t.Context(), EventQuery{Text: "dns"})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 0 {
		t.Errorf("searching for %q matched the code rather than the text: %d events",
			"dns", len(page.Events))
	}
}

// The window bounds are inclusive of the events at their edges, and both sides are
// optional. A reader dragging a range over a chart expects the row at the boundary to be
// in the selection rather than just outside it.
func TestTheTimeWindowKeepsTheEventsOnItsBoundaries(t *testing.T) {
	h := logOf(t,
		event(1, CodeAppStart, "app-tail started.", nil),
		event(2, CodeProxyUp, "The tailnet proxy is listening.", nil),
		event(3, CodeAppStop, "app-tail is stopping.", nil),
	)

	page, err := h.Events(t.Context(), EventQuery{
		Since: time.Date(2026, 8, 23, 12, 1, 0, 0, time.UTC),
		Until: time.Date(2026, 8, 23, 12, 2, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("the window matched %d events, want the two on its edges", len(page.Events))
	}
	if page.Events[0].Seq != 2 || page.Events[1].Seq != 1 {
		t.Errorf("the window returned seqs %d and %d, want 2 then 1",
			page.Events[0].Seq, page.Events[1].Seq)
	}
}

// Paging is keyset rather than offset, because the log is being written to while it is
// read. Every row has to appear exactly once across the pages: an offset would skip and
// duplicate rows as the log grows underneath the reader.
func TestPagingThroughTheLogReturnsEveryRowExactlyOnce(t *testing.T) {
	var events []Event
	for i := 1; i <= 7; i++ {
		events = append(events, event(i, CodeAppStart, "app-tail started.", nil))
	}
	h := logOf(t, events...)

	seen := map[uint64]int{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("paging did not terminate")
		}
		page, err := h.Events(t.Context(), EventQuery{Limit: 3, Cursor: cursor})
		if err != nil {
			t.Fatalf("read page %d: %v", pages, err)
		}
		for _, e := range page.Events {
			seen[e.Seq]++
		}
		if page.Total != 7 {
			t.Errorf("page %d reported a total of %d, want the 7 rows that matched",
				pages, page.Total)
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}

	if len(seen) != 7 {
		t.Fatalf("paging returned %d distinct rows, want 7", len(seen))
	}
	for seq, count := range seen {
		if count != 1 {
			t.Errorf("row %d was returned %d times", seq, count)
		}
	}
}

// A page exactly the size of the limit may or may not be the last one, so the answer says
// so explicitly. A client comparing len(events) to the limit would ask for one page too
// many, or stop one page too early.
func TestALogThatEndsExactlyOnAPageBoundarySaysThereIsNoNextPage(t *testing.T) {
	h := logOf(t,
		event(1, CodeAppStart, "app-tail started.", nil),
		event(2, CodeAppStop, "app-tail is stopping.", nil),
	)

	page, err := h.Events(t.Context(), EventQuery{Limit: 2})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("the page holds %d events, want 2", len(page.Events))
	}
	if page.Next != "" {
		t.Errorf("a page that reached the end offered a cursor of %q", page.Next)
	}
}

// A cursor this package did not write cannot be honoured. Silently restarting at the first
// page would hand a caller halfway through a security-adjacent log the top of it again,
// with nothing saying the position was lost.
func TestACursorThatCannotBeReadIsRefusedRatherThanRestartingAtTheTop(t *testing.T) {
	h := logOf(t, event(1, CodeAppStart, "app-tail started.", nil))

	for _, bad := range []string{"not base64!!", "", "____"} {
		if bad == "" {
			// An empty cursor is the documented way to ask for the first page.
			continue
		}
		_, err := h.Events(t.Context(), EventQuery{Cursor: bad})
		if !errors.Is(err, ErrBadCursor) {
			t.Errorf("cursor %q returned %v, want ErrBadCursor", bad, err)
		}
	}
}

// The page size is clamped on both sides: a caller naming none gets a usable default, and
// one naming ten thousand gets the cap rather than a response the dashboard has to render
// in one go.
func TestThePageSizeIsClampedIntoTheRangeTheStoreWillServe(t *testing.T) {
	cases := []struct {
		asked int
		want  int
	}{
		{asked: 0, want: DefaultPageRows},
		{asked: -5, want: DefaultPageRows},
		{asked: 10, want: 10},
		{asked: MaxPageRows + 1000, want: MaxPageRows},
	}
	for _, c := range cases {
		if got := (EventQuery{Limit: c.asked}).limit(); got != c.want {
			t.Errorf("a limit of %d resolved to %d, want %d", c.asked, got, c.want)
		}
	}
}

// The total is what lets a table say "showing 100 of 2,431" rather than leaving the reader
// to guess, so it counts everything the filter matched rather than everything on the page.
func TestTheTotalCountsEverythingTheFilterMatchedNotJustThePage(t *testing.T) {
	var events []Event
	for i := 1; i <= 5; i++ {
		events = append(events, event(i, CodeAppStart, "app-tail started.", nil))
	}
	events = append(events, event(6, CodeForwardError, "The forward web could not start.", nil))
	h := logOf(t, events...)

	page, err := h.Events(t.Context(), EventQuery{Codes: []EventCode{CodeAppStart}, Limit: 2})
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("the page holds %d events, want the limit of 2", len(page.Events))
	}
	if page.Total != 5 {
		t.Errorf("the page reports a total of %d, want the 5 rows that matched", page.Total)
	}
}

// The read takes a context because a database sits behind this interface as soon as
// persistence lands. A read that outlived the request that asked for it is a read nobody
// is waiting on, so a cancelled one stops rather than answering.
func TestAReadWhoseCallerHasGoneAwayStopsRatherThanAnswering(t *testing.T) {
	h := logOf(t, event(1, CodeAppStart, "app-tail started.", nil))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := h.Events(ctx, EventQuery{}); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled read returned %v, want context.Canceled", err)
	}
}

// The header of the Logs screen reports what is actually held, which is not the same as
// what the window was configured to hold: a short log on a quiet machine and a short log
// caused by a short window look identical without both numbers.
func TestTheStatsReportWhatIsHeldAndHowFarBackItGoes(t *testing.T) {
	h := logOf(t,
		event(1, CodeAppStart, "app-tail started.", nil),
		event(2, CodeAppStop, "app-tail is stopping.", nil),
	)
	h.SetConfig(Config{Enabled: true, EventRetention: 2 * time.Hour})

	got := h.Stats()
	if got.Events != 2 {
		t.Errorf("the log reports %d events held, want 2", got.Events)
	}
	if got.EventsRecorded != 2 {
		t.Errorf("the log reports %d events ever recorded, want 2", got.EventsRecorded)
	}
	if got.EventCapacity != eventRingSize {
		t.Errorf("the log reports a capacity of %d, want %d", got.EventCapacity, eventRingSize)
	}
	if want := time.Date(2026, 8, 23, 12, 1, 0, 0, time.UTC); !got.Oldest.Equal(want) {
		t.Errorf("the oldest row is reported as %v, want %v", got.Oldest, want)
	}
	if got.RetentionSec != int((2 * time.Hour).Seconds()) {
		t.Errorf("the window in force is reported as %ds, want 7200", got.RetentionSec)
	}
}

// An empty log has no oldest row, and reporting one would put a 1970 timestamp on the
// screen of every fresh install that just switched recording on.
func TestAnEmptyLogReportsNoOldestRowRatherThanTheZeroTime(t *testing.T) {
	h := logOf(t)
	if got := h.Stats(); !got.Oldest.IsZero() {
		t.Errorf("an empty log reports its oldest row as %v", got.Oldest)
	}
}
