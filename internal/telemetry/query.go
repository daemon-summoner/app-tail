// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MaxPageRows is the largest page any log endpoint will return. It bounds the response
// the dashboard has to render as much as the work the store has to do: a table nobody
// scrolls past the first screen of has no use for ten thousand rows in one answer.
const MaxPageRows = 500

// DefaultPageRows is the page size a caller that names none gets.
const DefaultPageRows = 100

// ErrBadCursor is what an unreadable cursor produces. It is a named error because the
// endpoint turns it into a 400: silently restarting at the first page would hand a
// caller who is halfway through a log the top of it again with no way to tell.
var ErrBadCursor = errors.New("telemetry: cursor is not readable")

// ErrNotEnabled is what every read answers while the module is switched off.
//
// It is an error rather than an empty page because those are different facts, and the
// endpoint above turns it into a plain "not enabled" answer with the switch to turn on
// rather than into a failure. An empty page would tell a user who has recorded nothing
// that nothing happened.
var ErrNotEnabled = errors.New("telemetry: recording is not enabled")

// EventQuery is one page of the event log, as a caller asks for it.
//
// Every filter is a narrowing, and an empty one matches everything. Since and Until
// bound the window; a zero time means unbounded on that side.
type EventQuery struct {
	Since time.Time
	Until time.Time

	// Categories and Severities are OR-ed within themselves and AND-ed with each other,
	// which is how the facet rails on the Logs screen behave.
	Categories []Category
	Severities []Severity
	// Codes narrows to specific things that happened.
	Codes []EventCode
	// Text matches the message or any field value, case-insensitively. It is a
	// substring match rather than a query language: this is a search box.
	Text string

	// Limit is how many rows to return, clamped to MaxPageRows.
	Limit int
	// Cursor resumes after a previous page. Empty starts at the newest row.
	Cursor string
}

// EventPage is one answer. Next is empty when the page reached the end of the log, which
// is what a caller checks rather than comparing len(Events) to the limit -- a page
// exactly the size of the limit may or may not be the last one.
type EventPage struct {
	Events []Event `json:"events"`
	Next   string  `json:"next,omitempty"`
	// Total is how many rows matched the filter before the limit, so a table can say
	// "showing 100 of 2,431" rather than leaving the reader to guess.
	Total int `json:"total"`
}

// cursor is a position in a log ordered newest first. Both halves are needed: a
// timestamp alone cannot resume inside a group of rows recorded in the same instant,
// and resuming at the wrong end of one either repeats rows or skips them.
type cursor struct {
	At  time.Time
	Seq uint64
}

// encode renders a cursor as the opaque string a caller hands back. It is base64 so that
// nothing downstream is tempted to parse it: the shape is this package's business and
// changes when the store behind it does.
func (c cursor) encode() string {
	raw := fmt.Sprintf("%d:%d", c.At.UnixNano(), c.Seq)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor reads one back, refusing anything it did not write.
func decodeCursor(s string) (cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, fmt.Errorf("%w: %w", ErrBadCursor, err)
	}
	nanos, seq, ok := strings.Cut(string(raw), ":")
	if !ok {
		return cursor{}, fmt.Errorf("%w: expected two fields", ErrBadCursor)
	}
	at, err := strconv.ParseInt(nanos, 10, 64)
	if err != nil {
		return cursor{}, fmt.Errorf("%w: %w", ErrBadCursor, err)
	}
	n, err := strconv.ParseUint(seq, 10, 64)
	if err != nil {
		return cursor{}, fmt.Errorf("%w: %w", ErrBadCursor, err)
	}
	return cursor{At: time.Unix(0, at), Seq: n}, nil
}

// before reports whether an event sorts strictly after the cursor in newest-first order,
// which is the same thing as "belongs on a later page".
func (c cursor) before(e Event) bool {
	if e.At.Equal(c.At) {
		return e.Seq < c.Seq
	}
	return e.At.Before(c.At)
}

// limit clamps a requested page size into the range the store will serve.
func (q EventQuery) limit() int {
	switch {
	case q.Limit <= 0:
		return DefaultPageRows
	case q.Limit > MaxPageRows:
		return MaxPageRows
	default:
		return q.Limit
	}
}

// matches applies every filter to one event.
func (q EventQuery) matches(e Event) bool {
	if !q.Since.IsZero() && e.At.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.At.After(q.Until) {
		return false
	}
	if len(q.Categories) > 0 && !containsValue(q.Categories, e.Category) {
		return false
	}
	if len(q.Severities) > 0 && !containsValue(q.Severities, e.Severity) {
		return false
	}
	if len(q.Codes) > 0 && !containsValue(q.Codes, e.Code) {
		return false
	}
	if q.Text != "" && !matchesText(e, q.Text) {
		return false
	}
	return true
}

func containsValue[T comparable](haystack []T, needle T) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// matchesText searches the sentence and the field values, which together are everything
// a reader can see in a row. The code is deliberately not searched: it is offered as its
// own filter, and matching it here would make a search for "dns" also return every event
// whose code merely starts that way.
func matchesText(e Event, text string) bool {
	needle := strings.ToLower(text)
	if strings.Contains(strings.ToLower(e.Message), needle) {
		return true
	}
	for _, v := range e.Fields {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

// Events answers one page of the event log, newest first.
//
// It takes a context because the store behind it will be a database as soon as
// persistence lands, and a read that outlives the request that asked for it is a read
// nobody is waiting on. The memory path checks it once rather than pretending to be
// interruptible.
func (h *Hub) Events(ctx context.Context, q EventQuery) (EventPage, error) {
	if h == nil {
		return EventPage{}, ErrNotEnabled
	}
	if err := ctx.Err(); err != nil {
		return EventPage{}, err
	}
	if !h.cfg.Load().Enabled {
		return EventPage{}, ErrNotEnabled
	}

	var after *cursor
	if q.Cursor != "" {
		c, err := decodeCursor(q.Cursor)
		if err != nil {
			return EventPage{}, err
		}
		after = &c
	}

	rows := h.events.all()

	// Newest first is the order every log screen reads in, and the ring holds oldest
	// first, so the walk runs backwards rather than reversing a slice that is about to
	// be filtered down anyway.
	page := make([]Event, 0, q.limit())
	total := 0
	var next string
	for i := len(rows) - 1; i >= 0; i-- {
		e := rows[i]
		if !q.matches(e) {
			continue
		}
		total++
		if after != nil && !after.before(e) {
			continue
		}
		if len(page) < q.limit() {
			page = append(page, e)
			continue
		}
		// One row past the page: proof there is a next one, and the cursor that
		// resumes at it is the last row actually returned.
		if next == "" {
			last := page[len(page)-1]
			next = cursor{At: last.At, Seq: last.Seq}.encode()
		}
	}
	return EventPage{Events: page, Next: next, Total: total}, nil
}

// Stats is what the telemetry module is currently holding, for the header of the Logs
// screen and for the capability endpoint.
type Stats struct {
	// Events is how many rows the log holds right now; EventsRecorded is how many it has
	// ever taken, including the ones the window has moved past.
	Events         int    `json:"events"`
	EventsRecorded uint64 `json:"eventsRecorded"`
	EventCapacity  int    `json:"eventCapacity"`
	// Dropped is rows the queue refused. Non-zero means the log has holes, and the
	// screen says so rather than leaving the reader to trust a short list.
	Dropped uint64 `json:"dropped"`
	// Oldest is the timestamp of the earliest row still held, zero when there is none.
	// It is how far back the log can actually answer, which is not the same as the
	// retention window it was configured with.
	Oldest time.Time `json:"oldest,omitzero"`
	// RetentionSec is the window in force, so a reader can tell a short log caused by a
	// short window from one caused by a quiet machine.
	RetentionSec int `json:"retentionSec"`
}

// Stats reports what is held. It is cheap enough for a poll: one ring lock and two
// atomic loads.
func (h *Hub) Stats() Stats {
	if h == nil {
		return Stats{}
	}
	cfg := h.cfg.Load()
	added, capacity := h.events.stats()
	rows := h.events.all()
	s := Stats{
		Events:         len(rows),
		EventsRecorded: added,
		EventCapacity:  capacity,
		Dropped:        h.dropped.Load(),
		RetentionSec:   int(cfg.retention().Seconds()),
	}
	if len(rows) > 0 {
		s.Oldest = rows[0].At
	}
	return s
}
