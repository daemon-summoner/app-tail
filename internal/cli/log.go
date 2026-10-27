// SPDX-License-Identifier: MIT

package cli

// Reading back what the agent did.
//
// The agent records an event for everything it decides -- a connection started, a profile
// switched, a setting written, a failure it carried on from -- and until this command there
// was nowhere to read one. That is the gap this closes: a machine running headless, or one
// whose owner is looking at a menu bar rather than a browser, had a full log and no reader.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// followInterval is how often --follow asks for anything new. It matches the dashboard's
// own cadence: the log is a record of decisions rather than a packet trace, and asking
// faster would spend a request per second to print nothing.
const followInterval = 2 * time.Second

// Telemetry reads the state of the logging module.
func (c *Client) Telemetry(ctx context.Context) (httpapi.TelemetryView, error) {
	var out httpapi.TelemetryView
	err := c.do(ctx, http.MethodGet, "/api/telemetry", nil, &out)
	return out, err
}

// TelemetryEvents reads one page of the event log, newest first.
func (c *Client) TelemetryEvents(ctx context.Context, q telemetry.EventQuery) (telemetry.EventPage, error) {
	var out telemetry.EventPage
	err := c.do(ctx, http.MethodGet, "/api/telemetry/events?"+eventQuery(q).Encode(), nil, &out)
	return out, err
}

// eventQuery renders a filter as the query string the agent parses. Every name here is one
// the endpoint reads; a word it does not know is refused there rather than ignored, which is
// what makes a mistyped severity an error instead of a full log presented as a filtered one.
func eventQuery(q telemetry.EventQuery) url.Values {
	values := url.Values{}
	if q.Text != "" {
		values.Set("q", q.Text)
	}
	if q.Cursor != "" {
		values.Set("cursor", q.Cursor)
	}
	if !q.Since.IsZero() {
		values.Set("since", q.Since.Format(time.RFC3339))
	}
	if !q.Until.IsZero() {
		values.Set("until", q.Until.Format(time.RFC3339))
	}
	if q.Limit > 0 {
		values.Set("limit", strconv.Itoa(q.Limit))
	}
	for _, c := range q.Categories {
		values.Add("category", c.String())
	}
	for _, s := range q.Severities {
		values.Add("severity", s.String())
	}
	for _, c := range q.Codes {
		values.Add("code", string(c))
	}
	return values
}

// runLog prints what the agent has been doing.
func runLog(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("log", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	follow := fs.Bool("follow", false, "keep printing rows as the agent records them")
	limit := fs.Int("limit", 50, "how many rows to show, newest last")
	since := fs.Duration("since", 0, "only rows from the last duration, e.g. 30m or 2h")
	grep := fs.String("grep", "", "only rows whose message or fields contain this text")
	categories := fs.String("category", "", "only these categories, comma separated")
	severities := fs.String("severity", "", "only these severities, comma separated")
	codes := fs.String("code", "", "only these event codes, comma separated")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "log"); err != nil {
		return err
	}
	if *follow && *asJSON {
		return usagef("--follow and --json cannot be used together: one is a stream and the other is one document")
	}
	if *limit < 1 || *limit > telemetry.MaxPageRows {
		return usagef("--limit must be 1-%d, got %d", telemetry.MaxPageRows, *limit)
	}

	query := telemetry.EventQuery{Text: *grep, Limit: *limit}
	if *since > 0 {
		query.Since = time.Now().Add(-*since)
	}
	var err error
	if query.Categories, err = parseCategoryList(*categories); err != nil {
		return err
	}
	if query.Severities, err = parseSeverityList(*severities); err != nil {
		return err
	}
	if query.Codes, err = parseCodeList(*codes); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}

	// The module's own state first, because "no rows" and "nothing is being recorded" read
	// identically on screen and mean opposite things: one is a quiet machine and the other
	// is a switch nobody turned on.
	view, err := client.Telemetry(ctx)
	if err != nil {
		return err
	}
	if !view.Enabled {
		return reportLoggingOff(env, view)
	}

	page, err := client.TelemetryEvents(ctx, query)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, page)
	}

	rows := oldestFirst(page.Events)
	fmt.Fprintln(env.Stdout, logHeader())
	for _, e := range rows {
		fmt.Fprintln(env.Stdout, logLine(e))
	}
	if !*follow {
		reportLogTail(env, page, view, rows)
		return nil
	}
	return followLog(ctx, client, env, query, newestOf(rows))
}

// followLog prints rows as they are recorded, until the caller interrupts it.
//
// It asks for the newest page and prints what it has not printed before rather than reading
// forward from a cursor: the cursor pages backwards into history, and a log being written to
// has no cursor for a row that does not exist yet.
func followLog(ctx context.Context, client *Client, env Env, query telemetry.EventQuery, last telemetry.Event) error {
	tick := time.NewTicker(followInterval)
	defer tick.Stop()

	// The window is only ever moved forward, so a long-running follow does not re-scan
	// history it has already shown on every poll.
	query.Cursor = ""
	for {
		select {
		case <-ctx.Done():
			// An interrupted follow is a reader who has finished reading, not a failure.
			return nil
		case <-tick.C:
		}

		if !last.At.IsZero() {
			query.Since = last.At
		}
		page, err := client.TelemetryEvents(ctx, query)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// A page that hit its limit left rows out, and a follow that printed the rest without
		// saying so would present a log with a hole in it as a complete one.
		if page.Total > len(page.Events) {
			fmt.Fprintf(env.Stdout, "... %d rows were recorded faster than this is printing them; "+
				"raise --limit to see them all\n", page.Total-len(page.Events))
		}
		for _, e := range oldestFirst(page.Events) {
			if !recordedAfter(e, last) {
				continue
			}
			fmt.Fprintln(env.Stdout, logLine(e))
			last = e
		}
	}
}

// recordedAfter reports whether e was recorded after last. The sequence number is the half
// that matters: several events land in one clock tick routinely -- a reconcile settles a
// connection, a route and a resolver together -- and comparing timestamps alone would either
// reprint that whole group every poll or drop all but one of it.
func recordedAfter(e, last telemetry.Event) bool {
	if last.At.IsZero() {
		return true
	}
	if e.At.Equal(last.At) {
		return e.Seq > last.Seq
	}
	return e.At.After(last.At)
}

// oldestFirst reverses one page into reading order. The agent answers newest first, which is
// what a screen with a scrollbar wants; a terminal is read downwards, and follow mode appends
// to the bottom, so both have to agree.
func oldestFirst(events []telemetry.Event) []telemetry.Event {
	out := make([]telemetry.Event, len(events))
	copy(out, events)
	sort.SliceStable(out, func(i, j int) bool { return recordedAfter(out[j], out[i]) })
	return out
}

// newestOf is the last row printed, which is where a follow resumes from.
func newestOf(rows []telemetry.Event) telemetry.Event {
	if len(rows) == 0 {
		return telemetry.Event{}
	}
	return rows[len(rows)-1]
}

// logStamp is unambiguous without being long: a log read a week later must not present two
// different days as the same time of day.
const logStamp = "Jan _2 15:04:05"

func logHeader() string {
	return fmt.Sprintf("%-15s  %-8s %-9s %-26s %s", "WHEN", "SEVERITY", "AREA", "EVENT", "WHAT HAPPENED")
}

// logLine renders one row. The time is local because the reader is sitting at the machine
// that recorded it.
func logLine(e telemetry.Event) string {
	line := fmt.Sprintf("%-15s  %-8s %-9s %-26s %s",
		e.At.Local().Format(logStamp), e.Severity.String(), e.Category.String(), e.Code, e.Message)
	if fields := fieldsText(e.Fields); fields != "" {
		line += "  " + fields
	}
	return line
}

// fieldsText renders the values behind the sentence, sorted so two rows of the same kind
// line up rather than printing their fields in whatever order a map handed them over.
func fieldsText(fields map[string]string) string {
	if len(fields) == 0 {
		return ""
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, name+"="+fields[name])
	}
	return "(" + strings.Join(pairs, ", ") + ")"
}

// reportLogTail says what was left out. A page that stops at the limit looks exactly like a
// log that ends there, and a reader who cannot tell will conclude the agent did nothing
// before that point.
func reportLogTail(env Env, page telemetry.EventPage, view httpapi.TelemetryView, rows []telemetry.Event) {
	if len(rows) == 0 {
		fmt.Fprintln(env.Stdout, "\nNothing matched. The agent is recording; either the filters "+
			"exclude everything or nothing has happened yet.")
		return
	}
	if page.Total > len(rows) {
		fmt.Fprintf(env.Stdout, "\nShowing the newest %d of %d matching rows; raise --limit for more.\n",
			len(rows), page.Total)
	}
	if dropped := view.Stats.Dropped; dropped > 0 {
		fmt.Fprintf(env.Stdout, "The log has holes: %d rows were recorded faster than they could be "+
			"stored.\n", dropped)
	}
}

// reportLoggingOff explains an empty log that is empty by choice, and names the switch. The
// switch key is served by the agent rather than written here so a module renamed on that side
// does not leave this command telling people to set a setting that no longer exists.
func reportLoggingOff(env Env, view httpapi.TelemetryView) error {
	reason := view.Reason
	if reason == "" {
		reason = "Recording is off, so nothing is being kept."
	}
	fmt.Fprintln(env.Stdout, reason)
	if view.SwitchKey != "" {
		fmt.Fprintf(env.Stdout, "Turn it on with: app-tail settings set %s true\n", view.SwitchKey)
	}
	return nil
}

func parseCategoryList(raw string) ([]telemetry.Category, error) {
	words := splitFilterList(raw)
	out := make([]telemetry.Category, 0, len(words))
	for _, word := range words {
		category, ok := telemetry.ParseCategory(word)
		if !ok {
			return nil, usagef("no such log area %q; use one of %s", word,
				strings.Join(categoryVocabulary(), ", "))
		}
		out = append(out, category)
	}
	return out, nil
}

func parseSeverityList(raw string) ([]telemetry.Severity, error) {
	words := splitFilterList(raw)
	out := make([]telemetry.Severity, 0, len(words))
	for _, word := range words {
		severity, ok := telemetry.ParseSeverity(word)
		if !ok {
			return nil, usagef("no such log severity %q; use one of %s", word,
				strings.Join(severityVocabulary(), ", "))
		}
		out = append(out, severity)
	}
	return out, nil
}

// parseCodeList refuses a code the agent does not define. A mistyped code that reached the
// agent would be refused there too, but the message here can list what is available.
func parseCodeList(raw string) ([]telemetry.EventCode, error) {
	words := splitFilterList(raw)
	out := make([]telemetry.EventCode, 0, len(words))
	for _, word := range words {
		code := telemetry.EventCode(word)
		if _, _, ok := telemetry.Classify(code); !ok {
			return nil, usagef("no such event code %q; `app-tail log --json` shows the codes in use", word)
		}
		out = append(out, code)
	}
	return out, nil
}

// splitFilterList reads one comma-separated flag value, ignoring the empty entries a
// trailing comma or a doubled one produces.
func splitFilterList(raw string) []string {
	out := make([]string, 0, 4)
	for _, word := range strings.Split(raw, ",") {
		if word = strings.TrimSpace(word); word != "" {
			out = append(out, word)
		}
	}
	return out
}

func categoryVocabulary() []string {
	_, categories, _ := httpapi.TelemetryFilterVocabulary()
	return categories
}

func severityVocabulary() []string {
	_, _, severities := httpapi.TelemetryFilterVocabulary()
	return severities
}
