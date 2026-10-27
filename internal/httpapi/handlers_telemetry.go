// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/sellitus/app-tail/internal/telemetry"
)

func (s *Server) handleGetTelemetry(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Telemetry, "logs"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Telemetry.View(r.Context()))
}

// eventsOffBody is what a client gets while recording is switched off.
//
// It is a 200 rather than an error status because "off" is not a fault: a fresh install
// has every log off, and answering 503 would put a red banner in front of every new user
// for a state they chose. The switch key is carried so the empty screen can offer the
// control that turns recording on.
type eventsOffBody struct {
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason"`
	SwitchKey string `json:"switchKey"`
}

func (s *Server) handleGetTelemetryEvents(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Telemetry, "logs"); err != nil {
		s.writeError(w, r, err)
		return
	}

	query, err := parseEventQuery(r.URL.Query())
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	page, err := s.deps.Telemetry.Events(r.Context(), query)
	switch {
	case errors.Is(err, telemetry.ErrNotEnabled):
		view := s.deps.Telemetry.View(r.Context())
		s.writeJSON(w, http.StatusOK, eventsOffBody{
			Reason:    view.Reason,
			SwitchKey: view.SwitchKey,
		})
		return
	case errors.Is(err, telemetry.ErrBadCursor):
		s.writeError(w, r, badRequest("%v", err))
		return
	case err != nil:
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, page)
}

// parseEventQuery turns the query string into a filter, refusing any word the log cannot
// match on.
//
// Refusing is the point: a mistyped severity that silently matched everything would show
// a reader a full log and let them believe it was the filtered one, which is the kind of
// wrong answer nobody double-checks.
func parseEventQuery(q url.Values) (telemetry.EventQuery, error) {
	out := telemetry.EventQuery{Text: q.Get("q"), Cursor: q.Get("cursor")}

	var err error
	if out.Since, err = parseTimeParam(q, "since"); err != nil {
		return telemetry.EventQuery{}, err
	}
	if out.Until, err = parseTimeParam(q, "until"); err != nil {
		return telemetry.EventQuery{}, err
	}

	if raw := q.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return telemetry.EventQuery{}, badRequest("limit must be a number, got %q", raw)
		}
		if limit < 1 || limit > telemetry.MaxPageRows {
			return telemetry.EventQuery{}, badRequest("limit must be 1-%d, got %d",
				telemetry.MaxPageRows, limit)
		}
		out.Limit = limit
	}

	for _, raw := range q["category"] {
		category, ok := telemetry.ParseCategory(raw)
		if !ok {
			return telemetry.EventQuery{}, badRequest("no such log category: %q", raw)
		}
		out.Categories = append(out.Categories, category)
	}
	for _, raw := range q["severity"] {
		severity, ok := telemetry.ParseSeverity(raw)
		if !ok {
			return telemetry.EventQuery{}, badRequest("no such log severity: %q", raw)
		}
		out.Severities = append(out.Severities, severity)
	}
	for _, raw := range q["code"] {
		code := telemetry.EventCode(raw)
		if _, _, ok := telemetry.Classify(code); !ok {
			return telemetry.EventQuery{}, badRequest("no such event code: %q", raw)
		}
		out.Codes = append(out.Codes, code)
	}

	if !out.Since.IsZero() && !out.Until.IsZero() && out.Until.Before(out.Since) {
		return telemetry.EventQuery{}, badRequest("until is before since, so the window is empty")
	}
	return out, nil
}

// parseTimeParam reads one RFC 3339 instant, which is what JavaScript's toISOString
// produces and what every timestamp on the wire here already uses.
func parseTimeParam(q url.Values, name string) (time.Time, error) {
	raw := q.Get(name)
	if raw == "" {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, badRequest("%s must be an RFC 3339 timestamp, got %q", name, raw)
	}
	return at, nil
}
