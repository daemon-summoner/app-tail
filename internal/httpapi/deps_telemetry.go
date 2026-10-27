// SPDX-License-Identifier: MIT

package httpapi

import (
	"context"

	"github.com/sellitus/app-tail/internal/telemetry"
)

// Telemetry is the recorded history of what the agent did, as the API needs it.
//
// Both methods take a context because the store behind them becomes a database as soon
// as persistence is switched on, and a read nobody is waiting on should not outlive the
// request that asked for it.
type Telemetry interface {
	// View reports whether recording is on, what is held, and the vocabulary a client
	// builds its filters from.
	View(ctx context.Context) TelemetryView
	// Events answers one page of the log, newest first. It returns
	// telemetry.ErrNotEnabled while the module is off, which the handler turns into a
	// plain "not enabled" answer rather than a failure.
	Events(ctx context.Context, q telemetry.EventQuery) (telemetry.EventPage, error)
}

// TelemetryView is the state of the logging module.
//
// SwitchKey names the setting that turns recording on, so a client that finds recording
// off can offer the control that fixes it without knowing anything module-specific --
// the same contract ModuleInfo.SwitchKey carries for every other optional module.
type TelemetryView struct {
	Enabled   bool   `json:"enabled"`
	SwitchKey string `json:"switchKey"`
	// Reason says why nothing is being recorded, in the words the dashboard renders
	// verbatim. Empty while recording is on.
	Reason string `json:"reason,omitempty"`
	// Stats is what is held right now. It is the zero value while recording is off,
	// which is what is actually true then: nothing is held.
	Stats telemetry.Stats `json:"stats"`
	// Codes, Categories and Severities are the whole filter vocabulary, served rather
	// than hard-coded in the client so a code added here appears in the facet rail
	// without a second edit.
	Codes      []string   `json:"codes"`
	Categories []string   `json:"categories"`
	Severities []string   `json:"severities"`
	Capability Capability `json:"capability"`
}

// TelemetryFilterVocabulary is the set of words every telemetry filter accepts. It is
// built from the catalog rather than authored twice, so a client rendering these choices
// is offering exactly what the agent will match on.
func TelemetryFilterVocabulary() (codes, categories, severities []string) {
	for _, c := range telemetry.EventCodes() {
		codes = append(codes, string(c))
	}
	for _, c := range []telemetry.Category{
		telemetry.CategorySystem, telemetry.CategoryNetwork, telemetry.CategoryDevice,
		telemetry.CategoryDNS, telemetry.CategorySecurity, telemetry.CategorySettings,
	} {
		categories = append(categories, c.String())
	}
	for _, s := range []telemetry.Severity{
		telemetry.SeverityInfo, telemetry.SeverityNotice,
		telemetry.SeverityWarning, telemetry.SeverityError,
	} {
		severities = append(severities, s.String())
	}
	return codes, categories, severities
}
