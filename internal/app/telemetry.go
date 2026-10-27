// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"strconv"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// telemetrySwitchKey is the setting a client is pointed at when it finds recording off.
// It is the registry key rather than a sentence, because the dashboard flips the switch
// with it; the sentence beside it comes from the registry too.
const telemetrySwitchKey = "telemetry.enabled"

// telemetryOffReason is what the dashboard renders on every log screen while recording
// is off. It says what turning it on would cost, because an empty screen with a button
// on it is an invitation, and the honest version of that invitation names the price.
const telemetryOffReason = "Nothing is being recorded. Turn on the log to keep a history " +
	"of what this app does, held in memory on this machine and sent nowhere."

// telemetryConfig is the hub's configuration derived from the settings document. It is
// the one place the two vocabularies meet, so a setting renamed on one side breaks the
// build rather than quietly stopping the other.
func telemetryConfig(s config.Settings) telemetry.Config {
	return telemetry.Config{
		Enabled:        s.TelemetryEnabled,
		EventRetention: time.Duration(s.TelemetryEventRetentionDays) * 24 * time.Hour,
	}
}

// recordEvent is how everything else in this package writes to the log.
//
// It is a method on the agent rather than a call to the hub so that call sites do not
// each have to know whether telemetry is wired, running, or switched off -- the hub
// answers all three the same way, by doing nothing.
func (a *Agent) recordEvent(code telemetry.EventCode, message string, fields map[string]string) {
	a.telemetry.RecordEvent(code, message, fields)
}

// configQuarantineView is the stored document that had to be moved aside, in the shape the
// dashboard reads it. nil in means nil out: the configuration loaded, and there is nothing
// to say.
func configQuarantineView(note *config.Quarantine) *httpapi.ConfigQuarantineView {
	if note == nil {
		return nil
	}
	return &httpapi.ConfigQuarantineView{
		Path:   note.Path,
		Reason: note.Reason,
		At:     note.At.UTC().Format(time.RFC3339),
	}
}

// reportConfigQuarantine says, once per run, that this process is on the defaults because
// the stored configuration could not be used.
//
// Both surfaces are written to deliberately: the structured log is what a person reading
// stderr sees at the moment it happens, and the event log is what is still there an hour
// later when they notice their settings are gone.
func (a *Agent) reportConfigQuarantine() {
	note := a.store.Quarantined()
	if note == nil {
		return
	}
	a.logger.Error("the stored configuration could not be used; app-tail started with the defaults",
		"reason", note.Reason,
		"kept", note.Path)
	a.recordEvent(telemetry.CodeConfigQuarantined,
		"The stored configuration could not be used, so app-tail started with the defaults. "+
			"The document was kept: `app-tail config restore` puts it back once it is fixed.",
		map[string]string{
			"reason": note.Reason,
			"kept":   note.Path,
		})
}

// recordSettingsChange records what a settings write actually moved.
//
// The values recorded are decided by config.SettingsChanged off each setting's kind, so
// a hostname, an auth key or a subnet list is reported as having changed without its
// value being written down. One event per setting rather than one per save: the log is
// filtered by code and read a row at a time, and a save that changed four things is four
// facts.
func (a *Agent) recordSettingsChange(before, after config.Settings) {
	for _, change := range config.SettingsChanged(before, after) {
		fields := map[string]string{"key": change.Key}
		message := change.Label + " changed."
		if change.Redacted {
			fields["value"] = "changed"
		} else {
			fields["from"], fields["to"] = change.From, change.To
			message = change.Label + " changed from " + change.From + " to " + change.To + "."
		}
		a.recordEvent(telemetry.CodeSettingsChanged, message, fields)
	}
}

// recordTunnelsChange records what a write moved on the connections, under the same rule
// and in the same shape as a settings change: a connection is configuration too, and a
// device name or a tag list is the user's there for the reason it was the user's here.
func (a *Agent) recordTunnelsChange(before, after []config.Tunnel) {
	for _, change := range config.TunnelsChanged(before, after) {
		fields := map[string]string{"key": change.Key}
		message := change.Label + " changed."
		if change.Redacted {
			fields["value"] = "changed"
		} else {
			fields["from"], fields["to"] = change.From, change.To
			message = change.Label + " changed from " + change.From + " to " + change.To + "."
		}
		a.recordEvent(telemetry.CodeSettingsChanged, message, fields)
	}
}

// observedState is what the log has already been told about the parts of the agent that
// have no event of their own.
//
// The reconcile is idempotent and runs on every poke, so the states it computes are not
// news -- most passes reach exactly the conclusion the last one did. Comparing against
// this is what turns a repeated conclusion into the one entry that matters: the pass
// where it changed. Everything here is read and written only by the lifecycle goroutine,
// which is also the only caller of noteObservedState.
type observedState struct {
	// valid is false until the first pass, so the initial reading is taken as the
	// baseline rather than reported as a change from nothing.
	valid bool

	nodeState string
	needsAuth bool
	network   config.NetworkMode

	proxyListening string
	routesServing  bool

	dnsApplied     bool
	dnsUnreachable string

	// forwards maps a forward's id to the state it was last seen in. A forward removed
	// from the configuration disappears from the map without an entry, because
	// settings.changed already said the user removed it.
	forwards map[string]string
}

// noteObservedState records everything that changed since the previous reconcile pass.
//
// It is called at the end of applyDesiredState, after every module has been given its
// chance to act, so what it reads is the state the pass actually reached rather than the
// one it was aiming for.
func (a *Agent) noteObservedState() {
	now := a.readObservedState()
	previous := a.observed
	a.observed = now

	// The first pass is the baseline. Reporting it would open every log with a burst of
	// entries saying each module reached the state it starts in, which is noise on top
	// of app.start rather than information.
	if !previous.valid {
		return
	}

	if now.nodeState != previous.nodeState {
		a.recordEvent(telemetry.CodeNodeState, "The tailnet node is now "+now.nodeState+".",
			map[string]string{"state": now.nodeState})
	}
	if now.needsAuth && !previous.needsAuth {
		a.recordEvent(telemetry.CodeNodeAuth,
			"The tailnet node is waiting to be signed in.", nil)
	}
	if now.network != previous.network {
		code, message := telemetry.CodeTunReleased, "The network interface was released."
		if now.network == config.NetworkTUN {
			code = telemetry.CodeTunTakeover
			message = "The network interface is carrying tailnet traffic for this machine."
		}
		a.recordEvent(code, message, map[string]string{"mode": string(now.network)})
	}

	if listening := now.proxyListening; listening != previous.proxyListening {
		if listening == "" {
			a.recordEvent(telemetry.CodeProxyDown, "The tailnet proxy stopped listening.", nil)
		} else {
			a.recordEvent(telemetry.CodeProxyUp, "The tailnet proxy is listening on "+listening+".",
				map[string]string{"address": listening})
		}
	}

	if now.routesServing != previous.routesServing {
		message := "This device stopped carrying subnet routes for the tailnet."
		if now.routesServing {
			message = "This device is carrying subnet routes for the tailnet."
		}
		a.recordEvent(telemetry.CodeRoutesChanged, message,
			map[string]string{"serving": strconv.FormatBool(now.routesServing)})
	}

	if now.dnsApplied != previous.dnsApplied {
		code, message := telemetry.CodeDNSReleased,
			"This machine's own resolver settings were put back."
		if now.dnsApplied {
			code = telemetry.CodeDNSTakeover
			message = "This machine is now resolving names through app-tail."
		}
		a.recordEvent(code, message, nil)
	}
	if now.dnsUnreachable != previous.dnsUnreachable {
		if now.dnsUnreachable == "" {
			a.recordEvent(telemetry.CodeDNSHealth,
				"The chosen resolvers are answering again.",
				map[string]string{"healthy": "true"})
		} else {
			a.recordEvent(telemetry.CodeDNSHealth,
				"The chosen resolvers stopped answering.",
				map[string]string{"healthy": "false", "reason": now.dnsUnreachable})
		}
	}

	a.noteForwardStates(previous.forwards, now.forwards)
}

// noteForwardStates reports each port mapping that started, stopped or failed.
func (a *Agent) noteForwardStates(before, now map[string]string) {
	names := a.forwardNames()
	for id, state := range now {
		if before[id] == state {
			continue
		}
		name := names[id]
		if name == "" {
			name = id
		}
		fields := map[string]string{"forward": id, "name": name, "state": state}
		switch state {
		case forward.StateRunning:
			a.recordEvent(telemetry.CodeForwardUp, "The forward "+name+" is listening.", fields)
		case forward.StateError:
			a.recordEvent(telemetry.CodeForwardError, "The forward "+name+" could not start.", fields)
		default:
			a.recordEvent(telemetry.CodeForwardDown, "The forward "+name+" stopped.", fields)
		}
	}
}

// forwardNames maps each configured forward's id to what the user called it, so an entry
// names the thing rather than an opaque identifier.
func (a *Agent) forwardNames() map[string]string {
	forwards := a.store.Get().Forwards
	names := make(map[string]string, len(forwards))
	for _, f := range forwards {
		names[f.ID] = f.Name
	}
	return names
}

// readObservedState takes one reading of everything noteObservedState compares.
//
// It reads the modules through the agent's fields rather than the locked accessors,
// because its only caller is the lifecycle goroutine -- the same goroutine that installs
// them. Each read is a local lock or an atomic, no tailnet round trip, which is what makes
// it acceptable on a path that runs on every reconcile.
func (a *Agent) readObservedState() observedState {
	out := observedState{valid: true, forwards: map[string]string{}}

	if a.node != nil {
		status := a.node.Status()
		out.nodeState = status.BackendState
		out.needsAuth = status.AuthURL != ""
		out.network = status.Network
	}
	if a.proxies != nil {
		if inst, ok := a.proxies.Get(config.DefaultProxyID); ok {
			out.proxyListening = inst.Status().Listening
		}
	}
	if a.subnets != nil {
		out.routesServing = a.subnets.Status().Serving
	}
	if a.systemDNS != nil {
		snap := a.systemDNS.snapshot()
		out.dnsApplied = snap.applied
		out.dnsUnreachable = snap.unreachable
	}
	if a.manager != nil {
		for _, st := range a.manager.Statuses() {
			out.forwards[st.ID] = st.State
		}
	}
	return out
}

// telemetryAPI presents the hub as the management API's log.
type telemetryAPI struct{ a *Agent }

var _ httpapi.Telemetry = telemetryAPI{}

// TelemetryAPI exposes the recorded history to the management API.
func (a *Agent) TelemetryAPI() httpapi.Telemetry { return telemetryAPI{a: a} }

// View reports whether recording is on and what is held.
func (t telemetryAPI) View(context.Context) httpapi.TelemetryView {
	hub := t.a.telemetry
	codes, categories, severities := httpapi.TelemetryFilterVocabulary()
	view := httpapi.TelemetryView{
		SwitchKey:  telemetrySwitchKey,
		Enabled:    hub.Config().Enabled,
		Codes:      codes,
		Categories: categories,
		Severities: severities,
		Capability: httpapi.Capability{
			Available: true,
			Limits: []string{
				"The log is held in this app's memory, so it starts empty every time " +
					"app-tail is started.",
			},
		},
	}
	if !view.Enabled {
		view.Reason = telemetryOffReason
		return view
	}
	view.Stats = hub.Stats()
	return view
}

// Events answers one page of the log.
func (t telemetryAPI) Events(ctx context.Context, q telemetry.EventQuery) (telemetry.EventPage, error) {
	return t.a.telemetry.Events(ctx, q)
}
