// SPDX-License-Identifier: MIT

// Package telemetry records what the agent did and what it carried, so the dashboard
// can answer questions about the past rather than only about this instant.
//
// Every other counter in app-tail is a live reading: the proxy says four gigabytes have
// crossed it, the peer table says a device has sent two, and nothing anywhere says when
// any of it happened or why the node dropped off the tailnet twenty minutes ago. This
// package is where that history lives.
//
// Three rules shape it, and they are the reason it looks the way it does:
//
// Recording is opt-in and off by default. A fresh install records nothing at all, keeps
// no file, and answers every read with "not enabled" rather than an error. Nothing here
// starts until a switch is turned on.
//
// The data path never blocks. A recorder is called from inside a DNS answer, a proxy
// connection close and the lifecycle goroutine, so each Record method does one atomic
// load, one boolean check and one non-blocking send. A queue that is full drops the row
// and counts it. A dropped row is a gap in a log; a blocked send would be a stalled
// connection, and stalling real traffic to keep a graph honest is the wrong trade.
//
// A log that was cut short says so. The drop counter is reported as an event of its own
// once a minute, because a log silently missing rows reads exactly like a quiet machine.
//
// Memory is the default and the floor. Rings are always present, sized so the whole
// package costs a few megabytes with nothing on disk; persistence is a separate switch
// that adds a database beneath the same reads.
package telemetry

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Severity is how much a reader should care about one event.
//
// Four levels rather than slog's five: this is a list a person reads and filters, and a
// debug level would fill it with rows that mean nothing outside a bug report. The
// distinction that earns its place is Notice -- a configuration change is not a fault,
// but it is the first thing to look at when something started behaving differently.
type Severity int

const (
	// SeverityInfo is something that happened in normal running.
	SeverityInfo Severity = iota
	// SeverityNotice is a deliberate change to how the agent is configured.
	SeverityNotice
	// SeverityWarning is degraded but still running: a module that fell back, a
	// resolver that went unhealthy.
	SeverityWarning
	// SeverityError is something that stopped working.
	SeverityError
)

// String renders the severity as the word the API and the dashboard use.
func (s Severity) String() string {
	switch s {
	case SeverityNotice:
		return "notice"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	default:
		return "info"
	}
}

// ParseSeverity resolves a wire value back to a severity. It is how a filter arriving
// as a query parameter is checked, so an unknown word is refused rather than silently
// matching everything.
func ParseSeverity(s string) (Severity, bool) {
	for _, v := range []Severity{SeverityInfo, SeverityNotice, SeverityWarning, SeverityError} {
		if v.String() == s {
			return v, true
		}
	}
	return SeverityInfo, false
}

// Category is which part of the agent an event came from. It is the facet a reader
// filters by first: "show me DNS" is a question about a subsystem, not about a level.
type Category int

const (
	// CategorySystem is the agent's own lifecycle.
	CategorySystem Category = iota
	// CategoryNetwork is what the agent carries: forwards, the proxy, subnet routes.
	CategoryNetwork
	// CategoryDevice is the tailnet node and the devices it talks to.
	CategoryDevice
	// CategoryDNS is name resolution, both the app's own and the machine's.
	CategoryDNS
	// CategorySecurity is tailnet lock and the settings that decide what this device
	// accepts.
	CategorySecurity
	// CategorySettings is a change to the configuration document.
	CategorySettings
)

// String renders the category as the word the API and the dashboard use.
func (c Category) String() string {
	switch c {
	case CategoryNetwork:
		return "network"
	case CategoryDevice:
		return "device"
	case CategoryDNS:
		return "dns"
	case CategorySecurity:
		return "security"
	case CategorySettings:
		return "settings"
	default:
		return "system"
	}
}

// ParseCategory resolves a wire value back to a category, for the same reason
// ParseSeverity exists.
func ParseCategory(s string) (Category, bool) {
	for _, v := range []Category{
		CategorySystem, CategoryNetwork, CategoryDevice,
		CategoryDNS, CategorySecurity, CategorySettings,
	} {
		if v.String() == s {
			return v, true
		}
	}
	return CategorySystem, false
}

// EventCode names one kind of thing that can happen. The set below is a contract: a
// dashboard filters on these strings and a user learns them, so a code is renamed the
// way a wire field is renamed, not the way a log message is edited.
//
// This is deliberately not a tee off the structured logger. A log line's level, wording
// and attributes are debug artefacts that change whenever someone improves a message;
// making them the backing store for a screen people read would mean the screen changes
// with them.
type EventCode string

const (
	// CodeAppStart and its pair bracket a run of the agent process.
	CodeAppStart   EventCode = "app.start"
	CodeAppStop    EventCode = "app.stop"
	CodeAppRestart EventCode = "app.restart"

	// CodeNodeState is a transition of the tailnet node: stopped, starting, running.
	CodeNodeState EventCode = "node.state"
	// CodeNodeAuth is the node asking to be authenticated, which is the state a user
	// has to act on.
	CodeNodeAuth EventCode = "node.auth"
	// CodeNodeRestart is an in-process rebuild of the node.
	CodeNodeRestart EventCode = "node.restart"
	// CodeNodeFallback is the node running on a different network mode than the
	// settings asked for, which is the state that otherwise looks like working.
	CodeNodeFallback EventCode = "node.fallback"

	// CodeConnectionUp and its pair are one private network this app attaches to being
	// started and stopped. They are separate from the node codes, which are about the
	// tailnet this installation is built around: with several networks connected, "the
	// node restarted" no longer says which one.
	CodeConnectionUp   EventCode = "connection.up"
	CodeConnectionDown EventCode = "connection.down"
	// CodeConnectionError is a connection that was meant to be up and could not start.
	CodeConnectionError EventCode = "connection.error"

	// CodeForwardUp and its pair are one port mapping starting and stopping.
	CodeForwardUp    EventCode = "forward.up"
	CodeForwardDown  EventCode = "forward.down"
	CodeForwardError EventCode = "forward.error"

	CodeProxyUp   EventCode = "proxy.up"
	CodeProxyDown EventCode = "proxy.down"

	// CodeTunTakeover and its pair are the network interface appearing and going away.
	CodeTunTakeover EventCode = "tun.takeover"
	CodeTunReleased EventCode = "tun.released"

	// CodeDNSTakeover and its pair are this machine's resolver being claimed and put
	// back. CodeDNSHealth is an upstream resolver failing or recovering.
	CodeDNSTakeover EventCode = "dns.takeover"
	CodeDNSReleased EventCode = "dns.released"
	CodeDNSHealth   EventCode = "dns.health"

	// CodeDNSBlockRefreshed is the blocklists having been compiled, and CodeDNSBlockFailed
	// one of them having failed to download. The pair matters because a list that stopped
	// updating still blocks from its cached copy, which looks exactly like a list that is
	// up to date.
	CodeDNSBlockRefreshed EventCode = "dnsblock.refreshed"
	CodeDNSBlockFailed    EventCode = "dnsblock.failed"

	// CodeIPSDetected is a connection that matched an inspection rule and was carried
	// anyway, and CodeIPSBlocked one that was refused. They are separate codes rather
	// than one code with a field because the two are read for opposite purposes: the
	// first is what a user reviews to decide whether to start refusing, and the second
	// is the first thing to look at when something has stopped working.
	CodeIPSDetected EventCode = "ips.detected"
	CodeIPSBlocked  EventCode = "ips.blocked"
	// CodeIPSCompiled is the inspection rules having been built, which is what says how
	// many entries are actually in force rather than how many were typed.
	CodeIPSCompiled EventCode = "ips.compiled"
	// CodeIPSFailed is the rules having failed to build, so what is in force is whatever
	// was compiled before -- or nothing at all, if this was the first attempt.
	CodeIPSFailed EventCode = "ips.failed"
	// CodeIPSAnomaly is a run of connections that read as a port scan, as fanning out, or
	// as data leaving inside DNS queries. It is a code of its own rather than a detected
	// event with a different signal because it names no rule anyone wrote: it is what the
	// traffic did, and it is read by somebody asking what this machine has been up to
	// rather than by somebody asking which entry stopped a connection.
	CodeIPSAnomaly EventCode = "ips.anomaly"
	// CodeIPSInterceptReady is the root certificate interception presents with having been
	// generated or read back, which is the moment its fingerprint becomes the one to check a
	// trust store against.
	CodeIPSInterceptReady EventCode = "ips.intercept.ready"
	// CodeIPSInterceptFailed is a connection that was going to be opened and was stopped
	// instead, most often because the real server's certificate did not verify.
	//
	// It is an error rather than a warning and it is never quiet: this is the only path in
	// app-tail that can break a working connection while claiming to inspect it, so a person
	// whose software has stopped must be able to find out here rather than by guessing.
	CodeIPSInterceptFailed EventCode = "ips.intercept.failed"

	// CodeExitNodeChanged is this device's traffic starting to leave through a
	// different device.
	CodeExitNodeChanged EventCode = "exitnode.changed"
	// CodeRoutesChanged is the set of subnet routes this device accepts or advertises
	// moving.
	CodeRoutesChanged EventCode = "routes.changed"

	// CodeSettingsChanged is a write to the configuration document. What it records
	// about the value depends on the setting's kind; see config.SettingsChanged.
	CodeSettingsChanged EventCode = "settings.changed"
	// CodeConfigQuarantined is the stored configuration having been moved aside on load
	// because this build could not use it, so this run is on the defaults. It is the one
	// event that explains every other setting reading as something the user never chose.
	CodeConfigQuarantined EventCode = "config.quarantined"
	// CodeDashboardMoved is the dashboard binding an address other than the configured
	// one because that port was taken. The stored address is rewritten to the one it
	// landed on, so without this entry the setting simply reads as something the user
	// never chose.
	CodeDashboardMoved EventCode = "dashboard.moved"

	// CodeTelemetryDropped is this package reporting on itself: rows the queue could
	// not take. Without it a log cut short by a burst reads as a quiet minute.
	CodeTelemetryDropped EventCode = "telemetry.dropped"
	// CodeTelemetryTrimmed is history removed to stay inside its budget.
	CodeTelemetryTrimmed EventCode = "telemetry.trimmed"
)

// codeSpec is the fixed classification of one code. Category and severity belong to the
// code rather than to the call site: two places recording "the node changed state" that
// disagreed about whether it is device or system news would make the dashboard's
// category filter meaningless.
type codeSpec struct {
	Category Category
	Severity Severity
}

// eventCatalog is the whole contract. A code absent from it cannot be recorded --
// RecordEvent refuses it -- so adding a code is a deliberate edit here rather than a
// string typed at a call site.
var eventCatalog = map[EventCode]codeSpec{
	CodeAppStart:   {CategorySystem, SeverityInfo},
	CodeAppStop:    {CategorySystem, SeverityInfo},
	CodeAppRestart: {CategorySystem, SeverityNotice},

	CodeNodeState:    {CategoryDevice, SeverityInfo},
	CodeNodeAuth:     {CategoryDevice, SeverityWarning},
	CodeNodeRestart:  {CategoryDevice, SeverityNotice},
	CodeNodeFallback: {CategoryDevice, SeverityWarning},

	CodeConnectionUp:    {CategoryNetwork, SeverityInfo},
	CodeConnectionDown:  {CategoryNetwork, SeverityInfo},
	CodeConnectionError: {CategoryNetwork, SeverityError},

	CodeForwardUp:    {CategoryNetwork, SeverityInfo},
	CodeForwardDown:  {CategoryNetwork, SeverityInfo},
	CodeForwardError: {CategoryNetwork, SeverityError},

	CodeProxyUp:   {CategoryNetwork, SeverityInfo},
	CodeProxyDown: {CategoryNetwork, SeverityInfo},

	CodeTunTakeover: {CategoryNetwork, SeverityNotice},
	CodeTunReleased: {CategoryNetwork, SeverityNotice},

	CodeDNSTakeover: {CategoryDNS, SeverityNotice},
	CodeDNSReleased: {CategoryDNS, SeverityNotice},
	CodeDNSHealth:   {CategoryDNS, SeverityWarning},

	CodeDNSBlockRefreshed: {CategoryDNS, SeverityInfo},
	CodeDNSBlockFailed:    {CategoryDNS, SeverityWarning},

	CodeIPSDetected: {CategorySecurity, SeverityWarning},
	CodeIPSBlocked:  {CategorySecurity, SeverityError},
	CodeIPSCompiled: {CategorySecurity, SeverityInfo},
	CodeIPSFailed:   {CategorySecurity, SeverityWarning},
	CodeIPSAnomaly:  {CategorySecurity, SeverityWarning},

	CodeIPSInterceptReady:  {CategorySecurity, SeverityInfo},
	CodeIPSInterceptFailed: {CategorySecurity, SeverityError},

	CodeExitNodeChanged: {CategoryNetwork, SeverityNotice},
	CodeRoutesChanged:   {CategoryNetwork, SeverityNotice},

	CodeSettingsChanged:   {CategorySettings, SeverityNotice},
	CodeConfigQuarantined: {CategorySettings, SeverityError},
	CodeDashboardMoved:    {CategorySettings, SeverityWarning},

	CodeTelemetryDropped: {CategorySystem, SeverityWarning},
	CodeTelemetryTrimmed: {CategorySystem, SeverityInfo},
}

// EventCodes returns every code the agent can record, in a stable order, so a client can
// offer the filter list without keeping its own copy.
func EventCodes() []EventCode {
	out := make([]EventCode, 0, len(eventCatalog))
	for code := range eventCatalog {
		out = append(out, code)
	}
	slices.Sort(out)
	return out
}

// Classify reports the category and severity a code carries, and whether it is in the
// catalog at all.
func Classify(code EventCode) (Category, Severity, bool) {
	spec, ok := eventCatalog[code]
	return spec.Category, spec.Severity, ok
}

// Event is one thing that happened, as the dashboard reads it.
//
// Message is a whole sentence written at the call site, because a screen that renders a
// code plus a bag of fields makes the reader assemble the meaning. Fields carry the few
// values worth filtering or sorting on, never a copy of the sentence.
type Event struct {
	// Seq orders events recorded inside the same clock tick and is the second half of
	// the pagination cursor. It is assigned by the hub, not by the caller.
	Seq uint64    `json:"seq"`
	At  time.Time `json:"at"`

	Code     EventCode `json:"code"`
	Category Category  `json:"category"`
	Severity Severity  `json:"severity"`
	Message  string    `json:"message"`

	// Fields are the small named values behind the sentence -- a device name, a port, a
	// setting key. They are strings because this is display and filter data: a consumer
	// that needs a number for arithmetic is asking the wrong endpoint.
	Fields map[string]string `json:"fields,omitempty"`
}

// eventWire is the shape an event takes on the wire: the enums as their words rather than
// as the integers they are stored as, so the JSON reads the same as every other enum in
// this app. Both directions go through it, which is what keeps them from drifting apart.
type eventWire struct {
	Seq      uint64            `json:"seq"`
	At       time.Time         `json:"at"`
	Code     EventCode         `json:"code"`
	Category string            `json:"category"`
	Severity string            `json:"severity"`
	Message  string            `json:"message"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// MarshalJSON renders an event in the wire shape.
func (e Event) MarshalJSON() ([]byte, error) {
	type wire = eventWire
	return json.Marshal(wire{
		Seq:      e.Seq,
		At:       e.At,
		Code:     e.Code,
		Category: e.Category.String(),
		Severity: e.Severity.String(),
		Message:  e.Message,
		Fields:   e.Fields,
	})
}

// UnmarshalJSON reads one back, refusing a category or severity that is not one of ours.
//
// The pair exists so the wire shape is a real contract rather than one direction of it: a
// word that only ever went out could be renamed on the way in without anything noticing.
// An unknown word is an error rather than the zero value, because filing a row under the
// wrong facet is worse than failing to read it.
func (e *Event) UnmarshalJSON(raw []byte) error {
	var in eventWire
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	category, ok := ParseCategory(in.Category)
	if !ok {
		return fmt.Errorf("telemetry: %q is not a log category", in.Category)
	}
	severity, ok := ParseSeverity(in.Severity)
	if !ok {
		return fmt.Errorf("telemetry: %q is not a log severity", in.Severity)
	}
	*e = Event{
		Seq:      in.Seq,
		At:       in.At,
		Code:     in.Code,
		Category: category,
		Severity: severity,
		Message:  in.Message,
		Fields:   in.Fields,
	}
	return nil
}

// maxEventFields bounds one event's field map. Every call site in this repo passes a
// handful, so the cap is a guard against a future one looping over something unbounded
// rather than a limit anyone will meet.
const maxEventFields = 12

// maxFieldValueLen bounds one field value. A device name or a setting key is short; a
// value long enough to matter here arrived from somewhere that should not be pasting
// into an event.
const maxFieldValueLen = 256

// truncateFields applies both bounds, returning a copy the caller cannot mutate
// afterwards. Copying matters: the map a call site passes is often a literal it keeps
// no reference to, but a ring holding the caller's map would be a data race the day
// somebody reuses one.
func truncateFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if len(keys) > maxEventFields {
		keys = keys[:maxEventFields]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		v := fields[k]
		if len(v) > maxFieldValueLen {
			v = v[:maxFieldValueLen] + "…"
		}
		out[k] = v
	}
	return out
}
