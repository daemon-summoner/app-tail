// SPDX-License-Identifier: MIT

package config

//go:generate go run ./gen

// The settings field registry is the single source of truth for what a setting is:
// its wire key, how it is typed, how it is presented, whether it is secret or
// read-only, which optional module owns it, and what a change to it costs (a live
// reload, a node rebuild, or a full process restart). Every surface derives from this
// one table -- the redacted view the API returns, the patch it accepts, the defaults a
// fresh install starts from, the validation every write passes, the restart
// classification, the CLI flags and interactive menu, the schema endpoint, and the
// generated TypeScript types. Adding a setting is one entry here plus the field it
// stores into on Settings; a drift test fails if the two ever disagree.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// FieldKind is how a setting is typed on the wire, parsed from a string, and checked
// for syntax. A kind that names a format (an address, a URL) carries that check, so
// every field of that kind is validated the same way on every surface.
type FieldKind int

const (
	KindString FieldKind = iota
	KindBool
	KindInt
	KindStringList // comma/space separated on the CLI, a JSON array on the wire
	KindSecret     // write-only; the view reports only presence, never the value
	KindSecretFile // a filesystem path; not itself secret
	KindAddrPort   // host:port with a literal IP host
	KindURL        // an absolute http(s) URL
	KindEnum       // one of a declared set of values, carried in Options
	// KindNodeRef is a peer named by its stable node ID. The choices are facts about
	// the tailnet rather than a fixed set, so they arrive at runtime through
	// OptionsFrom instead of being declared here.
	KindNodeRef
	// KindProfileRef is a resolver profile named by its id. Like a node reference the
	// choices are not a fixed set -- the built-in catalog plus whatever profiles the
	// user has added -- so they arrive at runtime through OptionsFrom, and a stored id
	// naming a profile that has since been deleted still loads.
	KindProfileRef
	// KindTunnelRef is one of this install's own connections, named by its id. The choices
	// are whatever connections the user has added, so they arrive at runtime through
	// OptionsFrom, and an id naming a connection that has since been removed still loads --
	// refusing the document would make deleting a connection able to make the app
	// unstartable.
	KindTunnelRef
	// KindTunnelRefList is an ordered list of this install's own connections. It is a list
	// rather than repeated KindTunnelRef fields because the set is the value: how many
	// connections carry something together is the user's choice, not a number this app
	// picks in advance. Like KindTunnelRef the choices arrive through OptionsFrom.
	KindTunnelRefList
	// KindCidrList is a list of network prefixes, stored parsed. Holding the parsed
	// form is what makes a route list that cannot be read impossible to store: the
	// only paths in are the decoder and the CLI parser, and both refuse an entry they
	// cannot parse rather than passing a string on to a stage with no way to complain.
	KindCidrList
	// KindInterfaceAddrList is a list of addresses this device holds, each written with
	// the size of the network it belongs to (10.0.0.2/24). It is a separate kind from
	// KindCidrList because the two mean opposite things about the host bits: a route
	// names a network and may carry none, and an address is precisely those bits.
	KindInterfaceAddrList
	// KindIPList is a list of bare addresses, with no network attached -- a resolver to
	// ask, not a range to reach.
	KindIPList
	// KindText is a string with newlines in it: a certificate, a key, a block pasted out
	// of another file. It is a separate kind from KindString because the difference is
	// visible to the person entering it -- a PEM block in a one-line box is a value nobody
	// can check before saving.
	KindText
	// KindSecretText is KindText that is write-only, on the same terms as KindSecret: the
	// view reports only whether one is stored. A private key is both at once, and folding
	// it into either of the two would give up the other half.
	KindSecretText
)

// Secret reports whether a value of this kind is write-only: stored, never sent back out,
// and reported to a client only as present or absent.
func (k FieldKind) Secret() bool { return k == KindSecret || k == KindSecretText }

func (k FieldKind) String() string {
	switch k {
	case KindBool:
		return "bool"
	case KindInt:
		return "int"
	case KindStringList:
		return "stringList"
	case KindSecret:
		return "secret"
	case KindSecretFile:
		return "secretFile"
	case KindAddrPort:
		return "addrPort"
	case KindURL:
		return "url"
	case KindEnum:
		return "enum"
	case KindNodeRef:
		return "nodeRef"
	case KindProfileRef:
		return "profileRef"
	case KindTunnelRef:
		return "tunnelRef"
	case KindTunnelRefList:
		return "tunnelRefList"
	case KindCidrList:
		return "cidrList"
	case KindInterfaceAddrList:
		return "interfaceAddrList"
	case KindIPList:
		return "ipList"
	case KindText:
		return "text"
	case KindSecretText:
		return "secretText"
	default:
		return "string"
	}
}

// lastKind is the final declared kind, which is how far the decoder looks.
const lastKind = KindSecretText

// MarshalJSON renders the kind as its name so the schema endpoint and generated TS
// read a word rather than an opaque integer.
func (k FieldKind) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

func (k *FieldKind) UnmarshalJSON(raw []byte) error {
	v, err := unmarshalNamed(raw, lastKind, "field kind")
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// EnumOption is one choice a KindEnum field accepts. Help is what the choice does,
// which a radio group shows beside each option and a dropdown shows for the selected
// one; without it a picker offers words with no way to tell them apart.
type EnumOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Help  string `json:"help,omitempty"`
	// Applies is the patch this option is a name for, set only on a derived field whose
	// value is a reading of other settings rather than a stored one of its own. Choosing
	// the option means writing this, so the reading and the writing are one table and
	// cannot drift into a picker that will not stay where it is put.
	Applies map[string]any `json:"applies,omitempty"`
}

// RestartClass is what a change to a field needs before it fully takes effect.
type RestartClass int

const (
	RestartNone RestartClass = iota // live: the forwarding engine re-reads it at once
	// RestartPrefs is pushed to the running node's own preferences. It needs no
	// restart, but it does need a node that is up: stored while it is down, applied
	// on the next transition into Running, and reported as waiting until then.
	RestartPrefs
	RestartNode // an in-process node rebuild (POST /api/restart)
	RestartUI   // a full process restart (only the dashboard address)
	// RestartApp is read once, when the process starts, and acted on nowhere else --
	// the tray icon is the case. It is separate from RestartUI because what a person is
	// told differs: the dashboard address needs a restart to move, while this is a
	// setting stored now and honoured on the next start.
	RestartApp
)

func (r RestartClass) String() string {
	switch r {
	case RestartPrefs:
		return "prefs"
	case RestartNode:
		return "node"
	case RestartUI:
		return "ui"
	case RestartApp:
		return "app"
	default:
		return "none"
	}
}

// lastRestart is the final declared restart class, which is how far the decoder looks.
const lastRestart = RestartApp

func (r RestartClass) MarshalJSON() ([]byte, error) { return json.Marshal(r.String()) }

func (r *RestartClass) UnmarshalJSON(raw []byte) error {
	v, err := unmarshalNamed(raw, lastRestart, "restart class")
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// WriteVia is which endpoint applies a write to a field.
type WriteVia int

const (
	WritePatch     WriteVia = iota // PUT /api/settings
	WriteAutostart                 // POST /api/autostart (the OS login item, not a config bool)
	WriteNone                      // read-only: stateDir, machineId, effectiveHostname
)

func (w WriteVia) String() string {
	switch w {
	case WriteAutostart:
		return "autostart"
	case WriteNone:
		return "none"
	default:
		return "patch"
	}
}

// lastWrite is the final declared write path, which is how far the decoder looks.
const lastWrite = WriteNone

func (w WriteVia) MarshalJSON() ([]byte, error) { return json.Marshal(w.String()) }

func (w *WriteVia) UnmarshalJSON(raw []byte) error {
	v, err := unmarshalNamed(raw, lastWrite, "write path")
	if err != nil {
		return err
	}
	*w = v
	return nil
}

// FieldOf describes one field of T. The exported metadata drives the schema and TS
// generation; the unexported closures drive reads, writes, defaults and validation.
//
// It is generic over the entity it describes because everything here except the four
// closures -- the kinds, the validation, the schema projection, the patch decoder, the
// CLI parser -- is about the field rather than about what it is a field of. A second
// kind of configurable thing gets its own table and inherits all of that, instead of a
// second hand-written validator and a second hand-written form.
type FieldOf[T any] struct {
	// JSONKey is the wire key used both in the patch and (for non-secret fields) the
	// view. ViewKey is where the value or presence lands in the view when it differs
	// from JSONKey -- a secret "authKey" reports as "hasAuthKey".
	JSONKey string
	ViewKey string
	// CLIName is the flag/menu name; empty means the field is not settable from the CLI.
	CLIName string
	Kind    FieldKind
	Restart RestartClass
	Write   WriteVia
	// Label is the short name a form puts beside the control. Help is the sentence
	// under it.
	Label string
	Group Group
	Tier  Tier
	// Module is the optional capability this setting belongs to; ModuleCore means it
	// is always available. ModuleSwitch is set on the one field whose value turns a
	// module on, which is itself an ordinary core setting.
	Module       FeatureModule
	ModuleSwitch FeatureModule
	// Platforms lists the GOOS values this setting does anything on; empty means all
	// of them. It exists because a switch that is offered and then quietly does
	// nothing is worse than one that is absent: the field is hidden and rejected by
	// name off-platform, and the surface says so rather than accepting the write.
	Platforms []string
	// Variant is the kind of entity this field applies to; empty means all of them.
	// It gates on what the entity IS -- a connection's protocol -- where Module gates
	// on what the installation has switched on, so a field can need both. A tailnet's
	// auth key and a WireGuard peer's private key are not two values of one field.
	Variant string
	// Example is the greyed sample a text control shows while the field is empty --
	// a representative value or the standing-in default, never a restatement of the
	// label. An empty Example means the control shows nothing.
	Example string
	// ExampleFrom names the view key whose current value stands in for Example. It is
	// how an empty setting shows what is actually in force instead of a generic
	// sample: an empty device name is the rendered template, and a client that had to
	// know which fields work that way could not be schema-driven.
	ExampleFrom string
	// Tray puts this setting in the menu-bar menu. A tray click is the whole
	// interaction and has no way to ask "restart now?", so only a boolean that takes
	// effect on the click belongs there -- one applied here or pushed to the tailnet
	// node, never one that needs a restart. The guard test enforces exactly that.
	Tray bool
	// Options are the values a KindEnum field accepts, in the order a picker should
	// offer them. They are declared here rather than in each consumer so the choice a
	// control offers and the choice the agent accepts cannot come apart.
	Options []EnumOption
	// OptionsFrom names the runtime list a picker fills this setting's choices from,
	// for a setting whose choices are facts about the tailnet rather than a set the
	// registry could hold. A client that has no such list still renders the control and
	// shows the stored value; it just has nothing to offer beside it.
	OptionsFrom string
	// Default is the value a fresh install starts from; nil means the zero of the kind.
	Default    any
	Constraint Constraint
	// Derived fields are computed from other settings (effectiveHostname), not stored.
	Derived bool
	// Pinnable lists the env/flag names that can override this at resolve time, so a
	// write that visibly does not move can name the culprit.
	Pinnable []string
	// Deprecated is what replaced this field, in words a person can act on. It is set on
	// a key that is kept because callers name it and answered because they would
	// otherwise get silence: a read-only field carrying one refuses a write with this
	// sentence instead of a bare "is read-only", and a form renders it as a redirect note
	// rather than as a control somebody will try to use.
	Deprecated string
	Help       string

	get     func(*T) any  // typed current value; nil for Derived
	set     func(*T, any) // apply a typed value; nil for read-only
	present func(*T) bool // secret presence for the view; only KindSecret
	// derive computes a value that is read rather than stored; only for Derived. It is
	// given the installation's settings as well as the entity, because a derived value
	// can depend on both -- a connection's rendered device name is its own template
	// against this machine's identity.
	derive func(T, *Settings) any
	// validate is the rule the kind's syntax and the declared Constraint cannot
	// express. It returns the bare reason; ValidateValue attributes it to the field.
	validate func(any) error
	// validateWrite is a rule for new values only: a patch is refused by it, a stored
	// document is not. It is for a rule whose stored violation is already refused where the
	// value is used, so loading an older document never quarantines it over that value.
	validateWrite func(any) error
}

// SettingField is a field of the global settings document. Every literal in
// settingsFields is one, and the name is what the rest of the app reads it by.
type SettingField = FieldOf[Settings]

// AdvertiseExitNodeLabel is what "routes.advertiseExitNode" is called on screen. It is a
// constant because two rules point the user at that setting by name -- the mutual
// exclusion with using an exit node, and the refusal of a default route in the subnet
// list -- and a rule inside this registry cannot look a label up in the registry it is
// part of. One constant is what keeps the three from drifting apart.
const AdvertiseExitNodeLabel = "Offer this device as an exit node"

// NetfilterNotApplicable is what this app does about the host firewall for the routes it
// carries: nothing at all. It is stated as a read-only setting rather than left out,
// because someone arriving from the official client goes looking for these knobs, and
// their absence otherwise reads as a gap rather than as a consequence of routing in
// userspace with no privileges.
const NetfilterNotApplicable = "Not applicable: app-tail routes in userspace and never " +
	"configures netfilter, so there is nothing here to set."

// settingsFields is the one authored table. Order here is the order the interactive
// menu and the schema present fields in, so it mirrors the dashboard's grouping.
var settingsFields = []SettingField{
	{
		JSONKey: "advancedNetworking", CLIName: "advanced-networking", Kind: KindBool,
		Restart: RestartNode, Write: WritePatch,
		Label: "Advanced networking", Group: GroupTailnet, Tier: TierBasic,
		ModuleSwitch: ModuleAdvancedNetworking,
		Help: "Reveal the settings for joining a coordination server other than " +
			"Tailscale's. Turning it back off returns them to their defaults.",
		get: func(s *Settings) any { return s.AdvancedNetworking },
		set: func(s *Settings, v any) { s.AdvancedNetworking = typed[bool](v) },
	},
	{
		JSONKey: "traffic.latency", CLIName: "traffic-latency", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Group: GroupTraffic, Tier: TierBasic,
		Label: "Measure the round trip to each device",
		Help: "Send a small probe to every online device every few seconds and report how " +
			"long it takes to answer. It is off by default because it is the one part of " +
			"this page that makes the machine send traffic rather than only report it, " +
			"which costs battery on a laptop and wakes radios on an idle network.",
		get: func(s *Settings) any { return s.TrafficLatency },
		set: func(s *Settings, v any) { s.TrafficLatency = typed[bool](v) },
	},
	{
		JSONKey: "traffic.smooth", CLIName: "traffic-smooth", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Group: GroupTraffic, Tier: TierBasic,
		Label: "Smooth the graph lines", Default: true,
		Help: "Draw the bandwidth graph as a moving average over about the last 25 seconds, " +
			"weighted toward the middle, so the shape of a transfer is visible " +
			"through the second-to-second noise. Only that line changes: the rate on the " +
			"card, the figures per device and the count of open connections are the measured " +
			"ones either way, and an interval nothing was measured in stays a gap.",
		get: func(s *Settings) any { return s.TrafficSmooth },
		set: func(s *Settings, v any) { s.TrafficSmooth = typed[bool](v) },
	},
	{
		JSONKey: "telemetry.enabled", CLIName: "telemetry", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleTelemetry,
		Label: "Keep a log of what this app does", Group: GroupTelemetry, Tier: TierBasic,
		Help: "Record the tailnet node connecting and dropping, forwards starting and " +
			"stopping, the resolver being claimed and put back, and every settings change, " +
			"so a fault that has already passed can still be looked at. It is kept in this " +
			"app's memory, it is never sent anywhere, and it is gone when the app stops.",
		get: func(s *Settings) any { return s.TelemetryEnabled },
		set: func(s *Settings, v any) { s.TelemetryEnabled = typed[bool](v) },
	},
	{
		JSONKey: "telemetry.eventLog.retentionDays", CLIName: "telemetry-event-days",
		Kind:    KindInt,
		Restart: RestartNone, Write: WritePatch, Module: ModuleTelemetry,
		Label: "Keep events for", Group: GroupTelemetry, Tier: TierAdvanced,
		Default:    DefaultEventRetentionDays,
		Constraint: between(0, 365),
		Help: "Days an entry stays in the log before it is removed; 0 uses the default of " +
			"30. The log also has a fixed size, so a busy machine reaches that limit long " +
			"before this one.",
		get: func(s *Settings) any { return s.TelemetryEventRetentionDays },
		set: func(s *Settings, v any) { s.TelemetryEventRetentionDays = typed[int](v) },
	},
	{
		JSONKey: "uiListenAddr", CLIName: "ui-addr", Kind: KindAddrPort,
		Restart: RestartUI, Write: WritePatch, Pinnable: []string{EnvUIAddr},
		Label: "Dashboard address", Group: GroupApplication, Tier: TierAdvanced,
		Example: DefaultUIListenAddr,
		Default: DefaultUIListenAddr,
		Help: "Loopback host:port the dashboard listens on. Port 0 asks for any free port. " +
			"When the port is already taken the app runs on one the system assigns for that " +
			"run and asks for this address again next time. It must stay on loopback: the " +
			"API token is the only thing between an address reachable off-host and your " +
			"tailnet identity.",
		get:      func(s *Settings) any { return s.UIListen },
		set:      func(s *Settings, v any) { s.UIListen = typed[string](v) },
		validate: loopbackOnly,
	},
	{
		JSONKey: "udpSessionTimeoutSec", CLIName: "udp-timeout", Kind: KindInt,
		Restart: RestartNone, Write: WritePatch,
		Label: "UDP session timeout (s)", Group: GroupForwarding, Tier: TierAdvanced,
		Default: DefaultUDPTimeoutSec, Constraint: atLeast(0),
		Help: "UDP has no close, so idle sessions are evicted after this many seconds. " +
			"A forward can override it per rule.",
		get: func(s *Settings) any { return s.UDPSessionTimeoutSec },
		set: func(s *Settings, v any) { s.UDPSessionTimeoutSec = typed[int](v) },
	},
	{
		JSONKey: "udpBufferBytes", CLIName: "udp-buffer", Kind: KindInt,
		Restart: RestartNone, Write: WritePatch,
		Label: "UDP buffer (bytes)", Group: GroupForwarding, Tier: TierAdvanced,
		Default: DefaultUDPBufferBytes, Constraint: between(0, 65535),
		Help: "Largest UDP datagram a forward can relay. 65535 is the protocol maximum.",
		get:  func(s *Settings) any { return s.UDPBufferBytes },
		set:  func(s *Settings, v any) { s.UDPBufferBytes = typed[int](v) },
	},
	{
		JSONKey: "proxy.enabled", CLIName: "proxy", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleProxy, Tray: true,
		Label: "Tailnet proxy", Group: GroupProxy, Tier: TierBasic,
		Help: "Run a loopback SOCKS5 and HTTP proxy that reaches the whole tailnet. " +
			"While it is on, any program running as any user on this machine can reach " +
			"every device your ACLs allow this node to reach.",
		get: func(s *Settings) any { return s.ProxyEnabled },
		set: func(s *Settings, v any) { s.ProxyEnabled = typed[bool](v) },
	},
	{
		JSONKey: "proxy.system", CLIName: "proxy-system", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleProxy, Tray: true,
		Platforms: []string{"windows"},
		Label:     "Point this machine's proxy settings at it", Group: GroupProxy, Tier: TierBasic,
		Help: "Write the auto-config URL into this Windows account's own proxy settings, so " +
			"programs that read them need no setup. It is put back as it was when this is " +
			"turned off. Firefox and most command-line tools keep their own setting.",
		get: func(s *Settings) any { return s.ProxySystem },
		set: func(s *Settings, v any) { s.ProxySystem = typed[bool](v) },
	},
	{
		JSONKey: "automap.enabled", CLIName: "automap", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleAutoMap, Tray: true,
		Label: "Open a port for every device", Group: GroupAutoMap, Tier: TierBasic,
		Help: "Open a local port for every device on the tailnet, so a peer's SSH or web " +
			"port is reachable at localhost. Each port is assigned once and kept, so " +
			"anything you save that names it keeps working.",
		get: func(s *Settings) any { return s.AutoMapEnabled },
		set: func(s *Settings, v any) { s.AutoMapEnabled = typed[bool](v) },
	},
	{
		JSONKey: "automap.ports", CLIName: "automap-ports", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleAutoMap,
		Label: "Ports to map", Group: GroupAutoMap, Tier: TierBasic,
		Default: []string{strconv.Itoa(DefaultAutoMapPort)}, Example: "22, 80, 3000",
		Help: "Which port on each device to map. Every device gets one local port per " +
			"entry, so a long list multiplied by a large tailnet reaches the limit fast.",
		get:      func(s *Settings) any { return s.AutoMapPorts },
		set:      func(s *Settings, v any) { s.AutoMapPorts = typed[[]string](v) },
		validate: arePorts,
	},
	{
		JSONKey: "automap.max", CLIName: "automap-max", Kind: KindInt,
		Restart: RestartNone, Write: WritePatch, Module: ModuleAutoMap,
		Label: "Most ports to open", Group: GroupAutoMap, Tier: TierAdvanced,
		Default: DefaultAutoMapMax, Constraint: between(0, 512),
		Help: "How many local ports the module will open at once. Devices are taken " +
			"online-first, then by name; anything past the limit is reported rather " +
			"than quietly left out. Zero uses the default.",
		get: func(s *Settings) any { return s.AutoMapMax },
		set: func(s *Settings, v any) { s.AutoMapMax = typed[int](v) },
	},
	{
		JSONKey: "automap.portBase", CLIName: "automap-port-base", Kind: KindInt,
		Restart: RestartNone, Write: WritePatch, Module: ModuleAutoMap,
		Label: "First port to use", Group: GroupAutoMap, Tier: TierAdvanced,
		Default: DefaultAutoMapPortBase, Constraint: between(0, 65535),
		Help: "Where the search for a free local port starts. Changing it does not move " +
			"ports already assigned; those are kept so nothing that names one breaks. " +
			"Zero uses the default.",
		get:      func(s *Settings) any { return s.AutoMapPortBase },
		set:      func(s *Settings, v any) { s.AutoMapPortBase = typed[int](v) },
		validate: unprivilegedPort,
	},
	{
		JSONKey: "exitNode.enabled", CLIName: "exit-node", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleExitNode,
		Label: "Use an exit node", Group: GroupExitNode, Tier: TierBasic,
		Tray: true,
		Help: "Turn on the settings that send this device's other traffic out through a " +
			"device on your tailnet. Nothing changes until you choose a device below.",
		get: func(s *Settings) any { return s.ExitNodeEnabled },
		set: func(s *Settings, v any) { s.ExitNodeEnabled = typed[bool](v) },
	},
	{
		JSONKey: "routes.enabled", CLIName: "routes", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleRouting, Tray: true,
		Label: "Use subnet routes", Group: GroupRouting, Tier: TierBasic,
		Help: "Turn on the settings that decide which private networks this device " +
			"reaches through the tailnet. Nothing changes until you choose one below.",
		get: func(s *Settings) any { return s.RoutesEnabled },
		set: func(s *Settings, v any) { s.RoutesEnabled = typed[bool](v) },
	},
	{
		JSONKey: "dns.enabled", CLIName: "dns", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleDNS, Tray: true,
		Label: "Use tailnet DNS", Group: GroupDNS, Tier: TierBasic,
		Help: "Turn on the setting that decides which resolver app-tail uses for the names " +
			"it looks up. Nothing changes until you choose below.",
		get: func(s *Settings) any { return s.DNSEnabled },
		set: func(s *Settings, v any) { s.DNSEnabled = typed[bool](v) },
	},
	{
		JSONKey: "systemDns.enabled", CLIName: "system-dns", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleSystemDNS, Tray: true,
		Label: "Use a chosen resolver for this machine", Group: GroupSystemDNS, Tier: TierBasic,
		Help: "Point every program on this machine at the resolver you choose below. This is " +
			"one of the two things app-tail changes outside itself: it needs administrator " +
			"rights once, it lists exactly what it changes, and it puts your previous " +
			"settings back when you turn it off. Nothing changes while the profile below " +
			"is System default.",
		get: func(s *Settings) any { return s.SystemDNSEnabled },
		set: func(s *Settings, v any) { s.SystemDNSEnabled = typed[bool](v) },
	},
	{
		JSONKey: "systemDns.profile", CLIName: "system-dns-profile", Kind: KindProfileRef,
		Restart: RestartNone, Write: WritePatch, Module: ModuleSystemDNS,
		Label: "Resolver", Group: GroupSystemDNS, Tier: TierBasic,
		Default: DefaultSystemDNSProfile, OptionsFrom: OptionsDNSProfiles,
		Help: "Which set of DNS servers this machine resolves names through. System default " +
			"leaves the machine exactly as it is. Switching is immediate, which is the point: " +
			"a resolver that blocks a site you need is one click away from one that does not.",
		get: func(s *Settings) any { return s.SystemDNSProfile },
		set: func(s *Settings, v any) { s.SystemDNSProfile = typed[string](v) },
	},
	{
		JSONKey: "systemDns.bootstrapProfile", CLIName: "system-dns-bootstrap",
		Kind:    KindProfileRef,
		Restart: RestartNone, Write: WritePatch, Module: ModuleSystemDNS,
		Label: "Look resolver hostnames up through", Group: GroupSystemDNS, Tier: TierAdvanced,
		Default: DefaultSystemDNSBootstrapProfile, OptionsFrom: OptionsDNSBootstrap,
		Help: "A resolver written as a hostname -- tls://dns.nextdns.io, an https:// URL -- has " +
			"to be turned into an address before app-tail can reach it, and that one lookup " +
			"cannot go to the resolver being looked up. It goes here instead. Keep it on an " +
			"encrypted profile: that lookup is the one part of the chain this network can " +
			"still answer, and an answer of its choosing makes your resolver unreachable " +
			"rather than wrong, since the certificate is checked against the hostname either " +
			"way. System default sends it to this network's resolvers, which is also what " +
			"happens if the profile here cannot be reached.",
		get: func(s *Settings) any { return s.SystemDNSBootstrapProfile },
		set: func(s *Settings, v any) { s.SystemDNSBootstrapProfile = typed[string](v) },
	},
	{
		JSONKey: "systemDns.localSuffixes", CLIName: "system-dns-local-suffixes",
		Kind:    KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleSystemDNS,
		Label: "Names this network answers for", Group: GroupSystemDNS, Tier: TierAdvanced,
		Example: "corp.example.com, home.arpa",
		Help: "Extra name suffixes to look up through the network you are on rather than " +
			"through the resolver above. app-tail already sends single names, .local, " +
			"anything under a private address range and the names this network publishes " +
			"that way; this is for a suffix it cannot know about.",
		get:      func(s *Settings) any { return s.SystemDNSLocalSuffixes },
		set:      func(s *Settings, v any) { s.SystemDNSLocalSuffixes = typed[[]string](v) },
		validate: dnsSuffixes,
	},
	{
		JSONKey: "systemDns.retryOnNxdomain", CLIName: "system-dns-retry-nxdomain",
		Kind:    KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleSystemDNS,
		Label: "Ask this network again for a name the resolver says does not exist",
		Group: GroupSystemDNS, Tier: TierAdvanced,
		Help: "Off, and worth leaving off. A resolver that filters a domain -- NextDNS, Pi-hole, " +
			"a family filter -- blocks it by answering that it does not exist, so asking a " +
			"second resolver afterwards is how a blocklist stops blocking. Turn it on only " +
			"if names on this network are genuinely coming back missing.",
		get: func(s *Settings) any { return s.SystemDNSRetryOnNXDOMAIN },
		set: func(s *Settings, v any) { s.SystemDNSRetryOnNXDOMAIN = typed[bool](v) },
	},
	{
		JSONKey: "systemDns.listenAddr", CLIName: "system-dns-addr", Kind: KindAddrPort,
		Restart: RestartNone, Write: WritePatch, Module: ModuleSystemDNS,
		Label: "Where app-tail answers DNS", Group: GroupSystemDNS, Tier: TierAdvanced,
		Example: DefaultSystemDNSListenAddr,
		Default: DefaultSystemDNSListenAddr,
		Help: "Loopback host:port app-tail's own resolver listens on, and what this machine " +
			"is pointed at. Nothing outside this machine can reach it. Change it only if " +
			"something here already holds the default; app-tail moves to another loopback " +
			"address by itself if it cannot take this one.",
		get:      func(s *Settings) any { return s.SystemDNSListenAddr },
		set:      func(s *Settings, v any) { s.SystemDNSListenAddr = typed[string](v) },
		validate: loopbackOnly,
	},
	{
		JSONKey: "dnsBlock.enabled", CLIName: "dns-block", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleDNSBlock, Tray: true,
		Label: "Block names on a list", Group: GroupDNSBlock, Tier: TierBasic,
		Help: "Download the lists you choose and refuse the names on them instead of looking " +
			"them up. Turning this on starts the downloads; the two switches below say where " +
			"the lists apply, and until one of them is on nothing is blocked anywhere.",
		get: func(s *Settings) any { return s.DNSBlockEnabled },
		set: func(s *Settings, v any) { s.DNSBlockEnabled = typed[bool](v) },
	},
	{
		JSONKey: "dnsBlock.own", CLIName: "dns-block-own", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleDNSBlock, Tray: true,
		Label: "Block what app-tail looks up", Group: GroupDNSBlock, Tier: TierBasic,
		Help: "Refuse a blocked name when app-tail resolves it: what its proxy dials, and what " +
			"an automatic port reaches. A port forward is unaffected -- it hands the target " +
			"you configured straight to the other end without ever looking a name up here.",
		get: func(s *Settings) any { return s.DNSBlockOwn },
		set: func(s *Settings, v any) { s.DNSBlockOwn = typed[bool](v) },
	},
	{
		JSONKey: "dnsBlock.system", CLIName: "dns-block-system", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleDNSBlock, Tray: true,
		Label: "Block what this machine looks up", Group: GroupDNSBlock, Tier: TierBasic,
		Default: true,
		Help: "Refuse a blocked name for every program on this machine, which is what an ad " +
			"blocker for the whole device means. It does nothing on its own: the machine only " +
			"asks app-tail at all while the system resolver in the section above is on.",
		get: func(s *Settings) any { return s.DNSBlockSystem },
		set: func(s *Settings, v any) { s.DNSBlockSystem = typed[bool](v) },
	},
	{
		JSONKey: "dnsBlock.answer", CLIName: "dns-block-answer", Kind: KindEnum,
		Restart: RestartNone, Write: WritePatch, Module: ModuleDNSBlock,
		Label: "Answer a blocked name with", Group: GroupDNSBlock, Tier: TierAdvanced,
		Default: DefaultDNSBlockAnswer,
		Options: []EnumOption{
			{Value: "nxdomain", Label: "No such name", Help: "What every filtering resolver " +
				"answers. A program takes the path it already has for a name that does not " +
				"exist, which is the quickest of the three and the one least likely to " +
				"confuse anything."},
			{Value: "sinkhole", Label: "This machine (0.0.0.0)", Help: "Answers with an " +
				"address that goes nowhere. Some older programs retry a missing name and " +
				"accept this one; the cost is a connection attempt that has to time out."},
			{Value: "refused", Label: "Refused", Help: "Says the resolver would not answer, " +
				"rather than that the name does not exist. It is the honest answer and the " +
				"one that shows up plainly in a packet capture, but a program that meets it " +
				"may ask a different resolver instead."},
		},
		Help: "What a program is told when it asks for a blocked name. All three stop the " +
			"connection; they differ in what the program does next.",
		get: func(s *Settings) any { return s.DNSBlockAnswer },
		set: func(s *Settings, v any) { s.DNSBlockAnswer = typed[string](v) },
	},
	{
		JSONKey: "dnsBlock.lists", CLIName: "dns-block-lists", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleDNSBlock,
		Label: "Lists in use", Group: GroupDNSBlock, Tier: TierAdvanced,
		Example: DefaultDNSBlockList,
		Default: []string{DefaultDNSBlockList},
		Help: "The ids of the lists that are switched on, which the switches on the card above " +
			"write for you. Every list here is downloaded and matched; a list you have added " +
			"but not switched on is kept and costs nothing.",
		get:      func(s *Settings) any { return s.DNSBlockLists },
		set:      func(s *Settings, v any) { s.DNSBlockLists = typed[[]string](v) },
		validate: blocklistIDs,
	},
	{
		JSONKey: "dnsBlock.refreshHours", CLIName: "dns-block-refresh-hours", Kind: KindInt,
		Restart: RestartNone, Write: WritePatch, Module: ModuleDNSBlock,
		Label: "Re-download a list after", Group: GroupDNSBlock, Tier: TierAdvanced,
		Default:    DefaultDNSBlockRefreshHours,
		Constraint: between(0, MaxDNSBlockRefreshHours),
		Help: "Hours before a list is fetched again. The lists themselves are rebuilt about " +
			"once a day. A copy that cannot be fetched keeps blocking from disk rather than " +
			"expiring, so a long interval costs coverage, never blocking itself. Zero uses " +
			"the default.",
		get:      func(s *Settings) any { return s.DNSBlockRefreshHours },
		set:      func(s *Settings, v any) { s.DNSBlockRefreshHours = typed[int](v) },
		validate: blockRefreshHours,
	},
	{
		JSONKey: "dnsBlock.allow", CLIName: "dns-block-allow", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleDNSBlock,
		Label: "Never block", Group: GroupDNSBlock, Tier: TierBasic,
		Example: "example.com, cdn.example.net",
		Help: "Names that resolve normally whatever any list says, each covering everything " +
			"under it. This is what a wrongly blocked site is fixed with, so it beats every " +
			"list and the one you added yourself.",
		get:      func(s *Settings) any { return s.DNSBlockAllow },
		set:      func(s *Settings, v any) { s.DNSBlockAllow = typed[[]string](v) },
		validate: dnsSuffixes,
	},
	{
		JSONKey: "dnsBlock.deny", CLIName: "dns-block-deny", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleDNSBlock,
		Label: "Always block", Group: GroupDNSBlock, Tier: TierBasic,
		Example: "ads.example.com, telemetry.example.net",
		Help: "Names blocked with no list involved, each covering everything under it. The " +
			"list above wins where the two disagree.",
		get:      func(s *Settings) any { return s.DNSBlockDeny },
		set:      func(s *Settings, v any) { s.DNSBlockDeny = typed[[]string](v) },
		validate: dnsSuffixes,
	},
	{
		JSONKey: "ips.enabled", CLIName: "ips", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleIPS, Tray: true,
		Label: "Inspect the traffic app-tail carries", Group: GroupIPS, Tier: TierBasic,
		Help: "Compare every connection app-tail carries against the entries below and record " +
			"the ones that match. Turning this on starts the matching; the two switches below " +
			"say what is examined, and until one of them is on nothing is examined anywhere.",
		get: func(s *Settings) any { return s.IPSEnabled },
		set: func(s *Settings, v any) { s.IPSEnabled = typed[bool](v) },
	},
	{
		JSONKey: "ips.mode", CLIName: "ips-mode", Kind: KindEnum,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tray: true,
		Label: "When a connection matches", Group: GroupIPS, Tier: TierBasic,
		Default: DefaultIPSMode,
		Options: []EnumOption{
			{Value: IPSModeDetect, Label: "Record it and carry it", Help: "The connection is " +
				"made as normal and the match is written to the log. Start here: it shows you " +
				"what would have been refused, on your own traffic, before anything is."},
			{Value: IPSModePrevent, Label: "Refuse it", Help: "The connection is refused " +
				"before anything is dialled, so nothing reaches the far end. A program that " +
				"meets this sees the same connection refused it would see from a host that " +
				"is not listening."},
		},
		Help: "What happens to a connection that matches an entry. Both record the match; they " +
			"differ in whether the connection is still made.",
		get: func(s *Settings) any { return s.IPSMode },
		set: func(s *Settings, v any) { s.IPSMode = typed[string](v) },
	},
	{
		JSONKey: "ips.names", CLIName: "ips-names", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tray: true,
		Label: "Examine the names asked for", Group: GroupIPS, Tier: TierBasic,
		Default: true,
		Help: "Match the name a program asked for, before it is looked up. This is what " +
			"app-tail's own resolver and its proxy see; a program that dials an address " +
			"directly never gave a name here, and is reached by the switch below instead.",
		get: func(s *Settings) any { return s.IPSNames },
		set: func(s *Settings, v any) { s.IPSNames = typed[bool](v) },
	},
	{
		JSONKey: "ips.destinations", CLIName: "ips-destinations", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tray: true,
		Label: "Examine where connections are bound", Group: GroupIPS, Tier: TierBasic,
		Default: true,
		Help: "Match the address a connection is bound for. This is all the network interface " +
			"and the subnet router ever have, and it is the half that still applies when a " +
			"program brings its own resolver or dials an address it hardcoded.",
		get: func(s *Settings) any { return s.IPSDestinations },
		set: func(s *Settings, v any) { s.IPSDestinations = typed[bool](v) },
	},
	{
		JSONKey: "ips.anomaly", CLIName: "ips-anomaly", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tray: true,
		Label: "Watch for unusual patterns", Group: GroupIPS, Tier: TierAdvanced,
		Help: "Report what a run of connections adds up to, rather than what any one of them " +
			"is bound for: one device reaching many ports on another, one reaching a great many " +
			"addresses at once, and data leaving inside DNS queries. This matches against no " +
			"list, so it works on a machine where nothing has been typed above. It is the only " +
			"part of inspection that keeps a record of where traffic went; that record is held " +
			"in memory for a minute, is never written to disk, and is discarded when you turn " +
			"this off.",
		get: func(s *Settings) any { return s.IPSAnomaly },
		set: func(s *Settings, v any) { s.IPSAnomaly = typed[bool](v) },
	},
	{
		JSONKey: "ips.handshake", CLIName: "ips-handshake", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tray: true,
		Label: "Read the start of each connection", Group: GroupIPS, Tier: TierAdvanced,
		Help: "Read the first few kilobytes a connection sends, where the name it is really " +
			"for lives: the server name inside a TLS handshake and the host of a plain web " +
			"request. This is what reaches a program that never asked app-tail for a name and " +
			"dialled an address instead. Nothing after the opening is read, and nothing is " +
			"decrypted: the name is sent in the clear before the encryption starts.",
		get: func(s *Settings) any { return s.IPSHandshake },
		set: func(s *Settings, v any) { s.IPSHandshake = typed[bool](v) },
	},
	{
		JSONKey: "ips.fingerprints", CLIName: "ips-fingerprints", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tier: TierAdvanced,
		Label: "Note which software opened the connection", Group: GroupIPS,
		Help: "Record a short fingerprint of how each TLS connection was opened, which says " +
			"which family of software made it. It is a note on a finding rather than something " +
			"matched against: everything built on the same library shares one, and anyone who " +
			"wants theirs changed can change it. Needs the setting above.",
		get: func(s *Settings) any { return s.IPSFingerprints },
		set: func(s *Settings, v any) { s.IPSFingerprints = typed[bool](v) },
	},
	{
		JSONKey: "ips.payload", CLIName: "ips-payload", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tier: TierAdvanced,
		Label: "Look for your own byte patterns", Group: GroupIPS,
		Help: "Read the same opening bytes against the patterns below, which is the one part of " +
			"inspection that looks at what a connection carries rather than where it is going. " +
			"Nothing is decrypted, so this reaches only what is sent in the clear. It also " +
			"holds those few kilobytes for the whole opening of each connection instead of " +
			"letting them go as soon as the connection is named. Needs the setting above.",
		get: func(s *Settings) any { return s.IPSPayload },
		set: func(s *Settings, v any) { s.IPSPayload = typed[bool](v) },
	},
	{
		JSONKey: "ips.signatures", CLIName: "ips-signatures", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tier: TierAdvanced,
		Label: "Byte patterns to look for", Group: GroupIPS,
		Example: `a token that must not leave = "hunter2-9f3a1c"`,
		Help: "One pattern per entry, written as a name, an equals sign, and the bytes in " +
			"quotes. Use \\xNN inside the quotes for a byte that is not text. The name is what a " +
			"finding is reported as; the bytes are never written to a log or shown on a card, so " +
			"a pattern can safely be something you are watching for a leak of. Matching is " +
			"exact, including case, and a pattern must be at least four bytes: anything shorter " +
			"appears in nearly every connection. There is no feed for these and no built-in " +
			"set -- no maintained list of stream patterns exists to download, so these are " +
			"yours.",
		get:      func(s *Settings) any { return s.IPSSignatures },
		set:      func(s *Settings, v any) { s.IPSSignatures = typed[[]string](v) },
		validate: signaturePatterns,
	},
	{
		JSONKey: "ips.lists", CLIName: "ips-lists", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS,
		Label: "Feeds in use", Group: GroupIPS, Tier: TierAdvanced,
		Example: "firehol-level1",
		Help: "The ids of the address feeds that are switched on, which the switches on the card " +
			"above write for you. Every feed here is downloaded and matched; a feed you have " +
			"added but not switched on is kept and costs nothing.",
		get:      func(s *Settings) any { return s.IPSLists },
		set:      func(s *Settings, v any) { s.IPSLists = typed[[]string](v) },
		validate: blocklistIDs,
	},
	{
		JSONKey: "ips.refreshHours", CLIName: "ips-refresh-hours", Kind: KindInt,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS,
		Label: "Re-download a feed after", Group: GroupIPS, Tier: TierAdvanced,
		Default:    DefaultIPSRefreshHours,
		Constraint: between(0, MaxIPSRefreshHours),
		Help: "Hours before a feed is fetched again. These feeds are rebuilt about once a day. " +
			"A copy that cannot be fetched keeps matching from disk rather than expiring, so a " +
			"long interval costs coverage, never matching itself. Zero uses the default.",
		get:      func(s *Settings) any { return s.IPSRefreshHours },
		set:      func(s *Settings, v any) { s.IPSRefreshHours = typed[int](v) },
		validate: blockRefreshHours,
	},
	{
		JSONKey: "ips.allow", CLIName: "ips-allow", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS,
		Label: "Never match", Group: GroupIPS, Tier: TierBasic,
		Example: "example.com, 10.0.0.0/8",
		Help: "Names and networks that are carried whatever any other entry says. A name here " +
			"covers everything under it. This is what a wrongly refused connection is fixed " +
			"with, so it beats every entry below, however specific that entry is.",
		get:      func(s *Settings) any { return s.IPSAllow },
		set:      func(s *Settings, v any) { s.IPSAllow = typed[[]string](v) },
		validate: namesOrPrefixes,
	},
	{
		JSONKey: "ips.deny", CLIName: "ips-deny", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS,
		Label: "Always match", Group: GroupIPS, Tier: TierBasic,
		Example: "malware.example.com, 198.51.100.0/24",
		Help: "Names, addresses and networks to match on. A name covers everything under it, " +
			"and an address on its own means that address alone. The list above wins where " +
			"the two disagree.",
		get:      func(s *Settings) any { return s.IPSDeny },
		set:      func(s *Settings, v any) { s.IPSDeny = typed[[]string](v) },
		validate: namesOrPrefixes,
	},
	{
		JSONKey: "ips.intercept", CLIName: "ips-intercept", Kind: KindEnum,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tier: TierAdvanced,
		Label: "Open encrypted connections", Group: GroupIPS,
		Default: DefaultIPSIntercept,
		Options: []EnumOption{
			{Value: IPSInterceptOff, Label: "Never", Help: "Encrypted connections are carried " +
				"as they are. Everything else on this card still applies: the name a connection " +
				"is for is sent in the clear before the encryption starts, and that is what is " +
				"matched against."},
			{Value: IPSInterceptOnly, Label: "Only the ones I name", Help: "Open the " +
				"destinations listed below and carry every other connection untouched. Start " +
				"here: it is one service at a time, and anything you have not named cannot " +
				"break."},
			{Value: IPSInterceptExcept, Label: "All except the ones I name", Help: "Open every " +
				"encrypted connection except the destinations listed below. The list ships " +
				"covering the software that checks its own certificates, and it will not be " +
				"complete: a program that stops working after you turn this on belongs on it."},
		},
		Help: "Read what encrypted connections carry, rather than only the name they are for. " +
			"app-tail does this by ending the connection here and starting its own to the real " +
			"server, presenting a certificate it signed with a root it generated on this " +
			"machine. Nothing accepts that certificate until you install the root yourself, and " +
			"nothing happens here at all until you have read what installing it means and said " +
			"so.",
		get: func(s *Settings) any { return s.IPSIntercept },
		set: func(s *Settings, v any) { s.IPSIntercept = typed[string](v) },
	},
	{
		JSONKey: "ips.interceptAgreed", CLIName: "ips-intercept-agreed", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tier: TierAdvanced,
		Label: "I have read what opening connections means", Group: GroupIPS,
		Help: "Opening connections needs a root certificate installed on this machine. Anything " +
			"that holds its private key can present a certificate for any site on the internet " +
			"that this machine will accept, and that stays true until the root is removed from " +
			"the trust store -- removing app-tail does not remove it. The key is generated here " +
			"and never leaves the machine. Nothing is opened while this is off, whatever the " +
			"setting above says.",
		get: func(s *Settings) any { return s.IPSInterceptAgreed },
		set: func(s *Settings, v any) { s.IPSInterceptAgreed = typed[bool](v) },
	},
	{
		JSONKey: "ips.interceptOnly", CLIName: "ips-intercept-only", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tier: TierAdvanced,
		Label: "Destinations to open", Group: GroupIPS,
		Example: "api.internal.example, 10.8.0.0/16",
		Help: "The destinations opened when the setting above is set to open only what you name. " +
			"A name covers everything under it, and a network covers every address in it. " +
			"Nothing else is opened.",
		get:      func(s *Settings) any { return s.IPSInterceptOnly },
		set:      func(s *Settings, v any) { s.IPSInterceptOnly = typed[[]string](v) },
		validate: namesOrPrefixes,
	},
	{
		JSONKey: "ips.interceptExcept", CLIName: "ips-intercept-except", Kind: KindStringList,
		Restart: RestartNone, Write: WritePatch, Module: ModuleIPS, Tier: TierAdvanced,
		Label: "Destinations to leave alone", Group: GroupIPS,
		Example: "apple.com, banking.example",
		Help: "The destinations left untouched when the setting above is set to open everything " +
			"else. Left empty this is the shipped list, which covers software that checks its " +
			"own certificates and stops working when a connection is opened -- software " +
			"updates, push notifications, messaging clients. Anything written here replaces " +
			"that list rather than adding to it, so start from the shipped one and edit it.",
		get:      func(s *Settings) any { return s.IPSInterceptExcept },
		set:      func(s *Settings, v any) { s.IPSInterceptExcept = typed[[]string](v) },
		validate: namesOrPrefixes,
	},
	{
		JSONKey: "security.enabled", CLIName: "security", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleSecurity, Tray: true,
		Label: "Security settings", Group: GroupSecurity, Tier: TierBasic,
		Help: "Turn on the settings that decide what this device accepts from the tailnet " +
			"and what it reports about itself. Nothing changes until you choose below.",
		get: func(s *Settings) any { return s.SecurityEnabled },
		set: func(s *Settings, v any) { s.SecurityEnabled = typed[bool](v) },
	},
	{
		JSONKey: "interface.enabled", CLIName: "interface", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch, ModuleSwitch: ModuleInterface, Tray: true,
		Label: "Offer the network-interface mode", Group: GroupInterface, Tier: TierBasic,
		Help: "Show the settings for running app-tail on a real network interface. Turning " +
			"this on changes nothing by itself: the interface is created only once you " +
			"also choose the mode below.",
		get: func(s *Settings) any { return s.InterfaceEnabled },
		set: func(s *Settings, v any) { s.InterfaceEnabled = typed[bool](v) },
	},
	{
		JSONKey: "interface.mode", CLIName: "interface-mode", Kind: KindEnum,
		Restart: RestartNode, Write: WritePatch, Module: ModuleInterface,
		Label: "How your networks are reached", Group: GroupInterface, Tier: TierBasic,
		Default: string(NetworkUserspace),
		Options: []EnumOption{
			{
				Value: string(NetworkUserspace), Label: "Inside app-tail only",
				Help: "The tailnet lives in this process. Nothing on the machine changes: no " +
					"interface, no routes, no resolver files, and no administrator rights. " +
					"Other programs reach the tailnet through app-tail's forwards and proxy.",
			},
			{
				Value: string(NetworkTUN), Label: "A network interface for the tailnet",
				Help: "Create a network interface, so every program reaches tailnet addresses " +
					"and MagicDNS names directly with nothing configured. Carries every " +
					"protocol, and carries the tailnet only. Needs the privileged helper " +
					"installed, and takes effect when the node next starts.",
			},
			{
				Value: string(NetworkFabric), Label: "One interface for every connection",
				Help: "Create one network interface carrying every connection at once, " +
					"including two networks that use the same addresses -- app-tail ends each " +
					"connection arriving on it and opens it again inside the right network. " +
					"Only TCP and UDP cross: a ping goes unanswered and every byte passes " +
					"through app-tail. Needs the privileged helper installed.",
			},
		},
		Help: "Which stack your connections are reached over.",
		get:  func(s *Settings) any { return string(s.InterfaceMode) },
		set:  func(s *Settings, v any) { s.InterfaceMode = NetworkMode(typed[string](v)) },
	},
	{
		JSONKey: "interface.name", CLIName: "interface-name", Kind: KindString,
		Restart: RestartNode, Write: WritePatch, Module: ModuleInterface,
		Label: "Interface name", Group: GroupInterface, Tier: TierAdvanced,
		Help: "The name to give the interface, or empty for the platform's default. A fixed " +
			"name is what makes an interface left behind by an unclean exit identifiable, " +
			"which is what `app-tail tun doctor` reports on.",
		get: func(s *Settings) any { return s.InterfaceName },
		set: func(s *Settings, v any) { s.InterfaceName = typed[string](v) },
	},
	{
		JSONKey: "interface.virtualPool", CLIName: "interface-virtual-pool", Kind: KindCidrList,
		Restart: RestartNode, Write: WritePatch, Module: ModuleInterface,
		Label: "Ranges to present moved networks from", Group: GroupInterface, Tier: TierAdvanced,
		Example: "198.18.0.0/15",
		Help: "Where a connection is reached when its own addresses are already taken by " +
			"another connection or by this machine, comma separated. Leave empty for the " +
			"range set aside for exactly this (198.18.0.0/15). Only the one-interface-for-" +
			"every-network mode moves anything: in every other mode nothing is presented " +
			"anywhere but its own addresses.",
		get: func(s *Settings) any { return s.InterfaceVirtualPool },
		set: func(s *Settings, v any) { s.InterfaceVirtualPool = typed[[]netip.Prefix](v) },
	},
	{
		JSONKey: "tailnet.repairRoutes", CLIName: "repair-tailnet-routes", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch,
		Label: "Put the tailnet's route back when it goes missing", Group: GroupTailnet,
		Tier: TierAdvanced, Default: true,
		// Reading where this machine sends tailnet traffic, and putting that route back, is
		// implemented for macOS alone. Everywhere else the watcher has nothing to watch, and
		// a switch that is on and inert is worse than one that is not offered.
		Platforms: []string{"darwin"},
		Help: "Watch for this machine losing the route to the tailnet's address range while " +
			"still carrying the tailnet's addresses, and put that route back on the interface " +
			"already holding them. It is the one fault a tailnet client cannot report: the " +
			"client stays connected and its own probes to every device keep answering, while " +
			"every ordinary program on this machine sends tailnet traffic out of the physical " +
			"network instead and times out. Nothing else is touched -- the range is the " +
			"tailnet's own and the interface has to be one already carrying it.",
		get: func(s *Settings) any { return s.TailnetRouteRepair },
		set: func(s *Settings, v any) { s.TailnetRouteRepair = typed[bool](v) },
	},
	{
		JSONKey: "egress.mode", CLIName: "egress", Kind: KindEnum,
		Restart: RestartNone, Write: WritePatch,
		Label: "Where internet traffic goes", Group: GroupEgress, Tier: TierBasic,
		Default: string(EgressDirect),
		Options: []EnumOption{
			{
				Value: string(EgressDirect), Label: "Out of this machine",
				Help: "Anything your connections do not carry leaves the way it always has, " +
					"over whatever network this machine is on.",
			},
			{
				Value: string(EgressTunnel), Label: "Through one of your connections",
				Help: "Anything your connections do not carry goes out through the connection " +
					"you choose below, so it leaves from there instead of from here. The " +
					"connection has to be able to carry it: a tailnet needs an exit node " +
					"selected on it, and a WireGuard peer needs a default route among its " +
					"allowed addresses.",
			},
			{
				Value: string(EgressMulti), Label: "Shared across several connections",
				Help: "Anything your connections do not carry goes through the connections you " +
					"choose below, either spread between them or chained through all of them -- " +
					"the setting under this one picks which. Nothing falls back to this " +
					"machine's own network: while the chosen connections cannot carry it, the " +
					"traffic waits rather than leaving from here.",
			},
		},
		Help: "Traffic to an address none of your connections carries -- the open internet. " +
			"This does not change what your connections reach; it changes where everything " +
			"else goes.",
		get: func(s *Settings) any { return string(s.EgressMode) },
		set: func(s *Settings, v any) { s.EgressMode = EgressMode(typed[string](v)) },
	},
	{
		JSONKey: "egress.tunnelId", CLIName: "egress-connection", Kind: KindTunnelRef,
		Restart: RestartNone, Write: WritePatch,
		Label: "Connection carrying it", Group: GroupEgress, Tier: TierBasic,
		OptionsFrom: OptionsTunnels,
		Help: "Which connection carries this machine's internet traffic. It is read only " +
			"while the setting above sends it through a connection: leaving a connection " +
			"named here while the traffic goes out directly is what lets someone switch " +
			"back and forth without re-choosing, and it carries nothing until they do.",
		get: func(s *Settings) any { return s.EgressTunnelID },
		set: func(s *Settings, v any) { s.EgressTunnelID = typed[string](v) },
	},
	{
		JSONKey: "egress.multi.shape", CLIName: "egress-shape", Kind: KindEnum,
		Restart: RestartNone, Write: WritePatch,
		Label: "How they carry it", Group: GroupEgress, Tier: TierBasic,
		Default: string(EgressSpreadShape),
		Options: []EnumOption{
			{
				Value: string(EgressSpreadShape), Label: "Spread between them",
				Help: "Each site is given one of the connections and keeps it, so a page and " +
					"everything it loads leave the same way while no single connection sees all " +
					"of it. They all carry traffic at once, each at its own speed.",
			},
			{
				Value: string(EgressCascade), Label: "Chained through all of them",
				Help: "The traffic goes through every connection in the order listed and leaves " +
					"through the last, each one carrying the next one's own packets. The first " +
					"knows who this machine is and not where it went; the last knows where it " +
					"went and not who asked. Every byte is encrypted once per connection and " +
					"waits for every hop, so it is slower than spreading them.",
			},
		},
		Help: "How the connections below carry this machine's internet traffic together. It is " +
			"read only while the setting above shares the traffic across several connections.",
		get: func(s *Settings) any { return string(s.EgressMultiShape) },
		set: func(s *Settings, v any) { s.EgressMultiShape = EgressShape(typed[string](v)) },
	},
	{
		JSONKey: "egress.multi.tunnelIds", CLIName: "egress-connections", Kind: KindTunnelRefList,
		Restart: RestartNone, Write: WritePatch,
		Label: "Connections sharing it", Group: GroupEgress, Tier: TierBasic,
		OptionsFrom: OptionsTunnels,
		Help: "Which connections carry this machine's internet traffic together, in order. " +
			"Spread between them, the order means nothing and leaving the list empty uses every " +
			"connection that is running; chained, it is the order the traffic passes through " +
			"them and the list has to name them. It is read only while the setting above shares " +
			"the traffic, and while it does, traffic is held rather than sent out of this " +
			"machine when these connections cannot carry it.",
		get: func(s *Settings) any { return s.EgressMultiTunnelIDs },
		set: func(s *Settings, v any) { s.EgressMultiTunnelIDs = typed[[]string](v) },
	},
	{
		JSONKey: "egress.killSwitch", CLIName: "kill-switch", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch,
		Label: "Hold it rather than let it out", Group: GroupEgress, Tier: TierBasic,
		Help: "While the connection above cannot carry this machine's internet traffic, hold " +
			"the traffic here instead of letting it out over whatever network this machine is " +
			"on. Nothing falls back: a connection that is down, switched off or not carrying " +
			"stops the traffic rather than leaking it. It is read only while the setting above " +
			"sends the traffic through one connection -- several connections already hold it, " +
			"and sending it out of this machine directly is the setting that says this " +
			"machine's own network is where it goes.",
		get: func(s *Settings) any { return s.EgressKillSwitch },
		set: func(s *Settings, v any) { s.EgressKillSwitch = typed[bool](v) },
	},
	{
		JSONKey: "showTray", CLIName: "show-tray", Kind: KindBool,
		Restart: RestartApp, Write: WritePatch,
		Label: "Show tray icon", Group: GroupApplication, Tier: TierBasic, Tray: true,
		Default: true,
		Help:    "Show the menu-bar or tray icon. Takes effect on the next start.",
		get:     func(s *Settings) any { return s.ShowTray },
		set:     func(s *Settings, v any) { s.ShowTray = typed[bool](v) },
	},
	{
		JSONKey: "autoOpenDashboard", CLIName: "auto-open-dashboard", Kind: KindBool,
		Restart: RestartNone, Write: WritePatch,
		Label: "Open the dashboard on first run", Group: GroupApplication, Tier: TierBasic, Tray: true,
		Default: true,
		Help:    "Open the dashboard in a browser on first run, when nothing is configured yet.",
		get:     func(s *Settings) any { return s.AutoOpenDashboard },
		set:     func(s *Settings, v any) { s.AutoOpenDashboard = typed[bool](v) },
	},
	{
		JSONKey: "startAtLogin", CLIName: "start-at-login", Kind: KindBool,
		Restart: RestartNone, Write: WriteAutostart,
		Label: "Start at login", Group: GroupApplication, Tier: TierBasic, Tray: true,
		Help: "Install a per-user login item so the agent starts when you sign in. " +
			"No administrator rights needed, except on Windows while a network mode that " +
			"needs them is selected: there the item is a scheduled task that starts " +
			"app-tail with those rights, so installing it asks for them once.",
		get: func(s *Settings) any { return s.StartAtLogin },
		// No set: the login item is applied through the autostart endpoint, not the
		// config patch, so the stored bool never diverges from the real item.
	},
	{
		JSONKey: "stateDir", Kind: KindString, Restart: RestartNone, Write: WriteNone,
		Pinnable: []string{EnvStateDir},
		Label:    "State directory", Group: GroupAbout, Tier: TierBasic,
		Help: "Holds the tailnet identity and this configuration. Deleting it forces a " +
			"new sign-in.",
		get: func(s *Settings) any { return s.StateDir },
	},
	{
		JSONKey: "machineId", Kind: KindString, Restart: RestartNone, Write: WriteNone,
		Label: "Machine ID", Group: GroupAbout, Tier: TierBasic,
		Help: "Per-install id the {id} hostname token renders to (read-only).",
		get:  func(s *Settings) any { return s.MachineID },
	},
	{
		JSONKey: "mode.primary", Kind: KindEnum, Restart: RestartNone, Write: WriteNone,
		Derived: true,
		Label:   "Current mode", Group: GroupMode, Tier: TierBasic,
		Options: runModeOptions,
		Help: "Read from the switches below rather than set on its own, so choosing a mode " +
			"and flipping the switches it stands for can never disagree.",
		derive: func(s Settings, _ *Settings) any { return string(PrimaryMode(s)) },
	},
	{
		JSONKey: "dns.zone", CLIName: "dns-zone", Kind: KindString,
		Restart: RestartNone, Write: WritePatch,
		Label: "Name every connection under", Group: GroupDNS, Tier: TierAdvanced,
		Default: DefaultDNSZone, Example: DefaultDNSZone,
		Help: "The parent of every connection's own names: with this at its default, a host " +
			"called db on the connection whose short name is office is db.office.internal. " +
			"It is what lets two networks that use the same addresses both be reached at " +
			"once, since the name says which one you meant and the address cannot. Changing " +
			"it renames every connection's suffix, so anything that already names one has to " +
			"be updated.",
		get:      func(s *Settings) any { return s.DNSZone },
		set:      func(s *Settings, v any) { s.DNSZone = typed[string](v) },
		validate: dnsZone,
	},
}

var (
	// settingsRegistry carries the table's lookups and the machinery every surface
	// derives from; the two maps are its indexes, named here because this package reads
	// them directly.
	settingsRegistry = NewRegistry(settingsFields)
	fieldByJSONKey   = settingsRegistry.byJSONKey
	fieldByCLIName   = settingsRegistry.byCLIName
)

func indexBy[T any](fields []FieldOf[T], key func(FieldOf[T]) string) map[string]FieldOf[T] {
	m := make(map[string]FieldOf[T], len(fields))
	for _, f := range fields {
		if k := key(f); k != "" {
			m[k] = f
		}
	}
	return m
}

// typed converts a value moving through the registry to the type the closure it is
// bound for expects. The registry guarantees the pairing -- a field's kind is what
// decides the type decode, ParseCLIValue and defaultValue produce -- so a mismatch is
// an error in the table above, not a runtime condition. It panics rather than
// substituting a zero value, which would silently store an empty setting under a name
// the user had just set.
func typed[T any](v any) T {
	out, ok := v.(T)
	if !ok {
		var want T
		panic(fmt.Sprintf("config: the settings registry produced a %T where a %T is required", v, want))
	}
	return out
}

// SettingsFields returns the registry. The slice is the authored order.
func SettingsFields() []SettingField { return settingsFields }

// FieldByCLIName looks up a settable field by its CLI/menu name.
func FieldByCLIName(name string) (SettingField, bool) {
	f, ok := fieldByCLIName[name]
	return f, ok
}

// FieldByJSONKey looks up a field by the key the wire uses. Front ends that carry a
// key back from a schema they were handed -- the tray's checkboxes, the dashboard's
// controls -- need this to find out how the setting is written before writing it.
func FieldByJSONKey(key string) (SettingField, bool) {
	f, ok := fieldByJSONKey[key]
	return f, ok
}

// viewKey is where a field lands in the outward view.
func (f FieldOf[T]) viewKey() string {
	if f.ViewKey != "" {
		return f.ViewKey
	}
	return f.JSONKey
}

// declaredDefault is the value the registry authored for this field, or nil when it
// simply starts at the zero of its kind. Lists are copied so a consumer cannot reach
// into the registry's own slice.
func (f FieldOf[T]) declaredDefault() any {
	switch list := f.Default.(type) {
	case []string:
		return slices.Clone(list)
	case []netip.Prefix:
		return slices.Clone(list)
	case []netip.Addr:
		return slices.Clone(list)
	}
	return f.Default
}

// defaultValue is what this field holds in a fresh configuration: its declared
// default, or the zero value of its kind.
func (f FieldOf[T]) defaultValue() any {
	if f.Default == nil {
		return zeroValueOf(f.Kind)
	}
	return f.declaredDefault()
}

// zeroValueOf is the typed zero a field's setter expects when nothing is declared.
func zeroValueOf(k FieldKind) any {
	switch k {
	case KindBool:
		return false
	case KindInt:
		return 0
	case KindStringList, KindTunnelRefList:
		return []string(nil)
	case KindCidrList, KindInterfaceAddrList:
		return []netip.Prefix(nil)
	case KindIPList:
		return []netip.Addr(nil)
	default:
		return ""
	}
}

// BuildSettingsView projects stored settings onto the outward-facing map the API
// returns. Secrets emit only a presence boolean under their view key; a value is
// never included. Every field appears, whether or not its module is on: availability
// is reported by the schema, so a client always finds a value where it expects one.
func BuildSettingsView(s Settings) map[string]any { return settingsRegistry.View(s, &s) }

// ApplySettingsPatch overlays the fields a request carried onto s. A present key is a
// change; an absent key is left alone. Unknown, read-only, autostart-managed and
// unavailable keys are rejected by name, and a secret sent as the redaction mask is
// treated as absent so a dashboard round-trip cannot store the mask as the secret.
func ApplySettingsPatch(s *Settings, patch map[string]json.RawMessage) error {
	before := *s
	// Module switches are applied before the settings they govern, so turning a module
	// on and configuring it in one save works: availability is judged against the
	// configuration the patch is asking for, not the one it started from.
	for _, switchPass := range []bool{true, false} {
		for key, raw := range patch {
			f, ok := fieldByJSONKey[key]
			if !ok {
				return invalid(key, "is not a known setting")
			}
			if (f.ModuleSwitch != ModuleCore) != switchPass {
				continue
			}
			// The settings document is its own module context: the switches that decide
			// what is writable are fields of the very value being patched.
			if err := settingsRegistry.applyField(s, s, f, raw); err != nil {
				return err
			}
		}
		// In the switch pass, so a save that turns a module on and configures it in the
		// same request keeps what it asked for: the shelf is put back first and the
		// patch's own values land on top of it in the pass below.
		if switchPass {
			applyModuleSwitchChanges(s, &before)
		}
	}
	return nil
}

// applyModuleSwitchChanges follows every module switch this patch moved: a module turned
// off has its settings shelved and reset to their defaults, and one turned back on has
// them restored (see shelf.go for why both halves exist).
func applyModuleSwitchChanges(s, before *Settings) {
	for _, sw := range settingsFields {
		if sw.ModuleSwitch == ModuleCore {
			continue
		}
		was, now := typed[bool](sw.get(before)), typed[bool](sw.get(s))
		switch {
		case was && !now:
			s.Shelved = settingsRegistry.shelve(s, sw.ModuleSwitch, s.Shelved)
		case !was && now:
			s.Shelved = settingsRegistry.unshelve(s, sw.ModuleSwitch, s.Shelved)
		}
	}
}

// decode turns a JSON value into the typed value this field's setter expects.
func (f FieldOf[T]) decode(raw json.RawMessage) (any, error) {
	switch f.Kind {
	case KindBool:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("must be a boolean")
		}
		return b, nil
	case KindInt:
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("must be an integer")
		}
		return n, nil
	case KindStringList:
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("must be an array of strings")
		}
		return list, nil
	case KindTunnelRefList:
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("must be an array of connection ids")
		}
		return list, nil
	case KindCidrList:
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("must be an array of networks in CIDR form, such as [\"10.0.0.0/24\"]")
		}
		return ParsePrefixList(list)
	case KindInterfaceAddrList:
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("must be an array of addresses with their network size, such as [\"10.0.0.2/24\"]")
		}
		return ParseInterfaceAddrList(list)
	case KindIPList:
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("must be an array of addresses, such as [\"10.0.0.1\"]")
		}
		return ParseAddrList(list)
	default: // string, secret, secretFile, addrPort, url
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return nil, fmt.Errorf("must be a string")
		}
		return str, nil
	}
}

// ParseCLIValue turns a command-line string into the typed value for this field,
// applying the same tag normalization the env/flag paths use and the same rules the
// API enforces. The reason is returned bare: a CLI caller has already named the
// setting by the time it reports one.
func (f FieldOf[T]) ParseCLIValue(raw string) (any, error) {
	var v any
	switch f.Kind {
	case KindBool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is not a boolean (use true/false)", raw)
		}
		v = b
	case KindInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is not an integer", raw)
		}
		v = n
	case KindStringList:
		v = ParseTags(raw)
	case KindTunnelRefList:
		v = splitList(raw)
	case KindCidrList:
		list, err := ParsePrefixList(splitList(raw))
		if err != nil {
			return nil, err
		}
		v = list
	case KindInterfaceAddrList:
		list, err := ParseInterfaceAddrList(splitList(raw))
		if err != nil {
			return nil, err
		}
		v = list
	case KindIPList:
		list, err := ParseAddrList(splitList(raw))
		if err != nil {
			return nil, err
		}
		v = list
	default:
		v = raw
	}
	if err := f.checkValue(v); err != nil {
		return nil, err
	}
	return v, nil
}

// checkValue applies the format this field's kind declares, its declared bounds, and
// its field-specific rule, returning the bare reason.
func (f FieldOf[T]) checkValue(v any) error {
	if err := checkKindSyntax(f.Kind, v); err != nil {
		return err
	}
	if err := f.checkOption(v); err != nil {
		return err
	}
	if err := f.Constraint.check(v); err != nil {
		return err
	}
	if f.validate != nil {
		return f.validate(v)
	}
	return nil
}

// checkOption refuses a value outside the field's declared set. An empty value is
// accepted for the same reason every other kind accepts one: it means the default
// applies, and a stored document written before the setting existed carries one.
func (f FieldOf[T]) checkOption(v any) error {
	if len(f.Options) == 0 {
		return nil
	}
	value := typed[string](v)
	if value == "" {
		return nil
	}
	names := make([]string, 0, len(f.Options))
	for _, opt := range f.Options {
		if opt.Value == value {
			return nil
		}
		names = append(names, strconv.Quote(opt.Value))
	}
	return fmt.Errorf("must be one of %s, got %q", strings.Join(names, ", "), value)
}

// ValidateValue checks one typed value against everything this field declares. It is
// the single implementation behind the patch decoder, the CLI parser and the document
// validator, so a value one surface accepts is exactly a value the others accept.
func (f FieldOf[T]) ValidateValue(v any) error {
	if err := f.checkValue(v); err != nil {
		return invalid(f.JSONKey, "%v", err)
	}
	return nil
}

// FieldSchema is the serializable projection of a field: everything a consumer
// (the schema endpoint, the generated TypeScript, a third-party client) needs to
// render or drive a setting, with none of the Go closures.
type FieldSchema struct {
	Key          string        `json:"key"`
	ViewKey      string        `json:"viewKey"`
	CLIName      string        `json:"cliName,omitempty"`
	Kind         FieldKind     `json:"kind"`
	Secret       bool          `json:"secret"`
	ReadOnly     bool          `json:"readOnly"`
	Derived      bool          `json:"derived"`
	Restart      RestartClass  `json:"restart"`
	Write        WriteVia      `json:"write"`
	Label        string        `json:"label"`
	Group        Group         `json:"group"`
	Tier         Tier          `json:"tier"`
	Module       FeatureModule `json:"module"`
	ModuleSwitch FeatureModule `json:"moduleSwitch,omitzero"`
	Example      string        `json:"example,omitempty"`
	ExampleFrom  string        `json:"exampleFrom,omitempty"`
	Tray         bool          `json:"tray,omitempty"`
	Options      []EnumOption  `json:"options,omitempty"`
	OptionsFrom  string        `json:"optionsFrom,omitempty"`
	Default      any           `json:"default,omitzero"`
	Constraint   Constraint    `json:"constraint,omitzero"`
	// Variant is the kind of entity this field applies to; empty means all of them. A
	// client renders one entity at a time, so it shows the fields whose variant is empty
	// or matches what it is rendering.
	Variant string `json:"variant,omitempty"`
	// Available is unset in the static schema and resolved in the served one, so a
	// client holding only the generated fallback reads every setting as available.
	Available       *bool  `json:"available,omitempty"`
	AvailableReason string `json:"availableReason,omitempty"`
	// PlatformSupported separates the two reasons a field can be unavailable, because a
	// client that lets a module switch move locally has to know which one it is looking
	// at: a module gate moves with that switch and this one never does. Unset in the
	// static schema for the same reason Available is -- the answer is about the machine
	// serving it, not about the machine the fallback was generated on.
	PlatformSupported *bool    `json:"platformSupported,omitempty"`
	Help              string   `json:"help"`
	Pinnable          []string `json:"pinnable,omitempty"`
	// Deprecated names what replaced this field. A client renders it as a note beside the
	// value rather than as a control, because the field is kept to answer callers who
	// already name it, not to be edited.
	Deprecated string `json:"deprecated,omitempty"`
}

// SettingsSchema is the registry projected to its serializable form, in authored
// order. It is pure: availability depends on stored settings, so it is left unset
// here and this is what the generator renders into the dashboard's fallback copy.
func SettingsSchema() []FieldSchema { return settingsRegistry.Schema() }

// SettingsSchemaFor is SettingsSchema with each field's availability resolved against
// s. It is what GET /api/settings/schema serves, so a client renders exactly the
// settings this configuration can write right now.
func SettingsSchemaFor(s Settings) []FieldSchema { return settingsRegistry.SchemaFor(&s) }

// Impact is what a settings change needs before it is fully in force.
type Impact struct {
	// NodeRestart, UIRelisten and AppRestart are the three restart classes.
	NodeRestart bool
	UIRelisten  bool
	AppRestart  bool
	// Prefs are the changed preferences the running nodes have to be told about. They
	// are named rather than counted because the caller pushes exactly these and reports
	// exactly these as waiting when a node is down, and each one names its connection
	// because the node to push it to is that connection's own.
	Prefs []PrefChange
}

// PrefChange is one pref-backed field of one connection that a change moved. The pair is
// the addressable unit: the same key on two connections is two preferences on two nodes,
// and a push that carried only the key would send one connection's value to whichever
// node the pusher happened to hold.
type PrefChange struct {
	TunnelID string
	Field    TunnelField
}

// ApplyImpact reports what a change from before to after needs to take effect, derived
// from each field's restart class rather than a hand-maintained list.
//
// It never reports preferences. A preference is a value held by a node, and a node is
// what a connection runs, so every pref-backed field is a connection's -- TunnelsImpact
// is where they come from. A guard test keeps the settings table free of them.
func ApplyImpact(before, after Settings) Impact {
	var impact Impact
	for _, f := range settingsFields {
		if f.Restart == RestartNone || f.get == nil {
			continue
		}
		if reflect.DeepEqual(f.get(&before), f.get(&after)) {
			continue
		}
		switch f.Restart {
		case RestartNode:
			impact.NodeRestart = true
		case RestartUI:
			impact.UIRelisten = true
		case RestartApp:
			impact.AppRestart = true
		}
	}
	return impact
}

// TunnelsImpact reports what a change to the connection list needs before it is in force,
// matched by id so a renamed connection is a change rather than a removal and an addition.
//
// A connection that appeared or disappeared is a node restart on its own: the node is
// built from the connection it runs, so one that is not there yet has nothing running it.
//
// A pref-backed field is reported as a preference of its own connection rather than as a
// node restart: it is pushed to the node already running that connection, which is what
// makes changing one a live edit instead of a reconnection.
func TunnelsImpact(before, after []Tunnel) Impact {
	held := make(map[string]Tunnel, len(before))
	for _, t := range before {
		held[t.ID] = t
	}
	var impact Impact
	for _, t := range after {
		old, existed := held[t.ID]
		delete(held, t.ID)
		if !existed {
			impact.NodeRestart = true
			continue
		}
		for _, f := range tunnelFields {
			if f.Restart == RestartNone || f.get == nil || !tunnelRegistry.applies(f, &t) {
				continue
			}
			if reflect.DeepEqual(f.get(&old), f.get(&t)) {
				continue
			}
			switch f.Restart {
			case RestartPrefs:
				impact.Prefs = append(impact.Prefs, PrefChange{TunnelID: t.ID, Field: f})
			case RestartNode:
				impact.NodeRestart = true
			case RestartUI:
				impact.UIRelisten = true
			case RestartApp:
				impact.AppRestart = true
			}
		}
	}
	if len(held) > 0 {
		impact.NodeRestart = true
	}
	return impact
}

// enableModule turns on the switch owning m, so a setting adopted from the node is
// visible and writable rather than stored under a module that reads as off.
func enableModule(s *Settings, m FeatureModule) {
	if sw, ok := moduleSwitchFor(m); ok {
		sw.set(s, true)
	}
}
