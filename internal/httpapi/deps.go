// SPDX-License-Identifier: MIT

package httpapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/sysproxy"
	"github.com/sellitus/app-tail/internal/traffic"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// The interfaces below are defined by this package, the consumer, rather than by
// the packages that implement them. Handlers therefore depend on nothing but these
// method sets, which is what lets the whole API be tested against fakes.

// Node is the tailnet identity as the API needs it.
type Node interface {
	// Status returns cached state; it must not block on the network.
	Status() tsnode.Status
	StartLogin(ctx context.Context) error
	Logout(ctx context.Context) error
	Peers(ctx context.Context) ([]tsnode.Peer, error)
}

// Forwards is the forward registry: stored configuration merged with live status.
//
// The mutating methods take a context because they wait for the forwarding engine to
// catch up before returning, so the view they hand back describes what is actually
// running. A disconnected client cancels that wait instead of holding a goroutine.
type Forwards interface {
	List() []ForwardView
	Get(id string) (ForwardView, error)
	Create(ctx context.Context, spec ForwardSpec) (ForwardView, error)
	Update(ctx context.Context, id string, spec ForwardSpec) (ForwardView, error)
	Delete(ctx context.Context, id string) error
	SetEnabled(ctx context.Context, id string, enabled bool) (ForwardView, error)
	// SuggestPort returns a bindable local port, preferring the given one.
	SuggestPort(protocol config.Protocol, bindAddr string, preferred int) (int, error)
	// AllRunning backs the readiness probe.
	AllRunning() bool
}

// Capability reports whether an optional feature is usable here and, when it is not
// or only partly, why.
//
// Every module answers degradation in this one shape so a client renders "unavailable
// because X" identically everywhere instead of growing a special case per feature.
// Available and Degraded are separate because the interesting state is the third one:
// running, but not doing everything the user expects.
type Capability struct {
	Available bool   `json:"available"`
	Degraded  bool   `json:"degraded"`
	Reason    string `json:"reason,omitempty"`
	// Limits are the things this feature does not do, stated up front. They are not
	// errors and never clear; a user who learns one by hitting it files a bug.
	Limits []string `json:"limits,omitempty"`
}

// Proxy is the tailnet proxy as the API needs it.
//
// PAC and Probe take a context because both read live node state: the script is
// derived from the tailnet's current routes, and a probe dials a real destination.
type Proxy interface {
	Status() tsproxy.Status
	// PAC renders the browser auto-config script for the tailnet's current state.
	PAC(ctx context.Context) (string, error)
	// Probe dials one destination through the proxy and reports what happened, which
	// is the difference between "the proxy is up" and "the proxy can reach that".
	Probe(ctx context.Context, address string) (ProxyProbeResult, error)
}

// ProxyProbeResult is one dial attempted on the caller's behalf. Reachable is the
// answer; ViaTailnet is why, and is what distinguishes a destination the proxy carried
// from one it would have refused had the scope been narrower.
type ProxyProbeResult struct {
	Address    string `json:"address"`
	Reachable  bool   `json:"reachable"`
	ViaTailnet bool   `json:"viaTailnet"`
	// ResolvedAddr is the address the destination classified to, which is the one
	// actually dialed.
	ResolvedAddr string `json:"resolvedAddr,omitempty"`
	// Refused marks a destination the proxy's own rules do not allow, which is why
	// nothing was dialed. It separates "this proxy will not carry that" from "it tried
	// and could not get there", which are different things to fix.
	Refused   bool   `json:"refused,omitempty"`
	Error     string `json:"error,omitempty"`
	ElapsedMs int64  `json:"elapsedMs"`
}

// Presets manages the service-template catalog.
type Presets interface {
	List() []config.Preset
	Create(p config.Preset) (config.Preset, error)
	Delete(id string) error
}

// SettingsAPI reads and writes app settings with secrets redacted on the way out.
// The view and the patch are field maps keyed by the settings registry's JSON keys,
// so the wire shape has exactly one source of truth (config.SettingsFields).
//
// Update takes a context for the same reason the mutating Forwards methods do: it
// waits for the engine to pick the change up, so the view it returns describes what
// is running rather than what is about to be. A disconnected client cancels that wait.
type SettingsAPI interface {
	Get() map[string]any
	Update(ctx context.Context, patch map[string]json.RawMessage) (map[string]any, SettingsUpdateResult, error)
	Schema() []config.FieldSchema
}

// SettingsUpdateResult reports what a settings change needs to fully take effect.
// A live change needs none of these fields. NodeRestart marks node-identity fields an
// in-process node restart applies; UIRelisten marks the dashboard listen address,
// which only a full process restart can move; AppRestart marks a setting the process
// reads once at start, which is stored now and honoured on the next one; AdminRestart
// marks a change that needs administrator rights this process does not hold and can only
// obtain by starting again; AdminRelaunch marks that the process is restarting itself now
// to obtain them, so the caller should expect it to go away and come back; Deferred names
// the settings that were stored but could not be handed to the tailnet node, because it is
// not up.
type SettingsUpdateResult struct {
	NodeRestart   bool
	UIRelisten    bool
	AppRestart    bool
	AdminRestart  bool
	AdminRelaunch bool
	Deferred      []DeferredField
}

// DeferredField is a setting that was stored but is not yet in force. It carries its
// own reason so a client states what is waiting and why, rather than reporting a
// successful save for a change nothing has applied.
type DeferredField struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
}

// RestartNeeded reports whether any kind of restart is still outstanding.
func (r SettingsUpdateResult) RestartNeeded() bool {
	return r.NodeRestart || r.UIRelisten || r.AppRestart || r.AdminRestart
}

// Prefs is the node-preference mirror as the API needs it: which settings this app
// keeps on the tailnet node itself, what the node reports for each, and whether the two
// agree. It is read-only -- these are ordinary settings, written through PUT
// /api/settings like every other one, so a second write path would be a second set of
// validation, redaction and availability rules to keep in step.
type Prefs interface {
	View() PrefsView
}

// PrefsView is the state of the mirror. Fields carries only the settings available in
// this configuration, so a module that is off renders as nothing rather than as a list
// of preferences the user cannot act on.
type PrefsView struct {
	// NodeUp reports whether the node is running; Known reports whether it has told us
	// its preferences yet. They are separate because a node that just came up has no
	// value to compare against, and calling that a disagreement would be a false alarm.
	NodeUp bool `json:"nodeUp"`
	Known  bool `json:"known"`
	// Fields is always an array in the response, empty rather than null: the dashboard
	// reads its length, and a nil slice would marshal to null and blank the page.
	Fields []PrefFieldView `json:"fields"`
	// Conflict names the settings this app has stopped trying to apply because
	// something outside it kept changing them back. It is the one state a user has to
	// resolve elsewhere, so it is reported rather than retried forever.
	Conflict   []string   `json:"conflict,omitempty"`
	Capability Capability `json:"capability"`
}

// PrefFieldView is one pref-backed setting seen from both sides.
type PrefFieldView struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Stored is what this app's settings say; Live is what the node reports, absent
	// until the node has reported anything at all.
	Stored  any  `json:"stored"`
	Live    any  `json:"live,omitempty"`
	InForce bool `json:"inForce"`
}

// Restarter rebuilds the tailnet node in place so node-identity settings apply
// without restarting the whole process. The dashboard listener is untouched, so the
// request serving the restart is not interrupted.
type Restarter interface {
	RestartNode(ctx context.Context) error
}

// TrafficView is what the agent has carried recently, and where.
//
// The rolling series comes from the agent's own sampler rather than from the browser: a
// dashboard stops polling while its tab is hidden, so a history kept there would go blank
// exactly when someone leaves the page open, and start empty again on every reload.
type TrafficView struct {
	// IntervalSec is the tick the samples were taken on, and WindowSec how much history
	// the agent keeps. Both are served so the dashboard draws the axis the agent actually
	// measured rather than one it assumed.
	IntervalSec int `json:"intervalSec"`
	WindowSec   int `json:"windowSec"`
	// Points is one entry per measured interval, oldest first. A point marked Gap could
	// not be measured -- a counter reset, or a machine resumed from sleep -- and a chart
	// must break its line there rather than draw a floor nobody observed.
	Points []traffic.Point `json:"points"`
	// Current is the most recent measured point, skipping gaps, for the headline figures.
	Current traffic.Point `json:"current"`
	// Totals are the cumulative figures the rates were derived from, for the readouts
	// that want "since this started" rather than "right now".
	Totals TrafficTotals `json:"totals"`
	// Peers is what the tailnet carried per device. These are WireGuard's own counters,
	// so they cover every byte the node moved and will not match the proxy's own figures
	// -- neither is wrong, they are counting different things.
	Peers []TrafficPeer `json:"peers"`
	// Destinations is where the proxy's traffic went, busiest first. Other and Folded
	// describe what the cap left unnamed; a list silently cut short reads as a full one.
	Destinations []tsproxy.DestCounters `json:"destinations"`
	Other        tsproxy.DestCounters   `json:"other,omitzero"`
	Folded       int                    `json:"folded,omitempty"`
}

// TrafficTotals are the proxy's cumulative figures, as the dashboard shows them beside
// the live rates.
type TrafficTotals struct {
	ProxyUp   int64 `json:"proxyUp"`
	ProxyDown int64 `json:"proxyDown"`
	Refused   int64 `json:"refused"`
	Failed    int64 `json:"failed"`
}

// TrafficPeer is one tailnet device and what has crossed to and from it.
type TrafficPeer struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Online  bool   `json:"online"`
	Active  bool   `json:"active"`
	RxBytes int64  `json:"rxBytes"`
	TxBytes int64  `json:"txBytes"`
	// Direct reports a path straight to the device; Relay names the DERP region carrying
	// it when there is not one. A device that works and feels slow is usually relayed.
	Direct bool   `json:"direct"`
	Relay  string `json:"relay,omitempty"`
	// ExitNode marks the device this machine's other traffic is leaving through.
	ExitNode bool `json:"exitNode"`
	// LastHandshake is when WireGuard last completed one, absent when it never has. It is
	// the difference between a device that is idle and one that is gone.
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	// LatencyMs is the measured round trip, absent unless latency probing is switched on.
	// Absent means "not measured" rather than "unreachable", and the two lead somewhere
	// different, so nothing here reports a peer that was never probed as slow.
	LatencyMs float64 `json:"latencyMs,omitempty"`
}

// TrafficBreakdown is the same window the view holds, split by whatever one lane names --
// a device, a connection, a destination, a port.
//
// It is served per lane rather than folded into TrafficView because the split is the
// expensive part of the payload and only one lane is ever on screen: a dashboard showing
// devices must not pay every two seconds for the port series nobody is looking at.
type TrafficBreakdown struct {
	// Lane is which breakdown this is, echoed back so a response that arrives after the
	// dashboard has switched away is recognisably about the lane it was asked for.
	Lane string `json:"lane"`
	// IntervalSec is the tick the samples were taken on, and WindowSec how much history the
	// agent keeps. Both match the flat view, which is what lets one hovered column mean the
	// same instant on every chart on the page.
	IntervalSec int `json:"intervalSec"`
	WindowSec   int `json:"windowSec"`
	// Series is one line per key, busiest first, and never more than the chart can tell
	// apart. Everything past that is summed into a single trailing series.
	Series []TrafficSeries `json:"series"`
	// Folded is how many keys are not named individually, whether they were summed into the
	// trailing series or dropped by the agent's own cap. A list silently cut short reads as
	// a complete one.
	Folded int `json:"folded,omitempty"`
	// Unmeasured is why this lane holds nothing, empty when it holds what it can. It is the
	// difference between a network that is quiet and one this agent cannot see: in interface
	// mode packets pass through app-tail's own stack, and in TUN mode they do not, so a port
	// breakdown there is unknowable rather than zero.
	Unmeasured string `json:"unmeasured,omitempty"`
}

// TrafficSeries is one key's rates across the window.
//
// Up and Down are parallel arrays rather than an array of points: a window is three hundred
// entries per key, and the field names repeated on every one of them are most of the bytes
// on the wire. A null entry is an interval that could not be measured -- the key was absent
// at one end of it, or its counters reset -- and a chart breaks its line there rather than
// drawing a floor nobody observed.
type TrafficSeries struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
	// Via is the connection carrying this key and Peer the device it belongs to, each empty
	// where the counter that measured the bytes could not attribute them. They are what the
	// dashboard filters a lane by.
	Via  string     `json:"via,omitempty"`
	Peer string     `json:"peer,omitempty"`
	Up   []*float64 `json:"up"`
	Down []*float64 `json:"down"`
}

// Traffic is the rolling activity view.
type Traffic interface {
	// View reads the peer list, which is a backend call, so it takes a context.
	View(ctx context.Context) TrafficView
	// Breakdown is one lane of the same window. A lane this build does not know is an error
	// rather than an empty breakdown: a typo in a route must not read as a quiet network.
	Breakdown(ctx context.Context, lane string) (TrafficBreakdown, error)
}

// Lifecycle is the process itself, as the API needs it.
//
// Separate from Restarter because the two are different events: one rebuilds the tailnet
// node while the dashboard keeps serving, and this one takes the dashboard down with
// everything else. Only a new binary or a new dashboard address needs the second.
type Lifecycle interface {
	// RestartProcess records the request and returns; it does not wait for the restart,
	// because the connection it would answer on goes away with the process.
	RestartProcess() error

	// StopProcess is the same event without the replacement: the process ends. It is how a
	// second copy of app-tail starting asks this one to hand over, which is the one case
	// where something outside the process needs an orderly shutdown it cannot signal.
	StopProcess() error
}

// InterfaceSetup makes this machine able to carry the network-interface mode, obtaining
// the administrator rights that needs rather than reporting that the caller lacks them.
//
// It is a request rather than a setting because it changes the machine and not this app:
// the mode is a stored setting, and this is the one-time arrangement that lets the mode
// actually take effect. A machine that is already set up is left alone, so the route is
// safe to call again.
type InterfaceSetup interface {
	SetUpInterface(ctx context.Context) error
	// View reads the machine, so it takes a context: what it reports is the state of
	// the helper and the interface right now, not what was true when the node started.
	View(ctx context.Context) InterfaceView
}

// InterfaceView is the network-interface mode as the dashboard sees it: what the machine
// can do, what it is actually doing, and what stands between the two.
//
// Mode and Configured are separate because they disagree in the one case this card exists
// for: a node asked for the interface and got the contained mode instead, which every
// other field on the status reports exactly as a node that asked for nothing.
type InterfaceView struct {
	Enabled bool `json:"enabled"`
	// Mode is the stack the node is really on, and Configured the one the settings ask
	// for -- while the module is off, the one its switch turns on. Both are the setting's
	// own words, so a client renders them with the labels the registry already carries.
	Mode       string `json:"mode"`
	Configured string `json:"configured"`
	// InForce reports that the two agree and the node is up. It is the one line the
	// card leads with, computed here so the dashboard and the tray cannot disagree
	// about what counts as on.
	InForce bool `json:"inForce"`
	// Fallback is why the node is not on the interface it asked for, empty when it is.
	Fallback string `json:"fallback,omitempty"`
	// Ready reports that the mode could be turned on right now, and Blocker says what
	// stands in the way when it could not. They answer only "would switching work",
	// which is what a one-click control needs and is a different question from the
	// Capability sentence beside it: a machine fully ready for the mode with the mode
	// switched off is ready here and degraded there.
	Ready   bool   `json:"ready"`
	Blocker string `json:"blocker,omitempty"`
	// Interface is the name a new interface would get, or the one in use.
	Interface string   `json:"interface,omitempty"`
	Helper    Helper   `json:"helper"`
	Conflict  string   `json:"conflict,omitempty"`
	Missing   string   `json:"missing,omitempty"`
	Leftovers []string `json:"leftovers,omitempty"`
	// Undo are the commands that remove the leftovers by hand, for the case where
	// app-tail is not the thing that will do the cleaning.
	Undo       []string   `json:"undo,omitempty"`
	Capability Capability `json:"capability"`
}

// Helper is the privileged helper as the dashboard sees it. It is reported even where the
// platform has none, because "this platform does not use one" is the answer to the same
// question and a card that omits the row leaves it unanswered.
type Helper struct {
	// Design reports whether this platform runs the privileged side out of process.
	Design bool `json:"design"`
	// Installable reports whether app-tail can install it for you here, which is the
	// difference between offering a button and printing a command to run as root.
	Installable bool   `json:"installable"`
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	Version     string `json:"version,omitempty"`
	Problem     string `json:"problem,omitempty"`
	Socket      string `json:"socket,omitempty"`
}

// Autostart manages the per-user login item.
type Autostart interface {
	Enabled() (bool, error)
	SetEnabled(enabled bool) error
	// Problem describes a login item that is installed but will not start app-tail
	// correctly, and is empty when there is none. It is served alongside the switch
	// because that is the only place a user looks: the fault has no symptom until the
	// next login, and the switch reads as on the whole time.
	Problem() string
}

// PolicyAPI performs the opt-in tailnet ACL bootstrap: it adds the fleet's tags to
// tagOwners (and optionally a grant) using an admin OAuth client the caller supplies
// per request. Preview reports what would change without writing; Apply writes it.
// The credential is used once and never stored, logged, or echoed back.
type PolicyAPI interface {
	Preview(ctx context.Context, req PolicyBootstrapRequest) (PolicyPlanView, error)
	Apply(ctx context.Context, req PolicyBootstrapRequest) (PolicyPlanView, error)
}

// Deps is everything the HTTP server needs. Any nil member degrades that route to
// a clear 503 rather than a panic.
type Deps struct {
	Node      Node
	Tunnels   Tunnels
	Forwards  Forwards
	Presets   Presets
	Settings  SettingsAPI
	Interface InterfaceSetup
	Autostart Autostart
	Policy    PolicyAPI
	Restart   Restarter
	Lifecycle Lifecycle
	Traffic   Traffic
	Proxy     Proxy
	Proxies   Proxies
	AutoMap   AutoMap
	SysProxy  SystemProxy
	Prefs     Prefs
	ExitNode  ExitNode
	Routes    Routes
	Routing   Routing
	Fabric    Fabric
	Egress    Egress
	Lock      Lock
	DNS       DNS
	Profiles  DNSProfiles
	DNSBlock  DNSBlock
	IPS       IPS
	Telemetry Telemetry
	Version   string
	// ConfigQuarantine is the stored document this run had to move aside to start, or nil
	// when the stored configuration loaded. It is a value rather than an interface
	// because it is settled before the API exists and cannot change while the process
	// runs: the document was replaced once, on load.
	ConfigQuarantine *ConfigQuarantineView
	// Dashboard answers where the management interface landed. It is an interface rather
	// than a value because the answer is settled by the bind, which happens after this
	// server is built.
	Dashboard Dashboard
	// Approvals is what this machine refused for want of an administrator's approval, and
	// the way to ask for it.
	Approvals Approvals
}

// Approvals is the changes this machine's privileged side refused because an administrator
// has not approved them.
type Approvals interface {
	// Pending is what is waiting, or nil when nothing is.
	Pending() *ApprovalsView
	// Approve asks an administrator to approve everything waiting and tries the refused
	// features again, returning what is still waiting afterwards. What is approved is the
	// agent's own list, never anything a caller names: the prompt has to describe exactly the
	// changes this machine asked for. A dismissed prompt is ErrApprovalDeclined; a machine
	// where app-tail cannot raise one is an error made by ApprovalByHand.
	Approve(ctx context.Context) (ApprovalsView, error)
}

// ApprovalsView is every approval waiting, and the command an administrator can run instead
// of the prompt.
type ApprovalsView struct {
	Needs   []grants.PendingNeed `json:"needs"`
	Command string               `json:"command"`
}

// ConfigQuarantineView is a configuration document this build could not use, and where it
// was kept. The dashboard shows it because the settings on screen are not the ones the
// user left behind, and nothing else on any page would say so.
type ConfigQuarantineView struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

// Dashboard is where the management interface actually is, as against where the settings
// ask for it to be.
type Dashboard interface {
	// Moved reports the configured address the dashboard could not have and the one it is
	// on instead, or nil when it is where it was asked to be.
	Moved() *DashboardMovedView
}

// DashboardMovedView is a dashboard on an address nobody chose. The settings screen keeps
// showing the configured address, which is the one the next start asks for again, so this
// is what says where the running agent actually is.
type DashboardMovedView struct {
	Configured string `json:"configured"`
	Bound      string `json:"bound"`
	Reason     string `json:"reason"`
}

// Lock is tailnet lock as the API needs it.
//
// It is not behind a module switch and has no setting: lock is turned on for a whole
// tailnet by an administrator, and this device only reports what that means for it. The
// state it explains -- a node that reports Running with an empty device list because its
// key is unsigned -- reaches a user who enabled nothing at all, which is exactly why it
// cannot be opt-in.
type Lock interface {
	// View reads live backend state, so it takes a context.
	View(ctx context.Context) LockView
	// Log reads the tailnet's key authority log, which is a separate call because it is
	// fetched when someone opens it rather than on every poll.
	Log(ctx context.Context) ([]LockUpdate, error)
	// Sign authorizes another device, which only a device holding a trusted key may do.
	Sign(ctx context.Context, nodeKey, rotationKey string) error
	// DisableLocal forgets this device's own copy of the lock state. It changes nothing
	// for the tailnet and nothing for any other device.
	DisableLocal(ctx context.Context) error
}

// LockView is what tailnet lock means for this device.
//
// SignCommand is built here rather than in a client: it is the exact command an
// administrator runs on another device, and a dashboard that assembled it from the two
// keys would be the second place its shape is written down.
type LockView struct {
	// Enabled reports lock turned on for the tailnet. Everything else here is worth
	// showing only while it is true.
	Enabled bool `json:"enabled"`
	// Signed reports this device authorized. False while Enabled is the cut-off state:
	// the node connects, reports Running, and can reach nothing.
	Signed bool `json:"signed"`
	// NodeKey and LockKey are this device's own keys, in the form the command below
	// takes them.
	NodeKey string `json:"nodeKey,omitempty"`
	LockKey string `json:"lockKey,omitempty"`
	// SignCommand is what to run on a device that holds a trusted key, ready to copy.
	SignCommand string `json:"signCommand,omitempty"`
	// Trusted are the keys the tailnet lets change lock state.
	Trusted []LockKeyView `json:"trusted,omitempty"`
	// CanSign reports this device holding one of them, which is the only condition under
	// which it may authorize another device.
	CanSign bool `json:"canSign"`
	// Visible counts the devices lock let through; Filtered are the ones it removed,
	// which are unreachable however the tailnet's ACLs read.
	Visible    int            `json:"visible"`
	Filtered   []LockPeerView `json:"filtered,omitempty"`
	Head       string         `json:"head,omitempty"`
	Error      string         `json:"error,omitempty"`
	Capability Capability     `json:"capability"`
}

// LockKeyView is one key trusted to change tailnet lock.
type LockKeyView struct {
	ID    string `json:"id"`
	Kind  string `json:"kind,omitempty"`
	Votes int    `json:"votes"`
	// Self reports this device holding the key.
	Self bool `json:"self"`
	// Label is what the tailnet recorded against the key, rendered as a phrase -- a
	// pre-auth key is the common one, and it is the difference between a key a person
	// holds and one a script does.
	Label string `json:"label,omitempty"`
}

// LockPeerView is a device tailnet lock removed from this one's view of the tailnet.
type LockPeerView struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	NodeKey string   `json:"nodeKey"`
	IPs     []string `json:"ips,omitempty"`
}

// LockUpdate is one entry in the tailnet's key authority log.
type LockUpdate struct {
	Hash   string `json:"hash"`
	Change string `json:"change"`
}

// DNS is name resolution as the API needs it, both halves of it: what app-tail itself
// resolves with, and what this whole machine resolves with.
//
// SetUpSystem is the one write, and it is a write about the machine rather than about a
// setting: which resolver to use is an ordinary registry field written through PUT
// /api/settings, and this is the one-time arrangement of administrator rights that lets the
// choice take effect. A machine already set up is left alone, so it is safe to call again.
type DNS interface {
	// View reads live backend state, so it takes a context.
	View(ctx context.Context) DNSView
	SetUpSystem(ctx context.Context) error
}

// DNSProfiles manages the resolver catalog: the shipped entries plus the user's own.
type DNSProfiles interface {
	List() []config.DNSProfile
	Create(p config.DNSProfile) (config.DNSProfile, error)
	// Update replaces a user profile in place. The id stays the same, so a profile the
	// settings point at keeps working across an edit.
	Update(id string, p config.DNSProfile) (config.DNSProfile, error)
	// Delete removes a user profile. It takes a context because the machine has to be put
	// back before the profile describing what it was pointed at goes away.
	Delete(ctx context.Context, id string) error
}

// DNSBlock is name blocking: which lists are on, what each contributed, and the controls
// that do not belong in the settings document -- refreshing now and pausing for a while.
type DNSBlock interface {
	// View reads the compiled matcher and the cached copies on disk.
	View() DNSBlockView
	// Refresh downloads every enabled list now, whether or not it is due.
	Refresh(ctx context.Context) error
	// Pause stops blocking for a while and returns when it ends. Resume ends it early.
	Pause(d time.Duration) time.Time
	Resume()
	// Check reports whether one name is blocked and by what, which is the answer neither
	// the list of lists nor the counters can give.
	Check(name string) DNSBlockCheckView
	// ApplyPreset switches on exactly the shipped lists one rung of the ladder names,
	// keeping the lists the user added on: those are theirs, and no rung claims them.
	ApplyPreset(ctx context.Context, id string) error

	// CreateList, UpdateList and DeleteList manage the user's own entries. A built-in is
	// refused by all three: it ships with the binary and can only be switched on and off.
	CreateList(l config.Blocklist) (config.Blocklist, error)
	UpdateList(id string, l config.Blocklist) (config.Blocklist, error)
	DeleteList(ctx context.Context, id string) error
}

// DNSBlockView is name blocking as every surface reads it.
//
// Own and System are separate because they are separate switches, and what each reaches is
// different: Own is what app-tail resolves for itself, System is what this machine
// resolves, and neither implies the other.
type DNSBlockView struct {
	Enabled bool `json:"enabled"`
	Own     bool `json:"own"`
	System  bool `json:"system"`
	// Answer is what a blocked name is answered with: "nxdomain", "sinkhole" or "refused".
	Answer string `json:"answer"`
	// Rules is how many names the compiled matcher holds, and Lists what each entry
	// contributed. CompiledAt is when that matcher was built.
	Rules      int                `json:"rules"`
	Lists      []DNSBlockListView `json:"lists,omitempty"`
	CompiledAt string             `json:"compiledAt,omitempty"`
	// Presets is the curated ladder, lowest first, and Preset the rung the shipped lists
	// that are on happen to be. Preset is empty for a set that is nobody's rung, which is
	// what switching one list on top of a rung produces and is a state in its own right
	// rather than an error.
	Presets []DNSBlockPresetView `json:"presets,omitempty"`
	Preset  string               `json:"preset,omitempty"`
	// PausedUntil is when a pause ends, and is empty while blocking is running.
	PausedUntil string `json:"pausedUntil,omitempty"`
	// RefreshHours is how often lists are re-downloaded, and NextRefresh when the oldest
	// enabled copy is next due.
	RefreshHours int    `json:"refreshHours"`
	NextRefresh  string `json:"nextRefresh,omitempty"`
	// Blocked is how many queries this machine's resolver refused, which is zero while the
	// machine-wide resolver is off however much app-tail blocked for itself.
	Blocked uint64 `json:"blocked"`
	// Allow and Deny are the two lists the user typed, repeated here so the card can show
	// them beside the lists they override.
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
	// RetryOnNXDOMAIN reports the machine-wide resolver's retry switch being on, which
	// sends a blocked name to this network as well and so unblocks it.
	RetryOnNXDOMAIN bool       `json:"retryOnNxdomain"`
	Error           string     `json:"error,omitempty"`
	Capability      Capability `json:"capability"`
}

// DNSBlockPresetView is one rung of the curated ladder: what it is called, what it is for,
// and every shipped list it turns on.
type DNSBlockPresetView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
	// Recommended marks the rung to pick without reading the rest. Exactly one carries it.
	Recommended bool     `json:"recommended,omitempty"`
	Lists       []string `json:"lists"`
}

// DNSBlockListView is one catalog entry and what its downloaded copy contributed.
type DNSBlockListView struct {
	ID string `json:"id"`
	// Provider is who publishes the list, and is what every surface groups the catalog by:
	// a publisher's tiers under one heading are a choice, while forty flat rows are a wall.
	// A list the user added carries the group they all share.
	Provider string `json:"provider"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Format   string `json:"format,omitempty"`
	BuiltIn  bool   `json:"builtIn"`
	Enabled  bool   `json:"enabled"`
	// Rules is how many names this list contributed and Skipped how many of its rules mean
	// nothing to a resolver. The pair is what says whether a list is pulling its weight
	// here or is mostly written for a browser.
	Rules   int `json:"rules"`
	Skipped int `json:"skipped"`
	Bytes   int `json:"bytes,omitempty"`
	// UpdatedAt is when the copy on disk was last confirmed current, and Error what went
	// wrong last time. A list carrying both is one that is still blocking from a copy that
	// has stopped being updated.
	UpdatedAt string `json:"updatedAt,omitempty"`
	Error     string `json:"error,omitempty"`
	// Note is what this list is, and where it applies the caveat that it was written for a
	// browser rather than for a resolver.
	Note string `json:"note,omitempty"`
}

// DNSBlockCheckView is why one name is or is not blocked.
type DNSBlockCheckView struct {
	Name    string `json:"name"`
	Blocked bool   `json:"blocked"`
	// List is what stopped it, empty when nothing did. Reason says why in words, including
	// the reasons that are not a list: blocking off, or paused.
	List   string `json:"list,omitempty"`
	Reason string `json:"reason"`
}

// IPS is traffic inspection: what the compiled rules hold, what they have matched, and the
// controls that do not belong in the settings document -- refreshing now and pausing for a
// while.
type IPS interface {
	// View reads the compiled rules, the downloaded feeds and the ring of recent matches.
	View() IPSView
	// Refresh downloads every enabled feed now, whether or not it is due.
	Refresh(ctx context.Context) error
	// Pause stops inspection for a while and returns when it ends. Resume ends it early.
	// A pause takes effect on the next connection rather than on the next reconcile: it is
	// asked for because something is broken right now.
	Pause(d time.Duration) time.Time
	Resume()
	// Check reports what the rules say about one destination -- a name or an address --
	// without a connection having to be made to find out.
	Check(dest string) IPSCheckView
	// ApplyPreset switches on exactly the shipped feeds one rung of the ladder names,
	// keeping the feeds the user added on: those are theirs, and no rung claims them.
	ApplyPreset(ctx context.Context, id string) error

	// CreateFeed, UpdateFeed and DeleteFeed manage the user's own entries. A built-in is
	// refused by all three: it ships with the binary and can only be switched on and off.
	CreateFeed(f config.IPSFeed) (config.IPSFeed, error)
	UpdateFeed(id string, f config.IPSFeed) (config.IPSFeed, error)
	DeleteFeed(ctx context.Context, id string) error

	// RemoveInterceptRoot deletes the interception root's certificate and key and drops it
	// from memory. It is refused, as a config.ValidationError, while interception is switched
	// on, because a fresh root would be generated on the next reconcile. Taking the root out
	// of the trust store is the caller's: app-tail cannot change what the machine trusts.
	RemoveInterceptRoot() error
}

// IPSView is traffic inspection as every surface reads it.
//
// Names and Destinations are separate because they are separate switches reaching different
// things: Names is what a program asked for, which only the proxy knows, and Destinations is
// the address a flow is bound for, which every path knows.
type IPSView struct {
	Enabled bool `json:"enabled"`
	// Mode is what a match leads to: "detect" records it and carries the connection,
	// "prevent" refuses it.
	Mode         string `json:"mode"`
	Names        bool   `json:"names"`
	Destinations bool   `json:"destinations"`
	// Anomaly is the signal that reads a run of connections rather than any one of them.
	// It matches against no list, so it is on or off independently of Rules being zero.
	Anomaly bool `json:"anomaly"`
	// Handshake is whether the opening bytes of a connection are read, which is where the
	// name lives on traffic that was dialled straight at an address. Fingerprints is whether
	// the software that sent them is noted alongside; it needs Handshake.
	Handshake    bool `json:"handshake"`
	Fingerprints bool `json:"fingerprints"`
	// Payload is whether those same opening bytes are read against the user's own byte
	// patterns, and Signatures how many of those are in force. The patterns themselves are
	// never carried here: they are often the thing the user is watching for a leak of, and a
	// view that repeated them would put them in every response this endpoint serves.
	Payload    bool `json:"payload"`
	Signatures int  `json:"signatures"`
	// Rules is how many entries the compiled matcher holds and CompiledAt when it was built.
	Rules      int    `json:"rules"`
	CompiledAt string `json:"compiledAt,omitempty"`
	// Feeds is every catalog entry and what its downloaded copy contributed. RefreshHours is
	// how often they are re-downloaded and NextRefresh when the oldest enabled copy is due.
	Feeds        []IPSFeedView `json:"feeds,omitempty"`
	RefreshHours int           `json:"refreshHours"`
	NextRefresh  string        `json:"nextRefresh,omitempty"`
	// Presets is the curated ladder, lowest first, and Preset the rung the shipped feeds that
	// are on happen to be. Preset is empty for a set that is nobody's rung, which is what
	// switching one feed on top of a rung produces and is a state in its own right rather than
	// an error.
	Presets []IPSPresetView `json:"presets,omitempty"`
	Preset  string          `json:"preset,omitempty"`
	// Skipped is how many entries the matcher could make nothing of. They are dropped
	// rather than refused, so without this a typed entry that is neither a name nor an
	// address would simply never match and nothing would say why.
	Skipped int `json:"skipped"`
	// PausedUntil is when a pause ends, and is empty while inspection is running.
	PausedUntil string `json:"pausedUntil,omitempty"`
	// Matched is how many connections the rules have matched and Refused how many of those
	// were stopped. The two differ by every match that landed while the mode was detect.
	Matched int64 `json:"matched"`
	Refused int64 `json:"refused"`
	// Anomalies is how many runs of connections have read as unusual. It is counted apart
	// from Matched because it names no entry anybody wrote: the two answer different
	// questions and adding them together would answer neither.
	Anomalies int64 `json:"anomalies"`
	// Allow and Deny are the two lists the user typed, repeated here so the card can show
	// them beside what they have matched.
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
	// Recent is the newest matches first, held in the agent rather than read from the
	// activity log: that log is off until a user turns it on, and this card has to work on
	// a fresh install.
	Recent []IPSDetectionView `json:"recent,omitempty"`
	// Beacons are destinations something keeps going back to on a rhythm. They are kept
	// apart from Recent because they are an observation and nothing else: on an ordinary
	// machine the regular things are chat clients, backups and certificate checks, so no
	// threshold separates those from a program checking in, and none of them is ever
	// refused or counted as a finding.
	Beacons []IPSBeaconView `json:"beacons,omitempty"`
	// Error is what the last round of downloads ended with, empty when it ended cleanly.
	Error string `json:"error,omitempty"`
	// Intercept is the state of opening encrypted connections, which is the one part of
	// inspection that changes what the program at the far end sees.
	Intercept  IPSInterceptView `json:"intercept"`
	Capability Capability       `json:"capability"`
}

// IPSInterceptView is the state of opening encrypted connections, as every surface reads it.
//
// It carries no key and never will: what is here is the public certificate's path and its
// fingerprint, which are what a user checks against their own trust store.
type IPSInterceptView struct {
	// Mode is which connections are opened: "off", "only" the ones named, or everything
	// "except" the ones named. Agreed is whether the person using this machine has said they
	// understand what opening a connection means; without it nothing is opened whatever the
	// mode says, and the card has to be able to say which of the two is missing.
	Mode   string `json:"mode"`
	Agreed bool   `json:"agreed"`
	// On is every setting asking for interception: the module, the agreement and a mode
	// that is not off. It differs from Running while a root cannot be used, and it is what
	// removing the root is refused on.
	On bool `json:"on"`
	// Running is every condition being met and a root being held: the one field that answers
	// "is this happening right now".
	Running bool `json:"running"`
	// Destinations is how many entries the list in force holds, and Shipped whether that list
	// is the one app-tail ships rather than one the user wrote.
	Destinations int  `json:"destinations"`
	Shipped      bool `json:"shipped"`
	// CertPath is where the certificate to install is written, Fingerprint its SHA-256 and
	// Expires when it stops being usable. The fingerprint is what a user compares against
	// what their trust store holds: the name in it is the same on every machine.
	CertPath    string `json:"certPath"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Expires     string `json:"expires,omitempty"`
	// RootScope is what the root can sign for, as the end of a sentence beginning "This root
	// can sign for": its name constraints, which every client trusting it enforces whoever
	// holds the key.
	RootScope string `json:"rootScope,omitempty"`
	// NeedsNewRoot is the list being intercepted reaching past what the root was made for, or
	// the root carrying no limits at all. Destinations it cannot sign for are carried
	// untouched until it is removed and a new one installed; NewRootReason is the sentence
	// saying so.
	NeedsNewRoot  bool   `json:"needsNewRoot"`
	NewRootReason string `json:"newRootReason,omitempty"`
	// ExpiresSoon is the root being within thirty days of its end, and Expired it being past
	// it. ExpiryWarning is the sentence saying which and what to do. A root is never replaced
	// on its own: the old one is in the trust store, and only the user can take it out.
	ExpiresSoon   bool   `json:"expiresSoon"`
	Expired       bool   `json:"expired"`
	ExpiryWarning string `json:"expiryWarning,omitempty"`
	// RootError is why the root files could not be read, empty when they could or are absent.
	RootError string `json:"rootError,omitempty"`
	// AwaitingApproval is why interception is switched on and not running because an
	// administrator has not approved it, and ApprovalError why the approvals could not be read
	// to find out. Both are empty when interception is approved or switched off.
	AwaitingApproval string `json:"awaitingApproval,omitempty"`
	ApprovalError    string `json:"approvalError,omitempty"`
	// Installed is whether this machine's trust store accepts the root right now, asked of
	// the machine rather than remembered. It is how a user knows an install worked, and the
	// only way to know a removal did.
	Installed bool `json:"installed"`
	// Install and Remove are the commands for this operating system, and Note what they do
	// not cover.
	Install string `json:"install,omitempty"`
	Remove  string `json:"remove,omitempty"`
	Note    string `json:"note,omitempty"`
	// Opened is how many connections have been opened, and Failed how many were stopped
	// because they could not be. The second is the number that matters: it counts the
	// connections interception broke.
	Opened int64 `json:"opened"`
	Failed int64 `json:"failed"`
}

// IPSPresetView is one rung of the curated ladder: what it is called, what it is for, and
// every shipped feed it turns on.
type IPSPresetView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
	// Recommended marks the rung to pick without reading the rest. Exactly one carries it.
	Recommended bool     `json:"recommended,omitempty"`
	Feeds       []string `json:"feeds"`
}

// IPSFeedView is one catalog entry and what its downloaded copy contributed.
//
// It carries no format, unlike a DNSBlockListView: every feed of this kind is one address or
// one network per line, so there is nothing to choose.
type IPSFeedView struct {
	ID string `json:"id"`
	// Provider is who publishes the feed, and is what every surface groups the catalog by. A
	// feed the user added carries the group they all share.
	Provider string `json:"provider"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	BuiltIn  bool   `json:"builtIn"`
	Enabled  bool   `json:"enabled"`
	// Rules is how many networks this feed contributed and Skipped how many of its entries
	// name a private, reserved or tailnet range. The pair matters here: a feed carrying
	// bogons would otherwise refuse this machine's own traffic, and Skipped is what says it
	// did not.
	Rules   int `json:"rules"`
	Skipped int `json:"skipped"`
	Bytes   int `json:"bytes,omitempty"`
	// UpdatedAt is when the copy on disk was last confirmed current, and Error what went
	// wrong last time. A feed carrying both is one that is still matching from a copy that
	// has stopped being updated.
	UpdatedAt string `json:"updatedAt,omitempty"`
	Error     string `json:"error,omitempty"`
	// Note is what this feed is, and where it applies the caveat that it is broad enough to
	// stop traffic a user wanted.
	Note string `json:"note,omitempty"`
}

// IPSBeaconView is one destination reached on a rhythm, most regular first.
type IPSBeaconView struct {
	// Source is the device doing it, which for this machine's own traffic is this machine,
	// and Addr what it keeps going back to.
	Source string `json:"source"`
	Addr   string `json:"addr"`
	// Every is the average gap between connections in seconds, and Jitter how much they
	// vary as a fraction of it: nearer zero is more regular.
	Every  float64 `json:"every"`
	Jitter float64 `json:"jitter"`
	// Count is how many connections the rhythm was measured over, and Since when the first
	// of them was.
	Count int    `json:"count"`
	Since string `json:"since"`
}

// IPSDetectionView is one match: what matched, where the connection was being carried, and
// whether it was stopped.
type IPSDetectionView struct {
	At     string `json:"at"`
	Signal string `json:"signal"`
	Value  string `json:"value"`
	Source string `json:"source"`
	Reason string `json:"reason"`
	// Where names the path that was carrying it, and Protocol what it was carrying, where
	// the path distinguishes them.
	Where    string `json:"where"`
	Protocol string `json:"protocol,omitempty"`
	// Peer is the device that asked, which only an inbound connection from the tailnet has.
	Peer string `json:"peer,omitempty"`
	// Fingerprint is which family of TLS software opened the connection, on a match read from
	// the opening bytes with fingerprinting on. Nothing is ever matched on it.
	Fingerprint string `json:"fingerprint,omitempty"`
	Refused     bool   `json:"refused"`
}

// IPSCheckView is what the rules say about one destination.
//
// Matched and Refused are separate for the same reason the counters are: in detect mode a
// destination matches and is still carried, and a check that reported only one of the two
// would be answering a different question than the one asked.
type IPSCheckView struct {
	Destination string `json:"destination"`
	Matched     bool   `json:"matched"`
	Refused     bool   `json:"refused"`
	Signal      string `json:"signal,omitempty"`
	Value       string `json:"value,omitempty"`
	Source      string `json:"source,omitempty"`
	// Reason says why in words, including the reasons that are not a rule: inspection off,
	// paused, or the signal this destination would match on being switched off.
	Reason string `json:"reason"`
}

// DNSView puts what the tailnet publishes beside what this machine actually resolves
// with, because the gap between the two is the whole question a DNS panel answers: a
// name the tailnet serves does not resolve in a browser, and nothing else says why.
type DNSView struct {
	// Enabled is the module switch; Using reports this app's own resolver actually
	// pointed at the tailnet.
	Enabled bool `json:"enabled"`
	Using   bool `json:"using"`
	// MagicDNS reports the tailnet resolving its own device names.
	MagicDNS bool `json:"magicDNS"`
	// Resolvers, SearchDomains and Routes are what the tailnet publishes. Routes are the
	// split-DNS suffixes: the names that resolve here and nowhere else on the machine.
	Resolvers     []string       `json:"resolvers,omitempty"`
	SearchDomains []string       `json:"searchDomains,omitempty"`
	Routes        []DNSRouteView `json:"routes,omitempty"`
	// Records are extra names the tailnet serves beyond its devices.
	Records []DNSRecordView `json:"records,omitempty"`
	// Machine is this machine's own resolver configuration, when app-tail manages one.
	// MachineReason says why there is none, which in the mode app-tail ships in is the
	// answer rather than a failure.
	Machine       *DNSMachineView `json:"machine,omitempty"`
	MachineReason string          `json:"machineReason,omitempty"`
	// ExitNodeResolving reports names being looked up by the exit node rather than from
	// here, which is the property people choose an exit node for and cannot otherwise
	// confirm. ExitNodeLabel names that device.
	ExitNodeResolving bool   `json:"exitNodeResolving"`
	ExitNodeLabel     string `json:"exitNodeLabel,omitempty"`
	// System is the machine-wide resolver: which resolver every program on this machine is
	// using, and whether app-tail is the one answering. It is a pointer so a client or a
	// fixture written before this existed reads it as absent rather than as a block of
	// zeroes claiming the module is off.
	System     *DNSSystemView `json:"system,omitempty"`
	Error      string         `json:"error,omitempty"`
	Capability Capability     `json:"capability"`
}

// DNSSystemView is the machine-wide resolver as the dashboard, the tray and the CLI all
// read it.
//
// Enabled and Applied are separate for the reason they are on the proxy card: the switch
// being on and this machine actually resolving through app-tail differ whenever the
// platform, the administrator rights or the chosen profile got in the way, and collapsing
// them is what turns a stated limitation into a bug report.
type DNSSystemView struct {
	Enabled bool `json:"enabled"`
	Applied bool `json:"applied"`
	// Profile is the id of the chosen profile and ProfileLabel its name. Servers are its
	// resolvers as the user wrote them, and Protocols the ways they are reached -- "plain",
	// "tls", "https" -- which is the one thing the address alone does not make obvious.
	Profile      string   `json:"profile"`
	ProfileLabel string   `json:"profileLabel,omitempty"`
	Servers      []string `json:"servers,omitempty"`
	Protocols    []string `json:"protocols,omitempty"`
	// Listen is the loopback address app-tail answers DNS on, which is what this machine's
	// own resolver setting is pointed at while the override is in force.
	Listen string `json:"listen,omitempty"`
	// Base is what this machine resolves with underneath app-tail: the network's own
	// resolvers, which is where a name belonging to this network still goes.
	Base *DNSBaseView `json:"base,omitempty"`
	// LocalSuffixes are the domains sent to the network rather than to the profile: the
	// ones the user listed plus the ones this network published.
	LocalSuffixes []string `json:"localSuffixes,omitempty"`
	// RetryOnNXDOMAIN reports the switch that sends a name the profile says does not exist
	// to the network as well. It is reported because it is the one setting here that
	// weakens a filtering resolver.
	RetryOnNXDOMAIN bool `json:"retryOnNxdomain"`
	// Ready reports that the machine could carry this right now, and Blocker what stands in
	// the way when it cannot -- the same pair the network-interface card uses, answering
	// only "would switching this on work".
	Ready   bool   `json:"ready"`
	Blocker string `json:"blocker,omitempty"`
	// NeedsSetup reports administrator rights not yet arranged, which is the one blocker a
	// button can fix (POST /api/dns/setup).
	NeedsSetup bool `json:"needsSetup"`
	// Unreachable is the chosen profile answering nothing at all. It is the captive-portal
	// shape: every name fails while the network's own sign-in page still resolves.
	Unreachable string `json:"unreachable,omitempty"`
	// Intercepted is this network answering plain DNS on its own behalf, checked only for
	// a profile that has a plain resolver in it. It is reported because it is the one state
	// where everything looks like it worked and none of the queries reached the resolver
	// that was picked.
	Intercepted string `json:"intercepted,omitempty"`
	// Bootstrap is how the resolvers in this profile that are named by hostname were turned
	// into addresses, and empty when none of them are. The two paths are not equivalent --
	// an encrypted bootstrap decides the address by certificate, the fallback to this
	// network's own resolvers lets the network decide it -- so which one happened is stated.
	Bootstrap string `json:"bootstrap,omitempty"`
	// BootstrapDegraded is that fallback having happened without the user asking for it,
	// which is a warning rather than a note. Choosing this network's resolvers deliberately
	// is a decision, and reporting a decision as a fault teaches the reader to ignore the
	// warning that matters.
	BootstrapDegraded bool `json:"bootstrapDegraded,omitempty"`
	// Queries are the counters since app-tail started answering.
	Queries    DNSSystemStats `json:"queries"`
	Error      string         `json:"error,omitempty"`
	Capability Capability     `json:"capability"`
}

// DNSBaseView is what this machine would resolve with if app-tail were not here.
type DNSBaseView struct {
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"searchDomains,omitempty"`
}

// DNSSystemStats is where this machine's queries went. Answered is the ones app-tail
// answered itself -- the loopback zone, a malformed query -- and Failed the ones nobody
// could answer, which is the number that means something is wrong.
type DNSSystemStats struct {
	Total     uint64 `json:"total"`
	ToProfile uint64 `json:"toProfile"`
	ToLocal   uint64 `json:"toLocal"`
	Answered  uint64 `json:"answered"`
	Failed    uint64 `json:"failed"`
	// Blocked is the subset of Answered that a blocklist stopped, so the counters still sum
	// to Total.
	Blocked uint64 `json:"blocked"`
}

// DNSRouteView is one split-DNS suffix and whoever answers for it.
type DNSRouteView struct {
	Suffix string `json:"suffix"`
	// Resolvers is empty when the tailnet's own resolver answers for the suffix.
	Resolvers []string `json:"resolvers,omitempty"`
}

// DNSRecordView is one name the tailnet serves that is not a device.
type DNSRecordView struct {
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

// DNSMachineView is what every program other than app-tail resolves with.
type DNSMachineView struct {
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"searchDomains,omitempty"`
	MatchDomains  []string `json:"matchDomains,omitempty"`
}

// Routes is the subnet-route module as the API needs it. There is no write method: the
// settings that drive it are ordinary registry fields written through PUT /api/settings,
// and this reports what came of them.
type Routes interface {
	// View reads live node state -- which networks peers carry to this device, and which
	// ones the tailnet has approved this device to carry back -- so it takes a context.
	View(ctx context.Context) RoutesView
	// Check measures which of the devices carrying a route this one accepts can actually
	// be reached from here. It is a probe rather than a read, which is why it is not part
	// of the view.
	Check(ctx context.Context) (RouteCheckResult, error)
}

// RoutesView is both directions of subnet routing: the networks this device reaches
// through its peers, and the ones it offers to carry for them.
//
// Advertised and Approved are separate because the difference between them is the single
// most common reason a subnet route does nothing: advertising is a request, and until an
// admin approves it in the console the tailnet sends this device no traffic at all.
type RoutesView struct {
	// TunnelID names the connection this describes. Routing is a property of one private
	// network rather than of the machine, so a client showing it beside a connection has
	// to be told which one it is about rather than assume.
	TunnelID string `json:"tunnelId"`
	// Enabled is the module switch. It is separate from Accepting and Serving because a
	// client hides this whole surface when the module is off rather than showing it as a
	// broken one, which is what keeps a default install free of it.
	Enabled bool `json:"enabled"`
	// Accepting reports that this device takes the networks its peers advertise.
	Accepting bool `json:"accepting"`
	// Reaching are the networks this device can reach through the tailnet right now,
	// which is empty while Accepting is off however many peers advertise routes.
	Reaching []string `json:"reaching"`
	// Advertised is what this device offers to carry; Approved is what the tailnet has
	// granted it. Serving is whether it answers the connections that arrive for them.
	Advertised []string `json:"advertised"`
	Approved   []string `json:"approved"`
	Serving    bool     `json:"serving"`
	// Carried and Refused count the connections that arrived for a network this device
	// routes; Refused means the destination was not one it carries.
	Carried  uint64 `json:"carried"`
	Refused  uint64 `json:"refused"`
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
	// Error is the last failure that stopped this device carrying traffic.
	Error      string     `json:"error,omitempty"`
	Capability Capability `json:"capability"`
}

// RouteCheckResult is which of the devices carrying an accepted route answered a probe.
//
// Several devices may advertise the same network for failover and only one carries it,
// so an accepted route with no reachable device is the state worth seeing: the route is
// in the netmap, the addresses look right, and nothing on that network answers.
type RouteCheckResult struct {
	Routes []RouteCheckEntry `json:"routes"`
	// Reason explains an empty answer, which is the ordinary result on a tailnet where
	// no peer advertises a route.
	Reason string `json:"reason,omitempty"`
}

// RouteCheckEntry is one accepted network and the devices carrying it that answered.
type RouteCheckEntry struct {
	Prefix string `json:"prefix"`
	// Via are the devices that answered for this network, by name.
	Via       []string `json:"via,omitempty"`
	Reachable bool     `json:"reachable"`
}

// Egress is where this machine's internet traffic leaves through, and whether the
// connection chosen for it is in a position to carry any.
//
// There is no write method: what chooses it is an ordinary registry field written through
// PUT /api/settings, and this reports what that choice currently amounts to. The two are
// worth reporting apart, because the gap between them is the whole failure this endpoint
// exists to show -- a connection named here that is down, or up with nothing at the far
// end routing traffic on, leaves a setting that says "through my VPN" over traffic that is
// going nowhere.
type Egress interface {
	// View asks the chosen connection whether it can carry traffic right now, so it takes a
	// context.
	View(ctx context.Context) EgressView
}

// EgressView is what this machine does with traffic none of its connections carries.
type EgressView struct {
	// Mode is the setting: out of this machine, or through a connection.
	Mode string `json:"mode"`
	// TunnelID and TunnelName are the connection chosen to carry it. They are present
	// whenever one is stored, including while the traffic is going out directly -- a
	// remembered choice is what lets someone switch back without picking again.
	TunnelID   string `json:"tunnelId,omitempty"`
	TunnelName string `json:"tunnelName,omitempty"`
	// Carrying reports that traffic is going through that connection right now. It is false
	// both when the mode sends traffic out of this machine and when the chosen connection
	// cannot carry it; Mode and Reason separate the two.
	Carrying bool `json:"carrying"`
	// Reason is why it is not carrying, in the connection's own words. Empty when it is.
	Reason string `json:"reason,omitempty"`
	// Limits are what choosing this connection does not do, stated up front rather than
	// discovered: a connection with no resolver of its own cannot keep name lookups off
	// this network, so the addresses being visited stay visible here even though the
	// traffic does not.
	Limits []string `json:"limits,omitempty"`
	// Shape is how the members carry the traffic between them: spread across them, or
	// chained through all of them in order. It is present only while several connections
	// carry it, and it is what makes the member rows readable -- the same list of four
	// connections means four independent ways out or one route through all four.
	Shape string `json:"shape,omitempty"`
	// Members are the connections carrying the traffic between them, one row each, present
	// only while several do. Each carries its own answer because the point of the mode is
	// that they are not one thing: spread, one member being down moves the destinations that
	// were on it and leaves the rest alone; chained, one being down stops the whole route at
	// that hop. A single line for the set could say neither.
	Members []EgressMember `json:"members,omitempty"`
	// Held reports that traffic is being held here rather than sent out over this machine's
	// own network, because the connections chosen to share it are all down. It is the
	// difference between "not carrying" and "leaking", which Carrying alone cannot say.
	Held bool `json:"held,omitempty"`
	// KillSwitch reports that the promise is on: nothing this machine sends is to leave over
	// its own network, whatever happens to the connection carrying it. It is present only
	// while one connection carries the traffic, which is the one mode the switch is read in --
	// several connections hold it whether it is on or not.
	//
	// It is the setting rather than the outcome, and the two are worth telling apart: the
	// switch is on all the time, and Held is true only at the moments it is stopping traffic.
	KillSwitch bool `json:"killSwitch,omitempty"`
}

// EgressMember is one connection out of the set carrying this machine's internet traffic.
type EgressMember struct {
	TunnelID   string `json:"tunnelId"`
	TunnelName string `json:"tunnelName,omitempty"`
	// Exit reports that this is the connection the traffic leaves through, which only a chain
	// has: it is the last hop, the one whose address the internet sees. Spread has no exit
	// because every member is one.
	Exit bool `json:"exit,omitempty"`
	// Carrying reports that this member is carrying right now: its share of the destinations
	// when the traffic is spread, and the hop after it -- or the traffic itself, at the end of
	// the chain -- when it is chained.
	Carrying bool `json:"carrying"`
	// Waiting reports that this hop has not started because the one before it in the chain is
	// not carrying yet. It is not a failure and is worth telling apart from one: every start
	// of a chain passes through it, and a hop reported as failed on every normal start is a
	// card nobody reads by the third time they see it.
	Waiting bool `json:"waiting,omitempty"`
	// Reason is why it is not, in the connection's own words. Empty when it is.
	Reason string `json:"reason,omitempty"`
	// Limits are what this member does not cover, in the same terms as EgressView.Limits.
	Limits []string `json:"limits,omitempty"`
}

// Fabric is where each connected network is reachable from this machine, and what two
// networks carrying the same addresses means for the ones that cannot be.
//
// There is no write method: what switches it on is an ordinary registry field written
// through PUT /api/settings, and this reports the result. With the interface off it reports
// what the addressing would have to be, which is worth reporting on its own -- a collision
// nobody is told about is a network silently answering for another one's addresses, and the
// symptom is a host that resolves and never answers.
type Fabric interface {
	// View asks every running connection what it carries, so it takes a context.
	View(ctx context.Context) FabricView
}

// FabricView is the whole addressing picture: the pool moved networks are presented from,
// where each network sits, and every range more than one of them claims.
type FabricView struct {
	// Mode is what this build does about a collision. "report" means it says so and
	// changes nothing, which is a client's cue to explain rather than to offer a fix.
	Mode string `json:"mode"`
	// Pool is the address space a moved network would be presented from.
	Pool []string `json:"pool,omitempty"`
	// Networks is one entry per range per connection, in the order the connections are
	// configured, which is the order that decides who keeps a contested range.
	Networks []FabricNetworkView `json:"networks,omitempty"`
	// Conflicts is one entry per contested range rather than per connection: three
	// connections claiming one range is one thing to say, not three.
	Conflicts []FabricConflictView `json:"conflicts,omitempty"`
	// Unread names the connections whose networks could not be read, with the reason. A
	// plan built from a partial list would report no collision for a range it never saw,
	// which is the one failure that must not look like a clean answer.
	Unread []FabricUnreadView `json:"unread,omitempty"`
	// Interface is what the operating system called the interface carrying these networks,
	// empty when nothing is carrying them.
	Interface string `json:"interface,omitempty"`
	// Running reports the interface up and carrying traffic. It is separate from Mode: the
	// mode is what was asked for, and this is what is happening.
	Running bool `json:"running"`
	// MTU is the largest packet the interface carries: the smallest of the connected
	// networks' own, because a datagram cannot be split the way a byte stream can.
	MTU int `json:"mtu,omitempty"`
	// Routes are the ranges this machine is sending to the interface right now.
	Routes []string `json:"routes,omitempty"`
	// Carried is what each connection has actually carried, keyed in the list by connection.
	// An entry with no connection id is what was refused because no connection carried the
	// address at all.
	Carried []FabricCarriedView `json:"carried,omitempty"`
	// Error is why the interface is not carrying what it was asked to.
	Error      string     `json:"error,omitempty"`
	Capability Capability `json:"capability"`
}

// FabricCarriedView is what one connection carried across the interface.
type FabricCarriedView struct {
	TunnelID string `json:"tunnelId,omitempty"`
	Name     string `json:"name,omitempty"`
	// Flows is how many connections and datagram flows were handed on, Refused how many
	// were turned away.
	Flows   uint64 `json:"flows"`
	Refused uint64 `json:"refused"`
	// Sent is what this machine put into the network, Received what came back.
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
	// Holding is how many flows are open right now.
	Holding int `json:"holding"`
}

// FabricNetworkView is one network a connection carries and where this machine would
// reach it.
type FabricNetworkView struct {
	TunnelID   string `json:"tunnelId"`
	TunnelName string `json:"tunnelName,omitempty"`
	Prefix     string `json:"prefix"`
	// PresentedAs is the range this machine would reach it at, empty both when the network
	// keeps its own addresses and when it has to move but nothing fits it. Reason tells
	// those apart: it is set exactly when the network cannot be reached at its own
	// addresses.
	PresentedAs string `json:"presentedAs,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// FabricConflictView is one range claimed by more than one network.
type FabricConflictView struct {
	Prefix string `json:"prefix"`
	// Holder is the connection reachable at the range as it stands, empty when this
	// machine itself is the one on that network.
	Holder     string `json:"holder,omitempty"`
	HolderName string `json:"holderName,omitempty"`
	// Claimants are the connections that carry the range and cannot be reached at it.
	Claimants []FabricClaimantView `json:"claimants,omitempty"`
	Detail    string               `json:"detail"`
}

// FabricClaimantView is one connection that carries a contested range, carrying its name
// so a client can render the sentence without joining it against the connection list.
type FabricClaimantView struct {
	TunnelID string `json:"tunnelId"`
	Name     string `json:"name,omitempty"`
}

// FabricUnreadView is a connection whose networks could not be read.
type FabricUnreadView struct {
	TunnelID string `json:"tunnelId"`
	Name     string `json:"name,omitempty"`
	Error    string `json:"error"`
}

// ExitNode is the exit-node module as the API needs it. There is no write method: the
// settings that drive it are ordinary registry fields written through PUT /api/settings,
// and this reports the result and the devices to choose between.
type ExitNode interface {
	View() ExitNodeView
	// Suggest asks the tailnet which exit node it recommends for this device. An empty
	// answer is a normal outcome, not an error.
	Suggest(ctx context.Context) (ExitNodeSuggestion, error)
}

// ExitNodeView is which device this machine's other traffic leaves through, and what it
// could leave through instead.
//
// Current and LiveID are separate because they answer different questions: Current is
// the device app-tail is asking for, LiveID the one the node reports carrying traffic.
// They differ while a change is in flight, and while something outside this app has
// selected a different one -- which is exactly when a user needs to see both.
type ExitNodeView struct {
	// TunnelID names the connection whose devices these are, for the reason RoutesView
	// carries one: a device id only means anything on the network that issued it.
	TunnelID string `json:"tunnelId"`
	Enabled  bool   `json:"enabled"`
	// Rotating reports that the schedule owns the choice, which is what makes the stored
	// device a fallback rather than the one in use.
	Rotating     bool   `json:"rotating"`
	Current      string `json:"current,omitempty"`
	CurrentLabel string `json:"currentLabel,omitempty"`
	LiveID       string `json:"liveId,omitempty"`
	LiveOnline   bool   `json:"liveOnline"`
	// Reason explains the state in one sentence, in the words a user reads.
	Reason string `json:"reason,omitempty"`
	// NextChange is when the schedule moves on, RFC 3339, empty when nothing is
	// scheduled.
	NextChange string `json:"nextChange,omitempty"`
	// Warning is what changing the exit node costs. It is served rather than written
	// into each client so the tray, the dashboard and the CLI say the same thing.
	Warning    string              `json:"warning"`
	Candidates []ExitNodeCandidate `json:"candidates"`
	Capability Capability          `json:"capability"`
}

// ExitNodeCandidate is one device the tailnet offers as an exit node.
type ExitNodeCandidate struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Display is the name with the place beside it, which is the only way to tell thirty
	// hosted nodes apart.
	Display string `json:"display"`
	Online  bool   `json:"online"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Current bool   `json:"current"`
}

// ExitNodeSuggestion is the tailnet's own recommendation. An empty ID with a Reason is
// the normal answer on a tailnet whose exit nodes are self-hosted: the control plane only
// suggests devices it has flagged, and saying so is what keeps the button from reading
// as broken.
type ExitNodeSuggestion struct {
	ID      string `json:"id,omitempty"`
	Label   string `json:"label,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// SystemProxy is this machine's own proxy configuration as the API reports it. There is
// no write method: the setting that drives it is an ordinary registry field, so it is
// written through PUT /api/settings like every other one, and this reports the result.
type SystemProxy interface {
	View() SystemProxyView
}

// SystemProxyView is what the dashboard card renders.
//
// Applied and Enabled are separate on purpose: the switch being on and the machine
// actually pointing at the proxy differ whenever the platform, the proxy's own state or
// another program got in the way, and collapsing them is what turns a stated limitation
// into a bug report.
type SystemProxyView struct {
	Enabled  bool   `json:"enabled"`
	Platform string `json:"platform"`
	// Supported reports that this platform can be changed at all without privilege.
	Supported bool `json:"supported"`
	Applied   bool `json:"applied"`
	// AutoConfigURL is what the machine points at now, whoever set it.
	AutoConfigURL string `json:"autoConfigUrl,omitempty"`
	// Managed distinguishes a value this app wrote from one that was already there,
	// which is the difference between offering to undo it and warning about it.
	Managed    bool               `json:"managed"`
	Manual     []sysproxy.Command `json:"manual"`
	Capability Capability         `json:"capability"`
}

// SourceAuto marks a forward a module derived rather than a user configured.
const SourceAuto = "auto"

// AutoMap is the automatic port mapping module as the API needs it. The mappings
// themselves are ordinary forwards and are reported through Forwards; this covers the
// module's own state and the one action that is not a forward edit.
type AutoMap interface {
	View() AutoMapView
	// Forget drops the port assignments for devices the tailnet no longer reports, and
	// returns how many went.
	Forget(ctx context.Context) (int, error)
}

// AutoMapView is what the module is doing right now. Stored counts assignments that
// persist, including ones for devices not currently mapped: it is the difference
// between "nothing is mapped" and "nothing is mapped and nothing is remembered", which
// is what tells a user whether forgetting would do anything.
type AutoMapView struct {
	Enabled bool  `json:"enabled"`
	Ports   []int `json:"ports,omitempty"`
	Limit   int   `json:"limit"`
	Mapped  int   `json:"mapped"`
	Stored  int   `json:"stored"`
	// Truncated is how many device-and-port pairs the limit left out, and Reason says
	// so in words. Reported rather than dropped: a missing device otherwise reads as
	// the feature being broken.
	Truncated int    `json:"truncated"`
	Reason    string `json:"reason,omitempty"`
}

// ForwardView is a forward as the dashboard sees it: its configuration plus its
// live counters.
type ForwardView struct {
	config.Forward
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	ActiveTCP int    `json:"activeTcp"`
	ActiveUDP int    `json:"activeUdp"`
	BytesUp   int64  `json:"bytesUp"`
	BytesDown int64  `json:"bytesDown"`
	Listening string `json:"listening,omitempty"`
	// Source is empty for a forward the user configured and "auto" for one a module
	// derived. A derived forward is rebuilt from the device list on every reconcile,
	// so the dashboard shows it without the controls that would edit it.
	Source string `json:"source,omitempty"`
	// Endpoint is the rendered "TCP 127.0.0.1:2222" label the UI shows.
	Endpoint string `json:"endpoint"`
	// Warning is something true about this forward that its own state cannot show: it is
	// running and correctly configured, and a setting elsewhere means it carries nothing.
	// Empty is the ordinary case, and it is not an error -- Error is for a forward that
	// failed.
	Warning string `json:"warning,omitempty"`
}

// ForwardSpec is the request body for creating or updating a forward. Pointer
// fields on update mean "leave unchanged", so a client can patch one field without
// resending the whole record.
type ForwardSpec struct {
	Name *string `json:"name"`
	// TunnelID is the connection this forward crosses. Absent on create means the primary
	// one, so a client that has never heard of connections keeps working.
	TunnelID      *string           `json:"tunnelId"`
	Direction     *config.Direction `json:"direction"`
	Protocol      *config.Protocol  `json:"protocol"`
	BindAddr      *string           `json:"bindAddr"`
	ListenPort    *int              `json:"listenPort"`
	Target        *string           `json:"target"`
	Enabled       *bool             `json:"enabled"`
	UDPTimeoutSec *int              `json:"udpTimeoutSec"`
	// ExposeToNetwork must be true for a to_local forward to bind an address other
	// machines can reach.
	ExposeToNetwork *bool `json:"exposeToNetwork"`
}

// PolicyBootstrapRequest carries an admin OAuth client (policy_file scope) used once
// to add the fleet's tags to the tailnet ACL. The credential is held only for the
// request and is never persisted, logged, or returned. There is deliberately no API
// URL field: the loopback API must not proxy credentials to an arbitrary host.
type PolicyBootstrapRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	// Tailnet is the tailnet to edit; empty means the credential's own ("-").
	Tailnet string `json:"tailnet"`
	// Tags is which tags to bring into the policy; empty defaults to the configured tags.
	Tags []string `json:"tags"`
	// Owners may apply the tags; empty means autogroup:admin.
	Owners []string `json:"owners"`
	// GrantDsts, when non-empty, adds a grant letting tagged nodes reach those destinations.
	GrantDsts []string `json:"grantDsts"`
	// GrantIPs restricts the grant's ports; empty means all ports.
	GrantIPs []string `json:"grantIps"`
}

// PolicyPlanView summarizes what a bootstrap would change (Preview) or changed
// (Apply). Changed is false when the policy already satisfies every tag, which is
// what makes the operation safe to re-run.
type PolicyPlanView struct {
	Summary     string   `json:"summary"`
	AddTagOwner bool     `json:"addTagOwner"`
	AddGrant    bool     `json:"addGrant"`
	Changed     bool     `json:"changed"`
	Notes       []string `json:"notes,omitempty"`
}

// StatusView is the node state the dashboard polls.
type StatusView struct {
	// TunnelID names the connection this status is about: the node this process runs,
	// which is the connection every install has. A client showing it beside the
	// connections is told which one rather than deducing it from the type.
	TunnelID     string `json:"tunnelId"`
	BackendState string `json:"backendState"`
	Running      bool   `json:"running"`
	// AuthPending reports that a login is waiting to be completed, without carrying the
	// URL that completes it. The URL enrolls this machine on a tailnet, so anything that
	// can read it can finish an enrolment somebody else started; this is a read anyone
	// who reaches the API may make, and the state-changing POST that hands the URL over
	// is the one the same-origin guard covers.
	AuthPending  bool     `json:"authPending,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	DNSName      string   `json:"dnsName,omitempty"`
	TailscaleIPs []string `json:"tailscaleIps,omitempty"`
	LoginName    string   `json:"loginName,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	AuthMode     string   `json:"authMode"`
	Problem      string   `json:"problem,omitempty"`
	Version      string   `json:"version,omitempty"`
	// Network is the stack the node is really on, and NetworkFallback why that is not
	// the stack the settings asked for. They are on the status rather than beside the
	// settings because the settings say what was requested and only this says what
	// happened: a node that fell back is Running, has an address and answers every other
	// field exactly as one that did not.
	Network         string `json:"network,omitempty"`
	NetworkFallback string `json:"networkFallback,omitempty"`
	// ConfigQuarantine is set when this run started on the defaults because the stored
	// document could not be used. It rides on the status because the status is what every
	// page polls, and the fact belongs to no single page: every setting on screen is a
	// default rather than the value the user chose.
	ConfigQuarantine *ConfigQuarantineView `json:"configQuarantine,omitempty"`
	// DashboardMoved is set when the dashboard could not bind the configured address. It
	// rides here for the same reason as the quarantine above: the page that shows the
	// address shows the one it moved to, so no page of its own would ever say it moved.
	DashboardMoved *DashboardMovedView `json:"dashboardMoved,omitempty"`
	// Approvals is what this machine refused for want of an administrator's approval. It
	// rides on the status because the refusals come from several features at once -- the
	// interface, a connection, the resolver -- and one prompt approves them all.
	Approvals *ApprovalsView `json:"approvals,omitempty"`
}
