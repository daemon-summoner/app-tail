// SPDX-License-Identifier: MIT

// Package app wires the tailnet node, forwarding engine, and management API into a
// single agent with one lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/policy"
	"github.com/sellitus/app-tail/internal/routing"
	"github.com/sellitus/app-tail/internal/subnets"
	"github.com/sellitus/app-tail/internal/sysproxy"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/traffic"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
	"github.com/sellitus/app-tail/internal/tunnel"
	"github.com/sellitus/app-tail/internal/tunnel/ovpntunnel"
	"github.com/sellitus/app-tail/internal/tunnel/tstunnel"
	"github.com/sellitus/app-tail/internal/tunnel/wgtunnel"
)

// shutdownStep bounds each stage of a graceful stop, so a wedged listener cannot
// hold the process open indefinitely.
const shutdownStep = 5 * time.Second

// NodeController is the tailnet identity the agent drives: the management API's
// view of it plus the dial/listen surface forwards run on. Defining it here lets a
// test drive the whole agent without a control plane.
type NodeController interface {
	httpapi.Node
	forward.Tailnet

	// Reach classifies where an address would go, which is what makes the proxy's
	// scope enforceable: without it the proxy could only dial and hope.
	Reach(ctx context.Context, network, address string) (tsnode.Reach, error)
	// LookupTailnet resolves a name through the tailnet's own resolver, which is the
	// only one that knows a domain the tailnet points at a private nameserver.
	LookupTailnet(ctx context.Context, host string) (tsnode.TailnetLookup, error)
	// Routes are the subnets this node reaches through the tailnet, and are the real
	// content of the browser auto-config script.
	Routes(ctx context.Context) ([]netip.Prefix, error)

	// The preference mirror. Settings whose value lives on the node itself are stored
	// here like any other, then pushed: CachedPrefs is what the node last reported,
	// CheckPrefs asks whether an edit would be accepted before anything is written,
	// and EditPrefs applies it.
	CachedPrefs() (tsnode.Prefs, bool)
	CheckPrefs(ctx context.Context, patch tsnode.PrefsPatch) error
	EditPrefs(ctx context.Context, patch tsnode.PrefsPatch) (tsnode.Prefs, error)

	// The subnet-router side: ApprovedRoutes is what the tailnet actually routes here,
	// which is what a carried connection is checked against, and ServeSubnets installs
	// the hook that delivers those connections at all.
	ApprovedRoutes(ctx context.Context) ([]netip.Prefix, error)
	ServeSubnets(h func(src, dst netip.AddrPort) func(net.Conn)) (func(), error)
	// RouteReachability probes the devices carrying each accepted route, which is the
	// only thing that distinguishes a route that is wrong from one whose device is away.
	RouteReachability(ctx context.Context) ([]tsnode.RouteReach, error)

	// The exit-node operations that need the backend rather than a preference:
	// SuggestExitNode is the tailnet's own recommendation, and PingPeer measures the
	// round trip the fastest-first strategy chooses on.
	SuggestExitNode(ctx context.Context) (tsnode.Suggestion, error)
	PingPeer(ctx context.Context, ip netip.Addr) (time.Duration, error)

	// Tailnet lock. NetworkLock is why a node can report Running and reach nothing,
	// LockLog is the only record of who changed lock, SignNode is the authorization a
	// locked-out device needs, and DisableLockLocally forgets this device's copy alone.
	NetworkLock(ctx context.Context) (tsnode.LockStatus, error)
	LockLog(ctx context.Context, max int) ([]tsnode.LockUpdate, error)
	SignNode(ctx context.Context, nodeKey, rotationKey string) error
	DisableLockLocally(ctx context.Context) error

	// Name resolution. TailnetDNS is what the tailnet publishes, MachineDNS is what
	// every other program on this machine resolves with, and the gap between them is
	// the question the DNS panel exists to answer. ExitNodeAnswersDNS reports lookups
	// leaving through the exit node, which is what people choose one for.
	TailnetDNS(ctx context.Context) (tsnode.TailnetDNS, error)
	MachineDNS(ctx context.Context) (tsnode.MachineDNS, error)
	ExitNodeAnswersDNS(ctx context.Context, stableID string) (bool, error)

	Start(ctx context.Context) error
	Close() error
	// Events signals that the node's status may have changed.
	Events() <-chan struct{}
}

// Options configures an Agent.
type Options struct {
	// Store holds the persisted config. Required.
	Store *config.Store
	// Runtime is the resolved effective configuration for this process.
	Runtime config.Runtime
	// Flags and Getenv are kept so settings can be re-resolved after an edit,
	// which keeps precedence in exactly one implementation.
	Flags  config.Flags
	Getenv config.Getenv

	Logger *slog.Logger
	// UI is the embedded dashboard. Nil serves an explanatory 503.
	UI fs.FS
	// Autostart manages the login item. Nil reports the capability as unavailable.
	Autostart httpapi.Autostart
	Version   string
	// NeedsAdminRestart reports whether settings as they now stand ask for administrator
	// rights this process does not hold, on a platform that takes them by starting again.
	// It is injected because answering it reads internal/hostnet, the privilege boundary
	// this package sits outside of, and because internal/cli already answers the same
	// question at startup. Nil answers no, which is right wherever a helper holds the
	// rights instead.
	NeedsAdminRestart func(config.Settings) bool
	// RightsByRestart reports whether this process obtains administrator rights by starting
	// again under the system's prompt, so that turning on a feature needing them restarts
	// app-tail rather than asking a helper. Injected for the reason NeedsAdminRestart is; nil
	// answers no.
	RightsByRestart func() bool

	// NewNode builds the tailnet node. Tests substitute one that never dials out.
	NewNode func(tsnode.Options) NodeController
	// NewWireGuardTunnel builds one WireGuard connection. Tests substitute one that never
	// opens a socket, so what the reconcile does with a connection is exercised without a
	// server to hand shake with.
	NewWireGuardTunnel func(wgtunnel.Options) tunnel.Tunnel
	// NewOpenVPNTunnel builds one OpenVPN connection. Tests substitute one that never opens
	// a socket, for the reason NewWireGuardTunnel is substituted and one more: the real one
	// drives a program running with administrator rights.
	NewOpenVPNTunnel func(ovpntunnel.Options) tunnel.Tunnel
	// OpenOpenVPN claims the right to run OpenVPN connections. Tests substitute one for the
	// reason OpenSystemDNS is substituted: the real one asks the machine for administrator
	// rights, and a suite must never do that.
	OpenOpenVPN func(ctx context.Context, logf func(format string, args ...any)) (ovpntunnel.Session, error)
	// RunsOpenVPN reports whether the privileged side can run OpenVPN connections, which
	// decides whether one may be added at all. Nil asks the platform; a test that
	// substitutes OpenOpenVPN answers for the side it substituted.
	RunsOpenVPN func() bool
	// WatchLinkChanges reports when this machine's own networking moves, which is what a
	// connection with no monitor of its own is told by. Tests substitute one that watches
	// nothing: the real one subscribes to the operating system's interface notifications,
	// which a suite has no business doing once per connection it starts.
	WatchLinkChanges func(ctx context.Context) (<-chan struct{}, error)
	// NewPolicyClient builds the control-plane client the ACL bootstrap writes
	// through. Tests substitute one pointed at a local server so the bootstrap is
	// exercised without an admin OAuth credential or a real tailnet.
	NewPolicyClient func(baseURL, tailnet string) *policy.Client
	// NewSystemProxy builds the manager for this machine's own proxy configuration.
	// Tests substitute one that records instead of writing, since the real one is
	// per-platform and would change the machine running the suite.
	NewSystemProxy func(stateDir string, logger *slog.Logger) SystemProxy
	// Clock is what the exit-node rotation schedule reads. Tests substitute one so a
	// whole schedule runs in an instant; nil means the real clock.
	Clock func() time.Time
	// HostNetworks reads the networks this machine is directly attached to, which every
	// network a connection carries is placed around. Tests substitute a fixed answer so a
	// range a test claims cannot collide with the LAN of whichever machine runs the suite;
	// nil means the real interfaces.
	HostNetworks func() ([]netip.Prefix, error)
	// HostAddrs reads the addresses this machine's own interfaces hold, which a forward's
	// target is checked against so it cannot reach app-tail's listeners by this machine's
	// LAN address. Tests substitute a fixed answer; nil means the real interfaces.
	HostAddrs func() ([]netip.Addr, error)
	// RetryDelay is how soon after a pass that could not bring everything up the next one
	// runs. Tests shorten it so a recovery is watched rather than waited out; zero means the
	// shipped ladder, which starts at retryFirst and doubles.
	RetryDelay time.Duration
	// Provision makes this machine able to carry what a caller wants of it -- the
	// network-interface mode, or the machine-wide resolver. Tests substitute one that
	// records, because the real one raises the system's password prompt -- which a suite
	// must never do, and which is exactly the step whose triggering conditions are worth
	// pinning. configPath is the config the agent runs from, so the same dialog also approves
	// the network changes its settings use.
	Provision func(ctx context.Context, logf func(format string, args ...any), want tsnode.Rights, mayElevate bool, configPath string) error
	// InspectInterface reads what this machine says about the network-interface mode.
	// Tests substitute one so every machine state -- a helper that is missing, one that
	// is wedged, a conflicting client -- is reachable from a suite running on a machine
	// in exactly one of them.
	InspectInterface func(ctx context.Context, logf func(format string, args ...any)) tsnode.InterfaceReport
	// OpenSystemDNS claims this machine's own name resolution, which is what the
	// machine-wide resolver needs before it can point anything anywhere. Tests substitute
	// one for the reason ProvisionInterface is substituted: the real one asks the machine
	// for administrator rights, and a suite must never do that.
	OpenSystemDNS func(ctx context.Context, logf func(format string, args ...any)) (tsnode.SystemDNSRights, error)
	// OpenFabric creates the interface that carries every connection at once. Tests
	// substitute one for the reason OpenSystemDNS is substituted, and one more: the real one
	// creates a network interface and points this machine's routing table at it, which a
	// suite must not do to the machine it happens to be running on.
	OpenFabric func(ctx context.Context, opts fabric.LiveOptions) (fabricLive, error)
	// Preflight reports whether this machine could carry the network-interface mode.
	// Tests substitute one for the reason InspectInterface is substituted: the real
	// answer is a property of the machine the suite happens to run on, and what is worth
	// pinning is what the agent does about each answer it can give -- including the one
	// answer it now repairs instead of accepting.
	Preflight func(ctx context.Context, p tsnode.ServerParams, logf func(format string, args ...any)) error
	// ReadTailnetRouting reports whether this machine can reach a tailnet another client on it
	// is carrying. Tests substitute one because the real answer is a property of the machine
	// the suite happens to run on -- almost always "there is no tailnet here" -- and the state
	// worth pinning is the one nothing can arrange for: a tailnet present and unreachable.
	ReadTailnetRouting func(ctx context.Context, own string) (tsnode.TailnetRouting, error)
	// RepairTailnetRoutes puts the route to that tailnet back. Tests substitute one for the
	// reason Provision is substituted: the real one reaches the privileged side and changes
	// this machine's routing table.
	RepairTailnetRoutes func(ctx context.Context, iface string, logf func(format string, args ...any)) ([]netip.Prefix, error)
	// LoadGrants reads what an administrator has approved, which decides whether traffic
	// interception may open encrypted connections. Tests substitute one because the real file
	// is root's, on the machine the suite happens to run on; nil reads that file.
	LoadGrants func() (grants.Document, error)
	// ApproveGrants asks an administrator to approve the changes this machine refused. Tests
	// substitute one for the reason Provision is substituted: the real one raises the
	// system's password prompt.
	ApproveGrants func(ctx context.Context, logf func(format string, args ...any), needs []grants.Need) error
}

// SystemProxy is this machine's own proxy configuration, as the agent changes it.
// It is the one part of the app that writes something outside its own state
// directory, which is why it is a seam rather than a direct call.
type SystemProxy interface {
	// State reports what the machine points at now, given the auto-config URL this
	// agent serves.
	State(pacURL string) sysproxy.State
	// Apply points the machine at pacURL, remembering what it replaced.
	Apply(pacURL string) error
	// Clear puts back what was there before, and does nothing when nothing was applied.
	Clear() error
}

// Agent is the running application: one tailnet node, one forward manager, one
// management server, and the single goroutine that reconciles them.
type Agent struct {
	store  *config.Store
	logger *slog.Logger
	flags  config.Flags
	getenv config.Getenv
	ui     fs.FS

	autostart         httpapi.Autostart
	version           string
	needsAdminRestart func(config.Settings) bool
	rightsByRestart   func() bool
	newNode           func(tsnode.Options) NodeController
	newWireGuard      func(wgtunnel.Options) tunnel.Tunnel
	newOpenVPN        func(ovpntunnel.Options) tunnel.Tunnel
	// openvpnReached is what each OpenVPN connection last reached its server with. It is
	// held here rather than on the connection because the connection is rebuilt whenever
	// the choice of which one carries internet traffic changes, and searching the same
	// ladder again on every switch is the whole of what this avoids.
	openvpnReached *ovpntunnel.Reached
	openOpenVPN    func(ctx context.Context, logf func(format string, args ...any)) (ovpntunnel.Session, error)
	// startable are the kinds of connection this process can bring up, read by the add
	// path and the reconcile alike.
	startable       map[config.TunnelType]bool
	watchLinks      func(ctx context.Context) (<-chan struct{}, error)
	newPolicyClient func(baseURL, tailnet string) *policy.Client
	newSystemProxy  func(stateDir string, logger *slog.Logger) SystemProxy
	openSystemDNS   func(ctx context.Context, logf func(format string, args ...any)) (tsnode.SystemDNSRights, error)
	openFabric      func(ctx context.Context, opts fabric.LiveOptions) (fabricLive, error)
	provision       func(ctx context.Context, logf func(format string, args ...any), want tsnode.Rights, mayElevate bool, configPath string) error
	inspect         func(ctx context.Context, logf func(format string, args ...any)) tsnode.InterfaceReport
	preflight       func(ctx context.Context, p tsnode.ServerParams, logf func(format string, args ...any)) error
	// The two halves of the tailnet-route watch. See tailnetroutes.go.
	readTailnetRouting  func(ctx context.Context, own string) (tsnode.TailnetRouting, error)
	repairTailnetRoutes func(ctx context.Context, iface string, logf func(format string, args ...any)) ([]netip.Prefix, error)

	node    NodeController
	manager *forward.Manager
	api     *httpapi.Server
	// apiKeys is the token the management API demands and the sign-in links minted from
	// it, nil until start loads them.
	apiKeys *apiauth.Keys
	// tunnels is every network this app is connected to, behind the one seam a consumer
	// reaches any of them through: the tailnet a.node runs, kept in step by publishNode,
	// beside every other connection the reconcile started, of whatever kind. What a
	// consumer reads is the same for all of them.
	tunnels *tunnel.Registry
	// tunnelMu guards the three maps below and the OpenVPN claim, which the lifecycle
	// goroutine writes as it starts and stops connections and every API reader reads while
	// it does. It is separate from mu because a status read must never be parked behind a
	// node being built.
	tunnelMu sync.Mutex
	// openvpn is the claim on the privileged side that every OpenVPN connection runs
	// through, held while at least one of them is up and dropped when the last stops.
	//
	// It is one claim rather than one per connection because dropping it stops every
	// connection started through it -- which is what guarantees no program holding
	// administrator rights outlives this process, and is exactly wrong if a second
	// connection is still using it.
	openvpn ovpntunnel.Session
	// running is every connection beside the primary one that this process started,
	// keyed by connection id.
	running map[string]*runningTunnel
	// tunnelErrs is why a connection that is meant to be up is not, keyed the same way.
	// It exists because a node that never started has no status of its own to report
	// with, so without it a connection that cannot start is indistinguishable from one
	// that is switched off.
	tunnelErrs map[string]string
	// tunnelRetry is the connections somebody asked to be tried again now. It is a set
	// rather than a flag on the connection because a retry is an instruction with no
	// duration: the next reconcile acts on it and forgets it, and one asked for twice
	// before that pass runs is one retry.
	tunnelRetry map[string]struct{}

	// proxies outlive a node rebuild on purpose: they reach the connections through the
	// registry rather than holding a node, so their ports and auto-config URLs survive
	// POST /api/restart rather than moving underneath whatever the user already pointed at
	// them.
	proxies *tsproxy.Set

	// subnets carries the connections the tailnet sends here for a network this device
	// routes. Unlike the proxy it is rebuilt with the node, because the hook it installs
	// belongs to that node's own network stack and means nothing on a later one.
	subnets *subnets.Router

	// sysproxy manages this machine's own proxy configuration. Like the proxy it
	// outlives a node rebuild, because what it wrote outside this process must not be
	// forgotten by anything short of a restore.
	sysproxy SystemProxy

	// systemDNS is this machine's own name resolution: the claim on it, the sockets
	// queries arrive on and the forwarder behind them. Like sysproxy it outlives a node
	// rebuild, and unlike everything else here it works with no tailnet at all.
	systemDNS *systemDNSRunner

	// blocklists owns the downloaded name lists: the copies on disk and the one compiled
	// matcher both this machine's resolver and app-tail's own resolution ask. Like
	// systemDNS it outlives a node rebuild and works with no tailnet at all.
	blocklists *blocklistRunner

	// ips owns traffic inspection: the compiled rules and the ring of what has matched.
	// Like blocklists it outlives a node rebuild -- what has matched belongs to this
	// machine, and a rebuild would empty the list a user is reading.
	ips *ipsRunner

	// ipsFeeds owns the downloaded address feeds those rules are built from. It is separate
	// from ips because the feeds are one of two things compiled into the matcher and the
	// entries the user typed are the other, and only one of them involves the network.
	ipsFeeds *ipsFeedRunner

	// fabric is the interface carrying every connection at once. Like systemDNS it outlives
	// a node rebuild and works with no tailnet at all: the networks it carries belong to the
	// connections, and the primary node is only one of them.
	fabric *fabricRunner

	// autoMap holds the last set of forwards derived from the peer list, so the API
	// reports exactly the ones the engine is running rather than recomputing them and
	// risking a different answer.
	autoMap autoMapState

	// systemProxy holds the outcome of the last machine-proxy reconcile, so the
	// dashboard reports what happened rather than what was asked for.
	systemProxy systemProxyState

	// prefs holds the state of the node-preference mirror per connection: what each
	// node has disagreed about and what this app has given up on. It is keyed by
	// connection id because a preference belongs to a node, and every connection runs
	// its own.
	prefs map[string]*prefsState

	// exitNode holds which device this machine's other traffic leaves through, and the
	// schedule moving it. The choice lives here rather than in the settings document
	// because rotation changes it on a timer.
	exitNode exitNodeState

	// supervise decides whether a pass that could not bring everything up is owed another
	// one, and when. Like exitNode it is written and read only by the lifecycle goroutine,
	// which is the same goroutine that arms the timer both of them answer to.
	supervise supervisor

	// interfaceRecovery paces the machine reads that move a node stuck in the contained
	// mode onto the network interface once it can carry one. Same goroutine as the two
	// above, and the same timer.
	interfaceRecovery interfaceRetry

	// clock is what the exit-node schedule reads. It is a seam so a test drives a whole
	// rotation without waiting one out; nil means the real clock.
	clock func() time.Time
	// hostNetworks reads what this machine is attached to, for the fabric report and the
	// runner alike, so the two never disagree about where a network can be placed.
	hostNetworks func() ([]netip.Prefix, error)
	// hostAddrs reads the addresses this machine's interfaces hold, for telling whether a
	// forward's target is this machine.
	hostAddrs func() ([]netip.Addr, error)

	// pending is every change the privileged side refused for want of an administrator's
	// approval, as the sessions to it heard. It has its own lock, because refusals arrive on
	// whatever goroutine was talking to the helper.
	pending *grants.Pending
	// loadGrants reads the approvals file, for the one decision made on this side of the
	// helper: whether traffic interception may run.
	loadGrants func() (grants.Document, error)
	// approveGrants raises the administrator prompt that approves pending changes.
	approveGrants func(ctx context.Context, logf func(format string, args ...any), needs []grants.Need) error

	// reconcile is poked by both node events and config edits. The lifecycle
	// goroutine is its only consumer, which is what serializes every start and
	// stop of a forward.
	reconcile chan struct{}

	// syncReconcile carries reconcile requests that the caller waits on, so an API
	// write can answer with the state the engine actually reached. It is separate
	// from reconcile so node events stay non-blocking no matter how many callers
	// are waiting.
	syncReconcile chan chan struct{}

	// blocklistWake asks the blocklist loop to look now rather than at its next tick.
	// Switching blocking on, or turning a list on, is a download the user is waiting
	// for, and the card says nothing is being blocked until it has happened.
	blocklistWake chan struct{}

	// ipsFeedWake is the same for the inspection feeds, and is separate because the two
	// loops are: a feed being switched on must not wait out a blocklist download, and a
	// shared channel would make one wake the other for nothing.
	ipsFeedWake chan struct{}

	// stopping closes at the very start of shutdown, releasing callers parked on an
	// acknowledgement before the management server waits for them.
	stopping chan struct{}

	// restart carries in-process node-rebuild requests to the lifecycle goroutine,
	// so the node swap happens on the one goroutine that reads a.node unlocked.
	restart chan restartRequest

	// relaunch closes when something asks for the whole process to start again. It is
	// separate from cancelling the context because a cancelled context means "stop",
	// and whoever called Run has to be able to tell a deliberate restart from a quit.
	// Nothing here execs anything: the agent's part is to stop cleanly and say why,
	// and the caller that owns the process decides what happens next.
	relaunch     chan struct{}
	relaunchOnce sync.Once

	// quit closes when something asks the whole process to stop without a replacement. It is
	// separate from cancelling the context only in where it comes from -- the API, rather
	// than a signal or the tray -- and Run treats the two the same. It exists because a
	// second copy of app-tail starting has to be able to ask this one to go, and on Windows
	// there is no signal that says it.
	quit     chan struct{}
	quitOnce sync.Once

	mu      sync.RWMutex
	runtime config.Runtime

	// nodeErr remembers why the last node start or rebuild failed. The node itself
	// cannot report this: it never came up, so its own status has nothing to say.
	nodeErr string

	// networkFallback remembers why the node is not on the network interface the
	// settings asked for. Unlike nodeErr it describes a node that is up and working,
	// which is the only state where nothing else would mention it.
	networkFallback string
	// networkFallbackFromMachine records that the reason came from reading this machine
	// -- a conflicting client, a missing driver, an absent helper. Only that kind can
	// stop being true without app-tail doing anything, so only that kind is retired by
	// reading the machine again. A start that failed is a fact about a run, and a
	// machine that now reads ready says nothing about it.
	networkFallbackFromMachine bool

	// tailnetRouteProblem is what the last tailnet-route round could not do, empty when it
	// did it. It is remembered rather than only logged so a standing fault -- no helper, a
	// route the machine will not accept -- is reported once instead of every minute for as
	// long as it lasts.
	tailnetRouteProblem string
	// tailnetRouteInterval overrides how often the watch runs, zero meaning the shipped one.
	// Tests shorten it for the reason RetryDelay is shortened: a loop that comes round is
	// watched rather than waited out.
	tailnetRouteInterval time.Duration

	// askedToRepairInterface records that this run has already asked for the rights to
	// put the machine back in a state where it can carry the interface mode. The asking
	// is a password dialog, and a node rebuild is not a reason to raise it again: a run
	// that prompts twice for one machine fault is a run somebody stops answering.
	askedToRepairInterface bool

	uiAddr net.Addr
	// uiMoved is set when the dashboard could not have the configured address, and is what
	// keeps that fact reportable after the stored address has been rewritten to the one it
	// landed on.
	uiMoved  *httpapi.DashboardMovedView
	shutdown sync.Once
	stopped  chan struct{}

	// telemetry is the log of what this agent did. It is built with the agent and
	// outlives every node rebuild, because a history that reset whenever the tailnet
	// reconnected would lose exactly the entries explaining why it did. It is never
	// nil: switched off, it records nothing and answers every read with a reason.
	telemetry *telemetry.Hub
	// telemetryStop ends the hub's own goroutine at shutdown.
	telemetryStop context.CancelFunc

	// observed is what the log has already been told about the modules that report a
	// state rather than an event. Only the lifecycle goroutine touches it, which is what
	// lets it be compared and replaced without a lock.
	observed observedState

	// sampler holds the rolling traffic window. It outlives a node rebuild on purpose:
	// reconnecting the tailnet does not make the last five minutes untrue, and clearing
	// the graph every time settings are saved would hide exactly the moment worth seeing.
	sampler *traffic.Sampler
	// samplerStop ends the sampler's goroutine at shutdown.
	samplerStop context.CancelFunc
	// blocklistRound is what the last blocklist round ended with, nil when it ended
	// cleanly. A round that failed before any list was reached -- no directory to write
	// in, a matcher that would not compile -- has no per-list row to appear in, so
	// without this the card would report every list fine and nothing blocking.
	blocklistRound atomic.Pointer[string]
	// blocklistsDone closes when the blocklist loop has returned. Shutdown waits on it
	// because that loop is the one background goroutine that writes to the state
	// directory: a download landing after the agent reported itself stopped writes a file
	// into a directory the caller is entitled to consider finished with.
	blocklistsDone chan struct{}
	// ipsFeedRound and ipsFeedsDone are the same two for the inspection feeds, which write
	// to a directory of their own beside the blocklists' and so are the second background
	// goroutine shutdown has to wait for.
	ipsFeedRound atomic.Pointer[string]
	ipsFeedsDone chan struct{}

	// latency is the last round trip measured to each peer, keyed by device ID, empty
	// while the probing setting is off. A peer absent from the map was not measured,
	// which is a different thing from being slow.
	latencyMu sync.RWMutex
	latency   map[string]time.Duration
}

// currentSampler is the traffic window, nil before the agent has started.
func (a *Agent) currentSampler() *traffic.Sampler {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sampler
}

// peerLatency is the last measured round trip per device. The map is copied because it is
// replaced wholesale by each probe round while the dashboard is reading it.
func (a *Agent) peerLatency() map[string]time.Duration {
	a.latencyMu.RLock()
	defer a.latencyMu.RUnlock()
	if len(a.latency) == 0 {
		return nil
	}
	out := make(map[string]time.Duration, len(a.latency))
	for k, v := range a.latency {
		out[k] = v
	}
	return out
}

// setPeerLatency publishes a completed probe round.
func (a *Agent) setPeerLatency(measured map[string]time.Duration) {
	a.latencyMu.Lock()
	defer a.latencyMu.Unlock()
	a.latency = measured
}

// New builds an agent. It performs no I/O beyond reading the supplied config.
func New(opts Options) (*Agent, error) {
	if opts.Store == nil {
		return nil, errors.New("app: a config store is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	getenv := opts.Getenv
	if getenv == nil {
		getenv = config.OSGetenv
	}
	newNode := opts.NewNode
	if newNode == nil {
		newNode = func(o tsnode.Options) NodeController { return tsnode.New(o) }
	}
	newWireGuard := opts.NewWireGuardTunnel
	if newWireGuard == nil {
		newWireGuard = wgtunnel.New
	}
	newOpenVPN := opts.NewOpenVPNTunnel
	if newOpenVPN == nil {
		newOpenVPN = ovpntunnel.New
	}
	// One list for the whole process: a refusal heard by any session to the privileged side
	// belongs on the same dashboard, and outlives a node rebuild the way the refusal does.
	pending := grants.NewPending()
	openOpenVPN := opts.OpenOpenVPN
	if openOpenVPN == nil {
		openOpenVPN = func(ctx context.Context, logf func(format string, args ...any)) (ovpntunnel.Session, error) {
			return ovpntunnel.Open(ctx, logf, pending)
		}
	}
	runsOpenVPN := opts.RunsOpenVPN
	if runsOpenVPN == nil {
		runsOpenVPN = ovpntunnel.Supported
	}
	watchLinks := opts.WatchLinkChanges
	if watchLinks == nil {
		watchLinks = tsnode.WatchLinkChanges
	}
	newPolicyClient := opts.NewPolicyClient
	if newPolicyClient == nil {
		newPolicyClient = func(baseURL, tailnet string) *policy.Client {
			return policy.NewClient(baseURL, tailnet, nil)
		}
	}
	newSystemProxy := opts.NewSystemProxy
	if newSystemProxy == nil {
		newSystemProxy = func(stateDir string, logger *slog.Logger) SystemProxy {
			return sysproxy.New(stateDir, logger)
		}
	}
	provision := opts.Provision
	if provision == nil {
		provision = tsnode.Provision
	}
	inspect := opts.InspectInterface
	if inspect == nil {
		inspect = tsnode.InspectInterface
	}
	preflight := opts.Preflight
	if preflight == nil {
		preflight = tsnode.Preflight
	}
	openSystemDNS := opts.OpenSystemDNS
	if openSystemDNS == nil {
		openSystemDNS = func(ctx context.Context, logf func(format string, args ...any)) (tsnode.SystemDNSRights, error) {
			return tsnode.OpenSystemDNSRights(ctx, logf, pending)
		}
	}
	openFabricInner := opts.OpenFabric
	if openFabricInner == nil {
		openFabricInner = openFabric
	}
	openFabricLive := func(ctx context.Context, o fabric.LiveOptions) (fabricLive, error) {
		o.Grants = pending
		return openFabricInner(ctx, o)
	}
	readTailnetRouting := opts.ReadTailnetRouting
	if readTailnetRouting == nil {
		readTailnetRouting = readTailnetRoutingOf
	}
	repairTailnetRoutes := opts.RepairTailnetRoutes
	if repairTailnetRoutes == nil {
		repairTailnetRoutes = repairTailnetRoutesOn
	}
	hostNetworks := opts.HostNetworks
	if hostNetworks == nil {
		hostNetworks = fabric.HostNetworks
	}
	hostAddrs := opts.HostAddrs
	if hostAddrs == nil {
		hostAddrs = interfaceAddrs
	}
	loadGrants := opts.LoadGrants
	if loadGrants == nil {
		loadGrants = loadMachineGrants
	}
	approveGrants := opts.ApproveGrants
	if approveGrants == nil {
		approveGrants = tsnode.ApproveGrants
	}

	a := &Agent{
		store:             opts.Store,
		logger:            logger,
		flags:             opts.Flags,
		getenv:            getenv,
		ui:                opts.UI,
		autostart:         opts.Autostart,
		version:           opts.Version,
		needsAdminRestart: opts.NeedsAdminRestart,
		rightsByRestart:   opts.RightsByRestart,
		newNode:           newNode,
		newWireGuard:      newWireGuard,
		newOpenVPN:        newOpenVPN,
		openvpnReached:    ovpntunnel.NewReached(),
		openOpenVPN:       openOpenVPN,
		startable:         startableTypes(runsOpenVPN()),
		watchLinks:        watchLinks,
		newPolicyClient:   newPolicyClient,
		newSystemProxy:    newSystemProxy,
		openSystemDNS:     openSystemDNS,
		openFabric:        openFabricLive,
		provision:         provision,
		preflight:         preflight,
		inspect:           inspect,

		readTailnetRouting:  readTailnetRouting,
		repairTailnetRoutes: repairTailnetRoutes,
		hostNetworks:        hostNetworks,
		hostAddrs:           hostAddrs,

		pending:       pending,
		loadGrants:    loadGrants,
		approveGrants: approveGrants,

		clock:         opts.Clock,
		supervise:     supervisor{first: opts.RetryDelay},
		runtime:       opts.Runtime,
		tunnels:       tunnel.NewRegistry(),
		reconcile:     make(chan struct{}, 1),
		syncReconcile: make(chan chan struct{}),
		blocklistWake: make(chan struct{}, 1),
		ipsFeedWake:   make(chan struct{}, 1),
		restart:       make(chan restartRequest),
		relaunch:      make(chan struct{}),
		quit:          make(chan struct{}),
		stopping:      make(chan struct{}),
		stopped:       make(chan struct{}),
	}
	// Built here rather than in start(), so a caller that only reads settings still has
	// a hub to hand the API, and so the switch's own state is in force before the first
	// thing worth recording happens.
	a.telemetry = telemetry.New(telemetry.Options{
		Logger: logger,
		Config: telemetryConfig(opts.Runtime.Settings),
	})
	// Built here for the reason the hub is, and one more: the ring of what inspection has
	// matched is the whole of what the card shows on an install where telemetry is off, so
	// it has to outlive every node rebuild rather than be replaced by one.
	a.ips = newIPSRunner(a.now, a.recordEvent, a.logger)
	return a, nil
}

// restartRequest asks the lifecycle goroutine to rebuild the tailnet node and
// reports the outcome back on result.
type restartRequest struct {
	result chan error
}

// settings returns the effective settings for this process.
func (a *Agent) settings() config.Settings {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.runtime.Settings
}

// routes returns the per-destination exceptions to where this machine's internet traffic
// goes. The caller owns the slice: order is the meaning here, and a caller sorting or
// filtering one would change where the running machine sends its traffic.
//
// Read from the stored document rather than from the runtime, as the proxies are and for
// the same reason: nothing overrides these -- a rule injected by the environment would
// move traffic onto a connection with nothing stored saying so -- so the document is the
// whole truth, and reading it here is what makes an edit take effect on the next pass.
func (a *Agent) routes() []routing.Rule {
	return routing.Clone(a.store.Get().Routes)
}

func (a *Agent) stateDir() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.runtime.StateDir
}

// runtimeTunnels returns the connections this process runs, overrides included. The
// caller owns the slice.
func (a *Agent) runtimeTunnels() []config.Tunnel {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]config.Tunnel, len(a.runtime.Tunnels))
	for i, t := range a.runtime.Tunnels {
		out[i] = t.Clone()
	}
	return out
}

// runtimeDocument is the whole configuration this process is running with, overrides
// included. It is what a view of the settings is built from, because a settings key that
// was moved onto a connection or a proxy is read through that entity rather than out of
// the settings document.
func (a *Agent) runtimeDocument() *config.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.runtime.Document()
}

// primaryTailnet returns the tailnet settings the node joins with, taken from the
// connection that describes it rather than from the settings document, which no longer
// holds an identity of its own.
func (a *Agent) primaryTailnet() (config.TailscaleTunnel, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.runtime.PrimaryTailnet()
}

// tunnelPrefs is what one connection asks its node for: its stored preferences with the
// modules governing them folded in. A connection that is not there asks for nothing,
// which is the honest answer -- there is no node to hold a preference for.
func (a *Agent) tunnelPrefs(id string) config.TailnetPrefs {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, t := range a.runtime.Tunnels {
		if t.ID == id {
			return a.runtime.Settings.TailnetPrefsOf(t)
		}
	}
	return config.TailnetPrefs{}
}

// primaryPrefs is tunnelPrefs for the connection every install has, which is the one the
// modules that predate connections still describe.
func (a *Agent) primaryPrefs() config.TailnetPrefs {
	return a.tunnelPrefs(config.PrimaryTunnelID)
}

// UIAddr reports the bound management address, or nil before Run binds it.
func (a *Agent) UIAddr() net.Addr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.uiAddr
}

// Node reports the tailnet node, or nil before Run creates it. A front end running
// alongside the agent uses this for status and login.
func (a *Agent) Node() httpapi.Node {
	if node := a.currentNode(); node != nil {
		return node
	}
	// A typed nil inside a non-nil interface would defeat the caller's nil check.
	return nil
}

// Autostart reports the login-item manager, or nil when this build or platform has
// none.
func (a *Agent) Autostart() httpapi.Autostart { return a.autostart }

func (a *Agent) currentNode() NodeController {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.node
}

// publishNode makes a freshly built node the one everything reads, together with the
// forward manager and subnet router built on it. The three move as one because they are
// one node's worth of state: a reader that saw a new node beside the previous manager
// would run forwards on an identity that no longer exists.
//
// It deliberately does not close what it replaces. Every caller has already torn the old
// node down in its own order -- forwards stopped, then the subnet hook, then the node --
// and closing here would either duplicate that or race it.
func (a *Agent) publishNode(node NodeController, manager *forward.Manager, router *subnets.Router) {
	manager.SetDialGuard(a.ownListenerDial)
	a.mu.Lock()
	a.node, a.manager, a.subnets = node, manager, router
	a.mu.Unlock()

	a.tunnels.Remove(config.PrimaryTunnelID)
	if err := a.tunnels.Add(tstunnel.New(config.PrimaryTunnelID, node)); err != nil {
		// Unreachable: the id was just removed, and it is the only thing Add refuses for.
		// It is reported rather than dropped because the consequence is a connections
		// screen that shows no tailnet while one is running, which nothing else would
		// explain.
		a.logger.Error("could not publish the tailnet as a connection", "error", err)
	}
}

func (a *Agent) currentManager() *forward.Manager {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.manager
}

func (a *Agent) currentAPI() *httpapi.Server {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.api
}

// Run starts every component and blocks until ctx is cancelled or a component
// fails fatally. It always tears down what it started.
func (a *Agent) Run(ctx context.Context) error {
	// Started before start(), so the very first thing worth recording -- the agent
	// coming up, or failing to -- has somewhere to go. It is cancelled by shutdown
	// rather than by ctx, so the last events of a run survive a cancelled context.
	hubCtx, stopHub := context.WithCancel(context.WithoutCancel(ctx))
	a.mu.Lock()
	a.telemetryStop = stopHub
	a.mu.Unlock()
	go a.telemetry.Run(hubCtx)

	if err := a.start(ctx); err != nil {
		// start publishes the node, the manager and the bound listener as it goes, so
		// a failure partway through leaves live resources behind. This is also what
		// closes a.stopped: without it a later RestartNode waits forever on a select
		// nobody is serving.
		return errors.Join(err, a.Shutdown(context.WithoutCancel(ctx)))
	}

	// Sampling starts with the agent and runs for its whole life: the window is about
	// what this machine carried, which a node rebuild does not reset.
	sampleCtx, stopSampling := context.WithCancel(context.WithoutCancel(ctx))
	sampler := traffic.NewSampler(trafficSource{a: a}, trafficInterval, trafficWindow)
	blocklistsDone := make(chan struct{})
	ipsFeedsDone := make(chan struct{})
	a.mu.Lock()
	a.sampler, a.samplerStop = sampler, stopSampling
	a.blocklistsDone, a.ipsFeedsDone = blocklistsDone, ipsFeedsDone
	a.mu.Unlock()
	go sampler.Run(sampleCtx)
	// Shares the sampler's lifetime and its cancellation; it reads the setting on each
	// round rather than being started and stopped as the switch moves.
	go a.runLatencyProbes(sampleCtx)
	// And the same lifetime again for the blocklists: it reads the settings each round, so
	// switching blocking on is a setting rather than a goroutine somebody has to start.
	go func() {
		defer close(blocklistsDone)
		a.runBlocklists(sampleCtx)
	}()
	// And the same again for the inspection feeds, in a loop of its own so a feed switched on
	// is not waiting behind a forty-megabyte blocklist download.
	go func() {
		defer close(ipsFeedsDone)
		a.runIPSFeeds(sampleCtx)
	}()
	// And the same lifetime again for the route to the tailnet, its setting read on each round
	// like the two above. It is a loop rather than a reaction because what it watches for is a
	// change to this machine that nothing on this machine announces.
	go a.runTailnetRouteWatch(sampleCtx)
	// And the same lifetime for reading the inspection ledger, its switch read on each round
	// like the loops above. It is a loop rather than something the data path does because
	// what it looks for is the shape of a run of connections, and no single connection can
	// see that.
	go a.runIPSAnomaly(sampleCtx)
	// And the same lifetime for noticing that this machine was asleep. Nothing else asks for a
	// pass on wake: the loop below is driven by events, and a lid closing produces none.
	go watchForWake(sampleCtx, wakeSample, a.now, func(away time.Duration) {
		a.logger.Info("this machine was away; settling everything again",
			"away", away.Round(time.Second))
		a.pokeReconcile()
	})

	serveErr := make(chan error, 1)
	go func() { serveErr <- a.api.Serve() }()

	// Everything else here is driven by an event; the exit-node schedule is the one
	// thing that asks to be looked at again after a length of time, so the loop carries
	// a timer it arms after each pass.
	// Stopped until a pass asks for one: a stopped timer delivers nothing since Go 1.23,
	// so there is no stale fire to drain here or after any later Stop.
	wake := time.NewTimer(time.Hour)
	wake.Stop()
	defer wake.Stop()

	// The node's watcher may already have produced a state before this loop began.
	a.pokeReconcile()

	var runErr error
	for done := false; !done; {
		select {
		case <-ctx.Done():
			done = true
		case <-a.relaunch:
			done = true
		case <-a.quit:
			done = true
		case err := <-serveErr:
			// The management server dying is fatal: without it the agent cannot be
			// controlled, and silently continuing would strand the user.
			if err != nil {
				runErr = fmt.Errorf("management server stopped: %w", err)
			}
			done = true
		case <-a.node.Events():
			a.pokeReconcile()
		case <-wake.C:
			// Here rather than in applyAndSchedule so a rebuild is only ever paced by
			// the timer: the reconcile passes an edit or a node event drives are not a
			// schedule, and the ack branch below would hold an API caller open for the
			// length of one.
			a.recoverInterfaceMode(ctx)
			a.applyAndSchedule(ctx, wake)
		case <-a.reconcile:
			a.applyAndSchedule(ctx, wake)
		case ack := <-a.syncReconcile:
			a.applyAndSchedule(ctx, wake)
			// close never blocks, so a slow or vanished waiter can never stall the
			// one goroutine that starts and stops forwards.
			close(ack)
		case req := <-a.restart:
			// Handled here so the node swap and the reconcile loop share one goroutine
			// and never race over a.node.
			req.result <- a.restartNode(ctx)
		}
	}

	if err := a.Shutdown(context.WithoutCancel(ctx)); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

// start brings up the node, the forward manager, and the management listener.
func (a *Agent) start(ctx context.Context) error {
	settings := a.settings()

	tailnet, err := a.primaryTailnet()
	if err != nil {
		return err
	}
	secret, err := config.LoadOAuthSecret(tailnet)
	if err != nil {
		return err
	}
	params, err := tsnode.BuildServerParams(tailnet, settings, a.stateDir(), secret)
	if err != nil {
		return err
	}
	params, err = a.prepareParams(ctx, params)
	if err != nil {
		return err
	}

	node := a.newNode(tsnode.Options{
		Params:  params,
		Logger:  a.logger,
		Verbose: a.runtimeVerbose(),
		Grants:  a.pending,
	})
	manager := forward.NewManager(forwardNets{tunnels: a.tunnels}, a.settings, a.logger)
	router := subnets.New(node, a.primaryPrefs, a.logger)
	// The proxies reach the connections through the registry rather than holding a node,
	// so a later rebuild does not strand them. Nothing binds until applyProxy runs, and
	// nothing at all while the module is switched off.
	proxies := tsproxy.NewSet(tsproxy.Options{
		Network:  a.tunnels,
		Logger:   a.logger,
		StateDir: a.stateDir(),
	})
	// Built whether or not the setting is on: with it off, the first reconcile is what
	// puts back anything a previous run replaced and then never ran to restore.
	systemProxy := a.newSystemProxy(a.stateDir(), a.logger)
	// Built once and kept across node rebuilds: the machine's resolver is not the node's,
	// and dropping this machine's DNS for the length of a rebuild is exactly what holding
	// a separate claim avoids.
	systemDNS := a.currentSystemDNS()
	if systemDNS == nil {
		systemDNS = newSystemDNSRunner(a.logger, a.openSystemDNS, a.noteQuestion)
	}
	// Kept across node rebuilds for the same reason: the interface carries every connection,
	// and taking the machine off all of them for the length of one node's rebuild would drop
	// every flow on it.
	fabricRun := a.currentFabric()
	if fabricRun == nil {
		fabricRun = newFabricRunner(a.logger, a.hostLogf, registryCarriers{registry: a.tunnels}, a.openFabric,
			a.pokeReconcile)
	}

	// Published under the lock because a tray or any other in-process front end may
	// already be polling the agent while this runs, and because the API built below
	// reads a.proxy through the accessor as it answers.
	a.mu.Lock()
	a.proxies, a.sysproxy = proxies, systemProxy
	a.systemDNS, a.fabric = systemDNS, fabricRun
	if a.blocklists == nil {
		// Kept across node rebuilds for the same reason as the two above: the downloaded
		// lists belong to this machine, and rebuilding the matcher would stop blocking for
		// as long as a million names take to compile.
		a.blocklists = newBlocklistRunner(a.logger, a.runtime.StateDir, a.now, a.fetchBlocklist)
	}
	if a.ipsFeeds == nil {
		a.ipsFeeds = newIPSFeedRunner(a.logger, a.runtime.StateDir, a.now, a.fetchIPSFeed)
	}
	a.mu.Unlock()
	a.publishNode(node, manager, router)

	// The token lives beside the dashboard-address record, because the CLI finds both from
	// the config path it was pointed at.
	keys, err := apiauth.LoadOrCreate(filepath.Dir(a.store.Path()))
	if err != nil {
		return fmt.Errorf("load the management API token: %w", err)
	}
	if reason := keys.Replaced(); reason != "" {
		a.logger.Warn("wrote a new management API token; every dashboard has to be opened again",
			"reason", reason)
	}

	api := httpapi.New(httpapi.Options{
		Deps: httpapi.Deps{
			Node:      a.NodeAPI(),
			Tunnels:   a.TunnelsAPI(),
			Forwards:  a.Forwards(),
			Presets:   a.Presets(),
			Settings:  a.Settings(),
			Interface: a.InterfaceSetup(),
			Autostart: a.autostart,
			Policy:    a.Policy(),
			Restart:   a,
			Lifecycle: a,
			Traffic:   trafficAPI{a: a},
			Approvals: a.Approvals(),
			Proxy:     a.Proxy(),
			Proxies:   a.ProxiesAPI(),
			AutoMap:   a.AutoMap(),
			SysProxy:  a.SystemProxyAPI(),
			Prefs:     a.PrefsAPI(),
			ExitNode:  a.ExitNodeAPI(),
			Routes:    a.RoutesAPI(),
			Routing:   a.RoutingAPI(),
			Fabric:    a.FabricAPI(),
			Egress:    a.EgressAPI(),
			Lock:      a.LockAPI(),
			DNS:       a.DNSAPI(),
			Profiles:  a.DNSProfiles(),
			DNSBlock:  a.DNSBlock(),
			IPS:       a.IPS(),
			Telemetry: a.TelemetryAPI(),
			Version:   a.version,

			ConfigQuarantine: configQuarantineView(a.store.Quarantined()),
			Dashboard:        a,
		},
		Auth:   keys,
		Logger: a.logger,
		UI:     a.ui,
	})

	a.mu.Lock()
	a.api, a.apiKeys = api, keys
	a.mu.Unlock()

	if err := a.listenUI(settings.UIListen); err != nil {
		return err
	}

	// The node is started last so a bind failure does not leave a half-registered
	// device behind on the tailnet.
	if err := node.Start(ctx); err != nil {
		if err := a.retryContained(ctx, params, node, err); err != nil {
			// The listener is already bound, so it has to come down or the next start
			// attempt cannot rebind the port. A failure doing so is joined rather than
			// dropped: it is the reason a retry would fail.
			return errors.Join(err, a.closeAPI(context.WithoutCancel(ctx)))
		}
	}

	a.logger.Info("agent started",
		"hostname", params.Hostname,
		"authMode", params.Mode,
		"stateDir", a.stateDir(),
		"ui", a.UIAddr().String())
	// The hostname is in the log line above but not here: the structured log is a debug
	// artefact this machine's owner reads, and the event log follows one rule for every
	// entry -- a name the user chose is theirs, and the log says what happened without
	// writing it down.
	a.recordEvent(telemetry.CodeAppStart, "app-tail started.", map[string]string{
		"version": a.version,
		"mode":    string(params.Mode),
	})
	// After app.start rather than before it: the log is read newest-first, and the reason
	// this run is on the defaults belongs inside the run it explains.
	a.reportConfigQuarantine()
	return nil
}

func (a *Agent) runtimeVerbose() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.runtime.Verbose
}

// RestartNode rebuilds the tailnet node so node-identity settings take effect
// without restarting the whole process. The rebuild runs on the lifecycle goroutine,
// so it never races the reconcile loop that reads the node. It blocks until the
// rebuild finishes or ctx is cancelled.
func (a *Agent) RestartNode(ctx context.Context) error {
	req := restartRequest{result: make(chan error, 1)}
	select {
	case a.restart <- req:
	case <-a.stopped:
		return errors.New("app: agent is shutting down")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-req.result:
		return err
	case <-a.stopped:
		return errors.New("app: agent is shutting down")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RestartProcess asks for the whole process to stop and start again, which is the only
// way a dashboard-address change or a new binary takes effect.
//
// It returns as soon as the request is recorded rather than waiting for the restart: the
// process serving the request is the one going away, so an answer sent after the shutdown
// began would have no connection left to travel on. Run then unwinds through the ordinary
// shutdown -- listener first, then forwards, the proxy and the node -- and only once that
// has finished does the caller that owns the process start the replacement. That order is
// what keeps the new process from finding the dashboard port still held and quietly
// binding a different one.
func (a *Agent) RestartProcess() error {
	select {
	case <-a.stopped:
		return errors.New("app: agent is already shutting down")
	default:
	}
	a.relaunchOnce.Do(func() {
		a.recordEvent(telemetry.CodeAppRestart,
			"A restart of the whole app was requested.", nil)
		close(a.relaunch)
	})
	return nil
}

// StopProcess asks for the whole process to stop, with no replacement started.
//
// It is what a second copy of app-tail calls when it takes this one's place: the shutdown
// that follows is the ordered one, so this machine's resolver, proxy settings and routes are
// put back by the process that installed them rather than left for the new one to find. Like
// RestartProcess it returns as soon as the request is recorded, because the listener serving
// the request goes away with everything else.
func (a *Agent) StopProcess() error {
	select {
	case <-a.stopped:
		return errors.New("app: agent is already shutting down")
	default:
	}
	a.quitOnce.Do(func() { close(a.quit) })
	return nil
}

// RelaunchRequested reports whether the run ended because something asked for a restart
// rather than because it was told to stop. Only meaningful once Run has returned.
func (a *Agent) RelaunchRequested() bool {
	select {
	case <-a.relaunch:
		return true
	default:
		return false
	}
}

// restartNode rebuilds the tailnet node in place. It runs only from Run's select, so
// it is the sole writer of a.node while the reconcile loop is its sole other reader.
//
// The front of the order is fail-safe: the new parameters are built before anything
// is torn down, so an invalid configuration leaves the running node untouched. Past
// that point the old identity is released before the new one opens the same state
// directory. Nothing enforces that order for us -- the backend takes no lock on the
// directory and both nodes would rewrite the same file -- so a failed start of the
// replacement is reported and leaves the node down until the next successful restart.
func (a *Agent) restartNode(ctx context.Context) error {
	// Every path out of here leaves the published manager holding the desired state
	// derived from the store, failures included: a rebuild that fails leaves a node
	// whose watcher never started, so no event will arrive to do it later.
	defer a.pokeReconcile()

	settings := a.settings()

	tailnet, err := a.primaryTailnet()
	if err != nil {
		return a.recordNodeErr(err)
	}
	secret, err := config.LoadOAuthSecret(tailnet)
	if err != nil {
		return a.recordNodeErr(err)
	}
	// Nothing reaches this today: both of BuildServerParams' failures are closed off
	// upstream -- config.RenderHostname always falls back to a name rather than an
	// empty string, and Config.Validate refuses an OAuth secret with no tags on
	// every write path, the environment resolver included. It stays as the guard for
	// the day either of those relaxes, because reaching here means the node has no
	// usable identity and enrolling anyway would fail opaquely at the control plane.
	params, err := tsnode.BuildServerParams(tailnet, settings, a.stateDir(), secret)
	if err != nil {
		return a.recordNodeErr(err)
	}
	// Ahead of the teardown, deliberately: this is the last point at which a machine
	// that cannot run the requested network mode can be told so without the running
	// node having already been given up.
	params, err = a.prepareParams(ctx, params)
	if err != nil {
		return a.recordNodeErr(err)
	}

	if manager := a.currentManager(); manager != nil {
		stopCtx, cancel := context.WithTimeout(ctx, shutdownStep)
		manager.StopAll(stopCtx)
		cancel()
	}
	// Before the node it is registered on goes away, so no connection is still being
	// carried over an identity that is being torn down.
	if router := a.currentSubnets(); router != nil {
		router.Close()
	}
	if node := a.currentNode(); node != nil {
		if err := node.Close(); err != nil {
			a.logger.Warn("closing the previous tailnet node failed", "error", err)
		}
	}

	node := a.newNode(tsnode.Options{
		Params:  params,
		Logger:  a.logger,
		Verbose: a.runtimeVerbose(),
		Grants:  a.pending,
	})
	manager := forward.NewManager(forwardNets{tunnels: a.tunnels}, a.settings, a.logger)
	router := subnets.New(node, a.primaryPrefs, a.logger)

	a.publishNode(node, manager, router)

	if err := node.Start(ctx); err != nil {
		if err := a.retryContained(ctx, params, node, err); err != nil {
			return a.recordNodeErr(fmt.Errorf("restart tailnet node: %w", err))
		}
	}
	a.clearNodeErr()

	a.logger.Info("tailnet node restarted",
		"hostname", params.Hostname, "authMode", params.Mode)
	a.recordEvent(telemetry.CodeNodeRestart, "The tailnet node was rebuilt.",
		map[string]string{"hostname": params.Hostname, "authMode": string(params.Mode)})
	return nil
}

// recordNodeErr publishes why the node is down and hands the error straight back, so a
// caller can both report and return it in one line. The recorded reason surfaces through
// tsnode.Status.Problem, which is what lights up /healthz and the dashboard for a node
// that never got far enough to have a problem of its own.
func (a *Agent) recordNodeErr(err error) error {
	a.mu.Lock()
	changed := a.nodeErr != err.Error()
	a.nodeErr = err.Error()
	a.mu.Unlock()
	// Only on a change: a node that cannot start is retried, and one entry per attempt
	// would bury every other event under the same sentence.
	if changed {
		a.recordEvent(telemetry.CodeNodeState, "The tailnet node is down.",
			map[string]string{"state": "down", "problem": err.Error()})
	}
	return err
}

// clearNodeErr drops a recorded failure once a node is running again, so a stale
// reason cannot outlive the problem it described.
func (a *Agent) clearNodeErr() {
	a.mu.Lock()
	recovered := a.nodeErr != ""
	a.nodeErr = ""
	a.mu.Unlock()
	if recovered {
		a.recordEvent(telemetry.CodeNodeState, "The tailnet node came back up.",
			map[string]string{"state": "up"})
	}
}

// nodeProblem reports the recorded reason the node is down, if any.
func (a *Agent) nodeProblem() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.nodeErr
}

// networkModeFallback reports why the node is not on the network interface the settings
// asked for, empty when it is or when none was asked for.
func (a *Agent) networkModeFallback() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.networkFallback
}

// setNetworkFallback records, or clears, the reason this machine cannot carry the
// requested network mode. It is cleared on every successful preparation so a reason
// cannot outlive the machine state that produced it -- a helper installed after a refusal
// must not leave the node reporting that it is missing.
func (a *Agent) setNetworkFallback(reason string) {
	a.mu.Lock()
	changed := a.networkFallback != reason
	a.networkFallback = reason
	a.networkFallbackFromMachine = reason != ""
	a.mu.Unlock()
	if changed {
		a.recordNetworkFallback(reason)
	}
}

// setStartFallback records that the node could not start on the interface even though the
// machine was ready for it. Reading the machine again cannot retire this one, so it stands
// until a node comes up.
func (a *Agent) setStartFallback(reason string) {
	a.mu.Lock()
	changed := a.networkFallback != reason
	a.networkFallback = reason
	a.networkFallbackFromMachine = false
	a.mu.Unlock()
	if changed {
		a.recordNetworkFallback(reason)
	}
}

// recordNetworkFallback logs the node running on a different network mode than the
// settings asked for, and the moment it stops doing so. Both are worth an entry: the
// state looks exactly like working, so the only trace of it is the one written here.
func (a *Agent) recordNetworkFallback(reason string) {
	if reason == "" {
		a.recordEvent(telemetry.CodeNodeFallback,
			"The node is running on the network mode the settings ask for again.",
			map[string]string{"fallback": "cleared"})
		return
	}
	a.recordEvent(telemetry.CodeNodeFallback,
		"The node is not running on the network mode the settings ask for.",
		map[string]string{"fallback": "active", "reason": reason})
}

// retireMachineFallback drops a recorded machine reason because the caller has just read
// the machine again, and reports what is left.
//
// A reason that came from reading this machine is derived, not history: the fresh read the
// caller is holding says everything it said and says it about the machine as it is now.
// The recorded one is a snapshot from the last time a node was built, and the machine moves
// on without it -- the client that forced the contained mode gets disconnected, and a
// different thing entirely gets in the way. Kept alongside the live answer it is a second,
// older explanation of the same state, which is how a card ends up telling somebody to
// restart for a prompt that another line on the same card explains will not come.
//
// What survives is a start that failed, which is the one thing re-reading the machine
// cannot speak to: the machine looks able and the node still did not come up on it.
//
// The stored value is cleared rather than only the caller's copy, because the node's
// status carries the same string and the two must not disagree.
func (a *Agent) retireMachineFallback() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.networkFallbackFromMachine {
		a.networkFallback = ""
		a.networkFallbackFromMachine = false
	}
	return a.networkFallback
}

// hostLogf carries the privileged side's own logging into the agent's logger. A process
// holding root that cannot report what it did is worse than one that will not start, so
// this is never discarded.
func (a *Agent) hostLogf(format string, args ...any) {
	a.logger.Info("network interface: " + fmt.Sprintf(format, args...))
}

// prepareParams turns stored settings into the parameters a node is built from: the
// credential resolved to something a node can enrol with, and the network mode narrowed to
// one this machine can actually run.
//
// The mode check happens here, before anything is torn down, because a restart releases
// the running node's identity before the replacement can bind the same state directory.
// A machine with no helper discovered at that point would be left with no tailnet at all;
// discovered here it is a node that comes up in the contained mode and says why.
func (a *Agent) prepareParams(ctx context.Context, params tsnode.ServerParams) (tsnode.ServerParams, error) {
	params, err := tsnode.ResolveCredential(ctx, params)
	if err != nil {
		return tsnode.ServerParams{}, err
	}
	usable := a.preflight(ctx, params, a.hostLogf)
	if a.repairMachineForInterface(ctx, usable) {
		usable = a.preflight(ctx, params, a.hostLogf)
	}
	if usable != nil {
		a.logger.Warn("this machine cannot run the network-interface mode; using the contained mode instead",
			"error", usable)
		a.setNetworkFallback(usable.Error())
		params.Network = config.NetworkUserspace
		params.InterfaceName = ""
		return params, nil
	}
	a.setNetworkFallback("")
	return params, nil
}

// noteRightsRequested records that a request for administrator rights has been made this
// run, and reports whether this one is the first.
//
// Every path that raises the dialog records one, including the two a user asks for
// directly. Those two do not consult the answer -- somebody who turned the mode on, or
// pressed the button, is asking for the dialog and gets it -- but they must still be
// counted, or a dialog dismissed on the way in is followed by the node rebuild raising a
// second one for the question just answered.
func (a *Agent) noteRightsRequested() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	first := !a.askedToRepairInterface
	a.askedToRepairInterface = true
	return first
}

// repairMachineForInterface puts right whatever stopped this machine carrying the
// interface mode, when the setup is what would put it right, and reports whether the
// machine is now worth reading again.
//
// The rights are otherwise asked for only when somebody turns the mode on, because a
// password dialog at every login is how an app teaches people to dismiss its dialogs.
// That reasoning is about a machine that was never set up. This is the other case: it was
// set up, it worked, and upgrading app-tail broke it -- the privileged helper only takes
// commands from the binary it was installed for, so the new app silently gets the
// contained mode instead, and on macOS the tailnet's DNS goes with it. The user has
// already asked for this mode; leaving it broken until they find a terminal is not
// respecting that answer, it is losing it. tsnode.SetupWouldFix is what holds this to the
// one refusal where it is true.
//
// Once per run. The dialog is a question, and a run that raises it again is asking
// somebody to answer the same question twice.
func (a *Agent) repairMachineForInterface(ctx context.Context, why error) bool {
	if !tsnode.SetupWouldFix(why) || !a.mayElevate() || !a.noteRightsRequested() {
		return false
	}

	a.logger.Info("this machine's privileged helper is from an earlier build of app-tail; "+
		"asking for the rights to replace it", "reason", why)
	// Bounded like the settings path's own: a dialog nobody is sitting in front of must
	// not hold the start open indefinitely.
	ctx, cancel := context.WithTimeout(ctx, interfaceSetupTimeout)
	defer cancel()
	if err := a.provision(ctx, a.hostLogf, tsnode.RightsInterface, a.mayElevate(), a.store.Path()); err != nil {
		a.logger.Warn("could not replace the privileged helper left by an earlier build of app-tail",
			"error", err)
		return false
	}
	a.logger.Info("replaced the privileged helper with the one this build of app-tail installs")
	return true
}

// retryContained brings the node up in the contained mode after the interface mode failed
// to start, and reports the original failure when it cannot.
//
// This is the last resort and the trade is deliberate: by the time a start fails the
// previous node has already released the state directory, so refusing here leaves the
// machine with no tailnet at all. That is worse than a working node in a mode the user did
// not choose -- provided the substitution is visible, which is what recording the reason
// on the running node's status is for.
func (a *Agent) retryContained(ctx context.Context, params tsnode.ServerParams, failed NodeController, cause error) error {
	if !params.TUN() {
		return cause
	}
	a.logger.Warn("could not start the tailnet node on a network interface; continuing in the contained mode",
		"error", cause)
	if err := failed.Close(); err != nil {
		a.logger.Warn("closing the node that could not start failed", "error", err)
	}

	params.Network = config.NetworkUserspace
	params.InterfaceName = ""
	a.setStartFallback(cause.Error())

	node := a.newNode(tsnode.Options{
		Params:  params,
		Logger:  a.logger,
		Verbose: a.runtimeVerbose(),
		Grants:  a.pending,
	})
	manager := forward.NewManager(forwardNets{tunnels: a.tunnels}, a.settings, a.logger)
	router := subnets.New(node, a.primaryPrefs, a.logger)

	a.publishNode(node, manager, router)

	if err := node.Start(ctx); err != nil {
		// Both are reported: the interface failure is what the user has to fix, and the
		// contained failure is why there is no node at all.
		return errors.Join(cause, err)
	}
	return nil
}

// listenUI binds the management socket and records where it landed. A configured
// port that is already taken falls back to an OS-assigned one rather than refusing
// to start: losing the dashboard because something else grabbed the port would
// leave the user with no way to fix it. The configured address survives that
// fallback untouched, so the next start asks for it again.
func (a *Agent) listenUI(configured string) error {
	var moved *httpapi.DashboardMovedView
	addr, bindErr := a.api.Listen(configured)
	if bindErr != nil {
		host, port, splitErr := net.SplitHostPort(configured)
		if splitErr != nil || port == "0" {
			return bindErr
		}
		fallback := net.JoinHostPort(host, "0")
		a.logger.Warn("configured dashboard port is unavailable; using an OS-assigned one",
			"configured", configured, "error", bindErr)

		bound, err := a.api.Listen(fallback)
		if err != nil {
			return err
		}
		addr = bound
		moved = &httpapi.DashboardMovedView{
			Configured: configured,
			Bound:      addr.String(),
			Reason:     bindErr.Error(),
		}
	}

	a.mu.Lock()
	a.uiAddr, a.uiMoved = addr, moved
	a.mu.Unlock()

	if moved != nil {
		a.recordEvent(telemetry.CodeDashboardMoved,
			"The dashboard could not use the configured address, so it is on one the "+
				"system assigned. The configured address is unchanged and is tried again "+
				"the next time the app starts.",
			map[string]string{
				"configured": moved.Configured,
				"bound":      moved.Bound,
				"reason":     moved.Reason,
			})
	}
	return a.recordUIAddr(addr)
}

// Moved reports a dashboard that is not on the address it was configured for.
func (a *Agent) Moved() *httpapi.DashboardMovedView {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.uiMoved
}

// recordUIAddr writes the bound address into the state directory so the CLI and tray can
// find the running agent, which matters because the default asks for any free port.
//
// It stays out of the config document on purpose: uiListenAddr is the address that was
// asked for, and storing the bound one over it would let a port somebody else held for a
// moment replace the setting for good.
func (a *Agent) recordUIAddr(addr net.Addr) error {
	return config.WriteDashboardAddr(a.store.Path(), addr.String())
}

// pokeReconcile asks the lifecycle goroutine to re-derive desired state. The send
// is non-blocking because a pending request already covers this one.
func (a *Agent) pokeReconcile() {
	select {
	case a.reconcile <- struct{}{}:
	default:
	}
}

// pokeBlocklists asks the blocklist loop to look now.
//
// It is what makes switching blocking on download the lists rather than wait out the tick:
// the loop notices either way, but the card says nothing is being blocked in the meantime,
// and a user reading that reaches for the download button the app was about to press itself.
//
// Non-blocking, for the reason pokeReconcile's send is: a round already asked for covers this
// one, and the caller is an API handler answering a user.
func (a *Agent) pokeBlocklists() {
	select {
	case a.blocklistWake <- struct{}{}:
	default:
	}
}

// reconcileTimeout bounds how long an API write waits for the engine to catch up
// before answering from whatever state it can already see.
const reconcileTimeout = 3 * time.Second

// reconcileNow asks the lifecycle goroutine to re-derive desired state and waits for
// it to finish, so a caller that just edited the config can report what the engine
// actually reached rather than what it was about to do.
//
// A missed acknowledgement costs freshness, never correctness: on timeout, on
// shutdown, or on a cancelled request it falls back to the asynchronous poke, and the
// reconcile still happens.
//
// It must never be called from the lifecycle goroutine itself -- that would be a
// goroutine waiting on its own next loop iteration.
func (a *Agent) reconcileNow(ctx context.Context) {
	ack := make(chan struct{})

	timeout := time.NewTimer(reconcileTimeout)
	defer timeout.Stop()

	select {
	case a.syncReconcile <- ack:
	case <-a.stopping:
		a.pokeReconcile()
		return
	case <-ctx.Done():
		a.pokeReconcile()
		return
	case <-timeout.C:
		a.pokeReconcile()
		return
	}

	select {
	case <-ack:
	case <-a.stopping:
	case <-ctx.Done():
	case <-timeout.C:
	}
}

// applyDesiredState is the only place forwards are started or stopped. Running it
// on a single goroutine is what keeps node transitions and config edits from
// racing each other.
func (a *Agent) applyDesiredState(ctx context.Context) {
	// First, and the one step that does not consult the node at all: this machine has to
	// resolve names whether or not it is signed in to anything.
	a.applySystemDNS(ctx)

	// Before anything that reaches a network: the connections beside the primary one are
	// started here, and a forward or a rule naming one has to find it registered.
	a.reconcileTunnels(ctx)

	// Immediately after, and for the same reason in reverse: what the interface carries is
	// every range the connections say they reach, so it is decided from the set that has just
	// been brought into line rather than from the one before it.
	a.applyFabric(ctx)

	// Before the proxies and the inbound router, which are two of the three paths it is
	// handed to: an inspector applied after them would leave one pass of traffic carried
	// against the rules the settings no longer ask for.
	a.reconcileIPS()

	up := a.node.Status().Running()
	// Which network carries each forward is resolved inside this call, out of the
	// connections reconcileTunnels has just brought into line, so a connection coming up
	// or going down needs no separate signal to reach the forwards on it.
	a.manager.Apply(a.admitForwards(a.autoMapForwards(ctx, a.store.Get().EnabledForwards(), up)))
	// The proxies reconcile here too, but unlike forwards they keep their ports while the
	// connections are down and refuse with a reason: a closed port reads as a broken app.
	// What they report is whether any connection is up, not the primary one: a proxy whose
	// rules name a WireGuard network is working perfectly while the tailnet is signed out.
	a.applyProxies(a.anyTunnelUp())
	// After the proxy and before the mirror: this is the inbound direction, and it is
	// installed on the node the mirror is about to push routes to.
	a.applySubnets(up)
	// Before the mirror, because the exit node it chooses is one of the settings the
	// mirror pushes: deciding after would leave every choice a whole pass behind.
	a.applyExitNode(ctx, up)
	// Last, because it is the only step that talks to the tailnet backend: a slow
	// answer there must not hold up starting the forwards this machine serves.
	a.applyPrefs(ctx, up)

	// After every module has acted, so a feature this pass switched off stops waiting for an
	// approval in the same pass that stopped it.
	a.prunePendingApprovals()

	// Last of all, and after every module has had its chance to act: what the pass
	// actually reached, compared against what the log was last told.
	a.noteObservedState()

	// And what it did not reach, which is what decides whether the loop comes back on its
	// own. Nothing here retries anything; this pass is the retry, and this records whether
	// another one is owed.
	a.supervise.settled(a.downCount())
}

// applyAndSchedule reconciles and then arms the timer for whatever asked to be looked at
// again later: the exit-node rotation schedule, a retry for anything this pass wanted
// running and could not reach, and another read of a machine that could not carry the
// network interface the settings ask for.
func (a *Agent) applyAndSchedule(ctx context.Context, wake *time.Timer) {
	a.applyDesiredState(ctx)
	// Stop before Reset even though an undrained fire is safe since Go 1.23: a timer
	// that is already stopped stays stopped, which is how "nothing is scheduled" is
	// expressed.
	wake.Stop()
	next := soonerOf(a.exitNode.nextWake(), a.supervise.nextWake())
	if d := soonerOf(next, a.interfaceRecoveryWake()); d > 0 {
		wake.Reset(d)
	}
}

// soonerOf is the earlier of two waits, where zero means nothing is waiting. One timer serves
// both schedules, so the pass it wakes for has to be the first one either of them wants: the
// later request is still owed, and the pass that answers the earlier one arms it again.
func soonerOf(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	default:
		return min(a, b)
	}
}

// Shutdown stops everything in dependency order: refuse new API requests, stop
// forwarding, then release the tailnet identity. It is safe to call more than once.
func (a *Agent) Shutdown(ctx context.Context) error {
	var err error
	a.shutdown.Do(func() {
		defer close(a.stopped)
		err = a.shutdownOnce(ctx)
	})
	<-a.stopped
	return err
}

func (a *Agent) shutdownOnce(ctx context.Context) error {
	var errs []error

	// Release anyone parked on a reconcile acknowledgement first. Closing the API
	// waits for in-flight requests, so a handler still waiting on the lifecycle
	// goroutine -- which has stopped consuming -- would serialize shutdown behind it.
	close(a.stopping)

	// Stop sampling before the counters it reads are torn down. A tick landing midway
	// through the teardown below would record a half-stopped agent as a traffic cliff.
	a.mu.RLock()
	stopSampling, sampler := a.samplerStop, a.sampler
	blocklistsDone, ipsFeedsDone := a.blocklistsDone, a.ipsFeedsDone
	a.mu.RUnlock()
	if stopSampling != nil {
		stopSampling()
	}
	if sampler != nil {
		sampler.Stop()
	}

	errs = append(errs, a.restoreMachine(ctx)...)

	if e := a.closeAPI(ctx); e != nil {
		errs = append(errs, e)
	}
	// With the listener closed, the recorded address names a port this process no longer
	// holds: leaving it there sends the CLI at whatever takes the port next.
	if e := config.RemoveDashboardAddr(a.store.Path()); e != nil {
		errs = append(errs, e)
	}

	// After the API, so a refresh somebody asked for over HTTP has finished too: between
	// them these are every path that downloads a list. Cancelling the loop's context aborts
	// a download in flight, so this waits on a request already being torn down rather than
	// on a fetch timeout.
	if e := waitForDownloadLoop("blocklist", blocklistsDone, shutdownStep); e != nil {
		errs = append(errs, e)
	}
	if e := waitForDownloadLoop("inspection feed", ipsFeedsDone, shutdownStep); e != nil {
		errs = append(errs, e)
	}
	if manager := a.currentManager(); manager != nil {
		stopCtx, cancel := context.WithTimeout(ctx, shutdownStep)
		manager.StopAll(stopCtx)
		cancel()
	}
	// Before the node, so no connection is still being carried when the identity it
	// runs over goes away.
	if set := a.currentProxies(); set != nil {
		set.Close()
	}
	// Before the primary connection, because it is the one the management API, the
	// forwards and the proxy are built on: stopping the others first leaves the machine
	// with a working app for the whole of the teardown rather than a broken one.
	a.stopAllTunnels()
	if node := a.currentNode(); node != nil {
		// Out of the registry first, so nothing polling the connections screen reads a
		// status off a node that is closing underneath it.
		a.tunnels.Remove(config.PrimaryTunnelID)
		if e := node.Close(); e != nil {
			errs = append(errs, fmt.Errorf("close tailnet node: %w", e))
		}
	}

	a.logger.Info("agent stopped")

	// Last, and with the hub stopped straight after: Stop drains what is queued, so
	// this entry and everything recorded during the teardown above is in the log before
	// the goroutine that owns it returns.
	a.recordEvent(telemetry.CodeAppStop, "app-tail stopped.", nil)
	a.mu.RLock()
	stopHub := a.telemetryStop
	a.mu.RUnlock()
	if stopHub != nil {
		a.telemetry.Stop()
		stopHub()
	}

	return errors.Join(errs...)
}

// restoreMachine puts back everything this run changed outside its own process.
//
// It is separated from the rest of the teardown, and runs at the front of it, because it is
// the only part working to a deadline that is not app-tail's own: Windows gives a process
// about five seconds after it says the session is ending, and launchd twenty. Everything
// below this in shutdownOnce closes listeners, goroutines and sockets, which a dying process
// gives back on its own. This is the part that does not come back on its own -- an adapter
// pointed at 127.0.0.153 survives the reboot.
//
// Each step is safe to run twice, so a caller that reaches here and then reaches shutdownOnce
// is not a problem: the DNS runner forgets its rights, the fabric runner forgets its live
// interface, and the proxy manager removes its record.
func (a *Agent) restoreMachine(ctx context.Context) []error {
	var errs []error

	// First, because while app-tail is the resolver every step below that looks up a name
	// goes through the socket about to close.
	if systemDNS := a.currentSystemDNS(); systemDNS != nil {
		if e := systemDNS.close(ctx); e != nil {
			errs = append(errs, fmt.Errorf("restore this machine's name resolution: %w", e))
		}
	}
	// Beside it and for the same reason: the machine is sending whole networks at an
	// interface this process owns, and every step below that reaches one of them goes
	// through it. Taking those ranges off is what makes them fail immediately rather than
	// hang against an interface nothing is reading any more.
	if fabricRun := a.currentFabric(); fabricRun != nil {
		if e := fabricRun.close(); e != nil {
			errs = append(errs, fmt.Errorf("take this machine off the networks it was carrying: %w", e))
		}
	}
	// Before the proxy closes, while the address it wrote is still the live one, so a
	// value something else has since replaced is recognised and left alone.
	if systemProxy := a.currentSystemProxy(); systemProxy != nil {
		if e := systemProxy.Clear(); e != nil {
			errs = append(errs, fmt.Errorf("restore this machine's proxy configuration: %w", e))
		}
	}
	if router := a.currentSubnets(); router != nil {
		router.Close()
	}
	return errs
}

func (a *Agent) closeAPI(ctx context.Context) error {
	api := a.currentAPI()
	if api == nil {
		return nil
	}
	apiCtx, cancel := context.WithTimeout(ctx, shutdownStep)
	defer cancel()
	if err := api.Shutdown(apiCtx); err != nil {
		return fmt.Errorf("stop management server: %w", err)
	}
	return nil
}

// ConfigQuarantine is the stored configuration this run had to move aside to start, or
// nil when it loaded. It is exposed so the surfaces that are not the dashboard -- the menu
// bar in particular -- can say that the settings in front of the user are defaults.
func (a *Agent) ConfigQuarantine() *httpapi.ConfigQuarantineView {
	return configQuarantineView(a.store.Quarantined())
}

// DashboardURL is where a browser should be pointed at this agent.
func (a *Agent) DashboardURL() string {
	hostPort := a.dashboardHostPort()
	if hostPort == "" {
		return ""
	}
	return "http://" + hostPort
}

// DashboardLaunchURL is a link that opens the dashboard already signed in: the dashboard
// address with a one-time launch token, valid for two minutes, merged into query (for
// example "?settings=1"). Everything that hands the dashboard to a browser uses it, since
// a plain DashboardURL lands on the signed-out screen.
func (a *Agent) DashboardLaunchURL(query string) (string, error) {
	base := a.DashboardURL()
	a.mu.RLock()
	keys := a.apiKeys
	a.mu.RUnlock()
	if base == "" || keys == nil {
		return "", errors.New("the dashboard is not listening yet")
	}
	values, err := url.ParseQuery(strings.TrimPrefix(query, "?"))
	if err != nil {
		return "", fmt.Errorf("read the dashboard query %q: %w", query, err)
	}
	launch, err := keys.MintLaunch(apiauth.ThisAccount)
	if err != nil {
		return "", err
	}
	values.Set("launch", launch)
	return base + "/?" + values.Encode(), nil
}

// dashboardHostPort is the management address in the form a browser can dial, empty
// before Run binds one. Everything a user is handed -- the dashboard link, the
// auto-config URL -- is built from this one derivation, so they always name the same
// listener.
func (a *Agent) dashboardHostPort() string {
	addr := a.UIAddr()
	if addr == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	// A wildcard or unspecified host is not something a browser can open.
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = config.DefaultBindAddr
	}
	return net.JoinHostPort(host, port)
}

// portOf extracts a numeric port from an address, returning 0 when it has none.
func portOf(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}
