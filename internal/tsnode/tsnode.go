// SPDX-License-Identifier: MIT

// Package tsnode owns the tailnet node: its lifecycle, login state, and the
// tailnet-side network operations forwards are built on. It is the only package
// that talks to tsnet.
package tsnode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tsnet"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/grants"
)

// Backend states reported by the Tailscale backend.
const (
	StateNoState          = "NoState"
	StateNeedsLogin       = "NeedsLogin"
	StateNeedsMachineAuth = "NeedsMachineAuth"
	StateStopped          = "Stopped"
	StateStarting         = "Starting"
	StateRunning          = "Running"
)

// ErrNotRunning is returned by tailnet operations attempted before the node is up.
var ErrNotRunning = errors.New("tailnet node is not running")

// Status is the cached view of node state that the API and tray read. It is a value
// type so callers always get an immutable snapshot.
type Status struct {
	BackendState string
	AuthURL      string
	Hostname     string
	DNSName      string
	TailscaleIPs []string
	LoginName    string
	Tags         []string
	AuthMode     AuthMode
	// MagicDNSSuffix is the tailnet's name domain without surrounding dots, such as
	// "tail1a2b3c.ts.net". It is what a caller matches a hostname against to decide
	// whether the tailnet claims it, which no address range can answer.
	MagicDNSSuffix string
	// ExitNodeActive reports that traffic this node does not otherwise route is being
	// sent through a peer. It changes where non-tailnet destinations belong, so a
	// caller deciding what to send through the tailnet has to know.
	ExitNodeActive bool
	// ExitNodeID is the peer carrying that traffic, and ExitNodeOnline whether it is
	// alive. An exit node that is selected but offline is the state worth reporting on
	// its own: the backend blackholes everything rather than sending it out directly, so
	// what the user sees is a machine with no connectivity and no other explanation.
	ExitNodeID     string
	ExitNodeOnline bool
	// Problem explains why the node is not Running when that is diagnosable,
	// most usefully for non-interactive credentials that failed to enroll.
	Problem string
	// Network is the stack this node is actually on. It answers the one question a
	// user of the interface mode has that nothing else answers: whether the machine is
	// really carrying tailnet addresses, or whether this is the contained mode where
	// only app-tail's own forwards and proxy reach the tailnet.
	Network config.NetworkMode
	// NetworkFallback says why the node is not on the stack the settings asked for,
	// empty when it is. It is reported on a node that is up and working, which is
	// exactly when nothing else would mention it -- and where silence would read as the
	// requested mode being in force.
	NetworkFallback string
}

// Running reports whether forwards may use the tailnet.
func (s Status) Running() bool { return s.BackendState == StateRunning }

// Peer is a tailnet device offered to the device picker.
type Peer struct {
	// ID is the peer's stable node ID: it survives the peer re-registering, and is the
	// identity the control plane accepts when a node is named in a preference. Anything
	// that stores a peer across restarts keys on this rather than on a name or address.
	ID       string   `json:"id"`
	HostName string   `json:"hostName"`
	DNSName  string   `json:"dnsName"`
	IPs      []string `json:"ips"`
	Online   bool     `json:"online"`
	OS       string   `json:"os"`
	Tags     []string `json:"tags"`
	// ExitNodeOption reports that this peer both offers itself as an exit node and has
	// been approved for it. An offered-but-unapproved peer reads false, which is why a
	// picker built from this never lists a device the tailnet would refuse to route
	// through.
	ExitNodeOption bool `json:"exitNodeOption"`
	// ExitNodeCurrent reports that this peer is the one carrying the traffic right now.
	ExitNodeCurrent bool `json:"exitNodeCurrent"`
	// Location is where an exit node says it is, when the tailnet publishes one. It is
	// set for Mullvad and other location-tagged nodes and empty for a device someone
	// runs themselves.
	Location PeerLocation `json:"location,omitzero"`

	// RxBytes and TxBytes are WireGuard's own totals for this peer, cumulative since the
	// node started. They count every byte the tailnet carried to and from this device --
	// forwards, the proxy, routed subnets and exit-node traffic alike -- which is what
	// makes them the honest answer to "which machines is this one actually talking to".
	// A rate is the caller's to derive: these only ever go up while the node lives.
	RxBytes int64 `json:"rxBytes"`
	TxBytes int64 `json:"txBytes"`
	// CurAddr is the address packets are going to right now, empty when the path runs
	// through a relay. Relay is the DERP region carrying it in that case. The pair is one
	// fact worth reading together: a peer with no CurAddr and a Relay is reachable but
	// paying for every packet in latency, which is the usual explanation for a device
	// that works and feels slow.
	CurAddr string `json:"curAddr,omitempty"`
	Relay   string `json:"relay,omitempty"`
	// LastHandshake is when WireGuard last completed one with this peer. It is the
	// difference between a peer that is idle and one that is gone: the control plane can
	// still call a device online well after it stopped answering.
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	// Active reports that the peer has exchanged traffic recently, as the backend judges
	// it rather than as this app guesses from byte counts.
	Active bool `json:"active"`
	// InMagicSock reports that the socket layer is tracking this peer. It is true for
	// every device the control plane lists, and the case where it is not is the one worth
	// naming: a peer the tailnet reports online, with addresses, that no layer below the
	// netmap knows about. It resolves to nothing through MagicDNS and drops every packet
	// sent to it, while reading as a healthy device everywhere a name and an address are
	// all that is shown.
	//
	// InEngine reports that the WireGuard engine holds a configuration for it, which is a
	// statement about traffic rather than about reachability: an idle peer is kept out of
	// the engine and configured on the first packet sent to it, so this is false for most
	// of a quiet tailnet.
	InEngine    bool `json:"inEngine"`
	InMagicSock bool `json:"inMagicSock"`
	// Expired reports that the peer's node key has expired -- the control plane breaks
	// such a key deliberately, so the device stays listed and stops being reachable.
	// KeyExpiry is when that happened, when the control plane names a time.
	Expired   bool      `json:"expired,omitempty"`
	KeyExpiry time.Time `json:"keyExpiry,omitzero"`
	// Reach is what the fields above add up to. It is derived once, here, and carried on
	// the wire so the dashboard, the CLI and any other consumer all read one verdict
	// instead of each assembling their own from the parts.
	Reach PeerReach `json:"reach,omitzero"`
}

// PeerState is what this node can actually do with a peer, as distinct from whether the
// control plane calls the peer online. The two disagree in exactly the case that is
// hardest to diagnose from a device list: one the tailnet names and this node cannot
// touch.
type PeerState string

const (
	// PeerReady is a peer with a direct path, or one idle enough not to need one yet.
	PeerReady PeerState = "ready"
	// PeerRelayed is reachable but paying a relay for every packet.
	PeerRelayed PeerState = "relayed"
	// PeerNoPath is listed by the control plane and absent from the layers that would
	// carry traffic to it.
	PeerNoPath PeerState = "no-path"
	// PeerOffline is a device the tailnet says is not connected.
	PeerOffline PeerState = "offline"
	// PeerExpired is a device whose node key the control plane has broken.
	PeerExpired PeerState = "expired"
)

// PeerReach pairs that state with one sentence naming the cause. The sentence is what
// tells a person what to do next; the state is what a caller branches on. Reason is
// empty only for PeerReady, because every other state is worth saying out loud.
//
// It is distinct from Reach, which answers where a dial to an address would go: this one
// is about a device, and is derived rather than asked.
type PeerReach struct {
	State  PeerState `json:"state"`
	Reason string    `json:"reason,omitempty"`
}

// OK reports whether traffic to the peer can be expected to arrive. A relayed peer is
// slow, not broken, so it counts.
func (r PeerReach) OK() bool { return r.State.OK() }

// OK reports whether traffic to a peer in this state can be expected to arrive.
func (s PeerState) OK() bool { return s == PeerReady || s == PeerRelayed }

// Or supplies a state for a peer that was never given one: a value from an agent old
// enough to predate the field, or a view model built without it. The empty state is
// silence rather than a verdict, and reading it literally would report every peer from
// such a source as unreachable -- louder, and wronger, than the blind spot this replaced.
// Whether the control plane calls the device online is all that source knew, so it is all
// this claims.
func (s PeerState) Or(online bool) PeerState {
	if s != "" {
		return s
	}
	if online {
		return PeerReady
	}
	return PeerOffline
}

// reachOf derives what this node can do with a peer. It reads only fields the status
// call already filled in -- no I/O, no clock -- so every state is reachable from a test
// and the answer cannot change between asking and acting on it.
//
// The order is by how completely each cause explains the others: an expired key and a
// disconnected device account for everything below them, and the engine check is last
// among the failures because it is the one that otherwise renders as a healthy device.
//
// Handshake age is deliberately not a signal, and neither is the engine entry. Tailscale
// builds a path on first use and keeps an idle peer out of the WireGuard engine until
// then, so a peer nobody has contacted has no handshake, no address and no engine entry
// while being perfectly reachable; treating any of that as a fault would flag most of a
// quiet tailnet. The socket layer is the one that holds every peer in the netmap whether
// or not traffic has flowed, which is what makes its absence a verdict.
func reachOf(p Peer) PeerReach {
	switch {
	case p.Expired:
		reason := "this device's node key has expired, so the tailnet no longer routes to it"
		if !p.KeyExpiry.IsZero() {
			reason += " (expired " + p.KeyExpiry.Format("2006-01-02") + ")"
		}
		return PeerReach{State: PeerExpired, Reason: reason + "; reauthenticate it to bring it back"}
	case !p.Online:
		return PeerReach{State: PeerOffline, Reason: "the tailnet reports this device offline"}
	case !p.InMagicSock:
		return PeerReach{
			State: PeerNoPath,
			Reason: "the tailnet lists this device but this node is not tracking it, so nothing reaches it " +
				"and its name does not resolve; restarting the node rebuilds the netmap",
		}
	case !p.InEngine:
		// Idle, and the relay named for it is where a path would start rather than one it
		// is paying for, so this stops short of the arm below.
		return PeerReach{State: PeerReady}
	case p.CurAddr == "" && p.Relay != "":
		return PeerReach{State: PeerRelayed, Reason: "reachable only through the " + p.Relay + " relay, which costs latency on every packet"}
	default:
		return PeerReach{State: PeerReady}
	}
}

// PeerLocation is where a peer is, as the control plane reports it. It is the part of
// tailcfg.Location worth showing beside an exit node: a picker offering thirty Mullvad
// nodes is unusable without it.
type PeerLocation struct {
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	City        string `json:"city,omitempty"`
	// Priority orders exit nodes within one place, highest first. Zero means the node
	// expressed no preference.
	Priority int `json:"priority,omitempty"`
}

// Label renders a location as a person names a place, or empty when there is nothing to
// name. City and country together are what distinguishes two nodes in the same country.
func (l PeerLocation) Label() string {
	switch {
	case l.City != "" && l.Country != "":
		return l.City + ", " + l.Country
	case l.City != "":
		return l.City
	default:
		return l.Country
	}
}

// dialPlanner reports the address a dial would resolve to and whether that dial
// leaves through the tailnet. It mirrors tsdial's own signature so the backend's
// classifier drops straight in, and it is a named type so a test can substitute one
// without a tailnet.
type dialPlanner func(ctx context.Context, network, address string) (netip.AddrPort, bool, error)

// Options configures a Node.
type Options struct {
	Params ServerParams
	Logger *slog.Logger
	// Verbose routes the backend's own debug logging to the logger.
	Verbose bool
	// Grants hears every route and resolver change the helper refused for a missing approval,
	// and every one it accepted, in interface mode. The engine swallows a failed change, so
	// this is the only place a refusal can be seen from. Nil hears nothing.
	Grants grants.Observer
}

// Node is a live tailnet identity: one tsnet server, its cached state, and the
// tailnet-side dial/listen operations forwards run on.
type Node struct {
	srv    backend
	params ServerParams
	logger *slog.Logger

	// mu guards every field below it. The backend client and the watcher's cancel
	// are written when the node starts and read by API handlers on other goroutines,
	// so they belong under the same lock as the cached status.
	mu     sync.RWMutex
	status Status
	ip4    netip.Addr
	ip6    netip.Addr
	lc     *local.Client
	cancel context.CancelFunc
	// prefs is the last value the event stream carried, and prefsKnown says whether
	// one has arrived. The two are separate because every preference this app models
	// is a bool: a zero value and "not read yet" are otherwise the same thing, and
	// reporting the first as the second is how a false drift alarm gets raised.
	prefs      Prefs
	prefsKnown bool
	// started records that the tsnet server owns resources, which is what makes
	// closing it safe. tsnet's own Close panics if Start never ran.
	started bool

	events chan struct{}

	// Backend access points, set once the local client exists. They are fields
	// rather than methods so the watch loop can be driven without a tailnet. Only
	// the watch goroutine reads them, and publish happens before it is started.
	openBus     func(ctx context.Context) (busWatcher, error)
	fetchStatus func(ctx context.Context) (*ipnstate.Status, error)
	// plan classifies an address the way a dial would route it. Unlike the two
	// above it is read by API goroutines, so it is guarded by mu.
	plan dialPlanner

	// The peer-bearing status and when it was fetched, guarded by their own mutex
	// rather than mu: fetching one takes a backend round trip, and holding the lock
	// that every status read needs for the length of that would serialise the whole
	// API behind the slowest netmap walk.
	statusMu      sync.Mutex
	fullStatusVal *ipnstate.Status
	fullStatusAt  time.Time
	// clock is what the cache ages against. Tests substitute one so a TTL expiring is
	// something a test states rather than something it waits for.
	clock func() time.Time

	closeOnce sync.Once
	watchDone chan struct{}

	// loginURLs keeps the login URL out of everything the tailscale stack logs through
	// this node.
	loginURLs loginURLRedactor
}

// now reads the clock, defaulting to the real one.
func (n *Node) now() time.Time {
	if n.clock != nil {
		return n.clock()
	}
	return time.Now()
}

// New builds a node from resolved parameters. It does not contact the network.
//
// Which stack it is built on follows from the parameters alone, so every caller keeps
// one construction seam: an agent that knows nothing about interfaces builds a TUN node
// by passing settings that ask for one.
func New(opts Options) *Node {
	// Before any stack exists, so nothing a node logs is ever queued for upload.
	disableLogUpload()
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	node := &Node{
		params:    opts.Params,
		logger:    logger,
		events:    make(chan struct{}, 1),
		watchDone: make(chan struct{}),
		status:    Status{BackendState: StateNoState, AuthMode: opts.Params.Mode},
	}
	userLogf := node.loginURLs.wrap(func(format string, args ...any) { logger.Info(fmt.Sprintf(format, args...)) })
	logf := backendLogf(opts, logger, &node.loginURLs)
	if opts.Params.TUN() {
		node.srv = newTUNBackend(opts, logf, userLogf)
		return node
	}
	srv := &tsnet.Server{
		Hostname:      opts.Params.Hostname,
		Dir:           opts.Params.Dir,
		ControlURL:    opts.Params.ControlURL,
		AuthKey:       opts.Params.AuthKey,
		ClientSecret:  opts.Params.ClientSecret,
		AdvertiseTags: opts.Params.AdvertiseTags,
		Ephemeral:     opts.Params.Ephemeral,
		UserLogf:      userLogf,
		Logf:          logf,
	}
	node.srv = srv
	return node
}

// backendLogf routes the tailscale stack's own logging. It is extremely chatty, so the
// lines are discarded unless the user asked for them: at Debug they are worth having and
// at anything else they bury every line this app writes itself. What is kept passes
// through the login URL redactor first.
func backendLogf(opts Options, logger *slog.Logger, redactor *loginURLRedactor) func(string, ...any) {
	if !opts.Verbose {
		return func(string, ...any) {}
	}
	return redactor.wrap(func(format string, args ...any) { logger.Debug(fmt.Sprintf(format, args...)) })
}

// Start brings the node up and begins watching the IPN bus. It returns as soon as
// the backend is started; callers observe readiness through Status and Events.
func (n *Node) Start(ctx context.Context) error {
	if err := removeLogBuffers(n.params.Dir); err != nil {
		return fmt.Errorf("start tailnet node: %w", err)
	}
	if err := n.srv.Start(); err != nil {
		return fmt.Errorf("start tailnet node: %w", err)
	}
	// Past this point the tsnet server holds resources, including open files under the
	// state directory, so Close has to shut it down even if the rest of Start fails.
	//
	// Nothing locks that directory: the backend's store rewrites the whole file on every
	// write, so two nodes pointed at one directory overwrite each other's identity with no
	// error from either. Whoever builds nodes gives each its own directory, and that is the
	// only thing keeping them apart.
	n.mu.Lock()
	n.started = true
	n.mu.Unlock()

	lc, err := n.srv.LocalClient()
	if err != nil {
		return fmt.Errorf("open local client: %w", err)
	}

	watchCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	n.publish(lc, cancel)
	go n.watch(watchCtx)
	return nil
}

// publish makes the backend client and the watcher's cancel visible to the rest of
// the process. The lock is taken only for the assignment -- never across srv.Start
// or LocalClient -- so a Status reader is never parked behind backend I/O.
func (n *Node) publish(lc *local.Client, cancel context.CancelFunc) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lc = lc
	n.cancel = cancel
	n.openBus = func(ctx context.Context) (busWatcher, error) {
		// InitialPrefs is what makes the first value arrive without a round trip;
		// every later change is delivered regardless of the mask.
		return lc.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyInitialPrefs)
	}
	n.fetchStatus = func(ctx context.Context) (*ipnstate.Status, error) {
		return lc.StatusWithoutPeers(ctx)
	}
	// The engine registers its dialer during Start, which has already returned by the
	// time publish runs. Reading it here rather than per call keeps the subsystem
	// lookup out of the hot path.
	n.plan = dialPlanFrom(n.srv.Sys())
}

// dialPlanFrom reads the classifier out of the engine's subsystem registry. It is
// separate from publish so both answers are reachable without an engine.
//
// A node with no engine yet -- Sys is nil until Start builds one, and the dialer is
// registered during Start -- gets no classifier, and Reach then refuses to classify
// rather than answering from a second source. GetOK is what makes that a nil return
// rather than a panic: the registry's plain Get panics when the subsystem is unset.
func dialPlanFrom(sys *tsd.System) dialPlanner {
	if sys == nil {
		return nil
	}
	dialer, ok := sys.Dialer.GetOK()
	if !ok {
		return nil
	}
	return dialer.UserDialPlan
}

// client returns the backend client, or nil before Start and after Close.
func (n *Node) client() *local.Client {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.lc
}

// Close stops the watcher and shuts the node down. Tailnet operations that arrive
// afterwards report ErrNotRunning rather than an opaque failure from a dead backend,
// which is what makes the window during a restart honest.
//
// A node whose server never started is left alone: tsnet's Close is documented as
// unsafe before Start and panics there, and a node that failed to start is still
// published, so closing it blindly would turn a failed start into a crash.
func (n *Node) Close() error {
	var err error
	n.closeOnce.Do(func() {
		n.mu.Lock()
		cancel, started := n.cancel, n.started
		n.mu.Unlock()

		if cancel != nil {
			cancel()
			<-n.watchDone
		}
		if started {
			err = n.srv.Close()
		}

		n.mu.Lock()
		n.lc = nil
		// The dialer belongs to the engine that just shut down. Left in place it
		// would answer from a torn-down routing table, and a caller enforcing scope
		// would act on it.
		n.plan = nil
		n.mu.Unlock()
	})
	return err
}

// Status returns the current cached node state.
func (n *Node) Status() Status {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := n.status.clone()
	// Filled here rather than stored, because the cached status is replaced wholesale
	// every time the backend reports one and a stored copy would be dropped with it.
	// The parameters are fixed for this node's life, so this is the source of truth.
	out.Network = n.params.Network
	return out
}

func (s Status) clone() Status {
	out := s
	out.TailscaleIPs = append([]string(nil), s.TailscaleIPs...)
	out.Tags = append([]string(nil), s.Tags...)
	return out
}

// Events signals that the node's state changed. It coalesces: a single pending
// signal may cover several transitions, so consumers must read Status for truth.
func (n *Node) Events() <-chan struct{} { return n.events }

// StartLogin begins interactive login. It is always safe to call: the backend
// re-issues a fresh auth URL, which matters because a cached URL can expire.
func (n *Node) StartLogin(ctx context.Context) error {
	lc := n.client()
	if lc == nil {
		return ErrNotRunning
	}
	if err := lc.StartLoginInteractive(ctx); err != nil {
		return fmt.Errorf("start interactive login: %w", err)
	}
	return nil
}

// Logout drops this node's identity; the backend returns to NeedsLogin.
func (n *Node) Logout(ctx context.Context) error {
	lc := n.client()
	if lc == nil {
		return ErrNotRunning
	}
	if err := lc.Logout(ctx); err != nil {
		return fmt.Errorf("log out: %w", err)
	}
	return nil
}

// fullStatusTTL is how long a peer-bearing status is reused.
//
// Short enough that nothing on screen is visibly stale, long enough that one dashboard
// poll costs one backend call instead of four: the routes view alone asks twice, and the
// DNS view and the peer list ask again. The backend caches none of this -- every call
// walks the whole netmap building a status per peer, under the same lock that serves the
// packet path -- so the cost is real on a large tailnet.
const fullStatusTTL = time.Second

// fullStatus is the tailnet status including peers, reused for a moment.
//
// Deliberately not the same thing as Status(), which is a free read of a cache the event
// stream maintains from the peer-less StatusWithoutPeers. This one costs a backend round
// trip and carries every peer, so it is fetched only when something actually needs them.
func (n *Node) fullStatus(ctx context.Context) (*ipnstate.Status, error) {
	lc := n.client()
	if lc == nil {
		return nil, ErrNotRunning
	}

	n.statusMu.Lock()
	defer n.statusMu.Unlock()

	if n.fullStatusAt.IsZero() || n.now().Sub(n.fullStatusAt) >= fullStatusTTL {
		st, err := lc.Status(ctx)
		if err != nil {
			// The previous answer is not served in place of an error: a caller that
			// cannot tell a stale reading from a live one would report a peer as online
			// after the backend stopped answering for it.
			return nil, fmt.Errorf("fetch tailnet status: %w", err)
		}
		n.fullStatusVal = st
		n.fullStatusAt = n.now()
	}
	return n.fullStatusVal, nil
}

// Peers lists tailnet devices, with what the tailnet has actually carried to and from
// each one. It queries the backend rather than the event-fed cache because peer lists are
// large, and shares one short-lived answer with every other caller that needs peers.
func (n *Node) Peers(ctx context.Context) ([]Peer, error) {
	st, err := n.fullStatus(ctx)
	if err != nil {
		return nil, err
	}
	return peersFromStatus(st), nil
}

func peersFromStatus(st *ipnstate.Status) []Peer {
	if st == nil {
		return nil
	}
	peers := make([]Peer, 0, len(st.Peer))
	for _, ps := range st.Peer {
		if ps == nil || ps.ShareeNode {
			continue
		}
		peer := Peer{
			ID:              string(ps.ID),
			HostName:        ps.HostName,
			DNSName:         trimDNSName(ps.DNSName),
			IPs:             addrsToStrings(ps.TailscaleIPs),
			Online:          ps.Online,
			OS:              ps.OS,
			Tags:            tagsOf(ps),
			ExitNodeOption:  ps.ExitNodeOption,
			ExitNodeCurrent: ps.ExitNode,
			Location:        locationOf(ps.Location),
			RxBytes:         ps.RxBytes,
			TxBytes:         ps.TxBytes,
			CurAddr:         ps.CurAddr,
			Relay:           ps.Relay,
			LastHandshake:   ps.LastHandshake,
			Active:          ps.Active,
			InEngine:        ps.InEngine,
			InMagicSock:     ps.InMagicSock,
			Expired:         ps.Expired,
			KeyExpiry:       keyExpiryOf(ps),
		}
		peer.Reach = reachOf(peer)
		peers = append(peers, peer)
	}
	// Online devices first, then alphabetical, so the picker is stable and useful.
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Online != peers[j].Online {
			return peers[i].Online
		}
		return peers[i].Label() < peers[j].Label()
	})
	return peers
}

// Label is the peer's human name, for a picker entry or a generated forward's title.
func (p Peer) Label() string {
	if p.HostName != "" {
		return p.HostName
	}
	if p.DNSName != "" {
		return p.DNSName
	}
	return p.ID
}

// DialTarget is the host something reaching this peer should dial, or empty when the
// peer has neither a name nor an address yet.
//
// The MagicDNS name is preferred over an address: it keeps working when the peer's
// tailnet address changes, and resolving it is what the node's own resolver is for.
func (p Peer) DialTarget() string {
	if p.DNSName != "" {
		return p.DNSName
	}
	if len(p.IPs) > 0 {
		return p.IPs[0]
	}
	return ""
}

func locationOf(loc *tailcfg.Location) PeerLocation {
	if loc == nil {
		return PeerLocation{}
	}
	return PeerLocation{
		Country:     loc.Country,
		CountryCode: loc.CountryCode,
		City:        loc.City,
		Priority:    loc.Priority,
	}
}

func tagsOf(ps *ipnstate.PeerStatus) []string {
	if ps.Tags == nil {
		return nil
	}
	out := make([]string, 0, ps.Tags.Len())
	for i := range ps.Tags.Len() {
		out = append(out, ps.Tags.At(i))
	}
	return out
}

// keyExpiryOf flattens the control plane's optional expiry into a zero time, which is
// what "the tailnet named no expiry" and "there is no expiry" both mean to a reader.
func keyExpiryOf(ps *ipnstate.PeerStatus) time.Time {
	if ps.KeyExpiry == nil {
		return time.Time{}
	}
	return *ps.KeyExpiry
}

func addrsToStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// trimDNSName drops the trailing dot from a MagicDNS name so it can be used
// directly in a host:port target.
func trimDNSName(name string) string {
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// TailnetIPs returns this node's tailnet addresses, valid once Running.
func (n *Node) TailnetIPs() (netip.Addr, netip.Addr) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.ip4, n.ip6
}

// Dial opens a connection over the tailnet, resolving MagicDNS names.
// It satisfies forward.Tailnet.
func (n *Node) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !n.Status().Running() {
		return nil, ErrNotRunning
	}
	return n.srv.Dial(ctx, network, address)
}

// Listen accepts TCP connections on this node's tailnet identity.
// It satisfies forward.Tailnet.
func (n *Node) Listen(network string, port uint16) (net.Listener, error) {
	if !n.Status().Running() {
		return nil, ErrNotRunning
	}
	return n.srv.Listen(network, ":"+strconv.Itoa(int(port)))
}

// ListenPacket receives UDP on this node's tailnet IP. tsnet rejects a bare ":port"
// here, so the concrete address is resolved from the node's own IPs.
// It satisfies forward.Tailnet.
func (n *Node) ListenPacket(network string, port uint16) (net.PacketConn, error) {
	if !n.Status().Running() {
		return nil, ErrNotRunning
	}
	ip4, ip6 := n.TailnetIPs()
	ip := ip4
	if !ip.IsValid() {
		ip = ip6
	}
	if !ip.IsValid() {
		return nil, fmt.Errorf("%w: no tailnet IP assigned yet", ErrNotRunning)
	}
	return n.srv.ListenPacket(network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
}

// statusFromBackend projects backend status onto the cached view.
func statusFromBackend(st *ipnstate.Status, mode AuthMode) Status {
	out := Status{AuthMode: mode}
	if st == nil {
		return out
	}
	out.BackendState = st.BackendState
	out.AuthURL = st.AuthURL
	out.TailscaleIPs = addrsToStrings(st.TailscaleIPs)
	if st.CurrentTailnet != nil {
		out.MagicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
	}
	// The backend reports the exit node as a whole struct or not at all, so its
	// presence is the signal; there is no separate "selected but inactive" state here.
	out.ExitNodeActive = st.ExitNodeStatus != nil
	if st.ExitNodeStatus != nil {
		out.ExitNodeID = string(st.ExitNodeStatus.ID)
		out.ExitNodeOnline = st.ExitNodeStatus.Online
	}
	if st.Self != nil {
		out.Hostname = st.Self.HostName
		out.DNSName = trimDNSName(st.Self.DNSName)
		out.Tags = tagsOf(st.Self)
		if len(out.TailscaleIPs) == 0 {
			out.TailscaleIPs = addrsToStrings(st.Self.TailscaleIPs)
		}
		if user, ok := st.User[st.Self.UserID]; ok {
			out.LoginName = user.LoginName
		}
	}
	return out
}
