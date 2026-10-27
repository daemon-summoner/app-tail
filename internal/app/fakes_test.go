// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/sysproxy"
	"github.com/sellitus/app-tail/internal/testport"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tunnel"
	"github.com/sellitus/app-tail/internal/tunnel/ovpntunnel"
	"github.com/sellitus/app-tail/internal/tunnel/wgtunnel"
)

// fakeNode is a tailnet node that never contacts a control plane. Its dial and
// listen surface runs on loopback, so the agent's forwarding paths are exercised
// with real sockets and no tailnet.
type fakeNode struct {
	mu     sync.Mutex
	status tsnode.Status
	// params records what this node was built with, so a restart test can prove the
	// replacement reflects the new settings.
	params tsnode.ServerParams
	// routes maps a tailnet target to the loopback address standing in for it.
	routes map[string]string
	// subnets are the prefixes this node reports reaching through the tailnet, which
	// is what the browser auto-config script is built from.
	subnets []netip.Prefix
	// approved are the networks the tailnet has approved this node to carry, which is a
	// different set from what it advertised: only an admin puts a prefix in here, and
	// approvedErr is the refusal a backend that cannot answer gives instead.
	approved    []netip.Prefix
	approvedErr error
	// serveErr refuses the subnet hook, which is what a network stack that already has
	// one installed looks like to a caller.
	serveErr error
	// subnetHandler is the hook the subnet router installs, held so a test can see
	// whether one is installed and how many have been removed.
	subnetHandler func(src, dst netip.AddrPort) func(net.Conn)
	subnetStops   int
	// reach is which device carries each accepted route, as a probe would find it, and
	// reachErr the refusal instead.
	reach    []tsnode.RouteReach
	reachErr error
	// dns is what this tailnet's own resolver answers, keyed by name.
	dns map[string]netip.Addr
	// dialCloseErr makes every dialled connection refuse to close, which is the one
	// failure a caller that already got its answer still has to decide what to do about.
	dialCloseErr error
	dnsErr       error
	peers        []tsnode.Peer
	peersErr     error
	routesErr    error
	startErr     error
	closeErr     error
	started      bool
	closed       bool
	loginCall    int
	// observe, when set, is told when the node is closed and when the subnet hook is
	// removed, so a test can place those among the steps other fakes take.
	observe func(step string)

	// prefs is what this node holds as its own preferences, and prefsKnown says
	// whether it has reported any yet -- a node that has just come up has not.
	prefs      tsnode.Prefs
	prefsKnown bool
	prefsEdits int
	checkErr   error
	editErr    error
	// revertPrefs, when set, is put back after every edit, standing in for something
	// outside this app -- another client, a control-plane policy -- that keeps changing
	// a preference back.
	revertPrefs *tsnode.Prefs

	// suggestion is what the tailnet recommends as an exit node, and suggestErr the
	// refusal instead. The empty suggestion with no error is the ordinary answer on a
	// tailnet whose exit nodes are all self-hosted.
	suggestion tsnode.Suggestion
	suggestErr error
	// latency is the round trip each peer address answers a measurement with, keyed by
	// address; an address with no entry does not answer at all.
	latency  map[string]time.Duration
	pingCall int

	// lock is what tailnet lock means for this device, and lockErr the refusal instead.
	// A tailnet with lock off is the zero value, which is the ordinary case.
	lock     tsnode.LockStatus
	lockErr  error
	lockLog  []tsnode.LockUpdate
	logErr   error
	logMax   int
	signed   [][2]string
	signErr  error
	disabled int
	disErr   error

	// tailnetDNS is what the tailnet publishes and machineDNS what this machine resolves
	// with. machineErr defaults to tsnode.ErrDNSNotManaged in newFakeNode because that is
	// the answer in the mode app-tail ships in, and a fake that answered otherwise would
	// let a view claiming the machine was changed pass.
	tailnetDNS    tsnode.TailnetDNS
	tailnetDNSErr error
	machineDNS    tsnode.MachineDNS
	machineErr    error
	// exitDNS is the exit nodes that answer DNS, keyed by stable ID.
	exitDNS    map[string]bool
	exitDNSErr error

	events chan struct{}
}

func newFakeNode() *fakeNode {
	return &fakeNode{
		status: tsnode.Status{BackendState: tsnode.StateNoState},
		routes: make(map[string]string),
		// The real node in userspace mode has no machine DNS configuration to report, and
		// that is the answer rather than a failure. Defaulting to it here keeps every test
		// that does not care about DNS on the same footing as the shipping app.
		machineErr: tsnode.ErrDNSNotManaged,
		events:     make(chan struct{}, 1),
	}
}

func (n *fakeNode) Status() tsnode.Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.status
}

// setState moves the node to a backend state and signals the agent, the way the
// real IPN bus watcher does.
func (n *fakeNode) setState(state string) {
	n.mu.Lock()
	n.status.BackendState = state
	if state == tsnode.StateRunning {
		n.status.TailscaleIPs = []string{"100.64.0.9"}
		n.status.DNSName = "app-tail-test.tail1234.ts.net"
	}
	n.mu.Unlock()
	n.signal()
}

func (n *fakeNode) signal() {
	select {
	case n.events <- struct{}{}:
	default:
	}
}

func (n *fakeNode) route(target, loopback string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes[target] = loopback
	// The proxy dials the address its classifier resolved rather than the name it was
	// handed, so the resolved form has to be routable here too.
	n.routes[loopback] = loopback
}

func (n *fakeNode) Events() <-chan struct{} { return n.events }

func (n *fakeNode) Start(context.Context) error {
	n.mu.Lock()
	if n.startErr != nil {
		err := n.startErr
		n.mu.Unlock()
		return err
	}
	n.started = true
	n.status.BackendState = tsnode.StateStarting
	n.mu.Unlock()
	n.signal()
	return nil
}

func (n *fakeNode) Close() error {
	n.mu.Lock()
	n.closed = true
	err, observe := n.closeErr, n.observe
	n.mu.Unlock()
	if observe != nil {
		observe("node close")
	}
	return err
}

// setProblem publishes a control-plane complaint the way the IPN bus watcher does when
// it folds an ErrMessage into the node's status. It is the only way a backend error
// reaches the agent, and from there the tray and /healthz.
func (n *fakeNode) setProblem(problem string) {
	n.mu.Lock()
	n.status.Problem = problem
	n.mu.Unlock()
	n.signal()
}

func (n *fakeNode) wasClosed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

func (n *fakeNode) wasStarted() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.started
}

func (n *fakeNode) StartLogin(context.Context) error {
	n.mu.Lock()
	n.loginCall++
	n.status.BackendState = tsnode.StateNeedsLogin
	n.status.AuthURL = fmt.Sprintf("https://login.example/%d", n.loginCall)
	n.mu.Unlock()
	n.signal()
	return nil
}

func (n *fakeNode) Logout(context.Context) error {
	n.setState(tsnode.StateNeedsLogin)
	return nil
}

func (n *fakeNode) Peers(context.Context) ([]tsnode.Peer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.peersErr != nil {
		return nil, n.peersErr
	}
	return n.peers, nil
}

func (n *fakeNode) SuggestExitNode(context.Context) (tsnode.Suggestion, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.suggestion, n.suggestErr
}

// PingPeer answers with whatever round trip this address was given. An address with no
// entry never answers, which is how a device that is listed but unreachable is modelled.
func (n *fakeNode) PingPeer(ctx context.Context, ip netip.Addr) (time.Duration, error) {
	n.mu.Lock()
	latency, ok := n.latency[ip.String()]
	n.pingCall++
	n.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("ping %s: no answer", ip)
	}
	return latency, ctx.Err()
}

func (n *fakeNode) NetworkLock(context.Context) (tsnode.LockStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.lockErr != nil {
		return tsnode.LockStatus{}, n.lockErr
	}
	return n.lock, nil
}

func (n *fakeNode) LockLog(_ context.Context, max int) ([]tsnode.LockUpdate, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.logMax = max
	if n.logErr != nil {
		return nil, n.logErr
	}
	return n.lockLog, nil
}

func (n *fakeNode) SignNode(_ context.Context, nodeKey, rotationKey string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.signErr != nil {
		return n.signErr
	}
	n.signed = append(n.signed, [2]string{nodeKey, rotationKey})
	return nil
}

func (n *fakeNode) DisableLockLocally(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.disabled++
	return n.disErr
}

func (n *fakeNode) TailnetDNS(context.Context) (tsnode.TailnetDNS, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.tailnetDNSErr != nil {
		return tsnode.TailnetDNS{}, n.tailnetDNSErr
	}
	return n.tailnetDNS, nil
}

func (n *fakeNode) MachineDNS(context.Context) (tsnode.MachineDNS, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.machineErr != nil {
		return tsnode.MachineDNS{}, n.machineErr
	}
	return n.machineDNS, nil
}

func (n *fakeNode) ExitNodeAnswersDNS(_ context.Context, stableID string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.exitDNSErr != nil {
		return false, n.exitDNSErr
	}
	return n.exitDNS[stableID], nil
}

// setSuggestion is what the tailnet answers a request for a recommendation with.
func (n *fakeNode) setSuggestion(s tsnode.Suggestion, err error) {
	n.mu.Lock()
	n.suggestion, n.suggestErr = s, err
	n.mu.Unlock()
}

// setExitNodeStatus publishes what the backend reports about the exit node actually
// carrying traffic, which is the live side of the exit-node card and is not the same as
// the device this app asked for.
func (n *fakeNode) setExitNodeStatus(id string, online bool) {
	n.mu.Lock()
	n.status.ExitNodeID, n.status.ExitNodeOnline = id, online
	// An exit node in use is what the backend reports as traffic being carried through one,
	// so the two move together here as they do there. Setting only the id would leave this
	// node reporting a chosen exit node that nothing is going through.
	n.status.ExitNodeActive = id != ""
	n.mu.Unlock()
	n.signal()
}

// setLatency gives each address a round trip to answer measurements with.
func (n *fakeNode) setLatency(latency map[string]time.Duration) {
	n.mu.Lock()
	n.latency = latency
	n.mu.Unlock()
}

// pingCalls is how many measurements have been asked for, which is what proves a probe
// round happened rather than the decision falling back to an unmeasured order.
func (n *fakeNode) pingCalls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.pingCall
}

// setPeers replaces the device list the node reports, the way a netmap update does.
func (n *fakeNode) setPeers(peers ...tsnode.Peer) {
	n.mu.Lock()
	n.peers, n.peersErr = peers, nil
	n.mu.Unlock()
	n.signal()
}

// failPeers makes the device list unreadable, which is what a backend that has not
// finished starting looks like to a caller.
func (n *fakeNode) failPeers(err error) {
	n.mu.Lock()
	n.peersErr = err
	n.mu.Unlock()
	n.signal()
}

// Dial reaches the loopback stand-in for a tailnet target, so an unrouted target
// fails the way an ACL denial would.
func (n *fakeNode) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	n.mu.Lock()
	dest, ok := n.routes[address]
	closeErr := n.dialCloseErr
	n.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no route to %s (would be denied by tailnet ACLs)", address)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, dest)
	if err != nil || closeErr == nil {
		return conn, err
	}
	return failingCloseConn{Conn: conn, err: closeErr}, nil
}

// failCloses makes every connection this node hands out refuse to close, which is what a
// netstack conn does when the stack under it has already gone.
func (n *fakeNode) failCloses(err error) {
	n.mu.Lock()
	n.dialCloseErr = err
	n.mu.Unlock()
}

// failingCloseConn is a working connection that will not close cleanly. Closing the real
// one underneath keeps the test from leaking a socket.
type failingCloseConn struct {
	net.Conn
	err error
}

func (c failingCloseConn) Close() error {
	_ = c.Conn.Close()
	return c.err
}

// Reach classifies a target the same way Dial resolves one, so the proxy's scope check
// and its dial agree. An unrouted target is unclassifiable rather than public: the fake
// has no notion of a destination off the tailnet, and reporting one would let a
// wide-scope test pass for the wrong reason.
func (n *fakeNode) Reach(_ context.Context, _, address string) (tsnode.Reach, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	dest, ok := n.routes[address]
	if !ok {
		return tsnode.Reach{}, fmt.Errorf("no route to %s (would be denied by tailnet ACLs)", address)
	}
	addr, err := netip.ParseAddrPort(dest)
	if err != nil {
		return tsnode.Reach{}, fmt.Errorf("the stand-in route %q for %s is not an ip:port: %w", dest, address, err)
	}
	return tsnode.Reach{Addr: addr, ViaTailnet: true}, nil
}

// LookupTailnet answers from the names this tailnet's own resolver was given. A name it
// was not given comes back served by nothing, which is how the real resolver reports a
// name outside the tailnet's DNS.
func (n *fakeNode) LookupTailnet(_ context.Context, host string) (tsnode.TailnetLookup, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dnsErr != nil {
		return tsnode.TailnetLookup{}, n.dnsErr
	}
	addr, ok := n.dns[host]
	if !ok {
		return tsnode.TailnetLookup{}, nil
	}
	return tsnode.TailnetLookup{Addrs: []netip.Addr{addr}, TTL: time.Minute}, nil
}

// resolveAs makes host resolve to addr through the tailnet's own resolver, standing in
// for a split-DNS domain the admin console points at a private nameserver.
func (n *fakeNode) resolveAs(host string, addr netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dns == nil {
		n.dns = make(map[string]netip.Addr)
	}
	n.dns[host] = addr
}

func (n *fakeNode) Routes(context.Context) ([]netip.Prefix, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.routesErr != nil {
		return nil, n.routesErr
	}
	return append([]netip.Prefix(nil), n.subnets...), nil
}

// setSubnets is what this tailnet reports reaching, written under the lock the reader
// takes: the agent reads it from its own goroutines while a test is still arranging the
// world, and an unguarded write there is a race the detector fails the suite on.
func (n *fakeNode) setSubnets(prefixes ...netip.Prefix) {
	n.mu.Lock()
	n.subnets = prefixes
	n.mu.Unlock()
}

// failRoutes makes the routes this tailnet reaches unreadable, which is what a control
// plane that is not answering looks like to a caller.
func (n *fakeNode) failRoutes(err error) {
	n.mu.Lock()
	n.routesErr = err
	n.mu.Unlock()
}

func (n *fakeNode) ApprovedRoutes(context.Context) ([]netip.Prefix, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.approvedErr != nil {
		return nil, n.approvedErr
	}
	return append([]netip.Prefix(nil), n.approved...), nil
}

// ServeSubnets records the handler the way the real netstack hook does: one handler at a
// time, removed by the returned function. Holding it is what lets a test see whether the
// agent has the router installed at all.
func (n *fakeNode) ServeSubnets(h func(src, dst netip.AddrPort) func(net.Conn)) (func(), error) {
	if !n.Status().Running() {
		return nil, tsnode.ErrNotRunning
	}
	n.mu.Lock()
	if err := n.serveErr; err != nil {
		n.mu.Unlock()
		return nil, err
	}
	n.subnetHandler = h
	n.mu.Unlock()
	return func() {
		n.mu.Lock()
		n.subnetHandler = nil
		n.subnetStops++
		observe := n.observe
		n.mu.Unlock()
		if observe != nil {
			observe("subnet router stop")
		}
	}, nil
}

func (n *fakeNode) RouteReachability(context.Context) ([]tsnode.RouteReach, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.reachErr != nil {
		return nil, n.reachErr
	}
	return append([]tsnode.RouteReach(nil), n.reach...), nil
}

// carrying reports whether a subnet handler is installed on this node.
func (n *fakeNode) carrying() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.subnetHandler != nil
}

// subnetStopCount reports how many handlers have been removed from this node, which is
// what tells a re-registration apart from one left behind on a node that is gone.
func (n *fakeNode) subnetStopCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.subnetStops
}

// --- node preferences -----------------------------------------------------
//
// The real backend validates an edit, applies it, and republishes the result on the
// IPN bus. This models exactly that contract -- including the part that matters most
// here, that a preference can change without this app asking.

func (n *fakeNode) CachedPrefs() (tsnode.Prefs, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.prefs, n.prefsKnown
}

func (n *fakeNode) CheckPrefs(_ context.Context, _ tsnode.PrefsPatch) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.checkErr
}

func (n *fakeNode) EditPrefs(_ context.Context, patch tsnode.PrefsPatch) (tsnode.Prefs, error) {
	n.mu.Lock()
	if n.editErr != nil {
		err := n.editErr
		n.mu.Unlock()
		return tsnode.Prefs{}, err
	}
	n.prefsEdits++
	// Every member the patch names is applied, the way the backend applies a masked edit.
	// A fake that dropped one would let a setting read as pushed while the preference it
	// names never moved.
	if patch.RouteAll != nil {
		n.prefs.RouteAll = *patch.RouteAll
	}
	if patch.ExitNodeID != nil {
		n.prefs.ExitNodeID = *patch.ExitNodeID
	}
	if patch.AutoExitNode != nil {
		n.prefs.AutoExitNode = *patch.AutoExitNode
	}
	if patch.ExitNodeAllowLANAccess != nil {
		n.prefs.ExitNodeAllowLANAccess = *patch.ExitNodeAllowLANAccess
	}
	if patch.AdvertiseRoutes != nil {
		n.prefs.AdvertiseExitNode = advertisesExitNode(*patch.AdvertiseRoutes)
	}
	n.prefsKnown = true
	if n.revertPrefs != nil {
		n.prefs = *n.revertPrefs
	}
	out := n.prefs
	n.mu.Unlock()
	// The bus carries every accepted edit back, which is what wakes the agent again --
	// and is how it discovers a value that did not stay put.
	n.signal()
	return out, nil
}

// advertisesExitNode reads an advertised route set the way the backend does: offering
// this node as an exit node is both default routes being present, not a preference of
// its own.
func advertisesExitNode(routes []netip.Prefix) bool {
	var v4, v6 bool
	for _, r := range routes {
		switch {
		case r.Bits() == 0 && r.Addr().Is4():
			v4 = true
		case r.Bits() == 0 && r.Addr().Is6():
			v6 = true
		}
	}
	return v4 && v6
}

// publishPrefs delivers a preference value the way the IPN bus does, including the
// first one after a node comes up.
func (n *fakeNode) publishPrefs(prefs tsnode.Prefs) {
	n.mu.Lock()
	n.prefs, n.prefsKnown = prefs, true
	n.mu.Unlock()
	n.signal()
}

// keepPrefs makes every later edit be undone, standing in for another writer of the
// same preferences that will not yield.
func (n *fakeNode) keepPrefs(prefs tsnode.Prefs) {
	n.mu.Lock()
	n.prefs, n.prefsKnown = prefs, true
	n.revertPrefs = &prefs
	n.mu.Unlock()
	n.signal()
}

// yieldPrefs stops undoing edits, standing in for the other writer of the same
// preferences being dealt with somewhere this app cannot see.
func (n *fakeNode) yieldPrefs() {
	n.mu.Lock()
	n.revertPrefs = nil
	n.mu.Unlock()
}

// prefsState reports what the node holds and how many edits it has accepted.
func (n *fakeNode) prefsState() (tsnode.Prefs, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.prefs, n.prefsEdits
}

// refusePrefs makes the node reject a proposed edit, the way the backend does when the
// preferences a patch would produce are not a combination it allows.
func (n *fakeNode) refusePrefs(err error) {
	n.mu.Lock()
	n.checkErr = err
	n.mu.Unlock()
}

// failPrefsEdit makes an accepted edit fail while being applied.
func (n *fakeNode) failPrefsEdit(err error) {
	n.mu.Lock()
	n.editErr = err
	n.mu.Unlock()
}

func (n *fakeNode) Listen(network string, port uint16) (net.Listener, error) {
	return net.Listen(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
}

func (n *fakeNode) ListenPacket(network string, port uint16) (net.PacketConn, error) {
	return net.ListenPacket(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
}

// --- this machine's proxy configuration -----------------------------------

// recordingSystemProxy stands in for the per-user proxy setting the agent writes.
//
// It is substituted for exactly one reason: the real one changes the machine running
// the suite, and only on the one platform that has an implementation. Everything above
// it -- when to apply, when to put back, and what to tell the user instead -- is the
// code under test, and this is what lets it be exercised anywhere.
type recordingSystemProxy struct {
	mu sync.Mutex
	// pointsAt is what the machine currently points at, empty when nothing does.
	pointsAt string
	applies  int
	clears   int
	err      error
	clearErr error
	// observe, when set, is told when the machine is put back, so a test can place that
	// among the steps other fakes take.
	observe func(step string)
}

func (r *recordingSystemProxy) State(pacURL string) sysproxy.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return sysproxy.State{
		Supported:     true,
		AutoConfigURL: r.pointsAt,
		Managed:       r.pointsAt != "",
		Limits:        []string{"a stated limit"},
		Manual:        sysproxy.ManualCommands(pacURL),
	}
}

func (r *recordingSystemProxy) Apply(pacURL string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.pointsAt != pacURL {
		r.applies++
	}
	r.pointsAt = pacURL
	return nil
}

func (r *recordingSystemProxy) Clear() error {
	r.mu.Lock()
	observe := r.observe
	if r.clearErr != nil {
		r.mu.Unlock()
		return r.clearErr
	}
	if r.pointsAt != "" {
		r.clears++
	}
	r.pointsAt = ""
	r.mu.Unlock()
	if observe != nil {
		observe("proxy clear")
	}
	return nil
}

// snapshot reads the recorded state without holding the lock across an assertion.
func (r *recordingSystemProxy) snapshot() (pointsAt string, applies, clears int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pointsAt, r.applies, r.clears
}

// failWith makes every later Apply fail, standing in for a setting the OS refuses.
func (r *recordingSystemProxy) failWith(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

// failClearWith makes every later Clear fail, leaving the machine pointing at this
// proxy. It is kept apart from failWith because refusing to put a setting back is a
// different situation from refusing to write it, and the worse of the two.
func (r *recordingSystemProxy) failClearWith(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearErr = err
}

// fakeNodes hands out the node each connection is built on.
//
// The primary connection keeps one node across rebuilds, because a test driving it holds a
// reference to it and a replacement would leave that reference describing something the
// agent no longer runs. Every other connection gets a fresh one per build, because two
// connections sharing a node would report each other's status and closing one would close
// the other -- which is the very thing a per-connection state directory exists to prevent.
type fakeNodes struct {
	mu sync.Mutex
	// primaryDir is the state directory the connection every install has runs on, which
	// is the root itself rather than a subdirectory.
	primaryDir string
	primary    *fakeNode
	extra      map[string][]*fakeNode
	// built is every node's parameters in build order, which is what a test asserting how
	// a connection was brought up reads.
	built []tsnode.ServerParams
}

func newFakeNodes(primaryDir string, primary *fakeNode) *fakeNodes {
	return &fakeNodes{primaryDir: primaryDir, primary: primary, extra: make(map[string][]*fakeNode)}
}

func (f *fakeNodes) build(o tsnode.Options) NodeController {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.built = append(f.built, o.Params)
	if o.Params.Dir == f.primaryDir {
		return f.primary
	}
	held := newFakeNode()
	f.extra[o.Params.Dir] = append(f.extra[o.Params.Dir], held)
	return held
}

// paramsFor is how a connection with this state directory was built, and whether one ever
// was. The state directory is the identifier here because it is derived from the
// connection id, so it names one connection and nothing else.
func (f *fakeNodes) paramsFor(dir string) (tsnode.ServerParams, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.built) - 1; i >= 0; i-- {
		if f.built[i].Dir == dir {
			return f.built[i], true
		}
	}
	return tsnode.ServerParams{}, false
}

// nodesFor is every node built for one connection, oldest first.
func (f *fakeNodes) nodesFor(dir string) []*fakeNode {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeNode(nil), f.extra[dir]...)
}

// fakeWireGuard is one WireGuard connection that opens no socket and speaks to nothing.
//
// The device itself is covered where it lives, against a second real device: what these
// tests are about is what the agent does with a connection -- when it builds one, when it
// leaves one alone, when it takes one down -- and a real device would put a UDP socket and a
// handshake timer inside every one of them for no added coverage.
type fakeWireGuard struct {
	id   string
	held config.WireGuardTunnel
	// links is what the agent handed this device to learn about the machine's networking
	// moving. The device does nothing with it here; that it arrives at all is the wiring
	// these tests are about.
	links <-chan struct{}
	// through is the connection this one's own packets were to travel inside, and throughMTU
	// the room that connection leaves them. Both are nil and zero for an ordinary connection,
	// which is what makes their presence the whole of "this one is a hop in a chain".
	through    wgtunnel.Carrier
	throughMTU int

	mu       sync.Mutex
	started  bool
	closed   bool
	startErr error
	status   tunnel.Status
	events   chan struct{}
	// anchors is where this connection's own packets go and mtu the largest packet its
	// network carries. Both are zero unless a test sets them, which is the shape of a
	// connection whose transport addresses and packet size are not knowable.
	anchors []netip.Addr
	mtu     int
	// answers is what this network's resolver says about a name, for the connections a test
	// gives one to, and answerErr is that resolver failing to be reached at all.
	answers   map[string][]netip.Addr
	answerErr error
	// routesErr is this connection being unable to say what it reaches while it is up.
	routesErr error
	// dialed is every address something opened a connection to through this one.
	dialed []string
	// carriesExit is this connection's answer to whether it can carry this machine's internet
	// traffic. The real device decides it from the server's own allowed addresses, which is
	// nothing this fake has, so it is set by the test that cares.
	carriesExit bool
	// carried is what this connection says it has moved. The real device reads it off its own
	// report, which this fake has none of, so a test that cares writes it.
	carried tunnel.Carried
}

// resolvingFakeWireGuard is a fake connection whose network publishes resolvers, which is a
// separate type for the reason the real one is: the capability is discovered by type
// assertion, so a connection with no resolvers must not answer to it at all.
type resolvingFakeWireGuard struct{ *fakeWireGuard }

var (
	_ tunnel.Tunnel      = (*fakeWireGuard)(nil)
	_ tunnel.Sized       = (*fakeWireGuard)(nil)
	_ tunnel.Anchored    = (*fakeWireGuard)(nil)
	_ tunnel.ExitCarrier = (*fakeWireGuard)(nil)
	_ tunnel.Metered     = (*fakeWireGuard)(nil)
	_ tunnel.Resolving   = (*resolvingFakeWireGuard)(nil)
)

func (w *fakeWireGuard) MTU() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mtu
}

func (w *fakeWireGuard) Carried() tunnel.Carried {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.carried
}

// carries is what this connection reports having moved.
func (w *fakeWireGuard) carries(carried tunnel.Carried) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.carried = carried
}

func (w *fakeWireGuard) Anchors() []netip.Addr {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.anchors)
}

// LookupHost answers from what the test wrote. A name it was given nothing for comes back
// served by nothing, which is this network saying it does not know the name.
func (w *resolvingFakeWireGuard) LookupHost(_ context.Context, host string) (tunnel.Lookup, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.answerErr != nil {
		return tunnel.Lookup{}, w.answerErr
	}
	return tunnel.Lookup{Addrs: slices.Clone(w.answers[host])}, nil
}

// serves is what this network's resolver answers for one name.
func (w *fakeWireGuard) serves(host string, addrs ...netip.Addr) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.answers == nil {
		w.answers = make(map[string][]netip.Addr)
	}
	w.answers[host] = addrs
}

// failsToResolve is this network's resolver not answering at all, which is a different
// answer from a name it does not serve.
func (w *fakeWireGuard) failsToResolve(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.answerErr = err
}

// reachesItselfAt is where this connection's own packets go, which is what must keep leaving
// through the machine's own network.
func (w *fakeWireGuard) reachesItselfAt(addrs ...netip.Addr) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.anchors = addrs
}

// CanCarryExit is this connection's answer to whether it can carry this machine's internet
// traffic. It defaults to the ordinary WireGuard peer, which carries one network and routes
// nothing on.
func (w *fakeWireGuard) CanCarryExit(context.Context) (bool, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.carriesExit {
		return true, ""
	}
	return false, "this connection's allowed addresses do not include a default route"
}

// carriesInternetTraffic is this connection's server routing everything on.
func (w *fakeWireGuard) carriesInternetTraffic() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.carriesExit = true
}

// carriesNothingOut is this connection no longer routing anything on, which is what a
// connection that dropped looks like to whatever is carried by it.
func (w *fakeWireGuard) carriesNothingOut() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.carriesExit = false
}

// carriedBy is the connection this one's own packets were built to travel inside, and the
// room it was told that connection leaves them.
func (w *fakeWireGuard) carriedBy() (through wgtunnel.Carrier, mtu int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.through, w.throughMTU
}

// carriesPacketsOf is the largest packet this network takes.
func (w *fakeWireGuard) carriesPacketsOf(mtu int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mtu = mtu
}

func newFakeWireGuard(id string, held config.WireGuardTunnel) *fakeWireGuard {
	return &fakeWireGuard{
		id:     id,
		held:   held,
		status: tunnel.Status{State: tunnel.StateOff},
		events: make(chan struct{}, 1),
	}
}

func (w *fakeWireGuard) ID() string              { return w.id }
func (w *fakeWireGuard) Kind() tunnel.Kind       { return tunnel.KindWireGuard }
func (w *fakeWireGuard) Events() <-chan struct{} { return w.events }
func (w *fakeWireGuard) Addrs() []netip.Addr     { return w.held.InterfaceAddrs() }

func (w *fakeWireGuard) Routes(context.Context) ([]netip.Prefix, error) {
	w.mu.Lock()
	routesErr := w.routesErr
	w.mu.Unlock()
	if routesErr != nil {
		return nil, routesErr
	}
	return w.held.CarriedRoutes(), nil
}

// failToSayWhatItReaches is a connection that is up and cannot answer what it carries, which
// is a range missing from an interface that otherwise looks complete.
func (w *fakeWireGuard) failToSayWhatItReaches(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.routesErr = err
}

func (w *fakeWireGuard) Start(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.startErr != nil {
		w.status = tunnel.Status{State: tunnel.StateFailed, Detail: w.startErr.Error()}
		return w.startErr
	}
	w.started = true
	w.status = tunnel.Status{State: tunnel.StateConnected}
	return nil
}

func (w *fakeWireGuard) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	w.status = tunnel.Status{State: tunnel.StateOff}
	return nil
}

func (w *fakeWireGuard) Status() tunnel.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *fakeWireGuard) wasStarted() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.started
}

func (w *fakeWireGuard) wasClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

func (w *fakeWireGuard) failToStart(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.startErr = err
}

func (w *fakeWireGuard) Dial(_ context.Context, _, address string) (net.Conn, error) {
	w.mu.Lock()
	w.dialed = append(w.dialed, address)
	w.mu.Unlock()
	return nil, errors.New("this connection carries nothing in tests")
}

// wasDialed reports that something opened a connection to this address through this
// connection, which is how a caller proves where its traffic actually went.
func (w *fakeWireGuard) wasDialed(address string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Contains(w.dialed, address)
}

func (w *fakeWireGuard) Listen(string, uint16) (net.Listener, error) {
	return nil, errors.New("this connection carries nothing in tests")
}

func (w *fakeWireGuard) ListenPacket(string, uint16) (net.PacketConn, error) {
	return nil, errors.New("this connection carries nothing in tests")
}

// fakeWireGuards hands out the device each WireGuard connection is built on, and remembers
// what each was built from -- which is the whole question a rebuild test asks.
type fakeWireGuards struct {
	mu    sync.Mutex
	built map[string][]*fakeWireGuard
	// nextErr is what the next connection built for an id fails to start with.
	nextErr map[string]error
}

func newFakeWireGuards() *fakeWireGuards {
	return &fakeWireGuards{
		built:   make(map[string][]*fakeWireGuard),
		nextErr: make(map[string]error),
	}
}

func (f *fakeWireGuards) build(o wgtunnel.Options) tunnel.Tunnel {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := newFakeWireGuard(o.ID, o.Held)
	held.links = o.LinkChanges
	held.through, held.throughMTU = o.Through, o.ThroughMTU
	if err := f.nextErr[o.ID]; err != nil {
		held.failToStart(err)
	}
	f.built[o.ID] = append(f.built[o.ID], held)
	if len(o.Held.DNS) == 0 {
		// No resolvers, so nothing can look a name up on this network -- and the capability
		// has to be absent rather than answering with a failure, exactly as the real one is.
		return held
	}
	return &resolvingFakeWireGuard{held}
}

// devicesFor is every device built for one connection, oldest first.
func (f *fakeWireGuards) devicesFor(id string) []*fakeWireGuard {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeWireGuard(nil), f.built[id]...)
}

// refuseToStart makes every device built for this connection from now on fail.
func (f *fakeWireGuards) refuseToStart(id string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextErr[id] = err
}

// fakeOpenVPN stands in for one OpenVPN connection. It carries nothing: what a test asks
// here is what the reconcile does with a connection of this kind, and the conversation with
// the program that would carry the traffic is exercised in the package that holds it.
type fakeOpenVPN struct {
	id   string
	held config.OpenVPNTunnel
	mu   sync.Mutex
	// carry is how this connection carries this machine's internet traffic. It is set when the
	// connection is built and moved by SetCarry, which is the half of the choice a running
	// connection can take without being rebuilt.
	carry   ovpntunnel.Carry
	carries []ovpntunnel.Carry
	// links is what this connection was given to be told the machine's networking moved.
	links <-chan struct{}
	// through is the connection this one's packets were built to travel inside, nil for one
	// dialled over this machine's own network.
	through  ovpntunnel.Carrier
	status   tunnel.Status
	started  bool
	closed   bool
	startErr error
	events   chan struct{}
}

// SetCarry is the live half of choosing which connection carries this machine's internet
// traffic. Every value it is given is kept, so a test can tell one that was applied from one
// the connection was built with.
func (o *fakeOpenVPN) SetCarry(carry ovpntunnel.Carry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.carry = carry
	o.carries = append(o.carries, carry)
}

// carriedAs is how this connection carries the traffic now.
func (o *fakeOpenVPN) carriedAs() ovpntunnel.Carry {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.carry
}

func newFakeOpenVPN(o ovpntunnel.Options) *fakeOpenVPN {
	return &fakeOpenVPN{
		id:      o.ID,
		held:    o.Held,
		carry:   o.Carry,
		links:   o.LinkChanges,
		through: o.Through,
		status:  tunnel.Status{State: tunnel.StateOff},
		events:  make(chan struct{}, 1),
	}
}

func (o *fakeOpenVPN) ID() string              { return o.id }
func (o *fakeOpenVPN) Kind() tunnel.Kind       { return tunnel.KindOpenVPN }
func (o *fakeOpenVPN) Events() <-chan struct{} { return o.events }
func (o *fakeOpenVPN) Addrs() []netip.Addr     { return nil }

func (o *fakeOpenVPN) Routes(context.Context) ([]netip.Prefix, error) {
	return o.held.CarriedRoutes(), nil
}

func (o *fakeOpenVPN) Start(context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.startErr != nil {
		o.status = tunnel.Status{State: tunnel.StateFailed, Detail: o.startErr.Error()}
		return o.startErr
	}
	o.started = true
	o.status = tunnel.Status{State: tunnel.StateConnected}
	return nil
}

func (o *fakeOpenVPN) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	o.status = tunnel.Status{State: tunnel.StateOff}
	return nil
}

func (o *fakeOpenVPN) Status() tunnel.Status {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.status
}

func (o *fakeOpenVPN) wasStarted() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.started
}

func (o *fakeOpenVPN) wasClosed() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed
}

func (o *fakeOpenVPN) failToStart(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.startErr = err
}

func (o *fakeOpenVPN) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("this connection carries nothing in tests")
}

func (o *fakeOpenVPN) Listen(string, uint16) (net.Listener, error) {
	return nil, errors.New("this connection carries nothing in tests")
}

func (o *fakeOpenVPN) ListenPacket(string, uint16) (net.PacketConn, error) {
	return nil, errors.New("this connection carries nothing in tests")
}

// fakeOpenVPNs hands out the connection each OpenVPN entry is built on, and stands in for the
// claim on the privileged side that the real ones run through.
//
// The claim is the reason this fake exists at all rather than only the connection: opening the
// real one asks the machine for administrator rights and would start a program as root, which
// a suite must never do to the machine it happens to be running on.
type fakeOpenVPNs struct {
	mu     sync.Mutex
	built  map[string][]*fakeOpenVPN
	claims int
	closes int
	// nextErr is what the next connection built for an id fails to start with.
	nextErr map[string]error
	// claimErr is what claiming the privileged side fails with, for the machine that cannot
	// grant it.
	claimErr error
}

func newFakeOpenVPNs() *fakeOpenVPNs {
	return &fakeOpenVPNs{
		built:   make(map[string][]*fakeOpenVPN),
		nextErr: make(map[string]error),
	}
}

func (f *fakeOpenVPNs) build(o ovpntunnel.Options) tunnel.Tunnel {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := newFakeOpenVPN(o)
	if err := f.nextErr[o.ID]; err != nil {
		held.failToStart(err)
	}
	f.built[o.ID] = append(f.built[o.ID], held)
	return held
}

func (f *fakeOpenVPNs) open(context.Context, func(string, ...any)) (ovpntunnel.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	f.claims++
	return fakeOpenVPNSession{f}, nil
}

// connectionsFor is every connection built for one stored entry, oldest first.
func (f *fakeOpenVPNs) connectionsFor(id string) []*fakeOpenVPN {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeOpenVPN(nil), f.built[id]...)
}

// held reports how many claims on the privileged side are outstanding. Exactly one while any
// OpenVPN connection is up and none otherwise: dropping the claim stops every program started
// through it, so releasing it early would take a running connection down with it.
func (f *fakeOpenVPNs) held() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claims - f.closes
}

// refuseToClaim is the machine that will not grant administrator rights.
func (f *fakeOpenVPNs) refuseToClaim(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimErr = err
}

// fakeOpenVPNSession is the claim itself. It records rather than runs anything.
type fakeOpenVPNSession struct{ owner *fakeOpenVPNs }

// Neither of these runs anything: the connections this harness builds are fakes that never
// ask for a program to be started, and what the real one says over the management socket is
// exercised in the package that holds that conversation.
func (s fakeOpenVPNSession) StartOpenVPN(context.Context, ovpntunnel.Run) error { return nil }

func (s fakeOpenVPNSession) StopOpenVPN(context.Context, string) error { return nil }

func (s fakeOpenVPNSession) ScopeOpenVPN(context.Context, ovpntunnel.Scope) error { return nil }

func (s fakeOpenVPNSession) UnscopeOpenVPN(context.Context, string) error { return nil }

func (s fakeOpenVPNSession) Close() error {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	s.owner.closes++
	return nil
}

// fakeLinks stands in for the machine's own network monitor. It watches nothing: the real
// one subscribes to the operating system's interface notifications, which a suite must not
// do once per connection it starts.
//
// It keeps every context it was given, which is how a test asks the question that actually
// matters here -- whether a watcher outlives the connection it was opened for.
type fakeLinks struct {
	mu    sync.Mutex
	given []context.Context
}

func newFakeLinks() *fakeLinks { return &fakeLinks{} }

func (f *fakeLinks) watch(ctx context.Context) (<-chan struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.given = append(f.given, ctx)
	return make(chan struct{}), nil
}

// watchers is every context handed out, oldest first.
func (f *fakeLinks) watchers() []context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]context.Context(nil), f.given...)
}

// --- harness --------------------------------------------------------------

type harness struct {
	t     *testing.T
	agent *Agent
	node  *fakeNode
	// nodes is every node this harness built, which is how a test reaches a connection
	// other than the primary one.
	nodes *fakeNodes
	// wireguards is every WireGuard device this harness built, on the same terms.
	wireguards *fakeWireGuards
	// openvpns is every OpenVPN connection this harness built, and the claim on the
	// privileged side they would otherwise run through.
	openvpns *fakeOpenVPNs
	// links is the machine's network monitor, which watches nothing here.
	links    *fakeLinks
	store    *config.Store
	sysproxy *recordingSystemProxy
	stateDir string
	baseURL  string
	runErr   chan error
	cancel   context.CancelFunc
	// stopped keeps the cleanup from waiting a second time on an exit already taken.
	stopped bool
}

func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newHarness builds an agent over a throwaway state dir and runs it. seed may edit
// the stored config before the agent starts.
func newHarness(t *testing.T, seed func(*config.Config)) *harness {
	t.Helper()
	return newHarnessWith(t, seed, nil)
}

// tailnetOf is the tailnet block of the connection this app has always run, inside a
// document a test is seeding. The settings that name a tailnet live on it now, so a test
// that varies what this node joins with writes here.
func tailnetOf(t *testing.T, c *config.Config) *config.TailscaleTunnel {
	t.Helper()
	for i := range c.Tunnels {
		if c.Tunnels[i].ID != config.PrimaryTunnelID {
			continue
		}
		if c.Tunnels[i].Tailscale == nil {
			c.Tunnels[i].Tailscale = &config.TailscaleTunnel{}
		}
		return c.Tunnels[i].Tailscale
	}
	t.Fatalf("the document carries no %q connection", config.PrimaryTunnelID)
	return nil
}

// proxyOf is the default proxy instance inside a document a test is seeding. The settings
// that describe one proxy live on it now, so a test that varies what the proxy does writes
// here.
func proxyOf(t *testing.T, c *config.Config) *config.ProxyInstance {
	t.Helper()
	for i := range c.Proxies {
		if c.Proxies[i].ID == config.DefaultProxyID {
			return &c.Proxies[i]
		}
	}
	t.Fatalf("the document carries no %q proxy", config.DefaultProxyID)
	return nil
}

// storedProxy is what the store holds for that instance, for reading a write back.
func storedProxy(t *testing.T, store *config.Store) config.ProxyInstance {
	t.Helper()
	held, ok := store.Get().Proxy(config.DefaultProxyID)
	if !ok {
		t.Fatalf("the stored document carries no %q proxy", config.DefaultProxyID)
	}
	return held
}

// runtimeTailnetOf is the same block inside a resolved runtime, for a test that varies
// what this process joins with without writing it to the document.
func runtimeTailnetOf(t *testing.T, rt *config.Runtime) *config.TailscaleTunnel {
	t.Helper()
	for i := range rt.Tunnels {
		if rt.Tunnels[i].ID != config.PrimaryTunnelID {
			continue
		}
		if rt.Tunnels[i].Tailscale == nil {
			rt.Tunnels[i].Tailscale = &config.TailscaleTunnel{}
		}
		return rt.Tunnels[i].Tailscale
	}
	t.Fatalf("the resolved runtime carries no %q connection", config.PrimaryTunnelID)
	return nil
}

// storedTailnet is what the store holds for that connection, for reading a write back.
func storedTailnet(t *testing.T, store *config.Store) config.TailscaleTunnel {
	t.Helper()
	primary, ok := store.Get().Tunnel(config.PrimaryTunnelID)
	if !ok {
		t.Fatalf("the stored document carries no %q connection", config.PrimaryTunnelID)
	}
	return primary.TS()
}

// newUnstartedAgent builds an agent and stops there. Run is what constructs the node,
// the proxy and the routers, so this is the state every one of the agent's surfaces is
// in for the window between the dashboard listener binding and those being built -- and
// a caller reaching one of them then must get a refusal, not a nil dereference.
func newUnstartedAgent(t *testing.T) *Agent {
	t.Helper()

	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open config store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	agent, err := New(Options{
		Store:          store,
		Runtime:        runtime,
		Getenv:         emptyEnv,
		Logger:         quietLogger(),
		Version:        "test",
		NewNode:        func(tsnode.Options) NodeController { return newFakeNode() },
		NewSystemProxy: func(string, *slog.Logger) SystemProxy { return &recordingSystemProxy{} },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return agent
}

// newHarnessWith is newHarness with the agent's construction options open to the test,
// for the few that need a dependency the ordinary harness supplies for itself -- a clock
// a rotation schedule can be driven by, rather than waited out.
func newHarnessWith(t *testing.T, seed func(*config.Config), tune func(*Options)) *harness {
	t.Helper()
	return newHarnessIn(t, t.TempDir(), seed, tune)
}

// newHarnessIn is the same agent over a state directory the caller prepared, for the tests
// whose subject is what is already in that directory when the app starts.
func newHarnessIn(t *testing.T, stateDir string, seed func(*config.Config), tune func(*Options)) *harness {
	t.Helper()

	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open config store: %v", err)
	}
	if seed != nil {
		if _, err := store.Update(func(c *config.Config) error {
			seed(c)
			return nil
		}); err != nil {
			t.Fatalf("seed config: %v", err)
		}
	}

	node := newFakeNode()
	nodes := newFakeNodes(stateDir, node)
	wireguards := newFakeWireGuards()
	openvpns := newFakeOpenVPNs()
	links := newFakeLinks()
	systemProxy := &recordingSystemProxy{}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	opts := Options{
		Store:              store,
		Runtime:            runtime,
		Getenv:             emptyEnv,
		Logger:             quietLogger(),
		Version:            "test",
		NewNode:            nodes.build,
		NewWireGuardTunnel: wireguards.build,
		NewOpenVPNTunnel:   openvpns.build,
		OpenOpenVPN:        openvpns.open,
		// The claim substituted above runs on every platform, so OpenVPN connections can be
		// added and started here whatever the machine running the suite could do itself.
		RunsOpenVPN:      func() bool { return true },
		WatchLinkChanges: links.watch,
		NewSystemProxy:   func(string, *slog.Logger) SystemProxy { return systemProxy },
		// A fixed LAN from the documentation range, so a range a test claims is placed the
		// same way on every machine the suite runs on: a CI runner sitting on 10.0.2.0/24
		// would otherwise report 10.0.0.0/16 as overlapping its own network.
		HostNetworks: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, nil
		},
	}
	if tune != nil {
		tune(&opts)
	}
	agent, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{
		t: t, agent: agent, node: node, nodes: nodes, wireguards: wireguards,
		openvpns: openvpns, links: links, store: store, sysproxy: systemProxy,
		stateDir: stateDir, runErr: make(chan error, 1), cancel: cancel,
	}

	started := make(chan struct{})
	go func() {
		close(started)
		h.runErr <- agent.Run(ctx)
	}()
	<-started

	// Run binds the listener before serving; wait for the address to appear.
	waitFor(t, 5*time.Second, "agent to bind its dashboard port", func() bool {
		return agent.UIAddr() != nil
	})
	h.baseURL = "http://" + agent.UIAddr().String()

	// The node is started after the listener, and Start writes the backend state.
	// Handing the harness back before that lands would let a test's own state change
	// be overwritten by a Start still to come, and the agent would never see it.
	waitFor(t, 5*time.Second, "agent to start the node", func() bool {
		return node.wasStarted()
	})

	t.Cleanup(func() { h.stop() })
	return h
}

// stop cancels the agent and waits for a clean exit. It is idempotent so a test that
// stops the agent as part of what it is asserting does not fight the cleanup.
func (h *harness) stop() {
	h.t.Helper()
	if h.stopped {
		return
	}
	if err := h.exit(); err != nil {
		h.t.Errorf("agent exited with %v", err)
	}
}

// exit cancels the agent and hands back what Run reported, for the tests whose subject is
// the exit itself: a teardown that must fail, or one that must not. Stopping is done once;
// a second call is answered with a clean exit and the cleanup does not fight it.
func (h *harness) exit() error {
	h.t.Helper()
	if h.stopped {
		return nil
	}
	h.stopped = true
	h.cancel()
	select {
	case err := <-h.runErr:
		return err
	case <-time.After(15 * time.Second):
		return errors.New("agent did not exit within 15s of cancellation")
	}
}

// patchSettings writes settings through the path every real surface uses, so the module
// bookkeeping a raw document edit would skip -- availability rejection, and resetting a
// module's settings when its switch goes off -- applies here too.
func patchSettings(h *harness, patch map[string]any) {
	h.t.Helper()
	raw := make(map[string]json.RawMessage, len(patch))
	for key, value := range patch {
		encoded, err := json.Marshal(value)
		if err != nil {
			h.t.Fatalf("encode %s: %v", key, err)
		}
		raw[key] = encoded
	}
	if _, _, err := h.agent.Settings().Update(context.Background(), raw); err != nil {
		h.t.Fatalf("write %v: %v", patch, err)
	}
}

// storeSetting edits the stored document directly and republishes the resolved settings.
//
// It stands in for a config file that arrived already carrying a value -- copied from
// another machine, or restored from a backup -- which is the only way some settings are
// reachable at all: one the registry does not offer on this platform is refused by
// patchSettings by design, and the agent still has to act on what the document says.
// A module switch is not one of these: use patchSettings, or the reset that follows a
// switch going off is skipped and the module adopts itself straight back on.
func storeSetting(h *harness, edit func(*config.Settings)) {
	h.t.Helper()
	if _, err := h.store.Update(func(c *config.Config) error {
		edit(&c.Settings)
		return nil
	}); err != nil {
		h.t.Fatalf("store the setting: %v", err)
	}
	if _, err := h.agent.adoptSettings(); err != nil {
		h.t.Fatalf("resolve the stored settings: %v", err)
	}
	h.agent.pokeReconcile()
}

// emptyEnv reports every environment variable as unset, so tests are not affected
// by whatever credentials the developer has exported.
func emptyEnv(string) string { return "" }

// bringUp moves the node to Running and waits for the agent to act on it. A timeout
// means some forward never reached Running, so the failure carries the engine's own
// view of every forward rather than leaving the cause to guesswork.
//
// Forwards are started early in a reconcile, so "every forward is running" is not the
// same fact as "the pass finished" -- and a harness with no forwards at all is answered
// yes before the pass has started. The synchronous reconcile is the barrier that makes it
// one fact: it returns only after a whole pass has run, so a test may read the proxy, the
// subnet routes, the exit node or the resolver immediately after this.
func (h *harness) bringUp() {
	h.t.Helper()
	h.node.setState(tsnode.StateRunning)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.agent.Forwards().AllRunning() {
			h.agent.reconcileNow(context.Background())
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("timed out after 5s waiting for the agent to observe the node running; "+
		"node state %q, %d enabled forwards wanted, engine reports %+v, run loop exited: %v",
		h.node.Status().BackendState, len(h.store.Get().EnabledForwards()),
		h.agent.currentManager().Statuses(), h.runExited())
}

// runExited reports whether Run has already returned, and with what. A test that
// times out waiting on the agent needs to know whether the lifecycle goroutine is
// still there to answer.
func (h *harness) runExited() string {
	select {
	case err := <-h.runErr:
		// Put it back so stop() still sees it.
		h.runErr <- err
		return fmt.Sprintf("yes (%v)", err)
	default:
		return "no"
	}
}

func (h *harness) get(path string) (*http.Response, []byte) {
	h.t.Helper()
	return h.request(http.MethodGet, path, nil)
}

func (h *harness) request(method, path string, body io.Reader) (*http.Response, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.baseURL+path, body)
	if err != nil {
		h.t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// The agent wrote its token beside the config at start, where the CLI reads it.
	token, err := apiauth.Read(filepath.Dir(h.store.Path()))
	if err != nil {
		h.t.Fatalf("read the agent's API token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read %s %s body: %v", method, path, err)
	}
	return resp, raw
}

// --- helpers --------------------------------------------------------------

// waitFor polls until cond holds, failing with what was being waited for. Polling
// beats a fixed sleep: it neither flakes under load nor wastes time when fast.
func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}

// startEchoTCP runs a TCP echo server standing in for a remote service.
func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// roundTripTCP writes a payload through addr and returns the echoed reply.
func roundTripTCP(t *testing.T, addr, payload string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write to %s: %v", addr, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read from %s: %v", addr, err)
	}
	return string(buf)
}

// freePort returns a loopback port reserved for this test process.
func freePort(t *testing.T) int {
	t.Helper()
	port, err := testport.Reserve()
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	return port
}

// configFileMode reports the permission bits of the stored config.
func configFileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}
