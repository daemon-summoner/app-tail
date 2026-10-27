// SPDX-License-Identifier: MIT

// Package subnets carries the TCP connections that arrive over the tailnet for a
// network this device routes, out to the real host on that network.
//
// It is a userspace subnet router, and its limits are the point rather than a caveat:
// app-tail has no TUN device, so the only inbound hook the tailnet stack offers is one
// for TCP flows. UDP cannot be carried at all -- there is no equivalent hook -- so DNS,
// QUIC, VoIP, WireGuard and NFS all fail across a route this serves. Connections leave
// this machine from this machine's own address, so the far end sees this device rather
// than the peer that called it. Both facts are stated on the setting, in the dashboard
// and in the README, because each would otherwise be filed as a bug against a router
// working exactly as it can.
package subnets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sellitus/app-tail/internal/bytecount"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// approvedTTL is how long an approved-route set is reused before it is read again.
//
// Approval is an admin action taken elsewhere, so the set changes rarely and never
// because of anything this process did. Reading it per connection would put a status
// round trip in front of every flow; never re-reading it would leave a route approved
// minutes ago still refused. The short cache is what makes checking every connection
// against the approved set cheap enough to do at all, and the alternative to checking
// is trusting what this device asked for.
const approvedTTL = 30 * time.Second

// dialTimeout bounds one dial out to a destination host. A peer's connection is already
// waiting by then, so an address that is not answering should fail while the far end is
// still interested rather than hold the flow open for the operating system's own timeout.
const dialTimeout = 10 * time.Second

// PrefsFunc supplies the current preferences of the connection this router carries for.
// It is a function so the router reads live values rather than a copy taken at
// construction, matching the proxy and the forwarding engine.
type PrefsFunc func() config.TailnetPrefs

// Tailnet is the node as this router uses it: what the tailnet has approved this device
// to carry, and the hook that hands it those flows.
type Tailnet interface {
	ApprovedRoutes(ctx context.Context) ([]netip.Prefix, error)
	ServeSubnets(h func(src, dst netip.AddrPort) func(net.Conn)) (func(), error)
}

// Status is what this router is doing. What it is allowed to carry is deliberately not
// here: the approved set is the tailnet's answer, read from the node, and a copy cached
// inside this router would be a second source for the one number a user acts on.
type Status struct {
	// Serving reports that the hook is installed, so a flow to an approved network
	// reaches this process rather than being reset.
	Serving bool
	// Carried counts connections handed on to a destination, Refused those turned away
	// because the destination was not one this device carries.
	Carried uint64
	Refused uint64
	// BytesIn is what peers sent, BytesOut what the destinations sent back.
	BytesIn  uint64
	BytesOut uint64
	// Error is the last failure that stopped this router from serving, kept because a
	// route that is advertised and approved and still refuses traffic is otherwise
	// indistinguishable from one that is working.
	Error string
}

// Router carries connections for the networks this device routes. It is safe to Apply,
// Close and read the Status of from any goroutine.
type Router struct {
	tn     Tailnet
	prefs  PrefsFunc
	logger *slog.Logger
	// dial reaches a destination from this machine's own network stack, which is the
	// one boundary this package has and so the one seam a test substitutes.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	// now is the clock the approved-route cache ages against, so a test drives expiry
	// rather than waiting it out.
	now func() time.Time

	// inspector examines every flow before it is carried. It is atomic rather than under
	// r.mu because it is read once per flow on the tailnet stack's own goroutines, and r.mu
	// is what a flow being classified and a dashboard poll already contend for.
	inspector atomic.Pointer[Inspector]

	// ctx bounds every connection this router carries: closing it cuts the copies in
	// flight rather than leaving them to their own timeouts.
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	nodeUp bool
	stop   func()
	failed string
	// approved is the last approved set read and approvedAt when it was read. Both are
	// guarded because the handler runs on the tailnet stack's own goroutines.
	approved   []netip.Prefix
	approvedAt time.Time
	counters   counters
	// ports breaks the byte counters down by the port a flow went to and the device it came
	// from. It has its own bounding because the set is whatever devices on the tailnet ask
	// for, which is unbounded and not this machine's to decide.
	ports *bytecount.Table
}

// maxPorts is how many port-and-device pairs this router names before folding the rest into
// one bucket. It is the budget the proxy's destination table keeps, for the same reason.
const maxPorts = 64

// counters are the totals the status reports.
//
// They are atomic rather than guarded by r.mu: the byte counters are added to on both sides
// of every 32 KB chunk of every carried connection, and r.mu is also what a flow being
// classified and a dashboard poll contend for. A counter behind that lock puts every
// transfer this device routes in line behind both.
type counters struct {
	carried  atomic.Uint64
	refused  atomic.Uint64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
}

// New builds a router over the given tailnet. It carries nothing until Apply runs, and
// Apply carries nothing while the setting is off.
func New(tn Tailnet, prefs PrefsFunc, logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{}
	return &Router{
		tn:     tn,
		prefs:  prefs,
		logger: logger,
		dial:   dialer.DialContext,
		now:    time.Now,
		ctx:    ctx,
		cancel: cancel,
		ports:  bytecount.New(maxPorts),
	}
}

// SetNodeUp records tailnet availability. Unlike the proxy, which keeps its port bound
// while the node is down and refuses with a reason, this router carries nothing at all:
// the hook it installs belongs to that node's own network stack, so there is nothing to
// keep alive. The reason is published through the status instead.
func (r *Router) SetNodeUp(up bool) {
	r.mu.Lock()
	r.nodeUp = up
	r.mu.Unlock()
}

// Apply reconciles the router with the current preferences: it starts carrying connections
// or stops. It is idempotent, so the reconcile loop calls it on every pass.
func (r *Router) Apply() error {
	serve := r.prefs().RoutesServe

	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case !serve:
		r.stopLocked()
		r.failed = ""
		return nil
	case !r.nodeUp:
		// Said plainly rather than left blank: a user who has advertised a network, had
		// it approved and turned this on is looking at this card for the reason nothing
		// is reaching them.
		r.stopLocked()
		r.failed = "the tailnet node is not running"
		return nil
	}
	if r.stop != nil {
		return nil
	}

	stop, err := r.tn.ServeSubnets(r.handle)
	if err != nil {
		// Recorded as well as returned: a node that is not up yet is the ordinary case
		// on startup, and the reason belongs on screen for as long as it lasts.
		r.failed = err.Error()
		return fmt.Errorf("carry connections for the networks this device routes: %w", err)
	}
	r.stop, r.failed = stop, ""
	// Read fresh on the next connection rather than carried over from whatever was
	// cached while this router was switched off.
	r.approvedAt = time.Time{}
	r.logger.Info("carrying tailnet connections for the networks this device routes")
	return nil
}

// Close stops carrying connections and cuts the ones in flight. Removing the hook and
// cancelling cannot fail, so there is nothing for a caller to handle.
func (r *Router) Close() {
	r.mu.Lock()
	r.stopLocked()
	r.mu.Unlock()
	r.cancel()
}

// stopLocked removes the hook. The caller holds r.mu.
func (r *Router) stopLocked() {
	if r.stop == nil {
		return
	}
	r.stop()
	r.stop = nil
}

// Status reports what this router is doing.
func (r *Router) Status() Status {
	r.mu.Lock()
	serving, failed := r.stop != nil, r.failed
	r.mu.Unlock()
	return Status{
		Serving:  serving,
		Carried:  r.counters.carried.Load(),
		Refused:  r.counters.refused.Load(),
		BytesIn:  r.counters.bytesIn.Load(),
		BytesOut: r.counters.bytesOut.Load(),
		Error:    failed,
	}
}

// Inspector examines a flow before it is carried. It is declared here rather than imported
// so this package keeps knowing nothing about where a rule came from or how it is compiled.
type Inspector interface {
	// Refuse reports why a flow must not be carried, and whether it must not. A flow that
	// matched while inspection is only recording answers false: the match is already
	// recorded, and carrying it is what recording means.
	Refuse(f inspect.Flow) (reason string, refuse bool)
	// Watch reads the opening bytes of a flow that is being carried, and answers nil for a
	// flow it has nothing to read. It answers a question Refuse cannot: what arrived here is
	// a connection another device already addressed, and the name it is really for is inside
	// those first bytes and nowhere else.
	Watch(f inspect.Flow) netpipe.Stream
	// Open decides whether an encrypted flow is opened so that Watch has something to read,
	// and answers the pair of connections to carry it between either way. For almost every
	// flow that is the pair it was handed, untouched.
	//
	// An error means this flow was going to be opened and could not be, which is a flow that
	// must not be carried: its opening bytes are gone, and the reason is usually that the far
	// end could not be verified. Nothing comes back with the error -- the caller cuts the two
	// ends it already holds.
	Open(ctx context.Context, f inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error)
}

// SetInspector replaces what examines the flows this router carries. Nil inspects nothing,
// which is the switch being off and every state before the first compile.
func (r *Router) SetInspector(in Inspector) {
	if in == nil {
		r.inspector.Store(nil)
		return
	}
	r.inspector.Store(&in)
}

// inspects asks the inspector, and reports carrying the flow when there is none.
func (r *Router) inspects(flow inspect.Flow) (string, bool) {
	held := r.inspector.Load()
	if held == nil {
		return "", false
	}
	return (*held).Refuse(flow)
}

// watches asks for a reader of a flow's opening bytes, and answers none when there is no
// inspector.
func (r *Router) watches(flow inspect.Flow) netpipe.Stream {
	held := r.inspector.Load()
	if held == nil {
		return nil
	}
	return (*held).Watch(flow)
}

// opens asks whether a flow is opened, and answers the pair to carry it between. No
// inspector is the pair it was handed.
func (r *Router) opens(flow inspect.Flow, peer, upstream net.Conn) (net.Conn, net.Conn, error) {
	held := r.inspector.Load()
	if held == nil {
		return peer, upstream, nil
	}
	return (*held).Open(r.ctx, flow, peer, upstream)
}

// handle decides what to do with one flow the tailnet delivered. A nil result refuses it.
func (r *Router) handle(src, dst netip.AddrPort) func(net.Conn) {
	if err := r.allowed(dst); err != nil {
		r.counters.refused.Add(1)
		r.logger.Warn("refused a tailnet connection to an address this device does not carry",
			"from", src.String(), "to", dst.String(), "reason", err)
		return nil
	}
	// This is the one path in the app that knows which device asked, so the match names it.
	// The flow arrived over the tailnet already addressed, so there is no name here either.
	if reason, refuse := r.inspects(inspect.Flow{
		Addr:     dst.Addr(),
		Port:     dst.Port(),
		Where:    "a network this device routes",
		Protocol: "tcp",
		Peer:     src.Addr().String(),
	}); refuse {
		r.counters.refused.Add(1)
		r.logger.Warn("refused a tailnet connection that traffic inspection matched",
			"from", src.String(), "to", dst.String(), "reason", reason)
		return nil
	}
	r.counters.carried.Add(1)
	return func(c net.Conn) { r.carry(c, src, dst) }
}

// allowed reports why a destination must not be carried, or nil when it may be.
//
// The address classes are refused ahead of the approved set rather than relying on it.
// An approval covering one of them would be a mistake made in the admin console, and
// honouring it would turn a route into a way to reach this machine's own loopback
// services or a link-local address that names a different machine on every network.
func (r *Router) allowed(dst netip.AddrPort) error {
	if !dst.IsValid() {
		return errors.New("the destination is not an address")
	}
	addr := dst.Addr().Unmap()
	switch {
	case addr.IsLoopback():
		return errors.New("loopback on this machine is not a network this device routes")
	case addr.IsMulticast():
		// Before the link-local test: the link-local multicast ranges answer to both,
		// and multicast is the more accurate reason.
		return errors.New("multicast is not a destination a route carries")
	case addr.IsLinkLocalUnicast():
		return errors.New("a link-local address names a different machine on every network")
	case addr.IsUnspecified():
		return errors.New("the destination names no host")
	}

	approved, err := r.approvedRoutes()
	if err != nil {
		return fmt.Errorf("read which networks this device carries: %w", err)
	}
	for _, p := range approved {
		if p.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("%s is not inside a network the tailnet has approved this device to carry", addr)
}

// approvedRoutes is the approved set, read again once the cached one has aged out.
func (r *Router) approvedRoutes() ([]netip.Prefix, error) {
	r.mu.Lock()
	if !r.approvedAt.IsZero() && r.now().Sub(r.approvedAt) < approvedTTL {
		approved := r.approved
		r.mu.Unlock()
		return approved, nil
	}
	ctx := r.ctx
	r.mu.Unlock()

	// Outside the lock: this reaches the tailnet backend, and a connection being
	// classified must not hold up a status the dashboard is asking for at the same
	// moment.
	readCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	approved, err := r.tn.ApprovedRoutes(readCtx)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.approved, r.approvedAt = approved, r.now()
	r.mu.Unlock()
	return approved, nil
}

// carry joins a peer's connection to the destination it asked for.
func (r *Router) carry(peer net.Conn, src, dst netip.AddrPort) {
	target := net.JoinHostPort(dst.Addr().Unmap().String(), strconv.Itoa(int(dst.Port())))

	dialCtx, cancel := context.WithTimeout(r.ctx, dialTimeout)
	defer cancel()
	upstream, err := r.dial(dialCtx, "tcp", target)
	if err != nil {
		r.logger.Warn("could not reach a destination on a network this device carries",
			"from", src.String(), "to", target, "error", err)
		if err := peer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			r.logger.Debug("closing an uncarried tailnet connection failed", "error", err)
		}
		return
	}

	flow := r.portEntry(src, dst)
	flow.Open()
	defer func() {
		flow.Close()
		r.ports.Touch(flow)
	}()

	// The same instalment lands on the machine-wide counter and on this flow's own. What
	// peers sent this machine is its down, and what the destinations sent back and this
	// machine put onto the tailnet is its up -- the direction the flat lane already reports.
	// The same flow the routes were asked about, asked again for its opening bytes.
	inspecting := inspect.Flow{
		Addr:     dst.Addr(),
		Port:     dst.Port(),
		Where:    "a network this device routes",
		Protocol: "tcp",
		Peer:     src.Addr().String(),
	}
	watch := r.watches(inspecting)
	opened, openedUpstream, err := r.opens(inspecting, peer, upstream)
	if err != nil {
		// Cut rather than closed: a flow that was going to be read and could not be is being
		// stopped on purpose, and a reset says that where a graceful close would read to the
		// device on the other side as the destination hanging up.
		netpipe.Reset(peer)
		netpipe.Reset(upstream)
		// The window this flow was given back, on the one path that never reaches the copy that
		// would otherwise return it.
		if watch != nil {
			watch.Close()
		}
		r.logger.Warn("a carried connection was stopped rather than carried unread",
			"from", src.String(), "to", target, "error", err)
		return
	}
	peer, upstream = opened, openedUpstream
	err = netpipe.CopyWith(r.ctx, peer, upstream,
		func(n int64) { addBytes(&r.counters.bytesIn, n); flow.Down(n) },
		func(n int64) { addBytes(&r.counters.bytesOut, n); flow.Up(n) },
		watch,
	)
	if err != nil && r.ctx.Err() == nil {
		r.logger.Debug("a carried connection ended with an error",
			"from", src.String(), "to", target, "error", err)
	}
}

// portEntry is the counters for one carried flow, keyed by the port it went to and the
// device it came from.
//
// Both halves are in the key because this is the only place in app-tail that sees them
// together: every other seam carries this machine's own outbound traffic, where there is no
// tailnet device to name. Keying by port alone would throw away the one answer to "which
// device is hammering that port", which is the whole reason the port graph offers a device
// filter. The device is reported as the address it connected from; naming it needs the peer
// list, which this package deliberately does not hold.
func (r *Router) portEntry(src, dst netip.AddrPort) *bytecount.Entry {
	from := src.Addr().Unmap().String()
	port := strconv.Itoa(int(dst.Port()))
	entry := r.ports.Entry("tcp/"+port+"/"+from, bytecount.Meta{
		Label:  port,
		Detail: "tcp",
		Peer:   from,
	})
	r.ports.Touch(entry)
	return entry
}

// Ports is what each port this device carried to has moved, busiest first, plus what the cap
// left unnamed and how many distinct ports that stands for.
func (r *Router) Ports() (named []bytecount.Row, other bytecount.Row, folded int) {
	return r.ports.Snapshot()
}

// addBytes folds one instalment into a counter. The number is a copy's byte count, which is
// never negative, so the conversion cannot wrap the counter around.
func addBytes(counter *atomic.Uint64, n int64) { counter.Add(uint64(n)) }
