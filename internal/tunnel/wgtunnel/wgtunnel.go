// SPDX-License-Identifier: MIT

// Package wgtunnel connects one WireGuard server in userspace.
//
// Nothing here touches the machine. The device runs inside this process against its own
// network stack, so a connection is a pair of keys and a UDP socket rather than an
// interface, a route table entry and a privileged helper -- which is why a WireGuard
// network can be added, connected and removed without a password and without anything
// else on this machine noticing. What that costs is stated on the connection itself: only
// app-tail's own forwards and proxy reach the network, because nothing else on the machine
// has a route to it.
//
// One server per connection. WireGuard's configuration format allows several peers because
// it also describes meshes and servers; a client dialling one gateway is what this
// connects, and two gateways are two connections with their own names, addresses and place
// in the addressing report.
package wgtunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// staleAfter is how old the last handshake may be before the far side counts as having
// stopped answering. It is WireGuard's own rejection age: a session key is not accepted
// past it, so a connection still carrying traffic renegotiates well before this, and one
// that has not is either idle or gone.
const staleAfter = 180 * time.Second

// handshakeGrace is how long a device may fail to complete a handshake before this says so
// rather than going on reporting that it is connecting. WireGuard retries every few
// seconds, so anything past this is a wrong key, a wrong address or a server that is not
// answering -- and "connecting" forever is the report that sends someone looking at their
// own network for an hour.
const handshakeGrace = 20 * time.Second

// pollInterval is how often the device is asked what it is doing. The device holds the
// answer in memory, so this costs a lock rather than a packet; it decides how quickly the
// connections screen notices a handshake, not how quickly one happens.
const pollInterval = 2 * time.Second

// Options are what one WireGuard connection is built from.
type Options struct {
	// ID is the stored connection's identifier, which is what everything else names it by.
	ID string
	// Held is the stored configuration, already validated by the settings registry.
	Held config.WireGuardTunnel
	// Logger receives what the device has to say. Required.
	Logger *slog.Logger
	// Verbose passes the device's own per-packet logging through, which is off by default
	// because it is one line per handshake step and several per second under load.
	Verbose bool
	// Resolve turns the server's name into addresses. It must resolve through this
	// machine's own resolver and never through a tunnel: a server reached through a
	// tunnel that is itself being brought up is a loop, and one reached through another
	// tunnel silently depends on that one staying up. Nil uses the machine's resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// LinkChanges signals that this machine's own networking moved -- a different network, a
	// woken laptop, an interface that came or went. WireGuard has no monitor of its own, so
	// without this a connection that was up when the laptop was on one network stays bound
	// to a socket that network owned and goes quiet until something restarts it. Nil means
	// nothing is watching, which is what a test wants and what a machine that never roams
	// costs nothing for.
	LinkChanges <-chan struct{}
	// Now is the clock, injected so a test can age a handshake without waiting.
	Now func() time.Time
	// Through is the connection this one's own packets travel inside, and nil for a
	// connection that sends them over this machine's own network. It is what makes a chain:
	// the device is unchanged and only its way out of the machine differs.
	Through Carrier
	// ThroughMTU is the largest packet Through carries, which is what this connection's own
	// packet size is derived from. It is required alongside Through: a carried connection
	// built at the size it was configured with sends packets its carrier cannot move, and
	// the loss is silent -- small requests work and large ones hang.
	ThroughMTU int
}

// Tunnel is one WireGuard connection behind the tunnel seam.
type Tunnel struct {
	id      string
	held    config.WireGuardTunnel
	logger  *slog.Logger
	verbose bool
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	links   <-chan struct{}
	now     func() time.Time

	// events carries one signal per status change, buffered so a change is never lost and
	// never blocks the goroutine that noticed it.
	events chan struct{}

	mu        sync.Mutex
	dev       *device.Device
	ns        *netStack
	resolver  *net.Resolver
	status    tunnel.Status
	startedAt time.Time
	// carried is what the device last reported moving, read from the same report the status
	// is derived from so a reader never sees totals from one moment beside a state from
	// another.
	carried tunnel.Carried
	// endpoint is where the device is currently sending, which is what a re-resolution
	// after a link change is compared against: a name that still points at the same address
	// is a device that needs nothing said to it.
	endpoint  netip.AddrPort
	stopWatch context.CancelFunc
	closed    bool
	// mtu is the packet size the device was actually built at, which is the configured one
	// unless a carrier's own packets leave less room. Zero until the device is built.
	mtu int

	// through is the connection carrying this one's packets, and throughMTU the largest
	// packet it moves. Both are settled when this connection is built and never change: a
	// chain that was re-ordered is a different chain, and the connection is rebuilt.
	through    Carrier
	throughMTU int
}

// resolvingTunnel is a connection whose network publishes resolvers of its own.
//
// It is a separate type rather than a flag because the capability is discovered by type
// assertion: a connection configured with no resolvers has no way to look a name up, and
// answering that question with an error every caller then has to classify is the shape the
// capability pattern exists to avoid. Absence is absence.
type resolvingTunnel struct{ *Tunnel }

var (
	_ tunnel.Tunnel    = (*Tunnel)(nil)
	_ tunnel.Reaching  = (*Tunnel)(nil)
	_ tunnel.Metered   = (*Tunnel)(nil)
	_ tunnel.Resolving = (*resolvingTunnel)(nil)
)

// New builds a connection from its stored settings. It starts nothing: Start does that,
// and until then the connection reports itself off, which is what a configured connection
// that has not been switched on is.
func New(opts Options) tunnel.Tunnel {
	t := &Tunnel{
		id:      opts.ID,
		held:    opts.Held,
		logger:  opts.Logger,
		verbose: opts.Verbose,
		resolve: opts.Resolve,
		links:   opts.LinkChanges,
		now:     opts.Now,
		events:  make(chan struct{}, 1),
		status:  tunnel.Status{State: tunnel.StateOff, Limits: limits()},

		through:    opts.Through,
		throughMTU: opts.ThroughMTU,
	}
	if t.resolve == nil {
		t.resolve = resolveWithMachineResolver
	}
	if t.now == nil {
		t.now = time.Now
	}
	if len(opts.Held.DNS) == 0 {
		return t
	}
	return &resolvingTunnel{t}
}

// limits are what this connection does not carry, stated when it is built rather than
// discovered when something fails. Both are consequences of running in userspace: there is
// no interface on this machine, so nothing outside this app has a route to the network or
// a resolver that knows its names.
func limits() []string {
	return []string{
		"Only app-tail's own forwards and proxy reach this network; other programs on " +
			"this machine do not.",
		"Names on this network resolve for app-tail, not for the rest of the machine.",
	}
}

func (t *Tunnel) ID() string              { return t.id }
func (t *Tunnel) Kind() tunnel.Kind       { return tunnel.KindWireGuard }
func (t *Tunnel) Events() <-chan struct{} { return t.events }

// Addrs are the addresses this device holds inside the network.
func (t *Tunnel) Addrs() []netip.Addr { return t.held.InterfaceAddrs() }

// Routes are the networks reachable through this connection, which for WireGuard is what
// the server is configured to carry. They are known before the connection is up and do not
// change while it runs: unlike a tailnet, nothing here advertises a route at run time.
func (t *Tunnel) Routes(context.Context) ([]netip.Prefix, error) {
	return t.held.CarriedRoutes(), nil
}

// Anchors is where this connection's own packets go: the server address the device is
// sending to right now, which is the resolved endpoint rather than whatever was configured.
// A name that resolved to one address and now resolves to another has already been moved
// onto the new one, and the old one is not where anything is being sent.
// A carried connection has none: its packets are handed to the connection carrying it and
// never reach this machine's routing table, so there is nothing here to keep out of the way
// -- and naming its server would take that one address off the interface for every other
// program too, which is a hole in exactly the mode that promises there is none.
func (t *Tunnel) Anchors() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.endpoint.IsValid() || t.through != nil {
		return nil
	}
	return []netip.Addr{t.endpoint.Addr()}
}

// MTU is the largest packet this network carries. It is what the connection was configured
// with rather than anything the server said: WireGuard has nothing in its protocol that
// tells a peer what the other side's interface is set to.
//
// A carried connection reports what it was actually built at instead, which is smaller: its
// own packets travel inside another connection's, and what is left after that connection's
// headers is all there is room for.
func (t *Tunnel) MTU() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.mtu > 0 {
		return t.mtu
	}
	return t.held.EffectiveMTU()
}

// builtMTU is the packet size this connection is built at, given where its server is.
//
// A connection sending its own packets over this machine's network is built at the size it
// was configured with. A carried one takes what its carrier has room for, and is refused
// when that is below what the internet requires anything to carry: a chain long enough to
// shrink packets past that point does not fail visibly, it drops the large ones, so it is
// stopped here with the length named rather than left to be discovered as a site that
// half-loads.
func (t *Tunnel) builtMTU(server netip.Addr) (int, error) {
	configured := t.held.EffectiveMTU()
	if t.through == nil {
		return configured, nil
	}
	if t.throughMTU <= 0 {
		return 0, fmt.Errorf("the connection carrying this one did not say how big a packet it " +
			"takes, so this one cannot be built to fit inside it")
	}
	room := hopMTU(t.throughMTU, server)
	if room < minHopMTU {
		return 0, fmt.Errorf("the connection carrying this one has room for %d bytes a packet, "+
			"which is below the %d every network has to carry. The chain is too long, or a "+
			"connection in it is set to too small a packet size.", room, minHopMTU)
	}
	return min(configured, room), nil
}

// bind is how this connection's own packets leave: a socket on this machine, or one
// conversation through the connection carrying it.
//
// The conversation itself is opened when the device brings the bind up, which is inside the
// Up below -- so a carrier that cannot reach the server fails as a connection that could not
// start, with the reason on the connection, instead of as a handshake that never completes.
func (t *Tunnel) bind(ctx context.Context, server netip.AddrPort) conn.Bind {
	if t.through == nil {
		return conn.NewStdNetBind()
	}
	// Detached from the call that is starting the connection: the device closes and reopens
	// its bind on its own schedule, and a start context cancelled by then would fail the
	// reopen for a reason that has nothing to do with the network.
	return newHopBind(context.WithoutCancel(ctx), t.through, server)
}

// Status is the cached view, recomputed by the watcher rather than read from the device
// here: this is called on every dashboard poll and every tray open.
func (t *Tunnel) Status() tunnel.Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

// Carried is what this connection has moved and how long it has been up, as the device last
// reported it. Cached rather than read here: this is called on every dashboard poll, and
// asking the device costs a full report of every peer it holds.
func (t *Tunnel) Carried() tunnel.Carried {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.carried
}

// Start brings the connection up.
//
// It returns once the device is configured and running, which is before the first
// handshake: a server that is slow to answer, or a key the server does not know, is a
// connection that started and has not connected, and those are different states. What
// cannot work at all -- a missing key, an address that does not resolve -- is an error
// here, because there is nothing to watch and no state to report.
func (t *Tunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return fmt.Errorf("this connection has been closed and cannot be started again")
	}
	if t.dev != nil {
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()

	t.publish(tunnel.Status{State: tunnel.StateStarting, Limits: limits()})

	dev, ns, endpoint, err := t.build(ctx)
	if err != nil {
		t.publish(tunnel.Status{State: tunnel.StateFailed, Detail: err.Error(), Limits: limits()})
		return err
	}

	watchCtx, stopWatch := context.WithCancel(context.WithoutCancel(ctx))
	t.mu.Lock()
	// Closed while the device was being built: nothing is watching and nothing else will
	// take it down, so it is closed here rather than left running with no reference to it.
	if t.closed {
		t.mu.Unlock()
		stopWatch()
		dev.Close()
		return fmt.Errorf("this connection was closed while it was starting")
	}
	t.dev, t.ns, t.startedAt, t.stopWatch = dev, ns, t.now(), stopWatch
	t.endpoint = endpoint
	t.resolver = ns.resolver(t.held.DNS)
	t.mu.Unlock()

	t.refresh()
	go t.watch(watchCtx)
	return nil
}

// build assembles the device: this connection's own network stack, a UDP socket on this
// machine, and the configuration that ties the two to one server.
func (t *Tunnel) build(ctx context.Context) (*device.Device, *netStack, netip.AddrPort, error) {
	var none netip.AddrPort
	addrs := t.held.InterfaceAddrs()
	if len(addrs) == 0 {
		return nil, nil, none, fmt.Errorf("no addresses are configured for this device on the network, " +
			"so nothing inside it could answer this connection")
	}
	endpoint, err := t.resolveEndpoint(ctx)
	if err != nil {
		return nil, nil, none, err
	}
	uapi, err := Device{
		PrivateKey: t.held.PrivateKey,
		Peer: Peer{
			PublicKey:    t.held.Peer.PublicKey,
			PresharedKey: t.held.Peer.PresharedKey,
			Endpoint:     endpoint,
			AllowedIPs:   t.held.Peer.AllowedIPs,
			KeepaliveSec: t.held.Peer.KeepaliveSec,
		},
	}.UAPI()
	if err != nil {
		return nil, nil, none, err
	}

	mtu, err := t.builtMTU(endpoint.Addr())
	if err != nil {
		return nil, nil, none, err
	}
	t.mu.Lock()
	t.mtu = mtu
	t.mu.Unlock()

	ns, err := newNetStack(addrs, mtu)
	if err != nil {
		return nil, nil, none, fmt.Errorf("build this connection's network stack: %w", err)
	}
	dev := device.NewDevice(ns, t.bind(ctx, endpoint), t.deviceLogger())
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, nil, none, fmt.Errorf("configure this connection: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, none, fmt.Errorf("start this connection: %w", err)
	}
	return dev, ns, endpoint, nil
}

// resolveEndpoint resolves the configured server address.
//
// A name is looked up through this machine's own resolver, never through a tunnel. The
// packets carrying this connection have to leave the machine the ordinary way, so a name
// resolved inside a private network would point at an address only reachable through the
// very thing being brought up.
func (t *Tunnel) resolveEndpoint(ctx context.Context) (netip.AddrPort, error) {
	raw := strings.TrimSpace(t.held.Peer.Endpoint)
	if raw == "" {
		return netip.AddrPort{}, fmt.Errorf("no server address is configured for this connection")
	}
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		return addrPort, nil
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("the server address %q is not a host and a port", raw)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("the server address %q does not end in a port", raw)
	}
	addrs, err := t.resolve(ctx, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("look up the server %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("the server %q resolved to no addresses", host)
	}
	// The first answer, and only one: a WireGuard device holds a single endpoint per peer,
	// and it moves on its own the moment the server answers from somewhere else.
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil
}

// resolveWithMachineResolver is the default lookup: this machine's own resolver, whatever
// it currently is.
func resolveWithMachineResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// deviceLogger routes the device's own log lines into this app's logger, tagged with the
// connection they came from so several connections' lines stay separable.
func (t *Tunnel) deviceLogger() *device.Logger {
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			t.logger.Warn("wireguard", "connection", t.id, "message", fmt.Sprintf(format, args...))
		},
	}
	if t.verbose {
		logger.Verbosef = func(format string, args ...any) {
			t.logger.Debug("wireguard", "connection", t.id, "message", fmt.Sprintf(format, args...))
		}
	}
	return logger
}

// Close takes the connection down. It is safe to call on one that never started, and
// twice, which is what lets a caller stop a connection without first asking whether there
// is anything to stop.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	dev, stopWatch := t.dev, t.stopWatch
	t.closed, t.dev, t.ns, t.resolver, t.stopWatch = true, nil, nil, nil, nil
	t.status = tunnel.Status{State: tunnel.StateOff, Limits: limits()}
	t.mu.Unlock()

	if stopWatch != nil {
		stopWatch()
	}
	if dev != nil {
		// Closes the device's network stack with it, so nothing is left holding the socket
		// or the addresses this connection had.
		dev.Close()
	}
	t.signal()
	return nil
}

// watch keeps the cached status current. Without it a connection that came up, went away,
// or was refused by the server would go on reporting whatever it reported when it started.
func (t *Tunnel) watch(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	// A local copy, because it is cleared below when the watcher behind it goes away and
	// this goroutine is the only one that may do that.
	links := t.links
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.refresh()
		case _, ok := <-links:
			if !ok {
				// Nothing is watching this machine's networking any more. The connection
				// carries on; it simply stops being told about moves.
				links = nil
				continue
			}
			t.relink(ctx)
			t.refresh()
		}
	}
}

// relink puts the connection back on this machine's networking after it moved.
//
// Two things go stale at once and both have to be dealt with here. The socket the device
// sends from belongs to the network that has just gone, so it is reopened; and a server
// named rather than addressed may now answer somewhere else, which the device has no way to
// find out on its own -- it only learns a new address for a server that reaches it first.
//
// Neither failure is fatal: the connection was up a moment ago and the next link change or
// the server's own next packet can still repair it. They are reported and the watcher keeps
// going, because taking the connection down here would turn a moment of bad networking into
// something the user has to switch back on by hand.
func (t *Tunnel) relink(ctx context.Context) {
	t.mu.Lock()
	dev, current := t.dev, t.endpoint
	t.mu.Unlock()
	if dev == nil {
		return
	}

	if err := dev.BindUpdate(); err != nil {
		t.logger.Warn("wireguard: could not reopen this connection's socket after the machine's "+
			"networking changed", "connection", t.id, "error", err)
	}

	// The host's own resolver, for the reason resolveEndpoint states: a server reached
	// through a tunnel is a loop, and this lookup is what decides where the tunnel sends.
	resolved, err := t.resolveEndpoint(ctx)
	if err != nil {
		t.logger.Warn("wireguard: could not look up this connection's server after the machine's "+
			"networking changed", "connection", t.id, "error", err)
		return
	}
	if resolved == current {
		return
	}
	move, err := MoveEndpoint(t.held.Peer.PublicKey, resolved)
	if err != nil {
		t.logger.Warn("wireguard: could not point this connection at the server's new address",
			"connection", t.id, "error", err)
		return
	}
	if err := dev.IpcSet(move); err != nil {
		t.logger.Warn("wireguard: could not point this connection at the server's new address",
			"connection", t.id, "error", err)
		return
	}
	t.mu.Lock()
	t.endpoint = resolved
	t.mu.Unlock()
	t.logger.Info("wireguard: this connection's server has moved",
		"connection", t.id, "from", current.String(), "to", resolved.String())
}

// refresh reads the device and republishes the status it implies.
func (t *Tunnel) refresh() {
	t.mu.Lock()
	dev, ns, startedAt := t.dev, t.ns, t.startedAt
	t.mu.Unlock()
	if dev == nil {
		return
	}

	status := tunnel.Status{Addrs: addrStrings(t.held.InterfaceAddrs()), Limits: limits()}
	report, err := dev.IpcGet()
	if err != nil {
		// The device could not say what it is doing. That is not the same as being down,
		// and reporting it as down would have a working connection disappear from the
		// screen, so it is reported as working-with-a-problem with the reason attached.
		status.State = tunnel.StateDegraded
		status.Detail = "this connection could not be asked what it is doing: " + err.Error()
		t.publish(status)
		return
	}

	handshake, ok := lastHandshake(report)
	up, down := transferred(report)
	t.mu.Lock()
	t.carried = tunnel.Carried{Up: up, Down: down, Since: startedAt, Dropped: int64(ns.queueStats().Dropped)}
	if ok {
		t.carried.LastHandshake = handshake
	}
	t.mu.Unlock()
	status.State, status.Detail = stateOf(handshake, ok, t.now().Sub(startedAt), t.held.Peer.KeepaliveSec, t.now())
	t.publish(status)
}

// stateOf decides what a connection is doing from the one fact the device reports: when
// the two sides last agreed on keys.
//
// It is pure so every arm is reachable in a test without a server, a socket or a wait --
// including the two that only happen after minutes have passed, which is exactly where a
// connection is reported wrongly for long enough to matter.
func stateOf(handshake time.Time, ok bool, since time.Duration, keepaliveSec int, now time.Time) (tunnel.State, string) {
	switch {
	case ok && now.Sub(handshake) < staleAfter:
		return tunnel.StateConnected, ""
	case ok && keepaliveSec > 0:
		// Keepalive is on, so this connection sends often enough to have renegotiated by
		// now. A handshake this old means the server stopped answering.
		return tunnel.StateDegraded,
			fmt.Sprintf("the server last answered %s ago", roundedAge(now.Sub(handshake)))
	case ok:
		// No keepalive and nothing being sent: an idle connection with an old handshake is
		// working exactly as configured, and the next packet renegotiates.
		return tunnel.StateConnected, ""
	case since < handshakeGrace:
		return tunnel.StateConnecting, ""
	default:
		return tunnel.StateFailed, "the server has not answered. Check the server address, and " +
			"that it holds this connection's public key."
	}
}

// transferred reads what the device has moved, summed over its peers. The device reports the
// totals per peer, and this connection holds one; summing rather than taking the first keeps
// the figure right for a report that ever carries more.
//
// A total the device did not report is zero, which is the same answer as a peer that has moved
// nothing -- and for a connection whose report has no counters at all, that is the honest one:
// nothing was counted.
func transferred(report string) (up, down int64) {
	for _, line := range strings.Split(report, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		total, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "tx_bytes":
			up += total
		case "rx_bytes":
			down += total
		}
	}
	return up, down
}

// lastHandshake reads when the two sides last agreed on keys, which is the one fact that
// says whether this connection works. The device reports it as seconds since the epoch,
// and zero for a peer that has never completed one.
func lastHandshake(report string) (time.Time, bool) {
	for _, line := range strings.Split(report, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "last_handshake_time_sec" {
			continue
		}
		secs, err := strconv.ParseInt(value, 10, 64)
		if err != nil || secs == 0 {
			return time.Time{}, false
		}
		return time.Unix(secs, 0), true
	}
	return time.Time{}, false
}

// roundedAge renders a duration the way a person says one, since it lands in a sentence
// rather than in a log.
func roundedAge(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Minute).String()
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

// publish stores a status and signals only when something actually moved, so a consumer
// watching the channel is woken by changes rather than by the poll.
func (t *Tunnel) publish(status tunnel.Status) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	changed := t.status.State != status.State || t.status.Detail != status.Detail
	t.status = status
	t.mu.Unlock()
	if changed {
		t.signal()
	}
}

func (t *Tunnel) signal() {
	select {
	case t.events <- struct{}{}:
	default:
	}
}

// live is this connection's own network stack and resolver, or the reason there is not
// one. Every network method goes through it, so a call made before the connection is up
// says so rather than dereferencing nothing.
func (t *Tunnel) live() (*netStack, *net.Resolver, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ns == nil {
		return nil, nil, fmt.Errorf("this connection is not up")
	}
	return t.ns, t.resolver, nil
}

// Dial opens a connection inside the network.
//
// A name is looked up through the resolvers this network publishes, so a name that exists
// only inside it resolves and nothing about the lookup reaches the machine's own resolver.
// A connection configured with no resolvers still reaches an address.
func (t *Tunnel) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	ns, resolver, err := t.live()
	if err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %q is not a host and a port", network, address)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %q does not end in a port", network, address)
	}
	addrs, err := t.addrsOf(ctx, resolver, network, host)
	if err != nil {
		return nil, err
	}

	// Every answer in turn: a name with several addresses is one host reachable several
	// ways, and giving up on the first refusal would fail a connection that works.
	var firstErr error
	for _, addr := range addrs {
		conn, err := ns.dial(ctx, network, netip.AddrPortFrom(addr, uint16(port)))
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("dial %s: %q resolved to no address this connection can reach", network, address)
	}
	return nil, firstErr
}

// addrsOf resolves the host half of a dial, keeping only the address family the caller
// asked for. A literal address is used as it stands: resolving one would be a lookup of a
// name that is not a name.
func (t *Tunnel) addrsOf(ctx context.Context, resolver *net.Resolver, network, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	if len(t.held.DNS) == 0 {
		return nil, fmt.Errorf("dial %s: this connection has no resolvers configured, so the name "+
			"%q cannot be looked up inside it", network, host)
	}
	found, err := resolver.LookupNetIP(ctx, lookupNetwork(network), host)
	if err != nil {
		return nil, fmt.Errorf("dial %s: look up %q on this connection: %w", network, host, err)
	}
	out := make([]netip.Addr, 0, len(found))
	for _, addr := range found {
		out = append(out, addr.Unmap())
	}
	return out, nil
}

// Reach says where a destination would go without dialling it, which is what a permission
// check asks before it lets anything through.
//
// A default route in the allowed addresses is not counted, exactly as Routes does not count
// one: a connection offering 0.0.0.0/0 is a statement about where this machine's internet
// traffic goes, and treating it as a route here would have it claim every destination in
// existence and hide every other connection behind it.
//
// An address is reported only when this connection carries it. A name resolved through this
// network's own resolvers means nothing outside it, so handing that answer back for a
// destination this connection does not carry would send a caller to an address that is
// somebody else's on the machine's own network.
func (t *Tunnel) Reach(ctx context.Context, network, address string) (tunnel.Reach, error) {
	_, resolver, err := t.live()
	if err != nil {
		return tunnel.Reach{}, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return tunnel.Reach{}, fmt.Errorf("reach %s: %q is not a host and a port", network, address)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return tunnel.Reach{}, fmt.Errorf("reach %s: %q does not end in a port", network, address)
	}
	addrs, err := t.addrsOf(ctx, resolver, network, host)
	if err != nil {
		// A name this connection has no way to look up is a destination it does not carry
		// rather than a fault: the caller is asking every connection in turn, and one of
		// the others may well know the name.
		if len(t.held.DNS) == 0 {
			return tunnel.Reach{}, nil
		}
		return tunnel.Reach{}, err
	}
	for _, addr := range addrs {
		if t.carries(addr) {
			return tunnel.Reach{Addr: netip.AddrPortFrom(addr, uint16(port)), Carried: true}, nil
		}
	}
	return tunnel.Reach{}, nil
}

// CanCarryExit reports whether this connection can carry this machine's internet traffic.
//
// It is the server's own configuration that decides: a peer whose allowed addresses include
// a default route is one the device will hand every otherwise-unrouted packet to, and one
// without it will drop them. Both halves are reported, because a connection that is simply
// not up yet is a wait and a server that was never set up to route traffic out is a change
// somebody has to make at the other end.
func (t *Tunnel) CanCarryExit(context.Context) (bool, string) {
	if !t.held.CarriesDefault() {
		return false, "this connection's allowed addresses do not include a default route, " +
			"so its server is not set up to send traffic on to the internet"
	}
	if st := t.Status(); !st.State.Live() {
		return false, "the connection is not up"
	}
	return true, ""
}

// carries reports whether an address falls inside a network this connection reaches, or is
// one of this device's own addresses inside it.
func (t *Tunnel) carries(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range t.held.CarriedRoutes() {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, own := range t.held.InterfaceAddrs() {
		if own.Unmap() == addr {
			return true
		}
	}
	return false
}

// lookupNetwork is the address family a dial network asks for, in the words the resolver
// uses.
func lookupNetwork(network string) string {
	switch {
	case strings.HasSuffix(network, "4"):
		return "ip4"
	case strings.HasSuffix(network, "6"):
		return "ip6"
	default:
		return "ip"
	}
}

// dial opens one connection to one resolved address.
func (s *netStack) dial(ctx context.Context, network string, addr netip.AddrPort) (net.Conn, error) {
	switch {
	case strings.HasPrefix(network, "tcp"):
		return s.dialTCP(ctx, addr)
	case strings.HasPrefix(network, "udp"):
		return s.dialUDP(addr)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

// Listen accepts TCP inside the network, on this device's own address there.
func (t *Tunnel) Listen(network string, port uint16) (net.Listener, error) {
	ns, _, err := t.live()
	if err != nil {
		return nil, err
	}
	addr, err := t.listenAddr(network, port)
	if err != nil {
		return nil, err
	}
	return ns.listenTCP(addr)
}

// ListenPacket receives UDP inside the network, on this device's own address there.
func (t *Tunnel) ListenPacket(network string, port uint16) (net.PacketConn, error) {
	ns, _, err := t.live()
	if err != nil {
		return nil, err
	}
	addr, err := t.listenAddr(network, port)
	if err != nil {
		return nil, err
	}
	return ns.listenPacket(addr)
}

// listenAddr picks which of this device's addresses to listen on.
//
// The concrete address is chosen here rather than left unspecified because this stack is
// one network among several: a socket bound to nothing in particular would be a socket
// whose network nobody can name.
func (t *Tunnel) listenAddr(network string, port uint16) (netip.AddrPort, error) {
	wantV6 := strings.HasSuffix(network, "6")
	wantV4 := strings.HasSuffix(network, "4")
	for _, addr := range t.held.InterfaceAddrs() {
		switch {
		case wantV4 && !addr.Is4():
		case wantV6 && !addr.Is6():
		default:
			return netip.AddrPortFrom(addr, port), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("this connection holds no %s address to listen on", network)
}

// LookupHost resolves a name through the network's own resolvers, which are the only ones
// that know the names inside it.
func (r *resolvingTunnel) LookupHost(ctx context.Context, host string) (tunnel.Lookup, error) {
	_, resolver, err := r.live()
	if err != nil {
		return tunnel.Lookup{}, err
	}
	found, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		// A name this network's resolver does not have is not a failure to look it up:
		// the caller asks each network in turn, and the name may exist on the next one.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return tunnel.Lookup{}, nil
		}
		return tunnel.Lookup{}, err
	}
	out := make([]netip.Addr, 0, len(found))
	for _, addr := range found {
		out = append(out, addr.Unmap())
	}
	// Go's resolver does not report a record's TTL, so the answer carries none and the
	// caller applies its own floor.
	return tunnel.Lookup{Addrs: out}, nil
}
