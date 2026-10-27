// SPDX-License-Identifier: MIT

// Package ovpntunnel connects one OpenVPN server.
//
// It is the one kind of connection this app does not run in userspace, and the reason is not
// a design choice: OpenVPN has no way to be handed an interface that already exists, and on
// macOS an interface cannot be created before the process that will use it. So the program
// that carries the traffic has to hold administrator rights, and it is a separate process --
// the stock openvpn binary -- started by the privileged helper.
//
// What that changes is stated on the connection rather than discovered later. A real network
// interface appears on this machine, so every program here reaches the network by name and
// address with no per-program setup; and the machine's routing table has one winner per
// address range, so two connections carrying the same range cannot both be reached at their
// real addresses.
//
// Nothing about the connection is a file this app hands over. The stored settings cross the
// privilege boundary as typed values, the helper renders the configuration itself, and the
// account the server asks for is answered over the management socket so it is never written
// anywhere at all.
package ovpntunnel

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
	"syscall"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// defaultMTU is openvpn's own default interface size, which is what a connection carries
// when nothing set one and the interface has not been found yet. It is openvpn's documented
// default rather than a number invented here.
const defaultMTU = 1500

// resolverTimeout bounds one lookup through this network's own resolvers. A network whose
// resolver does not answer must not hold a dial open indefinitely: the caller is usually
// asking every connection in turn, and one slow network would stall all of them.
const resolverTimeout = 5 * time.Second

// Run is everything the privileged side is told about one connection: typed values, never a
// line of configuration, because it is the privileged side that renders the file.
//
// It is an alias rather than a copy. The description has to be the one the privileged side
// validates against -- a second struct here would be a field list that drifts, and a field
// missed in the copy is a setting saved, reported as applied, and never sent. What the alias
// buys is that every other package names this type through this one, which is what keeps the
// privilege boundary at exactly one importer.
type Run = hostnet.OpenVPNRun

// Scope is the connection and the interface it is running on, for the request that gives that
// interface a default route of its own. It is an alias for the same reason Run is: this
// package is the one importer of the privilege boundary, and every other package names the
// type through this one.
type Scope = hostnet.OpenVPNScope

// Runner is the privileged side that starts and stops the openvpn program.
//
// It is an interface rather than the helper itself so this package can be exercised without
// administrator rights: what is worth pinning here is the conversation over the management
// socket, and that needs a process to talk to rather than a process holding root.
type Runner interface {
	StartOpenVPN(ctx context.Context, run Run) error
	StopOpenVPN(ctx context.Context, id string) error
	ScopeOpenVPN(ctx context.Context, scope Scope) error
	UnscopeOpenVPN(ctx context.Context, id string) error
}

// Carry is how this connection carries this machine's internet traffic, which is two
// different arrangements on this machine and not one setting with a flag.
//
// The difference is which routing table says where the traffic goes. Owning the machine's
// default means openvpn puts the route in the table every program here reads, so the whole
// machine goes this way at kernel speed. Owning a route on its own interface means app-tail
// owns that table -- the one-interface mode does -- and this connection is reached by dialling
// out of its interface instead, which needs a route that belongs to the interface rather than
// to the machine.
type Carry string

const (
	// CarryNone is a connection that was not chosen to carry this machine's internet traffic.
	CarryNone Carry = ""
	// CarryDefault is a connection that takes this machine's own default route.
	CarryDefault Carry = "default"
	// CarryScoped is a connection that carries the traffic app-tail sends into its interface,
	// through a default route belonging to that interface alone.
	CarryScoped Carry = "scoped"
)

// scopeTimeout bounds asking the privileged side for that route. It is a couple of route
// changes on this machine, so it is short: what it protects against is a helper that has
// stopped answering holding this connection's status watcher open.
const scopeTimeout = 30 * time.Second

// Options are what one OpenVPN connection is built from.
type Options struct {
	// ID is the stored connection's identifier, which is what everything else names it by.
	ID string
	// Held is the stored configuration, already validated by the settings registry.
	Held config.OpenVPNTunnel
	// Carry says whether this connection was chosen to carry this machine's internet traffic,
	// and if so how. It is separate from the connection declaring a default route: declaring
	// one makes a connection able to carry everything, and this is the decision that it does.
	Carry Carry
	// Logger receives what the connection reports. Required.
	Logger *slog.Logger
	// Runner is the privileged side. Required.
	Runner Runner
	// Reached is the shared memory of which derived attempt last got each connection to its
	// server. It is optional: without one, every start searches from the stored settings again.
	Reached *Reached
	// LinkChanges signals that this machine's own networking moved -- another network, a cable
	// pulled, a laptop woken. It is optional: without it a connection whose path just went away
	// waits for openvpn's own ping timeout, which the server chooses and which is usually a
	// minute or more of sending packets from an address that no longer exists.
	LinkChanges <-chan struct{}
	// Through is the connection this one's own packets travel inside, which is what makes it a
	// hop of a chain rather than a connection dialled over this machine's own network. It is
	// optional, and nil is the ordinary case.
	//
	// A carried connection reaches its server over a stream rather than a datagram, so it is
	// started on the TCP transport whatever the stored settings say; the settings themselves
	// are refused before they get here if that is not what the server answers on.
	Through Carrier
}

// Tunnel is one OpenVPN connection behind the tunnel seam.
type Tunnel struct {
	id     string
	held   config.OpenVPNTunnel
	carry  Carry
	logger *slog.Logger
	runner Runner
	// reachedBy outlives this connection, so what worked survives the restart that switching
	// which connection carries the machine's internet traffic performs on both of them.
	reachedBy *Reached
	// links is this machine's own networking moving, nil when nothing is watching it.
	links <-chan struct{}
	// through is the connection carrying this one's packets, nil when it is dialled over this
	// machine's own network.
	through Carrier

	// forward is the loopback listener a carried connection reaches its server through, nil
	// for a connection that is not running or is not a hop.
	forward *hopForward

	// events carries one signal per status change, buffered so a change is never lost and
	// never blocks the goroutine that noticed it.
	events chan struct{}

	mu     sync.Mutex
	status tunnel.Status
	// running says the openvpn program was started, which is what a stop has to undo. It is
	// separate from the status: a connection that failed to reach its server is running and
	// not connected.
	running bool
	// stopping suppresses the failure report a deliberate shutdown produces. openvpn reports
	// its own exit as a state notification, and without this every ordinary stop would land
	// on screen as a connection that failed.
	stopping bool
	// switching suppresses what a deliberate restart produces while this connection moves on
	// to another way of reaching its server: the program being replaced reports its own exit,
	// and that exit is the replacement happening rather than a connection that failed.
	switching bool
	closed    bool
	// linkCtx lives as long as this connection runs, and stopLink ends it: the conversation
	// and the watch on this machine's networking are both bound to it.
	linkCtx  context.Context
	stopLink context.CancelFunc
	// conv is the conversation with the program now running, kept because a command that is
	// sent to it -- the reconnect a link change asks for -- is sent from outside the goroutine
	// reading it, and because the program that replaces this one on a restart is spoken to
	// through the same one. Nil when no program was started.
	conv *link
	// attempts are the ways this connection will be started, its stored settings first.
	// current is the one running, and gen counts the changes so a window armed for one
	// attempt cannot move a later one along.
	attempts []attempt
	current  int
	gen      int
	// reached says an attempt got as far as the server's control channel, which settles every
	// question the search is asking: after it, a connection that drops is openvpn's own to
	// retry.
	reached bool
	// using names the change that reached the server, empty when the stored settings did. It
	// is reported on the connection and written nowhere.
	using string
	last  report
	// notice is the last reason openvpn gave for a connection that is not coming up. It is
	// kept rather than only published, because the notification that ends a failed connection
	// carries no reason of its own and this is the only place one was ever said.
	notice string
	iface  string
	mtu    int
	// scopedIface is the interface that holds the default route of its own CarryScoped needs,
	// empty when none does, and scopeProblem is why. It is the interface name rather than a
	// flag because the route belongs to an interface: openvpn opens a fresh one every time it
	// reconnects, and the one it had took its routes with it when it went away. A flag would
	// leave this connection reporting itself as carrying the machine's internet traffic over a
	// route the kernel dropped, which is every destination failing with nothing saying why.
	//
	// scoping says one such request is in flight. openvpn reports the connected state again
	// every time it reconnects, and without this a slow answer would have a second request
	// asking for the same route behind the first.
	scopedIface  string
	scoping      bool
	scopeProblem string
	pushed       []string
	// served are the resolvers this connection's server handed out, used only when none are
	// configured here. They live as long as the connection runs and are written nowhere.
	served    []netip.Addr
	resolver  *net.Resolver
	rxBytes   int64
	txBytes   int64
	startedAt time.Time
}

// resolvingTunnel is a connection whose network publishes resolvers of its own.
//
// It is a separate type rather than a flag because the capability is discovered by type
// assertion: a connection configured with no resolvers has no way to look a name up, and
// answering that question with an error every caller then has to classify is the shape the
// capability pattern exists to avoid. Absence is absence.
type resolvingTunnel struct{ *Tunnel }

var (
	_ tunnel.Tunnel      = (*Tunnel)(nil)
	_ tunnel.Reaching    = (*Tunnel)(nil)
	_ tunnel.ExitCarrier = (*Tunnel)(nil)
	_ tunnel.Sized       = (*Tunnel)(nil)
	_ tunnel.Metered     = (*Tunnel)(nil)
	_ tunnel.Anchored    = (*Tunnel)(nil)
	_ tunnel.Resolving   = (*resolvingTunnel)(nil)
)

// New builds a connection from its stored settings. It starts nothing: Start does that, and
// until then the connection reports itself off, which is what a configured connection that
// has not been switched on is.
func New(opts Options) tunnel.Tunnel {
	t := &Tunnel{
		id:        opts.ID,
		held:      opts.Held,
		carry:     opts.Carry,
		logger:    opts.Logger,
		runner:    opts.Runner,
		reachedBy: opts.Reached,
		links:     opts.LinkChanges,
		through:   opts.Through,
		events:    make(chan struct{}, 1),
		mtu:       opts.Held.MTU,
	}
	t.status = tunnel.Status{State: tunnel.StateOff, Limits: t.limits()}
	if len(opts.Held.DNS) == 0 {
		return t
	}
	return &resolvingTunnel{t}
}

// limits are what this connection does not carry, stated when it is built rather than
// discovered when something fails.
//
// Both of the standing ones are consequences of running on a real interface: it is a change
// to this machine, and this machine has one routing table. The third appears only when this
// connection was chosen to carry everything, because that is where IPv6 traffic can quietly
// keep leaving the way it always did -- and what decides whether it does differs between the
// two ways of carrying it. Owning this machine's default sends IPv6 in only when the stored
// networks ask for it; a route on this connection's own interface can only carry IPv6 when
// the connection's network gave this machine an IPv6 address to send from.
func (t *Tunnel) limits() []string {
	out := []string{
		"This connection installs a network interface and routes on this machine, so every " +
			"program here reaches the network -- and starting it needs administrator rights.",
		"Two connections carrying the same address range cannot both be reached at their real " +
			"addresses: this machine's routing table has one winner.",
	}
	switch {
	case t.carry == CarryDefault && !carriesV6Default(t.held.Routes):
		out = append(out, "This connection carries this machine's internet traffic over IPv4 only. "+
			"IPv6 traffic still leaves through this machine's own network; add ::/0 to the "+
			"networks it carries to send that here too.")
	case t.carry == CarryScoped:
		out = append(out, "This connection carries this machine's IPv6 traffic only if its own "+
			"network gave this machine an IPv6 address. Where it did not, IPv6 traffic still "+
			"leaves through this machine's own network.")
	}
	return out
}

// carriesV6Default reports whether a connection declared an IPv6 default route, which is what
// decides whether IPv6 traffic can be sent into it at all.
func carriesV6Default(routes []netip.Prefix) bool {
	for _, prefix := range routes {
		if prefix.Bits() == 0 && prefix.Addr().Is6() {
			return true
		}
	}
	return false
}

func (t *Tunnel) ID() string              { return t.id }
func (t *Tunnel) Kind() tunnel.Kind       { return tunnel.KindOpenVPN }
func (t *Tunnel) Events() <-chan struct{} { return t.events }

// Routes are the networks reachable through this connection, which is what app-tail was told
// it carries rather than what the server offered. A default route is not one of them: that is
// the statement about where this machine's internet traffic goes, and counting it here would
// have this connection claim every destination there is.
func (t *Tunnel) Routes(context.Context) ([]netip.Prefix, error) {
	return t.held.CarriedRoutes(), nil
}

// Addrs are the addresses this device holds inside the network. They come from the server:
// unlike WireGuard, an OpenVPN client is assigned its address rather than configured with it,
// so there is nothing to report until the connection is up.
func (t *Tunnel) Addrs() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addrsLocked()
}

func (t *Tunnel) addrsLocked() []netip.Addr {
	var out []netip.Addr
	if t.last.TunV4.IsValid() {
		out = append(out, t.last.TunV4)
	}
	if t.last.TunV6.IsValid() {
		out = append(out, t.last.TunV6)
	}
	return out
}

// Anchors is where this connection's own packets go: the server address openvpn is currently
// talking to, which is the resolved one rather than whatever was configured. Those packets
// have to keep leaving through this machine's own network, and this is the only place that
// address is known.
//
// A carried connection anchors nothing. Its packets leave through the connection before it in
// the chain rather than through this machine's own network, and the address openvpn reports is
// the loopback listener carrying them -- so keeping this machine's own route to anywhere on
// its account would be a hole punched for an address nothing is dialling.
func (t *Tunnel) Anchors() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.through != nil || !t.last.Server.IsValid() {
		return nil
	}
	return []netip.Addr{t.last.Server}
}

// MTU is the largest packet this network carries: what the connection was configured with,
// or the interface's own size once the interface exists, or openvpn's default until then.
func (t *Tunnel) MTU() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.held.MTU > 0 {
		return t.held.MTU
	}
	if t.mtu > 0 {
		return t.mtu
	}
	return defaultMTU
}

// Status is the cached view, republished by the management conversation rather than read
// from anything here: this is called on every dashboard poll and every tray open.
func (t *Tunnel) Status() tunnel.Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

// Carried is what this connection has moved since it started and how long it has been up.
// openvpn is the only thing that counts the bytes: the packets cross in the kernel, so nothing
// in this process sees them, and what is reported here is what openvpn was asked to report on
// its management socket.
//
// There is no handshake time: openvpn re-keys on its own schedule and does not report when it
// last did, so the field stays zero rather than carrying a moment this connection invented.
func (t *Tunnel) Carried() tunnel.Carried {
	t.mu.Lock()
	defer t.mu.Unlock()
	return tunnel.Carried{Up: t.txBytes, Down: t.rxBytes, Since: t.startedAt}
}

// Start brings the connection up.
//
// It returns once openvpn is running and has been given its configuration, which is before it
// has reached the server: a wrong password or an unreachable server is a connection that
// started and has not connected, and those are different states. What cannot work at all --
// a configuration the privileged side refuses, a program whose management socket never
// answers -- is an error here, because there is nothing to watch and no state to report.
func (t *Tunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	switch {
	case t.closed:
		t.mu.Unlock()
		return errors.New("this connection has been closed and cannot be started again")
	case t.running:
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()

	t.publish(tunnel.Status{State: tunnel.StateStarting, Limits: t.limits()})

	// Before anything else that has to be undone: a connection that is a hop of a chain
	// reaches its server through this listener, and there is nothing to start without it.
	var forward *hopForward
	if t.through != nil {
		f, err := startHopForward(t.id, t.held.Remote, t.through, t.logger)
		if err != nil {
			t.fail(err)
			return err
		}
		forward = f
	}

	run := t.run(forward)
	linkCtx, stopLink := context.WithCancel(context.WithoutCancel(ctx))
	conv := t.link()
	go t.followLinks(linkCtx)

	// The stored settings, always. Everything else is only reached by this one failing.
	//
	// Recorded before openvpn is started rather than after: openvpn reports a dead address
	// within milliseconds of starting, and a search that was not yet armed when that arrived
	// would sit on the address it already knows is wrong.
	attempts := preferring(attemptsFor(run, forward != nil), t.reachedBy.of(t.id))
	t.mu.Lock()
	t.linkCtx, t.stopLink, t.conv, t.forward = linkCtx, stopLink, conv, forward
	t.attempts, t.current, t.reached, t.using = attempts, 0, false, ""
	// The interface belongs to the program that is about to start, not to whatever ran before,
	// and neither does the route that was on it.
	t.iface, t.mtu = "", 0
	t.scopedIface, t.scoping, t.scopeProblem = "", false, ""
	t.gen++
	gen := t.gen
	t.mu.Unlock()

	abandon := func(err error) error {
		stopLink()
		conv.close()
		if forward != nil {
			if closeErr := forward.Close(); closeErr != nil {
				t.logger.Warn("closing the listener of a connection that could not start failed",
					"connection", t.id, "error", closeErr)
			}
		}
		t.mu.Lock()
		t.linkCtx, t.stopLink, t.conv, t.attempts, t.forward = nil, nil, nil, nil, nil
		t.mu.Unlock()
		t.fail(err)
		return err
	}
	if err := t.runner.StartOpenVPN(ctx, attempts[0].run); err != nil {
		return abandon(err)
	}
	// openvpn waits, held, until something connects here and releases it, so nothing about
	// the connection happens before this side is listening to what it reports.
	if err := t.attach(ctx, linkCtx, conv); err != nil {
		return abandon(errors.Join(err, t.stopUnreachable()))
	}

	t.mu.Lock()
	t.running, t.startedAt = true, time.Now()
	t.mu.Unlock()

	t.publish(tunnel.Status{State: tunnel.StateConnecting, Limits: t.limits()})
	t.armWindow(gen)
	return nil
}

// followLinks tells the running program to make its connection again whenever this machine's
// own networking moves.
//
// openvpn works this out by itself in the end: the server's pushed keepalive gives it a ping
// timeout and it restarts when that expires. The timeout is the server's to choose and is
// usually a minute or more, and every second of it is a laptop that changed networks sending
// packets from an address that no longer exists. This is the same restart openvpn would have
// arrived at, taken as soon as the machine knows.
//
// It ends with the conversation it speaks down, so a connection that was stopped has nothing
// left listening for this.
func (t *Tunnel) followLinks(ctx context.Context) {
	links := t.links
	if links == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-links:
			if !ok {
				return
			}
			t.reconnect()
		}
	}
}

// reconnect asks the running program to drop its connection to the server and make it again.
//
// SIGUSR1 rather than a stop and a start: the program stays, so the account is not asked for
// again and nothing crosses the privilege boundary. The interface it opens is a new one, which
// is the case the connected state already handles -- the route this connection may carry the
// machine's internet traffic over is asked for again on every arrival there.
func (t *Tunnel) reconnect() {
	t.mu.Lock()
	conv := t.conv
	// A connection that is stopping, being replaced, or not started has nothing to tell: the
	// program is going away or is not there, and the one that follows connects on the machine's
	// networking as it now stands.
	quiet := t.closed || t.stopping || t.switching || !t.running
	t.mu.Unlock()
	if quiet || conv == nil {
		return
	}

	if err := conv.send("signal SIGUSR1"); err != nil {
		// Nothing is holding the socket, which is openvpn between programs rather than a
		// failure: it reconnects on the networking as it stands when it gets there.
		t.logger.Debug("this connection was not reachable when the machine's networking moved",
			"connection", t.id, "error", err)
		return
	}
	t.logger.Info("the machine's networking moved; making this connection again",
		"connection", t.id)
}

// attemptWindow is how long one way of reaching the server is given before the next is tried.
//
// A server that is going to answer answers at once: openvpn sends its first handshake packet on
// the millisecond it starts and repeats it every two seconds, so this is that handshake several
// times over plus room for a server on the other side of the world. What it is not is a wait for
// a server that will never answer, which is the case every attempt after the first is in.
const attemptWindow = 10 * time.Second

// armWindow gives the attempt now running its own time to reach the server. A connection that
// has not got there by then is one this address, key or digest will not reach.
//
// Nothing is armed for the last attempt: there is nothing to move on to, and openvpn goes on
// retrying it by itself, which is what a connection to a server that is merely down should do.
func (t *Tunnel) armWindow(gen int) {
	t.mu.Lock()
	more := t.current+1 < len(t.attempts)
	t.mu.Unlock()
	if !more {
		return
	}
	time.AfterFunc(attemptWindow, func() {
		t.advance("the server did not answer", false, gen)
	})
}

// advance moves this connection on to the next way of reaching its server.
//
// skipEndpoint drops every remaining attempt against the same address at once. It is set by
// the one failure that says the address itself is wrong: no key and no digest makes something
// that is not an OpenVPN server answer as one.
//
// The work happens in a goroutine of its own because this is called from the goroutine reading
// the management socket and from the window timer, neither of which may block -- and stopping
// one program to start another does.
func (t *Tunnel) advance(reason string, skipEndpoint bool, gen int) {
	t.mu.Lock()
	if t.closed || t.stopping || t.switching || t.reached || len(t.attempts) == 0 || t.gen != gen {
		t.mu.Unlock()
		return
	}
	next := nextFrom(t.attempts, t.current, skipEndpoint)
	if next >= len(t.attempts) {
		tried := len(t.attempts)
		t.mu.Unlock()
		if tried > 1 {
			t.exhausted(reason, tried)
		}
		// One attempt means there was nothing to search: openvpn goes on retrying the settings
		// as they stand, which is what a connection to a server that is merely down should do,
		// and the reason is already on the connection as its notice.
		return
	}
	t.gen++
	t.switching, t.current = true, next
	nextAttempt, nextGen, of := t.attempts[next], t.gen, len(t.attempts)
	t.mu.Unlock()

	go t.restart(nextAttempt, nextGen, reason, next+1, of)
}

// nextFrom is the attempt that follows the one now running.
//
// skipEndpoint passes over the rest of the attempts at the same address, which is what a reason
// that condemns the address itself calls for: no key and no digest makes something that is not
// an OpenVPN server answer as one.
func nextFrom(attempts []attempt, current int, skipEndpoint bool) int {
	next := current + 1
	if !skipEndpoint || current >= len(attempts) {
		return next
	}
	for next < len(attempts) && attempts[next].endpoint == attempts[current].endpoint {
		next++
	}
	return next
}

// restart replaces the running program with one configured the next way.
//
// The conversation is kept: the replacement listens on the same socket, and once it has been
// dialled it is served by the same link rather than by anything that has to be rebuilt.
func (t *Tunnel) restart(next attempt, gen int, reason string, at, of int) {
	t.logger.Info("this connection could not reach its server, trying another way",
		"connection", t.id, "reason", reason, "trying", next.what)

	stopCtx, cancelStop := context.WithTimeout(context.Background(), stopTimeout)
	err := t.runner.StopOpenVPN(stopCtx, t.id)
	cancelStop()
	if err != nil {
		t.mu.Lock()
		t.switching = false
		t.mu.Unlock()
		t.problem(fmt.Errorf("stop this connection before trying another way to reach its server: %w", err))
		return
	}

	startCtx, cancelStart := context.WithTimeout(context.Background(), stopTimeout)
	err = t.runner.StartOpenVPN(startCtx, next.run)
	cancelStart()
	if err == nil {
		t.mu.Lock()
		conv, linkCtx := t.conv, t.linkCtx
		t.mu.Unlock()
		if conv == nil {
			err = errors.New("this connection was taken down while its replacement was starting")
		} else if attachErr := t.attach(context.Background(), linkCtx, conv); attachErr != nil {
			err = errors.Join(attachErr, t.stopUnreachable())
		}
	}

	t.mu.Lock()
	t.switching = false
	// The replacement opens an interface of its own; the one the stopped program had is gone,
	// and so is the route that was on it.
	t.iface, t.mtu = "", 0
	t.scopedIface, t.scoping, t.scopeProblem = "", false, ""
	stale := t.closed || t.stopping || t.gen != gen
	t.mu.Unlock()
	if stale {
		return
	}
	if err != nil {
		t.fail(err)
		return
	}
	t.publish(tunnel.Status{
		State: tunnel.StateConnecting,
		Detail: fmt.Sprintf("the settings stored here did not reach this server; trying %s (%d of %d)",
			next.what, at, of),
		Limits: t.limits(),
	})
	t.armWindow(gen)
}

// exhausted reports a connection no way of reaching its server got through to.
//
// The last program is left running rather than stopped: openvpn keeps retrying it, and a
// server that was merely down comes back on its own. The reason is kept as this connection's
// notice so it survives the states that retrying goes on producing.
func (t *Tunnel) exhausted(reason string, tried int) {
	detail := fmt.Sprintf("%s. app-tail tried %d ways of reaching this server -- the address, "+
		"transport, key and digest stored here, and the alternatives those values allow -- and "+
		"none of them answered", reason, tried)
	t.mu.Lock()
	if t.closed || t.stopping {
		t.mu.Unlock()
		return
	}
	t.notice = detail
	pushed, using, served := t.pushed, t.using, t.served
	t.mu.Unlock()
	t.logger.Warn("this connection reached its server no way at all",
		"connection", t.id, "tried", tried, "reason", reason)
	t.publish(tunnel.Status{State: tunnel.StateFailed, Detail: detail, Limits: t.limitsWith(pushed, using, served)})
}

// run renders the stored settings into what crosses the privilege boundary.
//
// Every value is a typed field rather than a line of configuration: the privileged side
// renders the file from these against its own fixed template, and checks all of it again.
func (t *Tunnel) run(forward *hopForward) Run {
	// A carried connection is pointed at the loopback listener this package owns rather than
	// at its own server, and over a stream: what is carried is a TCP conversation, and the
	// settings are refused before they reach here if the server does not answer one.
	remote, proto := t.held.Remote, t.held.EffectiveProto()
	if forward != nil {
		remote, proto = forward.addr(), config.OpenVPNProtoTCP
	}
	return Run{
		ID:               t.id,
		Remote:           remote,
		Proto:            proto,
		CA:               t.held.CA,
		Cert:             t.held.Cert,
		Key:              t.held.Key,
		TLSCrypt:         t.held.TLSCrypt,
		TLSAuth:          t.held.TLSAuth,
		KeyDirection:     t.held.KeyDirection,
		AuthUserPass:     t.held.AuthUserPass,
		Cipher:           t.held.Cipher,
		Auth:             t.held.Auth,
		VerifyServerCert: t.held.VerifyServerCert,
		VerifyName:       t.held.VerifyName,
		VerifyNameType:   t.held.EffectiveVerifyNameType(),
		Routes:           t.held.Routes,
		// Only the arrangement where this connection owns the machine's default route. The
		// stored networks are the extra ones it reaches, and asking for a default route among
		// them as well would be asking the same question twice -- in a place a server's own
		// file usually cannot answer, since a provider pushes redirect-gateway at connect time
		// rather than writing it in the file it hands out. Carrying the traffic on a route
		// scoped to this connection's own interface is the other arrangement, and openvpn is
		// not the thing that installs that one: taking the machine's default as well would
		// take it from the interface that is already carrying it.
		RedirectGateway: t.carry == CarryDefault,
		MTU:             t.held.MTU,
	}
}

// link builds the management conversation, wiring what openvpn says to what this connection
// reports.
func (t *Tunnel) link() *link {
	return &link{
		creds: credentials{
			Username:      t.held.Username,
			Password:      t.held.Password,
			KeyPassphrase: t.held.KeyPassphrase,
		},
		onReport:  t.observe,
		onBytes:   t.count,
		onPushed:  t.notePushed,
		onLog:     func(text string) { t.logger.Debug("openvpn", "connection", t.id, "message", text) },
		onDevice:  t.noteDevice,
		onNotice:  t.note,
		onProblem: t.problem,
	}
}

// observe turns one state notification into the status this connection reports.
func (t *Tunnel) observe(state report) {
	t.mu.Lock()
	// Taken before this report replaces it, because a connection arriving at the connected
	// state is a different thing from one already there: the arrival is openvpn having opened
	// its interface, and the route this connection carries traffic over lives on that
	// interface rather than on the connection.
	wasConnected := t.last.Connected()
	t.last = state
	stopping, switching := t.stopping, t.switching
	if switching && !state.Connected() {
		// The program being replaced, reporting its own exit. That exit is the replacement
		// happening rather than anything this connection should say out loud.
		t.mu.Unlock()
		return
	}
	if reachedServer(state.Name) && !t.reached {
		// openvpn only says these once its control channel is up, which settles every question
		// the search was asking: this address, this key and this digest are the server's.
		t.reached = true
		if t.current < len(t.attempts) {
			t.using = t.attempts[t.current].what
			// Kept for the next start of this connection, which is a restart away: switching
			// which connection carries this machine's internet traffic restarts both of them.
			t.reachedBy.remember(t.id, t.using)
		}
		t.notice = ""
	}
	scope := false
	if state.Connected() {
		t.mtu = interfaceMTU(t.iface)
		t.resolver = t.newResolver()
		// A connection that reached its server owes nothing to the attempts that did not.
		t.notice = ""
		// Only now: openvpn opens its interface and configures it on the way to this state, and
		// a route asked for before that names an interface that does not exist yet.
		//
		// Asked for again on every arrival here, not only the first. openvpn is started without
		// persist-tun, so a connection that dropped and came back tore its interface down and
		// opened another -- and the route went with the old one whether or not the kernel handed
		// back the same name. The route is installed as a replacement, so asking when one is
		// already there costs a route command and changes nothing.
		scope = t.carry == CarryScoped && !t.scoping && (!wasConnected || t.scopedIface != t.iface)
		t.scoping = t.scoping || scope
	}
	addrs := addrStrings(t.addrsLocked())
	pushed, notice, using, served := t.pushed, t.notice, t.using, t.served
	t.mu.Unlock()

	if scope {
		// In a goroutine of its own because this runs on the goroutine reading the management
		// socket, which openvpn goes on writing to: blocking it for the length of a change to
		// this machine's routing would stop this connection being watched while it happened.
		go t.scopeInterface()
	}

	status := tunnel.Status{Addrs: addrs, Limits: t.limitsWith(pushed, using, served)}
	status.State, status.Detail = stateOf(state, stopping)
	status.Detail = detailWith(status.State, status.Detail, notice)
	t.publish(status)
}

// reachedServer reports whether one of openvpn's state names proves the server was reached.
//
// It is the search's own answer: openvpn reaches none of these until its control channel is
// up, so the address, the key and the digest in the attempt now running are the server's.
// What happens after -- an account refused, a certificate that did not match -- is a failure
// against the right server, and trying other addresses for it would be nonsense.
func reachedServer(name string) bool {
	switch name {
	case "AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "CONNECTED":
		return true
	}
	return false
}

// note puts the reason openvpn gave for a connection that is not coming up onto the
// connection itself.
//
// The state is left alone: openvpn retries a handshake that failed, so this is a connection
// still trying with a reason attached rather than one that has given up. Without it a server
// that never answers, an account the server refused and a certificate whose name did not
// match are all a connection that reports "connecting" for as long as anyone watches it.
func (t *Tunnel) note(text string) {
	skipEndpoint, unreached := reachFailure(text)

	t.mu.Lock()
	if t.closed || t.stopping || t.switching || t.status.State == tunnel.StateConnected {
		t.mu.Unlock()
		return
	}
	t.notice = text
	status := t.status
	gen := t.gen
	// A reason the search is about to move past is not put on screen. It is a step of a search
	// that is working, and shown on its own it reads as the connection having failed -- which
	// is what somebody watching would act on, seconds before the next attempt corrects it. It
	// is still kept as the notice, so a search that runs out of attempts reports it.
	moving := unreached && !t.reached && nextFrom(t.attempts, t.current, skipEndpoint) < len(t.attempts)
	t.mu.Unlock()

	t.logger.Warn("openvpn", "connection", t.id, "reason", text)
	if !moving {
		status.Detail = text
		t.publish(status)
	}

	// The window would get to the next attempt on its own; taking the same decision the moment
	// openvpn makes it is what keeps a search through a handful of addresses quick.
	if unreached {
		t.advance(text, skipEndpoint, gen)
	}
}

// detailWith folds the last reason openvpn gave into the detail of the state it went on to
// report. openvpn's own EXITING notification carries no reason for the failures that matter
// most -- a refused account, a certificate that did not match -- so without this a connection
// that was told exactly why it failed reports only that it ended.
func detailWith(state tunnel.State, detail, notice string) string {
	switch {
	case notice == "", state == tunnel.StateConnected, state == tunnel.StateStopping:
		return detail
	case detail == "":
		return notice
	case strings.Contains(detail, notice):
		return detail
	}
	return detail + ": " + notice
}

// stateOf maps openvpn's own state name onto the one vocabulary every connection reports in.
//
// It is pure, so every arm is reachable in a test without a server -- including the ones that
// only happen against a server that is refusing, which is exactly where a connection is
// reported wrongly for long enough to matter.
func stateOf(state report, stopping bool) (tunnel.State, string) {
	switch state.Name {
	case "CONNECTED":
		return tunnel.StateConnected, ""
	case "RESOLVE", "TCP_CONNECT", "CONNECTING", "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES":
		return tunnel.StateConnecting, ""
	case "AUTH_PENDING":
		// The server wants an approval this app has no way to give: a second factor, or a
		// device approval done somewhere else. It is a wait on a person rather than a
		// failure, and saying so is what stops it reading as a broken connection.
		return tunnel.StateNeedsLogin, "the server is waiting for this login to be approved somewhere else"
	case "RECONNECTING":
		detail := "the connection dropped and is being retried"
		if state.Detail != "" {
			detail = "the connection dropped and is being retried: " + state.Detail
		}
		return tunnel.StateConnecting, detail
	case "EXITING":
		if stopping {
			return tunnel.StateStopping, ""
		}
		detail := "the connection ended"
		if state.Detail != "" {
			detail = "the connection ended: " + state.Detail
		}
		return tunnel.StateFailed, detail
	}
	return tunnel.StateConnecting, ""
}

// count records what openvpn says it has carried.
func (t *Tunnel) count(in, out int64) {
	t.mu.Lock()
	t.rxBytes, t.txBytes = in, out
	t.mu.Unlock()
}

// notePushed records the options the server offered and this connection dropped, so they are
// something the user can read off the connection rather than guess at.
func (t *Tunnel) notePushed(pushed []string) {
	t.mu.Lock()
	same := len(t.pushed) == len(pushed)
	if same {
		for i := range pushed {
			if t.pushed[i] != pushed[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.mu.Unlock()
		return
	}
	t.pushed = pushed
	// Taken before the resolver is rebuilt, because a name looked up inside this network has
	// nowhere else to go: without them the lookup fails outright, and the connection is up with
	// every name on it unresolvable.
	t.served = servedResolvers(pushed)
	if t.status.State == tunnel.StateConnected {
		// A reply that arrives after the connection came up. The ordinary order is the other
		// way round, and rebuilding here is what keeps the two orders the same connection.
		t.resolver = t.newResolver()
	}
	status := t.status
	using, served := t.using, t.served
	adopted := len(t.held.DNS) == 0 && len(served) > 0
	t.mu.Unlock()

	t.logger.Info("this connection's server offered settings",
		"connection", t.id, "offered", strings.Join(pushed, "; "), "resolversTaken", adopted)
	status.Limits = t.limitsWith(pushed, using, served)
	t.publish(status)
}

// limitsWith is the standing limits, the change this connection had to make to reach the server
// at all, what it took from what that server offered, and what it left.
func (t *Tunnel) limitsWith(pushed []string, using string, served []netip.Addr) []string {
	out := t.limits()
	if using != "" {
		out = append(out, "The settings stored here did not reach this connection's server. It is "+
			"running with "+using+". Nothing stored here was changed: put the same change in under "+
			"OpenVPN to have it used from the start.")
	}
	taken := len(t.held.DNS) == 0 && len(served) > 0
	if taken {
		out = append(out, "No resolvers are configured for this connection, so names inside it are "+
			"looked up through the ones its server handed out: "+addrList(served)+". That server sees "+
			"those names. Set resolvers under DNS to use your own instead.")
	}
	if left := unapplied(pushed, taken); len(left) > 0 {
		out = append(out, "This connection's server offered settings that are not applied: "+
			strings.Join(left, "; ")+". What this connection carries and how this machine routes its "+
			"own traffic is what is configured here; add any of these under Addressing if you want them.")
	}
	return out
}

// unapplied are the offered options this connection did not act on. The resolvers drop out of
// the list when they were taken, since an option reported as ignored and used at the same time
// is worse than either answer on its own.
func unapplied(pushed []string, tookResolvers bool) []string {
	if !tookResolvers {
		return pushed
	}
	out := make([]string, 0, len(pushed))
	for _, option := range pushed {
		if len(servedResolvers([]string{option})) > 0 {
			continue
		}
		out = append(out, option)
	}
	return out
}

// addrList writes addresses the way they are read on a dashboard.
func addrList(addrs []netip.Addr) string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return strings.Join(out, ", ")
}

// problem records a failure the connection cannot recover from on its own.
func (t *Tunnel) problem(err error) {
	t.mu.Lock()
	stopping := t.stopping || t.closed || t.switching
	pushed, using, served := t.pushed, t.using, t.served
	t.mu.Unlock()
	if stopping {
		// A conversation ending because this connection is being taken down, or restarted onto
		// the next attempt, is that working rather than a fault.
		return
	}
	t.logger.Warn("openvpn", "connection", t.id, "error", err)
	t.publish(tunnel.Status{State: tunnel.StateFailed, Detail: err.Error(), Limits: t.limitsWith(pushed, using, served)})
}

// fail records a start that never got as far as a running program.
func (t *Tunnel) fail(err error) {
	t.publish(tunnel.Status{State: tunnel.StateFailed, Detail: err.Error(), Limits: t.limits()})
}

// Close takes the connection down. It is safe to call on one that never started, and twice,
// which is what lets a caller stop a connection without first asking whether there is
// anything to stop.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	running, conv, stopLink, forward := t.running, t.conv, t.stopLink, t.forward
	t.closed, t.stopping, t.running = true, true, false
	t.linkCtx, t.stopLink, t.conv, t.resolver, t.forward = nil, nil, nil, nil, nil
	t.status = tunnel.Status{State: tunnel.StateOff, Limits: t.limits()}
	t.mu.Unlock()

	var errs []error
	if running {
		// Asked first, and the conversation closed after: openvpn takes its own interface and
		// routes down when it is asked to stop, and dropping the conversation out from under
		// it would have it restart and hold before it got that far.
		ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		if err := t.runner.StopOpenVPN(ctx, t.id); err != nil {
			errs = append(errs, fmt.Errorf("stop this connection: %w", err))
		}
		cancel()
	}
	if stopLink != nil {
		stopLink()
	}
	if conv != nil {
		conv.close()
	}
	// Last, because openvpn reaches its server through it: taking it down before the program
	// has been asked to stop would cut the connection it is using to take its own routes down.
	if forward != nil {
		if err := forward.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	t.signal()
	return errors.Join(errs...)
}

// stopTimeout bounds asking the privileged side to stop this connection. It is longer than
// the grace that side gives the program, so an ordinary shutdown finishes inside it and a
// helper that has gone away does not hold this process on the path that ends it.
const stopTimeout = 15 * time.Second

// managementLocator is a runner that keeps its management sockets somewhere other than the
// helper's own directory. The in-process privileged side says where its are, and so does a
// runner standing in for one in a suite; the helper's client does not need to, because the
// helper puts them at hostnet.OpenVPNManagementSocket.
type managementLocator interface {
	ManagementSocket(id string) string
}

// managementSocket is where the program this connection starts listens for it.
func (t *Tunnel) managementSocket() string {
	if locator, ok := t.runner.(managementLocator); ok {
		return locator.ManagementSocket(t.id)
	}
	return hostnet.OpenVPNManagementSocket(t.id)
}

// attach dials the program just started and hands the conversation to conv, which then lasts
// as long as linkCtx or the program does. dialCtx bounds only the dial.
func (t *Tunnel) attach(dialCtx, linkCtx context.Context, conv *link) error {
	conn, err := dialManagement(dialCtx, t.managementSocket())
	if err != nil {
		return err
	}
	go conv.handle(linkCtx, conn)
	return nil
}

// stopUnreachable stops a program this connection started and could not reach. It is held,
// waiting for a management client that is not coming, so it would otherwise sit there as a
// root process holding an interface until the session ended.
func (t *Tunnel) stopUnreachable() error {
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	if err := t.runner.StopOpenVPN(ctx, t.id); err != nil {
		return fmt.Errorf("stop the openvpn program that could not be reached: %w", err)
	}
	return nil
}

// publish stores a status and signals only when something actually moved, so a consumer
// watching the channel is woken by changes rather than by every notification openvpn sends.
func (t *Tunnel) publish(status tunnel.Status) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	changed := t.status.State != status.State ||
		t.status.Detail != status.Detail ||
		len(t.status.Addrs) != len(status.Addrs) ||
		len(t.status.Limits) != len(status.Limits)
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

func addrStrings(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

// noteDevice records the interface openvpn opened for this connection.
//
// It comes from openvpn's own log because nothing else knows it: the kernel picks the name,
// and two connections to the same provider are handed the same address inside the network --
// so an interface found by looking for that address is as likely to be the other connection's
// as this one's.
func (t *Tunnel) noteDevice(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.iface = name
}

// scopeInterface asks the privileged side to give this connection's interface a default route
// of its own, which is what lets a dial bound to that interface reach anywhere at all.
//
// The failure is kept on the connection rather than only logged, because it is the answer to
// the question the setting asks: a connection chosen to carry this machine's internet traffic
// and unable to says why, where one that reported itself carrying would drop everything sent
// into it. Nothing here takes the route back -- the privileged side removes it when the
// connection ends, which is the one moment this side may not be there for.
func (t *Tunnel) scopeInterface() {
	t.mu.Lock()
	iface, gen := t.iface, t.gen
	t.mu.Unlock()
	if iface == "" {
		t.noteScope(gen, "", "openvpn has not said which network interface this connection is on, "+
			"so there is nothing to give a route to")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), scopeTimeout)
	defer cancel()
	err := t.runner.ScopeOpenVPN(ctx, Scope{ID: t.id, Interface: iface})
	if err != nil {
		t.logger.Warn("this connection could not be given the route it carries this machine's "+
			"internet traffic over", "connection", t.id, "interface", iface, "error", err)
		t.noteScope(gen, "", fmt.Sprintf("%s could not be given a route to the rest of the "+
			"internet: %v", iface, err))
		return
	}
	t.logger.Info("this connection now carries this machine's internet traffic",
		"connection", t.id, "interface", iface)
	t.noteScope(gen, iface, "")
}

// SetCarry moves this connection between carrying this machine's internet traffic and not,
// while it goes on running.
//
// It is a live change rather than a restart because it is one on this machine: the only thing
// the two ways this method moves between change about the running program is nothing at all.
// Which connection carries the traffic is settled by a route on an interface, so switching it
// puts a route on one interface and takes it off another -- and restarting openvpn to do that
// would drop a working connection, ask its server for the account again, and leave the machine
// with no way out for as long as the handshake takes.
//
// The other arrangement, where openvpn takes this machine's own default route, is not reachable
// from here: that one is a line in the configuration the program is started with, so moving to
// or from it is a rebuild. The caller is what decides which of the two this is.
func (t *Tunnel) SetCarry(carry Carry) {
	t.mu.Lock()
	if t.carry == carry || t.closed {
		t.mu.Unlock()
		return
	}
	previous, connected := t.carry, t.status.State == tunnel.StateConnected
	t.carry = carry
	// The route belongs to the arrangement being left, so what is recorded about it does too.
	t.scopedIface, t.scopeProblem = "", ""
	status := t.status
	status.Limits = t.limitsWith(t.pushed, t.using, t.served)
	scope := carry == CarryScoped && connected && !t.scoping
	t.scoping = t.scoping || scope
	t.mu.Unlock()

	t.publish(status)
	switch {
	case scope:
		go t.scopeInterface()
	case previous == CarryScoped:
		go t.unscopeInterface()
	}
}

// unscopeInterface takes back the route this connection was carrying the machine's internet
// traffic over, now that another connection carries it.
//
// A failure is logged rather than kept on the connection: what is left behind is a route on
// this connection's own interface, which says where traffic already bound there goes and
// nothing about where this machine's traffic goes -- so it is worth saying out loud and it is
// not a reason to report the connection as faulty. The privileged side removes it when the
// connection ends either way.
func (t *Tunnel) unscopeInterface() {
	ctx, cancel := context.WithTimeout(context.Background(), scopeTimeout)
	defer cancel()
	if err := t.runner.UnscopeOpenVPN(ctx, t.id); err != nil {
		t.logger.Warn("this connection no longer carries this machine's internet traffic, but the "+
			"route it carried it over could not be taken back", "connection", t.id, "error", err)
		return
	}
	t.logger.Info("this connection no longer carries this machine's internet traffic",
		"connection", t.id)
}

// noteScope records how the route turned out and publishes it.
//
// The generation is what makes a slow answer safe: a connection that moved on to another way
// of reaching its server while this was in flight is running on a different interface, and
// recording this answer against it would describe a route that was never installed there.
//
// scoped is the interface the route was installed on, empty when it was not installed at all.
func (t *Tunnel) noteScope(gen int, scoped, problem string) {
	t.mu.Lock()
	t.scoping = false
	if t.closed || t.stopping || t.gen != gen {
		t.mu.Unlock()
		return
	}
	// Another connection was chosen to carry this machine's internet traffic while this was in
	// flight, so the route this just installed is one nothing asked for -- and the removal that
	// choice fired went out while it was still on its way here.
	stale := scoped != "" && t.carry != CarryScoped
	if stale {
		scoped = ""
	}
	t.scopedIface, t.scopeProblem = scoped, problem
	status := t.status
	t.mu.Unlock()
	if stale {
		go t.unscopeInterface()
	}
	// Published so what depends on it is asked again: whether this connection is carrying the
	// machine's internet traffic changed, and nothing else is going to say so.
	t.publish(status)
}

// interfaceMTU is the largest packet the named interface takes, and zero when there is no
// such interface -- which is what a caller sizing against it reads as nothing measured.
// Reading which interfaces exist needs no privileges.
func interfaceMTU(name string) int {
	if name == "" {
		return 0
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return iface.MTU
}

// Interface is the network interface this connection is running on, empty until it has one.
// It is what a person types into their own tools to look at the connection, and it is not
// knowable in advance: the kernel chooses it.
func (t *Tunnel) Interface() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.iface
}

// CanCarryExit reports whether this connection can carry this machine's internet traffic.
//
// This kind carries it in a routing table, on a real interface, and the answer is whether the
// route it needs is there. What the stored networks or the server's pushed options say is not
// part of it: a commercial provider writes no redirect-gateway into the file it hands out,
// and a 0.0.0.0/0 added by hand is dropped from the rendered file because carrying everything
// is that flag's job. Neither puts a route on the interface.
//
// It matters because a dial bound to an interface holding no route for the destination fails
// with "no route to host" rather than falling back. A connection reporting itself able to
// carry the traffic without the route would be one that silently carries none.
//
// Liveness is asked first: nothing is installed until openvpn has connected, so a connection
// that is down has no answer to give rather than a no.
func (t *Tunnel) CanCarryExit(context.Context) (bool, string) {
	if st := t.Status(); !st.State.Live() {
		return false, "the connection is not up"
	}
	t.mu.Lock()
	// The route is on an interface, so it answers for this connection only while this
	// connection is still on that interface. openvpn opens a fresh one every time it
	// reconnects, and reporting the old answer would have this connection claim to carry
	// traffic over a route the kernel dropped when the interface it was on went away.
	carry, scoped := t.carry, t.scopedIface != "" && t.scopedIface == t.iface
	problem := t.scopeProblem
	t.mu.Unlock()
	switch {
	case carry == CarryNone:
		return false, "this connection was not chosen to carry this machine's internet traffic, so " +
			"it holds no route for anything outside its own network"
	case carry == CarryDefault, scoped:
		return true, ""
	case problem != "":
		return false, problem
	default:
		return false, "this connection's interface is waiting for the route that takes it to the " +
			"rest of the internet"
	}
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
	for _, own := range t.Addrs() {
		if own == addr {
			return true
		}
	}
	return false
}

// Reach says where a destination would go without dialling it, which is what a permission
// check asks before it lets anything through.
//
// An address is reported as carried only when this connection carries it. A name resolved
// through this network's own resolvers means nothing outside it, so handing that answer back
// for a destination this connection does not carry would send a caller to an address that is
// somebody else's on the machine's own network.
func (t *Tunnel) Reach(ctx context.Context, network, address string) (tunnel.Reach, error) {
	if st := t.Status(); !st.State.Live() {
		return tunnel.Reach{}, errors.New("this connection is not up")
	}
	host, port, err := hostAndPort(network, address)
	if err != nil {
		return tunnel.Reach{}, err
	}
	addrs, err := t.addrsOf(ctx, network, host)
	if err != nil {
		// A name this connection has no way to look up is a destination it does not carry
		// rather than a fault: the caller is asking every connection in turn, and one of the
		// others may well know the name.
		if len(t.held.DNS) == 0 {
			return tunnel.Reach{}, nil
		}
		return tunnel.Reach{}, err
	}
	for _, addr := range addrs {
		if t.carries(addr) {
			return tunnel.Reach{Addr: netip.AddrPortFrom(addr, port), Carried: true}, nil
		}
	}
	return tunnel.Reach{}, nil
}

// Dial opens a connection inside the network.
//
// The socket is bound to this connection's own address on the interface, so the packets leave
// through it rather than through whichever interface the machine would otherwise have picked.
// That binding is the whole of what makes a dial "through" this connection: the interface is
// a real one, and everything else about the call is ordinary networking.
func (t *Tunnel) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := hostAndPort(network, address)
	if err != nil {
		return nil, err
	}
	addrs, err := t.addrsOf(ctx, network, host)
	if err != nil {
		return nil, err
	}

	// Every answer in turn: a name with several addresses is one host reachable several ways,
	// and giving up on the first refusal would fail a connection that works.
	var firstErr error
	for _, addr := range addrs {
		conn, err := t.dialAddr(ctx, network, netip.AddrPortFrom(addr, port))
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

// dialAddr opens one connection to one resolved address, out of this connection's own
// interface and from its own address there.
//
// Both halves are needed. The address says who the packets are from, and the interface is
// what decides where they leave by: a socket bound only to the address still follows whatever
// route covers the destination, so once something else carries this machine's internet
// traffic, a dial "through" this connection would leave through that instead -- and with two
// connections to the same provider holding the same address, the address alone does not even
// say which of them was meant.
func (t *Tunnel) dialAddr(ctx context.Context, network string, addr netip.AddrPort) (net.Conn, error) {
	local, err := t.localAddr(addr.Addr())
	if err != nil {
		return nil, err
	}
	out, err := t.sendOut()
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Control: out}
	switch {
	case strings.HasPrefix(network, "tcp"):
		dialer.LocalAddr = &net.TCPAddr{IP: local.AsSlice()}
	case strings.HasPrefix(network, "udp"):
		dialer.LocalAddr = &net.UDPAddr{IP: local.AsSlice()}
	default:
		return nil, net.UnknownNetworkError(network)
	}
	return dialer.DialContext(ctx, network, addr.String())
}

// localAddr is this connection's own address in the same family as the destination.
//
// The family has to match: a socket bound to this connection's IPv4 address cannot reach an
// IPv6 destination, and binding the wrong one produces a failure that reads as the
// destination being unreachable.
func (t *Tunnel) localAddr(dest netip.Addr) (netip.Addr, error) {
	t.mu.Lock()
	v4, v6 := t.last.TunV4, t.last.TunV6
	t.mu.Unlock()
	if dest.Is4() {
		if v4.IsValid() {
			return v4, nil
		}
		return netip.Addr{}, errors.New("this connection holds no IPv4 address on the network yet")
	}
	if v6.IsValid() {
		return v6, nil
	}
	return netip.Addr{}, errors.New("this connection holds no IPv6 address on the network yet")
}

// sendOut is how a socket is made to leave by this connection's interface.
func (t *Tunnel) sendOut() (func(network, address string, c syscall.RawConn) error, error) {
	t.mu.Lock()
	name := t.iface
	t.mu.Unlock()
	if name == "" {
		return nil, errors.New("this connection has no network interface yet")
	}
	return through(name)
}

// Listen accepts TCP inside the network, on this device's own address there.
func (t *Tunnel) Listen(network string, port uint16) (net.Listener, error) {
	addr, err := t.listenAddr(network)
	if err != nil {
		return nil, err
	}
	return net.Listen(network, netip.AddrPortFrom(addr, port).String())
}

// ListenPacket receives UDP inside the network, on this device's own address there.
func (t *Tunnel) ListenPacket(network string, port uint16) (net.PacketConn, error) {
	addr, err := t.listenAddr(network)
	if err != nil {
		return nil, err
	}
	return net.ListenPacket(network, netip.AddrPortFrom(addr, port).String())
}

// listenAddr picks which of this device's addresses to listen on.
//
// The concrete address is chosen rather than left unspecified because this connection is one
// network among several on a machine that now has a real interface for it: a socket bound to
// nothing in particular would be reachable from every network the machine is on, which is the
// opposite of what listening inside one network means.
func (t *Tunnel) listenAddr(network string) (netip.Addr, error) {
	t.mu.Lock()
	v4, v6 := t.last.TunV4, t.last.TunV6
	t.mu.Unlock()
	wantV4 := strings.HasSuffix(network, "4")
	wantV6 := strings.HasSuffix(network, "6")
	switch {
	case wantV6:
		if v6.IsValid() {
			return v6, nil
		}
	case wantV4:
		if v4.IsValid() {
			return v4, nil
		}
	default:
		if v4.IsValid() {
			return v4, nil
		}
		if v6.IsValid() {
			return v6, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("this connection holds no %s address to listen on", network)
}

// addrsOf resolves the host half of a dial, keeping only the address family the caller asked
// for. A literal address is used as it stands: resolving one would be a lookup of a name that
// is not a name.
func (t *Tunnel) addrsOf(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	t.mu.Lock()
	resolver := t.resolver
	t.mu.Unlock()
	if resolver == nil {
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

// resolversLocked is what this connection asks for a name inside it: the resolvers configured
// here, or the ones its server handed out when there are none.
//
// The caller holds the lock.
func (t *Tunnel) resolversLocked() []netip.Addr {
	if len(t.held.DNS) > 0 {
		return t.held.DNS
	}
	return t.served
}

// newResolver builds the resolver for this network's own names.
//
// Every query is sent to a resolver this connection was configured with, through the
// connection itself, so a name that exists only inside the network resolves and nothing about
// the lookup reaches this machine's own resolver.
func (t *Tunnel) newResolver() *net.Resolver {
	servers := t.resolversLocked()
	if len(servers) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, resolverTimeout)
			defer cancel()
			var firstErr error
			for _, server := range servers {
				conn, err := t.dialAddr(ctx, network, netip.AddrPortFrom(server, 53))
				if err == nil {
					return conn, nil
				}
				if firstErr == nil {
					firstErr = err
				}
			}
			if firstErr == nil {
				firstErr = errors.New("this connection has no resolver to ask")
			}
			return nil, firstErr
		},
	}
}

// LookupHost resolves a name through the network's own resolvers, which are the only ones
// that know the names inside it.
func (r *resolvingTunnel) LookupHost(ctx context.Context, host string) (tunnel.Lookup, error) {
	r.mu.Lock()
	resolver := r.resolver
	r.mu.Unlock()
	if resolver == nil {
		return tunnel.Lookup{}, errors.New("this connection is not up")
	}
	found, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		// A name this network's resolver does not have is not a failure to look it up: the
		// caller asks each network in turn, and the name may exist on the next one.
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
	// Go's resolver does not report a record's TTL, so the answer carries none and the caller
	// applies its own floor.
	return tunnel.Lookup{Addrs: out}, nil
}

// hostAndPort splits a destination, in the words the caller of a dial or a reach uses.
func hostAndPort(network, address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("dial %s: %q is not a host and a port", network, address)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("dial %s: %q does not end in a port", network, address)
	}
	return host, uint16(port), nil
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
