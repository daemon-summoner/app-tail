// SPDX-License-Identifier: MIT

// Package tsproxy runs loopback proxies that reach the private networks this app holds.
// One port carries both SOCKS5 and HTTP, split by the first byte the client sends, so a
// program can be pointed at it with either protocol and use addresses and names verbatim
// -- with no VPN interface, no route table change and no privilege.
//
// There is one listener per configured instance, and each instance reaches exactly what
// its own rules allow and nothing else. That is the whole point of having more than one:
// a program handed the address of an instance whose rules name one service has been given
// that service, not the networks it happens to sit on.
//
// It is deliberately not part of internal/forward. That engine is a registry of fixed
// endpoints keyed by a stored forward's id; this is a listener whose destination is chosen
// per connection by the client.
package tsproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// ProxyUser is the SOCKS5 and HTTP username every instance accepts when a token is
// required. It is fixed because a proxy credential has one account by construction, and a
// configurable name would be one more thing to get wrong in a client that offers a single
// user/password box.
const ProxyUser = "app-tail"

// shutdownGrace bounds how long a stop waits for in-flight requests before the listener
// is torn down under them.
const shutdownGrace = 2 * time.Second

// Network is the set of connections a proxy dials through. *tunnel.Registry satisfies it,
// which is what lets the proxy ask "which connection carries this" instead of holding one
// network of its own.
type Network interface {
	// Resolve says which connection carries a destination and what address to dial. It
	// resolves once: the caller dials the address that comes back rather than the name it
	// asked about, because resolving a second time invites the answer to change in
	// between, and the direction it changes is the permissive one.
	Resolve(ctx context.Context, network, address string) (tunnel.Route, error)
	// All is every connection, in the order the user declared them.
	All() []tunnel.Tunnel
	// Get is one connection by id.
	Get(id string) (tunnel.Tunnel, bool)
	// Naming is which connection a suffixed name belongs to. A name that names one is
	// answered by Resolve alone: asking the connections' own resolvers about it first
	// would put the question to every network including the ones it did not name.
	Naming() tunnel.Naming
}

// Options are what a Set is built from.
type Options struct {
	Network Network
	Logger  *slog.Logger
	// StateDir is where each instance's local socket is created, under a "proxies"
	// directory. Empty means no local sockets: every instance is then reachable on its
	// loopback port only.
	StateDir string
	// Now is the clock the resolver cache ages entries against, so a test drives expiry
	// rather than waiting it out.
	Now func() time.Time
	// DialDirect opens a connection that leaves through this machine's own network, which
	// is what a route no connection carries takes. It is here for the same reason Network
	// is: this machine is one of the places a proxy reaches, and a test stands in for it
	// the same way it stands in for the private ones. Empty means the real one.
	DialDirect func(ctx context.Context, network, address string) (net.Conn, error)
}

// Set is every proxy instance the configuration declares, reconciled together.
//
// Reconciling them as a set rather than one at a time is what keeps an unrelated instance
// bound while another is edited: a change to one instance's rules must not drop the
// connections a program is holding open through a different one.
type Set struct {
	net      Network
	logger   *slog.Logger
	stateDir string
	now      func() time.Time
	direct   func(ctx context.Context, network, address string) (net.Conn, error)

	// resolved is what the networks' own resolvers last said about each name. It is shared
	// by every instance because an answer is a fact about the networks rather than about
	// any one listener, and because a burst of connections through two instances to one
	// destination should still cost one query.
	resolved resolveCache

	// up is read on every status and written by the reconcile loop. It reports whether any
	// connection is currently carrying traffic, which is what distinguishes a refusal that
	// will clear itself from one that will not.
	up atomic.Bool

	// inspector examines every destination before it is dialled. It is shared by every
	// instance for the reason the resolver cache is: what a rule says is a fact about the
	// traffic rather than about which listener it arrived on, and two instances that could
	// disagree would be two answers to one question.
	inspector atomic.Pointer[Inspector]

	mu        sync.Mutex
	order     []string
	instances map[string]*Instance
}

// NewSet builds the set. Nothing binds until Apply runs.
func NewSet(opts Options) *Set {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	direct := opts.DialDirect
	if direct == nil {
		direct = dialThisMachine
	}
	return &Set{
		net:       opts.Network,
		logger:    logger,
		stateDir:  opts.StateDir,
		now:       now,
		direct:    direct,
		instances: make(map[string]*Instance),
	}
}

// SetNetworksUp records whether any connection is currently up. Unlike the forwarding
// engine an instance does not stop when they go down: it keeps its port bound and refuses
// with a reason. A closed port makes a user conclude the app is broken; a bound port that
// answers "the connection is not running" is something they can act on.
func (s *Set) SetNetworksUp(up bool) { s.up.Store(up) }

// Apply reconciles the running instances with what the configuration declares.
//
// An instance that is unchanged is left exactly as it is, down to the connections open
// through it. One that was removed or switched off is stopped, and its live connections
// end with it: a proxy that has been turned off must stop carrying traffic now rather than
// whenever each connection happens to finish.
//
// A single instance failing to bind does not stop the others: its reason is published
// through its own status, where the dashboard shows it, and the failures are returned
// together so a caller logs one line rather than losing all but the first.
func (s *Set) Apply(want []config.ProxyInstance) error {
	wanted := make(map[string]struct{}, len(want))
	for _, p := range want {
		if p.Enabled {
			wanted[p.ID] = struct{}{}
		}
	}

	s.mu.Lock()
	var retired []*Instance
	kept := s.order[:0]
	for _, id := range s.order {
		if _, still := wanted[id]; still {
			kept = append(kept, id)
			continue
		}
		retired = append(retired, s.instances[id])
		delete(s.instances, id)
	}
	s.order = kept
	s.mu.Unlock()

	for _, gone := range retired {
		gone.Close()
	}

	var failures []error
	for _, held := range want {
		if !held.Enabled {
			continue
		}
		inst := s.instanceFor(held)
		if err := inst.apply(held); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", held.Handle(), err))
		}
	}
	s.reorder(want)
	return errors.Join(failures...)
}

// instanceFor returns the running instance for a stored one, creating it the first time.
func (s *Set) instanceFor(held config.ProxyInstance) *Instance {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inst, ok := s.instances[held.ID]; ok {
		return inst
	}
	inst := newInstance(s, held)
	s.instances[held.ID] = inst
	s.order = append(s.order, held.ID)
	return inst
}

// reorder puts the running instances back into the order the configuration lists them in,
// which is the order every surface shows them in.
func (s *Set) reorder(want []config.ProxyInstance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	order := make([]string, 0, len(s.instances))
	for _, held := range want {
		if _, running := s.instances[held.ID]; running {
			order = append(order, held.ID)
		}
	}
	s.order = order
}

// Get is one running instance by id.
func (s *Set) Get(id string) (*Instance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.instances[id]
	return inst, ok
}

// All is every running instance, in configuration order.
func (s *Set) All() []*Instance {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Instance, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.instances[id])
	}
	return out
}

// Statuses is every running instance as the API and the dashboard see it.
func (s *Set) Statuses() []Status {
	running := s.All()
	out := make([]Status, 0, len(running))
	for _, inst := range running {
		out = append(out, inst.Status())
	}
	return out
}

// Close stops every instance for good.
func (s *Set) Close() {
	s.mu.Lock()
	held := make([]*Instance, 0, len(s.order))
	for _, id := range s.order {
		held = append(held, s.instances[id])
	}
	s.order = nil
	s.instances = make(map[string]*Instance)
	s.mu.Unlock()

	for _, inst := range held {
		inst.Close()
	}
}

// Instance is one proxy: a listener, the rules deciding what it carries, and everything
// hanging off it. It is safe to reconcile, close and read the Status of from any
// goroutine.
type Instance struct {
	set *Set
	id  string
	// log carries the instance's handle, which changes when it is renamed. It is atomic
	// rather than held under mu because every serving goroutine reads it -- the SOCKS5
	// server logs through it from a Serve call already in flight -- while a reconcile on
	// another goroutine is free to rename the instance underneath them.
	log atomic.Pointer[slog.Logger]
	// transport carries ordinary proxied requests. It is per instance rather than shared
	// because its connection pool is keyed by destination alone: a pooled connection
	// reused across instances would carry one instance's traffic over a connection another
	// instance's rules opened.
	transport *http.Transport

	stats counters
	// dests attributes that traffic per destination, within a fixed budget: what the
	// totals above are worth knowing is which machine they went to.
	dests destTable
	// conns is every upstream connection currently open, so stopping ends them instead of
	// leaving them carrying traffic after the instance was switched off.
	conns liveConns

	mu sync.Mutex
	// raw is the listener the two protocol halves were split from. proxymux's halves do
	// not close it, so this is the one that has to be kept and closed.
	raw     net.Listener
	httpSrv *http.Server
	// local is the same proxy on a socket beside the port. It is the boundary that works:
	// the kernel vouches for the account at the other end of a local socket, and there is
	// no equivalent for a loopback port on any platform this runs on.
	local     net.Listener
	localPath string
	// spec is what the running listener was built from, so a reconcile knows whether it
	// can leave the listener alone.
	spec    listenerSpec
	live    Config
	held    config.ProxyInstance
	bound   string
	lastErr string
	// tunnels is the lifetime a hijacked CONNECT tunnel lives under, and cancel ends it.
	// They are the listener's rather than the request's: net/http cancels a request
	// context as soon as its handler returns, and a tunnel's handler returns the moment
	// the tunnel is established.
	tunnels context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// newInstance builds one instance. Nothing binds until apply runs.
func newInstance(set *Set, held config.ProxyInstance) *Instance {
	p := &Instance{set: set, id: held.ID, held: held}
	p.log.Store(set.logger.With("proxy", held.Handle()))
	p.transport = &http.Transport{
		DialContext: p.dial,
		// Every dial is already bounded by the configured timeout, and the destination is
		// on a private network rather than a public CDN, so the remaining knobs are about
		// not holding peers open for no reason.
		MaxIdleConns:          32,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		// Compression is the client's business, not ours: adding an Accept-Encoding the
		// client did not ask for makes the proxy alter the response it forwards.
		DisableCompression: true,
	}
	return p
}

// ID is the stored instance this one runs.
func (p *Instance) ID() string { return p.id }

// logger is this instance's log, carrying whatever handle it answers to right now.
func (p *Instance) logger() *slog.Logger { return p.log.Load() }

// Config is the part of an instance's configuration a connection is decided by. It is read
// fresh per dial, so changing any of it takes effect on the next connection with no rebind
// -- which is what keeps the port and the auto-config URL stable across an edit.
type Config struct {
	// Rules are what this instance carries, in the order they are matched. Nothing outside
	// them is reached: an instance whose rules cover nothing reaches nothing.
	Rules       []access.Rule
	DialTimeout time.Duration
	// ResolveVia is which resolver turns a name into an address. It sits here rather than
	// in listenerSpec because changing it takes effect on the next connection with no
	// rebind, exactly like the rules above.
	ResolveVia config.ProxyResolveVia
}

// ConfigOf is what one stored instance decides connections by. It is exported so a caller
// asking what an instance that is not currently listening would carry works from the same
// values a running one does, rather than assembling its own idea of them.
func ConfigOf(held config.ProxyInstance) Config {
	return Config{
		Rules:       config.CloneRules(held.Rules),
		DialTimeout: held.DialTimeout(),
		ResolveVia:  held.EffectiveResolveVia(),
	}
}

// listenerSpec is the part of the configuration a bound listener cannot change under.
// The address is obvious; the credential is here because the SOCKS5 server reads it off
// its own struct as each connection is greeted, and that struct is owned by a Serve call
// already in flight.
type listenerSpec struct {
	addr     string
	username string
	password string
}

func (s listenerSpec) authenticates() bool { return s.password != "" }

// alreadyBound reports that a listener sitting at bound, built from running, already
// serves everything this spec asks for.
//
// The address is compared against where the listener actually landed rather than against
// what it was asked for. A port conflict moves the listener and the caller persists the
// address it moved to, so the very next reconcile asks for the port the proxy is already
// on; reading that as a changed address would tear a working listener down only to rebuild
// it on the same port. A configured port of zero asked for whichever port was free, so any
// port on the same host satisfies it.
func (s listenerSpec) alreadyBound(running listenerSpec, bound string) bool {
	if bound == "" || s.username != running.username || s.password != running.password {
		return false
	}
	if s.addr == bound {
		return true
	}
	host, port, err := net.SplitHostPort(s.addr)
	if err != nil || port != "0" {
		return false
	}
	boundHost, _, err := net.SplitHostPort(bound)
	return err == nil && host == boundHost
}

// apply reconciles this instance's listener with its stored configuration. It is the only
// place an instance binds or unbinds, and it is idempotent: a call that changes nothing
// leaves an established listener and every connection on it untouched.
func (p *Instance) apply(held config.ProxyInstance) error {
	live := ConfigOf(held)

	spec, err := specFor(held)
	if err != nil {
		p.stop()
		return p.recordErr(err)
	}

	p.log.Store(p.set.logger.With("proxy", held.Handle()))

	p.mu.Lock()
	rulesChanged := !access.SameRules(p.live.Rules, live.Rules)
	resolverChanged := p.live.ResolveVia != live.ResolveVia
	p.live, p.held = live, held
	unchanged := p.raw != nil && spec.alreadyBound(p.spec, p.bound)
	p.mu.Unlock()

	if resolverChanged {
		// The remembered answers came from the resolver that is no longer in use, and the
		// whole reason to change resolvers is that the two answer differently.
		p.set.resolved.clear()
	}
	if rulesChanged || resolverChanged {
		// Pooled connections were established under the old rules and are keyed by
		// destination, so narrowing them would otherwise keep carrying traffic to a
		// destination this instance now refuses -- and a pooled connection reaches the
		// address the previous resolver gave, whatever the new one would say.
		p.transport.CloseIdleConnections()
	}
	if unchanged {
		return nil
	}

	p.stop()
	if err := p.start(spec); err != nil {
		return p.recordErr(err)
	}
	p.clearErr()
	return nil
}

// specFor derives the listener's fixed configuration, refusing a combination that cannot
// be served rather than binding a port that would let everything through.
func specFor(held config.ProxyInstance) (listenerSpec, error) {
	spec := listenerSpec{addr: held.ListenAddress()}
	if held.RequireToken {
		if held.Token == "" {
			return listenerSpec{}, errors.New("this proxy is set to require a password but none is stored; set one or turn the requirement off")
		}
		spec.username, spec.password = ProxyUser, held.Token
	}
	return spec, nil
}

// start binds the listener and serves both protocols on it.
//
// A configured port that is already taken falls back to an OS-assigned one rather than
// leaving the instance down: the caller persists whatever address came back, so the next
// start reuses it and every snippet naming it stays correct.
func (p *Instance) start(spec listenerSpec) error {
	raw, err := bind(spec.addr)
	if err != nil {
		return err
	}

	socksLn, httpLn := proxymux.SplitSOCKSAndHTTP(raw)
	ctx, cancel := context.WithCancel(context.Background())

	socksSrv := &socks5.Server{
		Logf:     func(format string, args ...any) { p.logger().Debug(fmt.Sprintf(format, args...)) },
		Dialer:   p.dial,
		Username: spec.username,
		Password: spec.password,
	}
	httpSrv := &http.Server{
		Handler:           p.httpHandler(spec),
		ReadHeaderTimeout: 30 * time.Second,
		// A CONNECT tunnel is hijacked out of the server, so this bounds only the header
		// exchange; a proxied request body is bounded by the dial timeout and by the peer.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	local, localPath, localErr := p.startLocal(httpSrv, socksSrv)
	if localErr != nil {
		// The port is the reachable half and it is already open. Refusing to run because
		// the socket beside it could not be created would take away a working proxy over a
		// second entrance most installs never use, so it is reported and the port stays up.
		p.logger().Warn("this proxy's local socket could not be created, so it is reachable on its port only",
			"error", localErr)
	}

	p.mu.Lock()
	p.raw, p.httpSrv, p.spec = raw, httpSrv, spec
	p.local, p.localPath = local, localPath
	p.tunnels, p.cancel = ctx, cancel
	p.bound = raw.Addr().String()
	p.mu.Unlock()

	p.wg.Add(2)
	go p.serve("SOCKS5", func() error { return socksSrv.Serve(socksLn) })
	go p.serve("HTTP", func() error { return httpSrv.Serve(httpLn) })

	p.logger().Info("proxy listening",
		"address", raw.Addr().String(), "socket", localPath, "requiresPassword", spec.authenticates())
	return nil
}

// startLocal opens this instance's socket beside its port and serves the same two
// protocols on it. An empty state directory means no socket was asked for.
//
// Who may connect is settled by the filesystem: the directory is 0700 and the socket 0600,
// both owned by the account running this app. That is the whole boundary here, unlike the
// privileged helper's socket, which checks the peer's identity as well because it runs as
// root and a mode on a root-owned socket can only choose between root and everybody.
func (p *Instance) startLocal(httpSrv *http.Server, socksSrv *socks5.Server) (net.Listener, string, error) {
	if p.set.stateDir == "" {
		return nil, "", nil
	}
	path := filepath.Join(p.set.stateDir, "proxies", p.held.Handle()+".sock")
	ln, err := listenLocal(path)
	if err != nil {
		return nil, "", err
	}
	if ln == nil {
		return nil, "", nil
	}

	socksLn, httpLn := proxymux.SplitSOCKSAndHTTP(ln)
	p.wg.Add(2)
	go p.serve("SOCKS5 on the local socket", func() error { return socksSrv.Serve(socksLn) })
	go p.serve("HTTP on the local socket", func() error { return httpSrv.Serve(httpLn) })
	return ln, path, nil
}

// serve runs one half of a split listener and reports why it stopped.
//
// Both halves end when the listener closes, so that is the ordinary stop and warning about
// it would put a line in the log on every clean shutdown. Anything else is a fault the
// operator has to see: the other half and the port both stay up, so the proxy goes on
// looking healthy while answering nothing on this protocol.
func (p *Instance) serve(protocol string, run func() error) {
	defer p.wg.Done()
	if err := run(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		p.logger().Warn("the proxy's listener stopped", "protocol", protocol, "error", err)
	}
}

// bind opens the configured address, falling back to an OS-assigned port on the same host
// when the configured one is taken.
func bind(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || port == "0" {
		return nil, fmt.Errorf("bind the proxy to %s: %w", addr, err)
	}
	fallback, fallbackErr := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if fallbackErr != nil {
		return nil, errors.Join(fmt.Errorf("bind the proxy to %s: %w", addr, err), fallbackErr)
	}
	return fallback, nil
}

// stop tears the listener down and waits for its goroutines. It is safe to call when
// nothing is running.
func (p *Instance) stop() {
	p.mu.Lock()
	raw, httpSrv, cancel := p.raw, p.httpSrv, p.cancel
	local, localPath := p.local, p.localPath
	p.raw, p.httpSrv, p.cancel, p.tunnels = nil, nil, nil, nil
	p.local, p.localPath = nil, ""
	p.spec = listenerSpec{}
	p.bound = ""
	p.mu.Unlock()

	if raw == nil && local == nil {
		return
	}

	if httpSrv != nil {
		ctx, done := context.WithTimeout(context.Background(), shutdownGrace)
		if err := httpSrv.Shutdown(ctx); err != nil {
			// Shutdown only reports that requests were still in flight when the grace ran
			// out. Closing below is what actually ends them.
			p.logger().Debug("the proxy's HTTP listener did not drain in time", "error", err)
		}
		done()
	}
	// Closing the raw listener is what unblocks both split halves; proxymux's own Close
	// does not reach it.
	if raw != nil {
		if err := raw.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.logger().Warn("closing the proxy listener failed", "error", err)
		}
	}
	if local != nil {
		if err := local.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.logger().Warn("closing the proxy's local socket failed", "error", err)
		}
		// A socket file outlives the listener that made it, so leaving it behind would make
		// the next start bind-fail on this instance's own leftover.
		removeLocal(localPath, p.logger())
	}
	if cancel != nil {
		// Tunnels are hijacked out of the HTTP server and survive its shutdown, so this is
		// what ends the ones still carrying traffic.
		cancel()
	}
	// SOCKS5 copies bytes on goroutines this package does not own, and closing the listener
	// does not reach a connection already accepted. Ending them here is what makes
	// switching an instance off take effect now rather than whenever each connection
	// happens to finish.
	if err := p.conns.closeAll(); err != nil {
		p.logger().Warn("ending the proxy's live connections failed", "error", err)
	}
	p.transport.CloseIdleConnections()
	p.wg.Wait()
	p.logger().Info("proxy stopped")
}

// Close stops this instance for good. Closing the listener and waiting out the connections
// it was carrying cannot fail, so there is nothing for a caller to handle.
func (p *Instance) Close() { p.stop() }

// current returns the configuration a dial is decided by.
func (p *Instance) current() Config {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live
}

func (p *Instance) recordErr(err error) error {
	p.mu.Lock()
	p.lastErr = err.Error()
	p.mu.Unlock()
	p.logger().Error("the proxy could not start", "error", err)
	return err
}

func (p *Instance) clearErr() {
	p.mu.Lock()
	p.lastErr = ""
	p.mu.Unlock()
}

// Status is one instance as the API and the dashboard see it.
type Status struct {
	// ID and Slug name which instance this is. Every other field is about that one
	// listener, so a report that did not name it would be unreadable the moment there is
	// more than one.
	ID   string
	Slug string
	Name string
	// Enabled reports the configured intent; Listening reports what is actually bound,
	// which is the pair that distinguishes "off" from "on but failed to bind".
	Enabled   bool
	Listening string
	// ModuleOn is the switch above this instance, and it is read only where Enabled is
	// false: an instance is off either because the module is or because its own switch is,
	// and Enabled folds the two together. Whoever fills Enabled fills this too.
	ModuleOn bool
	// LocalSocket is the path of the socket beside the port, or empty when there is none.
	LocalSocket string
	// NetworksUp says whether dials would currently succeed. The port stays bound either
	// way, so this is the difference between a refusal that will clear itself and one that
	// will not.
	NetworksUp bool
	// Scope is what this instance's rules amount to in one word, for the surfaces that
	// have room for a word rather than a table.
	Scope         config.ProxyScope
	ResolveVia    config.ProxyResolveVia
	RequiresToken bool
	Error         string
	Counters      Counters
	// Rules is how many rules decide what this instance carries. Zero is the state worth
	// showing plainly: an instance with no rules reaches nothing.
	Rules           int
	ConfiguredAddr  string
	MovedFromConfig bool
}

// Status reports this instance's live state.
func (p *Instance) Status() Status {
	p.mu.Lock()
	bound, lastErr, spec := p.bound, p.lastErr, p.spec
	held, live, localPath := p.held, p.live, p.localPath
	p.mu.Unlock()

	configured := held.ListenAddress()
	if bound != "" {
		// What this listener was asked for, not what the setting says now. A moved port is
		// persisted back to where it landed, so reading the setting here would compare the
		// address against itself and erase the move it just recorded -- taking with it the
		// one message that explains why every snippet a user already saved names the wrong
		// port.
		configured = spec.addr
	}
	return Status{
		ID:      held.ID,
		Slug:    held.Handle(),
		Name:    held.Name,
		Enabled: held.Enabled,
		// A listener only exists inside a running module: the reconcile drops every
		// instance while the module switch is off.
		ModuleOn:      true,
		Listening:     bound,
		LocalSocket:   localPath,
		NetworksUp:    p.set.up.Load(),
		Scope:         config.DerivedProxyScope(live.Rules),
		ResolveVia:    held.EffectiveResolveVia(),
		RequiresToken: spec.authenticates(),
		Error:         lastErr,
		Counters:      p.countersOf(),
		Rules:         len(live.Rules),
		// A port conflict moves the listener. Saying so is what explains a snippet that
		// names one port and a dashboard that reports another.
		ConfiguredAddr:  configured,
		MovedFromConfig: movedFrom(configured, bound),
	}
}

// movedFrom reports that the listener is not where the configuration asked for it.
//
// A configured port of zero asked for whichever port was free, so landing on one is not a
// move. Counting it as one would put a permanent warning on a deliberate choice and, worse,
// make the caller persist the bound address -- which changes the configuration on the next
// reconcile and rebinds the listener under live connections.
func movedFrom(configured, bound string) bool {
	if bound == "" || bound == configured {
		return false
	}
	_, port, err := net.SplitHostPort(configured)
	if err != nil || port == "0" {
		return false
	}
	return true
}

// Addr returns where this instance is bound, or "" when it is not.
func (p *Instance) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bound
}
