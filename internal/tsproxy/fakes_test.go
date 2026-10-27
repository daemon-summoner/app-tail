// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// officeTunnel is the one stand-in connection these tests dial through. Its id is what the
// rules name, so a grant written against it is the same shape a real one has.
const officeTunnel = "tn_office"

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeNetwork is the set of connections a proxy dials through: a real tunnel.Registry
// holding one stand-in connection, plus this machine's own network.
//
// It is built on the production registry rather than on a hand-written Network so the
// routing decision under test is the one that ships. Destinations registered with route
// are carried by the connection; destinations registered with expose resolve but are
// carried by nothing, which is what a destination on this machine looks like.
type fakeNetwork struct {
	*tunnel.Registry
	office *fakeTunnel

	// dials is what was dialled and under whose deadline, whichever network carried it.
	// Both halves record into one log because a test asks "what was dialled", not "which
	// code path dialled it".
	dials dialLog

	mu sync.Mutex
	// carries maps a destination the connection carries to the loopback address standing
	// in for the peer inside it.
	carries map[string]netip.AddrPort
	// public maps a destination this machine resolves but no connection carries.
	public map[string]netip.AddrPort
	// dns is what the connection's own resolver answers, keyed by name.
	dns map[string]netip.Addr
	// reachErr, when set, is what the connection fails to classify with.
	reachErr error
	// dnsErr, when set, is what its resolver fails with.
	dnsErr   error
	lookups  int
	lookedUp []string
	// throughTunnel counts the dials the connection itself made. The dial log records both
	// paths together, so it is the only way to tell a destination that left through the
	// connection from one that left through this machine.
	throughTunnel int
}

func newFakeNetwork(t *testing.T) *fakeNetwork {
	t.Helper()
	f := &fakeNetwork{
		Registry: tunnel.NewRegistry(),
		carries:  make(map[string]netip.AddrPort),
		public:   make(map[string]netip.AddrPort),
	}
	f.office = &fakeTunnel{stubTunnel: stubTunnel{id: officeTunnel}, net: f}
	if err := f.Registry.Add(f.office); err != nil {
		t.Fatalf("register the stand-in connection: %v", err)
	}
	f.Registry.SetHostResolver(f.resolveHere)
	return f
}

// route makes address reachable over the connection, standing in for the peer with a real
// loopback server that echoes what it is sent.
func (f *fakeNetwork) route(t *testing.T, address string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.carries[address] = echoServer(t)
}

// routeLiteral makes a real loopback server reachable over the connection under its own
// address, and answers with that address.
//
// It is what a test uses to pin a rule about a port: route() stands a peer in behind a name,
// so the address the rules are matched against carries whichever port the OS handed the
// stand-in rather than the one the destination named.
func (f *fakeNetwork) routeLiteral(t *testing.T) netip.AddrPort {
	t.Helper()
	addr := echoServer(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.carries[addr.String()] = addr
	return addr
}

// expose makes address resolvable on this machine and carried by no connection, which is
// what a destination outside every private network looks like to the rules.
func (f *fakeNetwork) expose(t *testing.T, address string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.public[address] = echoServer(t)
}

// serveHTTP registers a real HTTP server as a destination on this machine, for the paths
// where what is proxied has to be an actual request and response rather than bytes.
func (f *fakeNetwork) serveHTTP(t *testing.T, address, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	addr, err := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("parse the stand-in server's address: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.public[address] = addr
}

// resolveAs makes host resolve through the connection's own resolver, the way a domain a
// private nameserver answers for resolves only there.
func (f *fakeNetwork) resolveAs(host string, addr netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dns == nil {
		f.dns = make(map[string]netip.Addr)
	}
	f.dns[host] = addr
}

// resolveHere is this machine's own resolver: the exposed destinations, and an address
// literal answered as it stands.
func (f *fakeNetwork) resolveHere(_ context.Context, _, address string) (netip.AddrPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if addr, ok := f.public[address]; ok {
		return addr, nil
	}
	if addr, err := netip.ParseAddrPort(address); err == nil {
		return addr, nil
	}
	return netip.AddrPort{}, fmt.Errorf("no such host: %s", address)
}

// dialDirect stands in for this machine's network, recording what left through it.
func (f *fakeNetwork) dialDirect(ctx context.Context, network, address string) (net.Conn, error) {
	f.dials.record(ctx, address)
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// dialledAddresses is every address dialled, through the connection or through this
// machine.
func (f *fakeNetwork) dialledAddresses() []string { return f.dials.addresses() }

// lastDeadline is how far out the most recent dial's context deadline was, which is the
// only way to observe whose timeout is actually in force.
func (f *fakeNetwork) lastDeadline(t *testing.T) time.Duration {
	t.Helper()
	return f.dials.last(t)
}

// dialsThroughTheConnection is how many dials the connection itself made, as opposed to
// this machine's own network.
func (f *fakeNetwork) dialsThroughTheConnection() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.throughTunnel
}

// lookupCount is how many times the connection's own resolver has been asked anything.
func (f *fakeNetwork) lookupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups
}

// fakeTunnel is one connection standing in for a private network. It answers where a
// destination is from its own table and dials the loopback server behind it, so the
// proxy's whole path runs over real sockets with no network.
type fakeTunnel struct {
	stubTunnel
	net *fakeNetwork
}

var (
	_ tunnel.Tunnel    = (*fakeTunnel)(nil)
	_ tunnel.Reaching  = (*fakeTunnel)(nil)
	_ tunnel.Resolving = (*fakeTunnel)(nil)
)

func (f *fakeTunnel) Reach(_ context.Context, _, address string) (tunnel.Reach, error) {
	f.net.mu.Lock()
	defer f.net.mu.Unlock()
	if f.net.reachErr != nil {
		return tunnel.Reach{}, f.net.reachErr
	}
	if addr, ok := f.net.carries[address]; ok {
		return tunnel.Reach{Addr: addr, Carried: true}, nil
	}
	return tunnel.Reach{}, nil
}

// LookupHost answers as the connection's own resolver. A name it does not carry comes back
// served by nothing, which is the answer the caller falls back from.
func (f *fakeTunnel) LookupHost(_ context.Context, host string) (tunnel.Lookup, error) {
	f.net.mu.Lock()
	defer f.net.mu.Unlock()
	f.net.lookups++
	f.net.lookedUp = append(f.net.lookedUp, host)
	if f.net.dnsErr != nil {
		return tunnel.Lookup{}, f.net.dnsErr
	}
	addr, ok := f.net.dns[host]
	if !ok {
		return tunnel.Lookup{}, nil
	}
	return tunnel.Lookup{Addrs: []netip.Addr{addr}, TTL: time.Minute}, nil
}

func (f *fakeTunnel) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.net.mu.Lock()
	f.net.throughTunnel++
	f.net.mu.Unlock()
	f.net.dials.record(ctx, address)
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// stubTunnel carries the parts of the interface these tests never exercise, so a stand-in
// connection is only the two or three methods it is actually about.
type stubTunnel struct{ id string }

func (s stubTunnel) Listen(string, uint16) (net.Listener, error) {
	return nil, errors.New("not listened on in these tests")
}

func (s stubTunnel) ListenPacket(string, uint16) (net.PacketConn, error) {
	return nil, errors.New("not listened on in these tests")
}

func (s stubTunnel) ID() string                  { return s.id }
func (s stubTunnel) Kind() tunnel.Kind           { return tunnel.KindTailscale }
func (s stubTunnel) Start(context.Context) error { return nil }
func (s stubTunnel) Close() error                { return nil }
func (s stubTunnel) Status() tunnel.Status       { return tunnel.Status{State: tunnel.StateConnected} }
func (s stubTunnel) Events() <-chan struct{}     { return nil }
func (s stubTunnel) Routes(context.Context) ([]netip.Prefix, error) {
	return nil, nil
}
func (s stubTunnel) Addrs() []netip.Addr { return nil }

// dialLog records what was dialled and under whose deadline.
type dialLog struct {
	mu        sync.Mutex
	addrs     []string
	deadlines []time.Duration
}

func (l *dialLog) record(ctx context.Context, address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addrs = append(l.addrs, address)
	if deadline, ok := ctx.Deadline(); ok {
		l.deadlines = append(l.deadlines, time.Until(deadline))
	} else {
		l.deadlines = append(l.deadlines, 0)
	}
}

func (l *dialLog) addresses() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.addrs...)
}

func (l *dialLog) last(t *testing.T) time.Duration {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.deadlines) == 0 {
		t.Fatal("nothing was dialed, so there is no deadline to inspect")
	}
	return l.deadlines[len(l.deadlines)-1]
}

// echoServer runs a loopback TCP server that echoes every byte back, so a proxied
// connection can be proven to carry traffic rather than merely to have been accepted.
func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start the stand-in peer: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse the stand-in peer's address: %v", err)
	}
	return addr
}

// reachTheConnection is the grant that carries everything on the stand-in connection and
// nothing else -- the narrow reach every one of these proxies starts with.
func reachTheConnection() []access.Rule {
	return []access.Rule{{ID: "ar_connection", Action: access.Allow, Tunnel: officeTunnel}}
}

// reachThisMachineToo adds the second grant: destinations that leave through this machine's
// own network. The two are separate rules because they are separately revocable, which is
// the whole reason the old two-valued scope became a list.
func reachThisMachineToo() []access.Rule {
	return append(reachTheConnection(), access.Rule{
		ID: "ar_this_machine", Action: access.Allow, Tunnel: access.ThisMachine,
	})
}

// proxyBox is one stored instance and the set running it, so a test can edit the
// configuration and reconcile it the way the agent does.
type proxyBox struct {
	set  *Set
	held config.ProxyInstance
}

// newProxyBox builds a set over net with one instance in it. Nothing binds until apply
// runs.
func newProxyBox(hub Network, overrides ...func(*config.ProxyInstance)) *proxyBox {
	return newProxyBoxWith(Options{Network: hub, Logger: quietLogger()}, overrides...)
}

// newProxyBoxWith is the same for the tests that need the set built differently -- a clock
// they drive, a logger they read back, a stand-in for this machine's own network.
func newProxyBoxWith(opts Options, overrides ...func(*config.ProxyInstance)) *proxyBox {
	if opts.Logger == nil {
		opts.Logger = quietLogger()
	}
	if fake, ok := opts.Network.(*fakeNetwork); ok && opts.DialDirect == nil {
		opts.DialDirect = fake.dialDirect
	}
	held := config.ProxyInstance{
		ID:         config.DefaultProxyID,
		Slug:       config.DefaultProxySlug,
		Name:       "Default",
		Enabled:    true,
		ListenAddr: "127.0.0.1:0",
		Rules:      reachTheConnection(),
	}
	for _, o := range overrides {
		o(&held)
	}
	box := &proxyBox{set: NewSet(opts), held: held}
	box.set.SetNetworksUp(true)
	return box
}

// set edits the stored instance. Nothing takes effect until apply runs, which is the same
// order the agent does it in: the document is written, then reconciled.
func (b *proxyBox) edit(change func(*config.ProxyInstance)) {
	change(&b.held)
}

// apply reconciles the set with the stored instance and returns what went wrong, for the
// tests that are about the failure.
func (b *proxyBox) apply() error {
	return b.set.Apply([]config.ProxyInstance{b.held})
}

// mustApply reconciles and fails the test if anything refused to bind.
func (b *proxyBox) mustApply(t *testing.T) {
	t.Helper()
	if err := b.apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// instance is the running instance, or nil when the stored one is switched off.
func (b *proxyBox) instance() *Instance {
	inst, _ := b.set.Get(b.held.ID)
	return inst
}

// addr is where the instance is bound, or "" when nothing is.
func (b *proxyBox) addr() string {
	inst := b.instance()
	if inst == nil {
		return ""
	}
	return inst.Addr()
}

// status is the instance as the API sees it. A switched-off instance has none, so the
// zero value stands in -- which is what "off" reads as everywhere else.
func (b *proxyBox) status() Status {
	inst := b.instance()
	if inst == nil {
		return Status{}
	}
	return inst.Status()
}

// startProxy builds a set over net, applies the instance once, and tears it down with the
// test.
func startProxy(t *testing.T, hub Network, overrides ...func(*config.ProxyInstance)) (*Instance, *proxyBox) {
	t.Helper()
	box := newProxyBox(hub, overrides...)
	t.Cleanup(box.set.Close)
	box.mustApply(t)
	inst := box.instance()
	if inst == nil {
		t.Fatal("the instance is not running after a successful apply")
	}
	return inst, box
}

// bareInstance is an instance that has never bound anything, for the tests that drive its
// listener plumbing by hand -- serving a listener they made themselves, or tearing one
// down. Going through apply would put a real listener underneath and hide the very state
// those tests are about.
func bareInstance(t *testing.T, logger *slog.Logger) *Instance {
	t.Helper()
	set := NewSet(Options{Network: newFakeNetwork(t), Logger: logger})
	t.Cleanup(set.Close)
	return newInstance(set, config.ProxyInstance{
		ID:      config.DefaultProxyID,
		Slug:    config.DefaultProxySlug,
		Name:    "Default",
		Enabled: true,
	})
}

// capturedLogs is a log destination a test can read back while a proxy goroutine is
// still writing to it.
type capturedLogs struct {
	mu  sync.Mutex
	buf []byte
}

func (c *capturedLogs) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *capturedLogs) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}

func capturingLogger() (*slog.Logger, *capturedLogs) {
	logs := &capturedLogs{}
	return slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), logs
}

// stuckListener accepts nothing and refuses to close cleanly, which is what a listener
// whose file descriptor has already gone does. It is the only way to reach the paths
// that decide whether a listener ending is a fault or the ordinary shutdown.
type stuckListener struct {
	closeErr error
	closed   chan struct{}
	// accepting closes once the server has taken this listener, which is the point
	// after which a shutdown can find it.
	accepting  chan struct{}
	acceptOnce sync.Once
	once       sync.Once
}

func newStuckListener(closeErr error) *stuckListener {
	return &stuckListener{closeErr: closeErr, closed: make(chan struct{}), accepting: make(chan struct{})}
}

func (l *stuckListener) Accept() (net.Conn, error) {
	l.acceptOnce.Do(func() { close(l.accepting) })
	<-l.closed
	return nil, net.ErrClosed
}

func (l *stuckListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.closeErr
}

func (l *stuckListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}
