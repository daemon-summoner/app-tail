// SPDX-License-Identifier: MIT

package subnets

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

func mustPrefixes(t *testing.T, in ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse the test prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// fakeTailnet stands in for the node: what the tailnet has approved this device to
// carry, and the hook the router installs to receive flows.
type fakeTailnet struct {
	mu sync.Mutex
	// approved is what an admin has approved, which is deliberately not the same thing
	// as what the settings advertise.
	approved []netip.Prefix
	// approvedErr, when set, is what reading the approved set fails with.
	approvedErr error
	// reads counts how many times the approved set was read, which is what proves an
	// answer was reused rather than fetched per connection.
	reads int
	// serveErr, when set, is what installing the hook fails with.
	serveErr error
	handler  func(src, dst netip.AddrPort) func(net.Conn)
	stops    int
	installs int
}

func newFakeTailnet(approved ...netip.Prefix) *fakeTailnet {
	return &fakeTailnet{approved: approved}
}

func (f *fakeTailnet) ApprovedRoutes(context.Context) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.approvedErr != nil {
		return nil, f.approvedErr
	}
	return append([]netip.Prefix(nil), f.approved...), nil
}

func (f *fakeTailnet) ServeSubnets(h func(src, dst netip.AddrPort) func(net.Conn)) (func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.serveErr != nil {
		return nil, f.serveErr
	}
	f.handler = h
	f.installs++
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.handler = nil
		f.stops++
	}, nil
}

// approve replaces the approved set, standing in for an admin approving a route while
// the app is running.
func (f *fakeTailnet) approve(prefixes ...netip.Prefix) {
	f.mu.Lock()
	f.approved = prefixes
	f.mu.Unlock()
}

// deliver hands the installed handler one flow, the way the tailnet's network stack
// would, and reports whether it was accepted.
func (f *fakeTailnet) deliver(t *testing.T, dst netip.AddrPort) (func(net.Conn), bool) {
	t.Helper()
	f.mu.Lock()
	h := f.handler
	f.mu.Unlock()
	if h == nil {
		t.Fatal("no subnet handler is installed, so no flow could be delivered")
	}
	carry := h(netip.MustParseAddrPort("100.64.0.9:41000"), dst)
	return carry, carry != nil
}

func (f *fakeTailnet) installed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.handler != nil
}

func (f *fakeTailnet) counts() (installs, stops, reads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installs, f.stops, f.reads
}

// settingsBox holds what a router reads, so a test changes it between reconciles the way
// the agent does.
//
// It keeps the connection and the module switch apart and hands the router the resolved
// answer, because that is the shape the agent has: a preference is the connection's and the
// switch is the installation's, and the router is given what the two come to rather than
// deciding it for itself.
type settingsBox struct {
	mu     sync.Mutex
	app    config.Settings
	tunnel config.Tunnel
}

func newSettings(overrides ...func(*config.Settings, *config.TailnetPrefs)) *settingsBox {
	app := config.Settings{RoutesEnabled: true}
	prefs := config.TailnetPrefs{RoutesServe: true}
	for _, apply := range overrides {
		apply(&app, &prefs)
	}
	held := config.Tunnel{
		ID: config.PrimaryTunnelID, Slug: "tailnet", Name: "Tailnet",
		Type: config.TunnelTailscale, Enabled: true,
		Tailscale: &config.TailscaleTunnel{TailnetPrefs: prefs},
	}
	return &settingsBox{app: app, tunnel: held}
}

func (b *settingsBox) get() config.TailnetPrefs {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.app.TailnetPrefsOf(b.tunnel)
}

func (b *settingsBox) set(apply func(*config.Settings, *config.TailnetPrefs)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ts := b.tunnel.TS()
	apply(&b.app, &ts.TailnetPrefs)
	b.tunnel.Tailscale = &ts
}

// clock is a hand-driven time source, so a test drives the approved-set cache expiring
// rather than waiting it out.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// harness is a router wired to stand-ins for everything outside it.
type harness struct {
	router   *Router
	tailnet  *fakeTailnet
	settings *settingsBox
	clock    *clock
	// dialed records every address the router dialed out to, in order.
	dialed []string
	// dialErr, when set, is what dialing a destination fails with.
	dialErr error
	mu      sync.Mutex
	// destination is the stand-in host on the routed network. Every dial reaches it,
	// whatever address was asked for, because what is being tested is the policy that
	// decides whether to dial at all.
	destination netip.AddrPort
	// logs is what the router wrote. A refused flow leaves no other trace -- the status
	// carries a count and nothing else -- so the line naming the reason is the whole
	// diagnosis a user gets, and the only place it can be read from.
	logs *lines
}

// lines is a log destination a test can read back, safe for the tailnet stack's own
// goroutines to write to while the test reads.
type lines struct {
	mu  sync.Mutex
	buf []byte
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	return len(p), nil
}

func (l *lines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.buf)
}

func newHarness(t *testing.T, tn *fakeTailnet, box *settingsBox) *harness {
	t.Helper()
	h := &harness{
		tailnet:     tn,
		settings:    box,
		clock:       newClock(),
		destination: echoServer(t),
		logs:        &lines{},
	}
	// At debug level: the reasons a carried connection ended badly are logged there and
	// nowhere else, and they are the only diagnosis a user gets for a route that is
	// installed and approved and still not working.
	h.router = New(tn, box.get, slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	h.router.now = h.clock.get
	h.router.dial = h.dial
	h.router.SetNodeUp(true)
	t.Cleanup(h.router.Close)
	return h
}

func (h *harness) dial(ctx context.Context, network, address string) (net.Conn, error) {
	h.mu.Lock()
	h.dialed = append(h.dialed, address)
	err := h.dialErr
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, h.destination.String())
}

func (h *harness) dials() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dialed...)
}

func (h *harness) failDials(err error) {
	h.mu.Lock()
	h.dialErr = err
	h.mu.Unlock()
}

// apply reconciles the router and fails the test if it could not.
func (h *harness) apply(t *testing.T) {
	t.Helper()
	if err := h.router.Apply(); err != nil {
		t.Fatalf("reconcile the subnet router: %v", err)
	}
}

// carry delivers one flow and runs it to completion against the stand-in destination,
// returning what came back. It fails the test if the flow was refused.
func (h *harness) carry(t *testing.T, dst netip.AddrPort, send string) string {
	t.Helper()
	handle, ok := h.tailnet.deliver(t, dst)
	if !ok {
		t.Fatalf("the flow to %s was refused, but this test needs it carried", dst)
	}

	peer, far := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(far)
	}()

	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set the test connection's deadline: %v", err)
	}
	if _, err := io.WriteString(peer, send); err != nil {
		t.Fatalf("write to the carried connection: %v", err)
	}
	buf := make([]byte, len(send))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("read back from the carried connection: %v", err)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("close the test connection: %v", err)
	}
	<-done
	return string(buf)
}

// faultyConn is the end the router is handed, with a Read or a Close that fails. A
// tailnet flow that died mid-transfer, or one the stack already tore down, arrives here
// behaving exactly like this, and the router's log line is the only trace either leaves.
type faultyConn struct {
	net.Conn
	readErr  error
	closeErr error
}

func (c faultyConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(p)
}

func (c faultyConn) Close() error {
	if c.closeErr != nil {
		return c.closeErr
	}
	return c.Conn.Close()
}

// readablePipe is a peer's connection and the end the router is handed, with a deadline
// on the test's side so a read that should have failed cannot hang the suite instead.
func readablePipe(t *testing.T) (peer, far net.Conn) {
	t.Helper()
	peer, far = net.Pipe()
	t.Cleanup(func() { peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set the test connection's deadline: %v", err)
	}
	return peer, far
}

// echoServer is a real host on the routed network, which sends back what it is sent.
func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start the stand-in host: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close the stand-in host: %v", err)
		}
	})

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
		t.Fatalf("parse the stand-in host's address: %v", err)
	}
	return addr
}
