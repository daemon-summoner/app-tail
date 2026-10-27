// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// --- accept-loop fakes ----------------------------------------------------

// The accept loop treats a net.Error reporting Timeout as transient; timeoutErr from
// dialerr_test.go is exactly that shape, so it stands in for a socket deadline here too.
var _ net.Error = timeoutErr{}

// scriptedListener replays a fixed sequence of Accept outcomes so the accept loop's
// retry and give-up branches can be driven without a listener that really dies. Once the
// script is spent it blocks until Close, the way a healthy idle listener does.
type scriptedListener struct {
	mu      sync.Mutex
	script  []error
	next    int
	closed  chan struct{}
	once    sync.Once
	accepts atomic.Int32
}

func newScriptedListener(script ...error) *scriptedListener {
	return &scriptedListener{script: script, closed: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	l.mu.Lock()
	if l.next < len(l.script) {
		err := l.script[l.next]
		l.next++
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()

	<-l.closed
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

// acceptCount reports how many times the loop asked for a connection, which is how a
// test tells a throttled retry from a spin.
func (l *scriptedListener) acceptCount() int { return int(l.accepts.Load()) }

var _ net.Listener = (*scriptedListener)(nil)

// --- UDP fakes ------------------------------------------------------------

// failingWriteConn delivers datagrams inbound but refuses to send replies, which is what
// a client that vanished mid-conversation looks like to the reply pump.
type failingWriteConn struct {
	net.PacketConn
	err error
}

func (c failingWriteConn) WriteTo([]byte, net.Addr) (int, error) { return 0, c.err }

// failingUpstream is a target socket that accepts the dial and then refuses every
// datagram, which is what a target that went away between dial and send looks like.
// Read blocks until Close so the session's reply pump behaves like a live one.
type failingUpstream struct {
	net.Conn
	err    error
	closed chan struct{}
	once   sync.Once
}

func newFailingUpstream(err error) *failingUpstream {
	return &failingUpstream{err: err, closed: make(chan struct{})}
}

func (c *failingUpstream) Write([]byte) (int, error) { return 0, c.err }

func (c *failingUpstream) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *failingUpstream) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *failingUpstream) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func (c *failingUpstream) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}

func (c *failingUpstream) SetDeadline(time.Time) error      { return nil }
func (c *failingUpstream) SetReadDeadline(time.Time) error  { return nil }
func (c *failingUpstream) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*failingUpstream)(nil)

// refusingTailnet dials successfully and hands back a socket that refuses to send.
type refusingTailnet struct {
	*fakeTailnet
	err error
}

func (r *refusingTailnet) Dial(context.Context, string, string) (net.Conn, error) {
	return newFailingUpstream(r.err), nil
}

var _ Tailnet = (*refusingTailnet)(nil)

// countingConn reports when it is closed, so a socket leaked by a lost race is
// observable rather than merely suspected.
type countingConn struct {
	net.Conn
	closed *atomic.Int32
	once   sync.Once
}

func (c *countingConn) Close() error {
	c.once.Do(func() { c.closed.Add(1) })
	return c.Conn.Close()
}

// gatedTailnet holds every dial open until released and counts the sockets handed out
// and closed. It is what makes the duplicate-dial race deterministic: two datagrams from
// one client can be parked mid-dial, released together, and the loser's socket proven
// closed rather than leaked.
type gatedTailnet struct {
	*fakeTailnet
	gate        chan struct{}
	releaseOnce sync.Once
	parked      atomic.Int32
	opened      atomic.Int32
	closed      atomic.Int32
}

func newGatedTailnet(gated bool) *gatedTailnet {
	g := &gatedTailnet{fakeTailnet: newFakeTailnet()}
	if gated {
		g.gate = make(chan struct{})
	}
	return g
}

// release lets every parked dial proceed. The channel is closed rather than cleared:
// a Dial reading the field concurrently would otherwise race the write.
func (g *gatedTailnet) release() {
	if g.gate != nil {
		g.releaseOnce.Do(func() { close(g.gate) })
	}
}

// parkedDials reports how many dials are waiting at the gate, which is what makes
// "every racer has reached the dial" a wait rather than a sleep.
func (g *gatedTailnet) parkedDials() int { return int(g.parked.Load()) }

func (g *gatedTailnet) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if gate := g.gate; gate != nil {
		g.parked.Add(1)
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	conn, err := g.fakeTailnet.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	g.opened.Add(1)
	return &countingConn{Conn: conn, closed: &g.closed}, nil
}

var _ Tailnet = (*gatedTailnet)(nil)

// --- direct UDP forward construction --------------------------------------

// udpHarness is a UDP forward built straight over a loopback socket rather than through
// the manager's reconcile path. Several read-loop and reply-pump failure branches are
// only reachable at moments a manager-owned forward races past.
type udpHarness struct {
	uf     *udpForward
	entry  *entry
	addr   string
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// newUDPForward starts a UDP forward over local, or over a fresh loopback socket when
// local is nil. The read loop and janitor run exactly as startUDP would run them.
func newUDPForward(t *testing.T, m *Manager, f config.Forward, local net.PacketConn) *udpHarness {
	t.Helper()

	if local == nil {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("bind udp forward socket: %v", err)
		}
		local = pc
	}

	// The network is resolved the way a started forward's is, because that is where the
	// session dials through: an entry without it is one the manager could never produce.
	tn, carrying := m.nets.Tailnet(f.Connection())
	if !carrying {
		t.Fatalf("connection %q is not carrying, so this forward could not have started", f.Connection())
	}
	e := &entry{fwd: f, counters: newCounters(), net: tn}
	uf := &udpForward{
		mgr:      m,
		entry:    e,
		fwd:      f,
		local:    local,
		timeout:  m.udpTimeout(f),
		bufSize:  m.bufferSize(),
		sessions: make(map[string]*session),
	}
	e.counters.setRunning(local.LocalAddr().String())

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		uf.readLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		uf.janitor(ctx)
	}()

	h := &udpHarness{uf: uf, entry: e, addr: local.LocalAddr().String(), cancel: cancel, wg: wg}
	t.Cleanup(func() { h.stop() })
	return h
}

// stop cancels the forward and waits for its goroutines, so a test cannot leak one into
// the next.
func (h *udpHarness) stop() {
	h.cancel()
	h.uf.local.Close()
	h.wg.Wait()
}

// status is the forward's live snapshot under the id it was built with.
func (h *udpHarness) status() Status { return h.entry.counters.snapshot(h.uf.fwd.ID) }

// sessionCount reports the size of the live session table.
func (h *udpHarness) sessionCount() int {
	h.uf.mu.Lock()
	defer h.uf.mu.Unlock()
	return len(h.uf.sessions)
}

// anySession returns the one live session, failing if the table does not hold exactly
// one. Tests that reach into a session need to know which one they got.
func (h *udpHarness) anySession(t *testing.T) *session {
	t.Helper()
	h.uf.mu.Lock()
	defer h.uf.mu.Unlock()
	if len(h.uf.sessions) != 1 {
		t.Fatalf("session table holds %d entries, want exactly 1", len(h.uf.sessions))
	}
	for _, s := range h.uf.sessions {
		return s
	}
	return nil
}

// waitFor polls until cond holds, so no test has to guess at a sleep duration.
func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}
