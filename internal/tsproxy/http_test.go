// SPDX-License-Identifier: MIT

package tsproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// A CONNECT tunnel is two connections stitched together, and every failure between
// opening the peer's and handing back the client's is a place the peer's can be dropped
// on the floor. A leaked one holds a netstack endpoint open for as long as the agent
// runs, so these paths are exercised directly: net/http's own server never produces
// them, which is exactly why nothing else would catch a leak here.

// scriptedConn is a connection whose two halves a test decides. net.Pipe covers the
// working direction but not the ones this file exists to reach: a write that fails is
// what a peer disappearing mid-handshake looks like from this side.
type scriptedConn struct {
	mu       sync.Mutex
	readable bytes.Reader
	written  bytes.Buffer
	writeErr error
	closeErr error
	closes   int
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readable.Read(b)
}

func (c *scriptedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.written.Write(b)
}

func (c *scriptedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	return c.closeErr
}

func (c *scriptedConn) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes > 0
}

func (c *scriptedConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *scriptedConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:1" }

// scriptedTunnel carries every destination and hands back the one connection the test is
// watching, so what happens to the peer's connection after a failure is observable.
type scriptedTunnel struct {
	stubTunnel
	mu      sync.Mutex
	conn    *scriptedConn
	queue   []*scriptedConn
	dialErr error
}

var (
	_ tunnel.Tunnel   = (*scriptedTunnel)(nil)
	_ tunnel.Reaching = (*scriptedTunnel)(nil)
)

func (s *scriptedTunnel) Reach(context.Context, string, string) (tunnel.Reach, error) {
	return tunnel.Reach{Addr: netip.MustParseAddrPort("100.64.0.9:443"), Carried: true}, nil
}

func (s *scriptedTunnel) Dial(context.Context, string, string) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dialErr != nil {
		return nil, s.dialErr
	}
	if len(s.queue) > 0 {
		next := s.queue[0]
		s.queue = s.queue[1:]
		return next, nil
	}
	return s.conn, nil
}

// scriptedNetwork is a registry holding that one connection, so the routing decision these
// tests run through is the production one.
func scriptedNetwork(t *testing.T, tun *scriptedTunnel) Network {
	t.Helper()
	reg := tunnel.NewRegistry()
	if err := reg.Add(tun); err != nil {
		t.Fatalf("register the scripted connection: %v", err)
	}
	return reg
}

// hijackWriter takes over a connection the way net/http's writer does, with the two
// outcomes a test cannot otherwise produce: refusing to hand one over, and handing over
// one whose writes fail.
type hijackWriter struct {
	*httptest.ResponseRecorder
	err      error
	client   *scriptedConn
	buffered string
}

func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.err != nil {
		return nil, nil, h.err
	}
	reader := bufio.NewReader(io.MultiReader(strings.NewReader(h.buffered), h.client))
	if h.buffered != "" {
		// Fill the reader so the bytes read it as pipelined behind the request line,
		// which is where a TLS ClientHello actually sits.
		if _, err := reader.Peek(len(h.buffered)); err != nil {
			return nil, nil, err
		}
	}
	return h.client, bufio.NewReadWriter(reader, bufio.NewWriter(h.client)), nil
}

func connectTo(target string) *http.Request {
	req := httptest.NewRequest(http.MethodConnect, "http://"+target, nil)
	// A real CONNECT carries the destination in authority form -- "CONNECT peer:443" -- and
	// net/http puts it in Host, which is what every path here reads. httptest builds an
	// absolute URL instead, leaving Host as "http:", so it is set to what a server would see.
	req.Host = target
	req.URL = &url.URL{Host: target}
	return req
}

// tunnelProxy is an instance whose peer connection is the scripted one. These paths are
// reached by calling the handler, so it is bound but never dialled through.
func tunnelProxy(t *testing.T, peer *scriptedConn) *Instance {
	t.Helper()
	tun := &scriptedTunnel{stubTunnel: stubTunnel{id: officeTunnel}, conn: peer}
	p, _ := startProxy(t, scriptedNetwork(t, tun))
	return p
}

// A response writer that cannot be taken over would turn the tunnel into an ordinary
// response, and the client's next bytes -- a TLS ClientHello -- would be read as a second
// HTTP request. Refusing loudly is the only outcome that does not corrupt the exchange.
func TestATunnelThatCannotTakeOverTheConnectionIsRefusedRatherThanAnswered(t *testing.T) {
	peer := &scriptedConn{}
	p := tunnelProxy(t, peer)

	rec := httptest.NewRecorder()
	p.serveConnect(rec, connectTo("peer:443"))

	if rec.Code == http.StatusOK {
		t.Fatal("a tunnel was reported established on a connection nothing can take over")
	}
	if got := rec.Header().Get(ConnectErrorHeader); got == "" {
		t.Error("the refusal carries no reason, which is all a browser ever shows")
	}
	if !peer.closed() {
		t.Error("the peer connection was left open after the tunnel was refused")
	}
}

// Each of these fails after the peer has already been dialed, which is what makes them
// worth pinning: the request is over either way, and the only difference a leak makes is
// a netstack endpoint that stays open until the agent exits.
func TestAFailedTunnelNeverLeavesThePeerConnectionOpen(t *testing.T) {
	tests := []struct {
		name   string
		writer func(*scriptedConn) *hijackWriter
	}{
		{
			name: "the connection cannot be handed over",
			writer: func(*scriptedConn) *hijackWriter {
				return &hijackWriter{
					ResponseRecorder: httptest.NewRecorder(),
					err:              errors.New("the connection was already taken"),
				}
			},
		},
		{
			name: "the client is gone before the tunnel is confirmed",
			writer: func(*scriptedConn) *hijackWriter {
				return &hijackWriter{
					ResponseRecorder: httptest.NewRecorder(),
					client:           &scriptedConn{writeErr: errors.New("broken pipe")},
				}
			},
		},
		{
			name: "the peer is gone before the pipelined bytes reach it",
			writer: func(peer *scriptedConn) *hijackWriter {
				peer.writeErr = errors.New("connection reset by peer")
				return &hijackWriter{
					ResponseRecorder: httptest.NewRecorder(),
					client:           &scriptedConn{},
					buffered:         "the client hello",
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer := &scriptedConn{}
			p := tunnelProxy(t, peer)

			p.serveConnect(tc.writer(peer), connectTo("peer:443"))

			if !peer.closed() {
				t.Error("the peer connection was left open after the tunnel failed")
			}
		})
	}
}

// A client pointed at HTTP_PROXY sends the absolute-form URL; a request in origin form
// reached this handler by mistake, and answering it as if this were an ordinary server
// would serve the proxy's own root for every such request.
func TestAnOrdinaryRequestWithoutAnAbsoluteURLIsRefusedAsAMistake(t *testing.T) {
	p := tunnelProxy(t, &scriptedConn{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req.URL = &url.URL{Path: "/index.html"}
	p.serveForward(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want the request refused as malformed for a proxy", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "absolute URL") {
		t.Errorf("body is %q, want it to say what the client should have sent", rec.Body)
	}
}

// The Connection header is how a hop-by-hop header that is not on the standard list is
// declared. Forwarding one is a request-smuggling primitive: the next hop reads a header
// this hop was told to consume.
func TestTheHeadersTheConnectionHeaderNamesAreStrippedToo(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Session-Token, , Upgrade")
	h.Set("X-Session-Token", "secret")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic zzz")
	h.Set("Content-Type", "text/plain")

	stripHopByHop(h, h.Get("Connection"))

	for _, name := range []string{"X-Session-Token", "Keep-Alive", "Proxy-Authorization", "Connection"} {
		if h.Get(name) != "" {
			t.Errorf("%s survived, so the next hop reads a header this one was told to consume", name)
		}
	}
	if h.Get("Content-Type") != "text/plain" {
		t.Error("an end-to-end header was stripped along with the hop-by-hop ones")
	}
}

// A reason carrying a newline would end the header block, and everything after it would
// be read as the start of the response. The reason comes from a dial error that can name
// a destination the client chose.
func TestAReasonWithLineBreaksCannotEndTheHeaderBlock(t *testing.T) {
	rec := httptest.NewRecorder()
	writeRefusal(rec, errors.New("resolving evil\r\nX-Injected: yes\nhost: no such host"))

	got := rec.Header().Get(ConnectErrorHeader)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("the reason header is %q, which ends the header block early", got)
	}
	if !strings.Contains(got, "X-Injected: yes") {
		t.Errorf("the reason is %q, want the whole sentence kept on one line", got)
	}
}

// The tray starts before the listener does, and a refusal answered on the way up would
// otherwise copy bytes under a nil context.
func TestATunnelBeforeTheProxyIsRunningStillHasAContextToLiveUnder(t *testing.T) {
	p := bareInstance(t, quietLogger())

	if ctx := p.tunnelContext(); ctx == nil {
		t.Fatal("tunnelContext returned nothing before the proxy was started")
	}
}

// failingWriter accepts the status and headers and then fails on the body, which is what
// a client that closed the connection mid-download looks like from the handler.
type failingWriter struct {
	*httptest.ResponseRecorder
	wroteHeader bool
}

func (w *failingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		return 0, errors.New("broken pipe")
	}
	return w.ResponseRecorder.Write(b)
}

func (w *failingWriter) WriteHeader(code int) {
	w.ResponseRecorder.WriteHeader(code)
}

// A client that hangs up mid-download is ordinary, not a fault: the response has already
// been committed, so there is no status left to change and nothing to tell anyone. What
// must not happen is the handler treating it as an error worth failing the request over,
// which at this point would panic on a second WriteHeader.
func TestAClientThatHangsUpMidResponseEndsTheRequestQuietly(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.serveHTTP(t, "example.com:80", "a body long enough to still be arriving")
	p, _ := startProxy(t, tn, func(held *config.ProxyInstance) {
		held.Rules = reachThisMachineToo()
	})

	w := &failingWriter{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/large", nil)
	req.Host = "example.com:80"
	req.URL.Host = "example.com:80"
	p.serveForward(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want the upstream's own status kept once it was committed", w.Code)
	}
}
