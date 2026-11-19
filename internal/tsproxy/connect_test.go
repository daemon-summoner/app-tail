// SPDX-License-Identifier: MIT

package tsproxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// connect opens a tunnel the way every HTTPS client and `ssh -o ProxyCommand` does: a
// CONNECT request on a raw socket that becomes the tunnel itself once it is answered.
//
// The reader is handed back with the socket because the response and the tunnelled
// bytes arrive on the same connection -- reading the reply buffers whatever followed it,
// and a test that went back to the socket would lose exactly those bytes.
func connect(t *testing.T, p *Instance, target string, request string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy at %s: %v", p.Addr(), err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline on the tunnel: %v", err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("send the CONNECT request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read the proxy's answer to CONNECT %s: %v", target, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return conn, reader, resp
}

// waitUntil polls for a state another goroutine brings about, since a tunnel ending is
// noticed by the proxy rather than announced to the test.
func waitUntil(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after 5s waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// connectRequest is a well-formed CONNECT request with any extra headers appended.
func connectRequest(target string, headers ...string) string {
	var b strings.Builder
	b.WriteString("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// echoOver writes through an established tunnel and reads the same bytes back, proving
// it carries traffic in both directions rather than merely having been answered.
func echoOver(t *testing.T, conn net.Conn, reader *bufio.Reader, msg string) {
	t.Helper()
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read back through the tunnel: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("read %q back through the tunnel, want %q", buf, msg)
	}
}

// The other half of the headline claim: HTTPS_PROXY and every browser reach a peer
// through CONNECT, not SOCKS5. Without this a proxy that works perfectly under
// ALL_PROXY fails for every https:// URL.
func TestACONNECTTunnelReachesAPeerByName(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer.tail1a2b3c.ts.net:443")
	p, _ := startProxy(t, tn)

	conn, reader, resp := connect(t, p, "peer.tail1a2b3c.ts.net:443",
		connectRequest("peer.tail1a2b3c.ts.net:443"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %d, want the tunnel to be established", resp.StatusCode)
	}
	echoOver(t, conn, reader, "carried")
}

// A client that pipelines its first bytes behind the CONNECT line -- which is what a TLS
// client does with its ClientHello -- leaves them in the server's reader rather than in
// the socket. Dropping them does not fail the tunnel: it hangs the handshake until
// something times out, which reads as a slow network rather than as lost data.
func TestBytesSentBehindTheConnectLineAreNotLost(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:443")
	p, _ := startProxy(t, tn)

	// One write, so the payload is certain to be read into the same buffer as the
	// request rather than arriving as a second packet the tunnel would pick up anyway.
	_, reader, resp := connect(t, p, "peer:443", connectRequest("peer:443")+"early-bytes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %d, want the tunnel to be established", resp.StatusCode)
	}

	buf := make([]byte, len("early-bytes"))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("the bytes sent behind the CONNECT line never reached the peer: %v", err)
	}
	if string(buf) != "early-bytes" {
		t.Errorf("the peer echoed %q, want the pipelined %q", buf, "early-bytes")
	}
}

// A browser shows its own error page for a failed CONNECT and never displays the body,
// so the status has to say which kind of refusal it was and the reason has to be in a
// header. Otherwise the only symptom a user ever sees is "this site can't be reached".
func TestACONNECTRefusalSaysWhichKindItIs(t *testing.T) {
	tests := []struct {
		name   string
		target string
		// unclassifiable makes the connection unable to say where anything is, which is
		// what a connection that is not up looks like to a dial.
		unclassifiable bool
		status         int
		says           string
	}{
		{"no rule allows it", "example.com:443", false, http.StatusForbidden, "not allowed"},
		{"nothing can say where it is", "peer:443", true, http.StatusServiceUnavailable,
			"no connection could work out where that is"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tn := newFakeNetwork(t)
			tn.route(t, "peer:443")
			tn.expose(t, "example.com:443")
			p, _ := startProxy(t, tn)
			if tc.unclassifiable {
				tn.mu.Lock()
				tn.reachErr = errors.New("the connection is not running")
				tn.mu.Unlock()
			}

			_, _, resp := connect(t, p, tc.target, connectRequest(tc.target))
			if resp.StatusCode != tc.status {
				t.Errorf("CONNECT %s = %d, want %d", tc.target, resp.StatusCode, tc.status)
			}
			reason := resp.Header.Get(ConnectErrorHeader)
			if reason == "" {
				t.Fatalf("no %s header, so a browser shows its own page and the reason is lost",
					ConnectErrorHeader)
			}
			if !strings.Contains(reason, tc.says) {
				t.Errorf("%s = %q, want it to mention %q", ConnectErrorHeader, reason, tc.says)
			}
		})
	}
}

// The password has to guard the HTTP half exactly as it guards the SOCKS5 one. Every
// malformed credential is a refusal rather than a parse that lets something through:
// this is the one check standing between the tailnet and every process on the machine.
func TestTheHTTPHalfRefusesEveryCredentialButTheConfiguredOne(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:443")
	p, _ := startProxy(t, tn, func(held *config.ProxyInstance) {
		held.RequireToken = true
		held.Token = "correct-horse"
	})

	for _, tc := range []struct {
		name   string
		header []string
	}{
		{"none at all", nil},
		{"a scheme this proxy does not speak", []string{"Proxy-Authorization: Bearer correct-horse"}},
		{"a credential that is not base64", []string{"Proxy-Authorization: Basic not-base-64-at-all"}},
		{"a credential with no colon in it", []string{"Proxy-Authorization: Basic " + basic("correct-horse")}},
		{"the wrong password", []string{"Proxy-Authorization: Basic " + basic(ProxyUser+":wrong")}},
		{"the right password for the wrong user", []string{"Proxy-Authorization: Basic " + basic("root:correct-horse")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, resp := connect(t, p, "peer:443", connectRequest("peer:443", tc.header...))
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("CONNECT = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
			}
			// Without this a client has no way to know a credential is even wanted.
			if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, "Basic") {
				t.Errorf("Proxy-Authenticate = %q, want it to ask for Basic", got)
			}
		})
	}

	conn, reader, resp := connect(t, p, "peer:443",
		connectRequest("peer:443", "Proxy-Authorization: Basic "+basic(ProxyUser+":correct-horse")))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the proxy refused the configured password: CONNECT = %d", resp.StatusCode)
	}
	echoOver(t, conn, reader, "authenticated")
}

// basic encodes a credential the way a client puts it in Proxy-Authorization.
func basic(credential string) string {
	return base64.StdEncoding.EncodeToString([]byte(credential))
}

// A tunnel whose two ends both went away without a word never fails a read. Its idle limit
// is the only thing that gives its place back, and without one every such tunnel is held for
// as long as the proxy runs.
func TestATunnelCarryingNothingIsEndedAtItsIdleLimit(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer.tail1a2b3c.ts.net:443")
	box := newProxyBox(tn)
	box.set.tunnelIdle = 150 * time.Millisecond
	t.Cleanup(box.set.Close)
	box.mustApply(t)
	inst := box.instance()

	conn, reader, resp := connect(t, inst, "peer.tail1a2b3c.ts.net:443", connectRequest("peer.tail1a2b3c.ts.net:443"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %d", resp.StatusCode)
	}
	echoOver(t, conn, reader, "in use")

	// Nothing more is sent. The proxy has to be the one that hangs up.
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("reading a tunnel left idle returned %v, want the proxy to have closed it", err)
	}
	waitUntil(t, "the ended tunnel to stop counting as open", func() bool {
		return inst.Status().Counters.Active == 0
	})
}

// The other half: a tunnel in use is never ended for the time it has been open, only for
// the time it has been quiet.
func TestATunnelStillCarryingTrafficOutlivesItsIdleLimit(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer.tail1a2b3c.ts.net:443")
	box := newProxyBox(tn)
	const idle = 400 * time.Millisecond
	box.set.tunnelIdle = idle
	t.Cleanup(box.set.Close)
	box.mustApply(t)

	conn, reader, resp := connect(t, box.instance(), "peer.tail1a2b3c.ts.net:443", connectRequest("peer.tail1a2b3c.ts.net:443"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %d", resp.StatusCode)
	}
	for range 10 {
		echoOver(t, conn, reader, "still here")
		time.Sleep(idle / 4)
	}
}

// Opening a tunnel costs a program nothing and costs this process two descriptors for as
// long as it lives, so the number held cannot be left to whoever is asking.
func TestTunnelsPastTheLimitAreRefusedUntilOneEnds(t *testing.T) {
	tn := newFakeNetwork(t)
	const target = "peer.tail1a2b3c.ts.net:443"
	tn.route(t, target)
	box := newProxyBox(tn)
	const limit = 2
	box.set.maxTunnels = limit
	t.Cleanup(box.set.Close)
	box.mustApply(t)
	inst := box.instance()

	var held []net.Conn
	for i := range limit {
		conn, reader, resp := connect(t, inst, target, connectRequest(target))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tunnel %d of %d answered %d", i+1, limit, resp.StatusCode)
		}
		echoOver(t, conn, reader, "held open")
		held = append(held, conn)
	}

	_, _, over := connect(t, inst, target, connectRequest(target))
	if over.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("the tunnel past the limit answered %d, want %d", over.StatusCode, http.StatusServiceUnavailable)
	}
	if reason := over.Header.Get(ConnectErrorHeader); !strings.Contains(reason, "2 tunnels") {
		t.Errorf("refusal reason = %q, want it to name the limit", reason)
	}
	if got := len(tn.dialledAddresses()); got != limit {
		t.Errorf("%d destinations were dialled, want %d: the refused tunnel must not reach one", got, limit)
	}
	if got := inst.Status().Counters.Refused; got != 1 {
		t.Errorf("Refused = %d, want the tunnel past the limit counted", got)
	}

	// A place comes back when a tunnel ends, and not before.
	held[0].Close()
	waitUntil(t, "a tunnel to be carried again once one ended", func() bool {
		conn, err := net.DialTimeout("tcp", inst.Addr(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial the proxy: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, connectRequest(target)); err != nil {
			t.Fatalf("send the CONNECT request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("read the proxy's answer: %v", err)
		}
		return resp.StatusCode == http.StatusOK
	})
}

// The SOCKS5 half copies its own bytes, so the idle limit has to reach it through the
// connection it is handed rather than through the copy.
func TestASOCKS5ConnectionIsEndedOnlyOnceItHasGoneQuiet(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer.tail1a2b3c.ts.net:22")
	box := newProxyBox(tn)
	const idle = 400 * time.Millisecond
	box.set.tunnelIdle = idle
	t.Cleanup(box.set.Close)
	box.mustApply(t)
	inst := box.instance()

	conn, err := socksDial(t, inst, "peer.tail1a2b3c.ts.net:22", nil)
	if err != nil {
		t.Fatalf("reach the peer through SOCKS5: %v", err)
	}
	defer conn.Close()

	// In use for well past the limit, and still carried.
	for range 8 {
		echo(t, conn, "still here")
		time.Sleep(idle / 4)
	}

	// Nothing more is sent. The proxy has to be the one that hangs up.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("reading a connection left idle returned %v, want the proxy to have closed it", err)
	}
	waitUntil(t, "the ended connection to stop counting as open", func() bool {
		return inst.Status().Counters.Active == 0
	})
}

// One ceiling for both halves: a program refused a tunnel by CONNECT must not get it by
// asking over SOCKS5 instead.
func TestSOCKS5ConnectionsCountAgainstTheSameLimit(t *testing.T) {
	tn := newFakeNetwork(t)
	const target = "peer.tail1a2b3c.ts.net:443"
	tn.route(t, target)
	box := newProxyBox(tn)
	box.set.maxTunnels = 2
	t.Cleanup(box.set.Close)
	box.mustApply(t)
	inst := box.instance()

	tunnel, reader, resp := connect(t, inst, target, connectRequest(target))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %d", resp.StatusCode)
	}
	echoOver(t, tunnel, reader, "held open")
	socks, err := socksDial(t, inst, target, nil)
	if err != nil {
		t.Fatalf("the SOCKS5 connection under the limit was refused: %v", err)
	}
	defer socks.Close()
	echo(t, socks, "held open")

	if over, err := socksDial(t, inst, target, nil); err == nil {
		over.Close()
		t.Fatal("a SOCKS5 connection past the limit was carried")
	}
	if got := len(tn.dialledAddresses()); got != 2 {
		t.Errorf("%d destinations were dialled, want 2: the refused connection must not reach one", got)
	}
	if got := inst.Status().Counters.Refused; got != 1 {
		t.Errorf("Refused = %d, want the connection past the limit counted", got)
	}

	// A place comes back when a tunnel ends, and not before.
	tunnel.Close()
	waitUntil(t, "a SOCKS5 connection to be carried again once a tunnel ended", func() bool {
		conn, err := socksDial(t, inst, target, nil)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	})
}
