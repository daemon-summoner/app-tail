// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/proxy"
	"tailscale.com/net/socks5"
)

// storedPassword stands in for the one a user set on the proxy, which is the secret the
// relay exists to keep out of a command's environment.
const storedPassword = "correct-horse-battery-staple"

// upstreamProxy is a stand-in for the app's own proxy: SOCKS5, requiring the stored
// password, dialing whatever it is asked for. It is what the relay speaks to.
func upstreamProxy(t *testing.T) (addr string, reached *int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start the stand-in proxy: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	dials := 0
	srv := &socks5.Server{
		Logf:     func(string, ...any) {},
		Username: ProxyUser,
		Password: storedPassword,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials++
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
	}
	go srv.Serve(ln) //nolint:errcheck // the listener closes with the test
	return ln.Addr().String(), &dials
}

func startRelay(t *testing.T, upstream string) *Relay {
	t.Helper()
	relay, err := StartRelay(upstream, storedPassword, nil)
	if err != nil {
		t.Fatalf("start the relay: %v", err)
	}
	t.Cleanup(relay.Close)
	return relay
}

// relayURL is the address a client is pointed at, carrying the relay's own credential the
// way an environment variable does.
func relayURL(t *testing.T, relay *Relay) *url.URL {
	t.Helper()
	parsed, err := url.Parse("http://" + relay.Addr())
	if err != nil {
		t.Fatalf("parse the relay address: %v", err)
	}
	parsed.User = url.UserPassword(ProxyUser, relay.Password())
	return parsed
}

// The whole reason the relay exists: what a command is handed opens the relay and nothing
// else. A relay that simply passed its own credential through, or that reused the stored
// one, would put the account's proxy password back into the environment it was taken out of.
func TestTheRelayCredentialIsNotTheProxysOwn(t *testing.T) {
	upstream, _ := upstreamProxy(t)
	relay := startRelay(t, upstream)

	if relay.Password() == storedPassword {
		t.Fatal("the relay hands out the stored proxy password")
	}
	if len(relay.Password()) < 32 {
		t.Errorf("the relay credential is %d characters, which is guessable over loopback", len(relay.Password()))
	}
	if !strings.HasPrefix(relay.Addr(), "127.0.0.1:") {
		t.Errorf("the relay listens on %s, which is reachable from off this machine", relay.Addr())
	}
}

// A relay that authenticates but does not carry bytes is a proxy that broke every command
// run through it.
func TestTheRelayCarriesSOCKSTrafficToTheProxyBehindIt(t *testing.T) {
	upstream, dials := upstreamProxy(t)
	destination := echoServer(t)
	relay := startRelay(t, upstream)

	dialer, err := proxy.SOCKS5("tcp", relay.Addr(),
		&proxy.Auth{User: ProxyUser, Password: relay.Password()}, proxy.Direct)
	if err != nil {
		t.Fatalf("build a client for the relay: %v", err)
	}
	conn, err := dialer.Dial("tcp", destination.String())
	if err != nil {
		t.Fatalf("dial through the relay: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		t.Fatalf("send through the relay: %v", err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back through the relay: %v", err)
	}
	if string(got) != "hello\n" {
		t.Errorf("read %q through the relay, want what was sent", got)
	}
	// The traffic has to have gone through the proxy behind the relay, not straight out of
	// this machine: a relay that dialled direct would carry the command past every rule the
	// proxy applies.
	if *dials != 1 {
		t.Errorf("the proxy behind the relay dialled %d times, want 1", *dials)
	}
}

// The credential is the only thing between the relay and every other process on this
// machine, since the port it opens is reachable by all of them.
func TestTheRelayRefusesACredentialThatIsNotItsOwn(t *testing.T) {
	upstream, dials := upstreamProxy(t)
	destination := echoServer(t)
	relay := startRelay(t, upstream)

	for _, tc := range []struct {
		name string
		auth *proxy.Auth
	}{
		{"no credential at all", nil},
		{"the stored proxy password", &proxy.Auth{User: ProxyUser, Password: storedPassword}},
		{"the right credential for the wrong user", &proxy.Auth{User: "root", Password: relay.Password()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer, err := proxy.SOCKS5("tcp", relay.Addr(), tc.auth, proxy.Direct)
			if err != nil {
				t.Fatalf("build a client for the relay: %v", err)
			}
			conn, err := dialer.Dial("tcp", destination.String())
			if err == nil {
				conn.Close()
				t.Fatal("the relay carried a connection that presented the wrong credential")
			}
		})
	}
	if *dials != 0 {
		t.Errorf("the proxy behind the relay was dialled %d times for refused connections", *dials)
	}
}

// HTTP_PROXY and ALL_PROXY name the same address and different protocols, and plenty of
// tools read only the first. A relay that spoke SOCKS5 alone would send those tools direct.
func TestTheRelayCarriesPlainHTTPThroughTheProxyBehindIt(t *testing.T) {
	upstream, dials := upstreamProxy(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "carried") //nolint:errcheck // the client reports a short body
	}))
	defer origin.Close()
	relay := startRelay(t, upstream)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(relayURL(t, relay))}}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("fetch through the relay: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the answer the relay carried: %v", err)
	}
	if string(body) != "carried" {
		t.Errorf("body = %q, want what the origin sent", body)
	}
	if *dials != 1 {
		t.Errorf("the proxy behind the relay dialled %d times, want 1", *dials)
	}
}

// https:// through HTTPS_PROXY is a CONNECT tunnel rather than a forwarded request, and it
// is the shape almost every real fetch takes.
func TestTheRelayTunnelsCONNECTThroughTheProxyBehindIt(t *testing.T) {
	upstream, dials := upstreamProxy(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "tunnelled") //nolint:errcheck // the client reports a short body
	}))
	defer origin.Close()
	relay := startRelay(t, upstream)

	client := origin.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the test server's client carries a %T, want a transport to point at the relay", client.Transport)
	}
	transport.Proxy = http.ProxyURL(relayURL(t, relay))

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("fetch through the relay's tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the answer the tunnel carried: %v", err)
	}
	if string(body) != "tunnelled" {
		t.Errorf("body = %q, want what the origin sent", body)
	}
	if *dials != 1 {
		t.Errorf("the proxy behind the relay dialled %d times, want 1", *dials)
	}
}

// A browser shown a 407 asks for a password; a program reads the status and stops. Either
// way the refusal has to be the proxy's own, not a carried request that failed.
func TestTheRelaysHTTPFrontEndDemandsItsCredential(t *testing.T) {
	upstream, dials := upstreamProxy(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "carried") //nolint:errcheck // this must never be reached
	}))
	defer origin.Close()
	relay := startRelay(t, upstream)

	bare, err := url.Parse("http://" + relay.Addr())
	if err != nil {
		t.Fatalf("parse the relay address: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(bare)}}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("fetch through the relay without a credential: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("Proxy-Authenticate = %q, want the challenge that says what to present", got)
	}
	if *dials != 0 {
		t.Errorf("the proxy behind the relay was dialled %d times for a refused request", *dials)
	}
}

// The credential lives exactly as long as the command does. If the relay kept listening
// after the command ended, an environment that leaked it would still open something.
func TestClosingTheRelayLeavesTheCredentialOpeningNothing(t *testing.T) {
	upstream, _ := upstreamProxy(t)
	relay, err := StartRelay(upstream, storedPassword, nil)
	if err != nil {
		t.Fatalf("start the relay: %v", err)
	}
	addr, credential := relay.Addr(), relay.Password()
	relay.Close()

	dialer, err := proxy.SOCKS5("tcp", addr, &proxy.Auth{User: ProxyUser, Password: credential}, proxy.Direct)
	if err != nil {
		t.Fatalf("build a client for the closed relay: %v", err)
	}
	conn, err := dialer.Dial("tcp", "127.0.0.1:9")
	if err == nil {
		conn.Close()
		t.Fatal("a closed relay still carried a connection")
	}
}

func TestARelayNeedsSomethingToStandInFrontOf(t *testing.T) {
	if _, err := StartRelay("", storedPassword, nil); err == nil {
		t.Fatal("a relay started with no proxy behind it")
	}
}
