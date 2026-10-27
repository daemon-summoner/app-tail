// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/sellitus/app-tail/internal/config"
)

// socksDial reaches address through the proxy's SOCKS5 front end, the way a program run
// under ALL_PROXY does. It resolves nothing locally: the name is handed to the proxy,
// which is the whole reason MagicDNS works through it.
func socksDial(t *testing.T, p *Instance, address string, auth *proxy.Auth) (net.Conn, error) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", p.Addr(), auth, proxy.Direct)
	if err != nil {
		t.Fatalf("build a SOCKS5 client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", address)
}

// echo writes through conn and reads the same bytes back, proving the tunnel carries
// traffic rather than merely having been accepted.
func echo(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read back through the proxy: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("read %q, want %q", buf, msg)
	}
}

// The headline claim: a program that knows nothing about Tailscale reaches a peer by
// its MagicDNS name, with no interface, no route and no privilege.
func TestASOCKS5ClientReachesAPeerByName(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "buildbox.tail1a2b3c.ts.net:22")
	p, _ := startProxy(t, tn)

	conn, err := socksDial(t, p, "buildbox.tail1a2b3c.ts.net:22", nil)
	if err != nil {
		t.Fatalf("reach the peer through SOCKS5: %v", err)
	}
	defer conn.Close()

	echo(t, conn, "hello over socks")
}

// A first connection to a cold peer negotiates a path and often settles for DERP, which
// routinely takes longer than the five-second deadline the SOCKS5 library hardcodes on
// the dial it hands us. The configured timeout has to be the one that applies, or the
// symptom is an intermittent failure with no message anywhere naming a timeout.
func TestTheConfiguredDialTimeoutOutlivesTheOneSOCKS5Imposes(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, _ := startProxy(t, tn, func(held *config.ProxyInstance) { held.DialTimeoutSec = 45 })

	// The library's deadline arrives on the context it hands the dialer, so this is
	// exactly the shape a SOCKS5 connection presents.
	imposed, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.dial(imposed, "tcp", "peer:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Generous bounds: the assertion is which of the two timeouts governs, not the
	// handful of microseconds spent reaching the dial.
	if got := tn.lastDeadline(t); got < 40*time.Second {
		t.Errorf("the backend was dialed with %v left, want close to the configured 45s "+
			"rather than the 5s the SOCKS5 library imposes", got)
	}
}

// Detaching from the caller's deadline must not detach from the configured one: a dial
// with no deadline at all would hang a client until it gave up, with nothing in the
// proxy ever timing out.
func TestADialStillCarriesADeadlineWhenTheCallerImposedNone(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, _ := startProxy(t, tn, func(held *config.ProxyInstance) { held.DialTimeoutSec = 12 })

	conn, err := p.dial(context.Background(), "tcp", "peer:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	got := tn.lastDeadline(t)
	if got <= 0 || got > 12*time.Second {
		t.Errorf("the backend was dialed with %v left, want at most the configured 12s and never unbounded", got)
	}
}

// An instance stored before the timeout existed carries zero. Passing that through would
// create an already-expired context and fail every dial instantly.
func TestAnUnsetDialTimeoutFallsBackToTheDefaultRatherThanZero(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, _ := startProxy(t, tn)

	conn, err := p.dial(context.Background(), "tcp", "peer:22")
	if err != nil {
		t.Fatalf("dial with no configured timeout: %v", err)
	}
	defer conn.Close()

	if got := tn.lastDeadline(t); got <= 0 {
		t.Errorf("the backend was dialed with %v left, want the built-in default", got)
	}
}

// A refusal has to reach the client. SOCKS5 has one failure code for a failed dial, so
// the reason lives in the counters and the log -- but the connection itself must fail
// rather than succeed and carry traffic somewhere no rule allowed.
func TestSOCKS5RefusesADestinationNoRuleAllows(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.expose(t, "example.com:443")
	p, _ := startProxy(t, tn)

	conn, err := socksDial(t, p, "example.com:443", nil)
	if err == nil {
		conn.Close()
		t.Fatal("SOCKS5 carried a destination no rule allows")
	}
	if got := p.Status().Counters.Refused; got != 1 {
		t.Errorf("refused = %d, want the refusal to be counted", got)
	}
}

// Adding a grant is what a browser pointed entirely at the proxy needs, and it must take
// effect without rebinding: the port and the auto-config URL are copied into shell
// profiles and browser settings, and moving them silently breaks all of them.
func TestAddingAGrantTakesEffectWithoutMovingThePort(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.expose(t, "example.com:443")
	p, box := startProxy(t, tn)
	before := p.Addr()

	if conn, err := socksDial(t, p, "example.com:443", nil); err == nil {
		conn.Close()
		t.Fatal("a destination on this machine was carried with no rule granting it")
	}

	box.edit(func(held *config.ProxyInstance) { held.Rules = reachThisMachineToo() })
	box.mustApply(t)

	if p.Addr() != before {
		t.Errorf("the proxy moved from %s to %s for a rule change", before, p.Addr())
	}
	conn, err := socksDial(t, p, "example.com:443", nil)
	if err != nil {
		t.Fatalf("a destination on this machine was still refused after granting it: %v", err)
	}
	defer conn.Close()
	echo(t, conn, "public")
}

// The password is the difference between "any process on this machine" and "any process
// that knows the secret". A proxy that bound with one and accepted connections without
// it would be strictly worse than one with none, because the user would believe they
// were protected.
func TestAPasswordIsRequiredOnceOneIsConfigured(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, _ := startProxy(t, tn, func(held *config.ProxyInstance) {
		held.RequireToken = true
		held.Token = "correct-horse"
	})

	if conn, err := socksDial(t, p, "peer:22", nil); err == nil {
		conn.Close()
		t.Fatal("the proxy accepted a SOCKS5 client with no password")
	}
	if conn, err := socksDial(t, p, "peer:22", &proxy.Auth{User: ProxyUser, Password: "wrong"}); err == nil {
		conn.Close()
		t.Fatal("the proxy accepted a SOCKS5 client with the wrong password")
	}

	conn, err := socksDial(t, p, "peer:22", &proxy.Auth{User: ProxyUser, Password: "correct-horse"})
	if err != nil {
		t.Fatalf("the proxy refused the configured password: %v", err)
	}
	defer conn.Close()
	echo(t, conn, "authenticated")
}

// Requiring a password with none stored would bind a port that lets everything through
// while the configuration says it is protected. Refusing to start is the only honest
// outcome.
func TestRequiringAPasswordWithNoneStoredRefusesToBind(t *testing.T) {
	tn := newFakeNetwork(t)
	box := newProxyBox(tn, func(held *config.ProxyInstance) { held.RequireToken = true })
	t.Cleanup(box.set.Close)

	err := box.apply()
	if err == nil {
		t.Fatal("the proxy started while set to require a password it does not have")
	}
	if box.addr() != "" {
		t.Errorf("the proxy bound %s anyway", box.addr())
	}
	if got := box.status().Error; !strings.Contains(got, "password") {
		t.Errorf("status error = %q, want it to explain the missing password", got)
	}
}

// A disabled instance is a configured one that is off, and off has to mean no port is
// bound at all. This is the mechanical half of "installs minimally": a listener that
// exists while the instance is switched off is a grant the user never made.
func TestNothingIsBoundWhileTheInstanceIsOff(t *testing.T) {
	tn := newFakeNetwork(t)
	box := newProxyBox(tn, func(held *config.ProxyInstance) { held.Enabled = false })
	t.Cleanup(box.set.Close)

	box.mustApply(t)
	if box.addr() != "" {
		t.Errorf("the proxy bound %s while the instance was off", box.addr())
	}

	box.edit(func(held *config.ProxyInstance) { held.Enabled = true })
	box.mustApply(t)
	if box.addr() == "" {
		t.Fatal("the proxy did not bind once the instance was switched on")
	}

	bound := box.addr()
	box.edit(func(held *config.ProxyInstance) { held.Enabled = false })
	box.mustApply(t)
	if box.addr() != "" {
		t.Errorf("the proxy stayed bound at %s after the instance was switched off", box.addr())
	}
	// Proof rather than inference: the port is genuinely released.
	ln, err := net.Listen("tcp", bound)
	if err != nil {
		t.Errorf("the proxy's port %s is still held: %v", bound, err)
	} else {
		ln.Close()
	}
}

// A connection going down must not close the port. A closed port makes a user conclude the
// app is broken; a bound port that answers with a reason is something they can act on.
func TestThePortStaysBoundWhileAConnectionIsDown(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn)
	bound := p.Addr()

	tn.mu.Lock()
	tn.reachErr = errors.New("this connection is not up")
	tn.mu.Unlock()
	box.mustApply(t)

	if p.Addr() != bound {
		t.Errorf("the proxy moved from %s to %s when the connection went down", bound, p.Addr())
	}
	if conn, err := socksDial(t, p, "peer:22", nil); err == nil {
		conn.Close()
		t.Fatal("the proxy carried traffic while the connection was down")
	}

	tn.mu.Lock()
	tn.reachErr = nil
	tn.mu.Unlock()

	conn, err := socksDial(t, p, "peer:22", nil)
	if err != nil {
		t.Fatalf("the proxy did not recover once the connection came back: %v", err)
	}
	defer conn.Close()
	echo(t, conn, "recovered")
}

// A configured port that something else already holds must not leave the proxy down:
// the fallback is what the caller then persists, so every snippet naming the new port
// stays correct across restarts.
func TestAPortConflictFallsBackRatherThanLeavingTheProxyDown(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold a port: %v", err)
	}
	defer blocker.Close()

	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, _ := startProxy(t, tn, func(held *config.ProxyInstance) { held.ListenAddr = blocker.Addr().String() })

	if p.Addr() == "" {
		t.Fatal("the proxy gave up rather than falling back to another port")
	}
	if p.Addr() == blocker.Addr().String() {
		t.Fatal("the proxy claims the port something else is holding")
	}
	if !p.Status().MovedFromConfig {
		t.Error("the proxy moved but did not report that it had, so nothing can explain the mismatch")
	}
	if host, _, err := net.SplitHostPort(p.Addr()); err != nil || host != "127.0.0.1" {
		t.Errorf("the fallback bound %s, want the same loopback host", p.Addr())
	}

	conn, err := socksDial(t, p, "peer:22", nil)
	if err != nil {
		t.Fatalf("the fallback port does not serve: %v", err)
	}
	defer conn.Close()
	echo(t, conn, "fallback")
}

// Reconciling is the reconcile loop's normal work and runs on every configuration change
// and every connection event. Rebinding each time would drop every live connection on the
// proxy for a change that did not concern it.
func TestReApplyingAnUnchangedInstanceLeavesTheListenerAlone(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn)

	conn, err := socksDial(t, p, "peer:22", nil)
	if err != nil {
		t.Fatalf("open a connection through the proxy: %v", err)
	}
	defer conn.Close()
	bound := p.Addr()

	for range 3 {
		box.mustApply(t)
	}

	if p.Addr() != bound {
		t.Errorf("the proxy moved from %s to %s across an unchanged reconcile", bound, p.Addr())
	}
	echo(t, conn, "still open")
}

// The agent writes the address a conflict moved the listener to back into the settings,
// so the reconcile right after a move asks for the port the proxy is already sitting on.
// Reading that as a changed address would drop every connection on the proxy to rebuild
// the listener on the same port -- and would erase the move along with it, leaving
// nothing to explain why the port a user already pasted somewhere is the wrong one.
func TestAdoptingTheMovedAddressNeitherRebindsNorForgetsTheMove(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold a port: %v", err)
	}
	defer blocker.Close()
	wanted := blocker.Addr().String()

	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn, func(held *config.ProxyInstance) { held.ListenAddr = wanted })
	bound := p.Addr()

	conn, err := socksDial(t, p, "peer:22", nil)
	if err != nil {
		t.Fatalf("open a connection through the fallback port: %v", err)
	}
	defer conn.Close()

	box.edit(func(held *config.ProxyInstance) { held.ListenAddr = bound })
	box.mustApply(t)

	if p.Addr() != bound {
		t.Errorf("the proxy moved from %s to %s when the configuration adopted its address", bound, p.Addr())
	}
	echo(t, conn, "still open")

	st := p.Status()
	if !st.MovedFromConfig {
		t.Error("the proxy forgot it had moved as soon as its address was persisted")
	}
	if st.ConfiguredAddr != wanted {
		t.Errorf("ConfiguredAddr = %q, want the port that was taken (%q) so the mismatch can be explained",
			st.ConfiguredAddr, wanted)
	}
}

// Adopting the bound address must not make the listener deaf to a real move. Asking for
// a different port is the one case that has to rebind, including asking for the port the
// proxy was originally pushed off once it is free again.
func TestChangingTheConfiguredPortMovesTheListener(t *testing.T) {
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	wanted := free.Addr().String()
	if err := free.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}

	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn)
	if p.Addr() == wanted {
		t.Fatalf("the proxy happened to bind the port this test moves it to (%s)", wanted)
	}

	box.edit(func(held *config.ProxyInstance) { held.ListenAddr = wanted })
	box.mustApply(t)

	if p.Addr() != wanted {
		t.Fatalf("the proxy is at %s, want it moved to the newly configured %s", p.Addr(), wanted)
	}
	if p.Status().MovedFromConfig {
		t.Error("a listener that bound exactly where it was asked to reported itself as moved")
	}
	conn, err := socksDial(t, p, "peer:22", nil)
	if err != nil {
		t.Fatalf("the newly configured port does not serve: %v", err)
	}
	defer conn.Close()
	echo(t, conn, "moved")
}

// Revoking a grant has to reach connections the transport pooled under the wider rules.
// They are keyed by destination, so without this the proxy keeps carrying traffic to a
// destination it now refuses -- for as long as the pooled connection lives.
func TestRevokingAGrantDropsConnectionsPooledUnderIt(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.serveHTTP(t, "example.com:80", "public page")
	p, box := startProxy(t, tn, func(held *config.ProxyInstance) { held.Rules = reachThisMachineToo() })
	client := proxyClient(t, p)

	// A completed request leaves the connection it used in the transport's pool, which
	// is the state this test is about.
	if body := getThrough(t, client, "http://example.com/", http.StatusOK); body != "public page" {
		t.Fatalf("body = %q, want the stand-in server's page", body)
	}
	dialsBefore := len(tn.dialledAddresses())

	box.edit(func(held *config.ProxyInstance) { held.Rules = reachTheConnection() })
	box.mustApply(t)

	getThrough(t, client, "http://example.com/", http.StatusForbidden)
	// A refused request never reaches a dial, so a pooled connection being reused
	// instead would show up as no new dial attempt and a 200.
	if got := len(tn.dialledAddresses()); got != dialsBefore {
		t.Errorf("the backend was dialed %d more times after the grant was revoked, want 0", got-dialsBefore)
	}
}

// getThrough performs one request through the proxy and returns its body, failing the
// test unless the status is the expected one.
func getThrough(t *testing.T, client *http.Client, target string, wantStatus int) string {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s through the proxy: %v", target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the proxied response: %v", err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s = %d, want %d (%s)", target, resp.StatusCode, wantStatus, strings.TrimSpace(string(body)))
	}
	return strings.TrimSpace(string(body))
}

// proxyClient builds an HTTP client that sends everything through the proxy's HTTP
// front end, the way HTTP_PROXY does.
func proxyClient(t *testing.T, p *Instance) *http.Client {
	t.Helper()
	u, err := url.Parse("http://" + p.Addr())
	if err != nil {
		t.Fatalf("parse the proxy URL: %v", err)
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
}

// Closing has to release the port and end tunnels still carrying traffic. A tunnel that
// outlived the proxy would keep reaching the private networks after it was switched off.
func TestClosingReleasesThePortAndEndsLiveTunnels(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, _ := startProxy(t, tn)
	bound := p.Addr()

	conn, err := socksDial(t, p, "peer:22", nil)
	if err != nil {
		t.Fatalf("open a connection through the proxy: %v", err)
	}
	defer conn.Close()

	p.Close()

	ln, err := net.Listen("tcp", bound)
	if err != nil {
		t.Fatalf("the proxy's port %s is still held after Close: %v", bound, err)
	}
	ln.Close()

	// The deadline is an upper bound on "was it actually torn down", not the expected
	// outcome: a read that only ends because the deadline expired means the connection
	// outlived Close, which is the failure this test exists for. A net.Conn reports that
	// as os.ErrDeadlineExceeded -- context.DeadlineExceeded is never what surfaces here,
	// so matching on that would pass however long the connection survived.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("a connection through the proxy still reads after Close")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Error("a connection through the proxy was left open after Close")
	}
}

// The same guarantee has to hold when the instance is merely switched off rather than the
// process shut down: an SSH session left running through a proxy the user just disabled
// keeps reaching the private network for as long as it lasts.
func TestSwitchingAnInstanceOffEndsConnectionsItWasCarrying(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn)

	conn, err := socksDial(t, p, "peer:22", nil)
	if err != nil {
		t.Fatalf("open a connection through the proxy: %v", err)
	}
	defer conn.Close()

	box.edit(func(held *config.ProxyInstance) { held.Enabled = false })
	box.mustApply(t)

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("a connection kept reading after the proxy instance was switched off")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Error("switching the instance off left an established connection carrying private traffic")
	}
	if got := p.Status().Counters.Active; got != 0 {
		t.Errorf("active = %d after switching the instance off, want 0", got)
	}
}

// Closing twice happens on any path where shutdown overlaps a reconcile.
func TestClosingTwiceIsSafe(t *testing.T) {
	p, _ := startProxy(t, newFakeNetwork(t))
	p.Close()
	// The assertion is that this returns at all: a second stop over an already-closed
	// listener and a drained wait group panics or blocks if either is not idempotent.
	p.Close()
}

// The listener is reused when only the port would move, since the port was never the
// user's choice. A credential is: rebinding is the only way a client that authenticated
// under the old one is made to present the new one.
func TestChangingTheCredentialRebindsRatherThanReusingTheListener(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, box := startProxy(t, tn, func(held *config.ProxyInstance) {
		held.RequireToken = true
		held.Token = "first"
	})
	before := p.Addr()

	box.edit(func(held *config.ProxyInstance) { held.Token = "second" })
	box.mustApply(t)

	if conn, err := socksDial(t, p, "peer:22", &proxy.Auth{User: ProxyUser, Password: "first"}); err == nil {
		conn.Close()
		t.Fatal("the replaced password still opens the proxy")
	}
	conn, err := socksDial(t, p, "peer:22", &proxy.Auth{User: ProxyUser, Password: "second"})
	if err != nil {
		t.Fatalf("the new password was refused: %v", err)
	}
	defer conn.Close()
	echo(t, conn, "reauthenticated")
	if p.Addr() == "" {
		t.Errorf("nothing is bound after the credential changed; it was %s before", before)
	}
}

// A proxy that could not bind at all has to say so and stay down. The fallback covers a
// port already in use; an address this machine has no interface for is not a conflict,
// and binding some other port on a host that does not exist would be a lie.
func TestAnUnbindableAddressLeavesTheProxyDownWithTheReason(t *testing.T) {
	tests := []struct {
		name string
		addr string
		// wantAlso is a second thing the reason has to say, for the cases where naming
		// only the configured address would hide half of what was tried.
		wantAlso string
	}{
		{name: "no interface carries the address", addr: "203.0.113.7:0"},
		// A named port sends bind down its fallback path, which then fails for the same
		// reason. Reporting only the configured port would leave a user re-checking a
		// port that was never the problem, so both attempts have to be in the reason.
		{name: "no interface carries the address, on a named port", addr: "203.0.113.7:9999",
			wantAlso: "203.0.113.7:0"},
		{name: "not an address at all", addr: "not-an-address"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			box := newProxyBox(newFakeNetwork(t), func(held *config.ProxyInstance) {
				held.ListenAddr = tc.addr
			})
			t.Cleanup(box.set.Close)

			if err := box.apply(); err == nil {
				t.Fatal("the proxy reported it started on an address it cannot bind")
			}
			if box.addr() != "" {
				t.Errorf("the proxy bound %s despite the address being unusable", box.addr())
			}
			got := box.status().Error
			if !strings.Contains(got, tc.addr) {
				t.Errorf("status error = %q, want it to name the address that failed", got)
			}
			if tc.wantAlso != "" && !strings.Contains(got, tc.wantAlso) {
				t.Errorf("status error = %q, want it to also name %q as tried", got, tc.wantAlso)
			}
		})
	}
}

// Both halves of the split listener end when the raw listener closes, so warning about
// that would put a line in the log on every clean shutdown. Anything else is a fault the
// operator has to see: the other half and the port both stay up, so the proxy goes on
// looking healthy while answering nothing on the protocol that died.
func TestOnlyAListenerThatDiedForItsOwnReasonIsReported(t *testing.T) {
	ordinary := []struct {
		name string
		err  error
	}{
		{"the raw listener was closed", net.ErrClosed},
		{"the HTTP server was shut down", http.ErrServerClosed},
	}
	for _, tc := range ordinary {
		t.Run(tc.name, func(t *testing.T) {
			logger, logs := capturingLogger()
			p := bareInstance(t, logger)

			p.wg.Add(1)
			p.serve("HTTP", func() error { return tc.err })
			p.wg.Wait()

			if strings.Contains(logs.String(), "listener stopped") {
				t.Errorf("an ordinary shutdown was reported as a fault:\n%s", logs.String())
			}
		})
	}

	t.Run("a listener that died on its own", func(t *testing.T) {
		logger, logs := capturingLogger()
		p := bareInstance(t, logger)

		p.wg.Add(1)
		p.serve("SOCKS5", func() error { return errors.New("too many open files") })
		p.wg.Wait()

		out := logs.String()
		if !strings.Contains(out, "listener stopped") {
			t.Errorf("a listener that died is not reported:\n%s", out)
		}
		// Which half died is the whole content of the report: the port stays bound
		// either way, so without it there is nothing to act on.
		if !strings.Contains(out, "SOCKS5") || !strings.Contains(out, "too many open files") {
			t.Errorf("the report names neither the protocol nor the reason:\n%s", out)
		}
	})
}

// Tearing down leaves nothing for a caller to handle, so what goes wrong on the way out
// has to reach the log or it reaches nobody. Both of these leave the port held: the next
// Apply then falls back to an OS-assigned one, and every snippet naming the old address
// silently stops working with nothing on screen to explain it.
func TestATeardownThatCouldNotFinishIsRecordedRatherThanLost(t *testing.T) {
	logger, logs := capturingLogger()
	p := bareInstance(t, logger)

	httpLn := newStuckListener(errors.New("the HTTP listener was already gone"))
	srv := &http.Server{ReadHeaderTimeout: time.Second}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(httpLn)
	}()
	// The drain has nothing to report until Serve has registered the listener, which
	// it does just before its first Accept.
	<-httpLn.accepting

	p.mu.Lock()
	p.raw = newStuckListener(errors.New("the proxy listener was already gone"))
	p.httpSrv = srv
	p.mu.Unlock()

	p.stop()
	<-served

	out := logs.String()
	if !strings.Contains(out, "the proxy listener was already gone") {
		t.Errorf("a listener that would not close is not reported:\n%s", out)
	}
	if !strings.Contains(out, "the HTTP listener was already gone") {
		t.Errorf("a drain that could not finish is not reported:\n%s", out)
	}
}
