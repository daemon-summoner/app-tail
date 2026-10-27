// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// proxyOn seeds the module as a user would after switching it on. The port is
// OS-assigned because a fixed one makes the suite fail when a developer happens to be
// running something on it.
func proxyOn(c *config.Config) {
	c.Settings.ProxyEnabled = true
	for i := range c.Proxies {
		if c.Proxies[i].ID == config.DefaultProxyID {
			c.Proxies[i].ListenAddr = "127.0.0.1:0"
			return
		}
	}
}

// proxyView reads the API the dashboard reads.
func proxyView(h *harness) httpapi.ProxyView {
	h.t.Helper()
	resp, body := h.get("/api/proxy")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /api/proxy = %d: %s", resp.StatusCode, body)
	}
	var view httpapi.ProxyView
	if err := json.Unmarshal(body, &view); err != nil {
		h.t.Fatalf("decode the proxy view %q: %v", body, err)
	}
	return view
}

// waitForProxy waits for the reconcile loop to bring the proxy to a state, since Apply
// runs on the lifecycle goroutine rather than on the request that caused it.
func waitForProxy(h *harness, why string, ready func(httpapi.ProxyView) bool) httpapi.ProxyView {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var view httpapi.ProxyView
	for time.Now().Before(deadline) {
		view = proxyView(h)
		if ready(view) {
			return view
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("timed out after 5s waiting for %s; proxy view: %+v", why, view)
	return view
}

// The whole premise of the app is that installing it changes nothing. A module that
// bound a port while switched off would break that on the first run, before a user had
// chosen anything.
func TestTheProxyBindsNothingWhileItsModuleIsOff(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	view := proxyView(h)

	if view.Enabled {
		t.Error("the proxy module reports itself enabled on a fresh install")
	}
	if view.Listening != "" {
		t.Errorf("the proxy bound %s while switched off", view.Listening)
	}
	if view.Capability.Available {
		t.Error("the proxy reports itself available while switched off")
	}
	if len(view.Snippets) != 0 {
		t.Errorf("commands were offered for a proxy that is off: %+v", view.Snippets)
	}
}

// The dashboard listener binds before the node and the proxy are built, so every one of
// these is reachable with neither in place. The proxy surface has to be absent rather
// than present-and-empty: a typed nil inside a non-nil interface passes the caller's nil
// check and then panics on the first call.
func TestTheProxySurfaceIsAbsentUntilTheAgentHasBuiltOne(t *testing.T) {
	a := newUnstartedAgent(t)

	if got := a.Proxy(); got != nil {
		t.Errorf("an agent with no proxy hands out %#v, so a caller's nil check passes on nothing", got)
	}
}

// The surface handed out a moment ago outlives the proxy it names: a restart rebuilds
// both, and a request already inside one of these calls finds it gone. Each has to
// answer with what it does not have rather than dereference it.
func TestTheProxySurfaceAnswersAfterTheProxyItNamesHasGone(t *testing.T) {
	a := newUnstartedAgent(t)
	api := proxyAPI{a: a}

	if st := api.Status(); st.Listening != "" || st.Error != "" {
		t.Errorf("a proxy that does not exist reports %+v, want nothing at all", st)
	}

	script, err := api.PAC(t.Context())
	if err != nil {
		t.Fatalf("render the auto-config script with no proxy: %v", err)
	}
	if !strings.Contains(script, "FindProxyForURL") {
		t.Errorf("the script has no entry point, so a browser would ignore it:\n%s", script)
	}
	if strings.Contains(script, "SOCKS5") {
		t.Errorf("the script points a browser at a proxy that does not exist:\n%s", script)
	}
	if !strings.Contains(script, "not part of this agent") {
		t.Errorf("the script does not say why everything is direct:\n%s", script)
	}

	if _, err := api.Probe(t.Context(), "peer.tail1a2b3c.ts.net:22"); err == nil {
		t.Error("a probe through a proxy that does not exist reported an answer")
	}
}

// The node is rebuilt in place by a restart, and every dial goes through the connection
// registry rather than through a node someone captured -- which is what keeps the proxy's
// port from moving. The window where no node exists is real, and a dial into it must be
// refused rather than sent into a connection that is not there.
func TestNoConnectionCarriesAnythingBeforeTheNodeIsBuilt(t *testing.T) {
	a := newUnstartedAgent(t)

	if got := a.tunnels.All(); len(got) != 0 {
		t.Fatalf("the registry carries %d connections before a node was built", len(got))
	}

	// Standing in for this machine's own resolver, so the refusal under test is the
	// registry having nothing to ask rather than whatever DNS this machine happens to have.
	a.tunnels.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		return netip.AddrPort{}, errors.New("no such host")
	})

	if _, err := a.tunnels.Resolve(t.Context(), "tcp", "peer.tail1a2b3c.ts.net:22"); err == nil {
		t.Error("a tailnet destination was routed with no connection running")
	}
}

// The end-to-end path: a program points at the bound port, names a tailnet destination,
// and reaches it. Every layer is real here except the tailnet itself -- the SOCKS5
// server, the scope check, the classifier and the dial.
func TestAProgramReachesATailnetPeerThroughTheBoundPort(t *testing.T) {
	h := newHarness(t, proxyOn)
	peer := echoPeer(t)
	h.node.route("peer.tail1a2b3c.ts.net:22", peer)
	h.bringUp()

	view := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != "" && v.NodeUp
	})

	conn := dialThroughProxy(t, view.Listening, "peer.tail1a2b3c.ts.net:22")
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read back through the proxy: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("read %q through the proxy, want the peer's echo", buf)
	}
}

// A domain the admin console points at a private nameserver resolves nowhere but the
// tailnet's own resolver. The whole path is exercised here because the resolver is
// reached through the agent's live node rather than one captured at construction, and a
// name that resolves everywhere except through the proxy is the one failure this
// module's card cannot otherwise explain.
func TestASplitDNSNameIsReachedThroughTheProxy(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		proxyOn(c)
		proxyOf(t, c).ResolveVia = config.ResolveViaTailnet
	})
	// Routed by address alone: the name is in no netmap, which is what makes the
	// tailnet's resolver the only way to it.
	peer := echoPeer(t)
	h.node.route(peer, peer)
	host, port, err := net.SplitHostPort(peer)
	if err != nil {
		t.Fatalf("split the stand-in peer's address %q: %v", peer, err)
	}
	h.node.resolveAs("db.corp.example.com", netip.MustParseAddr(host))
	h.bringUp()

	view := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != "" && v.NodeUp
	})
	if view.ResolveVia != string(config.ResolveViaTailnet) {
		t.Errorf("resolveVia = %q, want the mode the settings asked for", view.ResolveVia)
	}

	conn := dialThroughProxy(t, view.Listening, net.JoinHostPort("db.corp.example.com", port))
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read back through the proxy: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("read %q through the proxy, want the echo from the peer the tailnet's resolver named", buf)
	}
}

// Restarting the node is how node-identity settings take effect. Rebuilding the proxy
// with it would move its port, and every shell profile, browser setting and saved
// command naming the old one would stop working -- silently, since the app would look
// perfectly healthy afterwards.
func TestTheProxyKeepsItsPortAcrossANodeRestart(t *testing.T) {
	h := newHarness(t, proxyOn)
	peer := echoPeer(t)
	h.node.route("peer:22", peer)
	h.bringUp()

	before := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})

	resp, body := h.request(http.MethodPost, "/api/restart", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/restart = %d: %s", resp.StatusCode, body)
	}
	h.bringUp()

	after := waitForProxy(h, "the proxy to be usable again", func(v httpapi.ProxyView) bool {
		return v.NodeUp
	})
	if after.Listening != before.Listening {
		t.Errorf("the proxy moved from %s to %s across a node restart", before.Listening, after.Listening)
	}
	if after.PACURL != before.PACURL {
		t.Errorf("the auto-config URL changed from %q to %q across a node restart", before.PACURL, after.PACURL)
	}

	// Still usable, not merely still bound: the proxy reaches the node indirectly, so
	// a stale reference would leave the port open and every dial failing.
	conn := dialThroughProxy(t, after.Listening, "peer:22")
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write through the proxy after a restart: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read through the proxy after a restart: %v", err)
	}
}

// The script is only worth generating because it is derived from this tailnet: its
// name domain and the subnets it reaches. A file built from constants would send the
// wrong traffic on any tailnet but the one it was written against.
func TestTheAutoConfigScriptIsBuiltFromTheTailnetsOwnState(t *testing.T) {
	h := newHarness(t, proxyOn)
	h.node.mu.Lock()
	h.node.status.MagicDNSSuffix = "tail1a2b3c.ts.net"
	h.node.subnets = []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}
	h.node.mu.Unlock()
	h.bringUp()

	view := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})

	resp, body := h.get("/proxy.pac")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy.pac = %d: %s", resp.StatusCode, body)
	}
	script := string(body)

	if !strings.Contains(script, "tail1a2b3c.ts.net") {
		t.Errorf("the script does not match this tailnet's name domain:\n%s", script)
	}
	if !strings.Contains(script, "10.42.0.0") {
		t.Errorf("the script does not carry the subnet this tailnet routes:\n%s", script)
	}
	if !strings.Contains(script, view.Listening) {
		t.Errorf("the script does not name the bound proxy address %s:\n%s", view.Listening, script)
	}
	// The tailnet's own ranges come from Tailscale's allocation rather than a guess.
	if !strings.Contains(script, "100.64.0.0") {
		t.Errorf("the script does not cover the tailnet's own addresses:\n%s", script)
	}
}

// A name on one of the connections resolves nowhere but inside this process, so a browser
// following the script has to send it to the proxy. Left out of the file it goes direct,
// and direct reaches nothing at all.
func TestTheAutoConfigScriptCarriesTheConnectionsOwnNames(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		proxyOn(c)
		c.Tunnels = append(c.Tunnels, config.Tunnel{
			ID: "tn_office", Slug: "office", Name: "Office", Type: config.TunnelWireGuard,
		})
	})
	h.bringUp()

	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.Listening != "" })

	resp, body := h.get("/proxy.pac")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy.pac = %d: %s", resp.StatusCode, body)
	}
	script := string(body)

	if !strings.Contains(script, "office."+config.DefaultDNSZone) {
		t.Errorf("the script does not match the names on the office connection:\n%s", script)
	}
}

// A PAC result line has nowhere to put a credential, so a script naming a proxy that
// requires one makes every request fail authentication. Sending traffic direct and
// saying why is the honest outcome.
func TestTheAutoConfigScriptStandsDownWhenTheProxyNeedsAPassword(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		proxyOn(c)
		held := proxyOf(t, c)
		held.RequireToken = true
		held.Token = "a-proxy-password"
	})
	h.bringUp()

	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.Listening != "" })

	resp, body := h.get("/proxy.pac")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy.pac = %d: %s", resp.StatusCode, body)
	}
	script := string(body)

	if !strings.Contains(script, "DIRECT") || strings.Contains(script, "SOCKS5") {
		t.Errorf("the script points a browser at a proxy it cannot authenticate to:\n%s", script)
	}
	if !strings.Contains(script, "password") {
		t.Errorf("the script does not say why everything is direct:\n%s", script)
	}
}

// The script is fetched by a browser whether or not the node is up, and a browser that
// cannot parse it silently sends everything direct. It has to stay a valid script.
func TestTheAutoConfigScriptIsStillServedWhileTheNodeIsDown(t *testing.T) {
	h := newHarness(t, proxyOn)
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.Listening != "" })

	h.node.setState(tsnode.StateStopped)
	waitForProxy(h, "the agent to notice the node is down", func(v httpapi.ProxyView) bool {
		return !v.NodeUp
	})

	resp, body := h.get("/proxy.pac")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy.pac = %d while the node is down: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "FindProxyForURL") {
		t.Errorf("the script has no entry point, so a browser would ignore it:\n%s", body)
	}
}

// A browser configured with the script's address keeps fetching it after the module is
// switched off. Serving nothing, or something a browser cannot parse, would leave every
// request going somewhere the user cannot predict with no way to find out why.
func TestTheAutoConfigScriptStandsDownWhileTheModuleIsOff(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	resp, body := h.get("/proxy.pac")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /proxy.pac = %d with the module off: %s", resp.StatusCode, body)
	}
	script := string(body)

	if !strings.Contains(script, "FindProxyForURL") {
		t.Errorf("the script has no entry point, so a browser would ignore it:\n%s", script)
	}
	if strings.Contains(script, "SOCKS5") {
		t.Errorf("the script points a browser at a proxy that is not running:\n%s", script)
	}
	if !strings.Contains(script, "switched off") {
		t.Errorf("the script does not say why everything is direct:\n%s", script)
	}
}

// The routes are half of what makes the script worth generating, so a script built
// without them would quietly stop sending subnet traffic through the proxy. Failing the
// request is what makes a browser keep the script it already has.
func TestNoAutoConfigScriptIsServedWhenTheRoutesCannotBeRead(t *testing.T) {
	h := newHarness(t, proxyOn)
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != "" && v.NodeUp
	})

	h.node.failRoutes(errors.New("the control plane is not answering"))

	resp, body := h.get("/proxy.pac")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a script was served without the routes it is meant to carry:\n%s", body)
	}
	if !strings.Contains(string(body), "not answering") {
		t.Errorf("the failure does not carry the reason the routes could not be read: %s", body)
	}
}

// The port stays bound while no connection is running, and the refusal says which of the
// two reasons it is. A closed port makes a user conclude the app is broken.
func TestTheProxyStaysBoundAndSaysWhyWhileTheNodeIsDown(t *testing.T) {
	h := newHarness(t, proxyOn)
	h.bringUp()
	bound := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != "" && v.NodeUp
	})

	h.node.setState(tsnode.StateStopped)
	view := waitForProxy(h, "the agent to notice the node is down", func(v httpapi.ProxyView) bool {
		return !v.NodeUp
	})

	if view.Listening != bound.Listening {
		t.Errorf("the proxy moved from %s to %s when the node went down", bound.Listening, view.Listening)
	}
	if !view.Capability.Available || !view.Capability.Degraded {
		t.Errorf("capability = %+v, want available but degraded", view.Capability)
	}
	if !strings.Contains(view.Capability.Reason, "no connection is running") {
		t.Errorf("reason = %q, want it to say no connection is carrying traffic", view.Capability.Reason)
	}

	// The port answering with a refusal is the whole reason it stays open.
	if _, err := net.DialTimeout("tcp", view.Listening, 2*time.Second); err != nil {
		t.Errorf("the proxy port is closed while the node is down: %v", err)
	}
}

// A conflict moves the listener. Writing the bound address back means the move happens
// once, so the next start reuses it and everything naming the new port keeps working.
func TestABindThatLandedElsewhereIsRecordedSoItDoesNotMoveAgain(t *testing.T) {
	// Hold a port, then ask the proxy for it.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold a port for the conflict: %v", err)
	}
	defer taken.Close()
	wanted := taken.Addr().String()

	h := newHarness(t, func(c *config.Config) {
		c.Settings.ProxyEnabled = true
		proxyOf(t, c).ListenAddr = wanted
	})
	h.bringUp()

	view := waitForProxy(h, "the proxy to fall back to another port", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})

	if view.Listening == wanted {
		t.Fatalf("the proxy bound %s, which was already held", wanted)
	}
	waitFor(t, 5*time.Second, "the bound address to be written back to the instance", func() bool {
		return storedProxy(t, h.store).ListenAddr == view.Listening
	})

	// Persisting rewrites the very setting the move was measured against, so this is
	// where a proxy that re-derived the move each time would silently drop the one
	// notice telling the user their saved snippets name a port nothing is on. Reconcile
	// again first: the settings change is itself what a real run reconciles on.
	h.node.signal()
	after := waitForProxy(h, "a reconcile against the adopted address", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})
	if after.Listening != view.Listening {
		t.Errorf("the proxy moved again, from %s to %s, once its address was persisted",
			view.Listening, after.Listening)
	}
	if !after.MovedFromConfig {
		t.Error("the proxy moved but did not report that it had")
	}
	if after.ConfiguredAddr != wanted {
		t.Errorf("ConfiguredAddr = %q, want the port that was taken (%q)", after.ConfiguredAddr, wanted)
	}
	_, takenPort, err := net.SplitHostPort(wanted)
	if err != nil {
		t.Fatalf("split the held address %q: %v", wanted, err)
	}
	if !strings.Contains(after.Capability.Reason, takenPort) {
		t.Errorf("capability reason = %q, want it to name the port that was taken (%s)",
			after.Capability.Reason, takenPort)
	}
}

// A configured port of zero asks for any free port, so landing on one is what was
// asked for -- not a conflict. Recording it would rewrite the configuration, which the
// next reconcile reads as a changed listener address and rebinds under live
// connections, moving the port again on every pass.
func TestAnyPortWasAskedForSoLandingOnOneIsNotAMove(t *testing.T) {
	h := newHarness(t, proxyOn)
	h.bringUp()

	view := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})

	if view.MovedFromConfig {
		t.Errorf("binding %s after asking for any port was reported as a move", view.Listening)
	}
	if got := storedProxy(t, h.store).ListenAddr; got != "127.0.0.1:0" {
		t.Errorf("stored proxy address = %q, want the configured %q left alone", got, "127.0.0.1:0")
	}
	if view.Capability.Degraded {
		t.Errorf("capability = %+v, want no warning for a port that was never pinned", view.Capability)
	}

	// The port has to still be the same one a moment later: a rewritten configuration
	// shows up as a rebind on the next reconcile rather than immediately.
	h.node.signal()
	time.Sleep(50 * time.Millisecond)
	if after := proxyView(h); after.Listening != view.Listening {
		t.Errorf("the proxy moved from %s to %s across a reconcile", view.Listening, after.Listening)
	}
}

// "The proxy is up" and "the proxy can reach that peer" are different questions, and
// only the second one is what someone typing an address is asking.
func TestAProbeAnswersWhetherADestinationIsActuallyReachable(t *testing.T) {
	h := newHarness(t, proxyOn)
	peer := echoPeer(t)
	h.node.route("peer:22", peer)
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.NodeUp })

	reachable := probe(h, "peer:22")
	if !reachable.Reachable {
		t.Errorf("a routed peer was reported unreachable: %+v", reachable)
	}
	if !reachable.ViaTailnet {
		t.Errorf("a tailnet peer was not reported as reached through the tailnet: %+v", reachable)
	}
	if reachable.ResolvedAddr != peer {
		t.Errorf("resolvedAddr = %q, want the address actually dialed %q", reachable.ResolvedAddr, peer)
	}

	missing := probe(h, "nowhere:22")
	if missing.Reachable {
		t.Errorf("an unrouted destination was reported reachable: %+v", missing)
	}
	if missing.Error == "" {
		t.Error("an unreachable destination came back with no reason")
	}
}

// A peer the tailnet knows about with nothing listening on the port is the ordinary
// case of a service that is down, and it has to be reported as unreachable rather than
// as an unknown destination -- the two send someone to different places: the ACLs, or
// the machine itself.
func TestAProbeSeparatesAPeerItCannotResolveFromAPortNothingAnswers(t *testing.T) {
	h := newHarness(t, proxyOn)
	// Port 1 needs privilege to bind, so nothing on the machine running this is on it.
	h.node.route("silent:22", "127.0.0.1:1")
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.NodeUp })

	result := probe(h, "silent:22")
	if result.Reachable {
		t.Errorf("a port nothing answers on was reported reachable: %+v", result)
	}
	if !result.ViaTailnet {
		t.Errorf("a peer the tailnet resolved was not reported as being on it: %+v", result)
	}
	if result.ResolvedAddr != "127.0.0.1:1" {
		t.Errorf("resolvedAddr = %q, want the address the classifier picked", result.ResolvedAddr)
	}
	if result.Error == "" {
		t.Error("the refused connection came back with no reason, leaving nothing to act on")
	}
}

// The probe's answer is "did this connection open", and it opened. A close that fails on
// the way out is a fact about the stack underneath rather than about the destination, so
// reporting it as unreachable would send someone to check a peer that answered fine.
func TestAProbeThatCouldNotHangUpStillReportsTheDestinationReachable(t *testing.T) {
	h := newHarness(t, proxyOn)
	peer := echoPeer(t)
	h.node.route("peer:22", peer)
	h.node.failCloses(errors.New("the network stack went away"))
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.NodeUp })

	result := probe(h, "peer:22")
	if !result.Reachable {
		t.Errorf("a peer that answered was reported unreachable because hanging up failed: %+v", result)
	}
	if result.Error != "" {
		t.Errorf("error = %q, want none: the destination answered", result.Error)
	}
}

// probe asks the agent to dial one destination through the proxy.
func probe(h *harness, address string) httpapi.ProxyProbeResult {
	h.t.Helper()
	resp, body := h.request(http.MethodPost, "/api/proxy/probe",
		strings.NewReader(`{"address":`+quote(address)+`}`))
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("POST /api/proxy/probe = %d: %s", resp.StatusCode, body)
	}
	var result httpapi.ProxyProbeResult
	if err := json.Unmarshal(body, &result); err != nil {
		h.t.Fatalf("decode the probe result %q: %v", body, err)
	}
	return result
}

func quote(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// dialThroughProxy reaches address the way a program run under ALL_PROXY does: the name
// is handed to the proxy rather than resolved here, which is the point of the feature.
func dialThroughProxy(t *testing.T, proxyAddr, address string) net.Conn {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build a SOCKS5 client: %v", err)
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial %s through the proxy at %s: %v", address, proxyAddr, err)
	}
	return conn
}

// echoPeer is a loopback server standing in for a tailnet peer, so a proxied connection
// is proven to carry traffic rather than merely to have been accepted.
func echoPeer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start a stand-in peer: %v", err)
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
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// The bound address is what stops the move repeating, so a write that failed has to be
// reported. Carrying on would leave the process claiming an address nothing recorded, and
// the next start would move the port again with nothing on screen saying why.
func TestABoundAddressThatCouldNotBeStoredIsReportedRatherThanAssumed(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	agent, err := New(Options{Store: store, Runtime: runtime, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// An ordinary file where the state directory was: the store recreates a missing
	// directory, so this is what a path it genuinely cannot write into looks like.
	if err := os.RemoveAll(stateDir); err != nil {
		t.Fatalf("remove the state directory: %v", err)
	}
	if err := os.WriteFile(stateDir, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatalf("put a file where the state directory was: %v", err)
	}

	err = agent.persistProxyAddr(tsproxy.Status{
		ID: config.DefaultProxyID, MovedFromConfig: true,
		Listening: "127.0.0.1:54321", ConfiguredAddr: "127.0.0.1:1080",
	})

	if err == nil {
		t.Fatal("a bound address that was never written was reported as persisted")
	}
	held, ok := store.Get().Proxy(config.DefaultProxyID)
	if !ok {
		t.Fatal("the stored document lost its proxy instance")
	}
	if held.ListenAddr == "127.0.0.1:54321" {
		t.Errorf("the process holds %q as its proxy address after the write failed", held.ListenAddr)
	}
}

// The settings this process runs on are the stored document plus flags and environment.
// An environment that no longer resolves cannot produce them, and answering with the
// zero value would silently put the whole agent on defaults -- every module off, the
// dashboard on another port -- with nothing saying it happened.
func TestSettingsThatCannotBeResolvedFailRatherThanFallingBackToDefaults(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	broken := func(key string) string {
		if key == config.EnvEphemeral {
			return "maybe"
		}
		return ""
	}
	agent, err := New(Options{Store: store, Runtime: runtime, Getenv: broken, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = agent.adoptSettings()

	if err == nil {
		t.Fatal("settings were adopted from an environment that does not resolve")
	}
	if !strings.Contains(err.Error(), config.EnvEphemeral) {
		t.Errorf("err = %v, want it to name the variable that could not be read", err)
	}
}

// Requiring a password without setting one is a state a user reaches by flipping one
// switch, and it is refused where the switch is flipped rather than at bind time. The
// refusal has to leave everything as it was: a half-applied write would take the listener
// down while this machine is still pointed at the port it was answering on, which sends
// every program's traffic into a dead socket and reads as the network being down.
func TestRequiringAPasswordWithNoneStoredIsRefusedAndChangesNothing(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		proxyOn(c)
		c.Settings.ProxySystem = true
	})
	h.bringUp()
	before := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	_, _, err := h.agent.Settings().Update(context.Background(),
		settingsPatch(t, map[string]any{"proxy.requireToken": true}))

	if err == nil {
		t.Fatal("the requirement was turned on with no password stored")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("err = %v, want it to name the missing password", err)
	}
	if got := storedProxy(t, h.store); got.RequireToken {
		t.Error("the refused requirement was stored anyway")
	}
	after := proxyView(h)
	if after.Listening != before.Listening {
		t.Errorf("the proxy moved from %q to %q on a write that was refused",
			before.Listening, after.Listening)
	}
	if after.Error != "" {
		t.Errorf("the proxy reports %q after a write that never landed", after.Error)
	}
	if pointsAt, _, clears := h.sysproxy.snapshot(); pointsAt == "" || clears != 0 {
		t.Errorf("this machine points at %q (restored %d times) after a write that was refused",
			pointsAt, clears)
	}
}

// The probe dials on the agent's behalf, so what it may reach has to be what the proxy may
// reach. Without the rules deciding first, one request to a loopback API is a connection
// from this machine to any address any connection carries -- every tailnet peer and every
// private network behind them -- which is a wider reach than the proxy the probe reports on.
func TestAProbeRefusesADestinationTheRulesDenyWithoutDialingIt(t *testing.T) {
	h := newHarness(t, proxyOn)
	peer, dials := countingPeer(t)
	h.node.route("peer:22", peer)
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.NodeUp })

	if _, err := h.agent.ProxiesAPI().SetRules(context.Background(), config.DefaultProxyID,
		[]access.Rule{
			{ID: "ar_no_peer", Action: access.Deny, Host: "peer"},
			{ID: "ar_rest", Action: access.Allow, Tunnel: config.PrimaryTunnelID},
		}); err != nil {
		t.Fatalf("setting rules: %v", err)
	}

	result := probe(h, "peer:22")
	if result.Reachable {
		t.Errorf("a destination the rules deny was reported reachable: %+v", result)
	}
	if !result.Refused {
		t.Errorf("a destination the rules deny was not reported as refused: %+v", result)
	}
	// The reason names the line that decided, in its position in the table. A refusal
	// somebody cannot trace to a rule they can edit is one they can only work around.
	if !strings.Contains(result.Error, "rule 1") || !strings.Contains(result.Error, "peer") {
		t.Errorf("the refusal said %q, which does not name the rule that decided", result.Error)
	}
	if opened := dials.Load(); opened != 0 {
		t.Errorf("the refused destination was dialed %d times, so the rules decided nothing", opened)
	}
}

// countingPeer is a stand-in peer that answers nothing and counts what reached it. What it
// proves is a negative -- that no connection was opened -- which an echo peer cannot.
func countingPeer(t *testing.T) (addr string, dials *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start a stand-in peer: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	dials = &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			conn.Close()
		}
	}()
	return ln.Addr().String(), dials
}
