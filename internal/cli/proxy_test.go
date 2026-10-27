// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// dashboardAddr is the address the fixture's PAC URL names, so a test can tell whether
// NO_PROXY kept the dashboard off the proxy.
const dashboardAddr = "127.0.0.1:8377"

// proxyRoutes answers the one endpoint every proxy command reads.
func proxyRoutes(t *testing.T, view httpapi.ProxyView) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/proxy": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, view)
		},
	}
}

// listeningView is the agent's answer for a proxy that is up and usable.
func listeningView(addr string) httpapi.ProxyView {
	// This endpoint answers for the instance the command line reaches when nothing names
	// one, which is what every way of pointing a program at a proxy applies to.
	cfg := tsproxy.SnippetConfig{
		ProxyAddr:     addr,
		DashboardAddr: dashboardAddr,
		Platform:      runtime.GOOS,
		Default:       true,
	}
	return httpapi.ProxyView{
		Enabled:        true,
		Listening:      addr,
		NodeUp:         true,
		Scope:          "tailnet",
		ScopeCarries:   "only destinations the tailnet routes",
		ConfiguredAddr: addr,
		SocksURL:       tsproxy.SOCKSURL(cfg),
		HTTPURL:        tsproxy.HTTPURL(cfg),
		PACURL:         tsproxy.PACURL(dashboardAddr),
		Capability:     httpapi.Capability{Available: true},
		Snippets:       tsproxy.Snippets(cfg),
	}
}

// offView is a proxy whose module is switched off.
func offView() httpapi.ProxyView {
	return httpapi.ProxyView{Capability: httpapi.Capability{Reason: "the proxy module is switched off"}}
}

// connectServer stands in for the proxy's HTTP front end: it reads one CONNECT request
// and hands the raw connection to serve. Answering CONNECT and then owning the same
// socket is the whole contract `proxy connect` speaks, and it cannot be exercised
// through httptest.Server, which does not hand out hijacked connections for CONNECT.
//
// serve is given the whole request rather than the destination alone, because the
// credential a client presents is part of what the front end has to be told.
func connectServer(t *testing.T, serve func(req *http.Request, conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start a stand-in proxy: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				serve(req, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// acceptAndEcho answers 200 and reflects everything back.
func acceptAndEcho(_ *http.Request, conn net.Conn) {
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// refuse answers with the proxy's own reason, the way the real front end does.
func refuse(status int, reason string) func(*http.Request, net.Conn) {
	return func(_ *http.Request, conn net.Conn) {
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n%s: %s\r\nContent-Length: 0\r\n\r\n",
			status, http.StatusText(status), tsproxy.ConnectErrorHeader, reason)
	}
}

// The tunnel is what makes `ssh -o ProxyCommand="app-tail proxy connect %h %p"` work
// on every platform, including Windows where `nc -X 5` does not exist. It has to carry
// bytes in both directions, not merely complete a handshake.
func TestProxyConnectCarriesBytesInBothDirections(t *testing.T) {
	proxyAddr := connectServer(t, acceptAndEcho)
	h := newHarness(t, proxyRoutes(t, listeningView(proxyAddr)))

	env := h.env()
	env.Stdin = strings.NewReader("SSH-2.0-app-tail\r\n")

	err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), "peer.tail1a2b3c.ts.net", "22")...), env)
	if err != nil {
		t.Fatalf("proxy connect: %v", err)
	}
	if got := h.out(); !strings.Contains(got, "SSH-2.0-app-tail") {
		t.Errorf("stdout = %q, want what was sent to come back through the tunnel", got)
	}
}

// storeConfig edits the document the CLI reads, standing in for what a user already wrote
// through the dashboard or `app-tail settings set`.
func (h *harness) storeConfig(edit func(*config.Config)) {
	h.t.Helper()
	store, err := config.Open(h.configPath)
	if err != nil {
		h.t.Fatalf("open the stored config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		edit(c)
		return nil
	}); err != nil {
		h.t.Fatalf("store the config: %v", err)
	}
}

// storeProxyPassword writes the password onto the default instance, which is the one every
// single-proxy command speaks to.
func (h *harness) storeProxyPassword(password string) {
	h.t.Helper()
	h.storeConfig(func(c *config.Config) {
		for i := range c.Proxies {
			if c.Proxies[i].ID == config.DefaultProxyID {
				c.Proxies[i].RequireToken = true
				c.Proxies[i].Token = password
				return
			}
		}
		h.t.Fatalf("the stored config carries no %q proxy", config.DefaultProxyID)
	})
}

// A ProxyCommand has nowhere to type a password, so the one in the settings is the only
// one there will ever be. Without this, turning the proxy password on silently breaks
// every `ssh -o ProxyCommand="app-tail proxy connect %h %p"` already in a config file.
func TestProxyConnectPresentsTheStoredPassword(t *testing.T) {
	presented := make(chan string, 1)
	proxyAddr := connectServer(t, func(req *http.Request, conn net.Conn) {
		presented <- req.Header.Get("Proxy-Authorization")
		acceptAndEcho(req, conn)
	})

	view := listeningView(proxyAddr)
	view.RequiresPassword = true
	h := newHarness(t, proxyRoutes(t, view))
	h.storeProxyPassword("correct-horse")

	env := h.env()
	env.Stdin = strings.NewReader("SSH-2.0-app-tail\r\n")

	if err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), "peer", "22")...), env); err != nil {
		t.Fatalf("proxy connect through a password-protected proxy: %v", err)
	}

	header := <-presented
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(tsproxy.ProxyUser+":correct-horse"))
	if header != want {
		t.Errorf("Proxy-Authorization = %q, want the stored password as %q", header, want)
	}
	if got := h.out(); !strings.Contains(got, "SSH-2.0-app-tail") {
		t.Errorf("stdout = %q, want the tunnel to have carried traffic", got)
	}
}

// Opening a tunnel that is certain to be refused, and reporting the refusal as the
// proxy's, would send someone looking at the wrong machine. The missing password is
// something only this side knows about, and it names the command that sets one.
func TestProxyConnectSaysWhenTheRequiredPasswordIsNotStored(t *testing.T) {
	reached := make(chan struct{}, 1)
	proxyAddr := connectServer(t, func(req *http.Request, conn net.Conn) {
		reached <- struct{}{}
		acceptAndEcho(req, conn)
	})

	view := listeningView(proxyAddr)
	view.RequiresPassword = true
	h := newHarness(t, proxyRoutes(t, view))

	err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), "peer", "22")...), h.env())
	if err == nil {
		t.Fatal("a tunnel was opened with a password the proxy requires and this side does not have")
	}
	if !strings.Contains(err.Error(), "settings set proxy.token") {
		t.Errorf("err = %v, want it to name the command that stores a password", err)
	}
	select {
	case <-reached:
		t.Error("the proxy was dialed anyway, so the refusal will read as the proxy's fault")
	default:
	}
}

// A proxy the agent reports as listening on an address nothing answers is what a stale
// recorded address looks like. Naming the address is what separates it from a
// destination that is simply unreachable.
func TestProxyConnectNamesTheProxyItCouldNotReach(t *testing.T) {
	// Port 1 needs privilege to bind, so nothing on the machine running this is on it.
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1")))

	err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), "peer", "22")...), h.env())
	if err == nil {
		t.Fatal("proxy connect reported success against a proxy that is not there")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("err = %v, want it to name the proxy address it could not reach", err)
	}
}

// A proxy that goes away between the dial and the request is what a restarting agent
// looks like from here. The socket has to go back with the error: `proxy connect` is what
// an ssh config runs, so a leaked one is held for as long as the ssh session lives.
func TestATunnelRequestThatCouldNotBeSentGivesTheSocketBack(t *testing.T) {
	conn := &recordingConn{writeErr: errors.New("broken pipe")}
	dial := func(context.Context, string, string) (net.Conn, error) { return conn, nil }

	got, err := connectThrough(t.Context(), dial, "127.0.0.1:1080", "peer:22", "")
	if err == nil {
		t.Fatal("a tunnel was returned over a request that was never sent")
	}
	if got != nil {
		t.Errorf("connectThrough = %v beside an error, want no tunnel at all", got)
	}
	if !strings.Contains(err.Error(), "peer:22") {
		t.Errorf("err = %v, want it to name the destination that was being asked for", err)
	}
	if !strings.Contains(err.Error(), "broken pipe") {
		t.Errorf("err = %v, want it to carry why the request could not be sent", err)
	}
	if !conn.closed {
		t.Error("the connection to the proxy was left open after the request failed")
	}
}

// recordingConn is a connection that fails to write and remembers being closed. Only the
// two methods connectThrough reaches before it gives up are implemented; anything else
// reaching this fake is a call the tunnel setup should not be making.
type recordingConn struct {
	net.Conn
	writeErr error
	closed   bool
}

func (c *recordingConn) Write([]byte) (int, error) { return 0, c.writeErr }

func (c *recordingConn) Close() error {
	c.closed = true
	return nil
}

// A peer that greets first -- SSH does -- sends its banner in the same TCP segment as
// the proxy's 200, so the response reader buffers it. Handing the bare connection on
// from there drops those bytes, and the failure looks like a hung SSH rather than a
// dropped read.
func TestProxyConnectKeepsBytesThatArrivedWithTheProxysAnswer(t *testing.T) {
	proxyAddr := connectServer(t, func(_ *http.Request, conn net.Conn) {
		// One Write, so the answer and the banner land in the same read.
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-peer\r\n"))
	})
	h := newHarness(t, proxyRoutes(t, listeningView(proxyAddr)))

	env := h.env()
	env.Stdin = strings.NewReader("")

	if err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), "peer", "22")...), env); err != nil {
		t.Fatalf("proxy connect: %v", err)
	}
	if got := h.out(); !strings.Contains(got, "SSH-2.0-peer") {
		t.Errorf("stdout = %q, want the banner that arrived with the proxy's answer", got)
	}
}

// The proxy already knows which of "the node is down" and "that is out of scope"
// applies, and the two call for opposite actions. Collapsing them into a bare
// connection error is what leaves a user with nothing to act on.
func TestProxyConnectReportsTheProxysOwnRefusal(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{"out of scope", http.StatusForbidden, "example.com is not a tailnet destination"},
		{"node down", http.StatusServiceUnavailable, "the tailnet node is not running"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxyAddr := connectServer(t, refuse(tc.status, tc.reason))
			h := newHarness(t, proxyRoutes(t, listeningView(proxyAddr)))

			env := h.env()
			env.Stdin = strings.NewReader("")
			err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), "example.com", "443")...), env)

			if err == nil {
				t.Fatal("a refused destination reported success")
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("err = %v, want the proxy's own reason %q", err, tc.reason)
			}
		})
	}
}

// Pointing a program at a proxy that is off would otherwise produce a connection error
// naming a closed port, which reads as a broken app rather than as a module the user
// has not switched on.
func TestProxyCommandsSayHowToTurnTheProxyOn(t *testing.T) {
	tests := []struct {
		name string
		// command is everything up to where --config goes, and rest is what follows it:
		// the flag has to sit after the subcommand and before a terminating --, or the
		// flag set never sees it.
		command, rest []string
	}{
		{"connect", []string{"proxy", "connect"}, []string{"peer", "22"}},
		{"exec", []string{"exec"}, []string{"--", "true"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, proxyRoutes(t, offView()))

			err := Run(t.Context(), invocation(tc.command, h.cfg(), tc.rest), h.env())

			if err == nil {
				t.Fatal("the command ran with the proxy switched off")
			}
			if !strings.Contains(err.Error(), "proxy.enabled") {
				t.Errorf("err = %v, want it to name the setting that turns the proxy on", err)
			}
		})
	}
}

// A proxy that is on but could not bind needs its own explanation: "turn it on" is
// wrong advice, since it already is.
func TestProxyConnectExplainsAProxyThatCouldNotBind(t *testing.T) {
	view := httpapi.ProxyView{
		Enabled:    true,
		Capability: httpapi.Capability{Reason: "listen tcp 127.0.0.1:1080: address already in use"},
	}
	h := newHarness(t, proxyRoutes(t, view))

	err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), "peer", "22")...), h.env())
	if err == nil {
		t.Fatal("connect ran against a proxy that never bound")
	}
	if !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("err = %v, want the agent's bind failure", err)
	}
	if strings.Contains(err.Error(), "proxy.enabled") {
		t.Errorf("err = %v, telling the user to switch on a module that is already on", err)
	}
}

// A swapped host and port is a mistake in the command, not a failure to reach a peer,
// so it must be caught before anything dials.
func TestProxyConnectChecksItsArguments(t *testing.T) {
	tests := [][]string{
		{},
		{"peer"},
		{"peer", "not-a-port"},
		{"peer", "22", "extra"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1")))

			err := Run(t.Context(), append([]string{"proxy", "connect"}, append(h.cfg(), args...)...), h.env())
			if !errors.Is(err, ErrUsage) {
				t.Errorf("err = %v, want a usage error", err)
			}
		})
	}
}

func TestProxySubcommandsAreRequiredAndChecked(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1")))
	for _, args := range [][]string{{"proxy"}, {"proxy", "frobnicate"}} {
		if err := Run(t.Context(), append(args, h.cfg()...), h.env()); !errors.Is(err, ErrUsage) {
			t.Errorf("%v gave %v, want a usage error", args, err)
		}
	}
}

// The status output is where a user finds the commands to paste. Rendering the state
// without them leaves them to assemble a socks5h URL by hand.
func TestProxyStatusShowsWhereItListensAndHowToUseIt(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

	if err := Run(t.Context(), append([]string{"proxy", "status"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	out := h.out()
	for _, want := range []string{
		"127.0.0.1:1080",
		"socks5h://127.0.0.1:1080",
		"http://" + dashboardAddr + "/proxy.pac",
		"app-tail proxy connect %h %p",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("proxy status output is missing %q:\n%s", want, out)
		}
	}
}

func TestProxyStatusSaysWhenTheProxyIsOff(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, offView()))

	if err := Run(t.Context(), append([]string{"proxy", "status"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	if !strings.Contains(h.out(), "proxy.enabled") {
		t.Errorf("proxy status does not say how to turn the proxy on:\n%s", h.out())
	}
}

// A destination that cannot be reached is the probe's answer and the command's failure:
// a script running `app-tail proxy probe` needs the exit status to mean something.
func TestProxyProbeReportsReachabilityBothWays(t *testing.T) {
	tests := []struct {
		name    string
		result  httpapi.ProxyProbeResult
		wantErr bool
		want    string
	}{
		{
			name: "reachable",
			result: httpapi.ProxyProbeResult{
				Address: "peer:22", Reachable: true, ViaTailnet: true,
				ResolvedAddr: "100.64.0.7:22", ElapsedMs: 12,
			},
			want: "100.64.0.7:22",
		},
		{
			name:    "refused",
			result:  httpapi.ProxyProbeResult{Address: "peer:22", Error: "no such host"},
			wantErr: true,
			want:    "no such host",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, map[string]http.HandlerFunc{
				"POST /api/proxy/probe": func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(t, w, http.StatusOK, tc.result)
				},
			})

			err := Run(t.Context(), append([]string{"proxy", "probe"}, append(h.cfg(), "peer:22")...), h.env())
			if tc.wantErr {
				if err == nil {
					t.Fatal("an unreachable destination reported success")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("err = %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("proxy probe: %v", err)
			}
			if !strings.Contains(h.out(), tc.want) {
				t.Errorf("probe output is missing %q:\n%s", tc.want, h.out())
			}
		})
	}
}

// Tools disagree about which variable and which case they read, and a tool that reads
// only the form we omitted bypasses the proxy silently -- resolving and connecting
// direct, which is the one outcome the module exists to prevent.
func TestEveryProxyVariableAToolMightReadIsSet(t *testing.T) {
	view := listeningView("127.0.0.1:1080")
	got := map[string]string{}
	for _, entry := range proxyEnv(view, "") {
		name, value, _ := strings.Cut(entry, "=")
		got[name] = value
	}

	for _, name := range []string{"ALL_PROXY", "all_proxy"} {
		if got[name] != "socks5h://127.0.0.1:1080" {
			t.Errorf("%s = %q, want the socks5h form so the proxy resolves the name", name, got[name])
		}
	}
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if got[name] != "http://127.0.0.1:1080" {
			t.Errorf("%s = %q, want the HTTP front end", name, got[name])
		}
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		// Without the dashboard here, a child that calls the app-tail API sends that
		// call through the proxy, back to this same machine.
		if !strings.Contains(got[name], dashboardAddr) {
			t.Errorf("%s = %q, want it to keep the dashboard off the proxy", name, got[name])
		}
		if !strings.Contains(got[name], "127.0.0.1") {
			t.Errorf("%s = %q, want it to keep loopback off the proxy", name, got[name])
		}
	}
}

// The API hands out a stand-in so no secret travels on it; the CLI is where a real
// credential is substituted. Shipping the placeholder to the child would authenticate as
// the literal word PASSWORD and fail every connection.
func TestTheChildGetsTheCredentialNotThePlaceholder(t *testing.T) {
	view := listeningView("127.0.0.1:1080")
	view.RequiresPassword = true
	cfg := tsproxy.SnippetConfig{ProxyAddr: view.Listening, RequiresPassword: true}
	view.SocksURL, view.HTTPURL = tsproxy.SOCKSURL(cfg), tsproxy.HTTPURL(cfg)

	for _, entry := range proxyEnv(view, "s3cret") {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasSuffix(name, "PROXY") || strings.HasSuffix(name, "proxy") {
			if name == "NO_PROXY" || name == "no_proxy" {
				continue
			}
			if strings.Contains(value, "PASSWORD") {
				t.Errorf("%s = %q still carries the placeholder", name, value)
			}
			if !strings.Contains(value, "s3cret") {
				t.Errorf("%s = %q does not carry the real password", name, value)
			}
		}
	}
}

// An environment is not a private place: it is inherited by everything the command starts,
// printed by crash reporters and build logs, and readable by this account's other
// processes. The password that opens this account's proxy for as long as it is set may
// therefore not be in there -- what goes in is a credential minted for this one command,
// opening a proxy that stops existing when the command does.
func TestExecKeepsTheStoredProxyPasswordOutOfTheChildsEnvironment(t *testing.T) {
	view := listeningView("127.0.0.1:1080")
	view.RequiresPassword = true
	h := newHarness(t, proxyRoutes(t, view))
	h.storeProxyPassword("correct-horse")

	args := invocation([]string{"exec"}, h.cfg(), []string{"--"}, printEnvCommand())
	if err := Run(t.Context(), args, h.env()); err != nil {
		t.Fatalf("exec: %v", err)
	}

	out := h.out()
	if strings.Contains(out, "correct-horse") {
		t.Errorf("the stored proxy password reached the child's environment:\n%s", out)
	}
	// The proxy itself takes that password and nothing else, so a child pointed straight at
	// it would be pointed at something it cannot open.
	if strings.Contains(out, "127.0.0.1:1080") {
		t.Errorf("the child was pointed at the proxy itself rather than at the one opened for it:\n%s", out)
	}
	if !strings.Contains(out, "socks5h://"+tsproxy.ProxyUser+":") {
		t.Errorf("the child's environment carries no credential at all:\n%s", out)
	}
}

// The variables are useless unless the child process actually receives them.
func TestExecPassesTheProxyToTheCommandItRuns(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

	args := invocation([]string{"exec"}, h.cfg(), []string{"--"}, printEnvCommand())
	if err := Run(t.Context(), args, h.env()); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(h.out(), "socks5h://127.0.0.1:1080") {
		t.Errorf("the child's environment does not carry the proxy:\n%s", h.out())
	}
}

// The shell that invoked app-tail has to see the status the command itself chose, or
// every failing build run under `app-tail exec` looks like a proxy failure.
func TestExecPassesTheCommandsOwnExitStatusThrough(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

	args := invocation([]string{"exec"}, h.cfg(), []string{"--"}, exitCommand(3))
	err := Run(t.Context(), args, h.env())

	var exited *ExitError
	if !errors.As(err, &exited) {
		t.Fatalf("err = %v, want an ExitError carrying the child's status", err)
	}
	if exited.Code != 3 {
		t.Errorf("exit code = %d, want 3", exited.Code)
	}
}

// What a proxy carries is a property of the proxy, not of one connection, and SOCKS5 has
// no channel to carry a per-connection one. Widening it for the duration of a command
// would leave the proxy carrying everything if this process were killed -- so the flag
// refuses instead, and says what has to change to widen it deliberately.
func TestExecRefusesRatherThanWideningTheProxyForOneCommand(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

	args := invocation([]string{"exec"}, h.cfg(), []string{"--scope", "all", "--"}, trueCommand())
	err := Run(t.Context(), args, h.env())

	if err == nil {
		t.Fatal("a command requiring the wide grant ran against a proxy that does not have it")
	}
	// A refusal that does not say what to change leaves the user with nothing to do but
	// drop the flag, which is the outcome the flag exists to prevent.
	if !strings.Contains(err.Error(), "rule that reaches this machine") {
		t.Errorf("err = %v, want it to name the change that widens what the proxy carries", err)
	}
	// The refusal is the point: nothing may have changed the proxy on the way out.
	for _, req := range h.recorded() {
		if req.Method != http.MethodGet {
			t.Errorf("the refusal made a %s request to %s", req.Method, req.Path)
		}
	}
}

func TestScopeRequirementsAreCheckedAgainstWhatTheProxyCarries(t *testing.T) {
	tests := []struct {
		required, actual string
		wantErr          bool
	}{
		{"", "tailnet", false},
		// Every scope carries the tailnet, so requiring it always holds.
		{"tailnet", "tailnet", false},
		{"tailnet", "all", false},
		{"all", "all", false},
		{"all", "tailnet", true},
		{"sideways", "all", true},
	}
	for _, tc := range tests {
		t.Run(tc.required+"/"+tc.actual, func(t *testing.T) {
			err := scopeSatisfies(tc.required, tc.actual)
			if (err != nil) != tc.wantErr {
				t.Errorf("scopeSatisfies(%q, %q) = %v, wantErr %v", tc.required, tc.actual, err, tc.wantErr)
			}
		})
	}
}

func TestExecNeedsACommandToRun(t *testing.T) {
	h := newHarness(t, proxyRoutes(t, listeningView("127.0.0.1:1080")))

	if err := Run(t.Context(), append([]string{"exec"}, h.cfg()...), h.env()); !errors.Is(err, ErrUsage) {
		t.Errorf("err = %v, want a usage error", err)
	}
}

// invocation joins the parts of a command line into one fresh slice. Nested appends
// across table rows share a backing array, which silently rewrites a later row's
// arguments with an earlier row's.
func invocation(parts ...[]string) []string {
	var out []string
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// The child-process commands below are the same trivial programs on each platform,
// named differently. cmd.exe has no `true` and no `env`.
func printEnvCommand() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/c", "set"}
	}
	return []string{"sh", "-c", "env"}
}

func exitCommand(code int) []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/c", fmt.Sprintf("exit %d", code)}
	}
	return []string{"sh", "-c", fmt.Sprintf("exit %d", code)}
}

func trueCommand() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/c", "exit 0"}
	}
	return []string{"true"}
}
