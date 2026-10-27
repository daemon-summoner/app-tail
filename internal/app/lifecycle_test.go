// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/telemetry"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// --- construction ---------------------------------------------------------

// The store is the agent's only non-optional dependency: without it there is nothing
// to read forwards from and nothing to persist the bound address to. Building anyway
// would panic on the first request instead of failing at startup where it is visible.
func TestNewRefusesToBuildAnAgentWithoutAConfigStore(t *testing.T) {
	agent, err := New(Options{})

	if err == nil {
		t.Fatal("New succeeded with no store")
	}
	if agent != nil {
		t.Errorf("New returned an agent alongside its error: %+v", agent)
	}
	if !strings.Contains(err.Error(), "config store") {
		t.Errorf("err = %v, want it to name the missing store", err)
	}
}

// Every optional dependency has a default, and the defaults are what a caller that
// supplies only a store gets. A nil one reaching a hot path is a nil dereference on
// the first status poll, long after startup reported success.
func TestNewFillsInEveryDependencyTheCallerOmitted(t *testing.T) {
	agent := newIdleAgent(t)

	if agent.logger == nil {
		t.Error("logger is nil; the first log line taken would panic")
	}
	if agent.getenv == nil {
		t.Error("getenv is nil; resolving settings would panic")
	}
	if agent.newNode == nil {
		t.Fatal("newNode is nil; start would panic before it ever reached the control plane")
	}
	// The default has to build a real node, not merely be non-nil.
	if node := agent.newNode(tsnode.Options{Logger: quietLogger()}); node == nil {
		t.Error("the default node factory returned nil")
	}

	// The channels are what the lifecycle goroutine selects on. A nil one blocks
	// forever, which reads as a hung agent rather than a crash.
	for name, ch := range map[string]bool{
		"reconcile":     agent.reconcile == nil,
		"syncReconcile": agent.syncReconcile == nil,
		"restart":       agent.restart == nil,
		"stopping":      agent.stopping == nil,
		"stopped":       agent.stopped == nil,
	} {
		if ch {
			t.Errorf("%s channel is nil; a select on it parks forever", name)
		}
	}
}

// The tray and the dashboard opener both guard on `Node() != nil`. Returning the
// interface-wrapped nil pointer directly would make that check pass and the very next
// method call panic in the menu-bar goroutine, taking the whole process with it.
func TestNodeReportsAnUntypedNilBeforeTheAgentBuildsOne(t *testing.T) {
	agent := newIdleAgent(t)

	if node := agent.Node(); node != nil {
		t.Fatalf("Node() = %#v before Run, want an untyped nil the caller's == nil sees", node)
	}
}

// The same guard on the other side: once the node exists the tray must see it, or the
// menu shows "still starting" for the life of the process.
func TestNodeReportsTheNodeOnceRunHasBuiltIt(t *testing.T) {
	h := newHarness(t, nil)

	node := h.agent.Node()
	if node == nil {
		t.Fatal("Node() is nil after the agent started")
	}
	if got := node.Status().BackendState; got == "" {
		t.Error("the published node reports no backend state")
	}
}

// Autostart is genuinely absent on platforms with no login item, and the tray reads
// that as "hide the menu entry". A typed nil here would show the entry and fail on use.
func TestAutostartIsAnUntypedNilWhenThePlatformHasNone(t *testing.T) {
	agent := newIdleAgent(t)

	if manager := agent.Autostart(); manager != nil {
		t.Errorf("Autostart() = %#v with none configured, want an untyped nil", manager)
	}
}

// --- dashboard address ----------------------------------------------------

// A browser cannot open http://0.0.0.0:8377. The agent binds the wildcard when the
// user asks for it, so the URL handed to the tray and printed by the CLI has to be
// rewritten or every "open dashboard" lands on a connection error.
func TestDashboardURLRewritesAnUnspecifiedBindToSomethingABrowserCanOpen(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"loopback is left alone", tcpAddr("127.0.0.1", 8377), "http://127.0.0.1:8377"},
		{"ipv4 wildcard", tcpAddr("0.0.0.0", 8377), "http://" + net.JoinHostPort(config.DefaultBindAddr, "8377")},
		{"ipv6 wildcard", tcpAddr("::", 8377), "http://" + net.JoinHostPort(config.DefaultBindAddr, "8377")},
		{"ipv6 loopback keeps its brackets", tcpAddr("::1", 8377), "http://[::1]:8377"},
		// A non-host:port address has no port to rewrite; passing it through beats
		// returning nothing, because the caller can still show the user where to look.
		{"an address with no port", unixAddr("/tmp/agent.sock"), "http:///tmp/agent.sock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := newIdleAgent(t)
			agent.mu.Lock()
			agent.uiAddr = tt.addr
			agent.mu.Unlock()

			if got := agent.DashboardURL(); got != tt.want {
				t.Errorf("DashboardURL = %q, want %q", got, tt.want)
			}
		})
	}
}

// Every "open the dashboard" goes through this link, so it has to sign the browser in once,
// keep the query that picks the page, and point at the address the agent is on.
func TestADashboardLaunchURLSignsTheBrowserInOnceAndKeepsItsQuery(t *testing.T) {
	h := newHarness(t, nil)

	link, err := h.agent.DashboardLaunchURL("?section=dns")
	if err != nil {
		t.Fatalf("DashboardLaunchURL: %v", err)
	}
	if !strings.HasPrefix(link, h.baseURL+"/?") {
		t.Fatalf("launch URL %q is not on the dashboard at %s", link, h.baseURL)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	if got := parsed.Query().Get("section"); got != "dns" {
		t.Errorf("section = %q, want the caller's query kept", got)
	}
	launch := parsed.Query().Get("launch")
	if launch == "" {
		t.Fatalf("launch URL %q carries no launch token", link)
	}

	exchange := func() *http.Response {
		t.Helper()
		resp, err := http.Post(h.baseURL+"/api/auth/session", "application/json",
			strings.NewReader(`{"launch":"`+launch+`"}`))
		if err != nil {
			t.Fatalf("exchange the launch token: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	resp := exchange()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode the session: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, h.baseURL+"/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+body.Session)
	status, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/status with the session: %v", err)
	}
	status.Body.Close()
	if status.StatusCode != http.StatusOK {
		t.Errorf("GET /api/status with the session = %d, want 200", status.StatusCode)
	}

	if again := exchange(); again.StatusCode != http.StatusUnauthorized {
		t.Errorf("a second exchange of the same launch token = %d, want 401", again.StatusCode)
	}
}

func TestADashboardLaunchURLBeforeTheAgentListensIsAnError(t *testing.T) {
	if link, err := newIdleAgent(t).DashboardLaunchURL(""); err == nil {
		t.Errorf("DashboardLaunchURL on an agent that never started = %q, want an error", link)
	}
}

// portOf feeds the forward engine's local-port bookkeeping. Anything it cannot parse
// has to come back as 0 -- "no port" -- because a garbage number would reserve a port
// nothing is listening on and refuse the next forward that legitimately wants it.
func TestPortOfReadsAPortOrReportsNone(t *testing.T) {
	tests := []struct {
		addr string
		want int
	}{
		{"127.0.0.1:8377", 8377},
		{"[::1]:8377", 8377},
		{":8377", 8377},
		{"0.0.0.0:0", 0},
		{"127.0.0.1", 0},
		{"", 0},
		{"127.0.0.1:http", 0},
		{"127.0.0.1:-1", -1},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := portOf(tt.addr); got != tt.want {
				t.Errorf("portOf(%q) = %d, want %d", tt.addr, got, tt.want)
			}
		})
	}
}

// --- listener fallback ----------------------------------------------------

// Something else holding the configured port must not cost the user their dashboard:
// without it there is no way left to reach the agent and fix the setting. Where it landed
// is recorded beside the config so the CLI and tray still find it, and the configured
// address is left alone -- a port taken for a moment, by the instance being replaced on a
// restart or by anything else, would otherwise replace the setting for good.
func TestAConfiguredDashboardPortThatIsTakenFallsBackToAnOSAssignedOne(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the blocking listener: %v", err)
	}
	defer blocker.Close()
	taken := blocker.Addr().String()

	h := newHarness(t, func(c *config.Config) { c.Settings.UIListen = taken })

	bound := h.agent.UIAddr()
	if bound == nil {
		t.Fatal("the agent bound nothing at all")
	}
	if bound.String() == taken {
		t.Fatalf("the agent claims to have bound %s, which is still held elsewhere", taken)
	}
	if portOf(bound.String()) == 0 {
		t.Errorf("fell back to %s, which carries no usable port", bound)
	}
	if recorded := config.ReadDashboardAddr(h.store.Path()); recorded != bound.String() {
		t.Errorf("the record names %q, want the address actually bound (%s); the CLI "+
			"and tray would keep looking for the agent on the old port", recorded, bound)
	}
	if stored := h.store.Settings().UIListen; stored != taken {
		t.Errorf("stored UIListen = %q, want the configured %q left as the user wrote it",
			stored, taken)
	}
}

// The settings screen goes on showing the configured address, which is the one the next
// start asks for again, so nothing else on any surface says the app is answering
// somewhere else for this run.
func TestADashboardThatCouldNotHaveItsConfiguredPortSaysSo(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the blocking listener: %v", err)
	}
	defer blocker.Close()
	taken := blocker.Addr().String()

	h := recordingHarness(t, func(c *config.Config) { c.Settings.UIListen = taken })

	moved := h.agent.Moved()
	if moved == nil {
		t.Fatal("the dashboard moved to a port nobody chose and reports nothing about it")
	}
	if moved.Configured != taken {
		t.Errorf("reports %q as the configured address, want %q", moved.Configured, taken)
	}
	if bound := h.agent.UIAddr().String(); moved.Bound != bound {
		t.Errorf("reports %q as the address it is on, but it is on %s", moved.Bound, bound)
	}
	if moved.Reason == "" {
		t.Error("reports no reason, which leaves the user nothing to fix")
	}

	// ...and it is still there an hour later, when the user notices the dashboard is not
	// where they left it.
	event := waitForEvent(h, telemetry.CodeDashboardMoved)
	if event.Fields["configured"] != taken {
		t.Errorf("the log entry names %q as the configured address, want %q",
			event.Fields["configured"], taken)
	}
}

// A dashboard that is where it was asked to be must say nothing: a notice that is always
// on screen is one nobody reads on the day it matters.
func TestADashboardOnTheAddressItWasAskedForReportsNoMove(t *testing.T) {
	h := newHarness(t, nil)

	if moved := h.agent.Moved(); moved != nil {
		t.Errorf("reports a move to %q with nothing having moved", moved.Bound)
	}
}

// The fallback exists only for a taken port. An address the OS will never let the
// agent bind -- a host that is not this machine's -- has no second attempt to make,
// and reporting it is the only way the user learns the setting is wrong.
func TestABindFailureWithNoUsableFallbackIsReported(t *testing.T) {
	tests := []struct {
		name       string
		addr       string
		wantDetail string
	}{
		// Already asking for port 0: the fallback would be the identical request.
		{"an unroutable host on an os-assigned port", "192.0.2.1:0", "192.0.2.1"},
		{"an address with no port at all", "127.0.0.1", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := t.TempDir()
			store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			agent.api = newAPIServer(t)

			err = agent.listenUI(tt.addr)
			if err == nil {
				t.Fatalf("listenUI(%q) succeeded", tt.addr)
			}
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Errorf("err = %v, want it to name %q so the user can find the setting",
					err, tt.wantDetail)
			}
			if agent.UIAddr() != nil {
				t.Errorf("UIAddr = %v after a failed bind, want nil", agent.UIAddr())
			}
		})
	}
}

// --- start failures -------------------------------------------------------

// A secret file the agent cannot read is a misconfiguration, not a reason to enroll
// anonymously: starting without the credential would register an untagged device on
// the tailnet that the policy file grants nothing.
func TestAnUnreadableCredentialFileStopsTheAgentBeforeItTouchesTheTailnet(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	missing := filepath.Join(stateDir, "no-such-secret")
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	runtimeTailnetOf(t, &runtime).OAuthClientSecretFile = missing

	node := newFakeNode()
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	runErr := agent.Run(context.Background())

	if runErr == nil {
		t.Fatal("the agent ran with a credential file it could not read")
	}
	if !strings.Contains(runErr.Error(), "oauthClientSecretFile") {
		t.Errorf("err = %v, want it to name the unreadable file", runErr)
	}
	if node.wasStarted() {
		t.Error("the node was started despite the missing credential")
	}
	// Run must still close a.stopped, or a RestartNode issued afterwards parks forever.
	select {
	case <-agent.stopped:
	default:
		t.Error("Run returned without finishing shutdown; a later RestartNode would hang")
	}
}

// The management server is the only way to control a running agent. If it dies the
// agent has to come down with it, loudly -- an agent still forwarding traffic that
// nobody can reach or stop is worse than one that exited.
func TestTheAgentStopsWhenItsManagementServerDies(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtimeCfg, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	node := newFakeNode()
	agent, err := New(Options{
		Store:   store,
		Runtime: runtimeCfg,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its node", node.wasStarted)

	// Stopping the server from underneath the run loop is what a management server
	// that died looks like: Serve returns and the loop has to notice.
	if err := agent.currentAPI().Shutdown(context.Background()); err != nil {
		t.Fatalf("stop the management server: %v", err)
	}

	select {
	case err := <-runErr:
		// A graceful stop is not a fault, so Run exits cleanly here. What matters is
		// that it exits at all rather than forwarding traffic nobody can reach or stop.
		if err != nil && !strings.Contains(err.Error(), "management server stopped") {
			t.Errorf("Run returned %v, want a clean exit or the management-server reason", err)
		}
		if !node.wasClosed() {
			t.Error("the tailnet identity was left registered after the agent gave up")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent kept running after its management server stopped")
	}
}

// Shutdown reports a node that would not release its tailnet identity: the state
// directory stays locked, so the next start of the agent fails for a reason that has
// nothing to do with the next start.
func TestANodeThatWillNotCloseIsReportedByShutdown(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	node := newFakeNode()
	node.closeErr = errors.New("state directory is still locked")
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its node", node.wasStarted)
	cancel()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run reported a clean exit over a node that would not close")
		}
		if !strings.Contains(err.Error(), "state directory is still locked") {
			t.Errorf("err = %v, want the node's own close failure", err)
		}
		if !strings.Contains(err.Error(), "close tailnet node") {
			t.Errorf("err = %v, want it to say which step failed", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run never returned")
	}
}

// A restart is a close and a rebuild. The close failing is worth a warning but not a
// refusal: the replacement node is what the user asked for, and refusing would leave
// them with the identity they were trying to change.
func TestARestartWhoseOldNodeWillNotCloseStillBringsUpTheNewOne(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	first := newFakeNode()
	first.closeErr = errors.New("the backend did not acknowledge the shutdown")
	second := newFakeNode()

	built := 0
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController {
			built++
			if built == 1 {
				return first
			}
			return second
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its first node", first.wasStarted)

	if err := agent.RestartNode(context.Background()); err != nil {
		t.Fatalf("RestartNode = %v; a close failure must not block the rebuild", err)
	}
	if !second.wasStarted() {
		t.Error("the replacement node was never started")
	}
	if agent.nodeProblem() != "" {
		t.Errorf("nodeErr = %q after a successful rebuild, want it cleared", agent.nodeProblem())
	}

	cancel()
	// The second node's own close is clean, so the run exits reporting only what the
	// final teardown found.
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run = %v after a successful restart", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run never returned")
	}
}

// A rebuild that cannot start the replacement leaves the node down, and the reason is
// the only thing standing between the user and a dashboard that says "not running"
// with no explanation.
func TestARestartThatCannotStartTheNewNodeRecordsWhy(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	first := newFakeNode()
	second := newFakeNode()
	second.startErr = errors.New("control plane refused the auth key")

	built := 0
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController {
			built++
			if built == 1 {
				return first
			}
			return second
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its first node", first.wasStarted)

	err = agent.RestartNode(context.Background())

	if err == nil {
		t.Fatal("RestartNode reported success over a node that never started")
	}
	if !strings.Contains(err.Error(), "restart tailnet node") {
		t.Errorf("err = %v, want it to name the step that failed", err)
	}
	if problem := agent.nodeProblem(); !strings.Contains(problem, "refused the auth key") {
		t.Errorf("recorded problem = %q, want the control plane's own reason; the "+
			"dashboard has nothing else to show", problem)
	}
	if !first.wasClosed() {
		t.Error("the previous node was left holding the state directory")
	}

	cancel()
	<-runErr
}

// --- persistence ----------------------------------------------------------

// The bound address is how the CLI and the tray find a running agent. A state directory
// the agent cannot write is a real condition -- read-only, or a full disk -- and starting
// anyway would leave every later `app-tail status` looking at the wrong port with no
// indication why.
func TestAnUnwritableStateDirStopsTheAgentRatherThanLosingTheBoundAddress(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bits this test depends on")
	}
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce the directory write bit the same way")
	}

	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	agent.api = newAPIServer(t)

	// The store writes through a temp file in the same directory, so revoking write
	// permission on the directory is what a read-only state dir looks like.
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatalf("make the state dir read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(stateDir, 0o700) })

	err = agent.listenUI("127.0.0.1:0")

	if err == nil {
		t.Fatal("listenUI succeeded over a state directory it could not write")
	}
	if !strings.Contains(err.Error(), "record the dashboard address") {
		t.Errorf("err = %v, want it to name the step that failed", err)
	}
}

// A record left behind after the agent stops points the CLI at a port this process no
// longer holds, which is whatever takes it next.
func TestStoppingRemovesTheRecordOfWhereTheAgentWasListening(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, config.ConfigFileName)
	store, err := config.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtimeCfg, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, path)
	if err != nil {
		t.Fatalf("resolve runtime: %v", err)
	}
	node := newFakeNode()
	agent, err := New(Options{Store: store, Runtime: runtimeCfg, Getenv: emptyEnv, Logger: quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its node", node.wasStarted)
	waitFor(t, 5*time.Second, "the agent to record where it is listening", func() bool {
		return config.ReadDashboardAddr(path) != ""
	})

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := config.ReadDashboardAddr(path); got != "" {
		t.Errorf("the record still names %q after the agent stopped listening", got)
	}
}

// A record the agent could not drop outlives the process holding the port, so shutdown
// says so rather than finishing quietly and leaving the next command pointed at whatever
// takes that port.
func TestARecordThatCannotBeRemovedIsReportedByShutdown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes what this test depends on being undeletable")
	}
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, config.ConfigFileName)
	store, err := config.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtimeCfg, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, path)
	if err != nil {
		t.Fatalf("resolve runtime: %v", err)
	}
	node := newFakeNode()
	agent, err := New(Options{Store: store, Runtime: runtimeCfg, Getenv: emptyEnv, Logger: quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to record where it is listening", func() bool {
		return config.ReadDashboardAddr(path) != ""
	})

	// A directory holding something is what a remove cannot take away, and it stands where
	// the record the agent wrote was.
	record := config.DashboardAddrPath(path)
	if err := os.Remove(record); err != nil {
		t.Fatalf("take the record the agent wrote: %v", err)
	}
	if err := os.Mkdir(record, config.DirMode); err != nil {
		t.Fatalf("put a directory where the record was: %v", err)
	}
	if err := os.WriteFile(filepath.Join(record, "occupied"), nil, config.FileMode); err != nil {
		t.Fatalf("fill that directory: %v", err)
	}

	cancel()

	err = <-runErr
	if err == nil {
		t.Fatal("the agent stopped cleanly over a record it could not remove")
	}
	if !strings.Contains(err.Error(), "remove the dashboard address record") {
		t.Errorf("err = %v, want it to name the record that was left behind", err)
	}
}

// --- helpers --------------------------------------------------------------

func tcpAddr(host string, port int) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
}

func unixAddr(path string) net.Addr {
	return &net.UnixAddr{Name: path, Net: "unix"}
}

// newAPIServer builds the management server the way start does, for tests that drive
// listenUI without running the whole agent.
func newAPIServer(t *testing.T) *httpapi.Server {
	t.Helper()
	keys, err := apiauth.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("create the API keys: %v", err)
	}
	s := httpapi.New(httpapi.Options{Auth: keys, Logger: quietLogger()})
	t.Cleanup(func() {
		if err := s.Shutdown(context.Background()); err != nil {
			t.Errorf("shut the management server down: %v", err)
		}
	})
	return s
}

// --- restarting the whole process -----------------------------------------

// A restart the user asked for has to end the run the same orderly way a quit does --
// listener released, forwards stopped, node closed -- because the replacement binds the
// same dashboard port and the same tsnet state directory. Cutting the run short and
// exec'ing from under it would hand both to a process that cannot have them yet.
func TestAskingForAProcessRestartStopsTheAgentCleanly(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtimeCfg, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	node := newFakeNode()
	agent, err := New(Options{
		Store:   store,
		Runtime: runtimeCfg,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its node", node.wasStarted)

	if agent.RelaunchRequested() {
		t.Fatal("a running agent already claims a restart was asked for")
	}
	if err := agent.RestartProcess(); err != nil {
		t.Fatalf("RestartProcess: %v", err)
	}

	select {
	case err := <-runErr:
		// Not an error: the user asked for this. Reporting a failure here would make
		// the caller skip the relaunch and leave the machine with no agent at all.
		if err != nil {
			t.Errorf("Run returned %v, want a clean exit for a restart the user asked for", err)
		}
		// The caller starts the replacement only after Run returns, so everything the
		// new process needs has to be released by now.
		if !node.wasClosed() {
			t.Error("the tailnet identity was still registered when the replacement would start")
		}
		if !agent.RelaunchRequested() {
			t.Error("the run ended without recording that a restart was what ended it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after a restart was asked for")
	}
}

// Told to stop and told to restart are different intents reaching the same shutdown, and
// the caller decides what happens next purely from this flag. Conflating them would make
// an ordinary quit silently start the process up again.
func TestAPlainShutdownIsNotARestart(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtimeCfg, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	node := newFakeNode()
	agent, err := New(Options{
		Store:   store,
		Runtime: runtimeCfg,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its node", node.wasStarted)

	cancel()

	select {
	case <-runErr:
		if agent.RelaunchRequested() {
			t.Error("a cancelled run asked for a restart, which would relaunch a process the user quit")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// A second copy of app-tail starting asks this one to go. Asking rather than ending it is
// the whole point: the shutdown has to run, because the node this agent registered and the
// resolver, proxy settings and routes it installed are put back by it and by nothing else.
// The run must also not read as a restart, or the caller would start a replacement that the
// agent doing the asking has already taken the place of.
func TestBeingAskedToQuitStopsTheAgentCleanlyAndIsNotARestart(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtimeCfg, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}

	node := newFakeNode()
	agent, err := New(Options{
		Store:   store,
		Runtime: runtimeCfg,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to start its node", node.wasStarted)

	if err := agent.StopProcess(); err != nil {
		t.Fatalf("StopProcess: %v", err)
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run returned %v, want a clean exit for a shutdown that was asked for", err)
		}
		if !node.wasClosed() {
			t.Error("the tailnet identity was still registered when the agent taking over would start")
		}
		if agent.RelaunchRequested() {
			t.Error("being asked to quit recorded a restart, which would start the copy this one handed over to a rival")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the process was asked to stop")
	}
}

// An agent that has already finished shutting down cannot be asked again: the ask would be
// recorded against a lifecycle that nothing is running, and the takeover waiting on it would
// read that silence as a handover it never got.
func TestAnAgentThatHasFinishedShuttingDownRefusesToQuitAgain(t *testing.T) {
	agent := newIdleAgent(t)
	if err := agent.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	err := agent.StopProcess()

	if err == nil {
		t.Fatal("an agent that had already stopped accepted a request to stop")
	}
	if !strings.Contains(err.Error(), "shutting down") {
		t.Errorf("err = %v, want it to say the agent is already shutting down", err)
	}
}

// Two copies starting at once, or a takeover that asks twice while waiting, must not panic on
// a second close of the same channel.
func TestAskingToQuitTwiceIsHarmless(t *testing.T) {
	agent := newIdleAgent(t)

	if err := agent.StopProcess(); err != nil {
		t.Fatalf("first StopProcess: %v", err)
	}
	if err := agent.StopProcess(); err != nil {
		t.Errorf("second StopProcess: %v", err)
	}
	if agent.RelaunchRequested() {
		t.Error("a shutdown was recorded as a restart")
	}
}

// Asked twice -- an impatient double click, or a second browser tab -- must not panic on
// a second close of the same channel.
func TestAskingForARestartTwiceIsHarmless(t *testing.T) {
	agent := newIdleAgent(t)

	if err := agent.RestartProcess(); err != nil {
		t.Fatalf("first RestartProcess: %v", err)
	}
	if err := agent.RestartProcess(); err != nil {
		t.Fatalf("second RestartProcess: %v", err)
	}
	if !agent.RelaunchRequested() {
		t.Error("the request was not recorded")
	}
}
