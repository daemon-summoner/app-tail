// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/elevate"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// harness is a fake agent plus a config file pointing at it, which is exactly the
// situation every network-facing command runs in.
type harness struct {
	t          *testing.T
	server     *httptest.Server
	configPath string
	// token is the stand-in agent's API token, written beside the config where Discover
	// reads it.
	token  string
	stdout bytes.Buffer
	stderr bytes.Buffer

	// requests records every call the CLI made, so a test can assert that a command
	// used the endpoint it claims to use. Handlers run on the server's goroutines,
	// so it is guarded.
	mu       sync.Mutex
	requests []recordedRequest
}

type recordedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   string
}

// newHarness starts a fake agent whose routes are supplied by the caller.
func newHarness(t *testing.T, routes map[string]http.HandlerFunc) *harness {
	t.Helper()

	h := &harness{t: t}
	mux := http.NewServeMux()
	for pattern, handler := range routes {
		mux.HandleFunc(pattern, handler)
	}

	dir := t.TempDir()
	keys, token := agentKeys(t, dir)
	h.token = token
	h.server = httptest.NewServer(answerHello(t, keys, token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		if r.Body != nil {
			if _, err := body.ReadFrom(r.Body); err != nil {
				t.Errorf("read request body: %v", err)
			}
			// Recording consumes the body, so hand the real handler a fresh copy.
			r.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
		}
		h.mu.Lock()
		h.requests = append(h.requests, recordedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.Query(),
			Body:   body.String(),
		})
		h.mu.Unlock()
		mux.ServeHTTP(w, r)
	})))
	t.Cleanup(h.server.Close)

	// The CLI locates the agent through the address the agent persisted, so the
	// config file has to carry the test server's real port.
	h.configPath = filepath.Join(dir, "config.json")
	store, err := config.Open(h.configPath)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	addr := strings.TrimPrefix(h.server.URL, "http://")
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = addr
		return nil
	}); err != nil {
		t.Fatalf("record the agent address: %v", err)
	}
	return h
}

// client is a CLI client holding the stand-in agent's token, for tests that call a
// Client method directly instead of running a command.
func (h *harness) client() *Client {
	return NewAuthenticatedClient(h.server.URL, h.token)
}

// agentKeys gives a stand-in agent a token of its own, written into dir where Discover
// reads it for a config file in the same directory.
func agentKeys(t *testing.T, dir string) (*apiauth.Keys, string) {
	t.Helper()
	keys, err := apiauth.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("create the agent's API token: %v", err)
	}
	token, err := apiauth.Read(dir)
	if err != nil {
		t.Fatalf("read the agent's API token back: %v", err)
	}
	return keys, token
}

// answerHello wraps a stand-in agent so it answers the CLI's identity check the way the
// real agent does, signing the address the connection arrived on. Every other API call
// must carry the token: one that does not fails the test and is refused, as the real
// agent would refuse it.
func answerHello(t *testing.T, keys *apiauth.Keys, token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/auth/hello" {
			var req struct {
				Nonce string `json:"nonce"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode the identity check: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			local := r.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]string{"proof": keys.Proof(req.Nonce, local)}); err != nil {
				t.Errorf("answer the identity check: %v", err)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("%s %s arrived with Authorization %q, want the agent's token",
				r.Method, r.URL.Path, r.Header.Get("Authorization"))
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newAgentServer starts a bare stand-in agent around handler and returns a client that
// holds its token, for tests that need control of every byte of the reply.
func newAgentServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	keys, token := agentKeys(t, t.TempDir())
	srv := httptest.NewServer(answerHello(t, keys, token, handler))
	t.Cleanup(srv.Close)
	return srv, NewAuthenticatedClient(srv.URL, token)
}

// stopAgent shuts the stand-in agent down while leaving the address it published in
// place, which is what a machine whose agent is not running looks like to every command.
func (h *harness) stopAgent() {
	h.t.Helper()
	h.server.Close()
}

func (h *harness) env() Env {
	return Env{
		Stdout: &h.stdout,
		Stderr: &h.stderr,
		Getenv: func(string) string { return "" },
	}
}

// run invokes a command against the fake agent. --config goes immediately after the
// subcommand because Go's flag package stops parsing at the first positional
// argument, so appending it would turn it into one.
func (h *harness) run(args ...string) error {
	full := []string{"--config", h.configPath}
	if len(args) > 0 {
		full = append([]string{args[0], "--config", h.configPath}, args[1:]...)
	}
	return Run(context.Background(), full, h.env())
}

func (h *harness) out() string { return h.stdout.String() }

// recorded returns a copy of the calls the CLI made.
func (h *harness) recorded() []recordedRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]recordedRequest(nil), h.requests...)
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}

func writeJSONResponse(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestUnknownCommandIsAUsageErrorNotAFailure(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run(context.Background(), []string{"frobnicate"}, Env{Stdout: &out, Stderr: &errOut})

	if err == nil {
		t.Fatal("an unknown command was accepted")
	}
	if !errors.Is(err, ErrUsage) {
		t.Errorf("error = %v, want it to wrap ErrUsage so the exit code is 2", err)
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not name the command the user typed", err)
	}
}

// noClaim stands in for the single-instance claim in tests about how a run is dispatched.
// Taking a real one would stop whatever app-tail is running on the machine the test runs on.
type noClaim struct{}

func (noClaim) Take(context.Context, config.Flags) error { return nil }
func (noClaim) Release() error                           { return nil }

// recordingClaim is noClaim with the order written down, and a refusal to hand the claim
// over when one is what the test is about.
type recordingClaim struct {
	events  *[]string
	takeErr error
}

func (c recordingClaim) Take(context.Context, config.Flags) error {
	*c.events = append(*c.events, "take")
	return c.takeErr
}

func (c recordingClaim) Release() error {
	*c.events = append(*c.events, "release")
	return nil
}

// One app-tail per state directory, and the order is the whole of it: the claim is taken
// before the agent runs, so two agents are never starting at once, and given up after it
// stops, so the next run takes it rather than waiting out a process that has already gone.
func TestTheAgentRunsOnlyWhileItHoldsTheClaim(t *testing.T) {
	var events []string
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Claim:  recordingClaim{events: &events},
		RunAgent: func(context.Context, config.Flags) error {
			events = append(events, "run")
			return nil
		},
	}

	if err := Run(context.Background(), []string{"run"}, env); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := strings.Join(events, ","); got != "take,run,release" {
		t.Errorf("the run went %q, want take,run,release", got)
	}
}

// A claim that could not be taken means another app-tail still holds this machine's
// resolver, proxy settings and routes. Starting anyway would put a second agent beside it,
// which is the state the claim exists to prevent.
func TestTheAgentIsNotStartedWhenTheClaimCannotBeTaken(t *testing.T) {
	var events []string
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Claim:  recordingClaim{events: &events, takeErr: errors.New("app-tail is already running as process 4242")},
		RunAgent: func(context.Context, config.Flags) error {
			events = append(events, "run")
			return nil
		},
	}

	err := Run(context.Background(), []string{"run"}, env)

	if err == nil {
		t.Fatal("the agent started while another one held the claim")
	}
	if !strings.Contains(err.Error(), "4242") {
		t.Errorf("the failure does not say what stopped the start: %v", err)
	}
	if got := strings.Join(events, ","); got != "take" {
		t.Errorf("the run went %q, want the claim to be the end of it", got)
	}
}

// A build wired without a claim cannot tell whether another app-tail is running, so it must
// refuse rather than start blind. Skipping the claim quietly is the one outcome that puts two
// agents on one machine's resolver, proxy settings and routes.
func TestTheAgentIsNotStartedByABuildThatCannotClaimAnything(t *testing.T) {
	started := false
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		RunAgent: func(context.Context, config.Flags) error {
			started = true
			return nil
		},
	}

	err := Run(context.Background(), []string{"run"}, env)

	if err == nil {
		t.Fatal("the agent started in a build that cannot take the claim")
	}
	if started {
		t.Error("the agent ran without any claim on the state directory")
	}
}

// Running the binary with no arguments has to start the agent; that is how the
// login item and a double-click both invoke it.
func TestNoArgumentsStartsTheAgent(t *testing.T) {
	var started bool
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Claim:  noClaim{},
		RunAgent: func(context.Context, config.Flags) error {
			started = true
			return nil
		},
	}
	if err := Run(context.Background(), nil, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !started {
		t.Fatal("no arguments did not start the agent")
	}
}

// A bare flag with no subcommand also means "run", so `app-tail --headless` works.
func TestALeadingFlagStillMeansRun(t *testing.T) {
	var got config.Flags
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Claim:  noClaim{},
		RunAgent: func(_ context.Context, flags config.Flags) error {
			got = flags
			return nil
		},
	}
	if err := Run(context.Background(), []string{"--headless"}, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Headless == nil || !*got.Headless {
		t.Fatalf("Headless = %v, want a set true", got.Headless)
	}
}

// The flag says the process will never ask for administrator rights, and the agent is the
// half of the process that would: the network-interface mode raises the system's password
// dialog when it is turned on. A flag that stopped only the Windows relaunch would leave
// that promise false everywhere else.
func TestRefusingToElevateReachesTheAgent(t *testing.T) {
	var got config.Flags
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Claim:  noClaim{},
		RunAgent: func(_ context.Context, flags config.Flags) error {
			got = flags
			return nil
		},
	}
	if err := Run(context.Background(), []string{"run", "--no-elevate"}, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.NoElevate == nil || !*got.NoElevate {
		t.Fatalf("NoElevate = %v, want a set true", got.NoElevate)
	}

	// Unpassed it must stay nil, not a set false: the agent reads it as a standing
	// instruction, and a false one that was never given is a different thing from silence.
	got = config.Flags{}
	if err := Run(context.Background(), []string{"run"}, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.NoElevate != nil {
		t.Errorf("--no-elevate was not passed but arrived as %v", *got.NoElevate)
	}
}

// An unpassed flag must stay nil. If it arrived as a set empty string it would
// override the config file with nothing, silently wiping a configured hostname.
func TestUnpassedAgentFlagsStayUnset(t *testing.T) {
	var got config.Flags
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Claim:  noClaim{},
		RunAgent: func(_ context.Context, flags config.Flags) error {
			got = flags
			return nil
		},
	}
	if err := Run(context.Background(), []string{"run", "--hostname", "box"}, env); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got.Hostname == nil || *got.Hostname != "box" {
		t.Errorf("Hostname = %v, want %q", got.Hostname, "box")
	}
	for name, value := range map[string]any{
		"config":      got.ConfigPath,
		"state-dir":   got.StateDir,
		"ui-addr":     got.UIAddr,
		"tags":        got.Tags,
		"control-url": got.ControlURL,
	} {
		if !isNil(value) {
			t.Errorf("--%s was not passed but arrived as %v", name, value)
		}
	}
	if got.Ephemeral != nil {
		t.Errorf("--ephemeral was not passed but arrived as %v", *got.Ephemeral)
	}
	if got.Verbose != nil {
		t.Errorf("--verbose was not passed but arrived as %v", *got.Verbose)
	}
}

func isNil(v any) bool {
	switch value := v.(type) {
	case *string:
		return value == nil
	default:
		return false
	}
}

// A command that needs a running agent must say so plainly. "connection refused"
// with no context is the single most common confusing failure for this kind of tool.
func TestCommandsExplainThatNoAgentIsRunning(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if _, err := config.Open(configPath); err != nil {
		t.Fatalf("open config: %v", err)
	}

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}
	err := Run(context.Background(), []string{"status", "--config", configPath}, env)

	if err == nil {
		t.Fatal("status succeeded with no agent running")
	}
	if !errors.Is(err, ErrNoAgent) {
		t.Errorf("error = %v, want it to wrap ErrNoAgent", err)
	}
	if !strings.Contains(err.Error(), "start the agent") {
		t.Errorf("error %q does not tell the user what to do", err)
	}
}

func TestStatusRendersTheNodeState(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/status": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, httpapi.StatusView{
				BackendState: "Running",
				Running:      true,
				Hostname:     "app-tail-laptop",
				DNSName:      "app-tail-laptop.tail1234.ts.net",
				TailscaleIPs: []string{"100.64.0.7"},
				LoginName:    "user@example.com",
				Tags:         []string{"tag:app-tail"},
				AuthMode:     "oauth",
			})
		},
	})

	if err := h.run("status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{"Running", "app-tail-laptop", "100.64.0.7", "user@example.com", "tag:app-tail"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("status output does not mention %q:\n%s", want, h.out())
		}
	}
}

// --json is a scripting contract: the output has to parse, with the field names the
// API uses, not a prettified rendering.
func TestStatusJSONIsMachineReadable(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/status": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, httpapi.StatusView{BackendState: "NeedsLogin"})
		},
	})

	if err := h.run("status", "--json"); err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var decoded httpapi.StatusView
	if err := json.Unmarshal([]byte(h.out()), &decoded); err != nil {
		t.Fatalf("status --json did not emit JSON: %v\n%s", err, h.out())
	}
	if decoded.BackendState != "NeedsLogin" {
		t.Errorf("backendState = %q, want %q", decoded.BackendState, "NeedsLogin")
	}
}

// A login waiting to be completed is the one state where a status that reads healthy is not:
// the node is up and doing nothing until somebody visits the URL. The status carries only the
// fact, so the URL is asked for separately -- and when that ask fails the pending login is
// still printed, with the command that produces a fresh URL, rather than dropped.
func TestStatusPrintsThePendingLoginURLOrHowToGetOne(t *testing.T) {
	pending := func(t *testing.T, loginURL http.HandlerFunc) *harness {
		return newHarness(t, map[string]http.HandlerFunc{
			"GET /api/status": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK, httpapi.StatusView{BackendState: "NeedsLogin", AuthPending: true})
			},
			"POST /api/login/url": loginURL,
		})
	}

	t.Run("the URL is fetched and printed", func(t *testing.T) {
		h := pending(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, LoginResult{AuthURL: "https://login.tailscale.com/a/abc123", BackendState: "NeedsLogin"})
		})

		if err := h.run("status"); err != nil {
			t.Fatalf("status: %v", err)
		}

		if !strings.Contains(h.out(), "Login URL:") || !strings.Contains(h.out(), "https://login.tailscale.com/a/abc123") {
			t.Errorf("status does not print the URL that completes the login:\n%s", h.out())
		}
		var asked bool
		for _, r := range h.recorded() {
			asked = asked || (r.Method == http.MethodPost && r.Path == "/api/login/url")
		}
		if !asked {
			t.Error("the URL was printed without asking the agent for it")
		}
	})

	t.Run("the URL cannot be fetched", func(t *testing.T) {
		h := pending(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusServiceUnavailable, map[string]string{"error": "the login expired"})
		})

		if err := h.run("status"); err != nil {
			t.Fatalf("status failed because the login URL could not be fetched: %v", err)
		}

		if !strings.Contains(h.out(), "waiting to be completed") || !strings.Contains(h.out(), "app-tail login") {
			t.Errorf("status does not say a login is pending and how to get its URL:\n%s", h.out())
		}
		if strings.Contains(h.out(), "Login URL:") {
			t.Errorf("status printed a URL row with nothing to put in it:\n%s", h.out())
		}
	})

	t.Run("no login pending", func(t *testing.T) {
		h := newHarness(t, map[string]http.HandlerFunc{
			"GET /api/status": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK, httpapi.StatusView{BackendState: "Running", Running: true})
			},
		})

		if err := h.run("status"); err != nil {
			t.Fatalf("status: %v", err)
		}

		for _, r := range h.recorded() {
			if r.Path == "/api/login/url" {
				t.Error("status asked for a login URL with no login pending, which would start one")
			}
		}
		if strings.Contains(h.out(), "Login") {
			t.Errorf("status mentions a login with none pending:\n%s", h.out())
		}
	})
}

// The point of `login` is the URL. Printing anything else leaves the user stuck.
func TestLoginPrintsTheURLToVisit(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/login": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, LoginResult{
				AuthURL:      "https://login.tailscale.com/a/deadbeef",
				BackendState: "NeedsLogin",
			})
		},
	})

	if err := h.run("login"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(h.out(), "https://login.tailscale.com/a/deadbeef") {
		t.Errorf("login did not print the auth URL:\n%s", h.out())
	}
}

func TestLoginSaysSoWhenAlreadyConnected(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/login": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, LoginResult{BackendState: "Running"})
		},
	})

	if err := h.run("login"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(h.out(), "already connected") {
		t.Errorf("login did not report the existing connection:\n%s", h.out())
	}
}

// restart is the headless way to apply a node-identity change; it must POST to the
// agent's restart endpoint and confirm what happened.
func TestRestartTellsTheAgentToRebuildTheNode(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/restart": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]string{"backendState": "Starting"})
		},
	})

	if err := h.run("restart"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !strings.Contains(h.out(), "restarted") {
		t.Errorf("restart printed %q, want confirmation the node restarted", h.out())
	}

	var sawRestart bool
	for _, req := range h.recorded() {
		if req.Path == "/api/restart" {
			sawRestart = true
			if req.Method != http.MethodPost {
				t.Errorf("restart used %s, want POST", req.Method)
			}
		}
	}
	if !sawRestart {
		t.Error("restart never called the agent's restart endpoint")
	}
}

// A restart against a dead agent must fail loudly, not print a false success.
func TestRestartSurfacesAFailure(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/restart": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusServiceUnavailable, map[string]any{
				"error": "node restart is unavailable",
			})
		},
	})

	err := h.run("restart")
	if err == nil {
		t.Fatal("restart reported success on a 503")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("error %q does not carry the agent's explanation", err)
	}
}

func TestListShowsEveryForwardWithItsState(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{
				{
					Forward:  config.Forward{ID: "fw_1", Name: "llm", Direction: config.ToLocal, Target: "gpu-box:8100", Enabled: true},
					State:    "running",
					Endpoint: "TCP 127.0.0.1:18100",
				},
				{
					Forward:  config.Forward{ID: "fw_2", Name: "ssh", Direction: config.ToLocal, Target: "box:22", Enabled: false},
					Endpoint: "TCP 127.0.0.1:2222",
				},
				{
					Forward:  config.Forward{ID: "fw_3", Name: "dns", Direction: config.ToLocal, Target: "box:53", Enabled: true},
					State:    "error",
					Error:    "address already in use",
					Endpoint: "UDP 127.0.0.1:5353",
				},
			}})
		},
	})

	if err := h.run("list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	out := h.out()
	for _, want := range []string{"fw_1", "llm", "TCP 127.0.0.1:18100", "gpu-box:8100", "running"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "disabled") {
		t.Errorf("a disabled forward is not shown as disabled:\n%s", out)
	}
	// A forward that failed must show why, or the user has to go read logs.
	if !strings.Contains(out, "address already in use") {
		t.Errorf("a failed forward does not show its reason:\n%s", out)
	}
}

func TestListSaysWhenThereIsNothingToShow(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{}})
		},
	})

	if err := h.run("list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(h.out(), "No forwards configured") {
		t.Errorf("an empty list printed nothing useful:\n%s", h.out())
	}
}

// Omitting --port must ask the agent for one rather than sending 0, which the agent
// would reject.
func TestAddAsksTheAgentForAPortWhenNoneIsGiven(t *testing.T) {
	specs := make(chan httpapi.ForwardSpec, 1)
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards/suggest-port": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]int{"port": 18100})
		},
		"POST /api/forwards": func(w http.ResponseWriter, r *http.Request) {
			var spec httpapi.ForwardSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			specs <- spec
			writeJSONResponse(t, w, http.StatusCreated, httpapi.ForwardView{
				Forward:  config.Forward{ID: "fw_9", Name: "gpu-box-8100", Target: "gpu-box:8100", Enabled: true},
				Endpoint: "TCP 127.0.0.1:18100",
			})
		},
	})

	if err := h.run("add", "--target", "gpu-box:8100"); err != nil {
		t.Fatalf("add: %v", err)
	}
	created := <-specs
	if created.ListenPort == nil || *created.ListenPort != 18100 {
		t.Fatalf("listenPort sent = %v, want the suggested 18100", created.ListenPort)
	}
	if created.Target == nil || *created.Target != "gpu-box:8100" {
		t.Errorf("target sent = %v", created.Target)
	}
	if created.Enabled == nil || !*created.Enabled {
		t.Errorf("a new forward should arrive enabled, got %v", created.Enabled)
	}
	if created.Direction == nil || *created.Direction != config.ToLocal {
		t.Errorf("direction sent = %v, want the to_local default", created.Direction)
	}

	// The suggestion request must carry the target so the agent can prefer its port.
	var sawSuggest bool
	for _, req := range h.recorded() {
		if req.Path == "/api/forwards/suggest-port" {
			sawSuggest = true
			if req.Query.Get("target") != "gpu-box:8100" {
				t.Errorf("suggest-port query = %v, want the target", req.Query)
			}
		}
	}
	if !sawSuggest {
		t.Error("add never asked for a port suggestion")
	}
}

func TestAddUsesTheGivenPortWithoutAskingForOne(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards/suggest-port": func(w http.ResponseWriter, _ *http.Request) {
			t.Error("add asked for a suggestion even though --port was given")
			writeJSONResponse(t, w, http.StatusOK, map[string]int{"port": 1})
		},
		"POST /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusCreated, httpapi.ForwardView{
				Forward:  config.Forward{ID: "fw_9", Name: "custom", Enabled: true},
				Endpoint: "TCP 127.0.0.1:9000",
			})
		},
	})

	if err := h.run("add", "--target", "box:22", "--port", "9000"); err != nil {
		t.Fatalf("add: %v", err)
	}
}

func TestAddRequiresATarget(t *testing.T) {
	h := newHarness(t, nil)
	err := h.run("add")
	if err == nil {
		t.Fatal("add ran without a target")
	}
	if !errors.Is(err, ErrUsage) {
		t.Errorf("error = %v, want a usage error", err)
	}
}

// A 409 from the agent names the forward already holding the port. Losing that
// detail would leave the user guessing.
func TestAddSurfacesTheAgentsConflictExplanation(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusConflict, map[string]any{
				"error": `TCP 127.0.0.1:18100 is already used by forward "llm"`,
			})
		},
	})

	err := h.run("add", "--target", "gpu-box:8100", "--port", "18100")
	if err == nil {
		t.Fatal("add reported success on a conflict")
	}
	if !strings.Contains(err.Error(), `already used by forward "llm"`) {
		t.Errorf("error %q does not carry the agent's explanation", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Errorf("error = %v, want an APIError carrying 409", err)
	}
}

func TestRemoveAcceptsEitherAnIDOrAName(t *testing.T) {
	forwards := []httpapi.ForwardView{
		{Forward: config.Forward{ID: "fw_1", Name: "llm"}},
		{Forward: config.Forward{ID: "fw_2", Name: "ssh"}},
	}

	for _, wanted := range []string{"fw_2", "ssh", "SSH"} {
		t.Run(wanted, func(t *testing.T) {
			deletions := make(chan string, 1)
			h := newHarness(t, map[string]http.HandlerFunc{
				"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": forwards})
				},
				"DELETE /api/forwards/{id}": func(w http.ResponseWriter, r *http.Request) {
					deletions <- r.PathValue("id")
					w.WriteHeader(http.StatusNoContent)
				},
			})

			if err := h.run("rm", wanted); err != nil {
				t.Fatalf("rm %s: %v", wanted, err)
			}
			if deleted := <-deletions; deleted != "fw_2" {
				t.Errorf("deleted %q, want fw_2", deleted)
			}
		})
	}
}

// Deleting the wrong forward cannot be undone from the CLI, so an ambiguous name
// has to stop rather than pick one.
func TestRemoveRefusesAnAmbiguousName(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{
				{Forward: config.Forward{ID: "fw_1", Name: "llm"}},
				{Forward: config.Forward{ID: "fw_2", Name: "llm"}},
			}})
		},
		"DELETE /api/forwards/{id}": func(http.ResponseWriter, *http.Request) {
			t.Error("rm deleted a forward despite the name being ambiguous")
		},
	})

	err := h.run("rm", "llm")
	if err == nil {
		t.Fatal("rm accepted an ambiguous name")
	}
	for _, want := range []string{"fw_1", "fw_2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not list the candidate %s", err, want)
		}
	}
}

func TestRemoveReportsAnUnknownForward(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{}})
		},
	})

	err := h.run("rm", "nope")
	if err == nil {
		t.Fatal("rm accepted an unknown forward")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error %q does not name what was not found", err)
	}
}

func TestRemoveNeedsExactlyOneArgument(t *testing.T) {
	h := newHarness(t, nil)
	for _, args := range [][]string{{"rm"}, {"rm", "a", "b"}} {
		if err := h.run(args...); !errors.Is(err, ErrUsage) {
			t.Errorf("%v gave %v, want a usage error", args, err)
		}
	}
}

// A stray positional argument usually means a typo. Ignoring it would run a command
// that quietly did something other than what was typed.
func TestStrayPositionalArgumentsAreRejected(t *testing.T) {
	h := newHarness(t, nil)
	for _, args := range [][]string{
		{"status", "extra"},
		{"list", "extra"},
		{"add", "--target", "box:22", "extra"},
		{"login", "extra"},
		{"restart", "extra"},
	} {
		if err := h.run(args...); !errors.Is(err, ErrUsage) {
			t.Errorf("%v gave %v, want a usage error", args, err)
		}
	}
}

func TestProvisionAppliesAProfileAndIsRepeatable(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	profilePath := filepath.Join(dir, "profile.json")

	profile := `{
	  "settings": {"hostnameTemplate": "fleet-{hostname}", "tags": ["tag:app-tail"]},
	  "forwards": [{"name": "llm", "direction": "to_local", "protocol": "tcp", "listenPort": 18100, "target": "gpu-box:8100"}]
	}`
	if err := writeFile(profilePath, profile); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}
	args := []string{"provision", "--profile", profilePath, "--config", configPath}

	if err := Run(context.Background(), args, env); err != nil {
		t.Fatalf("provision: %v", err)
	}
	first, err := readFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(out.String(), "fleet-{hostname}") {
		t.Errorf("provision did not report what it applied:\n%s", out.String())
	}

	// Re-running a provisioning step is routine in a fleet; it must not accumulate
	// duplicate forwards or churn the file.
	out.Reset()
	if err := Run(context.Background(), args, env); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	second, err := readFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if first != second {
		t.Errorf("a second provision changed the config:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

func TestProvisionNeedsAProfile(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}
	if err := Run(context.Background(), []string{"provision"}, env); !errors.Is(err, ErrUsage) {
		t.Errorf("provision without --profile gave %v, want a usage error", err)
	}
}

// A secret passed in argv is visible to every process on the machine, so the only
// ways in are a file or the environment.
func TestBootstrapSecretComesFromAFileOrTheEnvironmentOnly(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := writeFile(secretPath, "  tskey-client-from-file\n"); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	t.Run("file wins", func(t *testing.T) {
		env := Env{Getenv: func(string) string { return "tskey-from-env" }}
		got, err := bootstrapSecret(env, secretPath)
		if err != nil {
			t.Fatalf("bootstrapSecret: %v", err)
		}
		if got != "tskey-client-from-file" {
			t.Errorf("secret = %q, want the trimmed file contents", got)
		}
	})

	t.Run("environment fallback", func(t *testing.T) {
		env := Env{Getenv: func(key string) string {
			if key == config.EnvTSClientSecret {
				return "tskey-from-env"
			}
			return ""
		}}
		got, err := bootstrapSecret(env, "")
		if err != nil {
			t.Fatalf("bootstrapSecret: %v", err)
		}
		if got != "tskey-from-env" {
			t.Errorf("secret = %q", got)
		}
	})

	t.Run("empty file is refused", func(t *testing.T) {
		emptyPath := filepath.Join(dir, "empty")
		if err := writeFile(emptyPath, "\n  \n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		env := Env{Getenv: func(string) string { return "" }}
		if _, err := bootstrapSecret(env, emptyPath); err == nil {
			t.Error("an empty secret file was accepted")
		}
	})

	t.Run("nothing supplied", func(t *testing.T) {
		env := Env{Getenv: func(string) string { return "" }}
		_, err := bootstrapSecret(env, "")
		if !errors.Is(err, ErrUsage) {
			t.Errorf("error = %v, want a usage error", err)
		}
	})

	// There must be no way to pass the secret as a flag.
	if strings.Contains(usageText, "--client-secret ") {
		t.Error("usage advertises a --client-secret flag, which would leak the secret into argv")
	}
}

func TestVersionPrintsTheBuild(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Version: "1.2.3"}
	if err := Run(context.Background(), []string{"version"}, env); err != nil {
		t.Fatalf("version: %v", err)
	}
	if strings.TrimSpace(out.String()) != "1.2.3" {
		t.Errorf("version printed %q, want %q", out.String(), "1.2.3")
	}
}

func TestHelpListsEverySubcommand(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut}
	if err := Run(context.Background(), []string{"help"}, env); err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, command := range []string{
		"status", "login", "logout", "restart", "list", "add", "rm",
		"provision", "install-autostart", "bootstrap-policy", "version",
	} {
		if !strings.Contains(out.String(), command) {
			t.Errorf("help does not mention %q", command)
		}
	}
}

// A bare -h or --help is how most people ask, and both have to reach the same
// overview `help` prints rather than falling through to the agent's flag set,
// where an unrecognised -h reads as a usage error on a command nobody ran.
func TestHelpFlagsPrintTheOverviewInsteadOfStartingTheAgent(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		t.Run(flag, func(t *testing.T) {
			var out, errOut bytes.Buffer
			env := Env{
				Stdout: &out,
				Stderr: &errOut,
				RunAgent: func(context.Context, config.Flags) error {
					t.Error("the agent was started for a help flag")
					return nil
				},
			}
			if err := Run(context.Background(), []string{flag}, env); err != nil {
				t.Fatalf("%s: %v", flag, err)
			}
			if !strings.Contains(out.String(), "app-tail status") {
				t.Errorf("%s printed %q, want the command overview", flag, out.String())
			}
		})
	}
}

// The overview ends with "Run any command with --help for its own flags", so that
// has to be a success on every subcommand. Reporting it as a usage error would
// make the documented way to discover flags look like a mistake.
func TestSubcommandHelpPrintsFlagsAndIsNotAUsageError(t *testing.T) {
	for _, command := range []string{
		"run", "status", "login", "logout", "restart", "list", "add", "rm",
		"provision", "install-autostart", "bootstrap-policy",
	} {
		t.Run(command, func(t *testing.T) {
			var out, errOut bytes.Buffer
			env := Env{
				Stdout: &out,
				Stderr: &errOut,
				RunAgent: func(context.Context, config.Flags) error {
					t.Error("the agent was started for a help flag")
					return nil
				},
			}

			err := Run(context.Background(), []string{command, "--help"}, env)
			if !errors.Is(err, ErrHelpShown) {
				t.Fatalf("%s --help returned %v, want ErrHelpShown", command, err)
			}
			if errors.Is(err, ErrUsage) {
				t.Errorf("%s --help reports a usage error, so the binary would exit 2", command)
			}
			if !strings.Contains(errOut.String(), "Usage of "+command) {
				t.Errorf("%s --help printed %q, want its flag list", command, errOut.String())
			}
		})
	}
}

// A real mistake must stay distinguishable from a help request, or exit codes stop
// meaning anything to a script.
func TestAnUnknownFlagIsStillAUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut}

	err := Run(context.Background(), []string{"add", "--nope"}, env)
	if !errors.Is(err, ErrUsage) {
		t.Errorf("add --nope returned %v, want a usage error", err)
	}
	if errors.Is(err, ErrHelpShown) {
		t.Error("add --nope reports help was shown, so the binary would exit 0 on a typo")
	}
}

// Discover reads the address the agent persisted. A placeholder port means the
// agent has not bound yet, which is a different problem from a missing config.
func TestDiscoverRejectsAnAddressThatIsNotBoundYet(t *testing.T) {
	dir := t.TempDir()
	store, err := config.Open(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("open config: %v", err)
	}

	if _, err := Discover(store); !errors.Is(err, ErrNoAgent) {
		t.Errorf("Discover on a default config = %v, want ErrNoAgent", err)
	}

	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = "127.0.0.1:8377"
		return nil
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	agentKeys(t, dir)
	client, err := Discover(store)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if client.BaseURL() != "http://127.0.0.1:8377" {
		t.Errorf("BaseURL = %q", client.BaseURL())
	}
}

// Discover builds its URL straight from the stored address, which is safe only
// because the store refuses to hold a non-loopback one. If that ever stopped being
// true the CLI would start talking to an off-box address.
func TestTheStoreCannotHoldAnOffBoxDashboardAddress(t *testing.T) {
	dir := t.TempDir()
	store, err := config.Open(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("open config: %v", err)
	}

	for _, addr := range []string{"0.0.0.0:8377", "192.168.1.10:8377", "[::]:8377"} {
		if _, err := store.Update(func(c *config.Config) error {
			c.Settings.UIListen = addr
			return nil
		}); err == nil {
			t.Errorf("the store accepted the off-box dashboard address %q", addr)
		}
	}
}

// An IPv6 loopback address has to survive the round trip with its brackets intact,
// or the resulting URL is unparsable.
func TestDiscoverHandlesAnIPv6LoopbackAddress(t *testing.T) {
	dir := t.TempDir()
	store, err := config.Open(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = "[::1]:8377"
		return nil
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	agentKeys(t, dir)

	client, err := Discover(store)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if client.BaseURL() != "http://[::1]:8377" {
		t.Errorf("BaseURL = %q, want http://[::1]:8377", client.BaseURL())
	}
	if _, err := url.Parse(client.BaseURL()); err != nil {
		t.Errorf("BaseURL %q is not a parsable URL: %v", client.BaseURL(), err)
	}
}

// The agent's own message is the useful one. A generic "HTTP 400" would throw it
// away.
func TestErrorMessagePrefersTheAgentsExplanation(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		payload string
		want    string
	}{
		{"json error", 400, `{"error":"listenPort must be 1-65535"}`, "listenPort must be 1-65535"},
		{"plain text", 502, "upstream died", "upstream died"},
		{"empty", 500, "", "no explanation"},
		{"unparsable json", 500, `{"error":`, `{"error":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := errorMessage(tc.status, []byte(tc.payload))
			if !strings.Contains(got, tc.want) {
				t.Errorf("errorMessage = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// The agent tells a first run from a later one by whether the config file was already
// there, and opening one creates it. So the mode check that happens before anything else
// must never be the thing that creates it -- a machine that had never run app-tail would
// otherwise stop being offered its browser login, once, and never again.
func TestCheckingTheStoredModeNeverCreatesTheConfigFile(t *testing.T) {
	dir := t.TempDir()
	env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Getenv: envWith(map[string]string{
		config.EnvStateDir: dir,
	})}

	wants, err := storedRightsWants(t.Context(), env, config.Flags{})
	if err != nil {
		t.Fatalf("storedRightsWants on a machine with no config: %v", err)
	}
	if wants.interfaceMode {
		t.Error("a machine with no config asked for the network-interface mode")
	}

	if _, err := os.Stat(filepath.Join(dir, config.ConfigFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the mode check created %s; the agent now believes this machine has run before", config.ConfigFileName)
	}
}

// Only one combination asks for administrator rights, and the module switch is half of
// it: a stored mode of "tun" under a module that is off is what every machine looks like
// after someone turns the mode off again, and it must not prompt.
func TestOnlyAnEnabledInterfaceModeAsksForRights(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		want     bool
	}{
		{"a config that never mentions the mode", `{}`, false},
		{"the mode this app installs as", `{"interface.enabled":false,"interface.mode":"userspace"}`, false},
		{"the interface mode", `{"interface.enabled":true,"interface.mode":"tun"}`, true},
		{"the module on, still contained", `{"interface.enabled":true,"interface.mode":"userspace"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.ConfigFileName)
			if err := writeFile(path, `{"settings":`+tc.settings+`}`); err != nil {
				t.Fatalf("write the config: %v", err)
			}
			env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Getenv: envWith(map[string]string{
				config.EnvStateDir: dir,
			})}

			wants, err := storedRightsWants(t.Context(), env, config.Flags{})
			if err != nil {
				t.Fatalf("storedRightsWants: %v", err)
			}
			if got := wants.interfaceMode; got != tc.want {
				t.Errorf("stored settings %s want the interface mode = %t, want %t", tc.settings, got, tc.want)
			}
		})
	}
}

// A config that cannot be read is a reason to stop, not a reason to assume the contained
// mode: the machine may be set to the interface mode, and starting it without rights is
// how someone gets a node that comes up and carries nothing.
func TestAnUnreadableConfigStopsTheStartRatherThanGuessingTheMode(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file belongs, which is what a botched restore of a backup
	// leaves behind and what an operator would otherwise never be told about.
	if err := os.Mkdir(filepath.Join(dir, config.ConfigFileName), 0o755); err != nil {
		t.Fatalf("stage an unreadable config: %v", err)
	}
	env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Getenv: envWith(map[string]string{
		config.EnvStateDir: dir,
	})}

	if _, err := storedRightsWants(t.Context(), env, config.Flags{}); err == nil {
		t.Fatal("a config that cannot be read was reported as asking for the contained mode")
	}
}

// The platform is asked before the config file is, so a machine that has no way to
// elevate never fails on a file it had no reason to open. The order is invisible on a
// healthy machine and decides everything on a broken one.
func TestAMachineThatCannotElevateDoesNotFailOnAConfigItNeverNeededToRead(t *testing.T) {
	if elevate.Supported() {
		t.Skipf("%s elevates, so it reads the stored mode to find out whether it has to", runtime.GOOS)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, config.ConfigFileName), 0o755); err != nil {
		t.Fatalf("stage an unreadable config: %v", err)
	}
	env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Getenv: envWith(map[string]string{
		config.EnvStateDir: dir,
	})}

	handedOff, err := elevateIfNeeded(t.Context(), env, config.Flags{}, nil, false, false)
	if err != nil {
		t.Fatalf("elevateIfNeeded read the stored mode on a platform that cannot act on it: %v", err)
	}
	if handedOff {
		t.Errorf("%s reported that it handed the agent to an elevated copy of itself", runtime.GOOS)
	}
}

// replaceableAt answers the elevation check's question with what the test says about one
// path, so the decision is exercised on a machine that never elevates.
func replaceableAt(path string, replaceable bool) func(string) (bool, string, error) {
	return func(exe string) (bool, string, error) {
		if exe != path {
			return false, "", errors.New("the check was asked about " + exe + " rather than the binary being elevated")
		}
		if !replaceable {
			return false, "", nil
		}
		return true, "app-tail is at " + exe + ", which is not one of the folders Windows keeps writable only by administrators", nil
	}
}

// Whatever is at the binary's path when the prompt is answered is what runs as
// Administrator. A binary in a folder this account can write is one any program running as
// this account can swap, or plant a wintun.dll beside, so elevating it is refused and the
// refusal says how to put app-tail somewhere protected.
func TestElevationFromAUserWritableFolderIsRefused(t *testing.T) {
	exe := `C:\Users\someone\Desktop\app-tail\app-tail.exe`
	var stderr bytes.Buffer

	err := vetElevationTarget(exe, false, replaceableAt(exe, true), &stderr)
	if !errors.Is(err, errUnprotectedElevation) {
		t.Fatalf("elevating a binary other programs could replace returned %v, want a refusal", err)
	}
	for _, want := range []string{exe, "app-tail install", "--" + allowUnprotectedElevationFlag} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q", err, want)
		}
	}
}

// The flag is the one way through, for a single run somebody started on purpose, and that
// run still says what it is exposed to.
func TestTheAllowUnprotectedElevationFlagLetsOneRunElevateWithAWarning(t *testing.T) {
	exe := `C:\Users\someone\Desktop\app-tail\app-tail.exe`
	var stderr bytes.Buffer

	if err := vetElevationTarget(exe, true, replaceableAt(exe, true), &stderr); err != nil {
		t.Fatalf("the flag was passed and elevation was still refused: %v", err)
	}
	if !strings.Contains(stderr.String(), exe) {
		t.Errorf("an unprotected elevation went ahead without saying so; stderr: %q", stderr.String())
	}
}

func TestABinaryOnlyAdministratorsCanChangeIsElevatedWithoutComment(t *testing.T) {
	exe := `C:\Program Files\app-tail\app-tail.exe`
	var stderr bytes.Buffer

	if err := vetElevationTarget(exe, false, replaceableAt(exe, false), &stderr); err != nil {
		t.Fatalf("an installed app-tail was refused elevation: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("an installed app-tail printed %q before elevating", stderr.String())
	}
}

// A check that could not be made is not a pass: it is the only thing between the rights and
// a program anybody can replace.
func TestElevationIsNotAskedForWhenTheBinaryCouldNotBeChecked(t *testing.T) {
	failing := func(string) (bool, string, error) { return false, "", errors.New("access denied") }

	err := vetElevationTarget(`C:\app-tail.exe`, true, failing, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("a failed check returned %v, want its failure", err)
	}
}

// The per-run flag is accepted by run and is not read from anywhere else: the program this
// guards against can set persistent environment variables and rewrite the config file.
func TestTheAllowUnprotectedElevationFlagIsAcceptedByRun(t *testing.T) {
	var got config.Flags
	env := Env{
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		Claim:    noClaim{},
		RunAgent: func(_ context.Context, f config.Flags) error { got = f; return nil },
	}
	if err := Run(context.Background(), []string{"run", "--no-elevate", "--" + allowUnprotectedElevationFlag}, env); err != nil {
		t.Fatalf("run refused --%s: %v", allowUnprotectedElevationFlag, err)
	}
	if got.NoElevate == nil {
		t.Error("the agent did not start")
	}
}

// The login item is built for the mode the machine is set to, because on Windows the mode
// decides which one is installed rather than only how it behaves. A manager built without
// it reports on one form and removes the other.
func TestTheLoginItemIsBuiltForTheModeTheMachineIsSetTo(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		want     bool
	}{
		{"the mode this app installs as", `{"interface.enabled":false,"interface.mode":"userspace"}`, false},
		{"the interface mode", `{"interface.enabled":true,"interface.mode":"tun"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writeFile(filepath.Join(dir, config.ConfigFileName), `{"settings":`+tc.settings+`}`); err != nil {
				t.Fatalf("write the config: %v", err)
			}
			env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Getenv: envWith(map[string]string{
				config.EnvStateDir: dir,
			})}

			manager, err := loginItem(env)
			if err != nil {
				t.Fatalf("loginItem: %v", err)
			}
			if manager.Elevated != tc.want {
				t.Errorf("login item built with Elevated = %t, want %t; it would install the wrong one", manager.Elevated, tc.want)
			}
		})
	}
}

// envWith answers the variables a test sets and nothing else, so a developer's own
// APPTAIL_STATE_DIR cannot reach into the run.
func envWith(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

// `app-tail status` is what somebody runs when the app is not doing what they turned on.
// A node that fell back to the contained mode answers every other line like one that did
// not, so these two lines are the whole difference between a diagnosable machine and a
// mystery.
func TestStatusSaysWhichStackTheNodeIsOnAndWhyItIsNotTheOneAskedFor(t *testing.T) {
	tests := []struct {
		name       string
		network    string
		fallback   string
		wantPhrase string
		wantAbsent string
	}{
		{
			name:       "a node that fell back names the mode and the reason",
			network:    string(config.NetworkUserspace),
			fallback:   "the privileged helper is not running: run `sudo app-tail tun install-helper`",
			wantPhrase: "install-helper",
		},
		{
			name:       "and says plainly that only app-tail reaches the tailnet",
			network:    string(config.NetworkUserspace),
			fallback:   "the privileged helper is not running",
			wantPhrase: "only app-tail",
		},
		{
			// A reason on a node doing exactly what was asked would send somebody to fix
			// something that is already working.
			name:       "a node on the interface says so and offers no reason",
			network:    string(config.NetworkTUN),
			wantPhrase: "the whole machine",
			wantAbsent: "not in force",
		},
		{
			// An agent too old to report the mode sends nothing, and a bare "Network:"
			// row with nothing after it reads as a broken agent rather than an old one.
			name:       "an agent that does not report the mode prints no row for it",
			wantAbsent: "Network",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, map[string]http.HandlerFunc{
				"GET /api/status": func(w http.ResponseWriter, _ *http.Request) {
					writeJSONResponse(t, w, http.StatusOK, httpapi.StatusView{
						BackendState:    "Running",
						Running:         true,
						AuthMode:        "oauth",
						Network:         tc.network,
						NetworkFallback: tc.fallback,
					})
				},
			})

			if err := h.run("status"); err != nil {
				t.Fatalf("status: %v", err)
			}
			if tc.wantPhrase != "" && !strings.Contains(h.out(), tc.wantPhrase) {
				t.Errorf("status output does not mention %q:\n%s", tc.wantPhrase, h.out())
			}
			if tc.wantAbsent != "" && strings.Contains(h.out(), tc.wantAbsent) {
				t.Errorf("status output claims %q for a node doing what was asked:\n%s", tc.wantAbsent, h.out())
			}
		})
	}
}

// Asking for administrator rights is the one thing this app tries hardest not to do, and
// a prompt that cannot change the outcome is the worst kind: the mode falls back to the
// contained one whether or not the rights arrive, so the answer costs a click at every
// start and buys nothing. What is in the way has to be reported instead.
func TestNothingIsAskedForWhenTheModeCouldNotRunAnyway(t *testing.T) {
	blocked := tsnode.InterfaceReport{
		Supported: true,
		Conflict:  "the official Tailscale client is connected on this machine",
	}
	wantsInterface := rightsWants{interfaceMode: true}
	if got := elevationBlocker(blocked, wantsInterface); got != blocked.Conflict {
		t.Errorf("a machine with a conflict reported %q as the blocker, want the conflict itself", got)
	}

	missing := tsnode.InterfaceReport{Supported: true, Missing: "wintun.dll is not next to app-tail.exe"}
	if got := elevationBlocker(missing, wantsInterface); got != missing.Missing {
		t.Errorf("a machine missing the driver reported %q as the blocker", got)
	}

	// The machine that can carry the mode is the one where the rights are worth asking
	// for -- a blocker reported here would stop the mode ever coming up. Unprivileged,
	// because that is the only shape this question is ever asked in: a process that already
	// holds the rights is answered by elevate.Needed before it gets here.
	ready := tsnode.InterfaceReport{Supported: true}
	if got := elevationBlocker(ready, wantsInterface); got != "" {
		t.Errorf("a machine that can carry the mode reported the blocker %q, which would refuse to elevate for it", got)
	}
}

// The two machine-level features are refused for different reasons, and each one's blocker
// says nothing about the other: a second tailnet client stops a network interface and
// leaves DNS alone, while something already holding port 53 is the other way round.
// Reporting the wrong one is how a working feature reads as broken and never elevates.
func TestTheBlockerReportedIsTheOneForWhatTheSettingsAskFor(t *testing.T) {
	report := tsnode.InterfaceReport{
		Supported:    true,
		Conflict:     "the official Tailscale client is connected on this machine",
		ResolverBusy: "another program is already answering DNS on every address app-tail would use",
	}

	if got := elevationBlocker(report, rightsWants{interfaceMode: true}); got != report.Conflict {
		t.Errorf("the interface mode reported %q as its blocker, want the conflicting client", got)
	}
	if got := elevationBlocker(report, rightsWants{systemDNS: true}); got != report.ResolverBusy {
		t.Errorf("the machine-wide resolver reported %q as its blocker, want the busy port", got)
	}
	// A machine with nothing in the way of DNS elevates for it even while a second tailnet
	// client would stop the interface mode: the resolver does not need an interface.
	clear := tsnode.InterfaceReport{Supported: true, Conflict: report.Conflict}
	if got := elevationBlocker(clear, rightsWants{systemDNS: true}); got != "" {
		t.Errorf("the machine-wide resolver was refused for %q, which is not about DNS at all", got)
	}
}

// The gate that decides whether to ask for administrator rights must never be told that the
// reason not to ask is that the process does not have them. On Windows there is no privileged
// helper, so an unprivileged report's readiness answer IS "app-tail needs administrator
// rights" -- and a gate reading that refuses to prompt because the prompt has not happened
// yet. That is how a machine gets left pointed at a resolver nothing is listening on, across
// every close and reopen, forever.
func TestTheRightsThemselvesAreNeverReportedAsTheReasonNotToAskForThem(t *testing.T) {
	// The shape every Windows process has at the moment this question is asked: the mode is
	// supported, there is no helper design, and the rights have not arrived yet.
	report := tsnode.InterfaceReport{Supported: true}

	for _, wants := range []rightsWants{
		{interfaceMode: true},
		{systemDNS: true},
		{staleOverride: true},
		{interfaceMode: true, systemDNS: true, staleOverride: true},
	} {
		if got := elevationBlocker(report, wants); got != "" {
			t.Errorf("%+v reported %q as the reason not to ask for the rights, which is the rights themselves", wants, got)
		}
	}
}

// The other half of the same gate, and the reason it exists: a prompt that cannot change the
// outcome costs a click at every start and buys nothing. Everything the rights would not fix
// still refuses.
func TestAMachineTheRightsCannotFixIsStillNeverAskedAbout(t *testing.T) {
	tests := []struct {
		name   string
		report tsnode.InterfaceReport
		wants  rightsWants
		says   string
	}{
		{
			name:   "a platform that cannot run the mode",
			report: tsnode.InterfaceReport{Supported: false},
			wants:  rightsWants{interfaceMode: true},
			says:   "cannot run app-tail on a network interface",
		},
		{
			name:   "a machine with no driver",
			report: tsnode.InterfaceReport{Supported: true, Missing: "wintun.dll is not next to app-tail.exe"},
			wants:  rightsWants{interfaceMode: true},
			says:   "wintun.dll",
		},
		{
			name:   "a second tailnet client",
			report: tsnode.InterfaceReport{Supported: true, Conflict: "the official Tailscale client is connected on this machine"},
			wants:  rightsWants{interfaceMode: true},
			says:   "official Tailscale client",
		},
		{
			name:   "something else answering DNS",
			report: tsnode.InterfaceReport{Supported: true, ResolverBusy: "another program is already answering DNS"},
			wants:  rightsWants{systemDNS: true},
			says:   "already answering DNS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elevationBlocker(tt.report, tt.wants)
			if !strings.Contains(got, tt.says) {
				t.Errorf("the blocker is %q, want it to mention %q rather than prompt for rights that change nothing", got, tt.says)
			}
		})
	}
}

// Putting this machine's name resolution back is a teardown. It needs no free port 53 and no
// network interface, so nothing a readiness answer reports about turning the feature ON says
// anything about whether it can be turned back OFF. Refusing the rights here leaves a machine
// that cannot resolve names permanently, which is worse than every state being refused for.
func TestPuttingThisMachinesResolverBackIsWorthTheRightsWhateverElseIsInTheWay(t *testing.T) {
	blocked := tsnode.InterfaceReport{
		Supported:    true,
		Conflict:     "the official Tailscale client is connected on this machine",
		ResolverBusy: "another program is already answering DNS on every address app-tail would use",
		Missing:      "wintun.dll is not next to app-tail.exe",
	}
	if got := elevationBlocker(blocked, rightsWants{staleOverride: true}); got != "" {
		t.Errorf("a machine left unable to resolve names was refused the rights for %q, and nothing else would ever put it back", got)
	}
}

// A refused prompt is ordinary and says nothing. A refused prompt on a machine that cannot
// resolve names is the one case worth a dialog on a build with no console -- and it has to
// carry the command that fixes it by hand, in the form this platform can actually run.
func TestARefusedPromptOnlyWarnsWhenThisMachineIsLeftUnableToResolveNames(t *testing.T) {
	if got := staleOverrideWarning(rightsWants{interfaceMode: true, systemDNS: true}, "windows", "the prompt was declined"); got != "" {
		t.Errorf("a healthy machine raised the warning %q after an ordinary declined prompt", got)
	}

	stale := rightsWants{staleOverride: true}
	windows := staleOverrideWarning(stale, "windows", "the prompt was declined")
	if !strings.Contains(windows, "app-tail dns restore") {
		t.Errorf("the warning %q does not carry the command that puts this machine back", windows)
	}
	if strings.Contains(windows, "sudo") {
		t.Errorf("the warning %q tells a Windows user to run sudo", windows)
	}
	if !strings.Contains(windows, "the prompt was declined") {
		t.Errorf("the warning %q does not say why the rights were not obtained", windows)
	}

	unix := staleOverrideWarning(stale, "darwin", "")
	if !strings.Contains(unix, "sudo app-tail dns restore") {
		t.Errorf("the warning %q does not carry the command a Mac can run", unix)
	}
}

// The same question, asked at startup and again at every settings save. They disagreed: the
// restart banner left the stale override out of the facts, so the dashboard -- the only way
// back to the prompt after it is declined once -- reported nothing to restart for on exactly
// the machine that needed it.
func TestBothMomentsAskElevateTheSameQuestionOfTheSameMachine(t *testing.T) {
	tests := []struct {
		name  string
		wants rightsWants
		field func(elevate.Facts) bool
	}{
		{"the interface mode", rightsWants{interfaceMode: true}, func(f elevate.Facts) bool { return f.WantsInterface }},
		{"the machine-wide resolver", rightsWants{systemDNS: true}, func(f elevate.Facts) bool { return f.WantsSystemDNS }},
		{"an override an earlier run left", rightsWants{staleOverride: true}, func(f elevate.Facts) bool { return f.StaleOverride }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.field(rightsFacts(tt.wants, false)) {
				t.Error("this want does not reach the facts elevation is decided from, so one of the two moments cannot see it")
			}
		})
	}

	// And the flag the relaunched child carries still stops a prompt loop.
	if !rightsFacts(rightsWants{staleOverride: true}, true).AlreadyAsked {
		t.Error("the child's --no-elevate did not reach the facts, so it could ask to be started again")
	}
}
