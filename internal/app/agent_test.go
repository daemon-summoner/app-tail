// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

func ptr[T any](v T) *T { return &v }

// settingsPatch builds the wire form a settings Update accepts: a JSON object where a
// present key means "change this field".
func settingsPatch(t *testing.T, kv map[string]any) map[string]json.RawMessage {
	t.Helper()
	out := make(map[string]json.RawMessage, len(kv))
	for k, v := range kv {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal patch field %q: %v", k, err)
		}
		out[k] = raw
	}
	return out
}

// --- startup and persistence ---------------------------------------------

// The CLI, the tray and the smoke test all find a running agent by reading the port it
// recorded, so a bound-but-unrecorded address strands every one of them. The default asks
// for any free port, which is why nothing can be inferred from the setting.
func TestAgentRecordsTheBoundDashboardAddress(t *testing.T) {
	h := newHarness(t, nil)

	recorded := config.ReadDashboardAddr(h.store.Path())
	if recorded == "" || strings.HasSuffix(recorded, ":0") {
		t.Fatalf("the record holds %q, want the concrete bound address", recorded)
	}
	if recorded != h.agent.UIAddr().String() {
		t.Fatalf("recorded %q but bound %v", recorded, h.agent.UIAddr())
	}

	host, _, err := net.SplitHostPort(recorded)
	if err != nil {
		t.Fatalf("parse recorded address %q: %v", recorded, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("the agent bound %q, which is not loopback", recorded)
	}
}

// Config holds credentials, so it must never be group- or world-readable.
func TestStoredConfigIsOwnerReadableOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on windows")
	}
	h := newHarness(t, nil)

	if got := configFileMode(t, h.store.Path()); got != config.FileMode {
		t.Fatalf("config mode = %04o, want %04o", got, config.FileMode)
	}
}

// Losing the dashboard because something else grabbed the remembered port would
// leave the user with no way to fix it.
func TestAgentFallsBackWhenTheConfiguredPortIsTaken(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer blocker.Close()
	taken := blocker.Addr().String()

	h := newHarness(t, func(c *config.Config) { c.Settings.UIListen = taken })

	bound := h.agent.UIAddr().String()
	if bound == taken {
		t.Fatalf("agent claims to have bound %q, which is already in use", taken)
	}
	if recorded := config.ReadDashboardAddr(h.store.Path()); recorded != bound {
		t.Fatalf("recorded %q but bound %q", recorded, bound)
	}
	if stored := h.store.Settings().UIListen; stored != taken {
		t.Fatalf("the configured address became %q, want the %q the user wrote", stored, taken)
	}

	resp, _ := h.get("/api/status")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the fallback listener does not serve: status %d", resp.StatusCode)
	}
}

// A refusal to bind must not leave a registered device behind on the tailnet.
func TestAgentDoesNotStartTheNodeWhenTheDashboardCannotBind(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	node := newFakeNode()
	agent, err := New(Options{
		Store: store,
		Runtime: config.Runtime{
			StateDir:   stateDir,
			ConfigPath: store.Path(),
			// Non-loopback is refused by the management server on principle.
			Settings: config.Settings{UIListen: "0.0.0.0:0"},
			Tunnels:  config.Defaults().Tunnels,
		},
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := agent.Run(context.Background()); err == nil {
		t.Fatal("Run succeeded despite a non-loopback dashboard address")
	}
	if node.started {
		t.Fatal("the tailnet node was started even though the dashboard could not bind")
	}
}

func TestNewRequiresAStore(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New accepted a nil config store")
	}
}

// --- lifecycle ------------------------------------------------------------

// Forwards need the tailnet in both directions, so none may run before the node
// reaches Running.
func TestForwardsWaitForTheNodeThenStart(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_llm", Name: "LLM", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}}
	})
	h.node.route("100.64.0.5:8100", echo)

	local := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	if conn, err := net.DialTimeout("tcp", local, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("the forward was listening before the node reached Running")
	}
	if h.agent.Forwards().AllRunning() {
		t.Fatal("AllRunning is true while the node is not Running")
	}

	h.bringUp()

	if got := roundTripTCP(t, local, "hello llm"); got != "hello llm" {
		t.Fatalf("round trip = %q, want %q", got, "hello llm")
	}
}

// A node that drops off the tailnet must not leave listeners accepting traffic it
// can no longer forward.
func TestForwardsStopWhenTheNodeGoesDownAndRestartWhenItReturns(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_llm", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}}
	})
	h.node.route("100.64.0.5:8100", echo)
	h.bringUp()

	local := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	if got := roundTripTCP(t, local, "up"); got != "up" {
		t.Fatalf("round trip before the drop = %q", got)
	}

	h.node.setState(tsnode.StateNeedsLogin)
	waitFor(t, 5*time.Second, "the forward's port to be released", func() bool {
		conn, err := net.DialTimeout("tcp", local, 100*time.Millisecond)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	})

	h.bringUp()
	if got := roundTripTCP(t, local, "back"); got != "back" {
		t.Fatalf("round trip after the node returned = %q", got)
	}
}

// Creating a forward through the API must start it, not merely record it.
func TestCreatingAForwardThroughTheAPIStartsIt(t *testing.T) {
	echo := startEchoTCP(t)
	h := newHarness(t, nil)
	h.node.route("100.64.0.5:8100", echo)
	h.bringUp()

	port := freePort(t)
	body := mustJSON(t, httpapi.ForwardSpec{
		Name: ptr("LLM"), Direction: ptr(config.ToLocal), Protocol: ptr(config.TCP),
		BindAddr: ptr("127.0.0.1"), ListenPort: ptr(port), Target: ptr("100.64.0.5:8100"),
	})
	resp, raw := h.request(http.MethodPost, "/api/forwards", strings.NewReader(body))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/forwards = %d: %s", resp.StatusCode, raw)
	}

	// The 201 describes what is running, not what was merely recorded: the write
	// waits for the forwarding engine before answering. No polling here on purpose --
	// a wait would hide exactly the lag this is asserting is gone.
	var created httpapi.ForwardView
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode the created forward: %v (body %s)", err, raw)
	}
	if created.State != forward.StateRunning {
		t.Fatalf("the 201 reported state %q, want %q", created.State, forward.StateRunning)
	}

	local := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	if got := roundTripTCP(t, local, "created"); got != "created" {
		t.Fatalf("round trip = %q", got)
	}
}

// Disabling through the API must actually release the port, not just flip a flag.
func TestDisablingAForwardThroughTheAPIStopsIt(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_llm", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}}
	})
	h.node.route("100.64.0.5:8100", echo)
	h.bringUp()

	local := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	roundTripTCP(t, local, "still up")

	resp, raw := h.request(http.MethodPost, "/api/forwards/fwd_llm/toggle",
		strings.NewReader(`{"enabled":false}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("toggle = %d: %s", resp.StatusCode, raw)
	}

	// The toggle waits for the engine, so its own response already describes a
	// stopped forward rather than one that is about to stop.
	var toggled httpapi.ForwardView
	if err := json.Unmarshal(raw, &toggled); err != nil {
		t.Fatalf("decode the toggle response: %v (body %s)", err, raw)
	}
	if toggled.State != forward.StateStopped {
		t.Fatalf("the toggle reported state %q, want %q", toggled.State, forward.StateStopped)
	}

	if conn, err := net.DialTimeout("tcp", local, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("the disabled forward was still listening when the toggle returned")
	}
}

// The API and the running engine must not disagree about what exists.
func TestDeletingAForwardThroughTheAPIStopsAndForgetsIt(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_llm", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}}
	})
	h.node.route("100.64.0.5:8100", echo)
	h.bringUp()

	resp, raw := h.request(http.MethodDelete, "/api/forwards/fwd_llm", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE = %d: %s", resp.StatusCode, raw)
	}

	local := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	if conn, err := net.DialTimeout("tcp", local, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("the deleted forward was still listening when the delete returned")
	}

	if len(h.store.Get().Forwards) != 0 {
		t.Fatalf("the forward survived deletion in the stored config: %+v", h.store.Get().Forwards)
	}
	if _, raw := h.get("/api/forwards/fwd_llm"); !strings.Contains(string(raw), "not found") {
		t.Fatalf("the deleted forward is still served: %s", raw)
	}
}

// A forward created through the API must survive a restart.
func TestForwardsPersistAcrossAgentRestarts(t *testing.T) {
	h := newHarness(t, nil)
	port := freePort(t)
	body := mustJSON(t, httpapi.ForwardSpec{
		Direction: ptr(config.ToLocal), Protocol: ptr(config.TCP),
		BindAddr: ptr("127.0.0.1"), ListenPort: ptr(port), Target: ptr("100.64.0.5:8100"),
	})
	resp, raw := h.request(http.MethodPost, "/api/forwards", strings.NewReader(body))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/forwards = %d: %s", resp.StatusCode, raw)
	}

	reopened, err := config.Open(h.store.Path())
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	stored := reopened.Get().Forwards
	if len(stored) != 1 {
		t.Fatalf("reopened config has %d forwards, want 1", len(stored))
	}
	if stored[0].ListenPort != port || stored[0].Target != "100.64.0.5:8100" {
		t.Fatalf("reopened forward = %+v", stored[0])
	}
}

// --- readiness ------------------------------------------------------------

func TestHealthzTracksTheNodeAndTheForwards(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_llm", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}}
	})
	h.node.route("100.64.0.5:8100", echo)

	resp, raw := h.get("/healthz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/healthz = %d before the node is up, want 503: %s", resp.StatusCode, raw)
	}

	h.bringUp()
	waitFor(t, 5*time.Second, "/healthz to report ready", func() bool {
		resp, _ := h.get("/healthz")
		return resp.StatusCode == http.StatusOK
	})
}

// A control-plane rejection reaches the node as a bus message, becomes its Problem, and
// has to come out the far end of /healthz. That is the whole chain an operator has: a
// 503 whose reason is the generic "tailnet node is not running" tells them nothing,
// while the diagnosed problem names the credential or tag to fix.
func TestANodeProblemBecomesTheHealthzReason(t *testing.T) {
	h := newHarness(t, nil)

	const problem = "auth key is expired; issue a new one in the admin console"
	h.node.setProblem(problem)

	waitFor(t, 5*time.Second, "the node problem to reach /healthz", func() bool {
		_, raw := h.get("/healthz")
		return strings.Contains(string(raw), problem)
	})

	resp, raw := h.get("/healthz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/healthz = %d with the node not running, want 503: %s", resp.StatusCode, raw)
	}
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode /healthz: %v (body %s)", err, raw)
	}
	if body.Reason != problem {
		t.Errorf("reason = %q, want the node's own diagnosis %q", body.Reason, problem)
	}
	if body.Status != "unhealthy" {
		t.Errorf("status = %q, want %q", body.Status, "unhealthy")
	}
}

// A node that is running has nothing to explain, so a stale problem must not keep the
// agent unready: the probe would report a failure the node already recovered from and
// a supervisor would restart a healthy agent in a loop.
func TestAProblemOnARunningNodeDoesNotHoldReadinessDown(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	h.node.setProblem("a complaint from before the node connected")

	// The probe reads the node's state, not its problem text.
	resp, raw := h.get("/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d for a running node carrying a stale problem, want 200: %s",
			resp.StatusCode, raw)
	}
}

// --- settings -------------------------------------------------------------

// A dashboard round-trip must not wipe a secret the client was never shown.
func TestSettingsRoundTripKeepsStoredSecrets(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { tailnetOf(t, c).AuthKey = "tskey-auth-secret" })

	resp, raw := h.get("/api/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/settings = %d: %s", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), "tskey-auth-secret") {
		t.Fatalf("the settings response leaked the auth key: %s", raw)
	}

	// Submit the view straight back, the way a dashboard save does.
	resp, raw = h.request(http.MethodPut, "/api/settings", strings.NewReader(
		fmt.Sprintf(`{"hostname":"renamed","authKey":%q}`, config.RedactedSecret)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}

	if got := storedTailnet(t, h.store).AuthKey; got != "tskey-auth-secret" {
		t.Fatalf("stored auth key = %q, want it untouched", got)
	}
	if got := storedTailnet(t, h.store).Hostname; got != "renamed" {
		t.Fatalf("stored hostname = %q, want the edited value", got)
	}
}

func TestSettingsUpdateReportsWhenARestartIsNeeded(t *testing.T) {
	h := newHarness(t, nil)

	tests := []struct {
		name        string
		body        string
		wantRestart bool
	}{
		{"hostname feeds the node", `{"hostname":"new-name"}`, true},
		{"tags feed the node", `{"tags":["tag:app-tail","tag:extra"]}`, true},
		{"an auth key feeds the node", `{"authKey":"tskey-auth-new"}`, true},
		{"advertise-tags-on-login feeds the node", `{"advertiseTagsOnLogin":true}`, true},
		// The tray is built once, from this setting, when the process starts. Nothing
		// re-reads it, so the save is stored and waiting rather than in force.
		{"tray visibility waits for the next start", `{"showTray":false}`, true},
		{"the udp timeout is live", `{"udpSessionTimeoutSec":45}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(tt.body))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
			}
			var got struct {
				RestartRequired bool `json:"restartRequired"`
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("decode %s: %v", raw, err)
			}
			if got.RestartRequired != tt.wantRestart {
				t.Fatalf("restartRequired = %v, want %v", got.RestartRequired, tt.wantRestart)
			}
		})
	}
}

// A UDP timeout change must reach the running engine without a restart, since the
// API reports that no restart is needed.
func TestLiveSettingsTakeEffectWithoutARestart(t *testing.T) {
	h := newHarness(t, nil)

	resp, raw := h.request(http.MethodPut, "/api/settings",
		strings.NewReader(`{"udpSessionTimeoutSec":45}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}

	if got := h.agent.settings().UDPSessionTimeoutSec; got != 45 {
		t.Fatalf("the running agent still uses a %ds udp timeout", got)
	}
}

// Flags and environment win over the stored file, so a value pinned by a flag must
// visibly not move rather than appearing to change and reverting on restart.
func TestAFlagPinnedSettingDoesNotMove(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	flags := config.Flags{Hostname: ptr("pinned-by-flag")}
	runtime, err := config.Resolve(flags, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	agent, err := New(Options{
		Store: store, Runtime: runtime, Flags: flags, Getenv: emptyEnv, Logger: quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return newFakeNode() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	view, _, err := agent.Settings().Update(noEngine, settingsPatch(t, map[string]any{"hostname": "from-dashboard"}))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got, _ := view["hostname"].(string); got != "pinned-by-flag" {
		t.Fatalf("effective hostname = %q, want the flag to keep winning", got)
	}
	if got := storedTailnet(t, store).Hostname; got != "from-dashboard" {
		t.Fatalf("stored hostname = %q, want the edit recorded for when the flag is dropped", got)
	}
}

// --- suggest-port ---------------------------------------------------------

// Suggesting a port another forward already claims would produce a config the
// store immediately rejects.
func TestSuggestPortAvoidsPortsOtherForwardsClaim(t *testing.T) {
	port := freePort(t)
	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_a", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100",
			// Disabled on purpose: its port is still reserved, because re-enabling
			// it must not then fail.
			Enabled: false,
		}}
	})

	got, err := h.agent.Forwards().SuggestPort(config.TCP, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("SuggestPort: %v", err)
	}
	if got == port {
		t.Fatalf("SuggestPort returned %d, which a stopped forward already claims", got)
	}
}

// A both-protocol forward owns its port on both stacks, so a tcp-only suggestion for
// that port must be steered elsewhere, or saving the new forward would then conflict.
func TestSuggestPortAvoidsAPortAlreadyOwnedByABothForward(t *testing.T) {
	port := freePort(t)
	h := newHarness(t, func(c *config.Config) {
		c.Forwards = []config.Forward{{
			ID: "fwd_both", Direction: config.ToLocal, Protocol: config.Both,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "dns-box:53",
			Enabled: false,
		}}
	})

	got, err := h.agent.Forwards().SuggestPort(config.TCP, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("SuggestPort: %v", err)
	}
	if got == port {
		t.Fatalf("SuggestPort returned %d, which a both forward already claims on tcp", got)
	}
}

// Handing out the dashboard's own port would cut the user off from the app.
func TestSuggestPortNeverReturnsTheDashboardPort(t *testing.T) {
	h := newHarness(t, nil)
	uiPort := h.agent.UIAddr().(*net.TCPAddr).Port

	got, err := h.agent.Forwards().SuggestPort(config.TCP, "127.0.0.1", uiPort)
	if err != nil {
		t.Fatalf("SuggestPort: %v", err)
	}
	if got == uiPort {
		t.Fatal("SuggestPort handed out the dashboard's own port")
	}
}

func TestSuggestPortOverHTTP(t *testing.T) {
	h := newHarness(t, nil)
	resp, raw := h.get("/api/forwards/suggest-port?protocol=tcp&target=100.64.0.5:8100")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("suggest-port = %d: %s", resp.StatusCode, raw)
	}
	var got struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	if got.Port < 1 || got.Port > 65535 {
		t.Fatalf("port = %d, which is not a usable port", got.Port)
	}
}

// --- presets --------------------------------------------------------------

func TestUserPresetsPersistAndBuiltInsAreProtected(t *testing.T) {
	h := newHarness(t, nil)

	resp, raw := h.request(http.MethodPost, "/api/presets",
		strings.NewReader(`{"name":"Grafana","protocol":"tcp","remotePort":3000}`))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/presets = %d: %s", resp.StatusCode, raw)
	}
	var created config.Preset
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	if created.ID == "" {
		t.Fatal("the created preset has no id")
	}

	reopened, err := config.Open(h.store.Path())
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	stored := reopened.Get().Presets
	if len(stored) != 1 || stored[0].Name != "Grafana" || stored[0].RemotePort != 3000 {
		t.Fatalf("reopened presets = %+v", stored)
	}

	// Shipped presets belong to the binary; deleting one must be refused loudly.
	resp, raw = h.request(http.MethodDelete, "/api/presets/ssh", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DELETE /api/presets/ssh = %d, want 400: %s", resp.StatusCode, raw)
	}

	resp, raw = h.request(http.MethodDelete, "/api/presets/"+created.ID, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/presets/%s = %d: %s", created.ID, resp.StatusCode, raw)
	}
	if reopened, err := config.Open(h.store.Path()); err != nil {
		t.Fatalf("reopen store: %v", err)
	} else if len(reopened.Get().Presets) != 0 {
		t.Fatalf("the user preset survived deletion: %+v", reopened.Get().Presets)
	}
}

// --- shutdown -------------------------------------------------------------

// A clean exit is what makes the process usable under systemd and launchd.
func TestCancellingRunShutsEverythingDownCleanly(t *testing.T) {
	echo := startEchoTCP(t)
	port := freePort(t)

	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// Pin the dashboard port too: the release check below rebinds it, and an
	// OS-assigned one comes from the ephemeral pool another test process draws from.
	uiPort := freePort(t)
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = net.JoinHostPort("127.0.0.1", fmt.Sprint(uiPort))
		c.Forwards = []config.Forward{{
			ID: "fwd_llm", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: "127.0.0.1", ListenPort: port, Target: "100.64.0.5:8100", Enabled: true,
		}}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	node := newFakeNode()
	node.route("100.64.0.5:8100", echo)
	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	waitFor(t, 5*time.Second, "the agent to bind", func() bool { return agent.UIAddr() != nil })
	uiAddr := agent.UIAddr().String()
	// The node is started after the listener, and Start writes the backend state. Setting
	// Running before that lands would have the Start still to come overwrite it, and the
	// agent would never see the node come up.
	waitFor(t, 5*time.Second, "the agent to start the node", node.wasStarted)
	node.setState(tsnode.StateRunning)
	waitFor(t, 5*time.Second, "the forward to start", func() bool {
		return agent.Forwards().AllRunning()
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on a clean cancellation", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return within 15s of cancellation")
	}

	if !node.wasClosed() {
		t.Error("the tailnet node was not closed during shutdown")
	}

	// Every socket the agent owned must be released, or a restart cannot rebind.
	for _, addr := range []string{uiAddr, net.JoinHostPort("127.0.0.1", fmt.Sprint(port))} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("%s was not released on shutdown: %v", addr, err)
			continue
		}
		ln.Close()
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		NewNode: func(tsnode.Options) NodeController { return newFakeNode() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	waitFor(t, 5*time.Second, "the agent to bind", func() bool { return agent.UIAddr() != nil })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Run already shut down; an explicit second call must not hang or error.
	if err := agent.Shutdown(context.Background()); err != nil {
		t.Fatalf("a second Shutdown returned %v", err)
	}
}

// --- dashboard URL --------------------------------------------------------

func TestDashboardURLIsBrowserOpenable(t *testing.T) {
	h := newHarness(t, nil)
	url := h.agent.DashboardURL()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("DashboardURL = %q, want a loopback http URL", url)
	}

	resp, err := http.Get(url + "/api/status")
	if err != nil {
		t.Fatalf("the dashboard URL is not reachable: %v", err)
	}
	resp.Body.Close()
}

func TestDashboardURLIsEmptyBeforeBinding(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := agent.DashboardURL(); got != "" {
		t.Fatalf("DashboardURL = %q before Run, want empty", got)
	}
}

// An API write that lands while the agent is stopping must not park on a lifecycle
// goroutine that has stopped consuming. Closing the management server waits for
// in-flight requests, so a parked handler would serialize shutdown behind its own
// timeout -- the agent would take seconds longer to exit for no reason at all.
func TestReconcileNowDoesNotBlockOnceTheAgentIsStopping(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	done := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		agent.reconcileNow(context.Background())
		done <- time.Since(started)
	}()

	select {
	case elapsed := <-done:
		if elapsed >= reconcileTimeout {
			t.Fatalf("reconcileNow took %s: it waited out its timeout instead of noticing the shutdown", elapsed)
		}
	case <-time.After(reconcileTimeout + 2*time.Second):
		t.Fatal("reconcileNow never returned after the agent stopped")
	}
}

// A dashboard that navigates away mid-request cancels its context. Stage 1.4 threaded
// that context through the forward writes for exactly this: the handler stops waiting
// immediately instead of holding a goroutine for the full acknowledgement timeout.
// The reconcile itself still happens -- a missed ack costs freshness, never correctness.
func TestReconcileNowGivesUpWhenTheRequestIsCancelled(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := agent.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	// Nothing is consuming syncReconcile: New does not start the lifecycle goroutine,
	// so the send blocks and only the context can release it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		agent.reconcileNow(ctx)
		done <- time.Since(started)
	}()

	select {
	case elapsed := <-done:
		if elapsed >= reconcileTimeout {
			t.Fatalf("reconcileNow took %s: it waited out its timeout instead of noticing the cancelled request", elapsed)
		}
	case <-time.After(reconcileTimeout + 2*time.Second):
		t.Fatal("reconcileNow never returned after its context was cancelled")
	}

	// The fallback poke is what keeps the reconcile from being lost entirely.
	select {
	case <-agent.reconcile:
	default:
		t.Error("no asynchronous reconcile was queued, so the write would never be applied")
	}
}

// A node that refuses to start is an ordinary failure: bad credentials, a control
// plane that is down. The agent binds its dashboard port before it starts the node,
// so a failure there must still release the port and finish shutting down -- or the
// port stays held until the process is killed and every caller waiting on the agent
// waits on a lifecycle goroutine that was never running.
func TestAFailedNodeStartTearsTheAgentDown(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open config store: %v", err)
	}

	uiAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(freePort(t)))
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = uiAddr
		return nil
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	node := newFakeNode()
	node.startErr = errors.New("control plane refused the auth key")

	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		Version: "test",
		NewNode: func(tsnode.Options) NodeController { return node },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	runErr := agent.Run(context.Background())
	if runErr == nil {
		t.Fatal("Run reported success although the node could not start")
	}
	if !strings.Contains(runErr.Error(), "control plane refused the auth key") {
		t.Fatalf("Run error = %v, want it to carry the node's own failure", runErr)
	}

	ln, err := net.Listen("tcp", uiAddr)
	if err != nil {
		t.Fatalf("the dashboard port was still held after a failed start: %v", err)
	}
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch err := agent.RestartNode(ctx); {
	case err == nil:
		t.Fatal("RestartNode succeeded against an agent whose lifecycle never started")
	case errors.Is(err, context.DeadlineExceeded):
		t.Fatal("RestartNode blocked instead of reporting that the agent is down")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// newIdleAgent builds an agent whose lifecycle goroutine is not running, so nothing
// ever consumes syncReconcile. That is the state every reconcileNow give-up branch
// has to survive.
func newIdleAgent(t *testing.T) *Agent {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := agent.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return agent
}

// An engine too busy to accept the request within the timeout must not cost the write
// its reconcile. Dropping the fallback poke here is the one mutation that turns a
// slow reconcile into a forward that never starts at all, with the API still
// answering 201.
func TestReconcileNowFallsBackToTheAsyncPokeWhenTheEngineNeverAnswers(t *testing.T) {
	t.Parallel()
	agent := newIdleAgent(t)

	done := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		agent.reconcileNow(context.Background())
		done <- time.Since(started)
	}()

	select {
	case elapsed := <-done:
		if elapsed < reconcileTimeout {
			t.Fatalf("reconcileNow returned after %s, before its %s timeout", elapsed, reconcileTimeout)
		}
	case <-time.After(reconcileTimeout + 5*time.Second):
		t.Fatal("reconcileNow never gave up; an API write would hold its goroutine forever")
	}

	select {
	case <-agent.reconcile:
	default:
		t.Error("no asynchronous reconcile was queued, so the write would never be applied")
	}
}

// Once the request is accepted the caller is parked on the acknowledgement. Every exit
// from that second wait is tested below: without them a handler blocks until the
// process dies, and http.Shutdown -- which waits on in-flight requests -- blocks with
// it, so the agent could never finish shutting down.
func TestReconcileNowStopsWaitingForAnAcknowledgementItWillNeverGet(t *testing.T) {
	tests := []struct {
		name    string
		release func(t *testing.T, agent *Agent, cancel context.CancelFunc)
	}{
		{
			name: "the agent starts shutting down",
			release: func(t *testing.T, agent *Agent, _ context.CancelFunc) {
				t.Helper()
				if err := agent.Shutdown(context.Background()); err != nil {
					t.Errorf("Shutdown: %v", err)
				}
			},
		},
		{
			name:    "the request is cancelled",
			release: func(_ *testing.T, _ *Agent, cancel context.CancelFunc) { cancel() },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := newIdleAgent(t)

			// Take the request but never close the ack, standing in for a reconcile
			// that outlives the caller's patience.
			taken := make(chan struct{})
			go func() {
				<-agent.syncReconcile
				close(taken)
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := make(chan struct{})
			go func() {
				agent.reconcileNow(ctx)
				close(done)
			}()

			<-taken
			select {
			case <-done:
				t.Fatal("reconcileNow returned before it was released; it never waited for the ack")
			case <-time.After(50 * time.Millisecond):
			}

			tt.release(t, agent, cancel)

			select {
			case <-done:
			case <-time.After(reconcileTimeout):
				t.Fatal("reconcileNow stayed parked on an acknowledgement that will never arrive")
			}
		})
	}
}

// The acknowledgement wait has its own timeout, and it is the only thing standing
// between a wedged lifecycle goroutine and an API handler parked forever on a request
// that was accepted but never finished.
func TestReconcileNowGivesUpOnASilentEngineAfterTheTimeout(t *testing.T) {
	t.Parallel()
	agent := newIdleAgent(t)

	taken := make(chan struct{})
	go func() {
		<-agent.syncReconcile
		close(taken)
	}()

	done := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		agent.reconcileNow(context.Background())
		done <- time.Since(started)
	}()

	<-taken
	select {
	case elapsed := <-done:
		if elapsed < reconcileTimeout {
			t.Fatalf("reconcileNow returned after %s, before its %s timeout", elapsed, reconcileTimeout)
		}
	case <-time.After(reconcileTimeout + 5*time.Second):
		t.Fatal("reconcileNow never gave up on the acknowledgement")
	}
}

// RestartNode is what the settings dialog calls after a hostname or auth change. Unlike
// reconcileNow it has no timeout of its own, so its only exits are the two channels
// below -- and it is called from an HTTP handler that Shutdown waits on. A branch that
// did not fire would park that handler, and the agent would never finish exiting.
func TestRestartNodeGivesUpBeforeItsRequestIsEvenAccepted(t *testing.T) {
	tests := []struct {
		name    string
		release func(t *testing.T, agent *Agent, cancel context.CancelFunc)
		wantErr func(t *testing.T, err error)
	}{
		{
			name: "the agent is already shutting down",
			release: func(t *testing.T, agent *Agent, _ context.CancelFunc) {
				t.Helper()
				if err := agent.Shutdown(context.Background()); err != nil {
					t.Errorf("Shutdown: %v", err)
				}
			},
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "shutting down") {
					t.Errorf("err = %v, want it to say the agent is shutting down", err)
				}
			},
		},
		{
			name:    "the request is cancelled",
			release: func(_ *testing.T, _ *Agent, cancel context.CancelFunc) { cancel() },
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				if !errors.Is(err, context.Canceled) {
					t.Errorf("err = %v, want context.Canceled so the handler can tell a "+
						"caller that walked away from an agent that failed", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Nothing consumes a.restart: New does not start the lifecycle goroutine, so
			// the send parks and only one of the two escapes can release it.
			agent := newIdleAgent(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := make(chan error, 1)
			go func() { done <- agent.RestartNode(ctx) }()

			select {
			case err := <-done:
				t.Fatalf("RestartNode returned %v before anything released it; its request "+
					"was never actually offered to the lifecycle goroutine", err)
			case <-time.After(50 * time.Millisecond):
			}

			tt.release(t, agent, cancel)

			select {
			case err := <-done:
				tt.wantErr(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("RestartNode stayed parked on a request nothing will ever take")
			}
		})
	}
}

// Past the hand-off the caller waits on the rebuild's result. A shutdown that started
// while the node was being rebuilt has to release that wait too: the lifecycle goroutine
// is gone, so the result it promised is never coming.
func TestRestartNodeStopsWaitingForAResultThatWillNeverArrive(t *testing.T) {
	tests := []struct {
		name    string
		release func(t *testing.T, agent *Agent, cancel context.CancelFunc)
		wantErr func(t *testing.T, err error)
	}{
		{
			name: "the agent starts shutting down mid-rebuild",
			release: func(t *testing.T, agent *Agent, _ context.CancelFunc) {
				t.Helper()
				if err := agent.Shutdown(context.Background()); err != nil {
					t.Errorf("Shutdown: %v", err)
				}
			},
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				if err == nil || !strings.Contains(err.Error(), "shutting down") {
					t.Errorf("err = %v, want it to say the agent is shutting down", err)
				}
			},
		},
		{
			name:    "the request is cancelled mid-rebuild",
			release: func(_ *testing.T, _ *Agent, cancel context.CancelFunc) { cancel() },
			wantErr: func(t *testing.T, err error) {
				t.Helper()
				if !errors.Is(err, context.Canceled) {
					t.Errorf("err = %v, want context.Canceled", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := newIdleAgent(t)

			// Take the request but never answer it, standing in for a rebuild that
			// outlives the caller.
			taken := make(chan struct{})
			go func() {
				<-agent.restart
				close(taken)
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := make(chan error, 1)
			go func() { done <- agent.RestartNode(ctx) }()

			<-taken
			select {
			case err := <-done:
				t.Fatalf("RestartNode returned %v without waiting for the rebuild; the "+
					"dialog would report success while the node was still coming up", err)
			case <-time.After(50 * time.Millisecond):
			}

			tt.release(t, agent, cancel)

			select {
			case err := <-done:
				tt.wantErr(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("RestartNode stayed parked on a result that will never arrive")
			}
		})
	}
}

// The whole point of the round trip is that the caller learns whether the rebuild
// worked. A restart that swallowed the failure would leave the dashboard reporting a
// successful settings save over a node that is down.
func TestRestartNodeReportsWhatTheRebuildAnswered(t *testing.T) {
	tests := []struct {
		name  string
		reply error
	}{
		{"the rebuild succeeded", nil},
		{"the rebuild failed", errors.New("restart tailnet node: control plane refused the auth key")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := newIdleAgent(t)

			go func() {
				req := <-agent.restart
				req.result <- tt.reply
			}()

			err := agent.RestartNode(context.Background())

			switch {
			case tt.reply == nil && err != nil:
				t.Errorf("err = %v after a successful rebuild, want nil", err)
			case tt.reply != nil && !errors.Is(err, tt.reply):
				t.Errorf("err = %v, want the rebuild's own failure %v", err, tt.reply)
			}
		})
	}
}
