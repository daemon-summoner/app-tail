// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// exec runs a command against the fake agent with an explicit argument list, for the
// nested subcommands where --config must sit after the whole subcommand chain.
func (h *harness) exec(args ...string) error {
	return Run(context.Background(), args, h.env())
}

// cfg is the --config pair pointing the CLI at this harness's agent.
func (h *harness) cfg() []string { return []string{"--config", h.configPath} }

// settingsRoutes serves GET/PUT settings backed by the real registry drivers, so a CLI
// test exercises the true redaction and patch-apply contract rather than a restatement
// of it. restart says what the agent reports a change needs.
func settingsRoutes(t *testing.T, stored *config.Config, restart map[string]bool) map[string]http.HandlerFunc {
	view := func() map[string]any { return config.SettingsViewOf(stored) }
	return map[string]http.HandlerFunc{
		"GET /api/settings": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, view())
		},
		"PUT /api/settings": func(w http.ResponseWriter, r *http.Request) {
			var patch map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Errorf("decode patch: %v", err)
			}
			if err := config.ApplyPatchTo(stored, patch); err != nil {
				writeJSONResponse(t, w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			resp := view()
			resp["nodeRestart"] = restart["node"]
			resp["uiRelisten"] = restart["ui"]
			resp["appRestart"] = restart["app"]
			resp["restartRequired"] = restart["node"] || restart["ui"] || restart["app"]
			writeJSONResponse(t, w, http.StatusOK, resp)
		},
	}
}

// tailnetOf is the primary connection's tailnet block inside a fake agent's document,
// which is where the settings keys that name the tailnet write now.
func tailnetOf(t *testing.T, cfg *config.Config) *config.TailscaleTunnel {
	t.Helper()
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].ID != config.PrimaryTunnelID {
			continue
		}
		if cfg.Tunnels[i].Tailscale == nil {
			cfg.Tunnels[i].Tailscale = &config.TailscaleTunnel{}
		}
		return cfg.Tunnels[i].Tailscale
	}
	t.Fatalf("the fake document carries no %q connection", config.PrimaryTunnelID)
	return nil
}

func TestSettingsListShowsValuesAndHidesSecrets(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).Hostname = "app-tail-laptop"
	tailnetOf(t, stored).AuthKey = "tskey-auth-super-secret"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	if err := h.exec(append([]string{"settings", "list"}, h.cfg()...)...); err != nil {
		t.Fatalf("settings list: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "app-tail-laptop") {
		t.Errorf("list did not show the hostname:\n%s", out)
	}
	if strings.Contains(out, "tskey-auth-super-secret") {
		t.Fatalf("list leaked the auth key:\n%s", out)
	}
	// The auth key row must show only that one is set.
	if !strings.Contains(out, "auth-key") || !strings.Contains(out, "set") {
		t.Errorf("list did not report the auth key as set:\n%s", out)
	}
}

func TestSettingsGetPrintsASingleValue(t *testing.T) {
	stored := config.Defaults()
	stored.Settings.UDPSessionTimeoutSec = 90
	h := newHarness(t, settingsRoutes(t, stored, nil))

	if err := h.exec("settings", "get", "--config", h.configPath, "udp-timeout"); err != nil {
		t.Fatalf("settings get: %v", err)
	}
	if got := strings.TrimSpace(h.out()); got != "90" {
		t.Errorf("settings get udp-timeout = %q, want 90", got)
	}
}

// settings get --json emits the raw value a script can consume, not the rendered text.
func TestSettingsGetJSONEmitsTheRawValue(t *testing.T) {
	stored := config.Defaults()
	stored.Settings.UDPSessionTimeoutSec = 90
	h := newHarness(t, settingsRoutes(t, stored, nil))

	if err := h.exec("settings", "get", "--config", h.configPath, "--json", "udp-timeout"); err != nil {
		t.Fatalf("settings get --json: %v", err)
	}
	var got float64
	if err := json.Unmarshal([]byte(strings.TrimSpace(h.out())), &got); err != nil {
		t.Fatalf("settings get --json did not emit a JSON number: %v\n%s", err, h.out())
	}
	if got != 90 {
		t.Errorf("settings get --json udp-timeout = %v, want 90", got)
	}
}

func TestSettingsGetReportsASecretAsSetWithoutRevealingIt(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).AuthKey = "tskey-auth-super-secret"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	if err := h.exec("settings", "get", "--config", h.configPath, "auth-key"); err != nil {
		t.Fatalf("settings get auth-key: %v", err)
	}
	out := strings.TrimSpace(h.out())
	if out != "set" {
		t.Errorf("settings get auth-key = %q, want \"set\"", out)
	}
	if strings.Contains(out, "tskey") {
		t.Fatalf("settings get leaked the secret: %q", out)
	}
}

func TestSettingsSetAppliesAValue(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	if err := h.exec("settings", "set", "--config", h.configPath, "udp-timeout", "120"); err != nil {
		t.Fatalf("settings set: %v", err)
	}
	if stored.Settings.UDPSessionTimeoutSec != 120 {
		t.Errorf("stored udp timeout = %d, want 120", stored.Settings.UDPSessionTimeoutSec)
	}
}

// A patch that changes a restart-class field must tell the user what still has to
// happen for it to take effect, since the write alone does not apply it.
func TestSettingsSetReportsARequiredRestart(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, map[string]bool{"node": true, "ui": true}))

	if err := h.exec("settings", "set", "--config", h.configPath, "udp-timeout", "120"); err != nil {
		t.Fatalf("settings set: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "app-tail restart") {
		t.Errorf("a node-restart change did not point at `app-tail restart`:\n%s", out)
	}
	if !strings.Contains(out, "restart the app-tail process") {
		t.Errorf("a ui-relisten change did not warn about a process restart:\n%s", out)
	}
}

// A setting the process reads only at start is stored and correct the moment it is
// written, and nothing acts on it until the next start. A bare "Saved." there sends
// someone looking for a change that is not going to appear until they restart.
func TestSettingsSetSaysASettingReadAtStartWaitsForTheNextOne(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, map[string]bool{"app": true}))

	if err := h.exec("settings", "set", "--config", h.configPath, "show-tray", "false"); err != nil {
		t.Fatalf("settings set: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "next time app-tail runs") {
		t.Errorf("a start-read change did not say when it applies:\n%s", out)
	}
	// It is not a node restart, and pointing at one would have the user rebuild the node
	// and find nothing changed.
	if strings.Contains(out, "app-tail restart") {
		t.Errorf("a start-read change asked for a node restart:\n%s", out)
	}
}

func TestSettingsSetFlagFormAppliesSeveralValues(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	if err := h.exec("settings", "set", "--config", h.configPath,
		"--hostname=box", "--ephemeral=true"); err != nil {
		t.Fatalf("settings set flags: %v", err)
	}
	if tailnetOf(t, stored).Hostname != "box" {
		t.Errorf("stored hostname = %q, want box", tailnetOf(t, stored).Hostname)
	}
	if !tailnetOf(t, stored).Ephemeral {
		t.Error("stored ephemeral was not set true")
	}
}

// A secret must never be settable from argv, where it would be visible to every
// process; the command has to send the user to the no-echo menu instead.
func TestSettingsSetRefusesASecretOnTheCommandLine(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	err := h.exec("settings", "set", "--config", h.configPath, "auth-key", "tskey-leak")
	if err == nil {
		t.Fatal("settings set accepted a secret on the command line")
	}
	if !strings.Contains(err.Error(), "menu") {
		t.Errorf("error %q does not point at the interactive menu", err)
	}
	// It must not have reached the agent.
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut {
			t.Error("a secret patch was sent to the agent despite the refusal")
		}
	}
}

func TestSettingsSetRejectsReadOnlyAndUnknownKeys(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	cases := map[string]string{
		"machineId":    "read-only",
		"startAtLogin": "install-autostart",
		"notASetting":  "unknown setting",
	}
	for key, want := range cases {
		err := h.exec("settings", "set", "--config", h.configPath, key, "x")
		if err == nil {
			t.Errorf("settings set %s was accepted", key)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("settings set %s: error %q does not mention %q", key, err.Error(), want)
		}
	}
}

// When an env or flag pins a value above the stored config, a write of that field looks
// like a no-op; the command must say why rather than leave the user confused.
func TestWarnPinnedNamesTheEnvironmentCulprit(t *testing.T) {
	t.Run("pinned value warns", func(t *testing.T) {
		var buf bytes.Buffer
		patch := map[string]json.RawMessage{"hostname": json.RawMessage(`"typed-name"`)}
		view := map[string]any{"hostname": "pinned-name"}
		warnPinned(&buf, patch, view)
		out := buf.String()
		for _, want := range []string{"hostname", "pinned-name", config.EnvHostname} {
			if !strings.Contains(out, want) {
				t.Errorf("pin warning %q is missing %q", out, want)
			}
		}
	})

	t.Run("applied value is silent", func(t *testing.T) {
		var buf bytes.Buffer
		patch := map[string]json.RawMessage{"hostname": json.RawMessage(`"box"`)}
		view := map[string]any{"hostname": "box"}
		warnPinned(&buf, patch, view)
		if buf.Len() != 0 {
			t.Errorf("a value that applied cleanly still warned: %q", buf.String())
		}
	})

	// A secret has no echoed value, so it can never be compared and must never warn.
	t.Run("secret never warns", func(t *testing.T) {
		var buf bytes.Buffer
		patch := map[string]json.RawMessage{"authKey": json.RawMessage(`"tskey-new"`)}
		view := map[string]any{"hasAuthKey": true}
		warnPinned(&buf, patch, view)
		if buf.Len() != 0 {
			t.Errorf("a secret write warned about pinning: %q", buf.String())
		}
	})
}

// The menu would hang on the first prompt without a terminal, so it refuses one and
// names the scriptable alternative.
func TestSettingsMenuRefusesANonInteractiveStdin(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	err := h.exec("settings", "menu", "--config", h.configPath)
	if err == nil {
		t.Fatal("settings menu ran without a terminal")
	}
	if !strings.Contains(err.Error(), "terminal") || !strings.Contains(err.Error(), "settings set") {
		t.Errorf("error %q does not explain the non-interactive refusal", err)
	}
}

// scriptedPrompter feeds the menu a fixed sequence, so the interactive loop is tested
// without a real terminal.
type scriptedPrompter struct {
	lines   []string
	secrets []string
}

func (p *scriptedPrompter) line(string) (string, error) {
	if len(p.lines) == 0 {
		return "", errAborted
	}
	next := p.lines[0]
	p.lines = p.lines[1:]
	return next, nil
}

func (p *scriptedPrompter) secret(string) (string, error) {
	if len(p.secrets) == 0 {
		return "", errAborted
	}
	next := p.secrets[0]
	p.secrets = p.secrets[1:]
	return next, nil
}

func TestSettingsMenuEditsAFieldAndASecretThenRestarts(t *testing.T) {
	stored := config.Defaults()
	routes := settingsRoutes(t, stored, map[string]bool{"node": true})
	restarted := make(chan struct{}, 1)
	routes["POST /api/restart"] = func(w http.ResponseWriter, _ *http.Request) {
		restarted <- struct{}{}
		writeJSONResponse(t, w, http.StatusOK, map[string]string{"backendState": "Starting"})
	}
	h := newHarness(t, routes)
	client := h.client()

	// Field 1 is hostname, field 5 is the auth-key secret (registry order). Edit both,
	// save, and accept the offered node restart.
	p := &scriptedPrompter{
		lines:   []string{"1", "renamed-host", "5", "s", "y"},
		secrets: []string{"tskey-auth-brand-new"},
	}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), client, p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	if tailnetOf(t, stored).Hostname != "renamed-host" {
		t.Errorf("hostname = %q, want the edited value", tailnetOf(t, stored).Hostname)
	}
	if tailnetOf(t, stored).AuthKey != "tskey-auth-brand-new" {
		t.Errorf("auth key = %q, want the value typed at the no-echo prompt", tailnetOf(t, stored).AuthKey)
	}
	if !strings.Contains(out.String(), "Saved.") {
		t.Errorf("menu did not confirm the save:\n%s", out.String())
	}
	select {
	case <-restarted:
	default:
		t.Error("the accepted restart offer never reached the agent")
	}
	// The typed secret must not appear anywhere in what the menu printed.
	if strings.Contains(out.String(), "tskey-auth-brand-new") {
		t.Errorf("menu echoed the secret:\n%s", out.String())
	}
}

func TestSettingsMenuQuitsWithoutSaving(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).Hostname = "unchanged"
	h := newHarness(t, settingsRoutes(t, stored, nil))
	client := h.client()

	p := &scriptedPrompter{lines: []string{"1", "would-change", "q"}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), client, p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}
	if tailnetOf(t, stored).Hostname != "unchanged" {
		t.Errorf("quitting the menu still changed the hostname to %q", tailnetOf(t, stored).Hostname)
	}
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut {
			t.Error("quitting the menu still sent a settings write")
		}
	}
}

// The restart flags drive what the CLI tells the user to do next. An agent reply that
// omits them, or carries them with the wrong type, must read as "nothing to restart":
// the alternatives are a panic on a decoded string and a CLI that demands a restart
// after every settings write.
func TestUpdateSettingsReadsRestartFlagsDefensively(t *testing.T) {
	tests := []struct {
		name string
		body string
		want SettingsResult
	}{
		{
			name: "flags absent",
			body: `{"hostname":"box"}`,
		},
		{
			name: "flags carrying the wrong type",
			body: `{"nodeRestart":"yes","uiRelisten":1,"restartRequired":null}`,
		},
		{
			// Without this case the two above would pass just as well on a hardwired
			// false, which would silently drop every restart prompt the agent asks for.
			name: "flags set",
			body: `{"nodeRestart":true,"uiRelisten":true,"restartRequired":true}`,
			want: SettingsResult{NodeRestart: true, UIRelisten: true, RestartRequired: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, map[string]http.HandlerFunc{
				"PUT /api/settings": func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if _, err := w.Write([]byte(tt.body)); err != nil {
						t.Errorf("write response: %v", err)
					}
				},
			})

			got, err := h.client().UpdateSettings(context.Background(),
				map[string]json.RawMessage{"hostname": json.RawMessage(`"box"`)})
			if err != nil {
				t.Fatalf("UpdateSettings: %v", err)
			}
			if got.NodeRestart != tt.want.NodeRestart {
				t.Errorf("NodeRestart = %v, want %v", got.NodeRestart, tt.want.NodeRestart)
			}
			if got.UIRelisten != tt.want.UIRelisten {
				t.Errorf("UIRelisten = %v, want %v", got.UIRelisten, tt.want.UIRelisten)
			}
			if got.RestartRequired != tt.want.RestartRequired {
				t.Errorf("RestartRequired = %v, want %v", got.RestartRequired, tt.want.RestartRequired)
			}
			if got.View == nil {
				t.Error("View is nil; the refreshed settings were dropped")
			}
		})
	}
}

// settingsRoutesWithDeferred answers a write the agent stored but could not apply, which
// is what every pref-backed setting looks like while the tailnet node is down.
func settingsRoutesWithDeferred(t *testing.T, deferred any) map[string]http.HandlerFunc {
	stored := config.Defaults()
	return map[string]http.HandlerFunc{
		"GET /api/settings": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, config.SettingsViewOf(stored))
		},
		"PUT /api/settings": func(w http.ResponseWriter, r *http.Request) {
			var patch map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Errorf("decode patch: %v", err)
			}
			if err := config.ApplyPatchTo(stored, patch); err != nil {
				writeJSONResponse(t, w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			resp := config.SettingsViewOf(stored)
			resp["deferred"] = deferred
			writeJSONResponse(t, w, http.StatusOK, resp)
		},
	}
}

// A setting the agent stored but could not apply is not a setting that took effect. With
// nothing on screen saying so, a user changes a value, sees no error and concludes it is
// in force -- and then spends the next hour debugging the node it never reached.
func TestSettingsSetSaysWhichValuesAreStillWaitingOnTheNode(t *testing.T) {
	h := newHarness(t, settingsRoutesWithDeferred(t, []map[string]string{{
		"key":    "routes.accept",
		"label":  "Reach networks other devices advertise",
		"reason": "stored; the tailnet node is not running (the auth key was rejected), so it will be applied when it starts",
	}}))

	if err := h.exec("settings", "set", "--config", h.configPath, "udp-timeout", "120"); err != nil {
		t.Fatalf("settings set: %v", err)
	}

	out := h.out()
	for _, want := range []string{"Reach networks other devices advertise", "the auth key was rejected"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not carry %q:\n%s", want, out)
		}
	}
}

// The write itself succeeded, so a list this client cannot read is the one thing standing
// between the user and "saved". Dropping it turns "stored but not in force" into silence.
func TestSettingsSetReportsADeferredListItCannotRead(t *testing.T) {
	h := newHarness(t, settingsRoutesWithDeferred(t, []int{1, 2, 3}))

	err := h.exec("settings", "set", "--config", h.configPath, "udp-timeout", "120")

	if err == nil {
		t.Fatal("a deferred list the client could not read was passed over in silence")
	}
	if !strings.Contains(err.Error(), "deferred") {
		t.Errorf("err = %v, want it to say what could not be read", err)
	}
}

// A save that restarted the agent for administrator rights has nothing left to ask of the
// person at the terminal: telling them to restart it would send them to undo the prompt the
// restart is putting on screen.
func TestASaveThatRestartedTheAgentForRightsSaysSoAndNothingElse(t *testing.T) {
	var out bytes.Buffer
	noteRestart(&out, SettingsResult{AdminRestart: true, AdminRelaunch: true, NodeRestart: true})
	got := out.String()
	if !strings.Contains(got, "restarting so Windows can ask") {
		t.Errorf("output = %q, want it to say app-tail is restarting for the rights", got)
	}
	if strings.Contains(got, "Restart it to be asked") || strings.Contains(got, "app-tail restart") {
		t.Errorf("output = %q, want no restart offered for a process already restarting", got)
	}

	out.Reset()
	noteRestart(&out, SettingsResult{AdminRestart: true})
	if !strings.Contains(out.String(), "Restart it to be asked") {
		t.Errorf("output = %q, want a save needing rights without a restart to say how to get them", out.String())
	}
}
