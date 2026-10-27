// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/sysproxy"
)

// systemRoutes answers the one endpoint `proxy system` reads.
func systemRoutes(t *testing.T, view httpapi.SystemProxyView) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/proxy/system": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, view)
		},
	}
}

// The four states are the whole point of the command: "on" and "in force" are different
// things, and a user looking at a machine that stopped reaching the tailnet needs to be
// told which one they are in rather than shown the switch again.
func TestProxySystemNamesWhichOfTheFourStatesThisMachineIsIn(t *testing.T) {
	tests := []struct {
		name string
		view httpapi.SystemProxyView
		want []string
	}{
		{
			name: "applied",
			view: httpapi.SystemProxyView{
				Enabled: true, Platform: "windows", Supported: true, Applied: true, Managed: true,
				AutoConfigURL: "http://127.0.0.1:8377/proxy.pac",
			},
			want: []string{"point at app-tail", "http://127.0.0.1:8377/proxy.pac", "app-tail proxy system off"},
		},
		{
			name: "unsupported platform",
			view: httpapi.SystemProxyView{
				Platform: "darwin",
				Capability: httpapi.Capability{
					Reason: "changing this Mac's proxy settings needs an administrator",
				},
			},
			want: []string{"macOS", "needs an administrator"},
		},
		{
			name: "on but not in force",
			view: httpapi.SystemProxyView{
				Enabled: true, Platform: "windows", Supported: true,
				Capability: httpapi.Capability{
					Degraded: true,
					Reason:   "the proxy is not listening, so there is nothing to point this machine at",
				},
			},
			want: []string{"on but not in force", "the proxy is not listening"},
		},
		{
			name: "off, with someone else's value in place",
			view: httpapi.SystemProxyView{
				Platform: "windows", Supported: true,
				AutoConfigURL: "http://proxy.corp.example.com/company.pac",
			},
			want: []string{"untouched", "Something else points them at http://proxy.corp.example.com/company.pac"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, systemRoutes(t, tc.view))

			if err := Run(t.Context(), append([]string{"proxy", "system"}, h.cfg()...), h.env()); err != nil {
				t.Fatalf("proxy system: %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(h.out(), want) {
					t.Errorf("output is missing %q:\n%s", want, h.out())
				}
			}
		})
	}
}

// The limits and the commands are what a macOS user can act on. Printing the refusal
// without them leaves the command a dead end.
func TestProxySystemPrintsTheLimitsAndTheCommandsToRunByHand(t *testing.T) {
	h := newHarness(t, systemRoutes(t, httpapi.SystemProxyView{
		Platform: "darwin",
		Capability: httpapi.Capability{
			Reason: "this needs an administrator",
			Limits: []string{"macOS applies a proxy per network service."},
		},
		Manual: []sysproxy.Command{{
			Label:   "Point this Mac at it",
			Command: `sudo networksetup -setautoproxyurl "Wi-Fi" http://127.0.0.1:8377/proxy.pac`,
		}},
	}))

	if err := Run(t.Context(), append([]string{"proxy", "system"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("proxy system: %v", err)
	}
	for _, want := range []string{
		"macOS applies a proxy per network service.",
		"Point this Mac at it",
		`sudo networksetup -setautoproxyurl "Wi-Fi" http://127.0.0.1:8377/proxy.pac`,
	} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("output is missing %q:\n%s", want, h.out())
		}
	}
}

func TestProxySystemAsJSONIsTheAgentsOwnAnswer(t *testing.T) {
	view := httpapi.SystemProxyView{
		Enabled: true, Platform: "windows", Supported: true, Applied: true, Managed: true,
		AutoConfigURL: "http://127.0.0.1:8377/proxy.pac",
		Manual:        []sysproxy.Command{},
	}
	h := newHarness(t, systemRoutes(t, view))

	if err := Run(t.Context(), append([]string{"proxy", "system"}, append(h.cfg(), "--json")...), h.env()); err != nil {
		t.Fatalf("proxy system --json: %v", err)
	}
	var got httpapi.SystemProxyView
	if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
		t.Fatalf("parse the JSON output: %v\n%s", err, h.out())
	}
	if got.AutoConfigURL != view.AutoConfigURL || !got.Applied {
		t.Errorf("JSON output = %+v, want the agent's own view", got)
	}
}

// The argument checks are what stop `proxy system on` from reading as a way to turn it
// on -- the setting is written through settings, and a silently ignored argument would
// leave the user believing they had.
func TestProxySystemChecksItsArguments(t *testing.T) {
	h := newHarness(t, systemRoutes(t, httpapi.SystemProxyView{Platform: "windows", Supported: true}))

	for _, args := range [][]string{
		{"proxy", "system", "on"},
		{"proxy", "system", "off", "extra"},
		// `off` says what it did in words; a flag that quietly did nothing would be
		// worse than one that is refused.
		{"proxy", "system", "off", "--json"},
	} {
		full := append([]string{args[0], args[1]}, append(h.cfg(), args[2:]...)...)
		if err := Run(t.Context(), full, h.env()); !errors.Is(err, ErrUsage) {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
	for _, r := range h.recorded() {
		if r.Method != http.MethodGet {
			t.Errorf("a refused invocation still sent %s %s", r.Method, r.Path)
		}
	}
}

// Asking the agent is what makes the reconcile stop reapplying the setting. Doing the
// restore without turning the setting off would have the next reconcile undo it.
//
// The assertion is on the request rather than on a stored document because the setting
// only exists on Windows: a real registry patch applied on this host would be refused by
// name, which is the platform gate working, not this command failing.
func TestProxySystemOffAsksTheAgentToTurnTheSettingOff(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/proxy/system": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, httpapi.SystemProxyView{
				Enabled: true, Platform: "windows", Supported: true, Applied: true, Managed: true,
			})
		},
		"PUT /api/settings": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"proxy.system": false})
		},
	})

	if err := Run(t.Context(), append(append([]string{"proxy", "system"}, h.cfg()...), "off"), h.env()); err != nil {
		t.Fatalf("proxy system off: %v", err)
	}

	var patch map[string]json.RawMessage
	found := false
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut && req.Path == "/api/settings" {
			if err := json.Unmarshal([]byte(req.Body), &patch); err != nil {
				t.Fatalf("parse the patch the CLI sent: %v", err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("the setting was never turned off, so the next reconcile would point this machine straight back")
	}
	if string(patch["proxy.system"]) != "false" {
		t.Errorf("patch = %v, want proxy.system false and nothing else", patch)
	}
	if len(patch) != 1 {
		t.Errorf("patch carries %d keys, want only proxy.system: %v", len(patch), patch)
	}
	if !strings.Contains(h.out(), "put back") {
		t.Errorf("output does not say what happened:\n%s", h.out())
	}
}

// On a platform that never wrote the setting there is nothing to put back, and the
// patch would be refused by name as a setting this platform does not offer -- so the
// command says so rather than reporting an error the user cannot act on.
func TestProxySystemOffOnAPlatformThatNeverWroteItSaysSo(t *testing.T) {
	h := newHarness(t, systemRoutes(t, httpapi.SystemProxyView{Platform: "darwin"}))

	if err := Run(t.Context(), append(append([]string{"proxy", "system"}, h.cfg()...), "off"), h.env()); err != nil {
		t.Fatalf("proxy system off: %v", err)
	}
	if !strings.Contains(h.out(), "nothing to put back") {
		t.Errorf("output does not explain why it did nothing:\n%s", h.out())
	}
}

// The case the command exists for: the agent is gone and this machine is still pointing
// at a port nothing answers. It has to work with no agent at all.
func TestProxySystemOffWorksWithNoAgentRunning(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	store, err := config.Open(configPath)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		// An address nothing listens on, which is what "the agent is gone" looks like
		// to every command that tries to reach it.
		c.Settings.UIListen = "127.0.0.1:1"
		c.Settings.ProxyEnabled, c.Settings.ProxySystem = true, true
		return nil
	}); err != nil {
		t.Fatalf("write the stored settings: %v", err)
	}

	record := filepath.Join(dir, sysproxy.RestoreFileName)
	if err := os.WriteFile(record, []byte(`{"priorAutoConfigUrl":"","wroteAutoConfigUrl":"http://127.0.0.1:8377/proxy.pac"}`), 0o600); err != nil {
		t.Fatalf("write a restore record: %v", err)
	}

	h := &harness{t: t}
	args := []string{"proxy", "system", "--config", configPath, "--state-dir", dir, "off"}
	if err := Run(t.Context(), args, h.env()); err != nil {
		t.Fatalf("proxy system off with no agent: %v", err)
	}

	after, err := config.Open(configPath)
	if err != nil {
		t.Fatalf("reopen config: %v", err)
	}
	if after.Settings().ProxySystem {
		t.Error("the stored setting survived, so starting the app again would reapply it")
	}
	// This machine cannot be changed here, so the record is dropped rather than acted
	// on -- and dropping it is what stops every later start reconsidering it.
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Errorf("the restore record survived: %v", err)
	}
	if !strings.Contains(h.out(), "without a running agent") {
		t.Errorf("output does not say it acted alone:\n%s", h.out())
	}
}

// offlineOffArgs turns the system proxy off against a config the caller has arranged to
// be broken in one specific way, with no agent to fall back on.
func offlineOffArgs(dir, configPath string) []string {
	return []string{"proxy", "system", "--config", configPath, "--state-dir", dir, "off"}
}

// With no agent reachable, the stored config is the only thing that can turn the setting
// off. When it cannot be opened either, both causes belong in the sentence: "no running
// agent" alone reads as the expected offline case working, and the config error alone
// hides why the agent was not simply asked.
func TestProxySystemOffNamesBothTheMissingAgentAndTheUnreadableConfig(t *testing.T) {
	dir := t.TempDir()
	// A directory where the config file should be: openable as a path, never as a config.
	configPath := filepath.Join(dir, "config.json")
	if err := os.Mkdir(configPath, 0o700); err != nil {
		t.Fatalf("put a directory where the config file goes: %v", err)
	}

	h := &harness{t: t}
	err := Run(t.Context(), offlineOffArgs(dir, configPath), h.env())

	if err == nil {
		t.Fatal("the setting was reported as turned off with no config to turn it off in")
	}
	if !strings.Contains(err.Error(), "no running agent") {
		t.Errorf("err = %v, want it to say the agent could not be asked", err)
	}
	if !strings.Contains(err.Error(), "stored settings could not be opened") {
		t.Errorf("err = %v, want it to say the stored settings are what failed", err)
	}
}

// A write that failed must be reported, not passed over: the next start reads the stored
// setting and would point this machine straight back at a proxy the user just asked to
// come off, with the command having said it worked.
func TestProxySystemOffReportsASettingItCouldNotTurnOff(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bits this test depends on")
	}
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce the directory write bit the same way")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	store, err := config.Open(configPath)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = "127.0.0.1:1"
		c.Settings.ProxyEnabled, c.Settings.ProxySystem = true, true
		return nil
	}); err != nil {
		t.Fatalf("write the stored settings: %v", err)
	}
	// The store writes through a temp file in the same directory, so revoking write
	// permission on the directory is what a config that cannot be updated looks like.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("make the state dir read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	h := &harness{t: t}
	err = Run(t.Context(), offlineOffArgs(dir, configPath), h.env())

	if err == nil {
		t.Fatal("a setting that could not be written was reported as turned off")
	}
	if !strings.Contains(err.Error(), configPath) {
		t.Errorf("err = %v, want it to name the file the setting is stored in", err)
	}
	if strings.Contains(h.out(), "put back") {
		t.Errorf("output claims the machine was restored after the setting failed to save:\n%s", h.out())
	}
}

// The restore record is what every later start reads to decide whether there is anything
// to put back. A record that could not be dealt with has to be reported: reporting
// success would leave it there, and the next start would reconsider a restore this
// command said it had already finished.
func TestProxySystemOffReportsARestoreRecordItCouldNotDealWith(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	store, err := config.Open(configPath)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = "127.0.0.1:1"
		c.Settings.ProxyEnabled, c.Settings.ProxySystem = true, true
		return nil
	}); err != nil {
		t.Fatalf("write the stored settings: %v", err)
	}
	// A directory where the record file goes, with something inside it: readable as a
	// path and refused by every attempt to read or remove it as a file.
	record := filepath.Join(dir, sysproxy.RestoreFileName)
	if err := os.Mkdir(record, 0o700); err != nil {
		t.Fatalf("put a directory where the restore record goes: %v", err)
	}

	h := &harness{t: t}
	err = Run(t.Context(), offlineOffArgs(dir, configPath), h.env())

	if err == nil {
		t.Fatal("a restore record that could not be read was reported as dealt with")
	}
	if strings.Contains(h.out(), "put back") {
		t.Errorf("output claims the machine was restored:\n%s", h.out())
	}
}
