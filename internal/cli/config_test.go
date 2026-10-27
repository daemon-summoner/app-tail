// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// configHarness is a state directory and the environment to run a config command against
// it. There is no agent: these commands work on the file, and the case they exist for is a
// document no agent could start on.
type configHarness struct {
	t      *testing.T
	dir    string
	path   string
	stdout strings.Builder
	stderr strings.Builder
}

func newConfigHarness(t *testing.T) *configHarness {
	t.Helper()
	dir := t.TempDir()
	return &configHarness{t: t, dir: dir, path: filepath.Join(dir, config.ConfigFileName)}
}

func (h *configHarness) env() Env {
	return Env{
		Stdout: &h.stdout,
		Stderr: &h.stderr,
		Getenv: func(string) string { return "" },
	}
}

func (h *configHarness) run(args ...string) error {
	h.t.Helper()
	full := append([]string{"config"}, args...)
	full = append(full, "-config", h.path, "-state-dir", h.dir)
	return Run(context.Background(), full, h.env())
}

func (h *configHarness) out() string { return h.stdout.String() }

// write puts a document at path with exactly these bytes.
func (h *configHarness) write(path, body string) {
	h.t.Helper()
	if err := os.WriteFile(path, []byte(body), config.FileMode); err != nil {
		h.t.Fatal(err)
	}
}

// writeUsable puts a document this build can load at path.
func (h *configHarness) writeUsable(path, machineID string) {
	h.t.Helper()
	cfg := config.Defaults()
	cfg.Settings.MachineID = machineID
	data, err := json.Marshal(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.write(path, string(data))
}

func TestConfigCheckPassesADocumentThatLoads(t *testing.T) {
	h := newConfigHarness(t)
	h.writeUsable(h.path, "abcd1234")

	if err := h.run("check"); err != nil {
		t.Fatalf("config check: %v", err)
	}
	if !strings.Contains(h.out(), "Loads cleanly") {
		t.Errorf("output does not say the document is fine:\n%s", h.out())
	}
}

// The command someone runs because they suspect the file is damaged must not be the thing
// that replaces it: opening the store is what writes defaults over an unusable document.
func TestConfigCheckLeavesADamagedDocumentWhereItIs(t *testing.T) {
	h := newConfigHarness(t)
	h.write(h.path, "{not json")

	if err := h.run("check"); err != nil {
		t.Fatalf("config check: %v", err)
	}
	if !strings.Contains(h.out(), "Cannot be used") || !strings.Contains(h.out(), "JSON") {
		t.Errorf("output does not name what is wrong:\n%s", h.out())
	}
	held, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(held) != "{not json" {
		t.Errorf("checking the document changed it: %q", held)
	}
}

func TestConfigCheckReportsAsJSON(t *testing.T) {
	h := newConfigHarness(t)
	h.write(h.path, "{not json")
	h.writeUsable(h.path+".unusable-20240101-000000", "abcd1234")

	if err := h.run("check", "-json"); err != nil {
		t.Fatalf("config check --json: %v", err)
	}
	var report config.Inspection
	if err := json.Unmarshal([]byte(h.out()), &report); err != nil {
		t.Fatalf("the report is not JSON: %v\n%s", err, h.out())
	}
	if report.Usable {
		t.Error("a document that is not JSON was reported usable")
	}
	if len(report.Saved) != 1 || !report.Saved[0].Usable {
		t.Errorf("the copy that could be restored was not offered: %+v", report.Saved)
	}
}

// A list where nothing can be restored must not end by offering the restore: the command
// it points at can only refuse.
func TestConfigCheckDoesNotOfferARestoreThatWouldBeRefused(t *testing.T) {
	h := newConfigHarness(t)
	h.write(h.path, "{not json")
	h.write(h.path+".unusable-20240101-000000", "{also not json")

	if err := h.run("check"); err != nil {
		t.Fatalf("config check: %v", err)
	}
	if strings.Contains(h.out(), "config restore") {
		t.Errorf("output offers a restore with nothing restorable:\n%s", h.out())
	}
	if !strings.Contains(h.out(), "config reset") {
		t.Errorf("output does not say what can be done instead:\n%s", h.out())
	}
}

func TestConfigRestorePutsBackTheNamedCopy(t *testing.T) {
	h := newConfigHarness(t)
	h.write(h.path, "{not json")
	saved := h.path + ".unusable-20240101-000000"
	h.writeUsable(saved, "abcd1234")

	if err := h.run("restore", saved); err != nil {
		t.Fatalf("config restore: %v", err)
	}
	store, err := config.Open(h.path)
	if err != nil {
		t.Fatalf("open the restored config: %v", err)
	}
	if store.Quarantined() != nil {
		t.Fatal("the restored document does not load")
	}
	if got := store.Settings().MachineID; got != "abcd1234" {
		t.Errorf("machine id = %q, want the restored document's", got)
	}
	if !strings.Contains(h.out(), "Restored") {
		t.Errorf("output does not say what happened:\n%s", h.out())
	}
}

// A restore that installs a document the app cannot load only moves the fault, so it is
// refused with the reason rather than performed.
func TestConfigRestoreRefusesACopyThatDoesNotLoad(t *testing.T) {
	h := newConfigHarness(t)
	h.writeUsable(h.path, "abcd1234")
	bad := h.path + ".unusable-20240101-000000"
	h.write(bad, `{"settings":{"uiListenAddr":"0.0.0.0:8377"}}`)

	err := h.run("restore", bad)
	if err == nil {
		t.Fatal("config restore installed a document this build cannot load")
	}
	if !strings.Contains(err.Error(), "uiListenAddr") {
		t.Errorf("error = %q, want it to name what is wrong with the copy", err)
	}
}

func TestConfigResetKeepsWhatItReplaced(t *testing.T) {
	h := newConfigHarness(t)
	cfg := config.Defaults()
	cfg.Settings.MachineID = "abcd1234"
	cfg.Settings.UDPSessionTimeoutSec = 99
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.write(h.path, string(data))

	if err := h.run("reset"); err != nil {
		t.Fatalf("config reset: %v", err)
	}
	store, err := config.Open(h.path)
	if err != nil {
		t.Fatalf("open the reset config: %v", err)
	}
	if got := store.Settings().UDPSessionTimeoutSec; got != config.Defaults().Settings.UDPSessionTimeoutSec {
		t.Errorf("udpSessionTimeoutSec = %d, want the default", got)
	}
	// The way back has to be printed: a reset whose output does not name the file it kept
	// is a reset the user cannot undo without going looking.
	if !strings.Contains(h.out(), "config restore") {
		t.Errorf("output does not say how to undo it:\n%s", h.out())
	}
}

func TestConfigRejectsAnUnknownSubcommand(t *testing.T) {
	h := newConfigHarness(t)
	h.writeUsable(h.path, "abcd1234")
	err := h.run("repair")
	if err == nil {
		t.Fatal("an unknown config subcommand was accepted")
	}
	if !strings.Contains(err.Error(), "repair") {
		t.Errorf("error = %q, want it to name what was typed", err)
	}
}

// A repair made underneath a running agent lasts until its next write, because the agent
// holds the previous document in memory. Saying so is the difference between a fix and a
// fix that quietly comes undone.
func TestConfigResetSaysSoWhenAnAgentIsRunning(t *testing.T) {
	agent := newHarness(t, map[string]http.HandlerFunc{
		"/healthz": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
				t.Errorf("write the health reply: %v", err)
			}
		},
	})

	args := []string{"config", "reset", "-config", agent.configPath, "-state-dir", filepath.Dir(agent.configPath)}
	if err := Run(context.Background(), args, agent.env()); err != nil {
		t.Fatalf("config reset: %v", err)
	}
	if !strings.Contains(agent.out(), "still holds the previous settings") {
		t.Errorf("output does not warn that the running agent will write its copy back:\n%s", agent.out())
	}
}
