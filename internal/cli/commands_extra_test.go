// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/autostart"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

func sshForward(enabled bool) httpapi.ForwardView {
	return httpapi.ForwardView{
		Forward: config.Forward{
			ID: "fw_2", Name: "ssh", Direction: config.ToLocal,
			Protocol: config.TCP, Target: "box:22", Enabled: enabled,
		},
		State:    "running",
		Endpoint: "TCP 127.0.0.1:2222",
	}
}

func TestForwardGetPrintsOneForward(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
		"GET /api/forwards/{id}": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, sshForward(true))
		},
	})

	if err := h.exec("forward", "get", "--config", h.configPath, "ssh"); err != nil {
		t.Fatalf("forward get: %v", err)
	}
	for _, want := range []string{"fw_2", "ssh", "box:22", "TCP 127.0.0.1:2222"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("forward get is missing %q:\n%s", want, h.out())
		}
	}
}

// A forward listening beyond this machine reports itself running, because it is. The agent
// writes the sentence that says so, and a printout that dropped it would describe a forward
// only this machine can reach exactly as it describes one the whole network can.
func TestForwardGetPrintsWhatIsTrueBesideTheStatus(t *testing.T) {
	exposed := sshForward(true)
	exposed.BindAddr = "0.0.0.0"
	exposed.Endpoint = "TCP 0.0.0.0:2222"
	exposed.Warning = "This forward listens on every address this machine has, so anything that " +
		"can reach this machine over the networks it is on can use it, not only programs running here."

	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{exposed}})
		},
		"GET /api/forwards/{id}": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, exposed)
		},
	})

	if err := h.exec("forward", "get", "--config", h.configPath, "ssh"); err != nil {
		t.Fatalf("forward get: %v", err)
	}
	if !strings.Contains(h.out(), "every address this machine has") {
		t.Errorf("forward get says nothing about a forward the whole network can reach:\n%s", h.out())
	}
}

// The --json form is the contract scripts parse, so it must be valid JSON carrying the
// forward's identity, not the human table.
func TestForwardGetJSONEmitsTheForward(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
		"GET /api/forwards/{id}": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, sshForward(true))
		},
	})

	if err := h.exec("forward", "get", "--config", h.configPath, "--json", "ssh"); err != nil {
		t.Fatalf("forward get --json: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
		t.Fatalf("forward get --json did not emit valid JSON: %v\n%s", err, h.out())
	}
	if got["id"] != "fw_2" {
		t.Errorf("forward get --json id = %v, want fw_2", got["id"])
	}
}

func TestForwardToggleFlipsTheCurrentState(t *testing.T) {
	var toggleBody string
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
		"GET /api/forwards/{id}": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, sshForward(true))
		},
		"POST /api/forwards/{id}/toggle": func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode toggle body: %v", err)
			}
			toggleBody = map[bool]string{true: "enabled", false: "disabled"}[body.Enabled]
			writeJSONResponse(t, w, http.StatusOK, sshForward(body.Enabled))
		},
	})

	if err := h.exec("forward", "toggle", "--config", h.configPath, "ssh"); err != nil {
		t.Fatalf("forward toggle: %v", err)
	}
	// The forward was enabled, so toggling it must ask the agent to disable it.
	if toggleBody != "disabled" {
		t.Errorf("toggle sent enabled=%q, want it to flip an enabled forward off", toggleBody)
	}
}

func TestForwardDisableSetsEnabledFalse(t *testing.T) {
	var sawEnabled *bool
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
		"POST /api/forwards/{id}/toggle": func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode toggle body: %v", err)
			}
			sawEnabled = &body.Enabled
			writeJSONResponse(t, w, http.StatusOK, sshForward(body.Enabled))
		},
	})

	if err := h.exec("forward", "disable", "--config", h.configPath, "ssh"); err != nil {
		t.Fatalf("forward disable: %v", err)
	}
	if sawEnabled == nil || *sawEnabled {
		t.Errorf("forward disable sent enabled=%v, want false", sawEnabled)
	}
}

func TestForwardUpdateSendsOnlyTheChangedFields(t *testing.T) {
	specs := make(chan httpapi.ForwardSpec, 1)
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
		"PUT /api/forwards/{id}": func(w http.ResponseWriter, r *http.Request) {
			var spec httpapi.ForwardSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				t.Errorf("decode update body: %v", err)
			}
			specs <- spec
			writeJSONResponse(t, w, http.StatusOK, sshForward(true))
		},
	})

	if err := h.exec("forward", "update", "--config", h.configPath, "--target", "box:2222", "ssh"); err != nil {
		t.Fatalf("forward update: %v", err)
	}
	spec := <-specs
	if spec.Target == nil || *spec.Target != "box:2222" {
		t.Errorf("update target = %v, want box:2222", spec.Target)
	}
	// A field the user did not name must stay absent so the agent leaves it untouched.
	if spec.Name != nil {
		t.Errorf("update sent a name the user never gave: %v", spec.Name)
	}
}

// The natural order puts the forward name first and the flags after it. Go's flag
// package would otherwise stop at the name and leave --target unparsed, so this locks
// in the interspersed-argument parsing.
func TestForwardUpdateAcceptsTheNameBeforeTheFlags(t *testing.T) {
	specs := make(chan httpapi.ForwardSpec, 1)
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
		"PUT /api/forwards/{id}": func(w http.ResponseWriter, r *http.Request) {
			var spec httpapi.ForwardSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				t.Errorf("decode update body: %v", err)
			}
			specs <- spec
			writeJSONResponse(t, w, http.StatusOK, sshForward(true))
		},
	})

	// Name first, then the flag -- the order a user would naturally type.
	if err := h.exec("forward", "update", "ssh", "--config", h.configPath, "--target", "box:2222"); err != nil {
		t.Fatalf("forward update (name first): %v", err)
	}
	spec := <-specs
	if spec.Target == nil || *spec.Target != "box:2222" {
		t.Errorf("update target = %v, want box:2222", spec.Target)
	}
}

func TestForwardUpdateRequiresAField(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
	})
	err := h.exec("forward", "update", "--config", h.configPath, "ssh")
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("forward update with no field flags = %v, want a usage error", err)
	}
	if !strings.Contains(err.Error(), "field flag") {
		t.Errorf("error %q does not say what was missing", err)
	}
	for _, r := range h.recorded() {
		if r.Method != http.MethodGet {
			t.Errorf("a refused update still sent %s %s", r.Method, r.Path)
		}
	}
}

func TestAddSendsUDPTimeoutWhenGiven(t *testing.T) {
	specs := make(chan httpapi.ForwardSpec, 1)
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/forwards": func(w http.ResponseWriter, r *http.Request) {
			var spec httpapi.ForwardSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			specs <- spec
			writeJSONResponse(t, w, http.StatusCreated, httpapi.ForwardView{
				Forward:  config.Forward{ID: "fw_9", Name: "dns", Enabled: true},
				Endpoint: "UDP 127.0.0.1:5353",
			})
		},
	})

	if err := h.run("add", "--target", "box:53", "--port", "5353", "--protocol", "udp", "--udp-timeout", "45"); err != nil {
		t.Fatalf("add: %v", err)
	}
	spec := <-specs
	if spec.UDPTimeoutSec == nil || *spec.UDPTimeoutSec != 45 {
		t.Errorf("add sent udp timeout %v, want 45", spec.UDPTimeoutSec)
	}
}

func TestPeersListsVisibleDevices(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/peers": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"peers": []tsnode.Peer{
				{ID: "n1", HostName: "gpu-box", DNSName: "gpu-box.tail.ts.net", IPs: []string{"100.64.0.5"}, Online: true, OS: "linux", Tags: []string{"tag:app-tail"}, InEngine: true, InMagicSock: true, Reach: tsnode.PeerReach{State: tsnode.PeerReady}},
			}})
		},
	})

	if err := h.exec("peers", "--config", h.configPath); err != nil {
		t.Fatalf("peers: %v", err)
	}
	for _, want := range []string{"gpu-box", "ready", "tag:app-tail"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("peers output missing %q:\n%s", want, h.out())
		}
	}
	// A healthy device must not drag an explanation along behind the table, or the
	// explanations stop meaning anything.
	if strings.Contains(h.out(), "gpu-box:") {
		t.Errorf("a ready peer was given a reason to explain away:\n%s", h.out())
	}
}

// The CLI on PATH and the agent inside the installed app are routinely different builds.
// Against an agent too old to send a verdict, the listing must fall back to what that
// agent does report rather than printing an empty state for every device and following
// the table with one blank explanation per peer.
func TestPeersFallsBackWhenTheAgentSendsNoVerdict(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/peers": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"peers": []tsnode.Peer{
				{ID: "n1", HostName: "gpu-box", DNSName: "gpu-box.tail.ts.net", Online: true, OS: "linux"},
				{ID: "n2", HostName: "laptop", DNSName: "laptop.tail.ts.net", Online: false, OS: "macOS"},
			}})
		},
	})

	if err := h.exec("peers", "--config", h.configPath); err != nil {
		t.Fatalf("peers: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "ready") || !strings.Contains(out, "offline") {
		t.Errorf("states were not derived from what the old agent reported:\n%s", out)
	}
	for _, blank := range []string{"gpu-box: \n", "laptop: \n"} {
		if strings.Contains(out, blank) {
			t.Errorf("an empty explanation was printed for a device:\n%s", out)
		}
	}
}

// The listing exists to answer "can I use this device". A peer the tailnet reports
// online that no lower layer is tracking is the case where the old answer -- the word
// "online" -- was actively wrong: nothing reaches it and its name resolves to nothing.
func TestPeersNamesADeviceTheTailnetListsButThisNodeCannotReach(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/peers": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"peers": []tsnode.Peer{
				{ID: "n1", HostName: "gitlab", DNSName: "gitlab.tail.ts.net", IPs: []string{"100.64.0.7"}, Online: true, OS: "linux", InEngine: false, InMagicSock: true,
					Reach: tsnode.PeerReach{State: tsnode.PeerNoPath, Reason: "this node is not tracking it"}},
			}})
		},
	})

	if err := h.exec("peers", "--config", h.configPath); err != nil {
		t.Fatalf("peers: %v", err)
	}
	if !strings.Contains(h.out(), "no-path") {
		t.Errorf("an unreachable device was not marked in the table:\n%s", h.out())
	}
	if !strings.Contains(h.out(), "gitlab: ") {
		t.Errorf("no reason was printed for the unreachable device:\n%s", h.out())
	}
	if strings.Contains(h.out(), "online") {
		t.Errorf("the table still claims the device is usable:\n%s", h.out())
	}
}

// An empty peer list must still emit `[]`, not `null`, so a consumer can iterate it.
func TestPeersJSONEmitsAnArrayEvenWhenEmpty(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/peers": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"peers": []tsnode.Peer{}})
		},
	})
	if err := h.exec("peers", "--config", h.configPath, "--json"); err != nil {
		t.Fatalf("peers --json: %v", err)
	}
	var got []tsnode.Peer
	if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
		t.Fatalf("peers --json did not emit a JSON array: %v\n%s", err, h.out())
	}
	if got == nil {
		t.Errorf("peers --json emitted null, not an empty array:\n%s", h.out())
	}
}

func TestPeersSaysWhenNoneAreVisible(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/peers": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"peers": []tsnode.Peer{}})
		},
	})
	if err := h.exec("peers", "--config", h.configPath); err != nil {
		t.Fatalf("peers: %v", err)
	}
	if !strings.Contains(h.out(), "No peers") {
		t.Errorf("empty peers printed nothing useful:\n%s", h.out())
	}
}

func TestPresetListShowsBuiltInsAndUserEntries(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
				{ID: "ssh", Name: "SSH", Protocol: config.TCP, RemotePort: 22, BuiltIn: true},
				{ID: "user-1", Name: "Grafana", Protocol: config.TCP, RemotePort: 3000},
			}})
		},
	})

	if err := h.exec("preset", "list", "--config", h.configPath); err != nil {
		t.Fatalf("preset list: %v", err)
	}
	for _, want := range []string{"SSH", "built-in", "Grafana", "user"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("preset list missing %q:\n%s", want, h.out())
		}
	}
}

func TestPresetAddCreatesAPreset(t *testing.T) {
	presets := make(chan config.Preset, 1)
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/presets": func(w http.ResponseWriter, r *http.Request) {
			var p config.Preset
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Errorf("decode preset: %v", err)
			}
			presets <- p
			p.ID = "user-1"
			writeJSONResponse(t, w, http.StatusCreated, p)
		},
	})

	if err := h.exec("preset", "add", "--config", h.configPath, "--name", "Grafana", "--port", "3000"); err != nil {
		t.Fatalf("preset add: %v", err)
	}
	created := <-presets
	if created.Name != "Grafana" || created.RemotePort != 3000 {
		t.Errorf("preset add sent %+v, want Grafana on 3000", created)
	}
}

// Removing a built-in is not possible, so the command must refuse before it ever calls
// DELETE.
func TestPresetRemoveRefusesABuiltIn(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
				{ID: "ssh", Name: "SSH", Protocol: config.TCP, RemotePort: 22, BuiltIn: true},
			}})
		},
		"DELETE /api/presets/{id}": func(http.ResponseWriter, *http.Request) {
			t.Error("preset rm tried to delete a built-in")
		},
	})

	err := h.exec("preset", "rm", "--config", h.configPath, "ssh")
	if err == nil {
		t.Fatal("preset rm accepted a built-in")
	}
	if !strings.Contains(err.Error(), "built-in") {
		t.Errorf("error %q does not explain that built-ins cannot be removed", err)
	}
}

func TestPresetRemoveDeletesAUserPreset(t *testing.T) {
	deletions := make(chan string, 1)
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
				{ID: "user-1", Name: "Grafana", Protocol: config.TCP, RemotePort: 3000},
			}})
		},
		"DELETE /api/presets/{id}": func(w http.ResponseWriter, r *http.Request) {
			deletions <- r.PathValue("id")
			w.WriteHeader(http.StatusNoContent)
		},
	})

	if err := h.exec("preset", "rm", "--config", h.configPath, "Grafana"); err != nil {
		t.Fatalf("preset rm: %v", err)
	}
	if id := <-deletions; id != "user-1" {
		t.Errorf("deleted %q, want user-1", id)
	}
}

// autostart status reads the OS login item directly, so it works with no agent
// running and takes no --config flag. The two answers have to read differently: both
// contain the word "login", so a report that always printed the same branch -- or the
// inverted one -- would be indistinguishable from a working command.
func TestAutostartStatusDistinguishesInstalledFromNot(t *testing.T) {
	skipUnlessLoginItemsAreFiles(t)

	t.Run("not installed", func(t *testing.T) {
		isolateLoginItemHome(t)
		h := newHarness(t, nil)

		if err := h.exec("autostart", "status"); err != nil {
			t.Fatalf("autostart status: %v", err)
		}

		if !strings.Contains(h.out(), "does not start at login") {
			t.Errorf("status did not report the login item as absent:\n%s", h.out())
		}
		// The way out has to be on screen, or the user has nothing to run next.
		if !strings.Contains(h.out(), "install-autostart") {
			t.Errorf("status did not say how to enable it:\n%s", h.out())
		}
	})

	t.Run("installed", func(t *testing.T) {
		isolateLoginItemHome(t)
		manager, err := autostart.New()
		if err != nil {
			t.Fatalf("autostart.New: %v", err)
		}
		if err := manager.SetEnabled(true); err != nil {
			t.Fatalf("install the login item: %v", err)
		}

		h := newHarness(t, nil)
		if err := h.exec("autostart", "status"); err != nil {
			t.Fatalf("autostart status: %v", err)
		}

		if !strings.Contains(h.out(), "starts at login") {
			t.Errorf("status did not report the installed login item:\n%s", h.out())
		}
		if strings.Contains(h.out(), "does not start at login") {
			t.Errorf("status reported the installed item as absent:\n%s", h.out())
		}
		// The path is the only thing the user can inspect or delete by hand.
		if !strings.Contains(h.out(), manager.Path()) {
			t.Errorf("status did not name the login item file:\n%s", h.out())
		}
	})
}

// A login item can be installed and still never start app-tail: the app moves, and the
// item goes on naming the path it was created with. "app-tail starts at login." on its
// own is then a false report, and the only one the user gets -- there is no other surface
// that reads the item's program back.
func TestAutostartStatusSaysWhenAnInstalledItemCannotStartTheApp(t *testing.T) {
	skipUnlessLoginItemsAreFiles(t)
	if runtime.GOOS != "darwin" {
		t.Skip("only the LaunchAgent goes stale by path; the others cannot reach this branch")
	}
	isolateLoginItemHome(t)

	// Installed from a path that then went away, which is what moving the app does.
	gone := filepath.Join(t.TempDir(), "Applications", "App-Tail.app", "Contents", "MacOS", "app-tail")
	stale, err := autostart.New()
	if err != nil {
		t.Fatalf("autostart.New: %v", err)
	}
	stale.ExecPath = gone
	if err := stale.SetEnabled(true); err != nil {
		t.Fatalf("install the login item: %v", err)
	}

	h := newHarness(t, nil)
	if err := h.exec("autostart", "status"); err != nil {
		t.Fatalf("autostart status: %v", err)
	}

	out := h.out()
	if !strings.Contains(out, "no longer there") {
		t.Errorf("status did not say the login item names a program that is gone:\n%s", out)
	}
	// Naming the fault without the remedy leaves the user with nothing to run.
	if !strings.Contains(out, "install-autostart") {
		t.Errorf("status did not say how to correct it:\n%s", out)
	}
}

// The help overview is the only place a command is discoverable, so every entry in the
// registry has to appear in it with its own summary. Grepping for bare words would pass
// against a usage text that lists nothing: usageFooter already names most of the
// commands in prose.
func TestEveryRegisteredCommandAppearsInTheHelpOverview(t *testing.T) {
	for _, c := range commands {
		t.Run(c.name, func(t *testing.T) {
			// The invocation line, not just the word: two leading spaces and a
			// trailing space are what distinguish the table row from the prose.
			invocation := "  app-tail " + c.name + " "
			if c.name == "run" {
				invocation = "  app-tail [run] "
			}
			if !strings.Contains(usageText, invocation) {
				t.Errorf("no invocation line for %q in the help overview:\n%s", c.name, usageText)
			}
			if !strings.Contains(usageText, c.summary) {
				t.Errorf("%q is listed without its summary %q, so the user cannot tell "+
					"what it does:\n%s", c.name, c.summary, usageText)
			}
		})
	}
}

// The notices are a distribution obligation, and the archive they ship in is the
// first thing a user deletes. This is the copy that cannot be deleted, so the
// command has to work with no agent, no network and no state directory.
func TestLicensesPrintsTheEmbeddedNoticesOffline(t *testing.T) {
	h := newHarness(t, nil)
	if err := h.exec("licenses"); err != nil {
		t.Fatalf("licenses: %v", err)
	}
	out := h.out()
	if len(out) < 1000 {
		t.Fatalf("licenses printed %d bytes; the notices did not reach stdout", len(out))
	}
	if !strings.Contains(out, "tailscale.com") {
		t.Error("licenses output names no tailscale.com module")
	}
	if !strings.Contains(out, "--- LICENSE ---") {
		t.Error("licenses printed module names but no license text")
	}
}

// A typo'd invocation that silently prints 150 kB of licenses instead of reporting
// the mistake trains people to ignore the output.
func TestLicensesRejectsAPositionalArgument(t *testing.T) {
	h := newHarness(t, nil)
	if err := h.exec("licenses", "tailscale"); !errors.Is(err, ErrUsage) {
		t.Fatalf("licenses tailscale = %v, want a usage error", err)
	}
	if out := h.out(); out != "" {
		t.Errorf("a refused invocation still printed %d bytes", len(out))
	}
}

// licenses takes no flags. Accepting one silently would print 150 kB of notices in
// answer to a mistyped command, which is indistinguishable from it having worked.
func TestLicensesRejectsAnUnknownFlag(t *testing.T) {
	h := newHarness(t, nil)
	if err := h.exec("licenses", "--json"); err == nil {
		t.Fatal("licenses accepted an unknown flag")
	}
	if out := h.out(); out != "" {
		t.Errorf("licenses printed %d bytes despite a bad invocation", len(out))
	}
}
