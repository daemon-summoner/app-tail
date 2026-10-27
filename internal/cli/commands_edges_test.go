// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/autostart"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// --- logout ---------------------------------------------------------------

// Logging out is the one command that disconnects a working node, so it has to reach
// the agent's logout endpoint and nothing else. A command that silently hit /api/login
// instead would leave the node connected while telling the user it is not.
func TestLogoutDisconnectsTheNodeAndSaysWhatSurvives(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/logout": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]string{"backendState": "NeedsLogin"})
		},
	})

	if err := h.run("logout"); err != nil {
		t.Fatalf("logout: %v", err)
	}

	calls := h.recorded()
	if len(calls) != 1 {
		t.Fatalf("logout made %d calls, want exactly one", len(calls))
	}
	if calls[0].Method != http.MethodPost || calls[0].Path != "/api/logout" {
		t.Errorf("logout called %s %s, want POST /api/logout", calls[0].Method, calls[0].Path)
	}
	// The forwards outliving the logout is the part a user cannot see and would
	// otherwise reconfigure from scratch after signing back in.
	if !strings.Contains(h.out(), "stay configured") {
		t.Errorf("logout did not say the forwards survive:\n%s", h.out())
	}
}

// A refused logout must not print the reassuring message. Reporting success over a
// node that is still enrolled is worse than reporting nothing: the user walks away
// believing the device is off the tailnet.
func TestALogoutTheAgentRefusesIsReported(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/logout": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusServiceUnavailable,
				map[string]string{"error": "the tailnet node is not running"})
		},
	})

	err := h.run("logout")

	if err == nil {
		t.Fatal("a refused logout was reported as success")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("err = %v, want the agent's own reason", err)
	}
	if strings.Contains(h.out(), "Disconnected") {
		t.Errorf("the CLI claimed the node disconnected:\n%s", h.out())
	}
}

// logout talks to a running agent and takes no arguments. Accepting a stray one would
// disconnect the tailnet in answer to a mistyped command.
func TestLogoutRejectsAPositionalArgument(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/logout": func(w http.ResponseWriter, _ *http.Request) {
			t.Error("logout disconnected the node despite a bad invocation")
		},
	})

	err := h.run("logout", "everything")

	if !errors.Is(err, ErrUsage) {
		t.Errorf("err = %v, want a usage error so the exit code is 2", err)
	}
}

// --- install-autostart ----------------------------------------------------

// Installing the login item is what makes app-tail survive a reboot, and the message
// has to name the file that was written: it is the only thing the user can inspect or
// delete afterward.
func TestInstallAutostartWritesTheLoginItemAndNamesIt(t *testing.T) {
	skipUnlessLoginItemsAreFiles(t)
	isolateLoginItemHome(t)

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}

	if err := runInstallAutostart(t.Context(), nil, env); err != nil {
		t.Fatalf("install-autostart: %v", err)
	}

	manager, err := autostart.New()
	if err != nil {
		t.Fatalf("autostart.New: %v", err)
	}
	if _, err := os.Stat(manager.Path()); err != nil {
		t.Fatalf("no login item at %s: %v", manager.Path(), err)
	}
	if !strings.Contains(out.String(), manager.Path()) {
		t.Errorf("the message does not name the file it wrote:\n%s", out.String())
	}
	if !strings.Contains(out.String(), manager.Kind()) {
		t.Errorf("the message does not say which mechanism was used:\n%s", out.String())
	}
	if !strings.Contains(out.String(), manager.ExecPath) {
		t.Errorf("the message does not say which binary will run:\n%s", out.String())
	}
}

// --remove has to actually delete the item, and say so distinctly. A remove that
// printed the install message would leave the user believing they had just enabled
// what they meant to disable.
func TestRemovingTheLoginItemDeletesItAndSaysSoDistinctly(t *testing.T) {
	skipUnlessLoginItemsAreFiles(t)
	isolateLoginItemHome(t)

	var installOut, installErr strings.Builder
	installEnv := Env{Stdout: &installOut, Stderr: &installErr, Getenv: func(string) string { return "" }}
	if err := runInstallAutostart(t.Context(), nil, installEnv); err != nil {
		t.Fatalf("install-autostart: %v", err)
	}

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}
	if err := runInstallAutostart(t.Context(), []string{"--remove"}, env); err != nil {
		t.Fatalf("install-autostart --remove: %v", err)
	}

	manager, err := autostart.New()
	if err != nil {
		t.Fatalf("autostart.New: %v", err)
	}
	if _, err := os.Stat(manager.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the login item at %s survived the removal (stat: %v)", manager.Path(), err)
	}
	if !strings.Contains(out.String(), "Removed") {
		t.Errorf("the removal message does not say it removed anything:\n%s", out.String())
	}
	if strings.Contains(out.String(), "will start when you log in") {
		t.Errorf("removing printed the install message:\n%s", out.String())
	}
}

// install-autostart writes a file, so a mistyped invocation must be refused before it
// does. Silently ignoring the stray argument would install a login item in answer to
// something the user meant as a different command.
func TestInstallAutostartRejectsAPositionalArgument(t *testing.T) {
	skipUnlessLoginItemsAreFiles(t)
	isolateLoginItemHome(t)

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}

	err := runInstallAutostart(t.Context(), []string{"enable"}, env)

	if !errors.Is(err, ErrUsage) {
		t.Fatalf("err = %v, want a usage error so the exit code is 2", err)
	}
	manager, newErr := autostart.New()
	if newErr != nil {
		t.Fatalf("autostart.New: %v", newErr)
	}
	if _, statErr := os.Stat(manager.Path()); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a rejected invocation still wrote %s", manager.Path())
	}
}

// --- forward enable -------------------------------------------------------

// `forward enable` is the counterpart of the tested disable path and takes a different
// argument through the same helper. It must resolve the name, send enabled=true, and
// report the state the agent came back with rather than the one it asked for.
func TestForwardEnableTurnsADisabledForwardBackOn(t *testing.T) {
	var sentBody string
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK,
				map[string]any{"forwards": []httpapi.ForwardView{sshForward(false)}})
		},
		"POST /api/forwards/{id}/toggle": func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
			}
			sentBody = string(body)
			writeJSONResponse(t, w, http.StatusOK, sshForward(true))
		},
	})

	if err := h.exec(append([]string{"forward", "enable", "ssh"}, h.cfg()...)...); err != nil {
		t.Fatalf("forward enable: %v", err)
	}

	if !strings.Contains(sentBody, `"enabled":true`) {
		t.Errorf("the request body %q does not turn the forward on", sentBody)
	}
	out := h.out()
	if !strings.Contains(out, "Enabled") {
		t.Errorf("the CLI did not confirm the enable:\n%s", out)
	}
	if !strings.Contains(out, "running") {
		t.Errorf("the CLI did not report the state the agent came back with:\n%s", out)
	}
}

// The state the agent reports wins over the state the CLI asked for. A forward that
// fails the moment it is enabled -- a port already taken -- must show its reason here,
// or the user sees "Enabled" and goes looking for traffic that will never arrive.
func TestEnablingAForwardThatImmediatelyFailsShowsWhy(t *testing.T) {
	broken := sshForward(true)
	broken.State = "error"
	broken.Error = "bind 127.0.0.1:2222: address already in use"

	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK,
				map[string]any{"forwards": []httpapi.ForwardView{sshForward(false)}})
		},
		"POST /api/forwards/{id}/toggle": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, broken)
		},
	})

	if err := h.exec(append([]string{"forward", "enable", "ssh"}, h.cfg()...)...); err != nil {
		t.Fatalf("forward enable: %v", err)
	}

	if !strings.Contains(h.out(), "already in use") {
		t.Errorf("the CLI hid the reason the forward is not running:\n%s", h.out())
	}
}

// A name matching no forward has to be refused before any write. Guessing -- or sending
// an empty id -- would toggle whichever forward the agent happened to match.
func TestEnablingAForwardThatDoesNotExistIsRefusedBeforeAnyWrite(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK,
				map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
		},
		"POST /api/forwards/{id}/toggle": func(w http.ResponseWriter, _ *http.Request) {
			t.Error("an unresolvable name still reached a write")
		},
	})

	err := h.exec(append([]string{"forward", "enable", "no-such-rule"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("an unknown forward name was accepted")
	}
	if !strings.Contains(err.Error(), "no-such-rule") {
		t.Errorf("err = %v, want it to name what the user typed", err)
	}
}

// --- subcommand dispatch --------------------------------------------------

// Every command group has a subcommand it does not recognize, and each must say so
// with the list of what it does take. A group that fell through to its default action
// would run something the user did not ask for -- `preset frobnicate` deleting, or
// `settings frobnicate` printing a list that looks like it worked.
func TestAnUnknownSubcommandIsAUsageErrorThatListsTheRealOnes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantMenu []string
	}{
		{"forward", []string{"forward", "frobnicate"}, []string{"get", "update", "enable", "disable", "toggle"}},
		{"preset", []string{"preset", "frobnicate"}, []string{"list", "add", "rm"}},
		{"settings", []string{"settings", "frobnicate"}, []string{"get", "list", "set", "menu"}},
		{"autostart", []string{"autostart", "frobnicate"}, []string{"status"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, nil)

			err := h.exec(append(tt.args, h.cfg()...)...)

			if !errors.Is(err, ErrUsage) {
				t.Fatalf("err = %v, want it to wrap ErrUsage so the exit code is 2", err)
			}
			if !strings.Contains(err.Error(), "frobnicate") {
				t.Errorf("err = %v, want it to name what the user typed", err)
			}
			for _, sub := range tt.wantMenu {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("err = %v, want it to offer %q", err, sub)
				}
			}
			if len(h.recorded()) != 0 {
				t.Errorf("a rejected subcommand still called the agent: %+v", h.recorded())
			}
		})
	}
}

// A group invoked with no subcommand at all has to explain itself rather than fail
// obscurely or act. `preset` on its own is a plausible thing to type while exploring.
func TestACommandGroupWithNoSubcommandExplainsWhatItTakes(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"forward alone", []string{"forward"}},
		{"preset alone", []string{"preset"}},
		// A leading flag is not a subcommand: `forward --json` has no verb either.
		{"forward with only a flag", []string{"forward", "--json"}},
		{"preset with only a flag", []string{"preset", "--json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, nil)

			err := h.exec(append(tt.args, h.cfg()...)...)

			if !errors.Is(err, ErrUsage) {
				t.Fatalf("err = %v, want a usage error", err)
			}
			if !strings.Contains(err.Error(), "subcommand") {
				t.Errorf("err = %v, want it to say a subcommand is missing", err)
			}
		})
	}
}

// Bare `settings` and bare `autostart` are the two groups that default to an action
// rather than a usage error, because listing is the overwhelmingly common intent.
// Turning either into an error would break the shortest path to the thing people
// actually want.
func TestTheGroupsThatDefaultToListingStillDoSo(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).Hostname = "defaulted-listing"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	if err := h.exec(append([]string{"settings"}, h.cfg()...)...); err != nil {
		t.Fatalf("bare settings: %v", err)
	}
	if !strings.Contains(h.out(), "defaulted-listing") {
		t.Errorf("bare `settings` did not list the settings:\n%s", h.out())
	}
}

// --- --json output --------------------------------------------------------

// The --json forms are the contract scripts parse. Each has to emit valid JSON of the
// documented shape -- and an array rather than `null` when there is nothing, or every
// consumer iterating the result crashes on the empty case.
func TestTheJSONFormsEmitParseableDocuments(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		h := newHarness(t, map[string]http.HandlerFunc{
			"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK,
					map[string]any{"forwards": []httpapi.ForwardView{sshForward(true)}})
			},
		})
		if err := h.run("list", "--json"); err != nil {
			t.Fatalf("list --json: %v", err)
		}

		var got []httpapi.ForwardView
		if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
			t.Fatalf("list --json emitted something a script cannot parse: %v\n%s", err, h.out())
		}
		if len(got) != 1 || got[0].ID != "fw_2" {
			t.Errorf("list --json = %+v, want the one forward the agent reported", got)
		}
		// The human table must not be mixed in, or `| jq` fails on the header row.
		if strings.Contains(h.out(), "LISTENS ON") {
			t.Errorf("list --json printed the human table too:\n%s", h.out())
		}
	})

	t.Run("list with no forwards", func(t *testing.T) {
		h := newHarness(t, map[string]http.HandlerFunc{
			"GET /api/forwards": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK, map[string]any{})
			},
		})
		if err := h.run("list", "--json"); err != nil {
			t.Fatalf("list --json: %v", err)
		}
		if got := strings.TrimSpace(h.out()); got != "[]" {
			t.Errorf("list --json with nothing configured = %q, want %q; `null` breaks every "+
				"consumer that iterates the result", got, "[]")
		}
	})

	t.Run("preset list", func(t *testing.T) {
		h := newHarness(t, map[string]http.HandlerFunc{
			"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
					{ID: "ssh", Name: "SSH", Protocol: config.TCP, RemotePort: 22, BuiltIn: true},
				}})
			},
		})
		if err := h.exec(append([]string{"preset", "list", "--json"}, h.cfg()...)...); err != nil {
			t.Fatalf("preset list --json: %v", err)
		}

		var got []config.Preset
		if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
			t.Fatalf("preset list --json emitted something a script cannot parse: %v\n%s", err, h.out())
		}
		if len(got) != 1 || got[0].ID != "ssh" || !got[0].BuiltIn {
			t.Errorf("preset list --json = %+v, want the built-in the agent reported", got)
		}
		if strings.Contains(h.out(), "REMOTE PORT") {
			t.Errorf("preset list --json printed the human table too:\n%s", h.out())
		}
	})

	t.Run("preset list with none", func(t *testing.T) {
		h := newHarness(t, map[string]http.HandlerFunc{
			"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(t, w, http.StatusOK, map[string]any{})
			},
		})
		if err := h.exec(append([]string{"preset", "list", "--json"}, h.cfg()...)...); err != nil {
			t.Fatalf("preset list --json: %v", err)
		}
		if got := strings.TrimSpace(h.out()); got != "[]" {
			t.Errorf("preset list --json with none = %q, want %q", got, "[]")
		}
	})

	t.Run("settings list", func(t *testing.T) {
		stored := config.Defaults()
		tailnetOf(t, stored).Hostname = "scripted-host"
		tailnetOf(t, stored).AuthKey = "tskey-auth-super-secret"
		h := newHarness(t, settingsRoutes(t, stored, nil))

		if err := h.exec(append([]string{"settings", "list", "--json"}, h.cfg()...)...); err != nil {
			t.Fatalf("settings list --json: %v", err)
		}

		var got map[string]any
		if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
			t.Fatalf("settings list --json emitted something a script cannot parse: %v\n%s", err, h.out())
		}
		if got["hostname"] != "scripted-host" {
			t.Errorf("settings list --json hostname = %v, want %q", got["hostname"], "scripted-host")
		}
		// The JSON form goes through the same redaction as the table. A raw key here
		// would land in whatever log the calling script writes.
		if strings.Contains(h.out(), "tskey-auth-super-secret") {
			t.Fatalf("settings list --json leaked the auth key:\n%s", h.out())
		}
		if got["hasAuthKey"] != true {
			t.Errorf("hasAuthKey = %v, want the presence flag to survive redaction", got["hasAuthKey"])
		}
	})

	t.Run("settings get", func(t *testing.T) {
		stored := config.Defaults()
		stored.Settings.UDPSessionTimeoutSec = 90
		h := newHarness(t, settingsRoutes(t, stored, nil))

		if err := h.exec(append([]string{"settings", "get", "udp-timeout", "--json"}, h.cfg()...)...); err != nil {
			t.Fatalf("settings get --json: %v", err)
		}

		// A number has to stay a number: quoting it would make every arithmetic
		// consumer downstream fail on a string.
		var got any
		if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
			t.Fatalf("settings get --json emitted something a script cannot parse: %v\n%s", err, h.out())
		}
		if n, ok := got.(float64); !ok || n != 90 {
			t.Errorf("settings get --json = %#v, want the number 90", got)
		}
	})
}

// --- preset resolution ----------------------------------------------------

// Nothing stops two user presets sharing a name, and `preset rm` is destructive. A
// command that picked the first match would delete whichever one the agent happened to
// list first, which is not the one the user is looking at.
func TestRemovingAnAmbiguouslyNamedPresetRefusesAndNamesTheCandidates(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
				{ID: "grafana", Name: "Grafana", Protocol: config.TCP, RemotePort: 3000},
				{ID: "grafana-2", Name: "grafana", Protocol: config.TCP, RemotePort: 3001},
			}})
		},
		"DELETE /api/presets/{id}": func(w http.ResponseWriter, _ *http.Request) {
			t.Error("an ambiguous name still deleted a preset")
		},
	})

	err := h.exec(append([]string{"preset", "rm", "Grafana"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("an ambiguous preset name was accepted for a delete")
	}
	for _, want := range []string{"grafana", "grafana-2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name the candidate id %q so the user can pick", err, want)
		}
	}
}

// An exact id wins over a name collision. Otherwise the escape hatch the ambiguity
// message points the user at -- "remove one by id instead" -- would itself be ambiguous.
func TestAnExactPresetIDIsUsedEvenWhenNamesCollide(t *testing.T) {
	var deleted string
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
				{ID: "grafana", Name: "Grafana", Protocol: config.TCP, RemotePort: 3000},
				{ID: "grafana-2", Name: "Grafana", Protocol: config.TCP, RemotePort: 3001},
			}})
		},
		"DELETE /api/presets/{id}": func(w http.ResponseWriter, r *http.Request) {
			deleted = r.PathValue("id")
			w.WriteHeader(http.StatusNoContent)
		},
	})

	if err := h.exec(append([]string{"preset", "rm", "grafana-2"}, h.cfg()...)...); err != nil {
		t.Fatalf("preset rm by id: %v", err)
	}

	if deleted != "grafana-2" {
		t.Errorf("deleted %q, want the preset addressed by its exact id", deleted)
	}
}

// A name matching nothing has to say so and point at the listing. Falling through to a
// DELETE with an empty id would return an opaque 404 the user cannot act on.
func TestRemovingAPresetThatDoesNotExistPointsAtTheListing(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
				{ID: "ssh", Name: "SSH", Protocol: config.TCP, RemotePort: 22, BuiltIn: true},
			}})
		},
		"DELETE /api/presets/{id}": func(w http.ResponseWriter, _ *http.Request) {
			t.Error("an unresolvable name still reached a delete")
		},
	})

	err := h.exec(append([]string{"preset", "rm", "prometheus"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("an unknown preset name was accepted")
	}
	if !strings.Contains(err.Error(), "prometheus") {
		t.Errorf("err = %v, want it to name what the user typed", err)
	}
	if !strings.Contains(err.Error(), "preset list") {
		t.Errorf("err = %v, want it to point at the command that lists them", err)
	}
}

// A built-in cannot be removed, and matching one by name must not fall through to the
// "no such preset" message -- that would send the user looking for a typo in a name
// that is right.
func TestRemovingABuiltInByNameSaysItIsBuiltInRatherThanMissing(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/presets": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"presets": []config.Preset{
				{ID: "ssh", Name: "SSH", Protocol: config.TCP, RemotePort: 22, BuiltIn: true},
			}})
		},
		"DELETE /api/presets/{id}": func(w http.ResponseWriter, _ *http.Request) {
			t.Error("a built-in preset was deleted")
		},
	})

	err := h.exec(append([]string{"preset", "rm", "ssh"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("a built-in preset was accepted for removal")
	}
	if !strings.Contains(err.Error(), "built-in") {
		t.Errorf("err = %v, want it to say the preset is built in", err)
	}
}

// --- helpers --------------------------------------------------------------

// skipUnlessLoginItemsAreFiles keeps the install/remove tests off Windows, where
// SetEnabled writes a real HKCU\...\Run value into the runner's own registry with no
// seam to redirect it. CI runs windows-latest, so this is a hard safety requirement,
// not a convenience.
func skipUnlessLoginItemsAreFiles(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("login items are files only on darwin and linux; %s writes elsewhere", runtime.GOOS)
	}
}

// isolateLoginItemHome points every home-directory lookup the autostart package makes
// at a temp dir. All three variables are needed: os.UserHomeDir reads HOME on unix and
// USERPROFILE on Windows, and the linux Path() honours XDG_CONFIG_HOME above both --
// leaving it set would write a systemd unit into the developer's real ~/.config.
func isolateLoginItemHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

// Every command that reads the stored config finds it from the user's config directory
// when no flag names one. On a machine where that cannot be located -- a daemon context
// with no home, a stripped-down container -- the command has to say so: falling back to
// the working directory would quietly read a different config from the agent's.
func TestACommandSaysWhenItCannotLocateTheConfigDirectory(t *testing.T) {
	// os.UserConfigDir asks a different variable on each platform, and one left set is a
	// machine that can locate the directory after all -- which is not the case under test.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")

	env := Env{Stdout: io.Discard, Stderr: io.Discard, Getenv: func(string) string { return "" }}

	err := Run(t.Context(), []string{"status"}, env)

	if err == nil {
		t.Fatal("a command read the stored config with nowhere to read it from")
	}
	if !strings.Contains(err.Error(), "config dir") {
		t.Errorf("err = %v, want it to name what could not be located", err)
	}
}
