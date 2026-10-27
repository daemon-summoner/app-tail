// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/httpapi"
)

// autoMapRoutes answers the endpoints the automap commands read and write.
func autoMapRoutes(t *testing.T, view httpapi.AutoMapView, removed int) map[string]http.HandlerFunc {
	after := view
	after.Stored = view.Stored - removed
	return map[string]http.HandlerFunc{
		"GET /api/automap": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, view)
		},
		"POST /api/automap/forget": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"removed": removed, "automap": after})
		},
	}
}

// onView is the module running, with more remembered than currently open -- the ordinary
// state once a device has been seen and then gone away.
func onView() httpapi.AutoMapView {
	return httpapi.AutoMapView{Enabled: true, Ports: []int{22, 80}, Limit: 32, Mapped: 4, Stored: 7}
}

// The port list and both counts are the whole state: which ports, how many are open, and
// how many are remembered. Without the last one nothing on screen says whether forgetting
// would do anything at all.
func TestAutoMapStatusReportsWhatItOpensAndWhatItRemembers(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, onView(), 0))

	if err := Run(t.Context(), append([]string{"automap"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("automap: %v", err)
	}
	for _, want := range []string{"22, 80", "4 local ports", "7 assignments", "app-tail list"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("automap output is missing %q:\n%s", want, h.out())
		}
	}
}

// A truncation the module reports has to reach the user: a device silently left out
// reads as the tailnet being wrong rather than the limit being reached.
func TestAutoMapStatusPassesOnTheReasonTheAgentGave(t *testing.T) {
	view := onView()
	view.Truncated = 9
	view.Reason = "9 device-and-port pairs were left out by the limit of 32"
	h := newHarness(t, autoMapRoutes(t, view, 0))

	if err := Run(t.Context(), append([]string{"automap"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("automap: %v", err)
	}
	if !strings.Contains(h.out(), view.Reason) {
		t.Errorf("automap output does not carry the agent's reason:\n%s", h.out())
	}
}

func TestAutoMapStatusSaysHowToTurnItOn(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, httpapi.AutoMapView{Limit: 32}, 0))

	if err := Run(t.Context(), append([]string{"automap"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("automap: %v", err)
	}
	if !strings.Contains(h.out(), "settings set automap true") {
		t.Errorf("automap output does not say how to turn the module on:\n%s", h.out())
	}
}

func TestAutoMapStatusAsJSONIsTheAgentsOwnAnswer(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, onView(), 0))

	if err := Run(t.Context(), append([]string{"automap"}, append(h.cfg(), "--json")...), h.env()); err != nil {
		t.Fatalf("automap --json: %v", err)
	}
	var got httpapi.AutoMapView
	if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
		t.Fatalf("parse the JSON output: %v\n%s", err, h.out())
	}
	if got.Stored != 7 || got.Mapped != 4 {
		t.Errorf("JSON output = %+v, want the agent's own view", got)
	}
}

// Forgetting renumbers a device the next time it appears, so the count it dropped is the
// one thing the user needs back: "done" would leave them unable to tell a real prune
// from a no-op.
func TestAutoMapForgetReportsHowManyItDropped(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, onView(), 3))

	if err := Run(t.Context(), append([]string{"automap", "forget"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("automap forget: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "Forgot 3") || !strings.Contains(out, "4 remain") {
		t.Errorf("automap forget does not report what it did:\n%s", out)
	}
}

func TestAutoMapForgetSaysSoWhenEveryDeviceIsStillHere(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, onView(), 0))

	if err := Run(t.Context(), append([]string{"automap", "forget"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("automap forget: %v", err)
	}
	if !strings.Contains(h.out(), "still on the tailnet") {
		t.Errorf("automap forget does not explain why nothing changed:\n%s", h.out())
	}
}

// A misspelt subcommand that fell through to the status view would look like it worked
// while doing nothing the user asked for.
//
// The word goes before the flags in every case here. A subcommand written after them is
// an ordinary positional argument by the time the parser sees it, which the status view
// refuses for its own reason -- so an invocation in that order never reaches the check
// this is about.
func TestAutoMapChecksItsArguments(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, onView(), 0))

	for _, args := range [][]string{
		{"automap", "frobnicate"},
		{"automap", "forgett"},
		{"automap", "extra"},
	} {
		full := append(append([]string{}, args...), h.cfg()...)
		err := Run(t.Context(), full, h.env())
		if !errors.Is(err, ErrUsage) {
			t.Errorf("%v gave %v, want a usage error", args, err)
			continue
		}
		if !strings.Contains(err.Error(), args[1]) {
			t.Errorf("%v gave %q, want it to name what was misspelt", args, err)
		}
	}

	// The same word written after the flags is a positional argument by then, and the
	// status view has to refuse it too -- accepting it would print the view and leave a
	// user believing the word did something.
	for _, args := range [][]string{
		{"automap"},
		{"automap", "forget"},
	} {
		full := append(append(append([]string{}, args...), h.cfg()...), "everything")
		if err := Run(t.Context(), full, h.env()); !errors.Is(err, ErrUsage) {
			t.Errorf("%v everything gave %v, want a usage error", args, err)
		}
	}

	// A flag neither command has must fail on both rather than be ignored: silently
	// dropping one is how a user believes they asked for something they did not.
	for _, args := range [][]string{
		{"automap", "--frobnicate"},
		{"automap", "forget", "--frobnicate"},
	} {
		full := append(append([]string{}, args...), h.cfg()...)
		if err := Run(t.Context(), full, h.env()); err == nil {
			t.Errorf("%v was accepted, want the unknown flag refused", args)
		}
	}
}

// Both commands read the agent, so both have to fail when there is none rather than
// print an empty view. `automap` reporting no mappings when it simply could not ask is
// the same words a working agent uses for a module that is off.
func TestBothAutoMapCommandsSayWhenThereIsNoAgent(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, onView(), 0))
	h.stopAgent()

	for _, args := range [][]string{
		{"automap"},
		{"automap", "forget"},
	} {
		full := append(append([]string{}, args...), h.cfg()...)
		err := Run(t.Context(), full, h.env())
		if err == nil {
			t.Errorf("%v succeeded with no agent running", args)
			continue
		}
		if !errors.Is(err, ErrNoAgent) {
			t.Errorf("%v gave %v, want it to wrap ErrNoAgent", args, err)
		}
	}
}

// The agent's refusal is the answer, not a detail to swallow: a script that saw exit 0
// would carry on believing the ports were dropped.
func TestAutoMapForgetSurfacesTheAgentsRefusal(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/automap/forget": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusServiceUnavailable,
				map[string]string{"error": "the tailnet node is not running"})
		},
	})

	err := Run(t.Context(), append([]string{"automap", "forget"}, h.cfg()...), h.env())
	if err == nil {
		t.Fatal("a refused forget reported success")
	}
	if !strings.Contains(err.Error(), "the tailnet node is not running") {
		t.Errorf("err = %v, want the agent's own reason", err)
	}
}

// The status command reads one endpoint, so a refusal there is the whole answer. Printing
// an empty module instead would read as "nothing is mapped" on a machine whose agent is
// simply not answering.
func TestAutoMapStatusPassesOnTheAgentsRefusal(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/automap": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusInternalServerError,
				map[string]string{"error": "the device list could not be read"})
		},
	})

	err := Run(t.Context(), append([]string{"automap"}, h.cfg()...), h.env())

	if err == nil {
		t.Fatal("automap reported the module's state after the agent refused")
	}
	if !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("err = %v, want the agent's own reason", err)
	}
}

// Both commands read the stored config to find the agent, so a config that cannot be
// parsed has to stop them there. Falling through would run the command against whatever
// address a default config points at, and report that machine's mappings as this one's.
func TestBothAutoMapCommandsRefuseAConfigTheyCannotRead(t *testing.T) {
	h := newHarness(t, autoMapRoutes(t, onView(), 1))
	if err := os.WriteFile(h.configPath, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatalf("write a broken config: %v", err)
	}

	for _, args := range [][]string{
		{"automap"},
		{"automap", "forget"},
	} {
		full := append(append([]string{}, args...), h.cfg()...)
		err := Run(t.Context(), full, h.env())
		if err == nil {
			t.Errorf("%v ran against a config it could not read", args)
			continue
		}
		if !strings.Contains(err.Error(), h.configPath) {
			t.Errorf("%v gave %v, want it to name the file it could not read", args, err)
		}
	}
	if h.out() != "" {
		t.Errorf("a command that never reached the agent still printed:\n%s", h.out())
	}
}
