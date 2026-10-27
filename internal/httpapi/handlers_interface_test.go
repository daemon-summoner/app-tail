// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The dashboard is where somebody is standing when they learn the mode is not in force, so
// it has to be able to do something about it. Without this route the only fix is a command
// in a terminal, which is the step the whole path exists to remove.
func TestTheDashboardCanSetThisMachineUpForTheInterfaceMode(t *testing.T) {
	h := newHarness(t)
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, newAPIRequest(http.MethodPost, "/api/tun/setup", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if h.iface.calls != 1 {
		t.Errorf("the machine setup ran %d times, want once", h.iface.calls)
	}
	// Arranging the machine does not move the running node onto the interface, so a
	// client that stopped here would report success beside a card still saying the mode
	// is not in force.
	got := decode[struct {
		RestartNeeded bool `json:"restartNeeded"`
	}](t, rec)
	if !got.RestartNeeded {
		t.Error("the reply does not say the node still has to be rebuilt")
	}
}

// The card is the one surface that says what the interface mode is doing, and the state it
// exists for is the one where the settings and the machine disagree. A view built from the
// settings alone would report the mode as on for a node that fell back to the contained one.
func TestTheInterfaceCardReportsTheModeInForceAndNotTheOneAskedFor(t *testing.T) {
	h := newHarness(t)
	h.iface.view = InterfaceView{
		Enabled:    true,
		Configured: "tun",
		Mode:       "userspace",
		Fallback:   "the privileged helper is not running",
		Helper:     Helper{Design: true, Installable: true},
		Capability: Capability{Available: true, Degraded: true, Reason: "the privileged helper is not running"},
	}

	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, newAPIRequest(http.MethodGet, "/api/tun", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}

	got := decode[InterfaceView](t, rec)
	if got.InForce {
		t.Error("a node that fell back to the contained mode was reported as running on the interface")
	}
	if got.Mode == got.Configured {
		t.Errorf("the mode in force and the one configured were both reported as %q", got.Mode)
	}
	if got.Fallback == "" || got.Capability.Reason == "" {
		t.Errorf("nothing says why the mode is not in force: %+v", got)
	}
}

// A build without the agent's interface dependency must answer rather than panic, the same
// contract every other route holds to.
func TestTheInterfaceCardWithoutTheCapabilityReportsItRatherThanPanicking(t *testing.T) {
	s := New(Options{Auth: testKeys, Deps: Deps{Node: &fakeNode{}, Forwards: &fakeForwards{}}})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newAPIRequest(http.MethodGet, "/api/tun", nil))
	requireError(t, rec, http.StatusServiceUnavailable, "network interface")
}

// The reason is the entire value of asking: a declined password prompt and a machine that
// could not run the installer need different things done about them.
func TestASetupThatFailedSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.iface.err = errors.New("the request for administrator rights was declined")

	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, newAPIRequest(http.MethodPost, "/api/tun/setup", nil))
	requireError(t, rec, http.StatusInternalServerError, "declined")
}

// An agent too old to offer the setup, or a build without it, must answer rather than
// panic on a nil dependency -- the same contract every other route holds to.
func TestSetupWithoutTheCapabilityReportsItRatherThanPanicking(t *testing.T) {
	s := New(Options{Auth: testKeys, Deps: Deps{Node: &fakeNode{}, Forwards: &fakeForwards{}}})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newAPIRequest(http.MethodPost, "/api/tun/setup", nil))
	requireError(t, rec, http.StatusServiceUnavailable, "network-interface setup")
}

// The route changes the machine, so the same-origin guard has to cover it: a page on
// another site must not be able to raise a password prompt on this one.
func TestSetupRejectsACrossOriginRequest(t *testing.T) {
	h := newHarness(t)
	req := newAPIRequest(http.MethodPost, "/api/tun/setup", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("a cross-origin request set the machine up: %d", rec.Code)
	}
	if h.iface.calls != 0 {
		t.Errorf("a cross-origin request reached the machine setup %d times", h.iface.calls)
	}
}
