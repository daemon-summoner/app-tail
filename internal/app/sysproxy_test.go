// SPDX-License-Identifier: MIT

package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// systemProxyOn is a config with the proxy running and this machine pointed at it.
//
// ProxySystem is written into the document rather than patched through the API because
// the setting is offered only on Windows; the agent still has to act on whatever the
// document says, since a config file moves between machines.
func systemProxyOn(c *config.Config) {
	proxyOn(c)
	c.Settings.ProxySystem = true
}

// systemProxyView reads the API the dashboard card renders.
func systemProxyView(h *harness) httpapi.SystemProxyView {
	h.t.Helper()
	resp, body := h.get("/api/proxy/system")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /api/proxy/system = %d: %s", resp.StatusCode, body)
	}
	var view httpapi.SystemProxyView
	if err := json.Unmarshal(body, &view); err != nil {
		h.t.Fatalf("decode the system proxy view: %v", err)
	}
	return view
}

// waitForSystemProxy waits for the reconcile loop to reach a state, since the machine's
// setting is written on the lifecycle goroutine rather than on the request that caused it.
func waitForSystemProxy(h *harness, why string, ready func(string) bool) string {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var pointsAt string
	for time.Now().Before(deadline) {
		pointsAt, _, _ = h.sysproxy.snapshot()
		if ready(pointsAt) {
			return pointsAt
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("timed out after 5s waiting for %s; the machine points at %q", why, pointsAt)
	return pointsAt
}

// The install promise, for the one setting that reaches outside the app's own state
// directory: nothing on this machine changes unless it was asked for.
func TestNothingOnThisMachineIsChangedWhileTheSettingIsOff(t *testing.T) {
	h := newHarness(t, proxyOn)
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.Listening != "" })

	pointsAt, applies, _ := h.sysproxy.snapshot()
	if applies != 0 {
		t.Errorf("this machine's proxy configuration was written %d times with the setting off", applies)
	}
	if pointsAt != "" {
		t.Errorf("this machine points at %q with the setting off", pointsAt)
	}

	view := systemProxyView(h)
	if view.Enabled || view.Applied {
		t.Errorf("the module reports enabled=%v applied=%v with nobody having turned it on",
			view.Enabled, view.Applied)
	}
}

// The feature itself: the machine ends up pointing at the script this agent serves, at
// the address it is actually serving it on.
func TestTheMachineIsPointedAtTheScriptThisAgentServes(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()

	pointsAt := waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	want := h.agent.DashboardURL() + "/proxy.pac"
	if pointsAt != want {
		t.Errorf("this machine points at %q, want the script at %q", pointsAt, want)
	}

	// The URL has to be one something can actually fetch, or the whole feature is a
	// setting that breaks every program that reads it.
	resp, body := h.get("/proxy.pac")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET the script this machine was pointed at = %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "FindProxyForURL") {
		t.Errorf("the script this machine was pointed at is not an auto-config file: %s", body)
	}

	if view := systemProxyView(h); !view.Applied {
		t.Errorf("the card reports applied=false while the machine points at %q", pointsAt)
	}
}

// Turning the setting off has to put the machine back, on the reconcile that follows
// rather than at some later restart: the user turned it off because they want it gone.
func TestTurningTheSettingOffPutsThisMachineBack(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	storeSetting(h, func(s *config.Settings) { s.ProxySystem = false })

	waitForSystemProxy(h, "this machine to be put back", func(url string) bool { return url == "" })
	if _, _, clears := h.sysproxy.snapshot(); clears != 1 {
		t.Errorf("this machine was restored %d times, want once", clears)
	}
}

// Stopping the app must not leave the machine pointing at a port that is about to stop
// answering. A restore that only happened on the next start would leave every program
// that reads the setting broken in the meantime.
func TestStoppingTheAppPutsThisMachineBack(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	h.stop()

	if pointsAt, _, clears := h.sysproxy.snapshot(); pointsAt != "" || clears == 0 {
		t.Errorf("after the app stopped this machine still points at %q (restored %d times)",
			pointsAt, clears)
	}
}

// Every state that must not reach this machine's settings, and the words the user gets
// instead. A port nothing answers on is worse than no setting at all: it breaks every
// program that reads it, for a feature that is not running.
//
// The states are supplied rather than provoked because the proxy falls back to a free
// port when the configured one is taken, so a bind failure is not reproducible on demand
// -- and this is the decision that has to be right in every one of them.
func TestNoBrokenProxyIsInstalledOnThisMachine(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	for _, tc := range []struct {
		name   string
		status tsproxy.Status
		says   string
	}{
		{"the module is off", tsproxy.Status{}, "switched off"},
		{"nothing bound and no reason given",
			tsproxy.Status{Enabled: true}, "not listening"},
		{"nothing bound, with the bind error",
			tsproxy.Status{Enabled: true, Error: "port 1080 is already in use"}, "already in use"},
		{"a password the script cannot carry",
			tsproxy.Status{Enabled: true, Listening: "127.0.0.1:1080", RequiresToken: true}, "password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, reason := h.agent.systemProxyTarget(tc.status)
			if url != "" {
				t.Errorf("this machine would be pointed at %q", url)
			}
			if !strings.Contains(reason, tc.says) {
				t.Errorf("reason = %q, want it to mention %q", reason, tc.says)
			}
		})
	}

	// ...and the state that must reach it, so the guard above is not simply refusing
	// everything.
	running := tsproxy.Status{Enabled: true, Listening: "127.0.0.1:1080"}
	url, reason := h.agent.systemProxyTarget(running)
	if url == "" {
		t.Errorf("a listening proxy was refused: %s", reason)
	}
}

// A proxy that stops listening has to be taken back off this machine, not left pointing
// at a dead port until the next restart.
func TestAProxyThatStopsListeningIsTakenOffThisMachine(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	patchSettings(h, map[string]any{"proxy.enabled": false})

	waitForSystemProxy(h, "this machine to be put back", func(url string) bool { return url == "" })
	if view := systemProxyView(h); view.Applied {
		t.Error("the card reports the setting applied after the proxy was switched off")
	}
}

// A password-protected proxy produces a script that sends everything direct, because a
// PAC result line has nowhere to put a credential. Installing it would replace the
// user's proxy configuration with one that achieves exactly nothing.
func TestAPasswordProtectedProxyIsNotInstalledOnThisMachine(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		systemProxyOn(c)
		held := proxyOf(t, c)
		held.RequireToken = true
		held.Token = "a-token-a-user-chose"
	})
	h.bringUp()
	waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool { return v.Listening != "" })

	waitFor(t, 5*time.Second, "the card to explain the password", func() bool {
		return strings.Contains(systemProxyView(h).Capability.Reason, "password")
	})

	if pointsAt, applies, _ := h.sysproxy.snapshot(); pointsAt != "" || applies != 0 {
		t.Errorf("this machine points at %q after %d writes, for a proxy that needs a password",
			pointsAt, applies)
	}
}

// A reconcile runs on every node event, and the machine's setting is written by an OS
// call. Rewriting an unchanged value on each pass would notify every running browser to
// re-read its proxy configuration, several times a minute, forever.
func TestAnUnchangedSettingIsNotRewrittenOnEveryReconcile(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	for range 5 {
		h.agent.pokeReconcile()
	}
	// Reconciles are asynchronous, so wait for one that is observable before counting.
	waitForProxy(h, "a reconcile to complete", func(v httpapi.ProxyView) bool { return v.Listening != "" })

	if _, applies, _ := h.sysproxy.snapshot(); applies != 1 {
		t.Errorf("this machine's proxy configuration was written %d times, want once", applies)
	}
}

// A refusal from the OS is a fact the user needs, not a line in a log file: the switch
// is on and the machine is not pointing anywhere, and only the card can say why.
func TestARefusalFromThisMachineIsReportedRatherThanLogged(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.sysproxy.failWith(errors.New("the proxy settings are managed by your organization"))
	h.bringUp()

	waitFor(t, 5*time.Second, "the card to carry the refusal", func() bool {
		return strings.Contains(systemProxyView(h).Capability.Reason, "managed by your organization")
	})

	view := systemProxyView(h)
	if view.Applied {
		t.Error("the card reports the setting applied after the machine refused it")
	}
	if !view.Capability.Degraded {
		t.Error("a switch that is on and not in force is not reported as degraded")
	}
}

// A restore this machine refuses is the worst state the module has: the switch reads
// off, and the machine is still pointing at a port that is about to stop answering. It
// has to say so, and it has to keep trying -- the refusal is usually something the user
// can clear, and putting the setting back is the whole promise.
func TestARefusedRestoreIsReportedAndRetried(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	h.sysproxy.failClearWith(errors.New("the proxy settings are locked by another program"))
	storeSetting(h, func(s *config.Settings) { s.ProxySystem = false })

	waitFor(t, 5*time.Second, "the card to carry the refused restore", func() bool {
		return strings.Contains(systemProxyView(h).Capability.Reason, "could not be restored")
	})
	view := systemProxyView(h)
	if view.Applied {
		t.Error("the card reports the setting applied while the module is off")
	}
	if pointsAt, _, clears := h.sysproxy.snapshot(); pointsAt == "" || clears != 0 {
		t.Errorf("this machine points at %q after %d restores, want the refusal to have left it alone",
			pointsAt, clears)
	}

	// Whatever was blocking it goes away, and the next reconcile puts the machine back
	// without anyone touching the switch again.
	h.sysproxy.failClearWith(nil)
	h.agent.pokeReconcile()
	waitForSystemProxy(h, "this machine to be put back once the refusal cleared",
		func(url string) bool { return url == "" })
}

// An app that could not put this machine back has failed at something the user cares
// about after the window is gone. Exiting quietly would leave a machine pointing at a
// dead port with nothing anywhere saying so.
func TestAnAppThatCannotPutThisMachineBackSaysSoOnTheWayOut(t *testing.T) {
	h := newHarness(t, systemProxyOn)
	h.bringUp()
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})

	h.sysproxy.failClearWith(errors.New("the proxy settings are locked by another program"))

	// The exit is the assertion: a clean one is exactly what must not happen here.
	err := h.exit()
	if err == nil {
		t.Fatal("the app exited cleanly having left this machine pointing at a proxy that is gone")
	}
	if !strings.Contains(err.Error(), "restore this machine's proxy configuration") {
		t.Errorf("exit error = %v, want it to name what could not be put back", err)
	}
}

// The card carries whatever this machine cannot be switched into, and that differs by
// platform: macOS needs a command run by hand, Windows writes the setting itself, and
// Linux has no single setting to write. What holds everywhere is that the card describes
// the proxy actually running rather than a placeholder.
func TestTheCardDescribesTheRunningProxyForThisPlatform(t *testing.T) {
	h := newHarness(t, proxyOn)
	h.bringUp()
	view := waitForProxy(h, "the proxy to bind", func(v httpapi.ProxyView) bool {
		return v.Listening != ""
	})

	card := systemProxyView(h)
	if len(card.Capability.Limits) == 0 {
		t.Error("the card states no limits, so nothing tells the user what the switch misses")
	}

	if runtime.GOOS != "darwin" {
		// A command offered here is one that does nothing on this machine, which is worse
		// than offering none: it reads as the remedy and leaves the proxy unused.
		if len(card.Manual) != 0 {
			t.Errorf("the card offers %+v to run by hand, and this platform has no such setting", card.Manual)
		}
		return
	}

	if len(card.Manual) == 0 {
		t.Fatal("the card offers no way to use the proxy by hand")
	}
	var named bool
	for _, cmd := range card.Manual {
		if strings.Contains(cmd.Command, view.Listening) || strings.Contains(cmd.Command, view.PACURL) {
			named = true
		}
	}
	if !named {
		t.Errorf("no offered command names the running proxy at %s: %+v", view.Listening, card.Manual)
	}
}

// Every reconcile helper runs on a schedule the agent's own construction does not gate,
// so each has to answer for the window before the parts it reads exist. A nil dereference
// here takes the whole agent down on the way up, which is the one moment a user has no
// dashboard to read the crash from.
func TestTheSystemProxyIsLeftAloneUntilThereIsSomethingToWriteWith(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Neither the proxy nor the system-proxy manager exists yet; both calls belong to the
	// reconcile pass and must simply do nothing.
	agent.applyProxies(true)
	agent.applySystemProxy(tsproxy.Status{Enabled: true, Listening: "127.0.0.1:1080"})

	if applied, reason := agent.systemProxy.snapshot(); applied {
		t.Errorf("the system proxy reads as applied (%q) with nothing to apply it", reason)
	}
}

// The auto-config script lives on the dashboard, so there is nothing to point this
// machine at until the dashboard has an address. Writing the setting first would install
// a URL that answers nothing, and the machine would send everything to a dead port.
func TestNothingIsWrittenUntilTheDashboardHasAnAddressToPublish(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.ProxySystem = true
		return nil
	}); err != nil {
		t.Fatalf("switch the setting on: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	agent, err := New(Options{Store: store, Runtime: runtime, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	url, reason := agent.systemProxyTarget(tsproxy.Status{Enabled: true, Listening: "127.0.0.1:1080"})

	if url != "" {
		t.Errorf("target = %q before the dashboard bound, want nothing to point at", url)
	}
	if !strings.Contains(reason, "dashboard") {
		t.Errorf("reason = %q, want it to name the dashboard as what is missing", reason)
	}
}

// The dashboard asks for this surface on every poll, including during the window before
// Run has built the manager. It has to be absent rather than a typed nil inside a non-nil
// interface, which is the shape a caller's `!= nil` check silently passes.
func TestTheMachineProxySurfaceIsAbsentUntilTheAgentHasBuiltOne(t *testing.T) {
	if got := newUnstartedAgent(t).SystemProxyAPI(); got != nil {
		t.Errorf("SystemProxyAPI() = %#v before Run built a manager, want nothing at all", got)
	}
}

// A manager that has gone -- the far side of the same window, reached through a surface
// handed out before it went -- still has to answer. The platform is the one fact that
// holds without it, and it is what the card renders to explain why there is no switch.
func TestTheMachineProxyViewNamesThePlatformWithNoManagerToRead(t *testing.T) {
	view := sysProxyAPI{a: newUnstartedAgent(t)}.View()

	if view.Platform != runtime.GOOS {
		t.Errorf("Platform = %q, want this machine's own %q", view.Platform, runtime.GOOS)
	}
	if view.Supported || view.Applied || view.AutoConfigURL != "" {
		t.Errorf("view reports supported=%v applied=%v url=%q with no manager to have done any of it",
			view.Supported, view.Applied, view.AutoConfigURL)
	}
}
