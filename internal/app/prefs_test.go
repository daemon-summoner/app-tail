// SPDX-License-Identifier: MIT

package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// acceptRoutes turns on the subnet-routes module and the setting it governs, the way a
// user saving the form does.
func acceptRoutes(h *harness, accept bool) {
	h.t.Helper()
	patchSettings(h, map[string]any{"routes.enabled": true, "routes.accept": accept})
}

// waitForNodePrefs waits until the node holds want, reporting what it holds instead.
func waitForNodePrefs(h *harness, want tsnode.Prefs, what string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := h.node.prefsState(); got.Same(want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, edits := h.node.prefsState()
	h.t.Fatalf("timed out after 5s waiting for %s; the node holds %+v after %d edits, want %+v",
		what, got, edits, want)
}

// prefsView reads the mirror the dashboard renders.
func prefsView(h *harness) httpapi.PrefsView {
	h.t.Helper()
	resp, body := h.get("/api/prefs")
	if resp.StatusCode != 200 {
		h.t.Fatalf("GET /api/prefs = %d: %s", resp.StatusCode, body)
	}
	var view httpapi.PrefsView
	if err := json.Unmarshal(body, &view); err != nil {
		h.t.Fatalf("decode the preference mirror: %v", err)
	}
	return view
}

// mirroredField is the one setting the mirror reports under key. Selecting by key rather
// than by position is what keeps a test about one setting from failing when a module
// gains another one.
func mirroredField(h *harness, view httpapi.PrefsView, key string) httpapi.PrefFieldView {
	h.t.Helper()
	for _, f := range view.Fields {
		if f.Key == key {
			return f
		}
	}
	h.t.Fatalf("the mirror reports no setting %q, only %+v", key, view.Fields)
	return httpapi.PrefFieldView{}
}

// Settings the node holds reach the tailnet rather than only this machine, and tsnet
// applies none of them from the parameters a node is built with. This push is the only
// path any of them ever take: without it the setting stores, reads back correctly
// everywhere, and does nothing at all.
func TestASettingHeldOnTheNodeIsHandedToIt(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	acceptRoutes(h, true)

	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the node to be told to accept subnet routes")
}

// A setting the user turns off has to reach the node as off. Leaving the preference
// standing would leave the tailnet acting on a setting that reads as off here.
func TestTurningASettingOffIsHandedToTheNodeToo(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	acceptRoutes(h, true)
	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the setting to be applied")

	acceptRoutes(h, false)
	waitForNodePrefs(h, tsnode.Prefs{}, "the setting to be turned off on the node")
}

// Switching the module off must take its settings off the tailnet with it. A preference
// left standing under a switch reading off is a setting the user can neither see nor
// turn off -- the exact failure the module system exists to prevent.
func TestSwitchingTheModuleOffTakesItsSettingsOffTheNode(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	acceptRoutes(h, true)
	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the setting to be applied")

	patchSettings(h, map[string]any{"routes.enabled": false})

	waitForNodePrefs(h, tsnode.Prefs{}, "the node to stop accepting subnet routes")
}

// A save while the node is down stores fine and applies nothing. Reporting it as saved
// would be reporting a change nothing has made, so the wait is named on the way out and
// honoured when the node arrives.
func TestASettingStoredWhileTheNodeIsDownIsReportedAsWaitingAndAppliedLater(t *testing.T) {
	h := newHarness(t, nil)

	patch := map[string]json.RawMessage{
		"routes.enabled": json.RawMessage(`true`),
		"routes.accept":  json.RawMessage(`true`),
	}
	_, result, err := h.agent.Settings().Update(t.Context(), patch)
	if err != nil {
		t.Fatalf("write the setting while the node is down: %v", err)
	}

	if len(result.Deferred) != 1 {
		t.Fatalf("the save reported %d settings as waiting, want the one the node holds: %+v",
			len(result.Deferred), result.Deferred)
	}
	if result.Deferred[0].Key != "routes.accept" {
		t.Errorf("the save reported %q as waiting, want routes.accept", result.Deferred[0].Key)
	}
	if !strings.Contains(result.Deferred[0].Reason, "tailnet node") {
		t.Errorf("the reason reads %q, want it to name the tailnet node", result.Deferred[0].Reason)
	}

	// The setting is stored, so the node gets it as soon as there is a node to tell.
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})
	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the stored setting to be applied on startup")
}

// A save the node would refuse must not be stored. Storing it would leave the settings
// document and the tailnet permanently disagreeing about a value the user believes they
// set, with the failure surfacing later as a push nobody connects to the save.
func TestASettingTheNodeRefusesIsNeverStored(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})
	h.node.refusePrefs(errors.New("cannot use an exit node while advertising one"))

	patch := map[string]json.RawMessage{
		"routes.enabled": json.RawMessage(`true`),
		"routes.accept":  json.RawMessage(`true`),
	}
	_, _, err := h.agent.Settings().Update(t.Context(), patch)
	if err == nil {
		t.Fatal("a setting the node refused was accepted")
	}
	if !strings.Contains(err.Error(), "advertising one") {
		t.Errorf("the refusal reads %q, want the backend's own sentence", err)
	}
	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Errorf("the refusal is %T, want the kind the API answers 400 with", err)
	}

	if accept, module := storedRoutes(t, h); accept || module {
		t.Errorf("a refused setting was stored anyway: accept=%v, module=%v", accept, module)
	}
}

// A failure to hand a stored setting to a running node is the user's problem to see. A
// save that answered "saved" and logged the failure would leave them with a setting that
// reads as on everywhere and is off on the tailnet.
func TestASettingTheNodeAcceptsButCannotApplyIsReportedAsAFailedSave(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})
	h.node.failPrefsEdit(errors.New("the backend is not answering"))

	patch := map[string]json.RawMessage{
		"routes.enabled": json.RawMessage(`true`),
		"routes.accept":  json.RawMessage(`true`),
	}
	_, _, err := h.agent.Settings().Update(t.Context(), patch)
	if err == nil {
		t.Fatal("a setting the node could not apply was reported as saved")
	}
	if !strings.Contains(err.Error(), "not answering") {
		t.Errorf("the failure reads %q, want the backend's own reason", err)
	}
}

// Something outside this app changing a setting back is a disagreement no amount of
// retrying settles. Pushing on every change is a loop against the control plane, so it
// stops and says which setting -- the one state a user has to resolve elsewhere.
func TestASettingSomethingElseKeepsChangingBackIsReportedRatherThanFoughtForever(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})
	acceptRoutes(h, true)
	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the setting to be applied")

	// The fight starts here, from a settled state, so every write that follows is one
	// this app made on its own to put the setting back.
	_, settled := h.node.prefsState()
	h.node.keepPrefs(tsnode.Prefs{RouteAll: false})

	waitFor(t, 5*time.Second, "app-tail to stop putting the setting back", func() bool {
		conflict, _ := h.agent.prefsReport(config.PrimaryTunnelID)
		return len(conflict) > 0
	})

	conflict, _ := h.agent.prefsReport(config.PrimaryTunnelID)
	if conflict[0] != "routes.accept" {
		t.Errorf("gave up on %v, want [routes.accept]", conflict)
	}

	_, edits := h.node.prefsState()
	if corrections := edits - settled; corrections > prefsCorrectionLimit {
		t.Errorf("put the setting back %d times before giving up, want at most %d: a push per "+
			"change is a loop against the control plane", corrections, prefsCorrectionLimit)
	}

	// It stays given up on rather than resuming on the next reconcile.
	h.agent.reconcileNow(t.Context())
	h.agent.reconcileNow(t.Context())
	if _, after := h.node.prefsState(); after != edits {
		t.Errorf("kept writing after giving up: %d edits, was %d", after, edits)
	}

	view := prefsView(h)
	if len(view.Conflict) == 0 {
		t.Error("the mirror reports no conflict, so the user is never told why the setting is not on")
	}
	if !view.Capability.Degraded {
		t.Error("the mirror reports itself as working while a setting it cannot apply is outstanding")
	}
}

// Giving up is not permanent: writing the setting again is the user saying the
// disagreement was dealt with somewhere this app cannot see.
func TestWritingASettingAgainResumesApplyingItAfterAConflict(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.keepPrefs(tsnode.Prefs{RouteAll: false})

	acceptRoutes(h, true)
	waitFor(t, 5*time.Second, "app-tail to stop putting the setting back", func() bool {
		conflict, _ := h.agent.prefsReport(config.PrimaryTunnelID)
		return len(conflict) > 0
	})

	// Whatever was changing it back has stopped. Saving the setting again writes the
	// value already stored, which is exactly what a user resolving the conflict does.
	h.node.yieldPrefs()
	acceptRoutes(h, true)

	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the setting to be applied after being written again")
	if conflict, _ := h.agent.prefsReport(config.PrimaryTunnelID); len(conflict) != 0 {
		t.Errorf("still reporting a conflict over %v after the setting applied", conflict)
	}
}

// A node someone already enrolled arrives carrying preferences. Turning them off because
// this install has never heard of them would be changing a setting the user never touched
// here, by installing this app.
func TestAPreferenceTheNodeAlreadyHeldIsTakenOnFirstRun(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	h.node.publishPrefs(tsnode.Prefs{RouteAll: true})

	waitFor(t, 5*time.Second, "app-tail to take the node's existing preferences", func() bool {
		return prefsAdopted(t, h)
	})

	accept, module := storedRoutes(t, h)
	if !accept {
		t.Error("the node accepts subnet routes and the stored connection does not, so the app " +
			"turned off a setting the user never touched here")
	}
	if !module {
		t.Error("the taken setting's module is off, so the user cannot see or change what the " +
			"node is doing")
	}
	if got, _ := h.node.prefsState(); !got.RouteAll {
		t.Error("the node stopped accepting subnet routes, which is the change adoption exists to prevent")
	}
}

// Adoption happens once, at the start. Afterwards this document is the source of truth,
// so a change made on the node later is put back rather than taken -- taking it would
// silently turn a setting the user switched off here back on.
func TestAChangeMadeOnTheNodeLaterDoesNotRewriteTheSettingHere(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{RouteAll: true})
	waitFor(t, 5*time.Second, "the first run to take the node's preferences", func() bool {
		return prefsAdopted(t, h)
	})

	acceptRoutes(h, false)
	waitForNodePrefs(h, tsnode.Prefs{}, "the node to stop accepting subnet routes")

	// Something else turns it back on, long after the one-time adoption.
	h.node.publishPrefs(tsnode.Prefs{RouteAll: true})

	waitForNodePrefs(h, tsnode.Prefs{}, "the node to be put back")
	if accept, _ := storedRoutes(t, h); accept {
		t.Error("a change made on the node rewrote the setting stored here, switching back on " +
			"what the user switched off")
	}
}

// The mirror is what makes "stored here, applied there" visible. A view that reported
// only the stored value would look identical whether or not the tailnet ever heard of it.
func TestTheMirrorShowsTheNodesOwnValueBesideTheStoredOne(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	// Whatever this app writes, the node keeps holding the opposite, so the two values
	// stay visibly different.
	h.node.keepPrefs(tsnode.Prefs{RouteAll: false})

	acceptRoutes(h, true)

	view := prefsView(h)
	field := mirroredField(h, view, "routes.accept")
	if field.Label == "" {
		t.Errorf("the mirror reports %+v, want the label the form uses", field)
	}
	if field.Stored != true {
		t.Errorf("stored value = %v, want the setting as saved here", field.Stored)
	}
	if field.Live != false {
		t.Errorf("live value = %v, want what the node actually holds", field.Live)
	}
	if field.InForce {
		t.Error("the mirror calls the setting in force while the node holds the opposite")
	}
}

// A module that is off has no settings for the user to act on, so the mirror carries
// none: a card listing preferences nobody can change is worse than no card.
func TestTheMirrorIsEmptyWhileTheModuleOwningItsSettingsIsOff(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	view := prefsView(h)
	if len(view.Fields) != 0 {
		t.Errorf("the mirror reports %+v while the module owning them is off", view.Fields)
	}
	if view.Capability.Available {
		t.Error("the mirror reports itself as working while it holds nothing")
	}
	if view.Capability.Reason == "" {
		t.Error("the mirror is empty and says nothing about why")
	}
}

// Most pushes happen on their own, long after any save: a node coming back, or a value
// changed elsewhere. A failure there has no request to answer, so the mirror is the only
// place it can be seen -- logging it alone would leave a setting silently not in force.
func TestAPushThatFailsOnItsOwnIsReportedInTheMirror(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})
	acceptRoutes(h, true)
	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the setting to be applied")

	// The setting is changed somewhere else and the node stops accepting writes, so the
	// correction this app tries next has nobody to report to.
	h.node.failPrefsEdit(errors.New("the backend is not answering"))
	h.node.publishPrefs(tsnode.Prefs{RouteAll: false})

	waitFor(t, 5*time.Second, "the failure to reach the mirror", func() bool {
		_, failure := h.agent.prefsReport(config.PrimaryTunnelID)
		return failure != ""
	})

	view := prefsView(h)
	if !view.Capability.Degraded {
		t.Error("the mirror reports itself as working while a push it made is failing")
	}
	if !strings.Contains(view.Capability.Reason, "not answering") {
		t.Errorf("the reason reads %q, want the backend's own words", view.Capability.Reason)
	}

	// The next reconcile, whatever prompts it, tries again -- and a push that lands
	// clears the failure, so one that is over does not sit on screen forever.
	h.node.failPrefsEdit(nil)
	h.agent.reconcileNow(t.Context())

	waitForNodePrefs(h, tsnode.Prefs{RouteAll: true}, "the setting to be applied again")
	waitFor(t, 5*time.Second, "the stale failure to clear", func() bool {
		_, failure := h.agent.prefsReport(config.PrimaryTunnelID)
		return failure == ""
	})
}

// Adoption that cannot be written down must not be treated as done. Carrying on would
// push this app's untouched defaults over preferences it failed to take, turning off on
// the tailnet exactly what adoption exists to preserve -- and the flag would still be
// unset, so it would happen again on the next run with no record of why.
func TestAdoptionThatCannotBeStoredIsReportedRatherThanPassedOver(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bits this test depends on")
	}
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce the directory write bit the same way")
	}

	h := newHarness(t, nil)
	h.bringUp()

	// The store writes through a temp file in the same directory, so revoking write
	// permission on the directory is what a read-only state dir looks like.
	if err := os.Chmod(h.stateDir, 0o500); err != nil {
		t.Fatalf("make the state dir read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(h.stateDir, 0o700) })

	h.node.publishPrefs(tsnode.Prefs{RouteAll: true})

	waitFor(t, 5*time.Second, "the failure to reach the mirror", func() bool {
		_, failure := h.agent.prefsReport(config.PrimaryTunnelID)
		return failure != ""
	})
	_, failure := h.agent.prefsReport(config.PrimaryTunnelID)
	if !strings.Contains(failure, "existing preferences") {
		t.Errorf("the failure reads %q, want it to name the step that failed", failure)
	}

	if _, edits := h.node.prefsState(); edits != 0 {
		t.Errorf("wrote %d preferences to the node after failing to take its own, which is "+
			"how a setting the user never touched here gets turned off", edits)
	}
	if got, _ := h.node.prefsState(); !got.RouteAll {
		t.Error("the node stopped accepting subnet routes despite adoption never completing")
	}
}

// A patch the settings document itself rejects must be answered once, by the write that
// rejects it. The pre-flight sees the same bad patch first and has to stand aside, or the
// user gets a sentence about the tailnet node for a value that never got that far.
func TestAPatchTheSettingsRejectIsAnsweredByTheWriteNotThePreFlight(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patch := map[string]json.RawMessage{
		"routes.enabled": json.RawMessage(`true`),
		"routes.accept":  json.RawMessage(`"yes please"`),
	}
	_, _, err := h.agent.Settings().Update(t.Context(), patch)
	if err == nil {
		t.Fatal("a setting of the wrong type was accepted")
	}
	if strings.Contains(err.Error(), "tailnet node") {
		t.Errorf("the rejection reads %q, want the settings document's own reason rather "+
			"than one about the node, which never saw this value", err)
	}
	if _, edits := h.node.prefsState(); edits != 0 {
		t.Errorf("a rejected save still wrote %d preferences to the node", edits)
	}
}

// The mirror's capability line is the whole explanation a user gets for a setting that is
// stored and not in force. Each state has to produce its own sentence: one that fell
// through to "working" would report a stuck setting as fine.
func TestTheMirrorExplainsEveryReasonASettingIsNotInForce(t *testing.T) {
	inForce := httpapi.PrefFieldView{Key: "routes.accept", InForce: true}
	waiting := httpapi.PrefFieldView{Key: "routes.accept"}

	cases := []struct {
		name        string
		view        httpapi.PrefsView
		failure     string
		nodeProblem string
		available   bool
		degraded    bool
		wants       string
	}{{
		name:  "no settings are kept on the node at all",
		view:  httpapi.PrefsView{NodeUp: true, Known: true},
		wants: "No settings are kept on the tailnet node",
	}, {
		name:  "the node is down for a reason nobody reported",
		view:  httpapi.PrefsView{Fields: []httpapi.PrefFieldView{waiting}},
		wants: "The tailnet node is not running, so these settings are stored but not in force.",
	}, {
		name:        "the node is down and said why",
		view:        httpapi.PrefsView{Fields: []httpapi.PrefFieldView{waiting}},
		nodeProblem: "needs login",
		wants:       "not running (needs login)",
	}, {
		name: "something else keeps changing a setting back",
		view: httpapi.PrefsView{
			NodeUp: true, Known: true,
			Fields:   []httpapi.PrefFieldView{waiting},
			Conflict: []string{"routes.accept"},
		},
		available: true, degraded: true,
		wants: "routes.accept",
	}, {
		name:      "the last push failed",
		view:      httpapi.PrefsView{NodeUp: true, Known: true, Fields: []httpapi.PrefFieldView{inForce}},
		failure:   "apply settings to the tailnet node: refused",
		available: true, degraded: true,
		wants: "refused",
	}, {
		name:      "the node has not said what it holds yet",
		view:      httpapi.PrefsView{NodeUp: true, Fields: []httpapi.PrefFieldView{waiting}},
		available: true, degraded: true,
		wants: "has not reported its settings yet",
	}, {
		name:      "the node has not taken the setting yet",
		view:      httpapi.PrefsView{NodeUp: true, Known: true, Fields: []httpapi.PrefFieldView{waiting}},
		available: true, degraded: true,
		wants: "Waiting for the tailnet node",
	}, {
		name:      "everything is in force",
		view:      httpapi.PrefsView{NodeUp: true, Known: true, Fields: []httpapi.PrefFieldView{inForce}},
		available: true,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := prefsCapability(tc.view, tc.failure, tc.nodeProblem)
			if got.Available != tc.available || got.Degraded != tc.degraded {
				t.Errorf("available=%v degraded=%v, want available=%v degraded=%v",
					got.Available, got.Degraded, tc.available, tc.degraded)
			}
			if tc.wants == "" {
				if got.Reason != "" {
					t.Errorf("a working mirror explained itself anyway: %q", got.Reason)
				}
				return
			}
			if !strings.Contains(got.Reason, tc.wants) {
				t.Errorf("the reason reads %q, want it to say %q", got.Reason, tc.wants)
			}
		})
	}
}

// A node that is down makes every setting it holds stored-but-not-in-force. Saying so is
// the difference between "this is off" and "this is waiting".
func TestTheMirrorSaysTheseSettingsAreWaitingWhileTheNodeIsDown(t *testing.T) {
	h := newHarness(t, nil)
	patchSettings(h, map[string]any{"routes.enabled": true, "routes.accept": true})

	view := prefsView(h)
	if view.NodeUp {
		t.Fatal("the node reads as running before it has come up")
	}
	if field := mirroredField(h, view, "routes.accept"); field.InForce {
		t.Error("a setting is reported as in force while there is no node holding it")
	}
	if !strings.Contains(view.Capability.Reason, "not running") {
		t.Errorf("the reason reads %q, want it to say the node is not running", view.Capability.Reason)
	}
}

// "It will be applied when the node is running" is a promise, and a node that failed to
// start is not going to keep it on its own. Naming the failure in the same sentence is the
// difference between a user waiting and a user fixing what actually went wrong.
func TestASettingDeferredBehindAFailedNodeCarriesTheReasonItFailed(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	agent, err := New(Options{Store: store, Runtime: runtime, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	agent.recordNodeErr(errors.New("the auth key was rejected"))

	field, ok := prefField("routes.accept")
	if !ok {
		t.Fatal("routes.accept is not in the connection registry, so this covers nothing")
	}
	deferred, err := agent.pushPrefs(t.Context(),
		[]config.PrefChange{{TunnelID: config.PrimaryTunnelID, Field: field}})
	if err != nil {
		t.Fatalf("push a setting with no node: %v", err)
	}

	if len(deferred) != 1 {
		t.Fatalf("%d settings reported as waiting, want the one that was pushed: %+v", len(deferred), deferred)
	}
	if !strings.Contains(deferred[0].Reason, "the auth key was rejected") {
		t.Errorf("the reason reads %q, want it to carry why the node is not running", deferred[0].Reason)
	}
	if deferred[0].Label == "" {
		t.Error("the deferred setting carries no label, so a client can only show its wire key")
	}
}

// Adoption finishes by re-running the precedence chain, which is where the values taken
// from the node become the settings this process runs on. An environment that no longer
// resolves stops it there and has to be reported: the flag and the values are already
// written, so a caller told adoption succeeded would run on the settings it had before
// with nothing saying the node's own preferences never took effect.
func TestAdoptionThatCannotBeResolvedIntoRunningSettingsIsReported(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	resolved, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	broken := func(key string) string {
		if key == config.EnvEphemeral {
			return "maybe"
		}
		return ""
	}
	agent, err := New(Options{Store: store, Runtime: resolved, Getenv: broken, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = agent.adoptPrefsOnce(config.PrimaryTunnelID, tsnode.Prefs{RouteAll: true})

	if err == nil {
		t.Fatal("adoption reported success while the settings it produces could not be resolved")
	}
	if !strings.Contains(err.Error(), config.EnvEphemeral) {
		t.Errorf("err = %v, want it to name the variable that could not be read", err)
	}
	if got := agent.settings().UIListen; got == "" {
		t.Error("the process is running on zero-valued settings, so the failed step still replaced them")
	}
}

// storedRoutes is what the document holds for accepting subnet routes: the connection's own
// preference and the module governing it, which are stored in two different places now.
func storedRoutes(t *testing.T, h *harness) (accept, module bool) {
	t.Helper()
	return storedTailnet(t, h.store).RoutesAccept, h.store.Settings().RoutesEnabled
}

// prefsAdopted reports whether the primary connection has had its node's own preferences
// taken. The flag is per connection, because each one is a different node with different
// preferences to be asked about.
func prefsAdopted(t *testing.T, h *harness) bool {
	t.Helper()
	primary, ok := h.store.Get().Tunnel(config.PrimaryTunnelID)
	if !ok {
		t.Fatalf("the stored document carries no %q connection", config.PrimaryTunnelID)
	}
	return primary.PrefsAdopted
}

// prefField is one pref-backed connection field by its wire key.
func prefField(key string) (config.TunnelField, bool) {
	for _, f := range config.PrefsFields() {
		if f.JSONKey == key {
			return f, true
		}
	}
	return config.TunnelField{}, false
}
