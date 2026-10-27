// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/exitnode"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// noEngine is the context the settings-document tests hand to Update. They run over an
// agent that was constructed but never started, so no lifecycle goroutine exists to
// acknowledge a reconcile; an already-cancelled context takes Update's fall-back path
// at once instead of waiting out the reconcile timeout on every call.
var noEngine = func() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}()

// newSettingsAPI builds the settings document over a throwaway store. flags and env
// stand in for the precedence layers above the stored file.
func newSettingsAPI(t *testing.T, flags config.Flags, env config.Getenv) (settingsAPI, *config.Store) {
	t.Helper()
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if env == nil {
		env = emptyEnv
	}
	runtime, err := config.Resolve(flags, env, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Flags:   flags,
		Getenv:  env,
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return settingsAPI{a: agent}, store
}

func patchOf(t *testing.T, fields map[string]any) map[string]json.RawMessage {
	t.Helper()
	patch := make(map[string]json.RawMessage, len(fields))
	for k, v := range fields {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %s: %v", k, err)
		}
		patch[k] = raw
	}
	return patch
}

// The schema is what lets the dashboard render a settings form without hardcoding the
// field list, and it is the same registry the generated TypeScript comes from. Serving
// a subset would leave fields the API accepts that no client can discover.
func TestTheServedSchemaIsTheWholeFieldRegistry(t *testing.T) {
	api, _ := newSettingsAPI(t, config.Flags{}, nil)

	served := api.Schema()
	// All three tables, because a client built against the settings document names keys
	// that now live on the primary connection and on the default proxy instance, and it
	// discovers them here or nowhere.
	want := append(config.SettingsSchema(), config.LegacyTailnetSchema(&config.Settings{})...)
	want = append(want, config.LegacyProxySchema(&config.Settings{})...)

	if len(served) != len(want) {
		t.Fatalf("served %d fields, the registry has %d", len(served), len(want))
	}
	held := make(map[string]bool, len(served))
	for _, f := range served {
		held[f.Key] = true
	}
	for _, f := range want {
		if !held[f.Key] {
			t.Errorf("the schema does not serve %q, so no client can discover it", f.Key)
		}
	}
}

// Get reports what the process is running with, not what is on disk. A flag or
// environment variable that pins a value has to show through, or the dashboard would
// display a hostname the node is not actually using.
func TestGettingSettingsReportsTheEffectiveValuesRatherThanTheStoredOnes(t *testing.T) {
	pinned := "pinned-by-flag"
	api, store := newSettingsAPI(t, config.Flags{Hostname: &pinned}, nil)

	if _, err := store.Update(func(c *config.Config) error {
		tailnetOf(t, c).Hostname = "stored-name"
		return nil
	}); err != nil {
		t.Fatalf("seed the stored hostname: %v", err)
	}

	view := api.Get()

	if got := view["hostname"]; got != pinned {
		t.Errorf("hostname = %v, want the flag-pinned %q; the dashboard would show a "+
			"name the node is not using", got, pinned)
	}
	if stored := storedTailnet(t, store).Hostname; stored != "stored-name" {
		t.Errorf("the stored hostname was rewritten to %q", stored)
	}
}

// A write has to land in the file and be reflected back from the re-resolved runtime
// in one step, because the response is what the dashboard renders immediately after.
func TestUpdatingSettingsStoresThePatchAndReturnsTheResolvedResult(t *testing.T) {
	api, store := newSettingsAPI(t, config.Flags{}, nil)

	view, impact, err := api.Update(noEngine, patchOf(t, map[string]any{
		"hostname":             "new-name",
		"udpSessionTimeoutSec": 90,
	}))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if got := view["hostname"]; got != "new-name" {
		t.Errorf("returned hostname = %v, want %q", got, "new-name")
	}
	if stored := storedTailnet(t, store).Hostname; stored != "new-name" {
		t.Errorf("stored hostname = %q, want %q", stored, "new-name")
	}
	if stored := store.Settings().UDPSessionTimeoutSec; stored != 90 {
		t.Errorf("stored udpSessionTimeoutSec = %d, want 90", stored)
	}
	// The hostname is baked into the node at enrollment, so the user has to be told
	// the change is not live yet -- otherwise they wait for a rename that never comes.
	if !impact.NodeRestart {
		t.Error("a hostname change did not report that the node needs a restart")
	}
	if impact.UIRelisten {
		t.Error("a hostname change claimed the dashboard listener has to move")
	}
	// A setting the forwarding engine reads on every use is live immediately, so
	// claiming a restart would send the user through a needless reconnection.
	_, live, err := api.Update(noEngine, patchOf(t, map[string]any{"udpSessionTimeoutSec": 120}))
	if err != nil {
		t.Fatalf("second Update: %v", err)
	}
	if live.NodeRestart || live.UIRelisten {
		t.Errorf("a live setting reported restart impact %+v, want none", live)
	}
}

// Moving the dashboard's listener is the one change that costs the caller its own
// connection, so it is reported separately from a node restart.
func TestChangingTheDashboardAddressReportsARelistenRatherThanANodeRestart(t *testing.T) {
	api, _ := newSettingsAPI(t, config.Flags{}, nil)

	_, impact, err := api.Update(noEngine, patchOf(t, map[string]any{"uiListenAddr": "127.0.0.1:18412"}))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if !impact.UIRelisten {
		t.Error("moving the dashboard did not report that the listener has to move")
	}
	if impact.NodeRestart {
		t.Error("moving the dashboard claimed the tailnet node has to restart")
	}
}

// The tray icon is read once, when the process starts. The save is complete and correct,
// and nothing acts on it until the next start -- so it is neither live nor a node restart,
// and reporting it as either sends the user to the wrong recovery.
func TestChangingASettingReadAtStartReportsAnAppRestart(t *testing.T) {
	api, _ := newSettingsAPI(t, config.Flags{}, nil)

	_, impact, err := api.Update(noEngine, patchOf(t, map[string]any{"showTray": false}))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if !impact.AppRestart {
		t.Error("turning the tray icon off did not report that it waits for the next start")
	}
	if impact.NodeRestart || impact.UIRelisten {
		t.Errorf("a start-read setting reported %+v, want the app-restart flag alone", impact)
	}
	if !impact.RestartNeeded() {
		t.Error("a change that is not in force yet reported nothing outstanding")
	}
}

// Whether a save asks for administrator rights this process does not hold is the
// platform's answer, injected because reaching it reads the privilege boundary this package
// sits outside of. The answer is asked about the settings as saved, so the caller is told
// about the rights the new state needs rather than the old one; and a build with no answer
// -- every platform whose rights live in a helper -- reports no restart.
func TestASaveThatNeedsAdministratorRightsSaysSoAboutTheSettingsAsSaved(t *testing.T) {
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runtime, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	var asked []config.Settings
	agent, err := New(Options{
		Store:   store,
		Runtime: runtime,
		Getenv:  emptyEnv,
		Logger:  quietLogger(),
		NeedsAdminRestart: func(s config.Settings) bool {
			asked = append(asked, s)
			return s.SystemDNSEnabled
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	api := settingsAPI{a: agent}

	_, impact, err := api.Update(noEngine, patchOf(t, map[string]any{"systemDns.enabled": true}))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !impact.AdminRestart || !impact.RestartNeeded() {
		t.Errorf("impact = %+v, want a save that needs rights to report the restart that takes them", impact)
	}
	if len(asked) != 1 || !asked[0].SystemDNSEnabled {
		t.Errorf("the platform was asked about %+v, want the settings as saved, once", asked)
	}

	_, impact, err = api.Update(noEngine, patchOf(t, map[string]any{"systemDns.enabled": false}))
	if err != nil {
		t.Fatalf("second Update: %v", err)
	}
	if impact.AdminRestart {
		t.Error("a save that lets go of the rights still asks for a restart to take them")
	}

	// No answer is no restart: nothing here may guess at the privilege boundary.
	unanswered, _ := newSettingsAPI(t, config.Flags{}, nil)
	_, impact, err = unanswered.Update(noEngine, patchOf(t, map[string]any{"systemDns.enabled": true}))
	if err != nil {
		t.Fatalf("Update without an answer: %v", err)
	}
	if impact.AdminRestart {
		t.Error("a build with no platform answer reported that administrator rights are needed")
	}
}

// A value pinned above the file still gets stored -- removing the flag later has to
// reveal the user's choice -- but it must not appear to take effect now. Reporting the
// pinned value as changed would have the user believe a restart is pending when the
// setting will simply revert.
func TestUpdatingAFlagPinnedSettingStoresItWithoutChangingWhatIsRunning(t *testing.T) {
	pinned := "pinned-by-flag"
	api, store := newSettingsAPI(t, config.Flags{Hostname: &pinned}, nil)

	view, impact, err := api.Update(noEngine, patchOf(t, map[string]any{"hostname": "from-the-dashboard"}))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if stored := storedTailnet(t, store).Hostname; stored != "from-the-dashboard" {
		t.Errorf("stored hostname = %q, want the user's choice to be kept for later", stored)
	}
	if got := view["hostname"]; got != pinned {
		t.Errorf("effective hostname = %v, want it still pinned to %q", got, pinned)
	}
	if impact.NodeRestart {
		t.Error("a pinned setting reported a pending node restart that would never take effect")
	}
}

// A rejected patch must leave the stored document exactly as it was. A partial apply
// would store half a change the user never sees reported and cannot undo from the form.
func TestARejectedSettingsPatchChangesNothing(t *testing.T) {
	tests := []struct {
		name        string
		patch       map[string]any
		wantMessage string
	}{
		{"an unknown key", map[string]any{"hsotname": "typo"}, "hsotname"},
		{"a read-only key", map[string]any{"stateDir": "/tmp/elsewhere"}, "stateDir"},
		{"a value of the wrong type", map[string]any{"udpSessionTimeoutSec": "ninety"}, "udpSessionTimeoutSec"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, store := newSettingsAPI(t, config.Flags{}, nil)
			if _, err := store.Update(func(c *config.Config) error {
				tailnetOf(t, c).Hostname = "before"
				return nil
			}); err != nil {
				t.Fatalf("seed: %v", err)
			}

			_, _, err := api.Update(noEngine, patchOf(t, tt.patch))

			if err == nil {
				t.Fatal("the patch was accepted")
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("err = %v, want it to name %q so the form can highlight the field",
					err, tt.wantMessage)
			}
			if got := storedTailnet(t, store).Hostname; got != "before" {
				t.Errorf("stored hostname = %q after a rejected patch, want %q", got, "before")
			}
		})
	}
}

// A patch that is valid on its own but leaves the document invalid has to be refused
// by the store rather than written and discovered at the next start.
func TestAPatchThatWouldStoreAnInvalidDocumentIsRefused(t *testing.T) {
	api, store := newSettingsAPI(t, config.Flags{}, nil)

	_, _, err := api.Update(noEngine, patchOf(t, map[string]any{"uiListenAddr": "not-an-address"}))

	if err == nil {
		t.Fatal("an unusable dashboard address was accepted")
	}
	if got := store.Settings().UIListen; got == "not-an-address" {
		t.Error("the invalid address was stored anyway; the agent would fail to bind at next start")
	}
}

// The engine reads live settings on every use, so a write has to wake the lifecycle
// goroutine. Without the poke a buffer-size or timeout change sits unused until the
// next unrelated event.
func TestUpdatingSettingsAsksTheEngineToCatchUp(t *testing.T) {
	api, _ := newSettingsAPI(t, config.Flags{}, nil)

	// Drain anything already queued so the assertion is about this write.
	select {
	case <-api.a.reconcile:
	default:
	}

	if _, _, err := api.Update(noEngine, patchOf(t, map[string]any{"udpSessionTimeoutSec": 45})); err != nil {
		t.Fatalf("Update: %v", err)
	}

	select {
	case <-api.a.reconcile:
	default:
		t.Error("no reconcile was queued, so a live setting change would not reach the engine")
	}
}

// A setting whose choices come from the tailnet is only renderable if something fills
// them. Declaring a source nothing supplies serves a picker with nothing in it, which a
// user reads as the setting being broken; filling a source no setting declares is a list
// that reaches nobody. Neither produces an error anywhere, so the correspondence is
// asserted in both directions rather than trusted.
func TestEverySettingWhoseChoicesComeFromTheTailnetHasSomethingThatFillsThem(t *testing.T) {
	// Both registries, because a field that takes its choices from the tailnet may be stored
	// on a connection now: sweeping only the settings document would stop checking exactly
	// the fields that moved, and an unfilled picker is invisible until somebody opens it.
	declared := make(map[string]bool)
	schema := append(config.SettingsSchema(), config.TunnelSchemaStatic()...)
	for _, f := range schema {
		if f.OptionsFrom == "" {
			continue
		}
		declared[f.OptionsFrom] = true
		if optionSources[f.OptionsFrom] == nil {
			t.Errorf("setting %q takes its choices from %q and nothing here supplies that list, "+
				"so it would render as a picker with nothing selectable", f.Key, f.OptionsFrom)
		}
	}
	for source := range optionSources {
		if !declared[source] {
			t.Errorf("%q is filled here but no setting takes its choices from it, so the list "+
				"reaches no one", source)
		}
	}
}

// The choices are served with the schema on purpose: a client that had to fetch them
// separately would need a control of its own for every setting of this shape, which is
// what a schema-driven form exists to avoid.
func TestASettingsChoicesArriveWithTheSchemaThatDeclaresThem(t *testing.T) {
	api, _ := newSettingsAPI(t, config.Flags{}, nil)
	api.a.exitNode.publish(exitnode.State{}, []exitnode.Candidate{
		{ID: "nA", Label: "gateway", Online: true},
	}, "", 0)

	var found bool
	for _, f := range api.Schema() {
		if f.OptionsFrom != config.OptionsExitNodes {
			continue
		}
		found = true
		if len(f.Options) != 1 || f.Options[0].Value != "nA" {
			t.Errorf("setting %q was served %+v, want the devices the tailnet offers", f.Key, f.Options)
		}
	}
	if !found {
		t.Fatal("no setting takes its choices from the exit nodes, so this covers nothing")
	}
}

// newRightsAgent is an agent on a platform whose administrator rights arrive by starting
// again, the way Windows grants them, with the machine reading as report and every request
// for the helper-style arrangement counted.
func newRightsAgent(t *testing.T, byRestart bool, report tsnode.InterfaceReport) (*Agent, *int) {
	t.Helper()
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve settings: %v", err)
	}
	provisions := new(int)
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		RightsByRestart: func() bool { return byRestart },
		InspectInterface: func(context.Context, func(string, ...any)) tsnode.InterfaceReport {
			return report
		},
		Provision: func(context.Context, func(string, ...any), tsnode.Rights, bool, string) error {
			*provisions++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return agent, provisions
}

// windowsReport is a Windows machine with nothing in the way of either feature.
func windowsReport() tsnode.InterfaceReport {
	return tsnode.InterfaceReport{Platform: "windows", Supported: true}
}

var resolverOn = map[string]any{"systemDns.enabled": true, "systemDns.profile": "google"}

// Turning the resolver on is the moment somebody asks for the rights, and on Windows the only
// thing that puts the prompt on screen is a fresh start. A save that stores the setting and
// waits for somebody to find a restart button is the resolver silently never taking effect.
func TestTurningOnAFeatureWhoseRightsArriveWithARestartRestartsTheProcess(t *testing.T) {
	agent, provisions := newRightsAgent(t, true, windowsReport())

	_, impact, err := settingsAPI{a: agent}.Update(noEngine, patchOf(t, resolverOn))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !impact.AdminRelaunch {
		t.Errorf("impact = %+v, want the caller told the process is restarting for the rights", impact)
	}
	if !agent.RelaunchRequested() {
		t.Error("the save did not restart the process, so nothing ever asks for the rights")
	}
	if *provisions != 0 {
		t.Errorf("the helper arrangement ran %d times on a platform that has no helper", *provisions)
	}
}

// A restart that the start-up would not prompt in drops every connection for nothing, so
// something the rights cannot lift keeps this process running and says why.
func TestARestartForRightsIsNotMadeWhenSomethingElseIsInTheWay(t *testing.T) {
	report := windowsReport()
	report.ResolverBusy = "every address app-tail would listen for DNS on is already in use"
	agent, provisions := newRightsAgent(t, true, report)

	_, impact, err := settingsAPI{a: agent}.Update(noEngine, patchOf(t, resolverOn))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if impact.AdminRelaunch || agent.RelaunchRequested() {
		t.Errorf("impact = %+v, relaunch = %v, want no restart past a busy port 53",
			impact, agent.RelaunchRequested())
	}
	if *provisions != 0 {
		t.Errorf("the helper arrangement ran %d times", *provisions)
	}
}

// Only the transition asks. A save while the feature is already on -- after a declined
// prompt, say -- must not restart into a prompt somebody just refused.
func TestASaveThatDoesNotTurnTheFeatureOnDoesNotRestart(t *testing.T) {
	agent, _ := newRightsAgent(t, true, windowsReport())
	api := settingsAPI{a: agent}
	if _, _, err := api.Update(noEngine, patchOf(t, map[string]any{"systemDns.enabled": true})); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if agent.RelaunchRequested() {
		t.Error("switching on the System default profile, which changes nothing, restarted the process")
	}
}

// Where a helper holds the rights, the arrangement is the helper's and nothing restarts.
func TestAFeatureWhoseRightsLiveInAHelperIsArrangedInPlace(t *testing.T) {
	agent, provisions := newRightsAgent(t, false, windowsReport())

	_, impact, err := settingsAPI{a: agent}.Update(noEngine, patchOf(t, resolverOn))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if impact.AdminRelaunch || agent.RelaunchRequested() {
		t.Error("a platform with a helper restarted the process to obtain rights")
	}
	if *provisions != 1 {
		t.Errorf("the helper arrangement ran %d times, want once", *provisions)
	}
}

// The setup requests cannot raise the prompt themselves where it comes with a restart, so
// they say so with an answer a caller can recognise rather than a helper's install error.
func TestTheSetupRequestsNameARestartWhereThatIsHowRightsArrive(t *testing.T) {
	agent, provisions := newRightsAgent(t, true, windowsReport())

	if err := agent.DNSAPI().SetUpSystem(context.Background()); !errors.Is(err, ErrRightsAtRestart) {
		t.Errorf("SetUpSystem = %v, want ErrRightsAtRestart", err)
	}
	if err := agent.InterfaceSetup().SetUpInterface(context.Background()); !errors.Is(err, ErrRightsAtRestart) {
		t.Errorf("SetUpInterface = %v, want ErrRightsAtRestart", err)
	}
	if *provisions != 0 {
		t.Errorf("the helper arrangement ran %d times", *provisions)
	}
}
