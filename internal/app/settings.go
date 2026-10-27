// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// settingsAPI presents the agent as the management API's settings document.
type settingsAPI struct{ a *Agent }

var _ httpapi.SettingsAPI = settingsAPI{}

// Settings exposes the agent as the management API's settings document.
func (a *Agent) Settings() httpapi.SettingsAPI { return settingsAPI{a: a} }

// Get returns the settings this process is actually running with, which is the
// stored document after flags and environment overrides are applied.
func (sa settingsAPI) Get() map[string]any {
	return config.SettingsViewOf(sa.a.runtimeDocument())
}

// Schema returns the settings field registry with each field's availability resolved
// against the settings this process is running with, so a consumer renders exactly the
// settings that can be written right now rather than the whole catalog.
//
// It also fills the choices for the settings whose options are facts about the tailnet
// rather than a fixed set. Serving them here is what keeps a schema-driven form
// schema-driven: without it the form would need a fetch and a control of its own for
// every setting of that shape.
func (sa settingsAPI) Schema() []config.FieldSchema {
	app := sa.a.settings()
	// The keys that moved onto the primary connection and onto the default proxy instance
	// are served here too, so a client built against the settings document still finds every
	// field it knows by name -- and finds it described by the field that now stores it.
	schema := config.SettingsSchemaFor(app)
	schema = append(schema, config.LegacyTailnetSchema(&app)...)
	schema = append(schema, config.LegacyProxySchema(&app)...)
	return sa.a.fillOptions(schema)
}

// fillOptions supplies the choices for every field whose options are facts about the
// tailnet rather than a fixed set. Every schema this agent serves goes through it, whichever
// registry the field came from: a field that moved between them would otherwise reach a
// client as a picker with nothing in it, which reads as the setting being broken.
func (a *Agent) fillOptions(schema []config.FieldSchema) []config.FieldSchema {
	for i := range schema {
		if fill := optionSources[schema[i].OptionsFrom]; fill != nil {
			schema[i].Options = fill(a)
		}
	}
	return schema
}

// optionSources fills the settings whose choices are facts about the tailnet rather than
// a fixed set, keyed by the source name the registry field declares.
//
// A guard test asserts this table and the registry name exactly each other's sources, so
// a field declaring a source nothing fills -- which would render an empty picker and read
// as the setting being broken -- cannot reach a consumer.
var optionSources = map[string]func(*Agent) []config.EnumOption{
	config.OptionsExitNodes:    (*Agent).exitNodeChoices,
	config.OptionsDNSProfiles:  (*Agent).dnsProfileChoices,
	config.OptionsDNSBootstrap: (*Agent).dnsBootstrapChoices,
	config.OptionsTunnels:      (*Agent).tunnelChoices,
}

// Update writes the patch to the stored config and re-resolves the effective
// settings. Precedence therefore stays in exactly one implementation: a value
// pinned by a flag or environment variable visibly does not move, rather than
// appearing to change and then reverting on restart.
func (sa settingsAPI) Update(ctx context.Context, patch map[string]json.RawMessage) (map[string]any, httpapi.SettingsUpdateResult, error) {
	a := sa.a
	before := a.settings()
	// The connections are snapshotted alongside, because some of the keys a settings patch
	// may carry name a field of the primary connection now. Comparing only the settings
	// would report a renamed device as needing nothing, and the node would keep running
	// under the name it had.
	beforeTunnels := a.runtimeTunnels()

	// Settings the tailnet node holds are checked with the node before anything is
	// written, so a refusal arrives as the backend's own sentence on the control the
	// user just changed -- not as a failed push minutes later with a stored setting
	// the node never accepted.
	// Before the prefs check because it is the cheaper refusal and needs nothing from the
	// tailnet: the registry cannot see the resolver catalog, so "is that a profile" is the
	// one thing about this patch it cannot answer for itself.
	if err := a.checkDNSProfilePatch(patch); err != nil {
		return nil, httpapi.SettingsUpdateResult{}, err
	}
	if err := a.checkPrefsPatch(ctx, patch); err != nil {
		return nil, httpapi.SettingsUpdateResult{}, err
	}

	// The credential keys in a settings patch are the primary connection's, redirected.
	if _, _, err := a.store.UpdateReporting(func(c *config.Config) error {
		return config.ApplyPatchTo(c, patch)
	}, config.CredentialWritesIn(config.PrimaryTunnelID, patch)...); err != nil {
		return nil, httpapi.SettingsUpdateResult{}, err
	}

	after, err := a.adoptSettings()
	if err != nil {
		return nil, httpapi.SettingsUpdateResult{}, err
	}

	// After adoptSettings, which is what put the new switch state in force: a save that
	// turns recording on is itself worth recording, and one that turns it off must not
	// be, since by then the log is meant to be empty.
	afterTunnels := a.runtimeTunnels()
	a.recordSettingsChange(before, after)
	a.recordTunnelsChange(beforeTunnels, afterTunnels)

	impact := config.ApplyImpact(before, after)
	tunnelImpact := config.TunnelsImpact(beforeTunnels, afterTunnels)
	result := httpapi.SettingsUpdateResult{
		NodeRestart:  impact.NodeRestart || tunnelImpact.NodeRestart,
		UIRelisten:   impact.UIRelisten || tunnelImpact.UIRelisten,
		AppRestart:   impact.AppRestart || tunnelImpact.AppRestart,
		AdminRestart: a.wantsAdminRestart(after),
	}
	// Writing a setting the node holds is the signal that a disagreement this app gave
	// up on was dealt with elsewhere, so it is worth trying again. It keys off the
	// settings the patch names rather than the ones whose value moved: a user resolving
	// a conflict is saving the value they already asked for, which changes nothing here.
	// The primary connection, because that is where the settings document's pref-backed
	// keys write: they named the single tailnet this app used to have, and the redirect
	// keeps them pointing at the connection that inherited it.
	a.clearPrefsConflict(config.PrimaryTunnelID, prefKeysIn(patch))
	if len(tunnelImpact.Prefs) > 0 {
		deferred, err := a.pushPrefs(ctx, tunnelImpact.Prefs)
		if err != nil {
			return nil, httpapi.SettingsUpdateResult{}, err
		}
		result.Deferred = deferred
	}

	// Done before the reconcile below, so the node that reconcile builds is the one that
	// can use what was just installed rather than one that falls back and needs a second
	// restart to pick it up.
	relaunch := a.provisionRights(ctx, before, after)
	result.AdminRelaunch = relaunch

	// Live settings the forwarding engine reads on every use take effect at once;
	// anything baked into the node or the listener does not. Waiting for the engine
	// here is what makes the returned view describe the running state rather than the
	// state a reconcile was about to reach.
	a.reconcileNow(ctx)

	// Not waited on, unlike the reconcile above: a download is seconds of network, and the
	// answer to a settings write is the settings rather than the lists. What it buys is that a
	// patch switching blocking on starts the download now instead of within the tick.
	a.pokeBlocklists()
	a.pokeIPSFeeds()

	view := config.SettingsViewOf(a.runtimeDocument())
	// Last, once the write and the reconcile are done: the restart unwinds this process, and
	// the caller is still owed the answer, which the ordered shutdown lets it finish sending.
	if relaunch {
		if err := a.RestartProcess(); err != nil {
			return nil, httpapi.SettingsUpdateResult{}, fmt.Errorf("restart app-tail to ask for administrator rights: %w", err)
		}
	}
	return view, result, nil
}

// mayElevate reports whether this process may ask for administrator rights. --no-elevate is
// a standing answer to that question, and a dialog raised in spite of it is worse than the
// feature not existing: it is the app doing the thing the user disabled.
func (a *Agent) mayElevate() bool {
	return a.flags.NoElevate == nil || !*a.flags.NoElevate
}

// interfaceSetupAPI presents the agent as the management API's network-interface setup.
type interfaceSetupAPI struct{ a *Agent }

var _ httpapi.InterfaceSetup = interfaceSetupAPI{}

// InterfaceSetup exposes the agent as the management API's network-interface setup.
func (a *Agent) InterfaceSetup() httpapi.InterfaceSetup { return interfaceSetupAPI{a: a} }

// interfaceSetupTimeout bounds the wait for the password prompt, and is deliberately
// under the API's own write timeout: a dialog left sitting would otherwise run past it and
// the caller would get a reset connection instead of a sentence about what happened. The
// terminal command is not bounded this way, because a person at a prompt is not a stalled
// request.
const interfaceSetupTimeout = 90 * time.Second

// SetUpInterface makes this machine able to carry the interface mode.
//
// The failure is returned rather than recorded the way the settings path records it: this
// is a request whose whole purpose was the arrangement, so a caller that asked for it is
// owed the reason directly instead of having to go and read the node's status.
func (sa interfaceSetupAPI) SetUpInterface(ctx context.Context) error {
	a := sa.a
	ctx, cancel := context.WithTimeout(ctx, interfaceSetupTimeout)
	defer cancel()
	if a.rightsAtRestart() {
		return ErrRightsAtRestart
	}
	// Recorded but not consulted: this request is somebody asking for the dialog, so it
	// always gets one. What the record stops is the node rebuild that follows raising a
	// second dialog for the question this one just answered.
	a.noteRightsRequested()
	if err := a.provision(ctx, a.hostLogf, tsnode.RightsInterface, a.mayElevate(), a.store.Path()); err != nil {
		a.logger.Warn("could not set this machine up for the network-interface mode", "error", err)
		a.setNetworkFallback(err.Error())
		return err
	}
	// Cleared, because the card is about to be reloaded and the reason a mode was
	// unavailable must not outlive the machine state that produced it: a helper installed
	// after a refusal would otherwise leave the node still reporting it as missing.
	a.setNetworkFallback("")
	a.logger.Info("this machine is set up for the network-interface mode")
	return nil
}

// provisionRights gets this machine ready for whichever machine-level feature this write
// turned on: the network-interface mode, the machine-wide resolver, or both.
//
// Only on the transition, and only from a write: obtaining the rights raises a system
// authorization dialog, and the moment somebody asks for the feature is the one moment a
// dialog is expected rather than mysterious. Doing it on every save would prompt again for
// a mode that is already on, and doing it on start would prompt at every login.
//
// Both features turned on in one write prompt once. The rights are the same rights -- one
// helper, installed once -- so the second request would be a dialog for a question the
// first one already answered.
//
// A failure is not a failed settings write -- the setting was stored, and it is the feature
// that could not be arranged -- so it is recorded where an unavailable feature is already
// reported: the node's own fallback reason for the interface, and the resolver card's own
// reason for the resolver, which the reconcile below this fills in.
//
// It reports whether the rights are to be obtained by restarting this process, which is how
// Windows grants them: the prompt is raised by the start-up elevation and by nothing a
// running process can do. The caller performs the restart once its write is answered.
func (a *Agent) provisionRights(ctx context.Context, before, after config.Settings) bool {
	wantInterface := !before.InterfaceSelected() && after.InterfaceSelected()
	wantResolver := !dnsprofiles.OverrideWanted(before) && dnsprofiles.OverrideWanted(after)
	if !wantInterface && !wantResolver {
		return false
	}
	want := tsnode.RightsInterface
	if !wantInterface {
		want = tsnode.RightsResolver
	}
	if a.rightsAtRestart() {
		return a.restartWouldGrant(ctx, want)
	}
	// Bounded like the setup request's own, and for the same reason: this runs inside a
	// settings write, which is answered over HTTP, and a dialog left sitting would outlast
	// the server's write timeout and hand the caller a reset connection instead of a
	// sentence about what happened.
	ctx, cancel := context.WithTimeout(ctx, interfaceSetupTimeout)
	defer cancel()
	// Recorded for the reason SetUpInterface records it: turning the mode on is a request
	// for the dialog, and the reconcile this write ends with rebuilds the node.
	a.noteRightsRequested()
	if err := a.provision(ctx, a.hostLogf, want, a.mayElevate(), a.store.Path()); err != nil {
		a.logger.Warn("could not set this machine up", "want", want.String(), "error", err)
		if wantInterface {
			a.setNetworkFallback(err.Error())
		}
		return false
	}
	if wantInterface {
		a.setNetworkFallback("")
	}
	a.logger.Info("this machine is set up", "for", want.String())
	return false
}

// ErrRightsAtRestart reports that this process cannot be given administrator rights while it
// runs, and obtains them by restarting under the system's prompt instead. A caller about to
// store the setting that wants them carries on: that save is what performs the restart.
var ErrRightsAtRestart = errors.New("app-tail is given administrator rights on Windows only as it starts. " +
	"Turning the feature on restarts app-tail so Windows can ask for them; if it is already on, " +
	"restart app-tail to be asked again")

// rightsAtRestart reports whether this process obtains administrator rights by starting again.
func (a *Agent) rightsAtRestart() bool {
	return a.rightsByRestart != nil && a.rightsByRestart()
}

// restartWouldGrant reports whether restarting would put the prompt on screen for want.
//
// The start-up elevation declines to prompt when something the rights cannot lift is in the
// way -- a busy port 53, a second tailnet client, a missing wintun.dll -- so restarting into
// that would drop every connection for a prompt that never appears. The reason is recorded
// where the feature's card reads it instead.
func (a *Agent) restartWouldGrant(ctx context.Context, want tsnode.Rights) bool {
	report := a.inspect(ctx, a.hostLogf)
	blocker := report.ResolverBlockerDespiteRights()
	if want == tsnode.RightsInterface {
		blocker = report.BlockerDespiteRights()
	}
	if blocker != "" {
		a.logger.Warn("not restarting to ask for administrator rights", "want", want.String(), "reason", blocker)
		if want == tsnode.RightsInterface {
			a.setNetworkFallback(blocker)
		}
		return false
	}
	a.logger.Info("restarting app-tail so Windows can ask for administrator rights", "for", want.String())
	return true
}

// checkPrefsPatch asks each connection's node whether the preferences this patch implies
// would be accepted, without writing anything. A node that is down cannot answer, which is
// not a refusal: the settings are stored and pushed when it comes up.
//
// It is asked per connection because a preference belongs to one node. Asking a single
// node about every changed preference would put one connection's value to another
// connection's tailnet, where it may be refused for reasons that have nothing to do with
// the network it was meant for.
func (a *Agent) checkPrefsPatch(ctx context.Context, patch map[string]json.RawMessage) error {
	candidate, ok := a.candidateRuntime(patch)
	if !ok {
		return nil
	}
	impact := config.TunnelsImpact(a.runtimeTunnels(), candidate.Tunnels)
	if len(impact.Prefs) == 0 {
		return nil
	}

	for _, id := range prefConnections(impact.Prefs) {
		node := a.nodeFor(id)
		if node == nil || !node.Status().Running() {
			continue
		}
		want, held := candidatePrefs(candidate, id)
		if !held {
			// The patch removed the connection these preferences belong to, so there is
			// nothing to ask about and the write itself is what settles it.
			continue
		}
		keys := fieldKeys(prefFieldsFor(impact.Prefs, id))

		checkCtx, cancel := context.WithTimeout(ctx, prefsPushTimeout)
		err := node.CheckPrefs(checkCtx, tsnode.PrefsForFields(want, keys))
		cancel()
		switch {
		case err == nil, errors.Is(err, tsnode.ErrNotRunning):
			// The node stopped between the check above and here, which the deferred
			// reporting on the way out already covers.
			continue
		default:
			return &config.ValidationError{
				Field:   keys[0],
				Message: "the tailnet node will not accept this: " + err.Error(),
			}
		}
	}
	return nil
}

// candidateRuntime is the effective document this patch would produce, without storing it,
// and whether there is one at all. It goes through the same precedence chain as a real
// write, so a value pinned by a flag or an environment variable is pinned in the candidate
// too and no node is ever asked about a value that would not survive the write.
//
// A patch that does not apply has no candidate rather than an error to report: the real
// write applies the same patch and refuses it with the field attribution this pre-flight
// cannot improve on.
func (a *Agent) candidateRuntime(patch map[string]json.RawMessage) (config.Runtime, bool) {
	stored := a.store.Get()
	if err := config.ApplyPatchTo(stored, patch); err != nil {
		return config.Runtime{}, false
	}
	rt, err := a.resolveWith(stored)
	if err != nil {
		return config.Runtime{}, false
	}
	return rt, true
}

// candidatePrefs is what one connection would ask its node for under a candidate document,
// with every module governing those preferences already folded in.
func candidatePrefs(rt config.Runtime, id string) (config.TailnetPrefs, bool) {
	for _, t := range rt.Tunnels {
		if t.ID == id {
			return rt.Settings.TailnetPrefsOf(t), true
		}
	}
	return config.TailnetPrefs{}, false
}

// pushPrefs hands each changed preference to the node of the connection that holds it, and
// reports the ones that could not be handed over. A node that is down is not an error: the
// setting is stored, and the reconcile that follows that connection coming up applies it.
//
// What is pushed comes from the mirror rather than from the stored value, so this path and
// the reconcile cannot disagree about a preference the exit-node schedule is choosing.
func (a *Agent) pushPrefs(ctx context.Context, changes []config.PrefChange) ([]httpapi.DeferredField, error) {
	var deferred []httpapi.DeferredField
	for _, id := range prefConnections(changes) {
		fields := prefFieldsFor(changes, id)
		if node := a.nodeFor(id); node != nil && node.Status().Running() {
			pushCtx, cancel := context.WithTimeout(ctx, prefsPushTimeout)
			_, err := node.EditPrefs(pushCtx, tsnode.PrefsForFields(a.mirroredPrefs(id), fieldKeys(fields)))
			cancel()
			if err == nil {
				a.notePrefsPushed(id)
				continue
			}
			if !errors.Is(err, tsnode.ErrNotRunning) {
				return nil, fmt.Errorf("apply this setting to the tailnet node: %w", err)
			}
		}

		reason := "stored; it will be applied when the tailnet node is running"
		if problem := a.connectionProblem(id); problem != "" {
			reason = "stored; the tailnet node is not running (" + problem +
				"), so it will be applied when it starts"
		}
		for _, f := range fields {
			deferred = append(deferred, httpapi.DeferredField{Key: f.JSONKey, Label: f.Label, Reason: reason})
		}
	}
	return deferred, nil
}

// prefKeysIn is the pref-backed settings a patch names, whether or not the value it
// carries differs from the one already stored.
func prefKeysIn(patch map[string]json.RawMessage) []string {
	var keys []string
	for _, f := range config.PrefsFields() {
		if _, ok := patch[f.JSONKey]; ok {
			keys = append(keys, f.JSONKey)
		}
	}
	return keys
}

// prefConnections is the connections a set of preference changes names, first-seen order.
// Visiting each node once, in the order the changes were reported, is what keeps a push
// over several connections from asking the same node twice and from reporting the deferred
// settings in an order that moves between runs.
func prefConnections(changes []config.PrefChange) []string {
	var ids []string
	for _, c := range changes {
		if !slices.Contains(ids, c.TunnelID) {
			ids = append(ids, c.TunnelID)
		}
	}
	return ids
}

// prefFieldsFor is the changed preferences belonging to one connection.
func prefFieldsFor(changes []config.PrefChange, id string) []config.TunnelField {
	var fields []config.TunnelField
	for _, c := range changes {
		if c.TunnelID == id {
			fields = append(fields, c.Field)
		}
	}
	return fields
}

// fieldKeys is the wire keys of a set of registry fields, which is the form every
// projection onto node preferences is addressed by.
func fieldKeys(fields []config.TunnelField) []string {
	keys := make([]string, 0, len(fields))
	for _, f := range fields {
		keys = append(keys, f.JSONKey)
	}
	return keys
}

// adoptSettings re-runs the precedence chain over the stored document and publishes the
// result as what this process runs on. Every path that changes the document goes through
// here, so precedence is applied in exactly one place and a value pinned by a flag or an
// environment variable cannot be overwritten by a write that bypassed it.
//
// The connections are republished with the settings, in the same lock: a write that
// renamed a device changes a connection and not a setting, and leaving the previous list
// in place would have the node keep running under the identity it had before.
func (a *Agent) adoptSettings() (config.Settings, error) {
	resolved, err := a.resolveSettings()
	if err != nil {
		return config.Settings{}, err
	}
	after := resolved.Settings
	a.mu.Lock()
	a.runtime.Settings = after
	a.runtime.Tunnels = resolved.Tunnels
	a.mu.Unlock()
	// Here rather than in the one API handler that writes settings: this is where the
	// process starts running on a new document, whichever path got it here, so the log's
	// own switch cannot be left describing the previous one.
	a.telemetry.SetConfig(telemetryConfig(after))
	return after, nil
}

// resolveSettings re-runs the precedence chain over the newly stored document.
func (a *Agent) resolveSettings() (config.Runtime, error) { return a.resolveWith(a.store.Get()) }

// resolveWith runs the precedence chain over a document that is not necessarily the
// stored one, which is what lets a write be checked against the node before it is stored.
func (a *Agent) resolveWith(stored *config.Config) (config.Runtime, error) {
	a.mu.RLock()
	stateDir, configPath := a.runtime.StateDir, a.runtime.ConfigPath
	a.mu.RUnlock()

	return config.Resolve(a.flags, a.getenv, stored, stateDir, configPath)
}

// wantsAdminRestart reports whether the settings just saved ask for something this
// process has no rights to do, on a platform that obtains those rights by starting again.
//
// The answer is injected rather than worked out here: reaching it means reading
// internal/hostnet, which is the privilege boundary this package is deliberately outside
// of. Nil answers no, which is correct for every platform whose rights live in a helper.
func (a *Agent) wantsAdminRestart(s config.Settings) bool {
	if a.needsAdminRestart == nil {
		return false
	}
	return a.needsAdminRestart(s)
}
