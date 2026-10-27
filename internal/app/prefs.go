// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// Some settings are not this process's to apply: they are preferences of a tailnet node,
// so they reach that tailnet rather than only this machine. The stored document is still
// the source of truth -- a setting has to have an answer while the node is down -- and
// this file is the mirror that keeps each node matching what its connection asks for.
//
// It is per-connection throughout. Every connection is its own node holding its own
// preferences, so the drift, the corrections and the record of what was already adopted
// are all keyed by connection id: one shared set would have a second tailnet judged
// against the first one's answers.
//
// The mirror is not a background nicety. tsnet applies none of these preferences from
// the parameters a node is built with, so the push after a node comes up is the only
// path any of them ever take.

// prefsPushTimeout bounds one push. It is generous because the write goes through the
// backend's own validation and netmap reconfiguration, and short enough that a wedged
// backend cannot hold the reconcile goroutine.
const prefsPushTimeout = 10 * time.Second

// prefsCorrectionLimit is how many times in a row this app will put one preference back
// before it stops and reports a conflict instead.
//
// Something else changing a preference back -- another client, a control-plane policy --
// is a disagreement no amount of retrying settles, and a push per change is a loop
// against the control plane that turns a small bug into a rate-limit incident. Counting
// consecutive corrections rather than rating them over a window is deliberate: the
// failure being prevented is unbounded repetition, and a count needs no clock, so the
// rule is the same in a test as in production.
const prefsCorrectionLimit = 3

// prefsState is what the mirror remembers between reconciles.
type prefsState struct {
	// corrections counts, per setting, how many times in a row this app has had to put
	// the node's value back. A setting the node agrees with clears its own count, so a
	// change that lands never accumulates and only a real disagreement does.
	corrections map[string]int
	// conflict names the settings it has given up on. They stay listed until the user
	// writes one of them again, which is the signal that the disagreement was resolved
	// somewhere this app cannot see.
	conflict []string
	// err is why the last push or adoption failed, kept so the failure is visible in
	// the API rather than only in a log line nobody is watching.
	err string
}

// applyPrefs makes every running node's preferences match what its connection asks for.
// It runs on the reconcile goroutine, so it is serialized against node restarts and
// forward changes the same way everything else is.
//
// nodeUp is the primary connection's own state, which the rest of the reconcile has
// already established. Each other connection answers for itself: one that is up while
// another is down is the ordinary case with more than one network configured.
func (a *Agent) applyPrefs(ctx context.Context, nodeUp bool) {
	if node := a.currentNode(); node != nil && nodeUp {
		a.mirrorPrefs(ctx, config.PrimaryTunnelID, node)
	}
	for id, running := range a.runningTunnels() {
		// A connection of another kind has no node and no preferences: what a tailnet keeps
		// in preferences, a WireGuard connection keeps in its own stored settings and applies
		// by being rebuilt.
		if running.node == nil || !running.node.Status().Running() {
			continue
		}
		a.mirrorPrefs(ctx, id, running.node)
	}
}

// mirrorPrefs brings one connection's node into line with what that connection asks for.
func (a *Agent) mirrorPrefs(ctx context.Context, id string, node NodeController) {
	live, known := node.CachedPrefs()
	if !known {
		// The node has not reported its preferences yet. Pushing now would be pushing
		// blind, and the value that arrives a moment later would read as someone else
		// changing a setting back. The bus delivers one and wakes this loop again.
		return
	}

	if err := a.adoptPrefsOnce(id, live); err != nil {
		a.recordPrefsErr(id, fmt.Errorf("take the node's existing preferences: %w", err))
		return
	}

	want := a.mirroredPrefs(id)
	keys := a.planPrefsPush(id, tsnode.Drift(live, want))
	if len(keys) == 0 {
		return
	}

	pushCtx, cancel := context.WithTimeout(ctx, prefsPushTimeout)
	defer cancel()
	if _, err := node.EditPrefs(pushCtx, tsnode.PrefsForFields(want, keys)); err != nil {
		a.recordPrefsErr(id, fmt.Errorf("apply settings to the tailnet node: %w", err))
		return
	}
	a.notePrefsPushed(id)
}

// mirroredPrefs is what one connection's node is kept matching: the preferences in force
// for it, with the exit node the module chose substituted in. Every path that reads,
// compares or pushes a preference goes through here, so the mirror stays the single
// writer of every one of them while the choice of exit node is still made where the
// schedule lives.
//
// The substitution applies to the primary connection alone, because the rotation schedule
// runs against the node the exit-node module drives. Another connection is mirrored
// against exactly what it stores.
func (a *Agent) mirroredPrefs(id string) config.TailnetPrefs {
	prefs := a.tunnelPrefs(id)
	if id != config.PrimaryTunnelID {
		return prefs
	}
	return a.exitNodePrefs(prefs)
}

// adoptPrefsOnce folds one node's own preferences onto the connection running it, the
// first time this install ever sees that node up.
//
// A node enrolled elsewhere -- by `tailscale up --accept-routes`, or by this app under
// a config that has since been deleted -- arrives already carrying preferences. Without
// this, the first reconcile would turn them off: settings the user never touched here,
// changed by installing this app. Taking them instead makes the app show what the node
// is already doing, which is also the only way the user can then see it to change it.
//
// It happens once per connection rather than once per install, because each connection is
// a different node with different preferences to be asked about.
func (a *Agent) adoptPrefsOnce(id string, live tsnode.Prefs) error {
	held, stored := a.store.Get().Tunnel(id)
	if !stored || held.PrefsAdopted {
		return nil
	}

	var taken []string
	if _, err := a.store.Update(func(c *config.Config) error {
		for i := range c.Tunnels {
			if c.Tunnels[i].ID != id {
				continue
			}
			taken = config.AdoptPrefValues(&c.Settings, &c.Tunnels[i], tsnode.LiveValues(live))
			c.Tunnels[i].PrefsAdopted = true
			return nil
		}
		// Removed between the read above and this write. Nothing to adopt onto, and
		// inventing a connection to hold the values would put a network back that
		// somebody just took away.
		return fmt.Errorf("connection %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return err
	}
	if _, err := a.adoptSettings(); err != nil {
		return err
	}
	if len(taken) > 0 {
		a.logger.Info("took a tailnet node's existing preferences as this app's settings",
			"connection", id, "settings", taken)
	}
	return nil
}

// planPrefsPush decides which of one connection's preferences to push, given the ones its
// node currently disagrees about, and records the attempt. It is the only place the
// correction counters move, so the give-up rule exists in exactly one place.
func (a *Agent) planPrefsPush(id string, drift []string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	st := a.prefsStateLocked(id)
	if st.corrections == nil {
		st.corrections = make(map[string]int)
	}

	var keys []string
	for _, key := range tsnode.PrefKeys() {
		if !slices.Contains(drift, key) {
			// The node agrees, so whatever disagreement there was is over.
			delete(st.corrections, key)
			st.conflict = removeKey(st.conflict, key)
			continue
		}
		if slices.Contains(st.conflict, key) {
			continue
		}
		st.corrections[key]++
		if st.corrections[key] > prefsCorrectionLimit {
			st.conflict = append(st.conflict, key)
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

// removeKey drops one key from a list, leaving the rest in order.
func removeKey(keys []string, key string) []string {
	i := slices.Index(keys, key)
	if i < 0 {
		return keys
	}
	return slices.Delete(slices.Clone(keys), i, i+1)
}

// prefsStateLocked is one connection's mirror state, created on first use. The caller
// holds a.mu.
func (a *Agent) prefsStateLocked(id string) *prefsState {
	if a.prefs == nil {
		a.prefs = make(map[string]*prefsState)
	}
	st, held := a.prefs[id]
	if !held {
		st = &prefsState{}
		a.prefs[id] = st
	}
	return st
}

// notePrefsPushed records a landed push, which is what clears a stale failure.
func (a *Agent) notePrefsPushed(id string) {
	a.mu.Lock()
	a.prefsStateLocked(id).err = ""
	a.mu.Unlock()
}

// recordPrefsErr stores and logs why the mirror could not be applied. It is logged as
// an error and reported through the API: a settings change that silently never reached
// the tailnet is the one failure mode this whole file exists to make visible.
func (a *Agent) recordPrefsErr(id string, err error) {
	a.logger.Error("could not apply settings to a tailnet node", "connection", id, "error", err)
	a.mu.Lock()
	a.prefsStateLocked(id).err = err.Error()
	a.mu.Unlock()
}

// clearPrefsConflict forgets the disagreement over the named preferences of one
// connection, so a deliberate write resumes pushing what this app had given up on.
func (a *Agent) clearPrefsConflict(id string, keys []string) {
	if len(keys) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.prefsStateLocked(id)
	for _, key := range keys {
		delete(st.corrections, key)
		st.conflict = removeKey(st.conflict, key)
	}
	st.err = ""
}

// prefsReport is one connection's mirror state as the API renders it.
func (a *Agent) prefsReport(id string) (conflict []string, failure string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	st, held := a.prefs[id]
	if !held {
		return nil, ""
	}
	return slices.Clone(st.conflict), st.err
}

// prefsAPI presents the agent as the management API's preference mirror.
type prefsAPI struct{ a *Agent }

var _ httpapi.Prefs = prefsAPI{}

// PrefsAPI exposes the node-preference mirror to the management API.
func (a *Agent) PrefsAPI() httpapi.Prefs { return prefsAPI{a: a} }

// View reports every pref-backed setting this configuration can write, with the value
// the node holds beside the value this app stores.
//
// It answers for the primary connection. The panel it feeds is the one the settings
// document has always had, and its keys are the ones that named the single tailnet; each
// other connection reports its own preferences through the connections API.
func (pa prefsAPI) View() httpapi.PrefsView {
	a := pa.a
	s := a.settings()
	want := a.mirroredPrefs(config.PrimaryTunnelID)
	primary, _ := a.store.Get().Tunnel(config.PrimaryTunnelID)
	node := a.currentNode()

	var (
		live  tsnode.Prefs
		known bool
		up    bool
	)
	if node != nil {
		up = node.Status().Running()
		live, known = node.CachedPrefs()
	}

	drift := map[string]bool{}
	if up && known {
		for _, key := range tsnode.Drift(live, want) {
			drift[key] = true
		}
	}
	liveValues := tsnode.LiveValues(live)
	stored := config.PrefValues(&s, primary)

	conflict, failure := a.prefsReport(config.PrimaryTunnelID)
	view := httpapi.PrefsView{NodeUp: up, Known: known, Conflict: conflict}
	for _, f := range config.PrefsFields() {
		if ok, _ := f.Available(&s); !ok {
			continue
		}
		field := httpapi.PrefFieldView{
			Key:     f.JSONKey,
			Label:   f.Label,
			Stored:  stored[f.JSONKey],
			InForce: up && known && !drift[f.JSONKey],
		}
		if known {
			field.Live = liveValues[f.JSONKey]
		}
		view.Fields = append(view.Fields, field)
	}
	view.Capability = prefsCapability(view, failure, a.nodeProblem())
	return view
}

// prefsCapability states whether these settings are reaching the tailnet, and when they
// are not, why. Degraded rather than unavailable is the interesting case: the settings
// are stored and correct, and something outside this app is the reason they are not in
// force yet.
func prefsCapability(view httpapi.PrefsView, failure, nodeProblem string) httpapi.Capability {
	switch {
	case len(view.Fields) == 0:
		return httpapi.Capability{
			Reason: "No settings are kept on the tailnet node in this configuration.",
		}
	case !view.NodeUp:
		reason := "The tailnet node is not running, so these settings are stored but not in force."
		if nodeProblem != "" {
			reason = "The tailnet node is not running (" + nodeProblem +
				"), so these settings are stored but not in force."
		}
		return httpapi.Capability{Reason: reason}
	case len(view.Conflict) > 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Something outside app-tail keeps changing these settings back, so it " +
				"stopped applying them: " + strings.Join(view.Conflict, ", ") +
				". Save the setting again to try once more.",
		}
	case failure != "":
		return httpapi.Capability{Available: true, Degraded: true, Reason: failure}
	case !view.Known:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The tailnet node has not reported its settings yet.",
		}
	}
	for _, f := range view.Fields {
		if !f.InForce {
			return httpapi.Capability{
				Available: true, Degraded: true,
				Reason: "Waiting for the tailnet node to take these settings.",
			}
		}
	}
	return httpapi.Capability{Available: true}
}
