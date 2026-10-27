// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/exitnode"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// Choosing the exit node is this app's, not the node's: the tailnet's own chooser only
// considers devices the control plane flags, which never includes one someone runs
// themselves. So app-tail decides which device to use, and the preference mirror is what
// hands that decision to the node -- the decision is a value here, never a second writer
// of the same preference.

// exitNodeProbeTimeout bounds one round-trip measurement. A device that has not answered
// in this long is not the one to send everything through, so waiting longer would only
// delay choosing a device that did answer.
const exitNodeProbeTimeout = 3 * time.Second

// exitNodeProbeConcurrency is how many devices are measured at once. Each probe is a
// disco ping the peer's WireGuard layer answers, so the limit is about not flooding a
// tailnet with simultaneous handshakes rather than about local cost.
const exitNodeProbeConcurrency = 4

// exitNodeState is what the reconcile loop remembers about the exit node between passes,
// and the only place the current choice lives. It is deliberately not written to the
// settings document: while rotation is on the choice changes on a timer, and storing it
// would rewrite config.json and raise a settings-changed event every interval, forever.
type exitNodeState struct {
	mu         sync.RWMutex
	state      exitnode.State
	candidates []exitnode.Candidate
	// latency is the last measured round trip per device, for the strategy that needs
	// it. It is kept across passes because measuring is slow and a decision that had to
	// wait for one would stall the reconcile loop.
	latency map[string]time.Duration
	// wake is how long until the next decision is due, which the lifecycle loop arms a
	// timer with. Zero means nothing is scheduled.
	wake time.Duration
	// override reports that the decision landed on a device other than the stored one,
	// which is the only case in which the mirror is told to push something other than
	// the setting. It is false whenever the two agree, so the common case needs no
	// special handling anywhere.
	override bool
	// from is the stored choice this decision was made against. A settings write that
	// moves it makes the decision stale, and the new setting wins until the next pass
	// reconsiders it.
	from string
	// err is why the last decision could not be carried out, kept so the failure is
	// visible in the API rather than only in a log line.
	err string
	// probing guards against stacking measurement rounds: a probe takes seconds and the
	// reconcile loop can run several times in that window.
	probing bool
}

func (e *exitNodeState) snapshot() (exitnode.State, []exitnode.Candidate, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state, e.candidates, e.err
}

// pick is the device the module chose instead of the stored one, the stored choice it
// was decided against, and whether there is an override at all. It is read by the
// preference mirror on other goroutines.
func (e *exitNodeState) pick() (chosen, from string, override bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state.Current, e.from, e.override
}

func (e *exitNodeState) publish(state exitnode.State, candidates []exitnode.Candidate, from string, wake time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state, e.candidates, e.wake = state, candidates, wake
	e.from, e.override = from, state.Current != from
}

func (e *exitNodeState) nextWake() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.wake
}

func (e *exitNodeState) recordErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.err = ""
		return
	}
	e.err = err.Error()
}

// beginProbe claims the right to run a measurement round, or reports that one is already
// running.
func (e *exitNodeState) beginProbe() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.probing {
		return false
	}
	e.probing = true
	return true
}

func (e *exitNodeState) endProbe(measured map[string]time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.probing = false
	if measured != nil {
		e.latency = measured
	}
}

func (e *exitNodeState) latencySnapshot() map[string]time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.latency
}

// applyExitNode decides which device this machine's other traffic leaves through and
// records it. It does not push anything: the decision becomes part of the settings the
// preference mirror hands to the node, so there is exactly one writer of that
// preference and no two components can put different devices back in turn.
func (a *Agent) applyExitNode(ctx context.Context, nodeUp bool) {
	s := a.settings()
	prefs := a.primaryPrefs()
	if !s.ExitNodeEnabled {
		// Off is a decision in its own right: it clears the preference, which is what
		// puts traffic back on this machine's own connection.
		a.exitNode.publish(exitnode.State{
			Reason: "The exit node module is off, so this device's traffic leaves from here.",
		}, nil, "", 0)
		a.exitNode.recordErr(nil)
		return
	}
	if !nodeUp {
		// Nothing to decide against and nothing to tell: the device list is empty until
		// the node is running, and deciding against an empty one would read as "your
		// tailnet offers no exit node" and clear the one that was in use.
		previous, candidates, _ := a.exitNode.snapshot()
		previous.Reason = "The tailnet node is not running, so no exit node is in use."
		a.exitNode.publish(previous, candidates, prefs.ExitNodeID, 0)
		// Whatever went wrong reading the device list stopped being the reason the moment
		// the node went down. Leaving it recorded sends the user after a failure that has
		// been superseded, with the cause that replaced it one line further down the card.
		a.exitNode.recordErr(nil)
		return
	}

	peerCtx, cancel := context.WithTimeout(ctx, peerListTimeout)
	peers, err := a.node.Peers(peerCtx)
	cancel()
	if err != nil {
		// The previous decision stands, for the same reason: keeping the device that is
		// already working beats concluding the tailnet offers none.
		a.exitNode.recordErr(fmt.Errorf("read the device list to choose an exit node: %w", err))
		return
	}

	previous, _, _ := a.exitNode.snapshot()
	candidates := exitnode.Candidates(peers)
	state, decision := exitnode.Decide(exitnode.Input{
		Module:      s.ExitNodeEnabled,
		Prefs:       prefs,
		Candidates:  candidates,
		State:       previous,
		Now:         a.now(),
		Latency:     a.exitNode.latencySnapshot(),
		ActiveConns: a.proxyActiveConns(),
		Rand:        rand.IntN,
	})
	a.exitNode.publish(state, candidates, prefs.ExitNodeID, decision.Wake)
	a.exitNode.recordErr(nil)

	if decision.Changed {
		a.logger.Info("exit node changed", "device", decision.Pick, "why", decision.Reason)
		device, message := decision.Pick, "Traffic now leaves through "+decision.Pick+"."
		if device == "" {
			device = "none"
			message = "Traffic no longer leaves through another device."
		}
		a.recordEvent(telemetry.CodeExitNodeChanged, message,
			map[string]string{"device": device, "reason": decision.Reason})
	}
	if len(decision.ProbeLatency) > 0 {
		a.probeExitNodes(ctx, decision.ProbeLatency)
	}
}

// proxyActiveConns is how many connections are open through the proxies right now, which
// is what holds a scheduled change back. Zero when none is running: with nothing carrying
// traffic through the exit node there is nothing a change would drop.
func (a *Agent) proxyActiveConns() int {
	set := a.currentProxies()
	if set == nil {
		return 0
	}
	return int(set.Counters().Active)
}

// probeExitNodes measures the round trip to each device off the reconcile goroutine and
// wakes it when the measurements land. Measuring inline would stall every forward this
// machine serves for as long as the slowest device takes to answer.
func (a *Agent) probeExitNodes(ctx context.Context, candidates []exitnode.Candidate) {
	if !a.exitNode.beginProbe() {
		return
	}
	node := a.currentNode()
	if node == nil {
		a.exitNode.endProbe(nil)
		return
	}

	// Detached from the reconcile's context so a poke that finishes the pass does not
	// cancel a measurement round mid-flight; it is bounded by its own timeout instead.
	probeCtx := context.WithoutCancel(ctx)
	go func() {
		measured := measureLatency(probeCtx, node, exitNodeTargets(candidates), a.logger)
		a.exitNode.endProbe(measured)
		a.pokeReconcile()
	}()
}

// probeTarget is one device to measure the round trip to. It exists so the measurement
// below serves both the exit-node chooser and the traffic view without either having to
// know about the other's idea of a device.
type probeTarget struct {
	ID    string
	Label string
	Addr  netip.Addr
}

// exitNodeTargets is the candidate list as something measurable.
func exitNodeTargets(candidates []exitnode.Candidate) []probeTarget {
	out := make([]probeTarget, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, probeTarget{ID: c.ID, Label: c.Label, Addr: c.Addr})
	}
	return out
}

// measureLatency measures every target, bounded in both time and concurrency. A device
// that does not answer is left out rather than recorded as slow: "not measured" and
// "measured as bad" lead to different choices, and conflating them would rule out a
// device that a moment later answers fastest.
func measureLatency(ctx context.Context, node NodeController, targets []probeTarget, logger interface {
	Debug(msg string, args ...any)
}) map[string]time.Duration {
	var (
		mu       sync.Mutex
		measured = make(map[string]time.Duration, len(targets))
		wg       sync.WaitGroup
		slots    = make(chan struct{}, exitNodeProbeConcurrency)
	)
	for _, c := range targets {
		if !c.Addr.IsValid() {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			probeCtx, cancel := context.WithTimeout(ctx, exitNodeProbeTimeout)
			defer cancel()
			latency, err := node.PingPeer(probeCtx, c.Addr)
			if err != nil {
				logger.Debug("device did not answer a round-trip measurement",
					"device", c.Label, "error", err)
				return
			}
			mu.Lock()
			measured[c.ID] = latency
			mu.Unlock()
		}()
	}
	wg.Wait()
	return measured
}

// exitNodePrefs is p with the device the exit-node module chose substituted in, for
// the cases where that is not the stored one: a rotation schedule that has moved on, or
// a failure policy that stepped off a device that went away. It is what the preference
// mirror compares against and pushes, so the mirror stays the single writer of that
// preference while the choice itself is made where the schedule lives.
//
// Substituting rather than storing is the point: with rotation on the device changes on
// a timer, and writing each change to the settings document would rewrite config.json
// and raise a settings-changed event every interval for as long as the app runs.
func (a *Agent) exitNodePrefs(p config.TailnetPrefs) config.TailnetPrefs {
	chosen, from, override := a.exitNode.pick()
	if !override {
		return p
	}
	// A settings write that moved the stored choice makes this decision stale, but only
	// when the decision was derived from it: while rotation is on the stored device is
	// the fallback, and replacing the fallback does not replace the one in use.
	if from != p.ExitNodeID && !p.ExitNodeRotate {
		return p
	}
	p.ExitNodeID = chosen
	return p
}

// now is the clock the exit-node decision reads. It is a field rather than a call to
// time.Now so a test drives a whole rotation schedule without waiting for one.
func (a *Agent) now() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
}

// exitNodeAPI presents the exit-node module to the management API.
type exitNodeAPI struct{ a *Agent }

var _ httpapi.ExitNode = exitNodeAPI{}

// ExitNodeAPI exposes the exit-node module.
func (a *Agent) ExitNodeAPI() httpapi.ExitNode { return exitNodeAPI{a: a} }

// View reports which device traffic is leaving through, what the tailnet offers, and why
// the state is what it is.
func (e exitNodeAPI) View() httpapi.ExitNodeView {
	a := e.a
	s := a.settings()
	state, candidates, failure := a.exitNode.snapshot()
	summary := exitnode.Summarize(s.ExitNodeEnabled, a.primaryPrefs(), state, candidates)

	view := httpapi.ExitNodeView{
		TunnelID:     config.PrimaryTunnelID,
		Enabled:      summary.Enabled,
		Rotating:     summary.Rotating,
		Current:      summary.Current,
		CurrentLabel: summary.CurrentLabel,
		Reason:       summary.Reason,
		Warning:      exitnode.SwitchWarning,
	}
	if !summary.NextChange.IsZero() {
		view.NextChange = summary.NextChange.UTC().Format(time.RFC3339)
	}
	for _, c := range candidates {
		view.Candidates = append(view.Candidates, httpapi.ExitNodeCandidate{
			ID:      c.ID,
			Label:   c.Label,
			Display: c.Describe(),
			Online:  c.Online,
			Country: c.Location.Country,
			City:    c.Location.City,
			Current: c.ID == summary.Current,
		})
	}
	if node := a.currentNode(); node != nil {
		st := node.Status()
		view.LiveID, view.LiveOnline = st.ExitNodeID, st.ExitNodeOnline
	}
	view.Capability = exitNodeCapability(s, view, failure, a.nodeProblem())
	return view
}

// Suggest asks the tailnet which exit node it recommends.
//
// The empty answer is the common one and is not a failure: only devices the control
// plane flags as suggestable are considered, which on most tailnets means Tailscale's own
// hosted nodes and never a device someone runs themselves. Reporting that plainly is the
// difference between "your tailnet has no suggestion" and "this button is broken".
func (e exitNodeAPI) Suggest(ctx context.Context) (httpapi.ExitNodeSuggestion, error) {
	node := e.a.currentNode()
	if node == nil || !node.Status().Running() {
		return httpapi.ExitNodeSuggestion{}, httpapi.Unavailable("suggesting an exit node",
			"the tailnet node is not running")
	}
	s, err := node.SuggestExitNode(ctx)
	if err != nil {
		return httpapi.ExitNodeSuggestion{}, fmt.Errorf("ask the tailnet for an exit node: %w", err)
	}
	if s.ID == "" {
		return httpapi.ExitNodeSuggestion{
			Reason: "Your tailnet has no exit node to suggest. Only devices your network " +
				"marks as suggestable are considered, which usually means Tailscale's own " +
				"hosted nodes rather than one you run yourself. Choose from the list instead.",
		}, nil
	}
	return httpapi.ExitNodeSuggestion{
		ID:      s.ID,
		Label:   s.Name,
		Country: s.Location.Country,
		City:    s.Location.City,
	}, nil
}

// exitNodeCapability states whether the module is doing anything and, when it is not,
// why. Degraded is the interesting case: the module is on and correct, and something
// about the tailnet is the reason no traffic is leaving through a peer.
func exitNodeCapability(s config.Settings, view httpapi.ExitNodeView, failure, nodeProblem string) httpapi.Capability {
	switch {
	case !s.ExitNodeEnabled:
		return httpapi.Capability{
			Reason: "The exit node module is off, so this device's traffic leaves from here.",
		}
	case failure != "":
		return httpapi.Capability{Available: true, Degraded: true, Reason: failure}
	case nodeProblem != "":
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The tailnet node is not running (" + nodeProblem +
				"), so no exit node is in use.",
		}
	case len(view.Candidates) == 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Your tailnet is offering no approved exit node. A device has to " +
				"advertise itself as one and an admin has to approve it before it appears here.",
		}
	case view.Current == "":
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "No exit node is chosen, so this device's traffic leaves from here.",
		}
	case !view.LiveOnline:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The chosen exit node is not carrying traffic. app-tail refuses the " +
				"connections rather than sending them out from here, so nothing leaks " +
				"while it is away.",
		}
	}
	return httpapi.Capability{Available: true}
}

// exitNodeChoices renders the devices the tailnet offers as the choices the exit-node
// setting's picker fills itself from. It is served with the settings schema so a
// schema-driven form needs no exit-node-specific fetch of its own.
func (a *Agent) exitNodeChoices() []config.EnumOption {
	_, candidates, _ := a.exitNode.snapshot()
	out := make([]config.EnumOption, 0, len(candidates))
	for _, c := range candidates {
		help := "Offline right now; choosing it stops traffic until it comes back."
		if c.Online {
			help = "Online and approved by your tailnet."
		}
		out = append(out, config.EnumOption{Value: c.ID, Label: c.Describe(), Help: help})
	}
	return out
}
