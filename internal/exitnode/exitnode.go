// SPDX-License-Identifier: MIT

// Package exitnode decides which device this machine's other traffic leaves through,
// and when to move to another one.
//
// The decision is a pure function of the settings, the devices the tailnet offers, and
// what the last look found -- no clock, no network, no state of its own. Everything that
// touches the tailnet lives in the caller, which is what lets every rule here be
// exercised against an exact set of devices at an exact moment.
package exitnode

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// Candidate is one device the tailnet offers as an exit node, reduced to what choosing
// between them needs.
type Candidate struct {
	// ID is the stable node ID, which is the identity a preference names.
	ID string
	// Label is the device's name as a person reads it.
	Label string
	// Online reports whether the device is currently reachable. An offline device is
	// still listed, because a pinned choice has to stay visible while it is away.
	Online bool
	// Location is where the tailnet says the device is, empty for a self-hosted one.
	Location tsnode.PeerLocation
	// Addr is an address to measure the round trip to, invalid when the device has no
	// tailnet address yet.
	Addr netip.Addr
}

// Describe renders a candidate the way a picker and a log line both want it: the name,
// and the place when the tailnet publishes one.
func (c Candidate) Describe() string {
	if loc := c.Location.Label(); loc != "" {
		return c.Label + " (" + loc + ")"
	}
	return c.Label
}

// Candidates picks the devices offered as exit nodes out of a peer list, in the order a
// picker should show them: online first, then by place, then by name, so the list a user
// reads twice is the same list.
//
// Only approved offers appear. A peer that advertises an exit node the tailnet has not
// approved reads as no offer at all, so a device the tailnet would refuse to route
// through is never presented as a choice.
func Candidates(peers []tsnode.Peer) []Candidate {
	out := make([]Candidate, 0, len(peers))
	for _, p := range peers {
		if !p.ExitNodeOption {
			continue
		}
		out = append(out, Candidate{
			ID:       p.ID,
			Label:    p.Label(),
			Online:   p.Online,
			Location: p.Location,
			Addr:     firstAddr(p.IPs),
		})
	}
	sort.Slice(out, func(i, j int) bool { return lessCandidate(out[i], out[j]) })
	return out
}

func lessCandidate(a, b Candidate) bool {
	if a.Online != b.Online {
		return a.Online
	}
	if la, lb := a.Location.Label(), b.Location.Label(); la != lb {
		// A device with no published place sorts after the ones that have one, so a
		// tailnet mixing hosted and self-hosted nodes does not scatter the hosted ones.
		if la == "" || lb == "" {
			return lb == ""
		}
		return la < lb
	}
	if a.Label != b.Label {
		return a.Label < b.Label
	}
	return a.ID < b.ID
}

func firstAddr(ips []string) netip.Addr {
	for _, raw := range ips {
		if addr, err := netip.ParseAddr(raw); err == nil {
			return addr
		}
	}
	return netip.Addr{}
}

// usable are the candidates a switch may move to: online, and identified. An offline
// device is not a choice -- selecting it stops traffic rather than moving it.
func usable(candidates []Candidate) []Candidate {
	out := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Online && c.ID != "" {
			out = append(out, c)
		}
	}
	return out
}

// find returns the candidate with this id.
func find(candidates []Candidate, id string) (Candidate, bool) {
	for _, c := range candidates {
		if c.ID == id {
			return c, true
		}
	}
	return Candidate{}, false
}

// State is what the decision carries between looks. It is returned by Decide rather than
// held here, so the caller owns the only copy and the decision itself stays pure.
type State struct {
	// Current is the device in use, empty for none.
	Current string
	// Since is when Current was chosen, which is what the schedule counts from.
	Since time.Time
	// Deferrals counts the scheduled moves skipped so far because connections were open
	// through the current device.
	Deferrals int
	// Reason explains the state in one sentence, for the exit-node card.
	Reason string
}

// Decision is what to do now.
type Decision struct {
	// Pick is the device to use, empty for none. It is what the caller applies.
	Pick string
	// Changed reports that Pick differs from the device that was in use, which is the
	// only case in which the caller has anything to apply.
	Changed bool
	// Reason explains the decision in one sentence.
	Reason string
	// Wake is how long until the next look is due. Zero means nothing is scheduled: the
	// caller still looks again whenever the tailnet changes.
	Wake time.Duration
	// ProbeLatency asks the caller to measure the round trip to these devices before the
	// next look. It is set only by the strategy that needs it, so a tailnet that never
	// chose it is never probed.
	ProbeLatency []Candidate
}

// Input is everything a decision reads.
type Input struct {
	// Module is whether the exit-node module is on. It is the installation's own switch
	// rather than the connection's preference, and it is carried separately because the
	// two are different answers to a person: a module that is off is a feature nobody
	// asked for, while an empty selection under a module that is on is a choice still to
	// be made.
	Module bool
	// Prefs are the connection's exit-node preferences, with the module already folded
	// in, so nothing here has to apply it a second time.
	Prefs config.TailnetPrefs
	// Candidates are the devices the tailnet offers, from Candidates.
	Candidates []Candidate
	// State is what the last decision returned.
	State State
	// Now is the moment being decided for.
	Now time.Time
	// Latency is what the last probe measured, keyed by device id. A device missing
	// from it has not been measured.
	Latency map[string]time.Duration
	// ActiveConns is how many connections are open through the proxy. It is the whole
	// count rather than only the ones leaving the tailnet, because a connection's
	// destination is not tracked after it is dialed -- and holding a scheduled move
	// back too often is bounded by the deferral limit, while cutting a live download
	// is not undoable.
	ActiveConns int
	// Rand returns a value in [0, n) and is the only nondeterminism a decision has. It
	// is supplied rather than taken from the package so a test pins the choice.
	Rand func(n int) int
}

// Decide chooses the exit node to use now and returns the state to carry forward.
//
// It is the whole policy: whether an exit node is wanted at all, what to do when the one
// in use goes away, and when the schedule says to move to another.
func Decide(in Input) (State, Decision) {
	p := in.Prefs
	if !in.Module {
		return released("The exit node module is off.")
	}
	// Letting the tailnet choose is the backend's own job: it holds the preference and
	// re-picks on its own, so this app selecting a device as well would be two choosers
	// putting different ones back in turn.
	if p.ExitNodeAuto {
		return released("Tailscale is choosing the exit node.")
	}
	if !p.ExitNodeRotate {
		return pinned(in)
	}
	return rotate(in)
}

// released is the decision to use no exit node.
func released(reason string) (State, Decision) {
	return State{Reason: reason}, Decision{Reason: reason}
}

// pinned is the decision when rotation is off: use the device the settings name, and
// answer for it when it is not usable.
func pinned(in Input) (State, Decision) {
	id := in.Prefs.ExitNodeID
	if id == "" {
		return released("No exit node is chosen.")
	}
	chosen, listed := find(in.Candidates, id)
	if listed && chosen.Online {
		return hold(in, chosen, "Traffic is leaving through "+chosen.Describe()+".")
	}
	return unusable(in, id, chosen, listed)
}

// unusable answers for a chosen device that is offline, or no longer offered at all.
func unusable(in Input, id string, chosen Candidate, listed bool) (State, Decision) {
	what := "The chosen exit node is no longer offered by your tailnet"
	if listed {
		what = chosen.Describe() + " is offline"
	}
	switch in.Prefs.EffectiveExitNodeFailurePolicy() {
	case config.FailureOff:
		reason := what + ", so traffic is going out directly again."
		return State{Reason: reason}, Decision{Reason: reason}
	case config.FailureNext:
		if next, ok := pick(in, id); ok {
			reason := what + ", so traffic moved to " + next.Describe() + "."
			return hold(in, next, reason)
		}
		reason := what + ", and your tailnet offers no other one, so traffic through " +
			"app-tail is stopped rather than going out directly."
		return State{Current: id, Since: in.State.Since, Reason: reason},
			Decision{Pick: id, Changed: in.State.Current != id, Reason: reason}
	default:
		reason := what + ", so traffic through app-tail is stopped rather than going " +
			"out directly."
		return State{Current: id, Since: in.State.Since, Reason: reason},
			Decision{Pick: id, Changed: in.State.Current != id, Reason: reason}
	}
}

// rotate is the decision when the schedule owns the choice.
func rotate(in Input) (State, Decision) {
	current, listed := find(in.Candidates, in.State.Current)
	// Nothing in use, or what was in use has gone away: choose now rather than waiting
	// out a schedule that is measuring from a device that is no longer carrying anything.
	if in.State.Current == "" || !listed || !current.Online {
		next, ok := pick(in, in.State.Current)
		if !ok {
			return noCandidate(in)
		}
		return hold(in, next, "Traffic is leaving through "+next.Describe()+
			", chosen by rotation.")
	}

	interval := in.Prefs.EffectiveRotateInterval()
	due := in.State.Since.Add(interval)
	if in.Now.Before(due) {
		return hold(in, current, "Traffic is leaving through "+current.Describe()+
			", until the next change "+relative(due.Sub(in.Now))+".")
	}

	if in.Prefs.ExitNodeRotatePauseOnActive && in.ActiveConns > 0 &&
		in.State.Deferrals < maxDeferrals(in.Prefs) {
		state := State{
			Current:   current.ID,
			Since:     in.State.Since,
			Deferrals: in.State.Deferrals + 1,
			Reason: fmt.Sprintf("Staying on %s while %s open through app-tail; "+
				"changing now would drop %s.", current.Describe(),
				count(in.ActiveConns, "connection is", "connections are"),
				plural(in.ActiveConns, "it", "them")),
		}
		// Look again in a fraction of the interval rather than a whole one: the wait is
		// for the connections to end, which is not what the schedule measures.
		return state, Decision{
			Pick:    current.ID,
			Reason:  state.Reason,
			Wake:    deferralWait(interval),
			Changed: false,
		}
	}

	next, ok := pick(in, current.ID)
	if !ok {
		// Nothing else to move to. Staying is right -- the alternative is going out
		// directly, which is the property rotation exists to protect.
		return hold(in, current, "Traffic is staying on "+current.Describe()+
			"; your tailnet offers no other exit node to move to.")
	}
	return hold(in, next, "Traffic moved to "+next.Describe()+" on schedule.")
}

// noCandidate answers a rotation with nothing usable to rotate between.
func noCandidate(in Input) (State, Decision) {
	// The pinned device is the fallback the settings name for exactly this: rotation
	// wanted a device and the tailnet is offering none it can reach.
	if id := in.Prefs.ExitNodeID; id != "" {
		reason := "Your tailnet is offering no exit node that is online, so traffic is " +
			"stopped on the chosen one rather than going out directly."
		return State{Current: id, Since: in.State.Since, Reason: reason},
			Decision{Pick: id, Changed: in.State.Current != id, Reason: reason}
	}
	reason := "Your tailnet is offering no exit node that is online."
	return State{Reason: reason}, Decision{Reason: reason, Changed: in.State.Current != ""}
}

// hold settles on a device and reports how long it stays.
func hold(in Input, chosen Candidate, reason string) (State, Decision) {
	state := State{Current: chosen.ID, Since: in.State.Since, Reason: reason}
	changed := in.State.Current != chosen.ID
	if changed {
		state.Since = in.Now
		state.Deferrals = 0
	}
	decision := Decision{Pick: chosen.ID, Changed: changed, Reason: reason}
	if in.Prefs.ExitNodeRotate {
		interval := in.Prefs.EffectiveRotateInterval()
		decision.Wake = interval - in.Now.Sub(state.Since)
		if decision.Wake < time.Second {
			// A due-now schedule that found nothing to move to must still wait, or the
			// caller spins looking at the same unchanged tailnet.
			decision.Wake = interval
		}
		if in.Prefs.EffectiveRotateStrategy() == config.RotateLatency {
			decision.ProbeLatency = usable(in.Candidates)
		}
	}
	return state, decision
}

// pick chooses the next device by the strategy in force, never returning the one already
// in use: a rotation that lands on the current device is a rotation that did not happen,
// and on a two-device tailnet a naive random pick does that half the time.
func pick(in Input, exclude string) (Candidate, bool) {
	options := make([]Candidate, 0, len(in.Candidates))
	for _, c := range usable(in.Candidates) {
		if c.ID != exclude {
			options = append(options, c)
		}
	}
	if len(options) == 0 {
		return Candidate{}, false
	}
	switch in.Prefs.EffectiveRotateStrategy() {
	case config.RotateRandom:
		return pickRandom(in, options), true
	case config.RotateLatency:
		return pickFastest(in, options), true
	default:
		return pickNext(options, exclude), true
	}
}

// pickNext walks the devices in their stable order, continuing from the one in use so
// every device takes a turn rather than the first two trading it.
func pickNext(options []Candidate, exclude string) Candidate {
	sorted := append([]Candidate(nil), options...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, c := range sorted {
		if c.ID > exclude {
			return c
		}
	}
	return sorted[0]
}

// pickRandom draws from the options, falling back to the first when no source of
// randomness was supplied rather than reaching for a package-level one: a decision that
// silently became nondeterministic would be untestable exactly where it matters.
func pickRandom(in Input, options []Candidate) Candidate {
	if in.Rand == nil || len(options) == 1 {
		return options[0]
	}
	i := in.Rand(len(options))
	if i < 0 || i >= len(options) {
		return options[0]
	}
	return options[i]
}

// pickFastest takes the lowest measured round trip. A device that has not been measured
// yet sorts last rather than being dropped: the first decision happens before any probe
// has run, and refusing to choose then would leave the machine with no exit node.
func pickFastest(in Input, options []Candidate) Candidate {
	best := options[0]
	bestLatency, bestKnown := in.Latency[best.ID]
	for _, c := range options[1:] {
		latency, known := in.Latency[c.ID]
		switch {
		case known && !bestKnown, known && bestKnown && latency < bestLatency:
			best, bestLatency, bestKnown = c, latency, true
		}
	}
	return best
}

// maxDeferrals is how many scheduled moves may be skipped, with zero meaning the
// default. A machine that is never idle has to rotate eventually or the setting has
// quietly turned rotation off.
func maxDeferrals(p config.TailnetPrefs) int {
	if p.ExitNodeRotateMaxDeferrals <= 0 {
		return config.DefaultExitNodeRotateMaxDeferrals
	}
	return p.ExitNodeRotateMaxDeferrals
}

// deferralWait is how long to wait before looking again at connections that held a move
// back. A tenth of the interval, floored at a minute, checks often enough to move soon
// after the last connection closes without polling the proxy in a tight loop.
func deferralWait(interval time.Duration) time.Duration {
	wait := interval / 10
	if wait < time.Minute {
		wait = time.Minute
	}
	return wait
}

// relative renders a duration the way a sentence wants it.
func relative(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "in under a minute"
	case d < time.Hour:
		return fmt.Sprintf("in %s", count(int(d.Round(time.Minute)/time.Minute), "minute", "minutes"))
	default:
		return fmt.Sprintf("in %s", count(int(d.Round(time.Hour)/time.Hour), "hour", "hours"))
	}
}

// count renders "1 connection" and "3 connections" from the two forms.
func count(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, plural(n, one, many))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Summary is the exit-node state as a consumer renders it.
type Summary struct {
	// Enabled reports that the module is on.
	Enabled bool
	// Rotating reports that the schedule owns the choice, which is what makes the
	// chosen device a fallback rather than the one in use.
	Rotating bool
	// Current is the device app-tail is asking for, empty for none.
	Current string
	// CurrentLabel names that device, or is empty when it is not one the tailnet is
	// currently offering.
	CurrentLabel string
	// Reason explains the state in one sentence.
	Reason string
	// NextChange is when the schedule moves on, zero when nothing is scheduled.
	NextChange time.Time
	// Candidates are the devices the tailnet offers.
	Candidates []Candidate
}

// Summarize renders the state and the devices behind it for a consumer. module is the
// installation's switch and prefs the connection's own preferences, for the reason
// Input states.
func Summarize(module bool, prefs config.TailnetPrefs, state State, candidates []Candidate) Summary {
	out := Summary{
		Enabled:    module,
		Rotating:   module && prefs.ExitNodeRotate,
		Current:    state.Current,
		Reason:     state.Reason,
		Candidates: candidates,
	}
	if c, ok := find(candidates, state.Current); ok {
		out.CurrentLabel = c.Describe()
	}
	if out.Rotating && !state.Since.IsZero() && state.Current != "" {
		out.NextChange = state.Since.Add(prefs.EffectiveRotateInterval())
	}
	return out
}

// SwitchWarning is the sentence a consumer shows beside a control that changes the exit
// node. It is here rather than in the dashboard because the same words belong in the
// tray, the CLI and the API, and because the effect is a fact about the tailnet rather
// than a UI choice.
const SwitchWarning = "Changing the exit node drops every connection going through the " +
	"old one: downloads stop, SSH sessions end, and anything tied to the previous " +
	"address has to sign in again."

// Describe renders a summary as one line, for a log or a tray tooltip.
func (s Summary) Describe() string {
	if !s.Enabled {
		return "off"
	}
	parts := []string{}
	if s.CurrentLabel != "" {
		parts = append(parts, s.CurrentLabel)
	} else if s.Current != "" {
		parts = append(parts, s.Current)
	}
	if s.Rotating {
		parts = append(parts, "rotating")
	}
	if len(parts) == 0 {
		return "no exit node chosen"
	}
	return strings.Join(parts, ", ")
}
