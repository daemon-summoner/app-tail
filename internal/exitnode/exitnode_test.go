// SPDX-License-Identifier: MIT

package exitnode

import (
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// at is a fixed moment, so every schedule in these tests reads as an exact arithmetic
// rather than as a window around the wall clock.
var at = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// on is the preferences a decision reads when the schedule is off. The module is not one
// of them: it is the installation's switch rather than the connection's preference, so it
// reaches a decision as Input.Module beside these.
func on() config.TailnetPrefs {
	return config.TailnetPrefs{}
}

// rotating is the preferences a decision reads when the schedule owns the choice.
func rotating(p config.TailnetPrefs) config.TailnetPrefs {
	p.ExitNodeRotate = true
	return p
}

// node is a candidate that is online and reachable, which is the ordinary case.
func node(id, label string) Candidate {
	return Candidate{ID: id, Label: label, Online: true}
}

// offline is the same device with the tailnet reporting it away.
func offline(c Candidate) Candidate {
	c.Online = false
	return c
}

// ids is the candidate ids in the order given, for comparing an ordering in one line.
func ids(candidates []Candidate) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.ID)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A device the tailnet has not approved as an exit node must never reach a picker:
// choosing it stops this machine's traffic at a peer that will refuse to route it, which
// reads as the app being broken rather than as an unapproved offer.
func TestOnlyDevicesTheTailnetApprovedAsExitNodesAreOffered(t *testing.T) {
	got := Candidates([]tsnode.Peer{
		{ID: "n1", HostName: "laptop"},
		{ID: "n2", HostName: "gateway", ExitNodeOption: true},
		{ID: "n3", HostName: "phone"},
	})

	if want := []string{"n2"}; !equal(ids(got), want) {
		t.Fatalf("the tailnet offers %v, want only the approved exit node %v", ids(got), want)
	}
	if got[0].Label != "gateway" {
		t.Errorf("the candidate reads %q, want the device's own name", got[0].Label)
	}
}

// The list a user reads twice has to be the same list, and an offline device has to sink
// below the ones they can actually pick.
func TestTheOfferedDevicesAreOrderedOnlineFirstThenByPlaceThenByName(t *testing.T) {
	got := Candidates([]tsnode.Peer{
		{ID: "n1", HostName: "self-hosted", Online: true, ExitNodeOption: true},
		{ID: "n2", HostName: "away", Online: false, ExitNodeOption: true,
			Location: tsnode.PeerLocation{Country: "Sweden", City: "Malmo"}},
		{ID: "n3", HostName: "zurich", Online: true, ExitNodeOption: true,
			Location: tsnode.PeerLocation{Country: "Switzerland", City: "Zurich"}},
		{ID: "n4", HostName: "berlin", Online: true, ExitNodeOption: true,
			Location: tsnode.PeerLocation{Country: "Germany", City: "Berlin"}},
	})

	// Online first; among those, a published place before none, alphabetically; the
	// offline device last however good its place reads.
	want := []string{"n4", "n3", "n1", "n2"}
	if !equal(ids(got), want) {
		t.Fatalf("the picker offers %v, want %v", ids(got), want)
	}
}

// A candidate's address is what a latency probe measures, so a peer carrying addresses
// has to arrive with one.
func TestAnOfferedDeviceCarriesAnAddressToMeasure(t *testing.T) {
	got := Candidates([]tsnode.Peer{
		{ID: "n1", HostName: "gateway", Online: true, ExitNodeOption: true,
			IPs: []string{"not-an-address", "100.64.0.9"}},
	})

	if len(got) != 1 {
		t.Fatalf("the tailnet offers %d devices, want the one approved", len(got))
	}
	if got[0].Addr.String() != "100.64.0.9" {
		t.Errorf("the candidate is measured at %q, want its tailnet address", got[0].Addr)
	}
}

// The module being off is the default every install runs on, so it has to produce no exit
// node at all rather than the last one chosen.
func TestTheModuleBeingOffChoosesNoExitNode(t *testing.T) {
	state, decision := Decide(Input{
		Prefs:      config.TailnetPrefs{ExitNodeID: "n1"},
		Candidates: []Candidate{node("n1", "gateway")},
		State:      State{Current: "n1"},
		Now:        at,
	})

	if decision.Pick != "" || state.Current != "" {
		t.Errorf("the decision picks %q and carries %q, want no exit node while the module is off",
			decision.Pick, state.Current)
	}
	if !strings.Contains(state.Reason, "off") {
		t.Errorf("the reason reads %q, want it to say the module is off", state.Reason)
	}
}

// Letting Tailscale choose means it holds the preference and re-picks on its own. This
// app naming a device as well is two choosers putting different ones back in turn.
func TestLettingTailscaleChooseLeavesThePickToTheBackend(t *testing.T) {
	s := on()
	s.ExitNodeAuto = true
	s.ExitNodeID = "n1"

	state, decision := Decide(Input{
		Module:     true,
		Prefs:      s,
		Candidates: []Candidate{node("n1", "gateway"), node("n2", "other")},
		Now:        at,
	})

	if decision.Pick != "" || state.Current != "" {
		t.Errorf("the decision picks %q, want nothing while Tailscale is choosing", decision.Pick)
	}
	if !strings.Contains(state.Reason, "Tailscale is choosing") {
		t.Errorf("the reason reads %q, want it to say Tailscale is choosing", state.Reason)
	}
}

// The ordinary case: rotation off, one device named, and it is there.
func TestTheChosenDeviceIsUsedWhileItIsOnline(t *testing.T) {
	s := on()
	s.ExitNodeID = "n2"

	state, decision := Decide(Input{
		Module:     true,
		Prefs:      s,
		Candidates: []Candidate{node("n1", "one"), node("n2", "two")},
		Now:        at,
	})

	if decision.Pick != "n2" || !decision.Changed {
		t.Errorf("the decision is %+v, want it to move to the chosen device", decision)
	}
	if state.Since != at {
		t.Errorf("the choice is timed at %v, want the moment it was made (%v)", state.Since, at)
	}
	if decision.Wake != 0 {
		t.Errorf("the decision asks to be woken in %v, want nothing scheduled while rotation is off",
			decision.Wake)
	}
}

// Choosing again what is already in use is not a change: applying it would push the same
// preference on every look, and every push is an edit the tailnet has to answer.
func TestUsingTheDeviceAlreadyInUseIsNotAChange(t *testing.T) {
	s := on()
	s.ExitNodeID = "n1"

	_, decision := Decide(Input{
		Module:     true,
		Prefs:      s,
		Candidates: []Candidate{node("n1", "one")},
		State:      State{Current: "n1", Since: at.Add(-time.Hour)},
		Now:        at,
	})

	if decision.Changed {
		t.Errorf("the decision reports a change to %q, which is already in use", decision.Pick)
	}
}

// What each failure policy does when the chosen device goes away. The default matters
// most: holding a dead exit node is what keeps traffic from going out directly.
func TestWhatHappensWhenTheChosenDeviceIsNoLongerUsable(t *testing.T) {
	tests := []struct {
		name       string
		policy     config.ExitNodeFailurePolicy
		candidates []Candidate
		wantPick   string
		wantReason string
	}{
		{
			name:       "the default holds the dead device so traffic stops rather than leaking",
			candidates: []Candidate{offline(node("n1", "one")), node("n2", "two")},
			wantPick:   "n1",
			wantReason: "rather than going out directly",
		},
		{
			name:       "holding is what the hold policy names",
			policy:     config.FailureHold,
			candidates: []Candidate{offline(node("n1", "one"))},
			wantPick:   "n1",
			wantReason: "rather than going out directly",
		},
		{
			name:       "the next policy moves to another offered device",
			policy:     config.FailureNext,
			candidates: []Candidate{offline(node("n1", "one")), node("n2", "two")},
			wantPick:   "n2",
			wantReason: "traffic moved to two",
		},
		{
			name:       "the next policy holds when there is nowhere to move to",
			policy:     config.FailureNext,
			candidates: []Candidate{offline(node("n1", "one"))},
			wantPick:   "n1",
			wantReason: "offers no other one",
		},
		{
			name:       "the off policy is the one that lets traffic go out directly",
			policy:     config.FailureOff,
			candidates: []Candidate{offline(node("n1", "one")), node("n2", "two")},
			wantPick:   "",
			wantReason: "going out directly again",
		},
		{
			name:       "a device the tailnet stopped offering is answered the same way",
			candidates: []Candidate{node("n2", "two")},
			wantPick:   "n1",
			wantReason: "no longer offered",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := on()
			s.ExitNodeID = "n1"
			s.ExitNodeOnFailure = tc.policy

			state, decision := Decide(Input{
				Module:     true,
				Prefs:      s,
				Candidates: tc.candidates,
				State:      State{Current: "n1", Since: at.Add(-time.Hour)},
				Now:        at,
			})

			if decision.Pick != tc.wantPick {
				t.Errorf("the decision picks %q, want %q", decision.Pick, tc.wantPick)
			}
			if state.Current != tc.wantPick {
				t.Errorf("the state carries %q, want %q", state.Current, tc.wantPick)
			}
			if !strings.Contains(state.Reason, tc.wantReason) {
				t.Errorf("the reason reads %q, want it to say %q", state.Reason, tc.wantReason)
			}
		})
	}
}

// Naming no device at all is not a failure: the module is on and nothing is chosen yet,
// which is what the form looks like before the user picks one.
func TestTheModuleBeingOnWithNoDeviceChosenPicksNothing(t *testing.T) {
	state, decision := Decide(Input{
		Module:     true,
		Prefs:      on(),
		Candidates: []Candidate{node("n1", "one")},
		Now:        at,
	})

	if decision.Pick != "" {
		t.Errorf("the decision picks %q with nothing chosen", decision.Pick)
	}
	if !strings.Contains(state.Reason, "No exit node is chosen") {
		t.Errorf("the reason reads %q, want it to say nothing is chosen", state.Reason)
	}
}

// Rotation with nothing in use has to choose immediately: waiting out an interval that is
// measuring from no device leaves the machine without an exit node for the whole period.
func TestRotationChoosesAtOnceWhenNothingIsInUse(t *testing.T) {
	state, decision := Decide(Input{
		Module:     true,
		Prefs:      rotating(on()),
		Candidates: []Candidate{node("n1", "one"), node("n2", "two")},
		Now:        at,
	})

	if decision.Pick != "n1" || !decision.Changed {
		t.Errorf("the decision is %+v, want it to start on the first offered device", decision)
	}
	if state.Since != at {
		t.Errorf("the choice is timed at %v, want the moment it was made", state.Since)
	}
	if decision.Wake != config.DefaultExitNodeRotateIntervalSec*time.Second {
		t.Errorf("the next look is in %v, want a whole interval from a fresh choice", decision.Wake)
	}
}

// The schedule is the point of rotation: a device that has not served its interval keeps
// serving it, and the caller is told when to look again rather than polling.
func TestRotationWaitsOutTheIntervalBeforeMoving(t *testing.T) {
	s := rotating(on())
	s.ExitNodeRotateIntervalSec = 600

	_, decision := Decide(Input{
		Module:     true,
		Prefs:      s,
		Candidates: []Candidate{node("n1", "one"), node("n2", "two")},
		State:      State{Current: "n1", Since: at.Add(-100 * time.Second)},
		Now:        at,
	})

	if decision.Pick != "n1" || decision.Changed {
		t.Errorf("the decision is %+v, want the device to keep serving its interval", decision)
	}
	if want := 500 * time.Second; decision.Wake != want {
		t.Errorf("the next look is in %v, want the rest of the interval (%v)", decision.Wake, want)
	}
}

// Each strategy, at the moment a move is due, with the same two devices in use.
func TestEachRotationStrategyPicksTheDeviceItNames(t *testing.T) {
	all := []Candidate{node("n1", "one"), node("n2", "two"), node("n3", "three")}

	tests := []struct {
		name     string
		strategy config.RotateStrategy
		latency  map[string]time.Duration
		rand     func(int) int
		state    string
		want     string
	}{
		{
			name:  "the default takes the next device in the stable order",
			state: "n1",
			want:  "n2",
		},
		{
			name:     "round robin wraps past the last device rather than stopping",
			strategy: config.RotateRoundRobin,
			state:    "n3",
			want:     "n1",
		},
		{
			name:     "random draws from the devices supplied",
			strategy: config.RotateRandom,
			rand:     func(int) int { return 1 },
			state:    "n1",
			want:     "n3",
		},
		{
			name:     "latency takes the lowest measured round trip",
			strategy: config.RotateLatency,
			latency:  map[string]time.Duration{"n2": 90 * time.Millisecond, "n3": 20 * time.Millisecond},
			state:    "n1",
			want:     "n3",
		},
		{
			name:     "latency prefers a measured device over an unmeasured one",
			strategy: config.RotateLatency,
			latency:  map[string]time.Duration{"n3": 200 * time.Millisecond},
			state:    "n1",
			want:     "n3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := rotating(on())
			s.ExitNodeRotateStrategy = tc.strategy
			s.ExitNodeRotateIntervalSec = 600

			_, decision := Decide(Input{
				Module:     true,
				Prefs:      s,
				Candidates: all,
				State:      State{Current: tc.state, Since: at.Add(-time.Hour)},
				Now:        at,
				Latency:    tc.latency,
				Rand:       tc.rand,
			})

			if decision.Pick != tc.want {
				t.Errorf("the schedule moved to %q, want %q", decision.Pick, tc.want)
			}
			if !decision.Changed {
				t.Error("the decision reports no change while the schedule moved")
			}
		})
	}
}

// A random pick that lands on the device already in use is a rotation that did not
// happen, and on a two-device tailnet a naive draw does that half the time.
func TestRandomRotationNeverDrawsTheDeviceAlreadyInUse(t *testing.T) {
	s := rotating(on())
	s.ExitNodeRotateStrategy = config.RotateRandom
	s.ExitNodeRotateIntervalSec = 600

	// Every draw the source can return, so no index maps back to the current device.
	for i := range 2 {
		_, decision := Decide(Input{
			Module:     true,
			Prefs:      s,
			Candidates: []Candidate{node("n1", "one"), node("n2", "two")},
			State:      State{Current: "n1", Since: at.Add(-time.Hour)},
			Now:        at,
			Rand:       func(int) int { return i },
		})
		if decision.Pick == "n1" {
			t.Fatalf("draw %d landed back on the device already in use", i)
		}
	}
}

// The schedule only ever measures devices when the strategy that reads measurements is
// the one in force -- a tailnet that never chose it is never probed.
func TestOnlyTheLatencyStrategyAsksForMeasurements(t *testing.T) {
	all := []Candidate{node("n1", "one"), offline(node("n2", "two"))}

	s := rotating(on())
	s.ExitNodeRotateStrategy = config.RotateLatency
	_, latencyDecision := Decide(Input{
		Module: true, Prefs: s, Candidates: all,
		State: State{Current: "n1", Since: at}, Now: at,
	})
	if want := []string{"n1"}; !equal(ids(latencyDecision.ProbeLatency), want) {
		t.Errorf("the decision asks to measure %v, want only the devices a move could land on (%v)",
			ids(latencyDecision.ProbeLatency), want)
	}

	s.ExitNodeRotateStrategy = config.RotateRoundRobin
	_, roundRobin := Decide(Input{
		Module: true, Prefs: s, Candidates: all,
		State: State{Current: "n1", Since: at}, Now: at,
	})
	if len(roundRobin.ProbeLatency) != 0 {
		t.Errorf("the decision asks to measure %v under a strategy that reads no measurements",
			ids(roundRobin.ProbeLatency))
	}
}

// Cutting a live download is not undoable, so a due move waits while connections are
// open through the device carrying them.
func TestAScheduledMoveIsHeldBackWhileConnectionsAreOpen(t *testing.T) {
	s := rotating(on())
	s.ExitNodeRotateIntervalSec = 600
	s.ExitNodeRotatePauseOnActive = true

	state, decision := Decide(Input{
		Module:      true,
		Prefs:       s,
		Candidates:  []Candidate{node("n1", "one"), node("n2", "two")},
		State:       State{Current: "n1", Since: at.Add(-time.Hour)},
		Now:         at,
		ActiveConns: 2,
	})

	if decision.Pick != "n1" || decision.Changed {
		t.Errorf("the decision is %+v, want the move held back while connections are open", decision)
	}
	if state.Deferrals != 1 {
		t.Errorf("the state counts %d held-back moves, want 1", state.Deferrals)
	}
	if decision.Wake != time.Minute {
		t.Errorf("the next look is in %v, want a short wait for the connections to end", decision.Wake)
	}
	if !strings.Contains(state.Reason, "2 connections are open") {
		t.Errorf("the reason reads %q, want it to say what is holding the move back", state.Reason)
	}
}

// A machine that is never idle has to rotate eventually, or pausing on active
// connections has quietly turned rotation off.
func TestAMoveHeldBackTooManyTimesGoesAheadAnyway(t *testing.T) {
	s := rotating(on())
	s.ExitNodeRotateIntervalSec = 600
	s.ExitNodeRotatePauseOnActive = true
	s.ExitNodeRotateMaxDeferrals = 2

	state, decision := Decide(Input{
		Module:      true,
		Prefs:       s,
		Candidates:  []Candidate{node("n1", "one"), node("n2", "two")},
		State:       State{Current: "n1", Since: at.Add(-time.Hour), Deferrals: 2},
		Now:         at,
		ActiveConns: 5,
	})

	if decision.Pick != "n2" || !decision.Changed {
		t.Errorf("the decision is %+v, want the move to go ahead past the deferral limit", decision)
	}
	if state.Deferrals != 0 {
		t.Errorf("the state counts %d held-back moves after moving, want the count reset", state.Deferrals)
	}
}

// Not pausing is the setting's other position, and it has to actually move.
func TestOpenConnectionsDoNotHoldTheMoveBackWhenPausingIsOff(t *testing.T) {
	s := rotating(on())
	s.ExitNodeRotateIntervalSec = 600
	s.ExitNodeRotatePauseOnActive = false

	_, decision := Decide(Input{
		Module:      true,
		Prefs:       s,
		Candidates:  []Candidate{node("n1", "one"), node("n2", "two")},
		State:       State{Current: "n1", Since: at.Add(-time.Hour)},
		Now:         at,
		ActiveConns: 9,
	})

	if decision.Pick != "n2" {
		t.Errorf("the schedule moved to %q, want it to move despite open connections", decision.Pick)
	}
}

// Staying is right when there is nowhere else to go: the alternative is going out
// directly, which is the property rotation exists to protect.
func TestRotationStaysPutWhenTheTailnetOffersNowhereElse(t *testing.T) {
	s := rotating(on())
	s.ExitNodeRotateIntervalSec = 600

	state, decision := Decide(Input{
		Module:     true,
		Prefs:      s,
		Candidates: []Candidate{node("n1", "one"), offline(node("n2", "two"))},
		State:      State{Current: "n1", Since: at.Add(-time.Hour)},
		Now:        at,
	})

	if decision.Pick != "n1" || decision.Changed {
		t.Errorf("the decision is %+v, want it to stay on the only device it can reach", decision)
	}
	if decision.Wake != 600*time.Second {
		t.Errorf("the next look is in %v, want a whole interval rather than an immediate retry",
			decision.Wake)
	}
	if !strings.Contains(state.Reason, "no other exit node") {
		t.Errorf("the reason reads %q, want it to say there is nowhere to move to", state.Reason)
	}
}

// Rotation with nothing online falls back to the device the settings name, so traffic
// stops on a dead exit node rather than going out directly.
func TestRotationWithNothingOnlineFallsBackToTheChosenDevice(t *testing.T) {
	s := rotating(on())
	s.ExitNodeID = "n1"

	state, decision := Decide(Input{
		Module:     true,
		Prefs:      s,
		Candidates: []Candidate{offline(node("n1", "one")), offline(node("n2", "two"))},
		Now:        at,
	})

	if decision.Pick != "n1" || !decision.Changed {
		t.Errorf("the decision is %+v, want it to fall back to the chosen device", decision)
	}
	if !strings.Contains(state.Reason, "rather than going out directly") {
		t.Errorf("the reason reads %q, want it to say traffic is stopped rather than leaking",
			state.Reason)
	}
}

// Rotation with nothing online and nothing chosen has nothing to fall back to, and has to
// say so rather than reporting a device it is not using.
func TestRotationWithNothingOnlineAndNothingChosenReleasesTheExitNode(t *testing.T) {
	state, decision := Decide(Input{
		Module:     true,
		Prefs:      rotating(on()),
		Candidates: []Candidate{offline(node("n1", "one"))},
		State:      State{Current: "n1", Since: at.Add(-time.Hour)},
		Now:        at,
	})

	if decision.Pick != "" || state.Current != "" {
		t.Errorf("the decision picks %q, want none with nothing online and nothing chosen",
			decision.Pick)
	}
	if !decision.Changed {
		t.Error("the decision reports no change while it dropped the device that was in use")
	}
}

// The summary is what the card renders, and the distinction it has to carry is that while
// rotating, the chosen device is a fallback rather than the one in use.
func TestTheSummaryReportsWhatIsInUseAndWhenItChanges(t *testing.T) {
	s := rotating(on())
	s.ExitNodeRotateIntervalSec = 600
	candidates := []Candidate{
		{ID: "n1", Label: "one", Online: true,
			Location: tsnode.PeerLocation{Country: "Germany", City: "Berlin"}},
	}
	state := State{Current: "n1", Since: at, Reason: "in use"}

	got := Summarize(true, s, state, candidates)

	if !got.Enabled || !got.Rotating {
		t.Errorf("the summary reads %+v, want it on and rotating", got)
	}
	if got.CurrentLabel != "one (Berlin, Germany)" {
		t.Errorf("the summary names %q, want the device and its place", got.CurrentLabel)
	}
	if want := at.Add(600 * time.Second); !got.NextChange.Equal(want) {
		t.Errorf("the next change reads %v, want an interval past the choice (%v)", got.NextChange, want)
	}
	if line := got.Describe(); !strings.Contains(line, "one") || !strings.Contains(line, "rotating") {
		t.Errorf("the one-line summary reads %q, want the device and that it is rotating", line)
	}
}

// Nothing is scheduled when rotation is off, so a card must not render a next change that
// will never come.
func TestTheSummarySchedulesNoChangeWhileRotationIsOff(t *testing.T) {
	s := on()
	s.ExitNodeID = "n1"

	got := Summarize(true, s, State{Current: "n1", Since: at}, []Candidate{node("n1", "one")})

	if got.Rotating {
		t.Error("the summary reads as rotating while the schedule is off")
	}
	if !got.NextChange.IsZero() {
		t.Errorf("the summary schedules a change at %v with rotation off", got.NextChange)
	}
}

// A device the tailnet has stopped offering stays selected in the settings, so the
// summary has to report the id it is asking for with no name to put beside it rather than
// dropping it.
func TestTheSummaryKeepsADeviceTheTailnetNoLongerOffers(t *testing.T) {
	got := Summarize(true, on(), State{Current: "gone"}, []Candidate{node("n1", "one")})

	if got.Current != "gone" {
		t.Errorf("the summary reports %q, want the device still being asked for", got.Current)
	}
	if got.CurrentLabel != "" {
		t.Errorf("the summary names it %q, want no name for a device the tailnet is not offering",
			got.CurrentLabel)
	}
	if line := got.Describe(); !strings.Contains(line, "gone") {
		t.Errorf("the one-line summary reads %q, want it to name the device anyway", line)
	}
}

// peer is a device the tailnet offers as an approved exit node, which is what a candidate
// is built from.
func peer(id, name string, loc tsnode.PeerLocation) tsnode.Peer {
	return tsnode.Peer{ID: id, HostName: name, Online: true, ExitNodeOption: true, Location: loc}
}

// A tailnet mixing hosted nodes with self-hosted ones must not scatter the hosted ones
// through the list: the place is what makes a picker of thirty usable, so devices that
// have one are grouped ahead of the devices that do not.
func TestPlacedDevicesAreGroupedAheadOfTheOnesWithNoPlace(t *testing.T) {
	got := ids(Candidates([]tsnode.Peer{
		peer("n1", "aardvark", tsnode.PeerLocation{}),
		peer("n2", "zebra", tsnode.PeerLocation{City: "Berlin", Country: "Germany"}),
		peer("n3", "yak", tsnode.PeerLocation{City: "Amsterdam", Country: "Netherlands"}),
	}))

	if want := []string{"n3", "n2", "n1"}; !equal(got, want) {
		t.Errorf("the order is %v, want the placed devices first and by place: %v", got, want)
	}
}

// Two devices in the same place fall back to the name, or the list order depends on
// whatever order the tailnet happened to report them in.
func TestTwoDevicesInTheSamePlaceAreOrderedByName(t *testing.T) {
	berlin := tsnode.PeerLocation{City: "Berlin", Country: "Germany"}
	got := ids(Candidates([]tsnode.Peer{peer("n1", "zebra", berlin), peer("n2", "aardvark", berlin)}))

	if want := []string{"n2", "n1"}; !equal(got, want) {
		t.Errorf("the order is %v, want the same place ordered by name: %v", got, want)
	}
}

// Two devices reporting the same name are told apart by the only thing left, or the
// order flips between reads and the picker moves under the cursor.
func TestTwoDevicesWithTheSameNameAreOrderedByTheirId(t *testing.T) {
	none := tsnode.PeerLocation{}
	got := ids(Candidates([]tsnode.Peer{peer("n2", "gateway", none), peer("n1", "gateway", none)}))

	if want := []string{"n1", "n2"}; !equal(got, want) {
		t.Errorf("the order is %v, want the id to settle it: %v", got, want)
	}
}

// A source of randomness that answered outside the range would index past the end of the
// list. Falling back beats panicking on a decision that runs every interval forever.
func TestARandomDrawOutsideTheListFallsBackRatherThanPanicking(t *testing.T) {
	options := []Candidate{node("n1", "one"), node("n2", "two")}

	for _, draw := range []int{-1, 2, 99} {
		got := pickRandom(Input{Rand: func(int) int { return draw }}, options)
		if got.ID != "n1" {
			t.Errorf("a draw of %d chose %q, want the first option", draw, got.ID)
		}
	}
}

// The wait between looks at a busy proxy is a tenth of the interval, floored so a short
// interval does not turn into a poll of the proxy several times a second.
func TestTheWaitBetweenLooksAtABusyProxyIsFloored(t *testing.T) {
	if got := deferralWait(10 * time.Minute); got != time.Minute {
		t.Errorf("deferralWait(10m) = %v, want a tenth of it", got)
	}
	if got := deferralWait(time.Minute); got != time.Minute {
		t.Errorf("deferralWait(1m) = %v, want the floor rather than six seconds", got)
	}
	if got := deferralWait(2 * time.Hour); got != 12*time.Minute {
		t.Errorf("deferralWait(2h) = %v, want a tenth of it", got)
	}
}

// "in 90 minutes" is not how a person reads an hour and a half, and the singular forms
// are what keep "in 1 minutes" off the card.
func TestHowLongUntilTheNextChangeReads(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{30 * time.Second, "in under a minute"},
		{time.Minute, "in 1 minute"},
		{15 * time.Minute, "in 15 minutes"},
		{90 * time.Minute, "in 2 hours"},
		{time.Hour, "in 1 hour"},
		{5 * time.Hour, "in 5 hours"},
	}

	for _, tc := range cases {
		if got := relative(tc.in); got != tc.want {
			t.Errorf("relative(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The one-line summary is what a tray tooltip and a log line both read, so each state has
// to render as something rather than as an empty string.
func TestTheOneLineSummaryRendersEveryState(t *testing.T) {
	cases := []struct {
		name string
		in   Summary
		want string
	}{
		{name: "the module is off", in: Summary{}, want: "off"},
		{
			name: "a device is named",
			in:   Summary{Enabled: true, Current: "n1", CurrentLabel: "gateway"},
			want: "gateway",
		},
		{
			name: "a device with no name yet",
			in:   Summary{Enabled: true, Current: "n1"},
			want: "n1",
		},
		{
			name: "rotating between devices",
			in:   Summary{Enabled: true, Current: "n1", CurrentLabel: "gateway", Rotating: true},
			want: "gateway, rotating",
		},
		{
			name: "on with nothing chosen",
			in:   Summary{Enabled: true},
			want: "no exit node chosen",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Describe(); got != tc.want {
				t.Errorf("Describe() = %q, want %q", got, tc.want)
			}
		})
	}
}
