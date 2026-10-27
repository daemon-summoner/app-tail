// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/exitnode"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// testClock is a clock a test moves by hand, so a rotation schedule is driven rather than
// waited out.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// exitNodePeer is a device the tailnet offers as an approved exit node.
func exitNodePeer(id, name, addr string) tsnode.Peer {
	return tsnode.Peer{
		ID: id, HostName: name, Online: true, ExitNodeOption: true, IPs: []string{addr},
	}
}

// exitNodeView reads the exit-node card the dashboard renders.
func exitNodeView(h *harness) httpapi.ExitNodeView {
	h.t.Helper()
	resp, body := h.get("/api/exitnode")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /api/exitnode = %d: %s", resp.StatusCode, body)
	}
	var view httpapi.ExitNodeView
	if err := json.Unmarshal(body, &view); err != nil {
		h.t.Fatalf("decode the exit-node view: %v", err)
	}
	return view
}

// waitForExitNodeID waits until the node holds this device as its exit node.
func waitForExitNodeID(h *harness, want string, what string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if prefs, _ := h.node.prefsState(); prefs.ExitNodeID == want {
			return
		}
		h.agent.pokeReconcile()
		time.Sleep(5 * time.Millisecond)
	}
	prefs, edits := h.node.prefsState()
	h.t.Fatalf("timed out after 5s waiting for %s; the node holds %q after %d edits, want %q",
		what, prefs.ExitNodeID, edits, want)
}

// The chosen device has to reach the node: tsnet applies none of this from the parameters
// a node is built with, so this push is the only path an exit node ever takes.
func TestTheChosenExitNodeIsHandedToTheNode(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(exitNodePeer("n1", "gateway", "100.64.0.1"))
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{"exitNode.enabled": true, "exitNode.nodeId": "n1"})

	waitForExitNodeID(h, "n1", "the chosen exit node to reach the node")
}

// Turning the module off has to clear the preference, or traffic keeps leaving through a
// device the settings say is not in use.
func TestTurningTheExitNodeModuleOffClearsThePreference(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(exitNodePeer("n1", "gateway", "100.64.0.1"))
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{"exitNode.enabled": true, "exitNode.nodeId": "n1"})
	waitForExitNodeID(h, "n1", "the exit node to be applied")

	patchSettings(h, map[string]any{"exitNode.enabled": false})

	waitForExitNodeID(h, "", "the exit node to be cleared")
}

// Letting Tailscale choose and naming a device are the same preference at the backend, so
// the id must not be sent alongside: the two would disagree about what is in use.
func TestLettingTailscaleChooseSendsNoDeviceOfOurOwn(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(exitNodePeer("n1", "gateway", "100.64.0.1"))
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled": true, "exitNode.nodeId": "n1", "exitNode.auto": true,
	})

	waitFor(t, 5*time.Second, "the node to be told to choose for itself", func() bool {
		prefs, _ := h.node.prefsState()
		return prefs.AutoExitNode
	})
	if prefs, _ := h.node.prefsState(); prefs.ExitNodeID != "" {
		t.Errorf("the node holds %q as its exit node while Tailscale is choosing", prefs.ExitNodeID)
	}
}

// Advertising an exit node and using one is a combination the backend refuses outright,
// so it has to be refused here -- with an answer naming the setting to change rather than
// a push that fails minutes later with nothing on screen connecting the two.
func TestOfferingAnExitNodeWhileUsingOneIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	patchSettings(h, map[string]any{
		"routes.enabled": true, "routes.advertiseExitNode": true,
	})

	raw := map[string]json.RawMessage{
		"exitNode.enabled": json.RawMessage(`true`),
		"exitNode.nodeId":  json.RawMessage(`"n1"`),
	}
	_, _, err := h.agent.Settings().Update(context.Background(), raw)
	if err == nil {
		t.Fatal("using an exit node was accepted while this device is offering itself as one")
	}
	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("the refusal is %T (%v), want one naming the setting to change", err, err)
	}
	if !strings.Contains(invalid.Message, "Offer this device as an exit node") {
		t.Errorf("the refusal reads %q, want it to name the setting to turn off", invalid.Message)
	}
}

// The schedule is the whole point of rotation: once a device has served its interval the
// next one takes over, and the node has to be told.
func TestRotationMovesToTheNextDeviceWhenTheIntervalElapses(t *testing.T) {
	clock := newTestClock()
	h := newHarnessWith(t, nil, func(o *Options) { o.Clock = clock.Now })
	h.node.setPeers(
		exitNodePeer("n1", "one", "100.64.0.1"),
		exitNodePeer("n2", "two", "100.64.0.2"),
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled":              true,
		"exitNode.rotate.enabled":       true,
		"exitNode.rotate.intervalSec":   120,
		"exitNode.rotate.pauseOnActive": false,
	})
	waitForExitNodeID(h, "n1", "rotation to start on the first offered device")

	clock.advance(3 * time.Minute)
	h.agent.pokeReconcile()

	waitForExitNodeID(h, "n2", "the schedule to move to the next device")
}

// A device that has not served its interval keeps serving it. Without this, every
// reconcile -- and there is one per netmap change -- would move the exit node.
func TestRotationDoesNotMoveBeforeTheIntervalElapses(t *testing.T) {
	clock := newTestClock()
	h := newHarnessWith(t, nil, func(o *Options) { o.Clock = clock.Now })
	h.node.setPeers(
		exitNodePeer("n1", "one", "100.64.0.1"),
		exitNodePeer("n2", "two", "100.64.0.2"),
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled": true, "exitNode.rotate.enabled": true,
		"exitNode.rotate.intervalSec": 600,
	})
	waitForExitNodeID(h, "n1", "rotation to start on the first offered device")

	clock.advance(time.Minute)
	for range 5 {
		h.agent.pokeReconcile()
		h.agent.reconcileNow(context.Background())
	}

	if prefs, _ := h.node.prefsState(); prefs.ExitNodeID != "n1" {
		t.Errorf("the node holds %q, want the device still serving its interval", prefs.ExitNodeID)
	}
}

// While rotation is on, the stored device is a fallback rather than the one in use -- so
// the schedule's pick is what the mirror pushes, not the setting.
func TestTheRotatedDeviceIsWhatReachesTheNodeNotTheStoredOne(t *testing.T) {
	clock := newTestClock()
	h := newHarnessWith(t, nil, func(o *Options) { o.Clock = clock.Now })
	h.node.setPeers(
		exitNodePeer("n1", "one", "100.64.0.1"),
		exitNodePeer("n2", "two", "100.64.0.2"),
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled": true, "exitNode.nodeId": "n2",
		"exitNode.rotate.enabled": true, "exitNode.rotate.intervalSec": 120,
	})
	waitForExitNodeID(h, "n1", "rotation to choose for itself rather than take the stored device")

	p := h.agent.primaryPrefs()
	if p.ExitNodeID != "n2" {
		t.Fatalf("the stored device is %q, want the one the user chose to stay put", p.ExitNodeID)
	}
	if got := h.agent.mirroredPrefs(config.PrimaryTunnelID); got.ExitNodeID != "n1" {
		t.Errorf("the mirror is handed %q, want the device rotation is using", got.ExitNodeID)
	}
}

// With rotation off, a settings write moving the stored device has to win over a decision
// made against the old one: otherwise the user picks a device and the app keeps using
// what a failure policy stepped onto a moment earlier.
func TestAStoredDeviceThatMovedWinsOverAStaleDecision(t *testing.T) {
	agent := mirrorAgent(t)

	// A decision that stepped off the stored device, the way a failure policy does.
	exitNodeDecision(agent, "n9", "n1")

	p := config.TailnetPrefs{ExitNodeID: "n1"}
	if got := agent.exitNodePrefs(p); got.ExitNodeID != "n9" {
		t.Errorf("the mirror is handed %q, want the device the decision stepped onto", got.ExitNodeID)
	}

	p.ExitNodeID = "n2"
	if got := agent.exitNodePrefs(p); got.ExitNodeID != "n2" {
		t.Errorf("the mirror is handed %q, want the device the user just chose", got.ExitNodeID)
	}
}

// The module being off means the mirror pushes no exit node at all, so a stale decision
// cannot keep a preference alive after the switch goes off.
//
// Through the mirror rather than the substitution alone, because the module is folded in
// upstream of it now: what proves the switch is honoured is what the node is handed.
func TestADecisionIsIgnoredWhileTheModuleIsOff(t *testing.T) {
	agent := mirrorAgent(t)
	write := func(patch map[string]any) {
		t.Helper()
		if _, err := agent.store.Update(func(c *config.Config) error {
			return config.ApplyPatchTo(c, patchOf(t, patch))
		}); err != nil {
			t.Fatalf("write %v: %v", patch, err)
		}
		if _, err := agent.adoptSettings(); err != nil {
			t.Fatalf("adopt the stored document: %v", err)
		}
	}
	write(map[string]any{"exitNode.enabled": true, "exitNode.nodeId": "n1"})
	write(map[string]any{"exitNode.enabled": false})

	exitNodeDecision(agent, "n9", "n1")

	if got := agent.mirroredPrefs(config.PrimaryTunnelID); got.ExitNodeID != "" {
		t.Errorf("the mirror is handed %q while the module is off, want no exit node at all",
			got.ExitNodeID)
	}
}

// The strategy that reads measurements has to actually get them, and the measured device
// has to be the one it moves to.
func TestTheLatencyStrategyMeasuresDevicesAndTakesTheFastest(t *testing.T) {
	clock := newTestClock()
	h := newHarnessWith(t, nil, func(o *Options) { o.Clock = clock.Now })
	h.node.setLatency(map[string]time.Duration{
		"100.64.0.1": 200 * time.Millisecond,
		"100.64.0.2": 150 * time.Millisecond,
		"100.64.0.3": 10 * time.Millisecond,
	})
	h.node.setPeers(
		exitNodePeer("n1", "one", "100.64.0.1"),
		exitNodePeer("n2", "two", "100.64.0.2"),
		exitNodePeer("n3", "three", "100.64.0.3"),
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled": true, "exitNode.rotate.enabled": true,
		"exitNode.rotate.strategy": "latency", "exitNode.rotate.intervalSec": 120,
	})

	waitFor(t, 5*time.Second, "the devices to be measured", func() bool {
		h.agent.pokeReconcile()
		return h.node.pingCalls() > 0
	})

	clock.advance(3 * time.Minute)
	h.agent.pokeReconcile()

	waitForExitNodeID(h, "n3", "the schedule to move to the device that answered fastest")
}

// A device that never answers a measurement must not be recorded as slow: "not measured"
// and "measured as bad" lead to different choices, and conflating them rules out a device
// that a moment later answers fastest.
func TestADeviceThatDoesNotAnswerIsLeftUnmeasuredRatherThanRecordedAsSlow(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setLatency(map[string]time.Duration{"100.64.0.2": 40 * time.Millisecond})
	candidates := exitNodeCandidates(h,
		exitNodePeer("n1", "silent", "100.64.0.1"),
		exitNodePeer("n2", "answers", "100.64.0.2"),
	)

	measured := measureLatency(context.Background(), h.node, exitNodeTargets(candidates), quietLogger())

	if _, ok := measured["n1"]; ok {
		t.Errorf("the device that never answered was measured at %v", measured["n1"])
	}
	if measured["n2"] != 40*time.Millisecond {
		t.Errorf("the device that answered measured %v, want what it answered with", measured["n2"])
	}
}

// A device with no tailnet address yet cannot be measured, and asking anyway would spend
// a probe slot and a timeout on an address that does not exist.
func TestADeviceWithNoAddressIsNotProbed(t *testing.T) {
	h := newHarness(t, nil)
	candidates := exitNodeCandidates(h, tsnode.Peer{
		ID: "n1", HostName: "brand-new", Online: true, ExitNodeOption: true,
	})

	measureLatency(context.Background(), h.node, exitNodeTargets(candidates), quietLogger())

	if got := h.node.pingCalls(); got != 0 {
		t.Errorf("%d measurements were attempted against a device with no address", got)
	}
}

// The card is what a user reads to answer "is my traffic leaving through that device".
// It has to carry both sides: what this app asked for, and what the backend reports.
func TestTheExitNodeCardReportsBothWhatWeAskedForAndWhatIsLive(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(
		exitNodePeer("n1", "gateway", "100.64.0.1"),
		tsnode.Peer{ID: "n2", HostName: "away", ExitNodeOption: true},
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{"exitNode.enabled": true, "exitNode.nodeId": "n1"})
	waitForExitNodeID(h, "n1", "the exit node to be applied")
	h.node.setExitNodeStatus("n1", true)

	waitFor(t, 5*time.Second, "the card to report the live exit node", func() bool {
		return exitNodeView(h).LiveID == "n1"
	})

	view := exitNodeView(h)
	if !view.Enabled || view.Current != "n1" || view.CurrentLabel != "gateway" {
		t.Errorf("the card reads %+v, want it on and naming the chosen device", view)
	}
	if !view.LiveOnline {
		t.Error("the card reports the live exit node as not carrying traffic while it is")
	}
	if len(view.Candidates) != 2 {
		t.Fatalf("the card offers %d devices, want both the tailnet approved: %+v",
			len(view.Candidates), view.Candidates)
	}
	if !view.Candidates[0].Current {
		t.Errorf("no offered device is marked as the one in use: %+v", view.Candidates)
	}
	if view.Candidates[1].Online {
		t.Errorf("the offline device reads as online: %+v", view.Candidates[1])
	}
	if !view.Capability.Available || view.Capability.Degraded {
		t.Errorf("the card reads %+v, want the module working", view.Capability)
	}
	if !strings.Contains(view.Warning, "drops every connection") {
		t.Errorf("the card warns %q, want it to say what changing the device costs", view.Warning)
	}
}

// A chosen device the backend is not routing through is the case that matters most: the
// proxy refuses connections rather than sending them out from here, and a card that read
// as working would have the user hunting for a fault somewhere else.
func TestTheCardSaysSoWhenTheChosenDeviceIsNotCarryingTraffic(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(exitNodePeer("n1", "gateway", "100.64.0.1"))
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{"exitNode.enabled": true, "exitNode.nodeId": "n1"})
	waitForExitNodeID(h, "n1", "the exit node to be applied")

	view := exitNodeView(h)
	if !view.Capability.Degraded {
		t.Fatalf("the card reads %+v, want it degraded while nothing is carrying traffic",
			view.Capability)
	}
	if !strings.Contains(view.Capability.Reason, "nothing leaks") {
		t.Errorf("the reason reads %q, want it to say traffic is refused rather than sent out here",
			view.Capability.Reason)
	}
}

// A tailnet offering no approved exit node is the state a new user is in, and the card
// has to say what to do about it rather than reading as broken.
func TestTheCardExplainsATailnetThatOffersNoExitNode(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	patchSettings(h, map[string]any{"exitNode.enabled": true})

	waitFor(t, 5*time.Second, "the card to answer for an empty tailnet", func() bool {
		return exitNodeView(h).Capability.Degraded
	})
	view := exitNodeView(h)
	if !strings.Contains(view.Capability.Reason, "advertise itself") {
		t.Errorf("the reason reads %q, want it to say how a device becomes an exit node",
			view.Capability.Reason)
	}
}

// The module being off is the default every install runs on, and the card has to read as
// off rather than as a fault.
func TestTheCardReadsAsOffWhileTheModuleIsOff(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	view := exitNodeView(h)
	if view.Enabled || view.Capability.Available {
		t.Errorf("the card reads %+v, want it off", view)
	}
	if !strings.Contains(view.Capability.Reason, "leaves from here") {
		t.Errorf("the reason reads %q, want it to say traffic leaves from this device",
			view.Capability.Reason)
	}
}

// A device list that could not be read is the reason for exactly as long as it is still
// the reason. Once the node is down that is what the card has to say, or the user is sent
// after a stale failure while the real cause sits one line below it.
func TestTheCardStopsBlamingAnOldFailureOnceTheNodeIsDown(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	patchSettings(h, map[string]any{"exitNode.enabled": true})

	h.node.failPeers(errors.New("the backend has not finished starting"))
	waitFor(t, 5*time.Second, "the card to report the unreadable device list", func() bool {
		return strings.Contains(exitNodeView(h).Capability.Reason, "not finished starting")
	})

	h.node.setState(tsnode.StateNeedsLogin)
	waitFor(t, 5*time.Second, "the card to stop blaming the older failure", func() bool {
		return !strings.Contains(exitNodeView(h).Capability.Reason, "not finished starting")
	})
	if reason := exitNodeView(h).Reason; !strings.Contains(reason, "not running") {
		t.Errorf("the card reads %q, want the node being down named as the reason", reason)
	}
}

// The empty suggestion is the ordinary answer on a tailnet whose exit nodes are all
// self-hosted, and saying so plainly is the difference between "no suggestion" and "this
// button is broken".
func TestAnEmptySuggestionIsAnAnswerRatherThanAFailure(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	resp, body := h.request(http.MethodPost, "/api/exitnode/suggest", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/exitnode/suggest = %d: %s", resp.StatusCode, body)
	}
	var got httpapi.ExitNodeSuggestion
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode the suggestion: %v", err)
	}
	if got.ID != "" {
		t.Errorf("the tailnet suggested %q with nothing configured to suggest", got.ID)
	}
	if !strings.Contains(got.Reason, "no exit node to suggest") {
		t.Errorf("the answer reads %q, want it to say the tailnet has no suggestion", got.Reason)
	}
}

// A real suggestion has to come back with the device and where it is, since a picker of
// hosted exit nodes is unusable without the place.
func TestASuggestionCarriesTheDeviceAndItsPlace(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setSuggestion(tsnode.Suggestion{
		ID:   "n7",
		Name: "mullvad-berlin",
		Location: tsnode.PeerLocation{
			Country: "Germany", CountryCode: "de", City: "Berlin",
		},
	}, nil)
	h.bringUp()

	resp, body := h.request(http.MethodPost, "/api/exitnode/suggest", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/exitnode/suggest = %d: %s", resp.StatusCode, body)
	}
	var got httpapi.ExitNodeSuggestion
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode the suggestion: %v", err)
	}
	if got.ID != "n7" || got.Label != "mullvad-berlin" {
		t.Errorf("the suggestion is %+v, want the device the tailnet named", got)
	}
	if got.City != "Berlin" || got.Country != "Germany" {
		t.Errorf("the suggestion is %+v, want where the device is", got)
	}
}

// Asking a node that is not running cannot be answered, and has to read as unavailable
// rather than as the tailnet having no suggestion.
func TestSuggestingIsUnavailableWhileTheNodeIsDown(t *testing.T) {
	h := newHarness(t, nil)

	resp, body := h.request(http.MethodPost, "/api/exitnode/suggest", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/exitnode/suggest = %d: %s, want 503 while the node is down",
			resp.StatusCode, body)
	}
}

// The picker's choices are facts about the tailnet, so the schema endpoint has to fill
// them: a schema-driven form has no exit-node fetch of its own to fall back on.
func TestTheDevicePickerIsFilledFromWhatTheTailnetOffers(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(
		exitNodePeer("n1", "gateway", "100.64.0.1"),
		tsnode.Peer{ID: "n2", HostName: "away", ExitNodeOption: true},
	)
	h.bringUp()

	patchSettings(h, map[string]any{"exitNode.enabled": true})
	waitFor(t, 5*time.Second, "the tailnet's devices to reach the picker", func() bool {
		return len(h.agent.exitNodeChoices()) == 2
	})

	var picker config.FieldSchema
	for _, f := range h.agent.Settings().Schema() {
		if f.Key == "exitNode.nodeId" {
			picker = f
		}
	}
	if picker.Key == "" {
		t.Fatal("the schema offers no exitNode.nodeId setting to pick a device with")
	}
	if len(picker.Options) != 2 {
		t.Fatalf("the picker offers %+v, want both devices the tailnet approved", picker.Options)
	}
	if picker.Options[0].Value != "n1" || picker.Options[0].Label != "gateway" {
		t.Errorf("the first choice is %+v, want the online device named", picker.Options[0])
	}
	if !strings.Contains(picker.Options[1].Help, "Offline") {
		t.Errorf("the offline choice reads %q, want it to say choosing it stops traffic",
			picker.Options[1].Help)
	}
}

// exitNodeDecision publishes a decision the way a reconcile pass does, for the tests
// about what the mirror is handed. Going through publish rather than assigning the fields
// is what keeps the override bookkeeping under test rather than restated here.
func exitNodeDecision(agent *Agent, chosen, storedAtTheTime string) {
	agent.exitNode.publish(exitnode.State{Current: chosen}, nil, storedAtTheTime, 0)
}

// mirrorAgent is an agent that was constructed and never started. What the mirror hands
// the node is a pure read of the last decision and the settings passed in, and a running
// reconcile pass is a second writer of that decision -- one that would republish it
// underneath a test at whatever moment the machine happened to be busy.
func mirrorAgent(t *testing.T) *Agent {
	t.Helper()
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
	return agent
}

// exitNodeCandidates is the candidate list a peer set produces, which is what the probe
// takes.
func exitNodeCandidates(h *harness, peers ...tsnode.Peer) []exitnode.Candidate {
	h.t.Helper()
	return exitnode.Candidates(peers)
}

// The order of the reasons is the behaviour: each one is true at the same time as the
// ones below it, and the card shows exactly one. Reporting "no exit node is chosen" while
// the node is down sends the user to the picker for a problem no choice there fixes.
func TestTheCardGivesTheFirstReasonThatExplainsTheOthers(t *testing.T) {
	// Everything is wrong at once: the module is on, a read failed, the node is down,
	// the tailnet offers nothing, nothing is chosen and nothing is carrying traffic.
	on := config.Settings{ExitNodeEnabled: true}
	worst := httpapi.ExitNodeView{}
	withChoice := httpapi.ExitNodeView{
		Candidates: []httpapi.ExitNodeCandidate{{ID: "n1"}},
		Current:    "n1",
	}

	tests := []struct {
		name        string
		settings    config.Settings
		view        httpapi.ExitNodeView
		failure     string
		nodeProblem string
		available   bool
		degraded    bool
		want        string
	}{
		{
			name: "the module is off", settings: config.Settings{}, view: worst,
			failure: "a read failed", nodeProblem: "still starting",
			want: "module is off",
		},
		{
			name: "a read failed", settings: on, view: worst,
			failure: "read the device list: connection reset", nodeProblem: "still starting",
			available: true, degraded: true, want: "connection reset",
		},
		{
			name: "the node is down", settings: on, view: worst,
			nodeProblem: "still starting",
			available:   true, degraded: true, want: "not running (still starting)",
		},
		{
			name: "the tailnet offers none", settings: on, view: worst,
			available: true, degraded: true, want: "advertise itself",
		},
		{
			name: "nothing is chosen", settings: on,
			view:      httpapi.ExitNodeView{Candidates: []httpapi.ExitNodeCandidate{{ID: "n1"}}},
			available: true, degraded: true, want: "No exit node is chosen",
		},
		{
			name: "the chosen device is away", settings: on, view: withChoice,
			available: true, degraded: true, want: "nothing leaks",
		},
		{
			name: "everything is working", settings: on,
			view: httpapi.ExitNodeView{
				Candidates: withChoice.Candidates, Current: "n1", LiveOnline: true,
			},
			available: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := exitNodeCapability(tc.settings, tc.view, tc.failure, tc.nodeProblem)
			if got.Available != tc.available || got.Degraded != tc.degraded {
				t.Errorf("available/degraded = %v/%v, want %v/%v",
					got.Available, got.Degraded, tc.available, tc.degraded)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Errorf("reason = %q, want it to carry %q", got.Reason, tc.want)
			}
		})
	}
}

// A tailnet that cannot be asked is a failure, not an absence. Answering 200 with an
// empty suggestion would tell the user their tailnet offers none, which is a different
// problem with a different fix.
func TestASuggestionThatCouldNotBeAskedForIsAFailureRatherThanAnAbsence(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setSuggestion(tsnode.Suggestion{}, errors.New("the control plane refused"))
	h.bringUp()

	resp, body := h.request(http.MethodPost, "/api/exitnode/suggest", nil)

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("POST /api/exitnode/suggest = 200: %s, want the failure reported", body)
	}
	if !strings.Contains(string(body), "the control plane refused") {
		t.Errorf("the answer reads %s, want the reason the tailnet gave", body)
	}
}

// Rotation without a stated next time reads as a schedule that has stopped. The card is
// the only place a user can tell a rotating exit node from a pinned one.
func TestARotatingCardSaysWhenTheNextChangeIsDue(t *testing.T) {
	clock := newTestClock()
	h := newHarnessWith(t, nil, func(o *Options) { o.Clock = clock.Now })
	h.node.setPeers(
		exitNodePeer("n1", "one", "100.64.0.1"),
		exitNodePeer("n2", "two", "100.64.0.2"),
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled": true, "exitNode.rotate.enabled": true,
		"exitNode.rotate.intervalSec": 600,
	})
	waitForExitNodeID(h, "n1", "rotation to start on the first offered device")

	view := exitNodeView(h)
	if !view.Rotating {
		t.Fatalf("the card reads %+v, want it rotating", view)
	}
	if view.NextChange == "" {
		t.Fatal("the card names no next change, so a rotating exit node reads as a pinned one")
	}
	next, err := time.Parse(time.RFC3339, view.NextChange)
	if err != nil {
		t.Fatalf("the next change reads %q, which a client cannot parse: %v", view.NextChange, err)
	}
	if !next.After(clock.Now()) {
		t.Errorf("the next change is %s, which is not after now (%s)", next, clock.Now())
	}
}

// Pausing on active connections must weigh what is actually open. An idle proxy -- which
// is every machine that never turned the module on, and the default -- has to leave the
// schedule alone, or rotation stops for the people it was safest for.
func TestRotationIsNotHeldBackByAProxyThatIsCarryingNothing(t *testing.T) {
	clock := newTestClock()
	h := newHarnessWith(t, nil, func(o *Options) { o.Clock = clock.Now })
	h.node.setPeers(
		exitNodePeer("n1", "one", "100.64.0.1"),
		exitNodePeer("n2", "two", "100.64.0.2"),
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled": true, "exitNode.rotate.enabled": true,
		"exitNode.rotate.intervalSec": 120, "exitNode.rotate.pauseOnActive": true,
	})
	waitForExitNodeID(h, "n1", "rotation to start on the first offered device")

	clock.advance(3 * time.Minute)
	// One pass, deliberately: a pass that deferred would move on a later one anyway once
	// the deferral budget ran out, and that would read as the schedule working.
	h.agent.reconcileNow(context.Background())

	if prefs, _ := h.node.prefsState(); prefs.ExitNodeID != "n2" {
		t.Errorf("the node holds %q after the interval elapsed, want the schedule to have "+
			"moved rather than waited on connections that cannot exist", prefs.ExitNodeID)
	}
}

// The same guard, at the moment it actually fires: between construction and the node
// starting -- which every start and every restart passes through -- there is no proxy to
// ask, and an absent one carries nothing.
func TestAnAbsentProxyCarriesNothingRatherThanReadingAsBusy(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := agent.proxyActiveConns(); got != 0 {
		t.Errorf("proxyActiveConns = %d before the proxy exists, want nothing in flight", got)
	}
}

// The measurement latch is claimed before the node is read. Returning without releasing it
// would leave latency frozen at whatever it was for the rest of the process's life, and
// the latency strategy silently pinned to a stale ranking.
func TestAMeasurementRoundWithNoNodeReleasesTheLatchItClaimed(t *testing.T) {
	// An agent between construction and its node starting, which is also the window a
	// restart passes through.
	store, err := config.Open(filepath.Join(t.TempDir(), config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	agent.probeExitNodes(t.Context(), []exitnode.Candidate{{ID: "n1", Addr: netip.MustParseAddr("100.64.0.1")}})

	if !agent.exitNode.beginProbe() {
		t.Fatal("a measurement round is still held open, so none will ever run again")
	}
	agent.exitNode.endProbe(nil)
}

// waitForExitNodeIDUnprompted is waitForExitNodeID without the poke: nothing external
// asks the agent to look again, so only the schedule's own timer can move it.
func waitForExitNodeIDUnprompted(h *harness, want string, what string) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if prefs, _ := h.node.prefsState(); prefs.ExitNodeID == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	prefs, edits := h.node.prefsState()
	h.t.Fatalf("timed out after 10s waiting for %s with nothing poking the agent; the node "+
		"holds %q after %d edits, want %q", what, prefs.ExitNodeID, edits, want)
}

// Rotation is the one thing here no event drives: nothing changes on the tailnet when a
// device's turn is up. If the schedule only moved when something else happened to wake
// the agent, an idle machine -- which is the case rotation exists for -- would sit on one
// exit node indefinitely while the dashboard said it was rotating.
func TestTheScheduleMovesTheExitNodeWithNothingElseHappening(t *testing.T) {
	clock := newTestClock()
	h := newHarnessWith(t, nil, func(o *Options) { o.Clock = clock.Now })
	h.node.setPeers(
		exitNodePeer("n1", "one", "100.64.0.1"),
		exitNodePeer("n2", "two", "100.64.0.2"),
	)
	h.bringUp()
	h.node.publishPrefs(tsnode.Prefs{})

	patchSettings(h, map[string]any{
		"exitNode.enabled":              true,
		"exitNode.rotate.enabled":       true,
		"exitNode.rotate.intervalSec":   60,
		"exitNode.rotate.pauseOnActive": false,
	})
	waitForExitNodeID(h, "n1", "rotation to start on the first offered device")

	// One second short of the interval, so the pass this poke drives arms the timer for
	// a second rather than for the whole interval -- the same arithmetic a real run does,
	// at a length a test can wait out.
	clock.advance(59 * time.Second)
	h.agent.reconcileNow(context.Background())
	clock.advance(2 * time.Second)

	waitForExitNodeIDUnprompted(h, "n2", "the schedule's own timer to move to the next device")
}
