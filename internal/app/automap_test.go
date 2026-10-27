// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/automap"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// autoMapOn is a config the module is switched on in, mapping one port.
func autoMapOn(c *config.Config) {
	c.Settings.AutoMapEnabled = true
	c.Settings.AutoMapPorts = []string{"22"}
}

func testPeer(id, name string) tsnode.Peer {
	return tsnode.Peer{
		ID:       id,
		HostName: name,
		DNSName:  name + ".tail1a2b.ts.net",
		IPs:      []string{"100.64.0.9"},
		Online:   true,
	}
}

// derivedForwards is the subset of the forwards list a module produced.
func derivedForwards(h *harness) []httpapi.ForwardView {
	var out []httpapi.ForwardView
	for _, f := range h.agent.Forwards().List() {
		if f.Source == httpapi.SourceAuto {
			out = append(out, f)
		}
	}
	return out
}

// waitForDerived polls until the reconcile loop has published the expected number of
// derived forwards, since a peer change reaches them through a node event.
func waitForDerived(h *harness, want int) []httpapi.ForwardView {
	h.t.Helper()
	var got []httpapi.ForwardView
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got = derivedForwards(h)
		if len(got) == want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %d derived forwards, have %d: %+v", want, len(got), got)
	return nil
}

// byID indexes forward views so a test can name the row it means rather than depend on
// the order the list happens to come back in.
func byID(views []httpapi.ForwardView) map[string]httpapi.ForwardView {
	out := make(map[string]httpapi.ForwardView, len(views))
	for _, v := range views {
		out[v.ID] = v
	}
	return out
}

// The promise the app makes on install: nothing a user did not ask for. A module that
// opened a listener per device on a fresh state dir would break it on the first run.
func TestNoPortIsMappedWhileTheModuleIsOff(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(testPeer("nA", "alpha"), testPeer("nB", "beta"))
	h.bringUp()

	if got := derivedForwards(h); len(got) != 0 {
		t.Errorf("%d ports were mapped with the module off: %+v", len(got), got)
	}
	if stored := h.store.Get().AutoMap; len(stored) != 0 {
		t.Errorf("%d port assignments were recorded with the module off: %v", len(stored), stored)
	}

	view := h.agent.AutoMap().View()
	if view.Enabled {
		t.Error("the module reports itself on with nobody having turned it on")
	}
}

// The feature itself: a device the tailnet reports becomes a local port, reachable by
// name, with no per-device configuration.
func TestEveryDeviceGetsALocalPort(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"), testPeer("nB", "beta"))
	h.bringUp()

	got := waitForDerived(h, 2)
	targets := make(map[string]int, len(got))
	for _, f := range got {
		targets[f.Target] = f.ListenPort
	}

	for _, want := range []string{"alpha.tail1a2b.ts.net:22", "beta.tail1a2b.ts.net:22"} {
		port, ok := targets[want]
		if !ok {
			t.Errorf("no local port reaches %s; mapped %v", want, targets)
			continue
		}
		if port < config.DefaultAutoMapPortBase {
			t.Errorf("%s was mapped to %d, below the configured first port %d",
				want, port, config.DefaultAutoMapPortBase)
		}
	}
	if view := h.agent.AutoMap().View(); view.Mapped != 2 {
		t.Errorf("the module reports %d mapped, want 2", view.Mapped)
	}
}

// The assignment must reach the configuration file, because that is the only thing that
// makes the port survive a restart -- which is the whole reason to have the feature
// rather than telling people to run ssh over the proxy.
func TestAnAssignedPortIsRecordedBeforeAnythingDependsOnIt(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"))
	h.bringUp()

	got := waitForDerived(h, 1)
	stored := h.store.Get().AutoMap
	if len(stored) != 1 {
		t.Fatalf("recorded %d assignments, want 1: %v", len(stored), stored)
	}
	for key, port := range stored {
		// The connection is in front of the device because a device id is only unique
		// within the network that issued it, and an assignment nothing owns would be
		// claimed by whichever network reported that id next.
		if !strings.HasPrefix(key, config.PrimaryTunnelID+"/nA/") {
			t.Errorf("assignment key %q does not name the connection and the device's stable id", key)
		}
		if port != got[0].ListenPort {
			t.Errorf("recorded port %d but mapped %d", port, got[0].ListenPort)
		}
	}
}

// What a derived forward is -- its name, its port, what it reaches -- is rebuilt from the
// device list on every reconcile, so an edit to any of it would be silently undone.
// Refusing it by name, and naming the module, is what tells the user which switch to turn
// off to take the port over.
func TestADerivedForwardRefusesEditsAndSaysWhy(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"))
	h.bringUp()
	id := waitForDerived(h, 1)[0].ID

	ctx := context.Background()
	renamed, moved := "mine now", 19999
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"rename", func() error {
			_, err := h.agent.Forwards().Update(ctx, id, httpapi.ForwardSpec{Name: &renamed})
			return err
		}},
		{"move", func() error {
			_, err := h.agent.Forwards().Update(ctx, id, httpapi.ForwardSpec{ListenPort: &moved})
			return err
		}},
		{"delete", func() error { return h.agent.Forwards().Delete(ctx, id) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("the write was accepted, so it would be undone on the next reconcile")
			}
			if !strings.Contains(err.Error(), config.ModuleLabel(config.ModuleAutoMap)) {
				t.Errorf("error %q does not name the module that owns the forward", err)
			}
		})
	}

	// ...and the forward is still there and still running afterwards.
	if got := waitForDerived(h, 1); !got[0].Enabled {
		t.Error("a refused write still managed to disable the forward")
	}
}

// Switching one mapping off is the one gesture that is not an edit to what the module
// derived: it says this device should not be mapped, which is a choice the module has
// nowhere else to record. Without it the only lever is the module's own switch, so not
// wanting one port open costs every other mapping on the machine.
func TestOneMappingCanBeSwitchedOffWithoutTurningTheModuleOff(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"), testPeer("nB", "beta"))
	h.bringUp()
	derived := waitForDerived(h, 2)
	off, other := derived[0], derived[1]

	view, err := h.agent.Forwards().SetEnabled(context.Background(), off.ID, false)
	if err != nil {
		t.Fatalf("switching one mapping off: %v", err)
	}
	if view.Enabled {
		t.Error("the answer says the mapping is still on")
	}

	got := byID(waitForDerived(h, 2))
	if got[off.ID].Enabled {
		t.Error("the mapping is still enabled after the next reconcile, so the choice did not stick")
	}
	if got[off.ID].Listening != "" {
		t.Errorf("the mapping still holds %q, so the port was never released", got[off.ID].Listening)
	}
	// The row stays: there is nothing else to switch it back on with.
	if got[off.ID].ListenPort != off.ListenPort {
		t.Errorf("listen port = %d, want %d kept: the number is still owed to that device",
			got[off.ID].ListenPort, off.ListenPort)
	}
	if !got[other.ID].Enabled {
		t.Error("switching one mapping off took another one down with it")
	}
}

// Switching it back on is the other half, and without it the first half is a delete
// wearing a switch's clothes.
func TestAMappingSwitchedOffComesBackWhenItIsSwitchedOn(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"))
	h.bringUp()
	id := waitForDerived(h, 1)[0].ID

	ctx := context.Background()
	if _, err := h.agent.Forwards().SetEnabled(ctx, id, false); err != nil {
		t.Fatalf("switching the mapping off: %v", err)
	}
	if _, err := h.agent.Forwards().SetEnabled(ctx, id, true); err != nil {
		t.Fatalf("switching the mapping back on: %v", err)
	}

	got := byID(waitForDerived(h, 1))
	if !got[id].Enabled {
		t.Error("the mapping did not come back on")
	}
	// Nothing is left behind naming a mapping that is on, or the document grows a record
	// per switch flip that means nothing.
	if off := h.store.Get().AutoMapOff; len(off) != 0 {
		t.Errorf("the document still records %v as switched off", off)
	}
}

// A derived forward is readable like any other: the dashboard has to be able to show
// its counters, it just must not offer the controls that would edit it.
func TestADerivedForwardIsReadableAndMarkedAsDerived(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"))
	h.bringUp()
	id := waitForDerived(h, 1)[0].ID

	view, err := h.agent.Forwards().Get(id)
	if err != nil {
		t.Fatalf("a derived forward could not be read: %v", err)
	}
	if view.Source != httpapi.SourceAuto {
		t.Errorf("source = %q, want %q so the dashboard hides the edit controls",
			view.Source, httpapi.SourceAuto)
	}
	if view.Listening == "" {
		t.Error("the derived forward reports no listening address, so it never bound")
	}
}

// A device list that cannot be read is a transient backend state, not a reason to tear
// down every mapping: dropping them would close ports that things are connected
// through, and put them back moments later.
func TestMappingsSurviveADeviceListThatCannotBeRead(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"))
	h.bringUp()
	before := waitForDerived(h, 1)[0]

	h.node.failPeers(errors.New("the backend is not answering"))
	h.agent.pokeReconcile()

	// Waiting on the reason rather than on the forward count: the mapping is expected
	// to be unchanged, so its count says nothing about whether the failing reconcile
	// has run yet.
	waitFor(t, 5*time.Second, "the module to report the unreadable device list", func() bool {
		return strings.Contains(h.agent.AutoMap().View().Reason, "device list")
	})

	after := waitForDerived(h, 1)[0]
	if after.ListenPort != before.ListenPort {
		t.Errorf("the mapping moved from %d to %d when the device list failed",
			before.ListenPort, after.ListenPort)
	}
	if after.Target != before.Target {
		t.Errorf("the mapping now reaches %s rather than %s", after.Target, before.Target)
	}
}

// Devices past the limit are counted and explained. Silence would leave someone
// concluding their newest device does not work.
func TestDevicesPastTheLimitAreExplainedRatherThanMissing(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		autoMapOn(c)
		c.Settings.AutoMapMax = 1
	})
	h.node.setPeers(testPeer("nA", "alpha"), testPeer("nB", "beta"), testPeer("nC", "gamma"))
	h.bringUp()

	waitForDerived(h, 1)
	view := h.agent.AutoMap().View()
	if view.Truncated != 2 {
		t.Errorf("Truncated = %d, want the 2 devices the limit left out", view.Truncated)
	}
	if !strings.Contains(view.Reason, "limit") {
		t.Errorf("reason = %q, want it to name the limit as the cause", view.Reason)
	}
}

// Forgetting is what keeps the assignment map from growing without bound, and it must
// need a device list it can trust: pruning against an empty one would renumber every
// device on the next pass.
func TestForgettingNeedsARunningNodeAndDropsOnlyWhatIsGone(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"), testPeer("nB", "beta"))
	h.bringUp()
	waitForDerived(h, 2)

	h.node.setState(tsnode.StateStopped)
	if _, err := h.agent.AutoMap().Forget(context.Background()); err == nil {
		t.Error("assignments were pruned against a device list the node could not supply")
	}

	h.node.setState(tsnode.StateRunning)
	h.node.setPeers(testPeer("nA", "alpha"))
	waitForDerived(h, 1)

	removed, err := h.agent.AutoMap().Forget(context.Background())
	if err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed %d assignments, want the one whose device is gone", removed)
	}
	if stored := h.store.Get().AutoMap; len(stored) != 1 {
		t.Errorf("%d assignments remain, want only the device still on the tailnet: %v",
			len(stored), stored)
	}
}

// A running node whose device list cannot be read is not the same as a device list that
// came back empty, and pruning against the second one would renumber every device. The
// read has to fail the request rather than be treated as "nothing is out there".
func TestForgettingRefusesADeviceListThatCouldNotBeRead(t *testing.T) {
	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"))
	h.bringUp()
	waitForDerived(h, 1)

	h.node.failPeers(errors.New("the backend is not answering"))

	removed, err := h.agent.AutoMap().Forget(context.Background())
	if err == nil {
		t.Fatalf("assignments were pruned against a device list that could not be read (%d removed)", removed)
	}
	if !strings.Contains(err.Error(), "not answering") {
		t.Errorf("error = %v, want it to carry the reason the device list failed", err)
	}
	if stored := h.store.Get().AutoMap; len(stored) != 1 {
		t.Errorf("%d assignments remain, want the one that was never safely prunable: %v",
			len(stored), stored)
	}
}

// A mapping must never take a port a configured forward already owns: the configured
// one is what the user set up deliberately, and the derived one would fail to bind and
// report the device as broken.
func TestAMappingNeverTakesAConfiguredForwardsPort(t *testing.T) {
	// The port a mapping reaches for first, so what is under test is the refusal that
	// matters: skipping a claimed port is only interesting when that port was the
	// preferred one. Reserved rather than the shipped default, because the default is a
	// fixed number an app-tail running on this machine is already listening on, and a
	// forward that cannot bind never reaches the state this waits for.
	taken := freePort(t)
	h := newHarness(t, func(c *config.Config) {
		autoMapOn(c)
		c.Settings.AutoMapPortBase = taken
		c.Forwards = append(c.Forwards, config.Forward{
			ID: "manual", Name: "manual", Direction: config.ToLocal, Protocol: config.TCP,
			BindAddr: config.DefaultBindAddr, ListenPort: taken,
			Target: "somewhere.tail1a2b.ts.net:22", Enabled: true,
		})
	})
	h.node.setPeers(testPeer("nA", "alpha"))
	h.bringUp()

	got := waitForDerived(h, 1)[0]
	if got.ListenPort == taken {
		t.Errorf("the mapping took port %d, which a configured forward already listens on", taken)
	}
	if !strings.HasPrefix(got.ID, automap.IDPrefix) {
		t.Errorf("id %q does not carry the prefix that makes it refuse edits", got.ID)
	}
}

// A prune that could not be stored must be reported, not counted: the caller is told how
// many assignments went, and a number that was never written down would have the
// dashboard show them gone while the next start hands the same devices the same ports.
func TestForgettingReportsAPruneItCouldNotStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bits this test depends on")
	}
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce the directory write bit the same way")
	}

	h := newHarness(t, autoMapOn)
	h.node.setPeers(testPeer("nA", "alpha"), testPeer("nB", "beta"))
	h.bringUp()
	waitForDerived(h, 2)

	h.node.setPeers(testPeer("nA", "alpha"))
	waitForDerived(h, 1)

	// The store writes through a temp file in the same directory, so revoking write
	// permission on it is what a state dir that cannot be written looks like.
	if err := os.Chmod(h.stateDir, 0o500); err != nil {
		t.Fatalf("make the state dir read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(h.stateDir, 0o700) })

	removed, err := h.agent.AutoMap().Forget(context.Background())

	if err == nil {
		t.Fatalf("a prune that was never stored reported %d assignments dropped", removed)
	}
	if removed != 0 {
		t.Errorf("removed = %d alongside a failure, want nothing counted as dropped", removed)
	}
	if stored := h.store.Get().AutoMap; len(stored) != 2 {
		t.Errorf("%d assignments remain in memory, want both still there after a failed write: %v",
			len(stored), stored)
	}
}

// An assignment is what makes a local port survive a restart, so it is written down
// before anything listens on it. A write that failed means the next run would hand the
// same device a different port -- so nothing is mapped at all, and the reason says so.
// Mapping anyway would put a port on screen that quietly moves the next time.
func TestAnAssignmentThatCouldNotBeWrittenMapsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bits this test depends on")
	}
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce the directory write bit the same way")
	}

	h := newHarness(t, autoMapOn)
	h.bringUp()
	waitForDerived(h, 0)

	// The store writes through a temp file in the same directory, so revoking write
	// permission on it is what a state dir that cannot be written looks like.
	if err := os.Chmod(h.stateDir, 0o500); err != nil {
		t.Fatalf("make the state dir read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(h.stateDir, 0o700) })

	h.node.setPeers(testPeer("nA", "alpha"))
	h.agent.pokeReconcile()

	waitFor(t, 5*time.Second, "the module to report the assignment it could not save", func() bool {
		return strings.Contains(h.agent.AutoMap().View().Reason, "could not be saved")
	})
	if got := derivedForwards(h); len(got) != 0 {
		t.Errorf("%d ports were mapped on assignments that were never written down: %+v", len(got), got)
	}
	if stored := h.store.Get().AutoMap; len(stored) != 0 {
		t.Errorf("%d assignments are held in memory that no restart would reproduce: %v", len(stored), stored)
	}
}
