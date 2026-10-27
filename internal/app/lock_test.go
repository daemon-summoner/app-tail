// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// lockedOut is the state every app-tail install lands in on a tailnet with lock enabled:
// the node connects, reports Running, and the control plane strips every peer from its
// netmap until an administrator signs it.
func lockedOut() tsnode.LockStatus {
	return tsnode.LockStatus{
		Enabled: true,
		Signed:  false,
		NodeKey: "nodekey:aabb",
		LockKey: "tlpub:ccdd",
		Trusted: []tsnode.LockKey{
			{ID: "tlpub:eeff", Kind: "person", Votes: 2, Meta: map[string]string{"purpose": "pre-auth key"}},
		},
		Head: "0f0f",
	}
}

func lockView(h *harness) httpapi.LockView {
	h.t.Helper()
	resp, raw := h.get("/api/lock")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /api/lock = %d: %s", resp.StatusCode, raw)
	}
	var view httpapi.LockView
	if err := json.Unmarshal(raw, &view); err != nil {
		h.t.Fatalf("decode %s: %v", raw, err)
	}
	return view
}

// The command is the entire remedy for a locked-out device, and it needs both this
// device's keys. Assembling it in a client would put its shape in a second place; leaving
// it out entirely leaves the user with a diagnosis they cannot act on.
func TestALockedOutDeviceIsHandedTheCommandThatFixesIt(t *testing.T) {
	h := newHarness(t, nil)
	h.node.lock = lockedOut()
	h.bringUp()

	view := lockView(h)

	if !view.Enabled || view.Signed {
		t.Fatalf("enabled = %v signed = %v, want the locked-out state", view.Enabled, view.Signed)
	}
	if view.SignCommand != "tailscale lock sign nodekey:aabb tlpub:ccdd" {
		t.Errorf("sign command = %q, want it to carry both of this device's keys", view.SignCommand)
	}
	if !view.Capability.Degraded {
		t.Error("the capability reads healthy for a device that can reach nothing")
	}
	if !strings.Contains(view.Capability.Reason, "not signed") {
		t.Errorf("reason = %q, want it to name the unsigned key", view.Capability.Reason)
	}
}

// A device that has not logged in yet has no node key to sign. Offering a command with an
// empty argument would have an administrator run something that cannot work.
func TestNoCommandIsOfferedBeforeThereIsAKeyToSign(t *testing.T) {
	h := newHarness(t, nil)
	h.node.lock = tsnode.LockStatus{Enabled: true, LockKey: "tlpub:ccdd"}
	h.bringUp()

	if cmd := lockView(h).SignCommand; cmd != "" {
		t.Errorf("sign command = %q, want none while this device has no node key", cmd)
	}
}

// Lock off is the ordinary case and must read as healthy. A tailnet that never enabled
// lock showing a degraded card would send every user of the default configuration looking
// for a problem that does not exist.
func TestATailnetWithoutLockReadsAsHealthy(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	view := lockView(h)

	if view.Enabled {
		t.Fatal("lock reads enabled on a tailnet that never turned it on")
	}
	if !view.Capability.Available || view.Capability.Degraded {
		t.Errorf("capability = %+v, want a plain healthy reading", view.Capability)
	}
}

// A signed device that can see peers it cannot reach is the other unexplainable state:
// the tailnet's own access rules say yes and lock says no.
func TestPeersLockHoldsBackAreReportedAsDegraded(t *testing.T) {
	h := newHarness(t, nil)
	h.node.lock = tsnode.LockStatus{
		Enabled: true, Signed: true, Visible: 3,
		Filtered: []tsnode.LockPeer{{ID: "n7", Name: "laptop", NodeKey: "nodekey:zz", IPs: []string{"100.64.0.7"}}},
	}
	h.bringUp()

	view := lockView(h)

	if !view.Capability.Degraded {
		t.Fatalf("capability = %+v, want degraded while peers are unreachable", view.Capability)
	}
	if len(view.Filtered) != 1 || view.Filtered[0].Name != "laptop" {
		t.Fatalf("filtered = %+v, want the held-back device named", view.Filtered)
	}
	if len(view.Filtered[0].IPs) != 1 {
		t.Errorf("filtered addresses = %v, want them carried for a device whose name says little",
			view.Filtered[0].IPs)
	}
}

// Keys are what an administrator picks between when deciding which one to revoke. What
// the tailnet recorded against a key is the only thing that tells a person-held key from
// one a script uses, so it has to survive the projection.
func TestATrustedKeyCarriesWhatTheTailnetRecordedAgainstIt(t *testing.T) {
	h := newHarness(t, nil)
	h.node.lock = lockedOut()
	h.bringUp()

	view := lockView(h)

	if len(view.Trusted) != 1 {
		t.Fatalf("trusted = %+v, want the tailnet's key", view.Trusted)
	}
	key := view.Trusted[0]
	if key.ID != "tlpub:eeff" || key.Votes != 2 || key.Kind != "person" {
		t.Errorf("key = %+v, want the backend's own identity, weight and kind", key)
	}
	if key.Label != "pre-auth key" {
		t.Errorf("label = %q, want what the tailnet recorded against the key", key.Label)
	}
}

// Metadata is open-ended. A key carrying something the app has never heard of must still
// be distinguishable from the others, and the label must not reshuffle between polls --
// map order is random, and a flickering label is indistinguishable from a changing one.
func TestAKeyWithUnfamiliarMetadataIsStillLabelledAndIsStable(t *testing.T) {
	key := tsnode.LockKey{
		ID:   "tlpub:eeff",
		Meta: map[string]string{"zone": "eu", "authkey_stableid": "kABC", "owner": "ops"},
	}

	first := lockKeyLabel(key)
	for range 20 {
		if got := lockKeyLabel(key); got != first {
			t.Fatalf("label = %q then %q; a label that reshuffles reads as a key that changed",
				first, got)
		}
	}
	for _, want := range []string{"zone: eu", "authkey_stableid: kABC", "owner: ops"} {
		if !strings.Contains(first, want) {
			t.Errorf("label = %q, want it to carry %q rather than drop it", first, want)
		}
	}
}

// A key with nothing recorded against it is shown as itself. An empty label would render
// a blank row an administrator cannot tell from the key beside it.
func TestAKeyWithNothingRecordedIsShownAsItself(t *testing.T) {
	if got := lockKeyLabel(tsnode.LockKey{ID: "tlpub:eeff"}); got != "tlpub:eeff" {
		t.Errorf("label = %q, want the key's own identity", got)
	}
}

// A failed read is a failed read. Reporting it as "lock is off" would tell a user their
// tailnet is unlocked on the strength of a backend that stopped answering.
func TestALockReadThatFailedIsNotReportedAsLockOff(t *testing.T) {
	h := newHarness(t, nil)
	h.node.lockErr = errors.New("the key authority is not answering")
	h.bringUp()

	view := lockView(h)

	if !view.Capability.Degraded {
		t.Fatalf("capability = %+v, want degraded for a read that failed", view.Capability)
	}
	if !strings.Contains(view.Capability.Reason, "not answering") {
		t.Errorf("reason = %q, want the backend's own words", view.Capability.Reason)
	}
	if view.Error == "" {
		t.Error("the view carries no error, so a client cannot tell a failed read from lock off")
	}
}

// Every lock operation needs a running node. Answering with an empty view rather than a
// refusal would render a "lock is off" card for a node that has not started.
func TestEveryLockOperationRefusesWhileTheNodeIsDown(t *testing.T) {
	agent := newUnstartedAgent(t)
	api := agent.LockAPI()
	ctx := context.Background()

	view := api.View(ctx)
	if view.Capability.Available {
		t.Errorf("capability = %+v, want unavailable while the node is down", view.Capability)
	}
	if view.Capability.Reason == "" {
		t.Error("no reason is given for a view that could not be read")
	}

	if _, err := api.Log(ctx); err == nil {
		t.Error("the log was read with no node running")
	}
	if err := api.Sign(ctx, "nodekey:aa", ""); err == nil {
		t.Error("a device was signed with no node running")
	}
	if err := api.DisableLocal(ctx); err == nil {
		t.Error("the lock state was forgotten with no node running")
	}
}

// The log is read at the size the boundary chooses. Passing a count from here would put
// the same number in two places, and passing zero is how the boundary is asked for its own.
func TestTheLogIsReadWithTheBoundarysOwnLimit(t *testing.T) {
	h := newHarness(t, nil)
	h.node.lockLog = []tsnode.LockUpdate{{Hash: "0f0f", Change: "added key tlpub:eeff"}}
	h.bringUp()

	entries, err := h.agent.LockAPI().Log(context.Background())
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(entries) != 1 || entries[0].Change != "added key tlpub:eeff" {
		t.Fatalf("log = %+v, want the entry the authority carries", entries)
	}
	if h.node.logMax != 0 {
		t.Errorf("the log was asked for %d entries; the boundary chooses that, not this layer",
			h.node.logMax)
	}
}

// Signing reaches the backend with both keys as sent. This layer must not interpret a
// key: only the tailscale boundary knows what a valid one is, and a check here would be
// the second place that is decided.
func TestSigningReachesTheBackendWithBothKeys(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	if err := h.agent.LockAPI().Sign(context.Background(), "nodekey:beef", "tlpub:cafe"); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(h.node.signed) != 1 || h.node.signed[0] != [2]string{"nodekey:beef", "tlpub:cafe"} {
		t.Errorf("signed = %+v, want both keys passed through", h.node.signed)
	}
}

// A refused signature must surface. Reporting success would leave the other device cut
// off with the UI claiming it was authorized.
func TestASignatureTheBackendRefusesIsPropagated(t *testing.T) {
	h := newHarness(t, nil)
	h.node.signErr = errors.New("this node is not trusted to sign")
	h.bringUp()

	err := h.agent.LockAPI().Sign(context.Background(), "nodekey:beef", "")
	if err == nil {
		t.Fatal("Sign reported success for a signature the backend refused")
	}
	if !strings.Contains(err.Error(), "not trusted to sign") {
		t.Errorf("error = %v, want the backend's own reason", err)
	}
}

// One answer feeds the dashboard, the tray and the CLI, so each state lock can sit in has
// to say what is wrong with that one. The dangerous confusion is the whole reason this is
// a switch rather than a boolean: "lock is off" and "lock could not be read" render the
// same empty card, and only one of them means the user is safe.
func TestEveryStateTailnetLockCanSitInSaysWhatIsWrongWithThatOne(t *testing.T) {
	for _, tc := range []struct {
		name        string
		view        httpapi.LockView
		nodeUp      bool
		nodeProblem string
		want        string
		available   bool
		degraded    bool
	}{{
		// The recorded reason is what distinguishes a node that is still starting from one
		// that will never start, and it is the only thing here a user can act on.
		name:        "a node that failed to start says why it did",
		nodeProblem: "control plane refused the auth key",
		want:        "refused the auth key",
	}, {
		name:   "a node that is simply not up yet still says nothing was read",
		want:   "cannot be read",
		nodeUp: false,
	}, {
		name:      "a read that failed is reported in its own words",
		view:      httpapi.LockView{Error: "the key authority is not answering"},
		nodeUp:    true,
		want:      "not answering",
		available: true, degraded: true,
	}, {
		name:      "a tailnet without lock is healthy rather than empty",
		nodeUp:    true,
		want:      "Tailnet lock is off",
		available: true,
	}, {
		name:      "an unsigned device is told it can reach nothing",
		view:      httpapi.LockView{Enabled: true},
		nodeUp:    true,
		want:      "not signed for tailnet lock yet",
		available: true, degraded: true,
	}, {
		name: "peers lock holds back are the other half of an empty device list",
		view: httpapi.LockView{
			Enabled: true, Signed: true,
			Filtered: []httpapi.LockPeerView{{ID: "n7", Name: "laptop"}},
		},
		nodeUp:    true,
		want:      "holding back some devices",
		available: true, degraded: true,
	}, {
		name:      "a signed device with nothing held back has nothing wrong with it",
		view:      httpapi.LockView{Enabled: true, Signed: true},
		nodeUp:    true,
		want:      "can reach every device",
		available: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := lockCapability(tc.view, tc.nodeUp, tc.nodeProblem)

			if got.Available != tc.available || got.Degraded != tc.degraded {
				t.Errorf("available=%v degraded=%v, want %v and %v",
					got.Available, got.Degraded, tc.available, tc.degraded)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Errorf("reason = %q, want it to contain %q", got.Reason, tc.want)
			}
		})
	}
}

// Forgetting local state is what a device whose copy has diverged does instead of
// deleting its state directory, which would also lose its identity on the tailnet.
func TestForgettingLocalStateReachesTheBackend(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	if err := h.agent.LockAPI().DisableLocal(context.Background()); err != nil {
		t.Fatalf("DisableLocal: %v", err)
	}
	if h.node.disabled != 1 {
		t.Errorf("the backend was asked %d times, want exactly one", h.node.disabled)
	}
}
