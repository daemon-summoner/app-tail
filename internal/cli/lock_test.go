// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/httpapi"
)

// lockRoutes answers the endpoints the lock commands read and write, recording what was
// sent to the signing one.
func lockRoutes(t *testing.T, view httpapi.LockView, log []httpapi.LockUpdate, signed *[]byte) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/lock": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, view)
		},
		"GET /api/lock/log": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, log)
		},
		"POST /api/lock/sign": func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read the sign request body: %v", err)
			}
			if signed != nil {
				*signed = raw
			}
			writeJSONResponse(t, w, http.StatusOK, view)
		},
	}
}

// lockedOutView is the state every new device lands in on a tailnet with lock enabled.
func lockedOutView() httpapi.LockView {
	return httpapi.LockView{
		Enabled:     true,
		Signed:      false,
		NodeKey:     "nodekey:aabb",
		LockKey:     "tlpub:ccdd",
		SignCommand: "tailscale lock sign nodekey:aabb tlpub:ccdd",
		Trusted: []httpapi.LockKeyView{
			{ID: "tlpub:eeff", Kind: "person", Votes: 2, Label: "pre-auth key"},
		},
		Visible:  2,
		Filtered: []httpapi.LockPeerView{{ID: "n7", Name: "laptop", NodeKey: "nodekey:zz"}},
		Capability: httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "This device is not signed for tailnet lock yet, so it can reach no device on your tailnet.",
		},
	}
}

// A terminal is where someone lands after "the app says Running and I see no devices".
// The command that fixes it has to be there, on its own line, ready to copy -- describing
// it would leave them assembling two keys by hand.
func TestLockPrintsTheCommandThatFixesALockedOutDevice(t *testing.T) {
	h := newHarness(t, lockRoutes(t, lockedOutView(), nil, nil))

	if err := Run(t.Context(), append([]string{"lock"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("lock: %v", err)
	}
	out := h.out()
	for _, want := range []string{
		"not signed",
		"tailscale lock sign nodekey:aabb tlpub:ccdd",
		"This device is not signed for tailnet lock yet",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lock output is missing %q:\n%s", want, out)
		}
	}
}

// Peers lock is holding back are the other half of an empty device list, and a count
// alone would leave the user with nowhere to look.
func TestLockNamesThePeersItIsHoldingBack(t *testing.T) {
	h := newHarness(t, lockRoutes(t, lockedOutView(), nil, nil))

	if err := Run(t.Context(), append([]string{"lock"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if !strings.Contains(h.out(), "laptop") {
		t.Errorf("lock output does not name the held-back device:\n%s", h.out())
	}
}

// Lock off is the ordinary case, and it must read as a plain fact rather than as an empty
// table with nothing filled in.
func TestLockSaysSoPlainlyWhenTheTailnetHasNoLock(t *testing.T) {
	view := httpapi.LockView{Capability: httpapi.Capability{Available: true}}
	h := newHarness(t, lockRoutes(t, view, nil, nil))

	if err := Run(t.Context(), append([]string{"lock"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("lock: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "Tailnet lock is off") {
		t.Errorf("lock output does not say lock is off:\n%s", out)
	}
	// No command is offered, because there is nothing to sign.
	if strings.Contains(out, "tailscale lock sign") {
		t.Errorf("lock offers a signing command on a tailnet with no lock:\n%s", out)
	}
}

// A signed device must not be handed the command: printing it would have a user ask an
// administrator to fix something that is not broken.
func TestLockOffersNoCommandToADeviceThatIsAlreadySigned(t *testing.T) {
	view := lockedOutView()
	view.Signed = true
	h := newHarness(t, lockRoutes(t, view, nil, nil))

	if err := Run(t.Context(), append([]string{"lock"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if strings.Contains(h.out(), "Run this on a device") {
		t.Errorf("lock offers a signing command to a signed device:\n%s", h.out())
	}
}

func TestLockAsJSONIsTheAgentsOwnAnswer(t *testing.T) {
	h := newHarness(t, lockRoutes(t, lockedOutView(), nil, nil))

	if err := Run(t.Context(), append([]string{"lock"}, append(h.cfg(), "--json")...), h.env()); err != nil {
		t.Fatalf("lock --json: %v", err)
	}
	var got httpapi.LockView
	if err := json.Unmarshal([]byte(h.out()), &got); err != nil {
		t.Fatalf("parse the JSON output: %v\n%s", err, h.out())
	}
	if got.NodeKey != "nodekey:aabb" || got.Signed {
		t.Errorf("JSON output = %+v, want the agent's own view", got)
	}
}

func TestLockLogPrintsTheAuthoritysHistory(t *testing.T) {
	log := []httpapi.LockUpdate{
		{Hash: "abc123", Change: "added key tlpub:eeff"},
		{Hash: "def456", Change: "signed nodekey:aabb"},
	}
	h := newHarness(t, lockRoutes(t, lockedOutView(), log, nil))

	if err := Run(t.Context(), append([]string{"lock", "log"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("lock log: %v", err)
	}
	for _, want := range []string{"abc123", "added key tlpub:eeff", "def456"} {
		if !strings.Contains(h.out(), want) {
			t.Errorf("lock log output is missing %q:\n%s", want, h.out())
		}
	}
}

func TestLockLogSaysSoWhenNothingHasEverChanged(t *testing.T) {
	h := newHarness(t, lockRoutes(t, lockedOutView(), nil, nil))

	if err := Run(t.Context(), append([]string{"lock", "log"}, h.cfg()...), h.env()); err != nil {
		t.Fatalf("lock log: %v", err)
	}
	if !strings.Contains(h.out(), "no recorded changes") {
		t.Errorf("lock log does not explain an empty history:\n%s", h.out())
	}
}

// Both keys reach the agent, in the order `tailscale lock sign` takes them, so a command
// copied from that tool works here unchanged.
func TestLockSignSendsBothKeysInTheOrderTailscaleTakesThem(t *testing.T) {
	var sent []byte
	h := newHarness(t, lockRoutes(t, lockedOutView(), nil, &sent))

	args := append([]string{"lock", "sign", "nodekey:beef", "tlpub:cafe"}, h.cfg()...)
	if err := Run(t.Context(), args, h.env()); err != nil {
		t.Fatalf("lock sign: %v", err)
	}

	var body struct {
		NodeKey     string `json:"nodeKey"`
		RotationKey string `json:"rotationKey"`
	}
	if err := json.Unmarshal(sent, &body); err != nil {
		t.Fatalf("parse the request body %q: %v", sent, err)
	}
	if body.NodeKey != "nodekey:beef" || body.RotationKey != "tlpub:cafe" {
		t.Errorf("sent %+v, want the two keys in the order they were typed", body)
	}
}

// The rotation key is optional, and requiring it would make the common one-key case
// impossible from the command line.
func TestLockSignAcceptsADeviceKeyOnItsOwn(t *testing.T) {
	var sent []byte
	h := newHarness(t, lockRoutes(t, lockedOutView(), nil, &sent))

	args := append([]string{"lock", "sign", "nodekey:beef"}, h.cfg()...)
	if err := Run(t.Context(), args, h.env()); err != nil {
		t.Fatalf("lock sign: %v", err)
	}
	if !strings.Contains(string(sent), `"nodekey:beef"`) {
		t.Errorf("sent %q, want the one key that was typed", sent)
	}
}

// A misspelt subcommand that fell through to the status view would look like it worked
// while doing nothing the user asked for. Signing with no key at all is the same defect:
// the agent would refuse, but only after a round trip that reads as a backend problem.
func TestLockChecksItsArguments(t *testing.T) {
	for _, args := range [][]string{
		{"lock", "frobnicate"},
		{"lock", "logg"},
		{"lock", "sign"},
		{"lock", "sign", "nodekey:a", "tlpub:b", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			h := newHarness(t, lockRoutes(t, lockedOutView(), nil, nil))
			err := Run(t.Context(), append(args, h.cfg()...), h.env())
			if !errors.Is(err, ErrUsage) {
				t.Errorf("%v = %v, want a usage error:\n%s", args, err, h.out())
			}
			for _, r := range h.recorded() {
				if r.Method != http.MethodGet {
					t.Errorf("%v was refused and still sent %s %s", args, r.Method, r.Path)
				}
			}
		})
	}
}
