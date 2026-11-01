// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// tailnetWith is a primary connection carrying the preferences a case is about, which is
// where every one of them is stored now.
func tailnetWith(p TailnetPrefs) Tunnel {
	t := Tunnel{ID: PrimaryTunnelID, Slug: "tailnet", Name: "Tailnet", Type: TunnelTailscale, Enabled: true}
	t.Tailscale = &TailscaleTunnel{TailnetPrefs: p}
	return t
}

// Both questions read the module switch as well as the value beside it. A document that
// names a device with the module off describes a choice nobody made yet, and treating it
// as a selection is how a fresh install starts routing traffic through a stranger.
//
// The switch is folded in exactly once, by TailnetPrefsOf, so this asserts through it:
// what the node is asked for, what the dashboard reports and what a drift comparison is
// made against are all that one value.
func TestChoosingAndOfferingAnExitNodeBothRequireTheirModule(t *testing.T) {
	tests := []struct {
		name        string
		app         Settings
		prefs       TailnetPrefs
		selected    bool
		advertising bool
	}{
		{name: "nothing is on"},
		{
			name:  "a device is named but the module is off",
			prefs: TailnetPrefs{ExitNodeID: "nABC"},
		},
		{
			name: "the module is on with nothing named",
			app:  Settings{ExitNodeEnabled: true},
		},
		{
			name:     "a named device",
			app:      Settings{ExitNodeEnabled: true},
			prefs:    TailnetPrefs{ExitNodeID: "nABC"},
			selected: true,
		},
		{
			name:     "letting the tailnet choose",
			app:      Settings{ExitNodeEnabled: true},
			prefs:    TailnetPrefs{ExitNodeAuto: true},
			selected: true,
		},
		{
			name:  "advertising with the module off",
			prefs: TailnetPrefs{RoutesAdvertiseExitNode: true},
		},
		{
			name:        "advertising",
			app:         Settings{RoutesEnabled: true},
			prefs:       TailnetPrefs{RoutesAdvertiseExitNode: true},
			advertising: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.app.TailnetPrefsOf(tailnetWith(tc.prefs))
			if got.ExitNodeSelected() != tc.selected {
				t.Errorf("ExitNodeSelected() = %v, want %v", got.ExitNodeSelected(), tc.selected)
			}
			if got.RoutesAdvertiseExitNode != tc.advertising {
				t.Errorf("RoutesAdvertiseExitNode = %v, want %v", got.RoutesAdvertiseExitNode, tc.advertising)
			}
		})
	}
}

// A document written before the setting existed carries the zero value, and the answer
// it resolves to is the one that cannot surprise: traffic keeps waiting for an exit node
// rather than starting to leave from here.
func TestAnUnsetFailurePolicyHolds(t *testing.T) {
	tests := []struct {
		in   ExitNodeFailurePolicy
		want ExitNodeFailurePolicy
	}{
		{in: "", want: FailureHold},
		{in: FailureHold, want: FailureHold},
		{in: FailureNext, want: FailureNext},
		{in: FailureOff, want: FailureOff},
		{in: "something a later version writes", want: FailureHold},
	}

	for _, tc := range tests {
		p := TailnetPrefs{ExitNodeOnFailure: tc.in}
		if got := p.EffectiveExitNodeFailurePolicy(); got != tc.want {
			t.Errorf("policy %q resolved to %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Round-robin is the answer for an unset strategy because it is the only one that needs
// no measurement: falling back to latency would start pinging every candidate on a
// document that never asked for it.
func TestAnUnsetRotationStrategyWalksTheDevicesInTurn(t *testing.T) {
	tests := []struct {
		in   RotateStrategy
		want RotateStrategy
	}{
		{in: "", want: RotateRoundRobin},
		{in: RotateRoundRobin, want: RotateRoundRobin},
		{in: RotateRandom, want: RotateRandom},
		{in: RotateLatency, want: RotateLatency},
		{in: "something a later version writes", want: RotateRoundRobin},
	}

	for _, tc := range tests {
		p := TailnetPrefs{ExitNodeRotateStrategy: tc.in}
		if got := p.EffectiveRotateStrategy(); got != tc.want {
			t.Errorf("strategy %q resolved to %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The registry refuses anything under the floor at write time, so a document carrying one
// was hand-edited. Clamping it beats honouring it: a five-second rotation is a denial of
// service against the user's own connections.
func TestARotationIntervalIsDefaultedAndThenFloored(t *testing.T) {
	tests := []struct {
		name string
		secs int
		want time.Duration
	}{
		{name: "unset takes the default", secs: 0, want: DefaultExitNodeRotateIntervalSec * time.Second},
		{name: "negative takes the default", secs: -30, want: DefaultExitNodeRotateIntervalSec * time.Second},
		{name: "under the floor is raised", secs: 5, want: MinExitNodeRotateIntervalSec * time.Second},
		{name: "the floor itself is kept", secs: MinExitNodeRotateIntervalSec, want: MinExitNodeRotateIntervalSec * time.Second},
		{name: "a longer interval is kept", secs: 1800, want: 30 * time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := TailnetPrefs{ExitNodeRotateIntervalSec: tc.secs}
			if got := p.EffectiveRotateInterval(); got != tc.want {
				t.Errorf("EffectiveRotateInterval() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The refusal points at a setting by the name it carries on screen. Reading that name
// from the registry is what keeps the sentence true after a relabelling, so the test
// asserts they agree rather than repeating the current wording.
func TestRefusingBothExitNodeRolesNamesTheSettingToTurnOff(t *testing.T) {
	c := Defaults()
	c.Settings.ExitNodeEnabled = true
	c.Settings.RoutesEnabled = true
	for i := range c.Tunnels {
		if c.Tunnels[i].ID != PrimaryTunnelID {
			continue
		}
		ts := c.Tunnels[i].TS()
		ts.ExitNodeID = "nABC"
		ts.RoutesAdvertiseExitNode = true
		c.Tunnels[i].Tailscale = &ts
	}

	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted using an exit node while offering to be one")
	}
	label, ok := SettingByName("routes.advertiseExitNode")
	if !ok {
		t.Fatal("no routes.advertiseExitNode field for the sentence to name")
	}
	if !strings.Contains(err.Error(), label.Label) {
		t.Errorf("refusal is %q, want it to name %q", err, label.Label)
	}
}

// Sharing is on by default for installs that predate the setting, which a plain bool could
// not do: an absent key and a user's "off" would decode alike.
func TestADocumentWrittenBeforeIncomingExistedAllowsIt(t *testing.T) {
	var p TailnetPrefs
	if err := json.Unmarshal([]byte(`{"routes.serve":false}`), &p); err != nil {
		t.Fatal(err)
	}
	if !p.AllowsIncoming() {
		t.Error("a connection saved before this setting existed does not allow incoming connections")
	}
}

func TestTurningIncomingOffSurvivesBeingSaved(t *testing.T) {
	held := tailnetWith(TailnetPrefs{})
	field, ok := tunnelRegistry.ByJSONKey("incoming.allow")
	if !ok {
		t.Fatal("incoming.allow is not a registered connection field")
	}
	field.set(&held, false)

	saved, err := json.Marshal(held.TS().TailnetPrefs)
	if err != nil {
		t.Fatal(err)
	}
	var loaded TailnetPrefs
	if err := json.Unmarshal(saved, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.AllowsIncoming() {
		t.Errorf("a user's off came back on after a save and a load: %s", saved)
	}
}

// The value is shared by pointer, and the stored config must not change through a copy.
func TestAClonedPreferenceDoesNotShareIncomingWithItsOriginal(t *testing.T) {
	on := true
	original := TailnetPrefs{IncomingAllow: &on}
	copied := original.clone()
	*copied.IncomingAllow = false

	if !original.AllowsIncoming() {
		t.Error("changing a clone turned incoming connections off on the original")
	}
}

// Sharing is its own decision and no module's switch governs it. Masking it with routes
// off would leave the default install sharing nothing.
func TestIncomingStaysOnWithEveryModuleOff(t *testing.T) {
	var s Settings
	if !s.TailnetPrefsOf(tailnetWith(TailnetPrefs{})).AllowsIncoming() {
		t.Error("incoming connections read as off with the optional modules off")
	}
}
