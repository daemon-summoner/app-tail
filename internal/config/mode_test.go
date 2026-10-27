// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"testing"
)

// The mode screen offers three cards and every card writes a combination of the switches
// below it. If the reading of those switches disagreed with what a card wrote, choosing a
// mode would leave the screen showing a different one selected.
func TestEveryModeIsReadBackFromTheSwitchesThatChoseIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*Settings)
		want  RunMode
	}{
		{
			name:  "nothing on",
			apply: func(*Settings) {},
			want:  RunStandalone,
		},
		{
			name:  "the proxy on",
			apply: func(s *Settings) { s.ProxyEnabled = true },
			want:  RunProxy,
		},
		{
			name: "the interface chosen",
			apply: func(s *Settings) {
				s.InterfaceEnabled = true
				s.InterfaceMode = NetworkTUN
			},
			want: RunInterface,
		},
		{
			// The switches layer, so this is a real configuration rather than an
			// impossible one, and it has to read as exactly one mode.
			name: "the interface chosen with the proxy also on",
			apply: func(s *Settings) {
				s.ProxyEnabled = true
				s.InterfaceEnabled = true
				s.InterfaceMode = NetworkTUN
			},
			want: RunInterface,
		},
		{
			// Turning the module on only offers the mode. Reading that as the machine
			// being on an interface would claim a change that has not happened and
			// needs a privileged helper to happen at all.
			name:  "the interface module on but not selected",
			apply: func(s *Settings) { s.InterfaceEnabled = true },
			want:  RunStandalone,
		},
		{
			// The stored mode outlives the module switch, so a document that was in
			// interface mode and had the module turned off must not still read as one.
			name:  "the interface selected but the module off",
			apply: func(s *Settings) { s.InterfaceMode = NetworkTUN },
			want:  RunStandalone,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Defaults().Settings
			tc.apply(&s)

			if got := PrimaryMode(s); got != tc.want {
				t.Errorf("PrimaryMode = %q, want %q", got, tc.want)
			}
		})
	}
}

// Choosing a mode writes the option's own patch, and this is what reads it back. If the
// two halves disagreed, the picker would not stay where it was put -- which looks like a
// save that silently failed.
func TestChoosingAModeLeavesTheMachineInThatMode(t *testing.T) {
	for _, option := range runModeOptions {
		t.Run(option.Value, func(t *testing.T) {
			if len(option.Applies) == 0 {
				t.Fatalf("mode %q names no settings, so choosing it would write nothing",
					option.Value)
			}

			// From every mode, not just from the default: a card has to arrive at its own
			// mode from whichever one the machine is already in.
			for _, from := range runModeOptions {
				s := Defaults().Settings
				applyModeChoice(t, &s, from)
				applyModeChoice(t, &s, option)

				if got := PrimaryMode(s); string(got) != option.Value {
					t.Errorf("choosing %q from %q leaves the machine in %q",
						option.Value, from.Value, got)
				}
			}
		})
	}
}

// applyModeChoice writes one mode's patch the way the dashboard does: through the same
// registry a save goes through, so a key that no longer exists fails here rather than
// silently writing nothing.
func applyModeChoice(t *testing.T, s *Settings, option EnumOption) {
	t.Helper()
	patch := make(map[string]json.RawMessage, len(option.Applies))
	for key, value := range option.Applies {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encoding %s for mode %q: %v", key, option.Value, err)
		}
		patch[key] = encoded
	}
	if err := ApplySettingsPatch(s, patch); err != nil {
		t.Fatalf("applying mode %q: %v", option.Value, err)
	}
}

// The mode is served through the schema, so a card renders the agent's reading rather
// than repeating the rule in TypeScript.
func TestTheServedViewCarriesTheModeAndOffersEveryCard(t *testing.T) {
	s := Defaults().Settings
	s.ProxyEnabled = true

	view := BuildSettingsView(s)

	if view["mode.primary"] != string(RunProxy) {
		t.Errorf("mode.primary = %v, want %q", view["mode.primary"], RunProxy)
	}

	field, ok := fieldByJSONKey["mode.primary"]
	if !ok {
		t.Fatal("mode.primary is not in the registry, so no form can render it")
	}
	offered := make(map[string]bool, len(field.Options))
	for _, o := range field.Options {
		if o.Label == "" || o.Help == "" {
			t.Errorf("mode %q is offered with no %s", o.Value,
				map[bool]string{true: "label", false: "explanation"}[o.Label == ""])
		}
		offered[o.Value] = true
	}
	for _, want := range []RunMode{RunStandalone, RunProxy, RunInterface} {
		if !offered[string(want)] {
			t.Errorf("the mode picker does not offer %q", want)
		}
	}
}
