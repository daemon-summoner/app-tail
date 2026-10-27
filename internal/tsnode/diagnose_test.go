// SPDX-License-Identifier: MIT

package tsnode

import (
	"strings"
	"testing"
)

func TestDiagnoseExplainsNonInteractiveFailures(t *testing.T) {
	tests := []struct {
		name        string
		mode        AuthMode
		state       string
		tags        []string
		backendErr  string
		wantPhrases []string
		wantEmpty   bool
	}{
		{
			name:        "oauth stuck in NeedsLogin names the likely causes",
			mode:        AuthOAuth,
			state:       StateNeedsLogin,
			tags:        []string{"tag:app-tail"},
			wantPhrases: []string{"tag:app-tail", "Tag setup", "auth_keys", "approval"},
		},
		{
			name:        "oauth with no tags says a tag is required",
			mode:        AuthOAuth,
			state:       StateNeedsLogin,
			wantPhrases: []string{"tag is set", "ownerless"},
		},
		{
			name:        "backend error is carried through",
			mode:        AuthOAuth,
			state:       StateNeedsLogin,
			tags:        []string{"tag:app-tail"},
			backendErr:  "key cannot be used for node auth",
			wantPhrases: []string{"key cannot be used for node auth"},
		},
		{
			name:        "auth key failure explains expiry and reuse",
			mode:        AuthKey,
			state:       StateNeedsLogin,
			wantPhrases: []string{"expired", "reusable", "pre-authorization"},
		},
		{
			name:        "machine auth explains device approval regardless of mode",
			mode:        AuthInteractive,
			state:       StateNeedsMachineAuth,
			wantPhrases: []string{"approval", "admin console"},
		},
		{
			name:      "interactive NeedsLogin is normal and needs no explanation",
			mode:      AuthInteractive,
			state:     StateNeedsLogin,
			wantEmpty: true,
		},
		{
			name:        "interactive with advertised tags and a backend error points at tag setup",
			mode:        AuthInteractive,
			state:       StateNeedsLogin,
			tags:        []string{"tag:app-tail"},
			backendErr:  "requested tags are invalid or not permitted",
			wantPhrases: []string{"tag:app-tail", "Tag setup", "Advertise tags", "requested tags are invalid or not permitted"},
		},
		{
			name:      "interactive with advertised tags but no backend error stays quiet",
			mode:      AuthInteractive,
			state:     StateNeedsLogin,
			tags:      []string{"tag:app-tail"},
			wantEmpty: true,
		},
		{
			// Exported contract: called with a backend error but no tags, the message
			// still forms and offers the escape hatch rather than the tagOwners fix.
			name:        "interactive backend error without tags still offers the escape hatch",
			mode:        AuthInteractive,
			state:       StateNeedsLogin,
			backendErr:  "login rejected",
			wantPhrases: []string{"login rejected", "Advertise tags on login", "untagged"},
		},
		{
			name:      "running needs no explanation",
			mode:      AuthOAuth,
			state:     StateRunning,
			tags:      []string{"tag:app-tail"},
			wantEmpty: true,
		},
		{
			name:      "starting is transient and needs no explanation",
			mode:      AuthOAuth,
			state:     StateStarting,
			tags:      []string{"tag:app-tail"},
			wantEmpty: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Diagnose(tc.mode, tc.state, tc.tags, tc.backendErr)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("Diagnose returned %q, want no explanation", got)
				}
				return
			}
			if got == "" {
				t.Fatal("Diagnose returned no explanation for a diagnosable failure")
			}
			for _, phrase := range tc.wantPhrases {
				if !strings.Contains(got, phrase) {
					t.Errorf("explanation %q does not mention %q", got, phrase)
				}
			}
		})
	}
}

func TestNodeDiagnoseOnlyAppliesToNonInteractiveCredentials(t *testing.T) {
	t.Run("interactive node records no problem", func(t *testing.T) {
		n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
		n.diagnose(StateNeedsLogin)
		if got := n.Status().Problem; got != "" {
			t.Errorf("Problem = %q; needing login is the normal interactive path", got)
		}
	})

	t.Run("oauth node records a problem", func(t *testing.T) {
		n := newTestNode(t, AuthOAuth, newScriptedBus(), nil)
		n.diagnose(StateNeedsLogin)
		if got := n.Status().Problem; got == "" {
			t.Error("an OAuth node stuck at NeedsLogin recorded no explanation")
		}
	})

	t.Run("interactive node advertising tags explains a control rejection", func(t *testing.T) {
		n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
		// The watcher stores control's error here; diagnose wraps it with the fix.
		n.status.Problem = "requested tags are invalid or not permitted"
		n.diagnose(StateNeedsLogin)
		got := n.Status().Problem
		if !strings.Contains(got, "Tag setup") {
			t.Errorf("Problem = %q, want an explanation pointing at Tag setup", got)
		}
	})

	t.Run("reaching Running clears a previous problem", func(t *testing.T) {
		n := newTestNode(t, AuthOAuth, newScriptedBus(), nil)
		n.diagnose(StateNeedsLogin)
		if n.Status().Problem == "" {
			t.Fatal("precondition: expected a recorded problem")
		}
		n.diagnose(StateRunning)
		if got := n.Status().Problem; got != "" {
			t.Errorf("Problem = %q, want it cleared once the node is Running", got)
		}
	})
}
