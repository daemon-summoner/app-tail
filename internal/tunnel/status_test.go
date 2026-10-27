// SPDX-License-Identifier: MIT

package tunnel

import "testing"

// Every state a connection can be in has a word, because a colour alone is unreadable to
// anyone who cannot distinguish the hues and to anyone reading a log. A state added in Go and
// not added here has to render as itself rather than as nothing: a blank where the state
// belongs reads as a connection with no state at all.
func TestEveryStateHasAWordAndAnUnknownOneRendersAsItself(t *testing.T) {
	known := []State{
		StateOff, StateStarting, StateNeedsLogin, StateConnecting,
		StateConnected, StateDegraded, StateFailed, StateStopping,
	}
	seen := make(map[string]State, len(known))
	for _, state := range known {
		label := state.Label()
		if label == "" {
			t.Errorf("%q has no word", state)
			continue
		}
		if other, taken := seen[label]; taken {
			t.Errorf("%q and %q both read as %q, so the two cannot be told apart", state, other, label)
		}
		seen[label] = state
	}

	if got := State("wedged").Label(); got != "wedged" {
		t.Errorf("an unnamed state reads as %q, want the state itself", got)
	}
}
