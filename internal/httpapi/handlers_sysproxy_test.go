// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"testing"
)

// The card is only useful if it reaches the client whole. The switch being on and the
// machine actually pointing at the proxy are separate answers, and on a platform that
// cannot be changed without an administrator the manual command and the reason are the
// only things the user can act on -- a view that dropped either would leave the card
// saying the feature is broken.
func TestTheSystemProxyViewCarriesWhatWasAskedForWhatIsInForceAndHowToFixIt(t *testing.T) {
	h := newHarness(t)

	view := decode[SystemProxyView](t, h.do(t, http.MethodGet, "/api/proxy/system", nil))

	if !view.Enabled || view.Applied {
		t.Errorf("the view reads enabled=%v applied=%v, want the switch and the machine reported apart",
			view.Enabled, view.Applied)
	}
	if view.Platform != "darwin" || view.Supported {
		t.Errorf("the view reads platform=%q supported=%v, want this machine's own answer",
			view.Platform, view.Supported)
	}
	if len(view.Manual) != 1 || view.Manual[0].Command == "" {
		t.Errorf("the view offers %+v, want the command the user has to run themselves", view.Manual)
	}
	if !view.Capability.Degraded || view.Capability.Reason == "" {
		t.Errorf("the view reads %+v, want the limitation stated rather than left to look like a bug",
			view.Capability)
	}
}
