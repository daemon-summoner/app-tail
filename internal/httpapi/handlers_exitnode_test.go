// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The card is one read: the device asked for, the device the backend reports, what the
// tailnet offers, and why. A view that dropped any of them would have the dashboard
// making a second call for it or, worse, guessing.
func TestTheExitNodeViewCarriesBothSidesAndTheDevicesOnOffer(t *testing.T) {
	h := newHarness(t)

	view := decode[ExitNodeView](t, h.do(t, http.MethodGet, "/api/exitnode", nil))

	if !view.Enabled || view.Current != "nABC" || view.CurrentLabel != "gateway" {
		t.Errorf("the view reads %+v, want it on and naming the chosen device", view)
	}
	if view.LiveID != "nABC" || !view.LiveOnline {
		t.Errorf("the view reports live %q/%v, want what the backend says is carrying traffic",
			view.LiveID, view.LiveOnline)
	}
	if len(view.Candidates) != 1 || !view.Candidates[0].Current {
		t.Errorf("the view offers %+v, want the tailnet's devices with the one in use marked",
			view.Candidates)
	}
	if view.Warning == "" {
		t.Error("the view carries no warning, so a control that drops every connection has none beside it")
	}
	if !view.Capability.Available {
		t.Errorf("the view reads %+v, want the module working", view.Capability)
	}
}

// A recommendation is a round trip to the control plane, not a read of local state: it
// must not be reachable by a GET that a cache or a link prefetch would repeat.
func TestARecommendationIsOnlyReachableByPost(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/exitnode/suggest", nil)

	if rec.Code == http.StatusOK {
		t.Fatal("a GET produced a recommendation, so a prefetch would call the control plane")
	}
	if h.exitNode.suggested != 0 {
		t.Errorf("the control plane was asked %d times by a GET", h.exitNode.suggested)
	}
}

// The recommendation reaches the client whole: a picker of hosted exit nodes is unusable
// without the place, so dropping it would make the answer unactionable.
func TestARecommendationReachesTheClientWithWhereTheDeviceIs(t *testing.T) {
	h := newHarness(t)

	got := decode[ExitNodeSuggestion](t, h.do(t, http.MethodPost, "/api/exitnode/suggest", nil))

	if got.ID != "nXYZ" || got.Label != "mullvad-berlin" {
		t.Errorf("the recommendation is %+v, want the device the tailnet named", got)
	}
	if got.City != "Berlin" || got.Country != "Germany" {
		t.Errorf("the recommendation is %+v, want where the device is", got)
	}
	if h.exitNode.suggested != 1 {
		t.Errorf("the control plane was asked %d times, want once", h.exitNode.suggested)
	}
}

// A node that cannot answer is a 503 with a reason, not a 500 and not an empty
// recommendation: "your tailnet has nothing to suggest" and "nothing could be asked" send
// a user to two different places.
func TestARecommendationTheNodeCannotGiveIsUnavailableRatherThanEmpty(t *testing.T) {
	h := newHarness(t)
	h.exitNode.suggestErr = Unavailable("suggesting an exit node", "the tailnet node is not running")

	rec := h.do(t, http.MethodPost, "/api/exitnode/suggest", nil)

	requireStatus(t, rec, http.StatusServiceUnavailable)
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "not running") {
		t.Errorf("the error reads %q, want it to say why nothing could be asked", body.Error)
	}
}

// Any other refusal is the control plane's, and it has to reach the user rather than
// being flattened into an empty answer that reads as "no suggestion".
func TestAControlPlaneRefusalIsReportedRatherThanSwallowed(t *testing.T) {
	h := newHarness(t)
	h.exitNode.suggestErr = errors.New("control plane said no")

	rec := h.do(t, http.MethodPost, "/api/exitnode/suggest", nil)

	if rec.Code == http.StatusOK {
		t.Fatalf("a refused recommendation answered 200: %s", rec.Body.String())
	}
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "control plane said no") {
		t.Errorf("the error reads %q, want the refusal it was given", body.Error)
	}
}
