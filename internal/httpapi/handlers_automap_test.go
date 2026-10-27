// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Mapped and Stored answer different questions, and the gap between them is the whole
// reason forgetting exists: a user with nothing mapped and nothing remembered has a
// module that is off, and one with nothing mapped and three remembered has devices that
// went away still holding their ports.
func TestTheAutoMapViewSeparatesWhatIsMappedFromWhatIsRemembered(t *testing.T) {
	h := newHarness(t)

	view := decode[AutoMapView](t, h.do(t, http.MethodGet, "/api/automap", nil))

	if !view.Enabled {
		t.Error("the module reports itself off, but the view is built from a module that is on")
	}
	if view.Mapped != 2 || view.Stored != 3 {
		t.Errorf("mapped = %d and stored = %d, wanted the two reported separately as 2 and 3",
			view.Mapped, view.Stored)
	}
	if view.Truncated != 1 || view.Reason == "" {
		t.Errorf("truncated = %d with reason %q, want the devices the limit left out reported in words",
			view.Truncated, view.Reason)
	}
}

// Forgetting answers with the state afterwards rather than only a count. A client that
// had to re-read the view would race the reconcile that follows and render the mappings
// as they were a moment before the drop.
func TestForgettingAnswersWithWhatTheModuleLooksLikeAfterwards(t *testing.T) {
	h := newHarness(t)

	result := decode[autoMapForgetResult](t, h.do(t, http.MethodPost, "/api/automap/forget", nil))

	if h.autoMap.forgets != 1 {
		t.Errorf("forget ran %d times, want exactly one", h.autoMap.forgets)
	}
	if result.Removed != 1 {
		t.Errorf("removed = %d, want the one assignment that went", result.Removed)
	}
	if result.AutoMap.Stored != 2 {
		t.Errorf("the view reports %d stored, want the count after the drop rather than before",
			result.AutoMap.Stored)
	}
}

// Reading the view must not drop anything. The dashboard polls it, so a read with the
// side effect of forgetting would silently reassign a device's port every few seconds
// and break every bookmark pointing at it.
func TestReadingTheAutoMapViewForgetsNothing(t *testing.T) {
	h := newHarness(t)

	h.do(t, http.MethodGet, "/api/automap", nil)

	if h.autoMap.forgets != 0 {
		t.Errorf("reading the view forgot %d times, want a read to change nothing", h.autoMap.forgets)
	}
}

// A drop that could not be written is a failure of the request. Reporting it as "nothing
// was forgotten" is indistinguishable from a tailnet where every device is still there,
// and leaves a user re-pressing a button that cannot work.
func TestAForgetThatCouldNotBeWrittenIsReportedAsAFailure(t *testing.T) {
	h := newHarness(t)
	h.autoMap.forgetErr = errors.New("the configuration file is read-only")

	resp := h.do(t, http.MethodPost, "/api/automap/forget", nil)

	if resp.Code < 400 {
		t.Fatalf("POST /api/automap/forget = %d for a drop that failed, want an error: %s",
			resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "read-only") {
		t.Errorf("the response does not carry the reason the drop failed: %s", resp.Body.String())
	}
}

// An agent built without the module still routes these paths, so both have to answer
// that the module is absent rather than panic on a nil dependency.
func TestTheAutoMapEndpointsSayTheModuleIsAbsentRatherThanPanicking(t *testing.T) {
	h := newHarness(t)
	h.server.deps.AutoMap = nil

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/automap"},
		{http.MethodPost, "/api/automap/forget"},
	} {
		resp := h.do(t, tc.method, tc.path, nil)
		if resp.Code < 400 {
			t.Errorf("%s %s = %d with the module absent, want an error: %s",
				tc.method, tc.path, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "automatic ports") {
			t.Errorf("%s %s does not name the module that is missing: %s",
				tc.method, tc.path, resp.Body.String())
		}
	}
}
