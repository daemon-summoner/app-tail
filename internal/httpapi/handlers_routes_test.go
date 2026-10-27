// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The limits are the whole reason this module can be shipped honestly. A user who finds
// out that DNS does not work across a route they configured -- by watching it fail --
// files a bug against a router that is doing everything it can.
func TestTheRoutesViewStatesWhatAUserspaceRouterCannotDo(t *testing.T) {
	h := newHarness(t)

	view := decode[RoutesView](t, h.do(t, http.MethodGet, "/api/routes", nil))

	if len(view.Capability.Limits) == 0 {
		t.Fatal("the view states no limits, so nothing tells a user that UDP does not cross these routes")
	}
	joined := strings.ToLower(strings.Join(view.Capability.Limits, " "))
	for _, want := range []string{"udp", "dns", "own address"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the stated limits never mention %q: %v", want, view.Capability.Limits)
		}
	}
}

// Advertised and Approved answer different questions, and the gap between them is the
// most common reason a subnet route does nothing at all. Collapsing them into one list
// would hide the only state a user can act on.
func TestTheRoutesViewReportsBothDirectionsSeparately(t *testing.T) {
	h := newHarness(t)

	view := decode[RoutesView](t, h.do(t, http.MethodGet, "/api/routes", nil))

	if len(view.Reaching) != 1 || view.Reaching[0] != "192.168.1.0/24" {
		t.Errorf("reaching = %v, want the networks peers carry to this device", view.Reaching)
	}
	if len(view.Advertised) != 1 || view.Advertised[0] != "10.20.0.0/24" {
		t.Errorf("advertised = %v, want the networks this device offers", view.Advertised)
	}
	if len(view.Approved) != 1 || view.Approved[0] != "10.20.0.0/24" {
		t.Errorf("approved = %v, want the networks the tailnet granted", view.Approved)
	}
	if !view.Serving || view.Carried != 3 {
		t.Errorf("serving = %v and carried = %d, want the router's own state carried through",
			view.Serving, view.Carried)
	}
}

// Probing every device advertising a route is a round trip per device. On a GET the
// dashboard's own polling would run it continuously, which is why it is a POST that
// happens only when someone asks.
func TestCheckingRoutesOnlyProbesWhenAsked(t *testing.T) {
	h := newHarness(t)

	h.do(t, http.MethodGet, "/api/routes", nil)
	if h.routes.checked != 0 {
		t.Errorf("reading the view probed %d times, want a read to probe nothing", h.routes.checked)
	}

	result := decode[RouteCheckResult](t, h.do(t, http.MethodPost, "/api/routes/check", nil))
	if h.routes.checked != 1 {
		t.Errorf("the check ran %d probes, want exactly one", h.routes.checked)
	}
	if len(result.Routes) != 1 || !result.Routes[0].Reachable {
		t.Fatalf("check = %+v, want the reachable route it found", result.Routes)
	}
	if len(result.Routes[0].Via) != 1 || result.Routes[0].Via[0] != "gateway" {
		t.Errorf("via = %v, want the device carrying the route named", result.Routes[0].Via)
	}
}

// A probe that could not run is a failure of the request, not an answer to it: reporting
// it as "no route is reachable" would send a user looking for a network problem that
// does not exist.
func TestAProbeThatCouldNotRunIsReportedAsAFailure(t *testing.T) {
	h := newHarness(t)
	h.routes.checkErr = errors.New("the backend is not answering")

	resp := h.do(t, http.MethodPost, "/api/routes/check", nil)

	if resp.Code < 400 {
		t.Fatalf("POST /api/routes/check = %d for a probe that failed, want an error: %s",
			resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "not answering") {
		t.Errorf("the response does not carry the backend's own reason: %s", resp.Body.String())
	}
}
