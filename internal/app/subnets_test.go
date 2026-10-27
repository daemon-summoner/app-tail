// SPDX-License-Identifier: MIT

package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// waitForCarrying waits for the node to be carrying subnet connections, or not to be.
func waitForCarrying(h *harness, want bool, what string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.node.carrying() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("timed out after 5s waiting for %s; the node is carrying=%v, want %v",
		what, h.node.carrying(), want)
}

// The subnet router is only reachable at all once something installs its hook on the
// running node. Built but never wired, every setting in the routing module would save,
// report itself in force, and carry nothing.
func TestTurningOnCarryingTrafficInstallsTheRouterOnTheNode(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
	})
	h.bringUp()

	if h.node.carrying() {
		t.Fatal("the node is carrying subnet connections before the setting was turned on")
	}

	patchSettings(h, map[string]any{"routes.serve": true})
	waitForCarrying(h, true, "the router to be installed after the setting was turned on")

	patchSettings(h, map[string]any{"routes.serve": false})
	waitForCarrying(h, false, "the router to be removed after the setting was turned off")
}

// The hook belongs to the node's own network stack, so a node that is rebuilt leaves
// behind a router registered on an identity that no longer exists. Anything that kept
// the old registration would report itself as serving while carrying nothing.
func TestRestartingTheNodeMovesTheRouterToTheNewNode(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesServe = true
	})
	h.bringUp()
	waitForCarrying(h, true, "the router to be installed on the first node")
	before := h.agent.currentSubnets()

	resp, body := h.request(http.MethodPost, "/api/restart", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/restart = %d: %s", resp.StatusCode, body)
	}
	h.bringUp()
	waitForCarrying(h, true, "the router to be installed again after the node was rebuilt")

	if h.node.subnetStopCount() == 0 {
		t.Error("the router's old registration was never removed before the node was rebuilt")
	}
	// A router carried over from the rebuild would be one whose connections were all
	// cut with the node it belonged to: it would report itself as serving and cancel
	// every flow it accepted.
	if after := h.agent.currentSubnets(); after == before {
		t.Error("the same router is still published after the node it was registered on was rebuilt")
	} else if st := after.Status(); !st.Serving || st.Error != "" {
		t.Errorf("the rebuilt router reports serving=%v error=%q, want it carrying with nothing wrong",
			st.Serving, st.Error)
	}
}

// routesView reads the subnet-route surface the way the dashboard does.
func routesView(h *harness) httpapi.RoutesView {
	h.t.Helper()
	resp, body := h.get("/api/routes")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /api/routes = %d: %s", resp.StatusCode, body)
	}
	var view httpapi.RoutesView
	if err := json.Unmarshal(body, &view); err != nil {
		h.t.Fatalf("decode the routes view: %v", err)
	}
	return view
}

// The single most common way a subnet route does nothing: it is advertised, the settings
// all read as on, and no admin has approved it. Without the gap between the two lists on
// screen this is indistinguishable from a router that is broken.
func TestAdvertisedNetworksWaitingForApprovalSayExactlyThat(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesServe = true
		tailnetOf(t, c).RoutesAdvertise = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	})
	h.bringUp()
	waitForCarrying(h, true, "the router to be installed")

	view := routesView(h)

	// The whole surface is hidden while the module is off, so a view that does not say
	// the module is on takes the card with it however right the rest of it is.
	if !view.Enabled {
		t.Error("the view reports the routing module off although it is on")
	}
	if len(view.Advertised) != 1 || view.Advertised[0] != "10.20.0.0/24" {
		t.Errorf("advertised = %v, want the network this device offers", view.Advertised)
	}
	if len(view.Approved) != 0 {
		t.Errorf("approved = %v, want nothing approved on a tailnet where nobody approved it", view.Approved)
	}
	if !view.Capability.Degraded {
		t.Error("the view reports nothing wrong although no advertised network is approved")
	}
	if !strings.Contains(view.Capability.Reason, "approv") {
		t.Errorf("reason = %q, want it to name the approval that has not happened", view.Capability.Reason)
	}
}

// An approved network that this device refuses to carry is the other half of the same
// confusion: the tailnet is routing traffic here and every connection is being reset.
func TestApprovedNetworksNobodyIsCarryingSayExactlyThat(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesAdvertise = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	})
	h.node.approved = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	h.bringUp()

	view := routesView(h)

	if view.Serving {
		t.Fatal("the router reports it is carrying traffic although the setting is off")
	}
	if !view.Capability.Degraded {
		t.Error("the view reports nothing wrong although approved networks are being refused")
	}
	if !strings.Contains(view.Capability.Reason, "refused") {
		t.Errorf("reason = %q, want it to say the connections are being refused", view.Capability.Reason)
	}
}

// A module that is off must read as off rather than as broken: nothing is wrong with a
// feature nobody turned on, and reporting it as degraded trains a user to ignore the one
// place that says something really is.
func TestASwitchedOffRoutingModuleReadsAsOffRatherThanBroken(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	view := routesView(h)

	if view.Enabled {
		t.Error("the view reports the routing module on although nobody turned it on")
	}
	if view.Capability.Available || view.Capability.Degraded {
		t.Errorf("capability = %+v, want a module that is simply off", view.Capability)
	}
	if !strings.Contains(view.Capability.Reason, "off") {
		t.Errorf("reason = %q, want it to say the module is off", view.Capability.Reason)
	}
	if len(view.Capability.Limits) == 0 {
		t.Error("the limits are not stated while the module is off, which is when they inform a choice")
	}
}

// Every state this module can sit in has a different thing wrong with it and a different
// thing to do about it. One reason covering several of them is how a user ends up reading
// "waiting for approval" about a route nobody advertised, and the dashboard, the tray and
// the CLI all read this one answer.
func TestEveryStateSubnetRoutingCanSitInSaysWhatIsWrongWithThatOne(t *testing.T) {
	on := config.Settings{RoutesEnabled: true}

	for _, tc := range []struct {
		name        string
		settings    config.Settings
		view        httpapi.RoutesView
		nodeProblem string
		want        string
		available   bool
		degraded    bool
	}{{
		name:        "a node that is not running carries nothing in either direction",
		settings:    on,
		view:        httpapi.RoutesView{Accepting: true},
		nodeProblem: "no auth key",
		want:        "no auth key",
		available:   true, degraded: true,
	}, {
		name:      "a failure inside this device is reported in its own words",
		settings:  on,
		view:      httpapi.RoutesView{Accepting: true, Error: "the hook could not be installed"},
		want:      "the hook could not be installed",
		available: true, degraded: true,
	}, {
		// The module is on and neither half of it was chosen, which is the state a user
		// lands in the moment they switch it on and nothing else.
		name:      "a module switched on with nothing chosen says what to choose",
		settings:  on,
		view:      httpapi.RoutesView{},
		want:      "Nothing is chosen yet",
		available: true, degraded: true,
	}, {
		// Offering a network without accepting any is a whole, deliberate configuration:
		// this device is a subnet router and nothing else. Reading it as "nothing chosen"
		// would send a user to turn on a setting they meant to leave off.
		name:      "a device that only offers a network is not a device with nothing chosen",
		settings:  on,
		view:      httpapi.RoutesView{Advertised: []string{"10.20.0.0/24"}},
		want:      "waiting for approval",
		available: true, degraded: true,
	}, {
		name:      "accepting routes nobody advertises is the tailnet's doing, not this device's",
		settings:  on,
		view:      httpapi.RoutesView{Accepting: true},
		want:      "no device on your tailnet is advertising one",
		available: true, degraded: true,
	}, {
		// Carrying traffic with nothing offered is a switch that cannot do anything: the
		// tailnet has no route pointing here, so no connection will ever arrive.
		name:      "carrying traffic for no network of its own says so",
		settings:  on,
		view:      httpapi.RoutesView{Accepting: true, Reaching: []string{"192.168.1.0/24"}, Serving: true},
		want:      "offers no network",
		available: true, degraded: true,
	}, {
		name:     "a device reaching and carrying networks has nothing wrong with it",
		settings: on,
		view: httpapi.RoutesView{
			Accepting:  true,
			Reaching:   []string{"192.168.1.0/24"},
			Advertised: []string{"10.20.0.0/24"},
			Approved:   []string{"10.20.0.0/24"},
			Serving:    true,
		},
		want:      "",
		available: true, degraded: false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := routesCapability(tc.settings, tc.view, tc.nodeProblem)

			if got.Available != tc.available || got.Degraded != tc.degraded {
				t.Errorf("available=%v degraded=%v, want %v and %v",
					got.Available, got.Degraded, tc.available, tc.degraded)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Errorf("reason = %q, want it to contain %q", got.Reason, tc.want)
			}
			if tc.want == "" && got.Reason != "" {
				t.Errorf("reason = %q, want nothing said about a module that is working", got.Reason)
			}
			// The limits describe what a userspace router can carry rather than what it is
			// doing, so they belong on every answer including the one that says it is fine.
			if len(got.Limits) == 0 {
				t.Error("the limits are missing, so a client showing this reason states none of them")
			}
		})
	}
}

// A control plane that is not answering is a different thing from a tailnet with no
// routes, and the two render identically as an empty list. Swallowing the refusal would
// leave the card saying this device reaches nothing while it simply could not ask.
func TestARoutesViewThatCouldNotBeReadReportsTheRefusalRatherThanAnEmptyList(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesAccept = true
	})
	h.bringUp()
	h.node.failRoutes(errors.New("the control plane is not answering"))

	view := routesView(h)

	if view.Error != "the control plane is not answering" {
		t.Errorf("error = %q, want the refusal the node gave", view.Error)
	}
	if !view.Capability.Degraded || !strings.Contains(view.Capability.Reason, "not answering") {
		t.Errorf("capability = %+v, want the refusal reported as what is wrong", view.Capability)
	}
}

// The approved set is the one number a user acts on -- it is what says whether the
// approval they asked an admin for has happened. A backend that could not answer must not
// render as "still waiting", which is the same thing an unapproved route renders as.
func TestAnUnreadableApprovedSetIsReportedRatherThanShownAsUnapproved(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesAdvertise = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	})
	h.bringUp()
	h.node.mu.Lock()
	h.node.approvedErr = errors.New("the backend has no netmap yet")
	h.node.mu.Unlock()

	view := routesView(h)

	if view.Error != "the backend has no netmap yet" {
		t.Errorf("error = %q, want the refusal the node gave", view.Error)
	}
	if !strings.Contains(view.Capability.Reason, "no netmap yet") {
		t.Errorf("reason = %q, want the refusal rather than a claim about approval",
			view.Capability.Reason)
	}
}

// The hook belongs to the node's network stack and installing it can fail there. Losing
// that reason would leave the card reporting a router that is simply not serving, with
// nothing anywhere to say the install was refused.
func TestAHookTheNodeRefusedIsReportedOnTheCard(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesServe = true
		tailnetOf(t, c).RoutesAdvertise = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	})
	h.node.serveErr = errors.New("a handler is already installed")
	h.bringUp()

	view := routesView(h)

	if view.Serving {
		t.Fatal("the card reports this device carrying traffic although the hook was refused")
	}
	if view.Error != "a handler is already installed" {
		t.Errorf("error = %q, want the refusal the node gave", view.Error)
	}
}

// Probing needs a running node. Answering with an empty list instead would say every
// device carrying a route is unreachable, which is a much larger claim than "this device
// could not ask".
func TestCheckingRoutesWithoutARunningNodeIsRefusedRatherThanAnsweredEmpty(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesAccept = true
	})

	resp, body := h.request(http.MethodPost, "/api/routes/check", nil)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/routes/check = %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "not running") {
		t.Errorf("body = %s, want it to say the node is not running", body)
	}
}

// The probe reaches the tailnet, so it fails the way the tailnet fails. A refusal turned
// into an empty result would be read as an answer about the routes themselves.
func TestAProbeTheTailnetRefusedIsReportedAsAFailure(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesAccept = true
	})
	h.node.reachErr = errors.New("the netmap is not loaded yet")
	h.bringUp()

	resp, body := h.request(http.MethodPost, "/api/routes/check", nil)

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("POST /api/routes/check = 200 although the probe failed: %s", body)
	}
	if !strings.Contains(string(body), "netmap is not loaded") {
		t.Errorf("body = %s, want the refusal the tailnet gave", body)
	}
}

// Checking reachability probes every device advertising a route, so asking while the
// module is off would run that for nothing. Saying so beats an empty list, which reads
// as "no device is reachable".
func TestCheckingRoutesWhileNotAcceptingThemExplainsItselfRatherThanProbing(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Settings.RoutesEnabled = true })
	h.node.reach = []tsnode.RouteReach{{
		Prefix: netip.MustParsePrefix("192.168.1.0/24"), Via: []string{"gateway"},
	}}
	h.bringUp()

	resp, body := h.request(http.MethodPost, "/api/routes/check", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/routes/check = %d: %s", resp.StatusCode, body)
	}
	var result httpapi.RouteCheckResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode the check result: %v", err)
	}

	if len(result.Routes) != 0 {
		t.Errorf("routes = %+v, want nothing probed while this device accepts no routes", result.Routes)
	}
	if !strings.Contains(result.Reason, "not accepting") {
		t.Errorf("reason = %q, want it to say why nothing was checked", result.Reason)
	}
}

// A route in the netmap whose device does not answer is the state nothing else on the
// page distinguishes from a network that is simply misconfigured.
func TestCheckingRoutesReportsWhichDevicesAnswered(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesAccept = true
	})
	h.node.reach = []tsnode.RouteReach{
		{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Via: []string{"gateway"}},
		{Prefix: netip.MustParsePrefix("10.9.0.0/16")},
	}
	h.bringUp()

	resp, body := h.request(http.MethodPost, "/api/routes/check", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/routes/check = %d: %s", resp.StatusCode, body)
	}
	var result httpapi.RouteCheckResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode the check result: %v", err)
	}

	if len(result.Routes) != 2 {
		t.Fatalf("routes = %+v, want both accepted networks reported", result.Routes)
	}
	if !result.Routes[0].Reachable || len(result.Routes[0].Via) != 1 {
		t.Errorf("routes[0] = %+v, want the network its device answered for", result.Routes[0])
	}
	if result.Routes[1].Reachable {
		t.Errorf("routes[1] = %+v, want a network no device answered for reported as unreachable",
			result.Routes[1])
	}
}

// A probe that found nothing and a probe that could not run render identically as an
// empty list. On a tailnet where no peer advertises a route the empty answer is the
// correct one, and it still has to say which of the two it is.
func TestAProbeWithNoRoutesToCheckSaysThatRatherThanNothing(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.RoutesEnabled = true
		tailnetOf(t, c).RoutesAccept = true
	})
	h.bringUp()

	resp, body := h.request(http.MethodPost, "/api/routes/check", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/routes/check = %d: %s", resp.StatusCode, body)
	}
	var result httpapi.RouteCheckResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode the check result: %v", err)
	}

	if len(result.Routes) != 0 {
		t.Fatalf("routes = %+v, want nothing on a tailnet advertising no route", result.Routes)
	}
	if !strings.Contains(result.Reason, "advertising a network") {
		t.Errorf("reason = %q, want it to say no device is advertising one", result.Reason)
	}
}

// Every reconcile helper runs on a schedule the agent's own construction does not gate,
// so each has to answer for the window before the parts it reads exist. A nil dereference
// here takes the whole agent down on the way up.
func TestTheSubnetRouterIsLeftAloneUntilThereIsOneToReconcile(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	agent.applySubnets(true)
	agent.applySubnets(false)
}
