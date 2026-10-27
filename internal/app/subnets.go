// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"net/netip"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/subnets"
)

func (a *Agent) currentSubnets() *subnets.Router {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.subnets
}

// applySubnets reconciles the subnet router with the current settings and node state.
//
// It carries nothing while the node is down, because the hook it installs belongs to
// that node's network stack: there is no equivalent of the proxy's bound port to keep
// alive and answer with a reason. A failure is logged rather than propagated -- it must
// not stop the rest of the reconcile, and the reason is published through the router's
// own status, which is where the dashboard shows it.
func (a *Agent) applySubnets(nodeUp bool) {
	router := a.currentSubnets()
	if router == nil {
		return
	}
	router.SetNodeUp(nodeUp)
	if err := router.Apply(); err != nil {
		a.logger.Warn("the subnet router could not be reconciled", "error", err)
	}
}

// routesAPI is the management API's view of subnet routing, both directions.
type routesAPI struct{ a *Agent }

var _ httpapi.Routes = routesAPI{}

// RoutesAPI exposes the subnet-route module.
func (a *Agent) RoutesAPI() httpapi.Routes { return routesAPI{a: a} }

// View reports which networks this device reaches through the tailnet and which it
// offers to carry back, with the reason whenever one of those is doing nothing.
func (t routesAPI) View(ctx context.Context) httpapi.RoutesView {
	a := t.a
	s := a.settings()
	// The primary connection's, because this view describes the node this process runs.
	// The module switch is already folded into them, so the two cannot disagree about
	// whether a route this app asked for is actually being asked for.
	p := a.primaryPrefs()

	view := httpapi.RoutesView{
		TunnelID:   config.PrimaryTunnelID,
		Enabled:    s.RoutesEnabled,
		Accepting:  p.RoutesAccept,
		Advertised: prefixStrings(p.AdvertisedSubnets()),
	}
	if router := a.currentSubnets(); router != nil {
		st := router.Status()
		view.Serving = st.Serving
		view.Carried, view.Refused = st.Carried, st.Refused
		view.BytesIn, view.BytesOut = st.BytesIn, st.BytesOut
		view.Error = st.Error
	}

	// Both lists come from the node rather than from the settings. A network this device
	// reaches is one a peer is carrying now, and a network it may carry is one an admin
	// approved -- neither is what this app asked for, and the difference is the whole
	// point of showing them.
	if node := a.currentNode(); node != nil && node.Status().Running() {
		reaching, err := node.Routes(ctx)
		if err != nil {
			a.logger.Debug("reading the networks this device reaches failed", "error", err)
			view.Error = err.Error()
		} else {
			view.Reaching = prefixStrings(reaching)
		}
		approved, err := node.ApprovedRoutes(ctx)
		if err != nil {
			a.logger.Debug("reading the networks the tailnet routes here failed", "error", err)
			view.Error = err.Error()
		} else {
			view.Approved = prefixStrings(approved)
		}
	}

	view.Capability = routesCapability(s, view, a.nodeProblem())
	return view
}

// Check probes the devices carrying each accepted route.
func (t routesAPI) Check(ctx context.Context) (httpapi.RouteCheckResult, error) {
	node := t.a.currentNode()
	if node == nil || !node.Status().Running() {
		return httpapi.RouteCheckResult{}, httpapi.Unavailable("checking subnet routes",
			"the tailnet node is not running")
	}
	if !t.a.primaryPrefs().RoutesAccept {
		return httpapi.RouteCheckResult{
			Reason: "This device is not accepting the networks its peers advertise, so there " +
				"is nothing to check.",
		}, nil
	}

	reach, err := node.RouteReachability(ctx)
	if err != nil {
		return httpapi.RouteCheckResult{}, err
	}
	result := httpapi.RouteCheckResult{Routes: make([]httpapi.RouteCheckEntry, 0, len(reach))}
	for _, r := range reach {
		result.Routes = append(result.Routes, httpapi.RouteCheckEntry{
			Prefix:    r.Prefix.String(),
			Via:       r.Via,
			Reachable: len(r.Via) > 0,
		})
	}
	if len(result.Routes) == 0 {
		result.Reason = "No device on your tailnet is advertising a network to this one."
	}
	return result, nil
}

// routesCapability answers "is subnet routing doing anything, and if not why" in one
// place, so the dashboard, the tray and the CLI cannot reach different conclusions.
//
// The order matters: each case is the reason the next one would otherwise be reported
// misleadingly. Advertising with nothing approved is the most common of them by far,
// and it is indistinguishable from a broken router without being said.
func routesCapability(s config.Settings, view httpapi.RoutesView, nodeProblem string) httpapi.Capability {
	limits := httpapi.RouteLimits()
	switch {
	case !s.RoutesEnabled:
		return httpapi.Capability{
			Reason: "The subnet routes module is off, so this device neither reaches the " +
				"networks its peers advertise nor offers any of its own.",
			Limits: limits,
		}
	case nodeProblem != "":
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The tailnet node is not running (" + nodeProblem + "), so no route is carried " +
				"in either direction.",
			Limits: limits,
		}
	case view.Error != "":
		return httpapi.Capability{Available: true, Degraded: true, Reason: view.Error, Limits: limits}
	case !view.Accepting && len(view.Advertised) == 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Nothing is chosen yet: turn on reaching the networks other devices advertise, " +
				"or name a network for this device to offer.",
			Limits: limits,
		}
	case view.Accepting && len(view.Reaching) == 0 && len(view.Advertised) == 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "This device accepts routes, but no device on your tailnet is advertising one.",
			Limits: limits,
		}
	case len(view.Advertised) > 0 && len(view.Approved) == 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The networks this device offers are waiting for approval. Until an admin " +
				"approves them in the Tailscale admin console, your tailnet sends this device " +
				"no traffic for them at all.",
			Limits: limits,
		}
	case len(view.Approved) > 0 && !view.Serving:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Your tailnet routes these networks here, but carrying traffic for them is " +
				"switched off, so every connection to them is refused.",
			Limits: limits,
		}
	case view.Serving && len(view.Advertised) == 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Carrying traffic is on but this device offers no network, so there is " +
				"nothing for your tailnet to send here.",
			Limits: limits,
		}
	}
	return httpapi.Capability{Available: true, Limits: limits}
}

// prefixStrings renders a route list for the API.
func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}
