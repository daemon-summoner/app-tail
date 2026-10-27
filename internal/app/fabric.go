// SPDX-License-Identifier: MIT

package app

// Where each connected network is reachable from this machine.
//
// Two networks can carry the same addresses -- two companies both on 10.0.0.0/8, or a
// network whose addresses are the ones this machine already uses at home -- and only one of
// them can be reached at them. This module asks every running connection what it carries,
// asks the machine what it is already on, and reports the answer.
//
// What it does about that answer depends on the mode. With one interface carrying every
// connection, a network whose addresses are taken is moved and reached somewhere else, and
// what is reported here is what that interface is really doing. Without it nothing is moved,
// and the report stands on its own: the symptom of an unreported collision is a host that
// resolves and then never answers, with nothing anywhere naming the network that answered
// instead.

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// The two things this module can be doing, in the word the view carries.
const (
	// fabricReportOnly says a collision and changes nothing, which is a client's cue to
	// explain rather than to offer a fix.
	fabricReportOnly = "report"
	// fabricCarrying means one interface is carrying every connection, so a moved network
	// really is reachable where the report says it is.
	fabricCarrying = "carry"
)

// fabricReportLimits are what the report does not cover when nothing is carrying the
// networks. Neither is a defect: the first is a property of the pool, the second of reading
// the machine without privileges.
var fabricReportLimits = []string{
	"Nothing is re-addressed. This reports where each network would have to be reached " +
		"if two of them collide; reaching a moved network needs the mode that puts every " +
		"connection on one interface.",
	"A moved network is presented from an IPv4 range, so two connections carrying the " +
		"same IPv6 addresses are reported with nowhere to move either of them to.",
	"The networks this machine is on are read from its own interfaces, so a network it " +
		"reaches through a gateway is not counted as one of its own.",
}

type fabricAPI struct{ a *Agent }

var _ httpapi.Fabric = fabricAPI{}

// FabricAPI exposes the addressing report and what the interface is doing about it.
func (a *Agent) FabricAPI() httpapi.Fabric { return fabricAPI{a: a} }

func (f fabricAPI) View(ctx context.Context) httpapi.FabricView {
	stored := f.a.store.Get().Tunnels
	networks, unread := f.carried(ctx, stored)

	view := httpapi.FabricView{Mode: fabricReportOnly, Unread: unread}

	host, err := f.a.hostNetworks()
	if err != nil {
		// Without them a connection claiming the addresses of the LAN the user is sitting
		// on reads as uncontested, which is the one wrong answer this module can give:
		// every other gap here is a network missing from the report rather than a
		// collision reported as none.
		view.Capability.Degraded = true
		view.Capability.Reason = "This machine's own networks could not be read (" + err.Error() +
			"), so a connection carrying addresses this machine already uses is not reported."
	}

	pool := f.a.settings().InterfaceVirtualPool
	if len(pool) == 0 {
		pool = fabric.DefaultPool
	}
	// The interface's own addresses are claimed alongside this machine's, exactly as the
	// runner claims them, so the report and what is carried cannot place a network where the
	// other one says nothing can go.
	host = append(host, fabric.InterfaceAddrs(pool)...)

	plan := fabric.Allocate(networks, host, pool)
	view.Pool = prefixStrings(plan.Pool)
	for _, placed := range plan.Placements {
		entry := httpapi.FabricNetworkView{
			TunnelID:   placed.TunnelID,
			TunnelName: tunnelName(stored, placed.TunnelID),
			Prefix:     placed.Prefix.String(),
			Reason:     placed.Reason,
		}
		if placed.PresentedAs.IsValid() {
			entry.PresentedAs = placed.PresentedAs.String()
		}
		view.Networks = append(view.Networks, entry)
	}
	for _, clash := range plan.Collisions {
		claimants := make([]httpapi.FabricClaimantView, 0, len(clash.Claimants))
		for _, id := range clash.Claimants {
			claimants = append(claimants, httpapi.FabricClaimantView{TunnelID: id, Name: tunnelName(stored, id)})
		}
		view.Conflicts = append(view.Conflicts, httpapi.FabricConflictView{
			Prefix:     clash.Prefix.String(),
			Holder:     clash.Holder,
			HolderName: clash.HolderName,
			Claimants:  claimants,
			Detail:     clash.Detail,
		})
	}

	f.live(&view, stored)
	view.Capability = f.capability(view)
	return view
}

// live fills in what the interface is actually doing, and is what makes the difference
// between a report and a description: the plan above says where each network would be
// reached, and this says whether anything is reaching it there.
func (f fabricAPI) live(view *httpapi.FabricView, stored []config.Tunnel) {
	runner := f.a.currentFabric()
	if runner == nil {
		return
	}
	snap := runner.snapshot()
	view.Error = snap.failure
	if !snap.running {
		return
	}

	view.Mode = fabricCarrying
	view.Running = snap.status.Running
	view.Interface = snap.status.Interface
	view.MTU = snap.status.MTU
	view.Routes = prefixStrings(snap.status.Routes)
	if snap.status.Error != "" {
		view.Error = snap.status.Error
	}
	for id, counted := range snap.status.Counters {
		view.Carried = append(view.Carried, httpapi.FabricCarriedView{
			TunnelID: id,
			Name:     tunnelName(stored, id),
			Flows:    counted.Flows,
			Refused:  counted.Refused,
			Sent:     counted.Sent,
			Received: counted.Received,
			Holding:  counted.Holding,
		})
	}
	// Map order is not an order. The connections are listed as they are configured, which is
	// the order everything else about them is listed in, with the addresses no connection
	// carried at the end because they belong to none of them.
	sortCarriedByConfigured(view.Carried, stored)
}

// capability states whether this machine really reaches its connections by address, and when
// it does not, why. The order is the ladder a user climbs: what was asked for, then whether
// it is running, then whether it is carrying everything it was asked to.
func (f fabricAPI) capability(view httpapi.FabricView) httpapi.Capability {
	state := view.Capability
	state.Available = true
	if view.Mode != fabricCarrying {
		state.Limits = fabricReportLimits
		if state.Reason == "" {
			runner := f.a.currentFabric()
			if runner != nil {
				state.Reason = runner.snapshot().reason
			}
		}
		if view.Error != "" {
			state.Degraded = true
			state.Reason = view.Error
		}
		return state
	}

	state.Limits = fabric.Limits
	switch {
	case view.Error != "":
		state.Degraded = true
		state.Reason = view.Error
	case !view.Running:
		state.Degraded = true
		state.Reason = "The interface is up but is not carrying traffic."
	}
	return state
}

// sortCarriedByConfigured puts the per-connection counters in the order the connections are
// configured, with anything belonging to no connection last.
func sortCarriedByConfigured(carried []httpapi.FabricCarriedView, stored []config.Tunnel) {
	order := make(map[string]int, len(stored))
	for i, held := range stored {
		order[held.ID] = i
	}
	place := func(id string) int {
		if id == "" {
			return len(stored) + 1
		}
		if i, ok := order[id]; ok {
			return i
		}
		return len(stored)
	}
	slices.SortStableFunc(carried, func(a, b httpapi.FabricCarriedView) int {
		if d := place(a.TunnelID) - place(b.TunnelID); d != 0 {
			return d
		}
		return strings.Compare(a.TunnelID, b.TunnelID)
	})
}

// carried is what every running connection says it reaches, in the order the connections
// are configured -- which is the order that decides who keeps a contested range, so it is
// the stored list that is walked rather than the registry's.
//
// A connection that is not running contributes nothing and is not a problem: it is off, or
// still coming up, and neither is something to report as a failure. A connection that is
// running and cannot answer is a problem, because a range it carries would be missing from
// a report that otherwise looks complete.
func (f fabricAPI) carried(ctx context.Context, stored []config.Tunnel) ([]fabric.Network, []httpapi.FabricUnreadView) {
	var networks []fabric.Network
	var unread []httpapi.FabricUnreadView
	for _, held := range stored {
		live, running := f.a.tunnels.Get(held.ID)
		if !running {
			continue
		}
		routes, err := live.Routes(ctx)
		if err != nil {
			unread = append(unread, httpapi.FabricUnreadView{
				TunnelID: held.ID, Name: held.Name, Error: err.Error(),
			})
			continue
		}
		networks = append(networks, presentedNetworks(held.ID, held.Name, routes)...)
	}
	return networks, unread
}

// presentedNetworks are the ranges of one connection that the interface presents, which is
// what it carries less carrying everything.
//
// A default route is not a network to be presented. It is the answer to which connection this
// machine's internet traffic leaves by, and that is one setting rather than whichever
// connection happened to declare a default route first -- which is what taking it as a
// network here would quietly make it. The connection that was chosen gets it put on the
// interface separately; see egressMappings.
//
// The report and what is carried both go through here, because a report that named a network
// the interface does not carry would be a report about a different machine.
func presentedNetworks(id, name string, routes []netip.Prefix) []fabric.Network {
	out := make([]fabric.Network, 0, len(routes))
	for _, prefix := range routes {
		if prefix.Bits() == 0 {
			continue
		}
		out = append(out, fabric.Network{TunnelID: id, Name: name, Prefix: prefix})
	}
	return out
}

// tunnelName is what a connection is called, falling back to nothing rather than to the id:
// the id is already in the view beside it, and repeating it as a name would render a
// sentence about "tn_a1b2c3" in the one place a person reads.
func tunnelName(stored []config.Tunnel, id string) string {
	for _, held := range stored {
		if held.ID == id {
			return held.Name
		}
	}
	return ""
}
