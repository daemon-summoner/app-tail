// SPDX-License-Identifier: MIT

package app

// Where this machine's internet traffic leaves through.
//
// The setting is one field and its consequences are spread across three places -- the
// proxy dials through it, the interface routes everything else to it, and a name looked up
// on the way goes to its resolver -- so this is where the whole of it is reported back as
// one answer.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/routing"
	"github.com/sellitus/app-tail/internal/tunnel"
)

type egressAPI struct{ a *Agent }

// EgressAPI exposes where internet traffic goes and whether the connection chosen for it
// can carry any.
func (a *Agent) EgressAPI() httpapi.Egress { return egressAPI{a: a} }

func (e egressAPI) View(ctx context.Context) httpapi.EgressView {
	s := e.a.settings()
	view := httpapi.EgressView{Mode: string(s.EgressMode), TunnelID: s.EgressTunnelID}
	if view.TunnelID != "" {
		view.TunnelName = e.a.connectionName(view.TunnelID)
	}
	if hops, chained := s.EgressChain(); chained {
		return e.chained(ctx, view, hops)
	}
	if members, spreadOn := s.EgressSpread(); spreadOn {
		return e.shared(ctx, view, members)
	}
	if s.EgressMode != config.EgressTunnel {
		return view
	}
	// From here the kill switch is read, so the view carries it: it is the difference between
	// a connection that is down leaving the machine where it was and one that stops the
	// traffic, and every sentence below it changes with it.
	view.KillSwitch = s.EgressKillSwitch
	held := s.EgressHeld()
	if view.TunnelID == "" {
		// The state between the two halves of the choice: the mode applies the moment it is
		// picked, and naming a connection is a second act. Traffic is leaving this machine
		// while the setting says otherwise, which is exactly the disagreement this view is
		// for, so it is reported rather than read as a half-finished setting to ignore.
		view.Reason = "no connection is chosen to carry it"
		if held {
			view.Held = true
			view.Limits = e.heldLimits()
			view.Reason = "no connection is chosen to carry it, so it is being held here rather " +
				"than sent out over this machine's own network"
		}
		return view
	}

	live, running := e.a.tunnels.Get(view.TunnelID)
	if !running {
		view.Reason = fmt.Sprintf("%s is not running, so internet traffic is leaving this machine "+
			"the way it always has", view.TunnelName)
		if held {
			view.Held = true
			view.Limits = e.heldLimits()
			view.Reason = fmt.Sprintf("%s is not running, so internet traffic is being held here "+
				"rather than sent out over this machine's own network", view.TunnelName)
		}
		return view
	}
	view.Limits = egressLimits(live, view.TunnelName)
	view.Carrying, view.Reason = canCarryExit(ctx, live)
	if !held {
		return view
	}
	// Stated while the traffic is flowing rather than at the moment it stops: what the promise
	// does not cover is worth knowing before it is being relied on.
	view.Limits = append(view.Limits, e.heldLimits()...)
	// Chosen, running, and carrying nothing -- a tailnet with no exit node selected, a peer
	// whose allowed addresses route nothing on. The switch applies to that exactly as it
	// applies to a connection that is down: what is not carried is not sent out another way.
	// The connection's own words say why, and the consequence is added to them, because
	// without the switch those same words mean the traffic is leaving as it always has.
	view.Held = !view.Carrying
	if view.Held {
		view.Reason += ", so internet traffic is being held here rather than sent out over this " +
			"machine's own network"
	}
	return view
}

// heldLimits are what holding this machine's internet traffic does not cover, stated up front
// rather than discovered.
//
// Two things it does not cover, and both are the user's own doing rather than a gap that could
// be closed here. Without the one interface carrying every connection, app-tail routes nothing
// for this machine and holds only what is dialled through it -- its proxy, and the apps pointed
// at that. And a per-destination rule that sends its destinations out directly is an exception
// somebody wrote on purpose, so it keeps working: a printer on the desk is the ordinary reason
// to write one, and refusing it would take the local network down with the promise.
func (e egressAPI) heldLimits() []string {
	var out []string
	if !e.a.settings().FabricSelected() {
		out = append(out, "This machine is not on one interface carrying your connections, so "+
			"app-tail holds only the traffic that goes through it -- its proxy, and whatever is "+
			"pointed at that. Everything else on this machine leaves over its own network as it "+
			"always has.")
	}
	var direct []string
	for i, rule := range e.a.routes() {
		if rule.Action == routing.Direct {
			direct = append(direct, fmt.Sprintf("%d", i+1))
		}
	}
	switch {
	case len(direct) == 1:
		out = append(out, fmt.Sprintf("Per-destination rule %s sends its destinations out over "+
			"this machine's own network, and still does: a rule is an exception written on "+
			"purpose, so holding the rest does not take it back.", direct[0]))
	case len(direct) > 1:
		out = append(out, fmt.Sprintf("Per-destination rules %s and %s send their destinations "+
			"out over this machine's own network, and still do: a rule is an exception written "+
			"on purpose, so holding the rest does not take it back.",
			strings.Join(direct[:len(direct)-1], ", "), direct[len(direct)-1]))
	}
	return out
}

// shared reports the set of connections sharing this machine's internet traffic.
//
// Every chosen connection gets a row, including the ones that are down, because the set is
// what the user chose and a member that vanished from the list while it was down would read
// as a setting that changed itself. The whole is carrying as long as any one member is: the
// destinations that member holds are going through it, which is what sharing means.
func (e egressAPI) shared(ctx context.Context, view httpapi.EgressView, members []string) httpapi.EgressView {
	// An empty list is every connection that is meant to be up, which is what the agent
	// resolves it to when it hands the set to the registry. Reporting the ids instead of
	// that would show an empty card while traffic is going out through four connections.
	if len(members) == 0 {
		members = enabledTunnelIDs(e.a.runtimeTunnels())
	}
	// The chosen connection of a previous mode is not part of this one, and leaving it in
	// would name a connection the traffic is not going through.
	view.TunnelID, view.TunnelName = "", ""
	view.Shape = string(config.EgressSpreadShape)
	// The traffic is held in this mode whether or not anything is carrying it right now, so
	// what the holding does not cover is stated the whole time rather than at the moment it
	// starts refusing traffic.
	view.Limits = e.heldLimits()
	for _, id := range members {
		row := httpapi.EgressMember{TunnelID: id, TunnelName: e.a.connectionName(id)}
		live, running := e.a.tunnels.Get(id)
		if !running {
			row.Reason = fmt.Sprintf("%s is not running, so it is carrying none of it", row.TunnelName)
			view.Members = append(view.Members, row)
			continue
		}
		row.Limits = egressLimits(live, row.TunnelName)
		row.Carrying, row.Reason = canCarryExit(ctx, live)
		view.Carrying = view.Carrying || row.Carrying
		view.Members = append(view.Members, row)
	}
	if view.Carrying {
		return view
	}
	// Held rather than direct, and that is the whole difference between this mode and
	// choosing one connection: with nothing carrying it, traffic stops here instead of
	// going out the way it always has.
	view.Held = true
	if len(view.Members) == 0 {
		view.Reason = "no connection is chosen to share it, so it is being held here"
		return view
	}
	view.Reason = "none of these connections is carrying it, so it is being held here rather " +
		"than sent out over this machine's own network"
	return view
}

// chained reports the connections carrying this machine's internet traffic one inside the
// next, in the order the traffic passes through them.
//
// A chain is one route and not a set, so the whole of it carries only when its last hop does:
// that is the connection the internet sees, and a hop before it that is up carries nothing but
// the hop after it. The rows are in hop order for the same reason -- the order is the setting,
// not a presentation of it, and the first and last positions are what the mode is for.
//
// A hop whose carrier is not up yet is reported as waiting rather than as failed. Every start
// of a chain passes through that state, because hop two cannot be built until hop one has
// connected, and calling it a failure would put a red card on every normal start.
func (e egressAPI) chained(ctx context.Context, view httpapi.EgressView, hops []string) httpapi.EgressView {
	// The chosen connection of a previous mode is not a hop of this one.
	view.TunnelID, view.TunnelName = "", ""
	view.Shape = string(config.EgressCascade)
	if len(hops) == 0 {
		view.Held = true
		view.Reason = "no connections are chosen to carry it, so it is being held here rather " +
			"than sent out over this machine's own network"
		return view
	}
	carried := true
	for i, id := range hops {
		row := httpapi.EgressMember{
			TunnelID:   id,
			TunnelName: e.a.connectionName(id),
			Exit:       i == len(hops)-1,
		}
		live, running := e.a.tunnels.Get(id)
		switch {
		case !carried:
			row.Waiting = true
			row.Reason = fmt.Sprintf("%s is waiting on %s, the connection before it in the chain",
				row.TunnelName, e.a.connectionName(hops[i-1]))
		case !running:
			row.Reason = fmt.Sprintf("%s is not running, so nothing after it in the chain can be",
				row.TunnelName)
		default:
			row.Carrying, row.Reason = canCarryExit(ctx, live)
			if row.Exit {
				// Only the last hop's limits are this machine's: a name resolved for traffic
				// leaving the chain is resolved wherever that hop's resolvers are, and what an
				// earlier hop publishes never sees the traffic at all.
				row.Limits = egressLimits(live, row.TunnelName)
			}
		}
		carried = row.Carrying
		if row.Exit {
			view.Carrying = row.Carrying
		}
		view.Members = append(view.Members, row)
	}
	view.Limits = append(e.chainLimits(hops), e.heldLimits()...)
	if view.Carrying {
		return view
	}
	// Fail-closed is the whole of this mode: with the route incomplete the traffic stops here
	// instead of going out the way it always has, whichever hop is the one that is down.
	view.Held = true
	view.Reason = "this chain is not carrying it, so it is being held here rather than sent " +
		"out over this machine's own network"
	return view
}

// chainLimits are what a chain does not hide, stated up front rather than discovered.
//
// A hop's own server address is looked up before the chain exists to look it up through, so a
// hop configured by name has that name resolved on this machine's own network -- which tells
// this network's resolver which providers the chain is built from, though never where the
// traffic through it went. A hop configured by address says nothing at all, so the limit is
// reported only when there is one and names the hops it applies to.
func (e egressAPI) chainLimits(hops []string) []string {
	byName := make([]string, 0, len(hops))
	stored := e.a.store.Get().Tunnels
	for _, id := range hops {
		for _, held := range stored {
			if held.ID != id || held.Type != config.TunnelWireGuard {
				continue
			}
			if _, err := netip.ParseAddrPort(strings.TrimSpace(held.WG().Peer.Endpoint)); err != nil {
				byName = append(byName, e.a.connectionName(id))
			}
		}
	}
	if len(byName) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("The server address of %s is written as a name, and a hop's own "+
		"server is looked up on this machine's own network before the chain exists to look it up "+
		"through. Which providers this chain is built from stays visible there, though where the "+
		"traffic through it went does not.", strings.Join(byName, ", "))}
}

// canCarryExit asks a connection whether it can carry internet traffic right now.
//
// A connection that does not answer the question at all is one whose kind has no notion of
// sending traffic on -- so it is reported as not carrying, with the kind named. Reading
// silence as yes would show traffic leaving through a connection that drops it.
func canCarryExit(ctx context.Context, live tunnel.Tunnel) (carrying bool, reason string) {
	carrier, asks := live.(tunnel.ExitCarrier)
	if !asks {
		return false, fmt.Sprintf("a %s connection cannot carry this machine's internet traffic", live.Kind())
	}
	can, why := carrier.CanCarryExit(ctx)
	if can {
		return true, ""
	}
	if why == "" {
		// Every implementation gives a reason and a test holds them to it, so this is a
		// build where one stopped. An empty sentence would render as a blank line under a
		// setting that is not doing what it says.
		why = "that connection is not carrying it and did not say why"
	}
	return false, why
}

// egressLimits are what routing internet traffic through this connection does not cover.
//
// The one that matters is the lookup: the traffic goes through the connection, and a name
// resolved on this network before it left would tell this network's resolver every address
// being visited. A connection that publishes resolvers of its own closes that; one that
// does not cannot, and saying so is the only honest option -- there is nothing to fix at
// this end.
func egressLimits(live tunnel.Tunnel, name string) []string {
	if _, resolves := live.(tunnel.Resolving); resolves {
		return nil
	}
	return []string{fmt.Sprintf("%s publishes no resolvers of its own, so names are still looked "+
		"up on this machine's own network. What is being visited stays visible there, even though "+
		"the traffic does not go that way.", name)}
}

// tunnelChoices fills the picker for the connection carrying internet traffic.
//
// Every stored connection is offered, including the ones that are off: choosing a
// connection and switching it on are two separate acts, and a picker that hid the
// connection until it was running would make the second one a prerequisite for the first.
// The help is what the connection is, so the list reads as connections rather than as ids.
func (a *Agent) tunnelChoices() []config.EnumOption {
	stored := a.store.Get().Tunnels
	out := make([]config.EnumOption, 0, len(stored))
	for _, held := range stored {
		help := fmt.Sprintf("A %s connection.", held.Type)
		if !held.Enabled {
			help += " It is switched off, so nothing goes through it until it is switched on."
		}
		out = append(out, config.EnumOption{Value: held.ID, Label: held.Name, Help: help})
	}
	return out
}
