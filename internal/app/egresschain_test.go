// SPDX-License-Identifier: MIT

package app

// This machine's internet traffic chained through several connections, from the agent's side:
// which connection the internet sees, what each hop is built inside, and what the card says
// while the chain is coming up.

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/tunnel/ovpntunnel"
	"github.com/sellitus/app-tail/internal/tunnel/wgtunnel"
)

// carriesEverything lets both seeded connections hold a place in a chain: a hop carries the
// next hop's server, or the internet at the end, so a server that routes nothing on is refused
// where the chain is written.
func carriesEverything(c *config.Config) {
	for i := range c.Tunnels {
		if c.Tunnels[i].Type != config.TunnelWireGuard {
			continue
		}
		wg := c.Tunnels[i].WG()
		wg.Peer.AllowedIPs = append(wg.Peer.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
		c.Tunnels[i].WireGuard = &wg
	}
}

// chainedFabric is a harness whose two connections can each carry everything, with the
// interface up and both of them running.
func chainedFabric(t *testing.T) (*harness, *fakeFabrics) {
	t.Helper()
	return carryingFabricWith(t, labRange, carriesEverything)
}

// chainInternetTraffic points the stored document at an ordered chain and waits for the
// interface to be built from it.
func chainInternetTraffic(t *testing.T, h *harness, ids ...string) {
	t.Helper()
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = `"` + id + `"`
	}
	body := `{"egress.mode":"multi","egress.multi.shape":"cascade","egress.multi.tunnelIds":[` +
		strings.Join(quoted, ",") + `]}`
	resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}
	h.agent.reconcileNow(context.Background())
}

// reachesTheInternet is a connection whose server routes everything on, which is what a hop
// has to do to carry the hop after it out to that one's server.
func reachesTheInternet(t *testing.T, h *harness, ids ...string) {
	t.Helper()
	for _, id := range ids {
		latestDevice(t, h, id).carriesInternetTraffic()
	}
}

// latestDevice is the device a connection is running on now. A connection is rebuilt when what
// it is carried by changes, so the first one built for it is not always the live one.
func latestDevice(t *testing.T, h *harness, id string) *fakeWireGuard {
	t.Helper()
	built := h.wireguards.devicesFor(id)
	if len(built) == 0 {
		t.Fatalf("no device was ever built for %s", id)
	}
	return built[len(built)-1]
}

// carrierName is the connection a hop was built through. The registry hands out its own
// wrapper around a connection, so which one it is is asked rather than compared by identity.
func carrierName(t *testing.T, through wgtunnel.Carrier) string {
	t.Helper()
	named, ok := through.(interface{ ID() string })
	if !ok {
		t.Fatalf("the carrier %T does not say which connection it is", through)
	}
	return named.ID()
}

// The point of a chain: the traffic leaves through the last connection and nothing else. Every
// hop before it carries the hop after it and none of this machine's own traffic, so an
// interface that spread the traffic across the members would send most of it out of a
// connection the chain never meant to be an exit.
func TestInternetTrafficLeavesThroughTheLastConnectionInAChain(t *testing.T) {
	h, fabrics := chainedFabric(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	waitFor(t, 5*time.Second, "internet traffic to leave through the chain", func() bool {
		built := fabrics.all()
		dest, ok := built[len(built)-1].addressing().Lookup(somewhereOnline)
		return ok && dest.TunnelID == labTunnelID
	})

	built := fabrics.all()
	table := built[len(built)-1].addressing()
	// Every destination, not one: a chain has a single way out, so an interface that gave
	// destinations different answers would be spreading the traffic across the hops and
	// sending most of it out of a connection that was never the exit.
	for i := range 40 {
		addr := netip.AddrFrom4([4]byte{203, 0, byte(i), 9})
		if got := leavesThrough(t, h, table, addr); got != labTunnelID {
			t.Fatalf("%s leaves through %q, want the last connection in the chain", addr, got)
		}
	}
}

// Fail closed, on the connection that matters: with the last hop down there is no way out of
// the chain, and the traffic stops here rather than leaving over this machine's own network.
func TestInternetTrafficIsHeldWhenTheLastConnectionInAChainIsDown(t *testing.T) {
	h, fabrics := chainedFabric(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)
	switchOff(t, h, labTunnelID)
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "internet traffic to be held", func() bool {
		built := fabrics.all()
		dest, ok := built[len(built)-1].addressing().Lookup(somewhereOnline)
		return ok && dest.TunnelID == fabric.Blocked
	})

	built := fabrics.all()
	table := built[len(built)-1].addressing()
	if dest, ok := table.Lookup(somewhereOnline); !ok || dest.TunnelID != fabric.Blocked {
		t.Errorf("a destination on the internet is carried by %q (found=%v), want it held -- with "+
			"the exit down it is leaving over this machine's own network", dest.TunnelID, ok)
	}
	// The first hop is still up and still carries its own network. Holding internet traffic is
	// about the traffic nothing carries, and a hop is not an exit.
	if got := carriedBy(table, officeRange.Addr().Next()); got != wgTunnelID {
		t.Errorf("the office network is carried by %q, want the office connection", got)
	}
}

// A hop after the first is built through the one before it, at the size that connection has
// room for. Built any other way its packets would leave over this machine's own network, which
// is the chain not being a chain at all.
func TestAHopIsBuiltThroughTheConnectionBeforeItAtTheRoomItLeaves(t *testing.T) {
	h, _ := chainedFabric(t)
	first := h.wireguards.devicesFor(wgTunnelID)[0]
	first.carriesPacketsOf(1420)
	reachesTheInternet(t, h, wgTunnelID)

	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	var second *fakeWireGuard
	waitFor(t, 5*time.Second, "the second hop to be built through the first", func() bool {
		built := h.wireguards.devicesFor(labTunnelID)
		second = built[len(built)-1]
		through, _ := second.carriedBy()
		return through != nil
	})

	through, mtu := second.carriedBy()
	if got := carrierName(t, through); got != wgTunnelID {
		t.Errorf("the second hop is carried by %q, want the connection before it in the chain", got)
	}
	if mtu != 1420 {
		t.Errorf("the second hop was told its carrier has room for %d bytes, want 1420 -- a hop "+
			"built at the wrong size sends packets its carrier silently drops", mtu)
	}

	// The first hop is not carried by anything: its packets leave over this machine's own
	// network, which is what makes it the first.
	if through, _ := first.carriedBy(); through != nil {
		t.Errorf("the first hop is carried by %v, want nothing -- a connection carrying itself "+
			"is a loop that never completes a handshake", through)
	}
}

// A hop holds one conversation through the connection before it, opened when it was built.
// That conversation does not survive the connection before it going down, and nothing inside
// the device notices for as long as a session key stays valid -- minutes of a connection that
// looks up and moves nothing. It is taken down instead, so it is rebuilt when the one before
// it is back.
func TestAHopIsTakenDownWhenTheConnectionCarryingItGoesDown(t *testing.T) {
	h, _ := chainedFabric(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	var second *fakeWireGuard
	waitFor(t, 5*time.Second, "the second hop to be built through the first", func() bool {
		built := h.wireguards.devicesFor(labTunnelID)
		second = built[len(built)-1]
		through, _ := second.carriedBy()
		return through != nil
	})

	switchOff(t, h, wgTunnelID)
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the hop it was carrying to be taken down", func() bool {
		return second.wasClosed()
	})
	if _, running := h.agent.tunnels.Get(labTunnelID); running {
		t.Error("the second hop is still registered while the connection carrying it is down, so " +
			"it would go on reporting itself connected while moving nothing")
	}
}

// The hop after this one is reached at its own server's address on the open internet, so a
// carrier that reaches only its own network cannot get it there. Built through one anyway, the
// hop comes up and never completes a handshake: silence that reads as a broken network and
// sends somebody debugging their own machine. It waits instead, and says which connection
// cannot carry it.
func TestAHopIsNotBuiltThroughAConnectionThatCannotReachTheInternet(t *testing.T) {
	h, _ := chainedFabric(t)
	// Every connection is up, and the first one's server routes nothing on -- the state a
	// tailnet hop with no exit node chosen is in, which nothing at the point the chain is
	// written can see.
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	if _, running := h.agent.tunnels.Get(labTunnelID); running {
		t.Error("the second hop was built through a connection that cannot reach its server, so " +
			"it comes up and moves nothing while reporting itself connected")
	}
	problem := h.agent.tunnelProblem(labTunnelID)
	if !strings.Contains(problem, "cannot carry it out to the internet") {
		t.Errorf("the second hop reports %q, want it to say the connection before it cannot "+
			"carry it out to the internet", problem)
	}
	if !strings.Contains(problem, "Office") {
		t.Errorf("the second hop reports %q, want the connection that cannot carry it named",
			problem)
	}

	// It is a wait and not a verdict: the hop starts once that connection can carry it, with
	// no other change and nothing to switch off and on again.
	reachesTheInternet(t, h, wgTunnelID)
	h.agent.reconcileNow(context.Background())
	waitFor(t, 5*time.Second, "the second hop to start once the first can carry it", func() bool {
		_, running := h.agent.tunnels.Get(labTunnelID)
		return running
	})
}

// A chain that is coming up is not a chain that failed. Hop two cannot be built until hop one
// has connected, so every normal start passes through this -- and a card that called it a
// failure would be red on every start of the app.
func TestAHopSaysItIsWaitingOnTheConnectionBeforeIt(t *testing.T) {
	h, _ := chainedFabric(t)
	// The first hop is up and its server routes nothing on, so it cannot yet carry the hop
	// after it. That is the shape of a chain part-way up.
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	view := egressView(t, h)

	if view.Shape != string(config.EgressCascade) {
		t.Errorf("Shape = %q, want the chain -- the same list of connections means something "+
			"different under each shape", view.Shape)
	}
	if len(view.Members) != 2 {
		t.Fatalf("Members = %+v, want one row per hop", view.Members)
	}
	if view.Members[0].Carrying || view.Members[0].Waiting {
		t.Errorf("the first hop reads %+v, want it not carrying and not waiting -- nothing is "+
			"before it, so what it is waiting on could only be itself", view.Members[0])
	}
	if !view.Members[1].Waiting {
		t.Errorf("the second hop reads %+v, want it reported as waiting rather than failed",
			view.Members[1])
	}
	if !strings.Contains(view.Members[1].Reason, "waiting on") {
		t.Errorf("the second hop's reason is %q, want it to name what it is waiting on",
			view.Members[1].Reason)
	}
	if view.Carrying {
		t.Error("the card says the traffic is carried while the chain is still coming up")
	}
	if !view.Held {
		t.Error("Held is false while the chain carries nothing, so the card cannot say whether " +
			"the traffic is stopping here or going out over this machine's own network")
	}
}

// The whole of a chain carries only when its last hop does: that is the connection the
// internet sees, and a hop before it that is up carries nothing but the hop after it. The rows
// are in the order the traffic passes through them, because the order is the setting.
func TestTheEgressCardReportsAChainInHopOrderAndCarriesOnItsExit(t *testing.T) {
	h, _ := chainedFabric(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)
	waitFor(t, 5*time.Second, "the whole chain to be running", func() bool {
		_, running := h.agent.tunnels.Get(labTunnelID)
		return running
	})
	for _, id := range []string{wgTunnelID, labTunnelID} {
		latestDevice(t, h, id).carriesInternetTraffic()
	}

	view := egressView(t, h)

	if len(view.Members) != 2 {
		t.Fatalf("Members = %+v, want one row per hop", view.Members)
	}
	if view.Members[0].TunnelID != wgTunnelID || view.Members[1].TunnelID != labTunnelID {
		t.Errorf("the hops read %q then %q, want them in the order the traffic passes through them",
			view.Members[0].TunnelID, view.Members[1].TunnelID)
	}
	if view.Members[0].Exit {
		t.Error("the first hop is reported as the exit, so the card names the wrong connection " +
			"as the address the internet sees")
	}
	if !view.Members[1].Exit {
		t.Error("the last hop is not reported as the exit, so nothing on the card says which " +
			"connection the internet sees")
	}
	if !view.Carrying || view.Held {
		t.Errorf("the card reads carrying=%v held=%v while every hop is carrying",
			view.Carrying, view.Held)
	}
	if view.TunnelID != "" {
		t.Errorf("TunnelID = %q, want it empty -- it names a connection of another mode", view.TunnelID)
	}
}

// A chain whose exit is down carries nothing, whatever the hops before it are doing. Reading
// the whole from any hop that happens to be up would report traffic going out through a
// connection that is only carrying the next one.
func TestAChainCarriesNothingWhenItsExitDoesNot(t *testing.T) {
	h, _ := chainedFabric(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	view := egressView(t, h)

	if view.Carrying {
		t.Error("the card says the traffic is carried while the last hop is not carrying it, so " +
			"it reports traffic leaving through a connection that only carries the next hop")
	}
	if !view.Held {
		t.Error("Held is false while the chain's exit carries nothing")
	}
	if !strings.Contains(view.Reason, "held here") {
		t.Errorf("Reason = %q, want it to say the traffic is being held here", view.Reason)
	}
}

// A hop's own server is looked up before the chain exists to look it up through, so a hop
// written as a name has that name resolved on this machine's own network. It is said on the
// card rather than discovered: which providers a chain is built from is exactly what somebody
// chaining connections is trying not to publish.
func TestAChainSaysWhichOfItsHopsAreResolvedOnThisMachinesOwnNetwork(t *testing.T) {
	h, _ := chainedFabric(t)
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	view := egressView(t, h)

	if len(view.Limits) != 1 {
		t.Fatalf("Limits = %v, want the one about hop names being resolved here", view.Limits)
	}
	for _, name := range []string{"Office", "Lab"} {
		if !strings.Contains(view.Limits[0], name) {
			t.Errorf("the limit reads %q, want %s named -- its server is written as a name",
				view.Limits[0], name)
		}
	}
}

// A hop written as an address says nothing on the way up, so nothing is claimed about it.
func TestAChainOfHopsWrittenAsAddressesHasNothingToSay(t *testing.T) {
	h, _ := carryingFabricWith(t, labRange, func(c *config.Config) {
		carriesEverything(c)
		for i := range c.Tunnels {
			if c.Tunnels[i].Type != config.TunnelWireGuard {
				continue
			}
			wg := c.Tunnels[i].WG()
			wg.Peer.Endpoint = "198.51.100." + string(rune('1'+i)) + ":51820"
			c.Tunnels[i].WireGuard = &wg
		}
	})
	chainInternetTraffic(t, h, wgTunnelID, labTunnelID)

	if limits := egressView(t, h).Limits; len(limits) != 0 {
		t.Errorf("Limits = %v, want nothing -- a hop written as an address leaks no name", limits)
	}
}

// The hops of a chain are started in the chain's own order. A hop cannot be built before the
// connection carrying it is up, so starting them in declaration order would mean a hop's first
// attempt failing whenever the document happens to name it before its carrier.
func TestTheHopsOfAChainAreStartedInTheChainsOrder(t *testing.T) {
	app := config.Settings{
		EgressMode:           config.EgressMulti,
		EgressMultiShape:     config.EgressCascade,
		EgressMultiTunnelIDs: []string{"tn_first", "tn_second"},
	}
	wanted := []config.Tunnel{
		{ID: "tn_second"},
		{ID: "tn_elsewhere"},
		{ID: "tn_first"},
	}

	got := chainLast(wanted, app)

	order := make([]string, len(got))
	for i, held := range got {
		order[i] = held.ID
	}
	want := "tn_elsewhere,tn_first,tn_second"
	if strings.Join(order, ",") != want {
		t.Errorf("the connections are started %v, want %q -- a hop started before its carrier "+
			"fails its first attempt for no reason", order, want)
	}
}

// A hop carries the connection after it, so one that took this machine's own default route
// would carry everything else on the machine as well -- out of the first connection in the
// chain instead of out of the last.
func TestAChainedConnectionNeverTakesThisMachinesDefaultRoute(t *testing.T) {
	app := config.Settings{
		EgressMode:           config.EgressMulti,
		EgressMultiShape:     config.EgressCascade,
		EgressMultiTunnelIDs: []string{"tn_first", "tn_second"},
	}

	for _, id := range app.EgressMultiTunnelIDs {
		if got := carryFor(id, app); got != ovpntunnel.CarryScoped {
			t.Errorf("carryFor(%q) = %v, want it carried on this connection's own route", id, got)
		}
	}
	if got := carryFor("tn_elsewhere", app); got != ovpntunnel.CarryNone {
		t.Errorf("carryFor on a connection outside the chain = %v, want it carrying none of it", got)
	}
}

// chainedFabricWithOpenVPN is chainedFabric plus one OpenVPN connection that reaches its
// server over a stream, which is the transport a carried one has to use.
func chainedFabricWithOpenVPN(t *testing.T) (*harness, *fakeFabrics) {
	t.Helper()
	return carryingFabricWith(t, labRange, func(c *config.Config) {
		carriesEverything(c)
		seedOpenVPN(func(held *config.OpenVPNTunnel) {
			held.Proto = config.OpenVPNProtoTCP
			held.Routes = append(held.Routes, netip.MustParsePrefix("0.0.0.0/0"))
		})(c)
		// The interface's own two connections already hold the slug seedOpenVPN picks, and one
		// label with two networks under it is refused where the document is written.
		c.Tunnels[len(c.Tunnels)-1].Slug = "provider"
	})
}

// An OpenVPN connection cannot be told where to send its packets, but it can be told what
// address to dial -- so a carried one is built through the connection before it, and this is
// where that connection reaches it.
func TestAnOpenVPNHopIsBuiltThroughTheConnectionBeforeIt(t *testing.T) {
	h, _ := chainedFabricWithOpenVPN(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, ovpnTunnelID)

	waitFor(t, 5*time.Second, "the OpenVPN hop to be built through the connection before it", func() bool {
		built := h.openvpns.connectionsFor(ovpnTunnelID)
		return len(built) > 0 && built[len(built)-1].through != nil
	})

	built := h.openvpns.connectionsFor(ovpnTunnelID)
	through := built[len(built)-1].through
	if got := carrierName(t, through); got != wgTunnelID {
		t.Errorf("the OpenVPN hop is carried by %s, want the connection before it, %s", got, wgTunnelID)
	}
}

// An OpenVPN connection that is the whole of the egress is not carried by anything: there is
// no connection before it, so it dials its server over this machine's own network as it always
// has.
func TestAnOpenVPNConnectionThatIsTheFirstHopIsCarriedByNothing(t *testing.T) {
	h, _ := chainedFabricWithOpenVPN(t)
	chainInternetTraffic(t, h, ovpnTunnelID, wgTunnelID)

	waitFor(t, 5*time.Second, "the OpenVPN connection to be built", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) > 0
	})

	built := h.openvpns.connectionsFor(ovpnTunnelID)
	if through := built[len(built)-1].through; through != nil {
		t.Errorf("the first connection in the chain is carried by %s, want nothing",
			carrierName(t, through))
	}
}

// Hop two cannot dial anything until hop one is up, and starting it anyway is a program
// dialling a listener with nothing behind it. It waits instead, and says what it waits for.
func TestAnOpenVPNHopWaitsOnTheConnectionBeforeIt(t *testing.T) {
	h, _ := chainedFabricWithOpenVPN(t)
	// Running on its own before the chain names it, which is the state a stored connection is
	// in when the setting changes underneath it.
	waitFor(t, 5*time.Second, "the OpenVPN connection to start on its own", func() bool {
		_, registered := h.agent.tunnels.Get(ovpnTunnelID)
		return registered
	})
	was := len(h.openvpns.connectionsFor(ovpnTunnelID))

	// The connection before it carries only its own network, so it cannot carry this one out to
	// its server -- the same state as one that has not connected yet.
	chainInternetTraffic(t, h, wgTunnelID, ovpnTunnelID)

	if _, registered := h.agent.tunnels.Get(ovpnTunnelID); registered {
		t.Fatal("the OpenVPN hop is still running through a connection that cannot carry it, so " +
			"its packets are still leaving over this machine's own network")
	}
	if built := h.openvpns.connectionsFor(ovpnTunnelID); len(built) != was {
		t.Fatalf("the OpenVPN hop was built %d more times through a connection that cannot carry it",
			len(built)-was)
	}
	waitFor(t, 5*time.Second, "the hop to say what it is waiting for", func() bool {
		for _, view := range h.agent.TunnelsAPI().List() {
			if view.ID == ovpnTunnelID && strings.Contains(view.Detail, h.agent.connectionName(wgTunnelID)) {
				return true
			}
		}
		return false
	})

	// And it starts on its own once the connection before it can carry it, with nothing asked
	// of anybody: the reconcile is poked by that connection's own events.
	reachesTheInternet(t, h, wgTunnelID)
	h.agent.reconcileNow(context.Background())
	waitFor(t, 5*time.Second, "the hop to start once it can be carried", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) > was
	})
	built := h.openvpns.connectionsFor(ovpnTunnelID)
	if through := built[len(built)-1].through; through == nil {
		t.Error("the hop started carried by nothing, so its packets leave over this machine's own network")
	}
}

// A carried connection holds the connection before it, not its name: that one going down and
// coming back is a new object, and a hop still pointed at the old one dials a listener with
// nothing behind it forever. It is taken down here instead, and rebuilt through the new one.
func TestAnOpenVPNHopIsTakenDownWhenTheConnectionCarryingItGoesDown(t *testing.T) {
	h, _ := chainedFabricWithOpenVPN(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, ovpnTunnelID)

	waitFor(t, 5*time.Second, "the OpenVPN hop to be built through the connection before it", func() bool {
		built := h.openvpns.connectionsFor(ovpnTunnelID)
		return len(built) > 0 && built[len(built)-1].through != nil
	})

	// The connection before it stops carrying anything out to the internet, which is what it
	// looks like from here when that connection drops.
	latestDevice(t, h, wgTunnelID).carriesNothingOut()
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the hop to be taken down with the connection carrying it", func() bool {
		_, registered := h.agent.tunnels.Get(ovpnTunnelID)
		return !registered
	})
}

// Taking the chain off puts the connection back to dialling its own server. Kept as it was, it
// would still be reaching its server through a connection the setting no longer names -- the
// traffic going somewhere nothing on screen says it goes.
func TestAnOpenVPNHopStopsBeingCarriedWhenTheChainIsTakenOff(t *testing.T) {
	h, _ := chainedFabricWithOpenVPN(t)
	reachesTheInternet(t, h, wgTunnelID)
	chainInternetTraffic(t, h, wgTunnelID, ovpnTunnelID)

	waitFor(t, 5*time.Second, "the OpenVPN hop to be built through the connection before it", func() bool {
		built := h.openvpns.connectionsFor(ovpnTunnelID)
		return len(built) > 0 && built[len(built)-1].through != nil
	})
	was := len(h.openvpns.connectionsFor(ovpnTunnelID))

	body := `{"egress.mode":"tunnel","egress.tunnelId":"` + ovpnTunnelID + `"}`
	resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the connection to be rebuilt dialling its own server", func() bool {
		built := h.openvpns.connectionsFor(ovpnTunnelID)
		return len(built) > was && built[len(built)-1].through == nil
	})
}
