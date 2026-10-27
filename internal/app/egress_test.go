// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// egressView reads where internet traffic goes over HTTP, which is the surface a dashboard
// has.
func egressView(t *testing.T, h *harness) httpapi.EgressView {
	t.Helper()
	resp, raw := h.get("/api/egress")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/egress = %d: %s", resp.StatusCode, raw)
	}
	var view httpapi.EgressView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decode where internet traffic goes: %v: %s", err, raw)
	}
	return view
}

// sendInternetTrafficThrough points the setting at a connection, the way a dashboard does.
func sendInternetTrafficThrough(t *testing.T, h *harness, tunnelID string) {
	t.Helper()
	if _, _, err := h.agent.Settings().Update(context.Background(), settingsPatch(t, map[string]any{
		"egress.mode":     string(config.EgressTunnel),
		"egress.tunnelId": tunnelID,
	})); err != nil {
		t.Fatalf("send internet traffic through %s: %v", tunnelID, err)
	}
}

// An install nobody has changed sends its internet traffic out of this machine, and the
// view says so as a state rather than as a missing answer.
func TestInternetTrafficLeavesThisMachineUntilSomebodyChoosesOtherwise(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	view := egressView(t, h)

	if view.Mode != string(config.EgressDirect) {
		t.Errorf("mode = %q, want traffic leaving this machine", view.Mode)
	}
	if view.Carrying {
		t.Error("traffic is reported as going through a connection with none chosen")
	}
	if view.TunnelID != "" {
		t.Errorf("tunnelId = %q, want nothing chosen", view.TunnelID)
	}
}

// The end-to-end wiring: a setting written on the mode screen reaches the registry, so a
// destination no connection carries is dialled through the chosen one.
func TestChoosingAConnectionForInternetTrafficPutsItInFrontOfEveryOtherDestination(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.setExitNodeStatus("n1", true)

	sendInternetTrafficThrough(t, h, config.PrimaryTunnelID)

	view := egressView(t, h)
	if !view.Carrying {
		t.Fatalf("the chosen connection is not carrying it: %s", view.Reason)
	}
	if view.TunnelName == "" || view.TunnelName == view.TunnelID {
		t.Errorf("tunnelName = %q, want the connection as a person reads it", view.TunnelName)
	}

	live, ok := h.agent.tunnels.Egress()
	if !ok {
		t.Fatal("the registry carries no egress connection, so a dial would leave this machine directly")
	}
	if live.ID() != config.PrimaryTunnelID {
		t.Errorf("the registry carries %q, want the connection that was chosen", live.ID())
	}
}

// A connection chosen to carry the traffic that cannot is the failure this view exists to
// show: the setting says "through my VPN" and the packets are going nowhere, and nothing
// else on the machine would say which of the two is true.
func TestAChosenConnectionThatCannotCarryTheTrafficSaysWhyNot(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	sendInternetTrafficThrough(t, h, config.PrimaryTunnelID)

	view := egressView(t, h)
	if view.Carrying {
		t.Fatal("a connection with no exit node is reported as carrying internet traffic")
	}
	if view.TunnelID != config.PrimaryTunnelID {
		t.Errorf("tunnelId = %q, want the connection that was chosen to stay named", view.TunnelID)
	}
	if !strings.Contains(view.Reason, "exit node") {
		t.Errorf("reason = %q, want the connection's own words about what is missing", view.Reason)
	}
}

// Halfway through choosing: the mode applies as soon as it is picked and naming a
// connection is a second act, so this is what the mode screen shows between the two. The
// traffic is leaving this machine, and a view that reported the mode alone would say the
// opposite.
func TestSendingTrafficThroughAConnectionWithoutNamingOneSaysNoneIsChosen(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()

	if _, _, err := h.agent.Settings().Update(context.Background(), settingsPatch(t, map[string]any{
		"egress.mode": string(config.EgressTunnel),
	})); err != nil {
		t.Fatalf("send internet traffic through a connection nobody named: %v", err)
	}

	view := egressView(t, h)
	if view.Carrying {
		t.Fatal("traffic is reported as going through a connection while none is named")
	}
	if !strings.Contains(view.Reason, "no connection is chosen") {
		t.Errorf("reason = %q, want it to say nothing is chosen to carry it", view.Reason)
	}
}

// A kind that has no notion of sending traffic on at all -- openvpn, until it grows one.
// Reading its silence as agreement would report traffic leaving through a connection that
// drops every packet of it.
func TestAConnectionOfAKindThatCannotSendTrafficOnIsNotReadAsCarryingIt(t *testing.T) {
	carrying, reason := canCarryExit(context.Background(), anotherKind{})

	if carrying {
		t.Fatal("a connection that never answered the question is reported as carrying it")
	}
	if !strings.Contains(reason, string(config.TunnelOpenVPN)) {
		t.Errorf("reason = %q, want the kind that cannot carry it named", reason)
	}
}

// A connection refusing without saying why. Every implementation gives a reason and its own
// tests hold it to that, so this is the build where one stopped -- and an empty sentence
// renders as a blank line under a setting that is not doing what it says.
func TestAConnectionRefusingWithoutASayingWhyStillGetsASentence(t *testing.T) {
	carrying, reason := canCarryExit(context.Background(), silentRefusal{})

	if carrying {
		t.Fatal("a connection that refused is reported as carrying it")
	}
	if reason == "" {
		t.Error("the refusal is rendered as a blank line, so the setting looks applied and is not")
	}
}

// anotherKind is a connection whose kind answers nothing about internet traffic: it carries
// no CanCarryExit, which is how a kind that cannot send traffic on presents itself.
type anotherKind struct{ tunnel.Tunnel }

func (anotherKind) Kind() tunnel.Kind { return config.TunnelOpenVPN }

// silentRefusal is a connection that refuses to carry internet traffic and says nothing
// about why, which no implementation does and every one could regress into.
type silentRefusal struct{ tunnel.Tunnel }

func (silentRefusal) CanCarryExit(context.Context) (bool, string) { return false, "" }

// A connection that is stored, chosen and switched off. The traffic is leaving this machine
// the way it always has, and saying so is the difference between a setting that looks
// applied and one a reader can act on.
func TestAChosenConnectionThatIsNotRunningIsReportedAsNotCarryingIt(t *testing.T) {
	h := newHarnessWith(t, func(c *config.Config) {
		office := config.NewTunnel(wgTunnelID, "office", "Office", config.TunnelWireGuard)
		office.Enabled = false
		office.WireGuard = &config.WireGuardTunnel{
			PrivateKey: "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=",
			Addresses:  []netip.Prefix{netip.MustParsePrefix("172.30.99.4/24")},
			Peer: config.WireGuardPeer{
				PublicKey:  "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=",
				Endpoint:   "gateway.example.com:51820",
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		}
		c.Tunnels = append(c.Tunnels, office)
		c.Settings.EgressMode = config.EgressTunnel
		c.Settings.EgressTunnelID = wgTunnelID
	}, nil)
	h.bringUp()

	view := egressView(t, h)

	if view.Carrying {
		t.Fatal("a connection that is switched off is reported as carrying internet traffic")
	}
	if !strings.Contains(view.Reason, "not running") {
		t.Errorf("reason = %q, want it to say the connection is not running", view.Reason)
	}
	if !strings.Contains(view.Reason, "Office") {
		t.Errorf("reason = %q, want the connection named as a person reads it", view.Reason)
	}
}

// What choosing a connection with no resolvers of its own does not do. The traffic goes
// through it and the names are still looked up here, so the list of what is being visited
// stays on this network -- which is most of what somebody routing their traffic away was
// trying to stop.
func TestAConnectionWithNoResolversSaysNamesAreStillLookedUpHere(t *testing.T) {
	h := runningWireGuard(t)
	h.wireguards.devicesFor(wgTunnelID)[0].carriesInternetTraffic()
	sendInternetTrafficThrough(t, h, wgTunnelID)

	view := egressView(t, h)

	if !view.Carrying {
		t.Fatalf("the chosen connection is not carrying it: %s", view.Reason)
	}
	if len(view.Limits) == 0 {
		t.Fatal("a connection with no resolvers of its own states no limit, so the lookups it " +
			"cannot cover are left to be discovered")
	}
	if !strings.Contains(view.Limits[0], "looked up") {
		t.Errorf("limit = %q, want it to name the lookups that stay on this network", view.Limits[0])
	}
}

// The same connection with resolvers of its own. The limit has to be absent rather than
// always stated, or it says nothing about the connection it is shown against.
func TestAConnectionWithItsOwnResolversStatesNoSuchLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		seedWireGuard(c)
		for i := range c.Tunnels {
			if c.Tunnels[i].ID == wgTunnelID {
				c.Tunnels[i].WireGuard.DNS = []netip.Addr{netip.MustParseAddr("10.7.0.1")}
			}
		}
	})
	waitFor(t, 5*time.Second, "the seeded connection to be registered", func() bool {
		_, registered := h.agent.tunnels.Get(wgTunnelID)
		return registered
	})
	h.wireguards.devicesFor(wgTunnelID)[0].carriesInternetTraffic()
	sendInternetTrafficThrough(t, h, wgTunnelID)

	view := egressView(t, h)
	if !view.Carrying {
		t.Fatalf("the chosen connection is not carrying it: %s", view.Reason)
	}

	if len(view.Limits) != 0 {
		t.Errorf("limits = %v, want none for a connection that publishes its own resolvers", view.Limits)
	}
}

// The interface's side of the same choice: everything no connection carries is routed to
// the connection carrying internet traffic, which is what makes a program that knows
// nothing about app-tail leave through it.
func TestTheInterfaceSendsEverythingElseToTheConnectionCarryingInternetTraffic(t *testing.T) {
	fabrics := &fakeFabrics{}
	h := newHarnessWith(t, func(c *config.Config) {
		seedFabric(c, labRange)
		c.Settings.EgressMode = config.EgressTunnel
		c.Settings.EgressTunnelID = wgTunnelID
	}, func(o *Options) {
		o.OpenFabric = fabrics.open
	})
	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")

	waitFor(t, 5*time.Second, "the interface to carry everything else as well", func() bool {
		built := fabrics.all()
		if len(built) == 0 {
			return false
		}
		routes, _, calls := built[len(built)-1].carrying()
		return calls > 0 && slices.Contains(routes, defaultRoute)
	})

	routes, _, _ := fabrics.all()[0].carrying()
	if !slices.Contains(routes, netip.MustParsePrefix("::/0")) {
		t.Errorf("routes = %v, want the IPv6 default among them -- without it every IPv6 "+
			"destination leaves this machine directly while the setting says otherwise", routes)
	}
	for _, want := range []netip.Prefix{officeRange, labRange} {
		if !slices.Contains(routes, want) {
			t.Errorf("routes = %v, want %s still among them: a network a connection carries "+
				"goes through that connection", routes, want)
		}
	}
	if live, ok := h.agent.tunnels.Egress(); !ok || live.ID() != wgTunnelID {
		t.Errorf("the registry carries %v as the egress connection, want %s -- the interface "+
			"routes to it and the flows are handed on by id", live, wgTunnelID)
	}
}

// A connection chosen to carry it that is not running gets no default route. Pointing every
// destination at a connection that is not there would take this machine off the internet
// with only the mode screen saying why.
func TestTheInterfaceInstallsNoDefaultRouteForAConnectionThatIsNotRunning(t *testing.T) {
	const spareID = "tn_spare"
	h, fabrics := carryingFabricWith(t, labRange, func(c *config.Config) {
		// Stored, chosen, and switched off, which is the state a connection is in between
		// somebody choosing it and somebody turning it on.
		spare := config.NewTunnel(spareID, "spare", "Spare", config.TunnelWireGuard)
		spare.Enabled = false
		c.Tunnels = append(c.Tunnels, spare)
		c.Settings.EgressMode = config.EgressTunnel
		c.Settings.EgressTunnelID = spareID
	})

	routes, _, _ := fabrics.all()[0].carrying()

	for _, unwanted := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	} {
		if slices.Contains(routes, unwanted) {
			t.Errorf("routes = %v, want no %s: it points every destination at a connection "+
				"that is not running", routes, unwanted)
		}
	}
	if view := egressView(t, h); view.Carrying {
		t.Error("a connection that is not running is reported as carrying internet traffic")
	}
}

// The picker has to offer the connections that exist, including the ones that are off:
// choosing a connection and switching it on are two separate acts, and a picker that hid it
// until it was running would make the second a prerequisite for the first.
func TestTheInternetTrafficPickerOffersEveryStoredConnection(t *testing.T) {
	h := newHarnessWith(t, func(c *config.Config) {
		office := config.NewTunnel(wgTunnelID, "office", "Office", config.TunnelWireGuard)
		office.Enabled = false
		c.Tunnels = append(c.Tunnels, office)
	}, nil)

	choices := h.agent.tunnelChoices()

	ids := make([]string, 0, len(choices))
	for _, choice := range choices {
		ids = append(ids, choice.Value)
		if choice.Label == "" {
			t.Errorf("choice %q has no label, so the picker shows a bare id", choice.Value)
		}
	}
	if !slices.Contains(ids, config.PrimaryTunnelID) || !slices.Contains(ids, wgTunnelID) {
		t.Errorf("choices = %v, want every stored connection", ids)
	}
	for _, choice := range choices {
		if choice.Value == wgTunnelID && !strings.Contains(choice.Help, "switched off") {
			t.Errorf("help for the connection that is off = %q, want it to say so", choice.Help)
		}
	}
}
