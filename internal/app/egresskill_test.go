// SPDX-License-Identifier: MIT

package app

// The kill switch, from the agent's side: this machine's internet traffic held here rather
// than let out over the network this machine is on while the one connection chosen to carry
// it cannot, on both paths app-tail routes -- the interface and its own proxy.

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/routing"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// holdInternetTraffic sends this machine's internet traffic through one connection and turns
// the kill switch on, in one save: the mode without the switch is a different promise, and
// writing them separately would leave the document in the state being tested against.
func holdInternetTraffic(t *testing.T, h *harness, id string) {
	t.Helper()
	body := `{"egress.mode":"tunnel","egress.tunnelId":"` + id + `","egress.killSwitch":true}`
	resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}
	h.agent.reconcileNow(context.Background())
}

// The whole of the switch: with it on and the chosen connection down, the interface goes on
// claiming this machine's internet traffic and refuses it.
func TestTheKillSwitchHoldsInternetTrafficWhenTheChosenConnectionIsDown(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	holdInternetTraffic(t, h, labTunnelID)
	switchOff(t, h, labTunnelID)
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "internet traffic to be held", func() bool {
		built := fabrics.all()
		dest, ok := built[len(built)-1].addressing().Lookup(somewhereOnline)
		return ok && dest.TunnelID == fabric.Blocked
	})

	table := fabrics.all()[len(fabrics.all())-1].addressing()
	if dest, ok := table.Lookup(somewhereOnline); !ok || dest.TunnelID != fabric.Blocked {
		t.Errorf("a destination on the internet is carried by %q (found=%v), want it held -- it "+
			"is leaving over this machine's own network with the kill switch on", dest.TunnelID, ok)
	}
	// The connections' own networks are untouched. Holding internet traffic is about the
	// traffic nothing carries, and taking a private network with it would make the switch
	// unusable for anyone who has one.
	if got := carriedBy(table, officeRange.Addr().Next()); got != wgTunnelID {
		t.Errorf("the office network is carried by %q, want the office connection -- holding "+
			"internet traffic took a private network with it", got)
	}
}

// The switch is what does it. The same connection, down, without the switch leaves this
// machine on the network it was already on -- which is the documented behaviour of choosing
// one connection and the reason the switch exists to be turned on.
func TestOneChosenConnectionThatIsDownStillLeavesTheMachineWhereItWas(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	sendInternetTrafficThrough(t, h, labTunnelID)
	switchOff(t, h, labTunnelID)
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the interface to stop carrying internet traffic", func() bool {
		built := fabrics.all()
		_, claimed := built[len(built)-1].addressing().Lookup(somewhereOnline)
		return !claimed
	})

	table := fabrics.all()[len(fabrics.all())-1].addressing()
	if dest, claimed := table.Lookup(somewhereOnline); claimed {
		t.Errorf("a destination on the internet is claimed by the interface and carried by %q, "+
			"want it left to this machine's own network -- nothing asked for it to be held",
			dest.TunnelID)
	}
}

// The other path app-tail routes. What the proxy dials is refused for the same reason and
// with a sentence saying so, rather than dialled over this machine's own network.
func TestTheKillSwitchRefusesWhatTheProxyWouldHaveDialledDirectly(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	holdInternetTraffic(t, h, labTunnelID)
	switchOff(t, h, labTunnelID)
	h.agent.reconcileNow(context.Background())

	_, err := h.agent.tunnels.Resolve(context.Background(), "tcp", "93.184.216.34:443")
	if !errors.Is(err, tunnel.ErrEgressHeld) {
		t.Fatalf("resolving a destination on the internet = %v, want it held -- the proxy dialled "+
			"it over this machine's own network with the kill switch on", err)
	}
}

// A rule that sends its destinations out directly is an exception somebody wrote on purpose,
// so it keeps working while the rest is held -- a printer on the desk is the ordinary reason
// to write one. The card says so rather than leaving it to be discovered.
func TestHoldingTheTrafficKeepsTheExceptionsSomebodyWrote(t *testing.T) {
	h, _ := carryingFabricWith(t, labRange, func(c *config.Config) {
		c.Routes = []routing.Rule{
			{ID: "rt_1", Action: routing.Via, Tunnel: wgTunnelID, Host: "*.corp.example"},
			{ID: "rt_2", Action: routing.Direct, CIDR: netip.MustParsePrefix("192.0.2.0/24")},
		}
	})
	holdInternetTraffic(t, h, labTunnelID)

	view := egressView(t, h)
	if !view.KillSwitch {
		t.Fatal("the card does not say the kill switch is on")
	}
	found := false
	for _, limit := range view.Limits {
		if strings.Contains(limit, "rule 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("limits = %q, want one naming rule 2 -- the exception it makes to the hold is "+
			"invisible", view.Limits)
	}
	// The rule sending traffic through a connection is not an exception to anything and has no
	// business being named as one.
	for _, limit := range view.Limits {
		if strings.Contains(limit, "rule 1") {
			t.Errorf("limits = %q, want nothing about rule 1 -- it carries its destinations "+
				"through a connection rather than out of this machine", view.Limits)
		}
	}
}

// Chosen, running, and carrying nothing: a connection whose server routes nothing on. The
// switch applies to that exactly as it applies to one that is down, and the card tells the
// two outcomes apart -- held stops the traffic, not carrying leaves it going out as before.
func TestTheCardSaysHeldRatherThanNotCarryingWhileTheSwitchIsOn(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	holdInternetTraffic(t, h, labTunnelID)

	view := egressView(t, h)
	if view.Carrying {
		t.Fatal("the connection is reported as carrying internet traffic; its server routes nothing on")
	}
	if !view.Held {
		t.Error("the card says the traffic is not carried and not that it is held, so it reads " +
			"as leaving this machine the way it always has")
	}
	if !strings.Contains(view.Reason, "held") {
		t.Errorf("reason = %q, want it to say the traffic is held here", view.Reason)
	}
}

// Without the switch the same state is a different answer, and saying "held" for it would be
// a promise the app is not keeping.
func TestTheCardSaysNotCarryingWhileTheSwitchIsOff(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	sendInternetTrafficThrough(t, h, labTunnelID)

	view := egressView(t, h)
	if view.Held {
		t.Error("the card says the traffic is being held with nothing asking for it to be")
	}
	if view.KillSwitch {
		t.Error("the card says the kill switch is on with nobody having turned it on")
	}
}

// The switch is read only where it applies. Sending the traffic out of this machine is the
// setting that says this machine's own network is where it goes, so a switch left on from a
// previous choice must not report a promise nothing is keeping.
func TestTheSwitchIsNotReportedWhileTrafficLeavesThisMachineDirectly(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	holdInternetTraffic(t, h, labTunnelID)
	body := `{"egress.mode":"direct"}`
	resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}
	h.agent.reconcileNow(context.Background())

	view := egressView(t, h)
	if view.KillSwitch || view.Held {
		t.Errorf("killSwitch=%v held=%v while the traffic goes out of this machine, want neither "+
			"-- the card promises something it is not doing", view.KillSwitch, view.Held)
	}
	if h.agent.tunnels.EgressHeld() {
		t.Error("the proxy refuses what it can dial directly while the setting says direct is " +
			"where it goes")
	}
}
