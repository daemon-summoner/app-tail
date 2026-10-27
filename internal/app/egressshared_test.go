// SPDX-License-Identifier: MIT

package app

// This machine's internet traffic shared across several connections, from the agent's side:
// what reaches the interface, what the card says, and what removing a member does.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/spread"
	"github.com/sellitus/app-tail/internal/tunnel"
	"github.com/sellitus/app-tail/internal/tunnel/ovpntunnel"
)

// shareInternetTraffic points the stored document at a set of connections and waits for the
// interface to be built from it.
func shareInternetTraffic(t *testing.T, h *harness, ids ...string) {
	t.Helper()
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = `"` + id + `"`
	}
	body := `{"egress.mode":"multi","egress.multi.tunnelIds":[` + strings.Join(quoted, ",") + `]}`
	resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}
	h.agent.reconcileNow(context.Background())
}

// switchOff stops a connection while leaving it in the document, so it stays a member of the
// set and stays a row on the card while carrying nothing.
func switchOff(t *testing.T, h *harness, id string) {
	t.Helper()
	if _, err := h.agent.TunnelsAPI().Update(context.Background(), id,
		patchOf(t, map[string]any{"enabled": false})); err != nil {
		t.Fatalf("switching %s off: %v", id, err)
	}
	waitFor(t, 5*time.Second, "the connection to stop", func() bool {
		_, registered := h.agent.tunnels.Get(id)
		return !registered
	})
}

// leavesThrough is the connection one destination on the open internet goes out through,
// which is the per-destination answer rather than the one Lookup gives an unkeyed caller.
func leavesThrough(t *testing.T, h *harness, table *fabric.Table, addr netip.Addr) string {
	t.Helper()
	if table == nil {
		t.Fatal("the interface was given no addressing at all")
	}
	dest, ok := table.Choose(addr, spread.Key(spread.SeedFrom(h.agent.settings().MachineID), addr))
	if !ok {
		t.Fatalf("nothing carries %s, so this machine cannot reach the internet at all", addr)
	}
	return dest.TunnelID
}

// The point of the feature: with two connections sharing it, destinations far enough apart
// go out through different connections, so both are carrying traffic at once.
func TestInternetTrafficIsSharedBetweenTheChosenConnections(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	shareInternetTraffic(t, h, wgTunnelID, labTunnelID)

	waitFor(t, 5*time.Second, "internet traffic to be shared", func() bool {
		built := fabrics.all()
		dest, ok := built[len(built)-1].addressing().Lookup(somewhereOnline)
		return ok && (dest.TunnelID == wgTunnelID || dest.TunnelID == labTunnelID)
	})

	built := fabrics.all()
	table := built[len(built)-1].addressing()
	seen := map[string]bool{}
	for i := range 40 {
		seen[leavesThrough(t, h, table, netip.AddrFrom4([4]byte{203, 0, byte(i), 9}))] = true
	}
	if len(seen) < 2 {
		t.Errorf("every destination left through %v, want both connections carrying a share", seen)
	}
	for id := range seen {
		if id != wgTunnelID && id != labTunnelID {
			t.Errorf("a destination left through %q, which is not one of the connections chosen", id)
		}
	}

	// The tailnet is not part of the set, and mapping every address there is at two
	// connections must not take it with them.
	if got := carriedBy(table, aTailnetDevice); got != config.PrimaryTunnelID {
		t.Errorf("a tailnet device is carried by %q, want the tailnet", got)
	}
}

// Fail closed. With every chosen connection down, the interface keeps claiming internet
// traffic and refuses it, rather than letting it out over this machine's own network -- which
// is the one outcome choosing a set of connections exists to exclude.
func TestInternetTrafficIsHeldWhenNoChosenConnectionIsRunning(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	// The set names one connection and that connection is switched off, so the set is chosen
	// and nothing in it is running -- which is the state the hold is for. The office
	// connection stays up to prove the private networks are untouched by it.
	shareInternetTraffic(t, h, labTunnelID)
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
		t.Errorf("a destination on the internet is carried by %q (found=%v), want it held -- it is "+
			"leaving over this machine's own network", dest.TunnelID, ok)
	}
	// The connections' own networks are untouched: holding internet traffic is about the
	// traffic nothing carries, and taking the private networks away with it would make the
	// mode unusable for the thing the interface is for.
	if got := carriedBy(table, officeRange.Addr().Next()); got != wgTunnelID {
		t.Errorf("the office network is carried by %q, want the office connection -- holding "+
			"internet traffic took a private network with it", got)
	}
}

// The card reports one row per chosen connection, including the ones that are down. A member
// that vanished from the list while it was down would read as a setting that changed itself.
func TestTheEgressCardReportsEveryConnectionSharingTheTraffic(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	// A connection whose server routes nothing on genuinely cannot carry internet traffic and
	// says so, which is a different thing from the one being tested here.
	h.wireguards.devicesFor(wgTunnelID)[0].carriesInternetTraffic()
	shareInternetTraffic(t, h, wgTunnelID, labTunnelID)
	switchOff(t, h, labTunnelID)

	resp, raw := h.request(http.MethodGet, "/api/egress", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/egress = %d: %s", resp.StatusCode, raw)
	}
	var view httpapi.EgressView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decoding the egress view: %v", err)
	}
	if view.Mode != string(config.EgressMulti) {
		t.Errorf("Mode = %q, want %q", view.Mode, config.EgressMulti)
	}
	if len(view.Members) != 2 {
		t.Fatalf("Members = %+v, want one row for each connection chosen", view.Members)
	}
	if view.Members[0].TunnelID != wgTunnelID || !view.Members[0].Carrying {
		t.Errorf("the running member reads %+v, want it carrying its share", view.Members[0])
	}
	if view.Members[1].Carrying || view.Members[1].Reason == "" {
		t.Errorf("the member that is not running reads %+v, want it not carrying and saying why",
			view.Members[1])
	}
	if !view.Carrying {
		t.Error("Carrying is false while one member is carrying its share, so the card would " +
			"read as though nothing were going through any of them")
	}
	if view.Held {
		t.Error("Held is true while a member is carrying, which reads as traffic stopping here")
	}
	if view.TunnelID != "" {
		t.Errorf("TunnelID = %q, want it empty -- it names a connection the traffic is not "+
			"going through", view.TunnelID)
	}
}

// An empty list is every connection there is, the tailnet included, in the order the document
// declares them -- and "there is" means enabled: one that is switched off was not chosen,
// which is different from one that is chosen and down.
func TestSharingWithNoListNamedMeansEveryEnabledConnection(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	h.wireguards.devicesFor(wgTunnelID)[0].carriesInternetTraffic()
	shareInternetTraffic(t, h)

	waitFor(t, 5*time.Second, "internet traffic to be shared", func() bool {
		built := fabrics.all()
		dest, ok := built[len(built)-1].addressing().Lookup(somewhereOnline)
		return ok && dest.TunnelID != fabric.Blocked
	})

	memberIDs := func() []string {
		resp, raw := h.request(http.MethodGet, "/api/egress", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/egress = %d: %s", resp.StatusCode, raw)
		}
		var view httpapi.EgressView
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatalf("decoding the egress view: %v", err)
		}
		ids := make([]string, 0, len(view.Members))
		for _, m := range view.Members {
			ids = append(ids, m.TunnelID)
		}
		return ids
	}
	if got, want := memberIDs(), []string{config.PrimaryTunnelID, wgTunnelID, labTunnelID}; !slices.Equal(got, want) {
		t.Errorf("members = %v, want every connection in the document, in its order: %v", got, want)
	}

	// Switched off is not chosen: the row goes, where a chosen member that is down stays.
	switchOff(t, h, labTunnelID)
	h.agent.reconcileNow(context.Background())
	if got, want := memberIDs(), []string{config.PrimaryTunnelID, wgTunnelID}; !slices.Equal(got, want) {
		t.Errorf("members = %v after switching one off, want it out of the set: %v", got, want)
	}
}

// With none of them carrying, the card says the traffic is being held rather than leaving.
// "Not carrying" and "leaking" are the two states this mode has to keep apart.
func TestTheEgressCardSaysTheTrafficIsHeldWhenNoMemberCarriesIt(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	shareInternetTraffic(t, h, labTunnelID)
	switchOff(t, h, labTunnelID)

	resp, raw := h.request(http.MethodGet, "/api/egress", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/egress = %d: %s", resp.StatusCode, raw)
	}
	var view httpapi.EgressView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decoding the egress view: %v", err)
	}
	if !view.Held {
		t.Error("Held is false while nothing is carrying the traffic, so the card cannot say " +
			"whether it is stopping here or going out over this machine's own network")
	}
	if !strings.Contains(view.Reason, "held here") {
		t.Errorf("Reason = %q, want it to say the traffic is being held here", view.Reason)
	}
}

// Removing a connection that is sharing internet traffic is refused, for the same reason
// removing the single chosen one is: dropping it from the set would hand its share of the
// destinations to the others without anybody saying so.
func TestAConnectionSharingInternetTrafficCannotBeRemoved(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	shareInternetTraffic(t, h, wgTunnelID, labTunnelID)

	resp, raw := h.request(http.MethodDelete, "/api/tunnels/"+labTunnelID, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DELETE /api/tunnels/%s = %d, want it refused: %s", labTunnelID, resp.StatusCode, raw)
	}
	// The instruction, not the validator's own sentence. Letting the document's validator
	// answer instead would report the connection as one that "does not exist", to somebody
	// who is looking at it and asking for it to be removed.
	if !strings.Contains(string(raw), "Take it out of that set") {
		t.Errorf("the refusal reads %s, want it to say what to do about it", raw)
	}
	if _, found := h.agent.store.Get().Tunnel(labTunnelID); !found {
		t.Error("the connection was removed anyway")
	}
}

// A connection in the set carries internet traffic on a route this app installs beside it,
// never by taking this machine's own default route. Two members both claiming the default
// route is one of them winning and the other silently carrying nothing.
func TestASharingConnectionNeverTakesThisMachinesDefaultRoute(t *testing.T) {
	var app config.Settings
	app.EgressMode = config.EgressMulti
	app.EgressMultiTunnelIDs = []string{"tn_one", "tn_two"}

	for _, id := range app.EgressMultiTunnelIDs {
		if got := carryFor(id, app); got != ovpntunnel.CarryScoped {
			t.Errorf("carryFor(%q) = %v, want it carried on this connection's own route", id, got)
		}
	}
	if got := carryFor("tn_other", app); got != ovpntunnel.CarryNone {
		t.Errorf("carryFor on a connection outside the set = %v, want it carrying none of it", got)
	}

	// An empty set is every connection, so every connection carries a share of it.
	app.EgressMultiTunnelIDs = nil
	if got := carryFor("tn_other", app); got != ovpntunnel.CarryScoped {
		t.Errorf("carryFor with no set named = %v, want every connection carrying a share", got)
	}
}

// The probe answers "would the proxy reach this", so it has to dial the way the proxy dials.
// A probe that went out over this machine's own network while the proxy sends the same
// destination through a connection reports on a path nothing else uses -- and with internet
// traffic held it would report reachable something the proxy refuses.
func TestAProbeGoesOutThroughTheConnectionCarryingInternetTraffic(t *testing.T) {
	h, _ := carryingFabricWith(t, labRange, proxyOn)
	office := h.wireguards.devicesFor(wgTunnelID)[0]
	office.carriesInternetTraffic()

	resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(
		`{"egress.mode":"tunnel","egress.tunnelId":"`+wgTunnelID+`"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}
	h.agent.reconcileNow(context.Background())

	// The rules decide before anything is dialled, so the destination has to be one this
	// proxy is allowed to reach or the probe never gets as far as the question being asked.
	if _, err := h.agent.ProxiesAPI().SetRules(context.Background(), config.DefaultProxyID,
		[]access.Rule{{ID: "ar_all", Action: access.Allow, Tunnel: tunnel.ThisMachine}}); err != nil {
		t.Fatalf("setting rules: %v", err)
	}

	// An address rather than a name, so nothing here depends on a resolver and no lookup
	// reaches this machine's own network on the way.
	result := probe(h, somewhereOnline.String()+":443")
	if !office.wasDialed(somewhereOnline.String() + ":443") {
		t.Errorf("the probe did not go through the connection carrying internet traffic: %+v", result)
	}
	if result.Reachable {
		t.Errorf("the probe reported reachable through a connection that carries nothing: %+v", result)
	}
}
