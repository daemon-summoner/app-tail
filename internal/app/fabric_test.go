// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// fabricView reads the addressing report over HTTP, which is the surface a dashboard has.
func fabricView(t *testing.T, h *harness) httpapi.FabricView {
	t.Helper()
	resp, raw := h.get("/api/fabric")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/fabric = %d: %s", resp.StatusCode, raw)
	}
	var view httpapi.FabricView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decode the addressing report: %v: %s", err, raw)
	}
	return view
}

// networkFor is what the report says about one connection's range.
func networkFor(t *testing.T, view httpapi.FabricView, id, prefix string) httpapi.FabricNetworkView {
	t.Helper()
	for _, network := range view.Networks {
		if network.TunnelID == id && network.Prefix == prefix {
			return network
		}
	}
	t.Fatalf("the report says nothing about %s on connection %q: %+v", prefix, id, view.Networks)
	return httpapi.FabricNetworkView{}
}

// The report exists for exactly this: two networks carrying the same addresses, where only
// one of them can be reached at them. Without it the second connects, looks healthy, and
// every address on it silently answers from the first.
func TestTwoConnectionsCarryingTheSameAddressesAreReportedAsOneConflict(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setSubnets(netip.MustParsePrefix("10.0.0.0/16"))
	h.bringUp()

	office := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, office.ID)
	waitFor(t, 5*time.Second, "the second connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(office.ID)
		return registered
	})
	built := h.nodes.nodesFor(dir)
	if len(built) != 1 {
		t.Fatalf("%d nodes were built for the second connection, want one", len(built))
	}
	built[0].setSubnets(netip.MustParsePrefix("10.0.0.0/16"))

	view := fabricView(t, h)

	if len(view.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want the one range both connections carry", view.Conflicts)
	}
	clash := view.Conflicts[0]
	if clash.Prefix != "10.0.0.0/16" || clash.Holder != config.PrimaryTunnelID {
		t.Errorf("conflict = %+v, want 10.0.0.0/16 held by the connection that claimed it first", clash)
	}
	if len(clash.Claimants) != 1 || clash.Claimants[0].TunnelID != office.ID ||
		clash.Claimants[0].Name != "Office" {
		t.Errorf("claimants = %+v, want the second connection, named", clash.Claimants)
	}
	if clash.Detail == "" {
		t.Error("a conflict with no detail leaves the dashboard with nothing to explain")
	}

	kept := networkFor(t, view, config.PrimaryTunnelID, "10.0.0.0/16")
	if kept.Reason != "" || kept.PresentedAs != "" {
		t.Errorf("the first connection was moved off its own addresses: %+v", kept)
	}
	moved := networkFor(t, view, office.ID, "10.0.0.0/16")
	if moved.Reason == "" {
		t.Fatalf("the second connection was reported as reachable at addresses the first answers for: %+v", moved)
	}
	presented, err := netip.ParsePrefix(moved.PresentedAs)
	if err != nil {
		t.Fatalf("presented as %q, which is not an address range: %v", moved.PresentedAs, err)
	}
	if len(view.Pool) == 0 {
		t.Fatal("the report names no pool, so nothing says where a moved network comes from")
	}
	pool := netip.MustParsePrefix(view.Pool[0])
	if !pool.Overlaps(presented) {
		t.Errorf("presented as %s, which is outside the pool %s the report names", presented, pool)
	}
}

// One connection, nothing in its way, keeps its own addresses and the report says so with
// no conflict at all. A report that moved a network anyway would break every address a user
// has written down to solve a problem they do not have.
func TestAConnectionNothingCollidesWithKeepsItsOwnAddresses(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setSubnets(netip.MustParsePrefix("172.30.0.0/16"))
	h.bringUp()

	view := fabricView(t, h)

	if len(view.Conflicts) != 0 {
		t.Errorf("conflicts = %+v, want none", view.Conflicts)
	}
	network := networkFor(t, view, config.PrimaryTunnelID, "172.30.0.0/16")
	if network.Reason != "" || network.PresentedAs != "" {
		t.Errorf("network = %+v, want it reached at its own addresses", network)
	}
	if view.Mode != "report" {
		t.Errorf("mode = %q, want the report-only mode this build carries out", view.Mode)
	}
	if len(view.Capability.Limits) == 0 {
		t.Error("the report states no limits, so nothing says it changes no addressing")
	}
}

// The LAN this machine sits on is claimed ahead of every connection: a connection carrying
// the same addresses is moved out of its way and the report says why. This reads the LAN
// through the seam the suite fixes, so the answer is the same on a machine sitting on
// 10.0.2.0/24 as on one that is not.
func TestAConnectionCarryingThisMachinesOwnNetworkIsMovedOutOfItsWay(t *testing.T) {
	h := newHarnessWith(t, nil, func(o *Options) {
		o.HostNetworks = func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")}, nil
		}
	})
	h.node.setSubnets(netip.MustParsePrefix("10.0.0.0/16"))
	h.bringUp()

	view := fabricView(t, h)

	network := networkFor(t, view, config.PrimaryTunnelID, "10.0.0.0/16")
	if network.PresentedAs == "" {
		t.Fatalf("network = %+v, want it presented away from the LAN it overlaps", network)
	}
	if !strings.Contains(network.Reason, "10.0.2.0/24") {
		t.Errorf("reason = %q, want it to name the network this machine is already on", network.Reason)
	}
}

// A connection that is running and cannot say what it carries is named, with the reason.
// Dropping it would leave a report that looks complete while the range it carries is the
// one thing missing from it -- a collision reported as none.
func TestAConnectionWhoseNetworksCannotBeReadIsNamedRatherThanDropped(t *testing.T) {
	h := newHarness(t, nil)
	h.bringUp()
	h.node.failRoutes(errors.New("the control plane is not answering"))

	view := h.agent.FabricAPI().View(context.Background())

	if len(view.Unread) != 1 {
		t.Fatalf("unread = %+v, want the connection that could not answer", view.Unread)
	}
	if got := view.Unread[0]; got.TunnelID != config.PrimaryTunnelID ||
		!strings.Contains(got.Error, "the control plane is not answering") {
		t.Errorf("unread = %+v, want the primary connection and why it could not answer", got)
	}
	for _, network := range view.Networks {
		if network.TunnelID == config.PrimaryTunnelID {
			t.Errorf("network %+v was reported for a connection whose networks could not be read", network)
		}
	}
}

// What the report says once an interface is really carrying the connections, which is a
// different question from where each network would be reached. The mode screen leads with
// it, and a machine reported as carrying when nothing is on the interface is one where
// every address on every connection is unreachable and nothing on screen says so.
func TestTheReportSaysWhatTheInterfaceIsActuallyCarrying(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	built := fabrics.all()
	live := built[len(built)-1]
	live.carried(wgTunnelID, fabric.Counters{Flows: 12, Refused: 1, Sent: 2048, Received: 4096, Holding: 3})
	live.carried("", fabric.Counters{Refused: 5})

	view := fabricView(t, h)

	if view.Mode != fabricCarrying {
		t.Errorf("mode = %q, want %q -- the report describes an interface, not a plan", view.Mode, fabricCarrying)
	}
	if !view.Running || view.Interface == "" {
		t.Errorf("running = %v on interface %q, want the interface it is carrying them on",
			view.Running, view.Interface)
	}
	if view.MTU != fabricFloorMTU {
		t.Errorf("mtu = %d, want the %d the smallest connected network holds it to", view.MTU, fabricFloorMTU)
	}
	for _, want := range []string{officeRange.String(), labRange.String()} {
		if !slices.Contains(view.Routes, want) {
			t.Errorf("routes = %v, want %s among them -- the report names what the interface carries",
				view.Routes, want)
		}
	}

	office := carriedFor(t, view, wgTunnelID)
	if office.Flows != 12 || office.Refused != 1 || office.Sent != 2048 || office.Received != 4096 ||
		office.Holding != 3 {
		t.Errorf("what %s carried = %+v, want the counters it reported", wgTunnelID, office)
	}
	if office.Name == "" {
		t.Errorf("what %s carried is listed as %q, want the name a person calls it", wgTunnelID, office.Name)
	}
	// Refused with no connection at all: an address none of them carries. It belongs to no
	// connection, so it is reported apart from them rather than charged to one.
	if unrouted := carriedFor(t, view, ""); unrouted.Refused != 5 {
		t.Errorf("addresses no connection carried = %+v, want the 5 that were refused", unrouted)
	}
}

// The dashboard polls this on the first paint, which is before anything has been brought up.
// There is no interface to describe then and no failure to report -- only the plan -- and the
// report has to answer rather than fault on the runner that does not exist yet.
func TestTheReportAnswersBeforeAnythingHasBeenBroughtUp(t *testing.T) {
	h := newHarness(t, nil)

	view := h.agent.FabricAPI().View(context.Background())

	if view.Mode != fabricReportOnly {
		t.Errorf("mode = %q, want %q -- nothing has been started", view.Mode, fabricReportOnly)
	}
	if view.Running || view.Interface != "" || view.Error != "" {
		t.Errorf("view reports interface %q running=%v error=%q, want nothing running and nothing wrong",
			view.Interface, view.Running, view.Error)
	}
	if !view.Capability.Available {
		t.Error("the report is unavailable before anything starts, so the mode screen has nothing to show")
	}
}

// An interface that is up and in trouble is the state a dashboard has to distinguish from
// both of the easy ones: it is not off, and it is not working. Reported as either, the user
// is told to fix something that is already done or that nothing is wrong.
func TestAnInterfaceThatIsUpAndInTroubleSaysSoWithTheReason(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	built := fabrics.all()
	built[len(built)-1].troubled("this machine's resolver would not take the connections' suffixes")

	view := fabricView(t, h)

	if view.Mode != fabricCarrying {
		t.Fatalf("mode = %q, want %q -- an interface in trouble is still an interface", view.Mode, fabricCarrying)
	}
	if !strings.Contains(view.Error, "would not take the connections' suffixes") {
		t.Errorf("error = %q, want what the interface said was wrong", view.Error)
	}
	if !view.Capability.Available || !view.Capability.Degraded {
		t.Errorf("capability = %+v, want available and degraded -- neither off nor working", view.Capability)
	}
	if view.Capability.Reason != view.Error {
		t.Errorf("the reason given is %q while the error is %q; two answers to one question",
			view.Capability.Reason, view.Error)
	}
}

// Up and carrying nothing is the state with no symptom: every address on every connection is
// unreachable while the mode itself looks chosen and fine, and nothing else on the machine
// has anything to say about it.
func TestAnInterfaceCarryingNothingIsNotReportedAsWorking(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	built := fabrics.all()
	built[len(built)-1].stalls()

	view := fabricView(t, h)

	if view.Running {
		t.Fatal("an interface carrying nothing is reported as carrying traffic")
	}
	if !view.Capability.Degraded || view.Capability.Reason == "" {
		t.Errorf("capability = %+v, want degraded with the reason it is not carrying", view.Capability)
	}
}

// The mode was asked for and the interface could not be created. There is nothing to
// describe, so the report falls back to saying where each network would go -- and it has to
// carry the failure with it, or the one screen that could explain it shows a plan instead.
func TestAnInterfaceThatCouldNotBeCreatedLeavesTheReportSayingWhy(t *testing.T) {
	fabrics := &fakeFabrics{}
	fabrics.refuses("the privileged helper is not installed")
	h := newHarnessWith(t, func(c *config.Config) { seedFabric(c, labRange) }, func(o *Options) {
		o.OpenFabric = fabrics.open
	})
	waitFor(t, 5*time.Second, "the failure to be reported", func() bool {
		return h.agent.currentFabric().snapshot().failure != ""
	})

	view := fabricView(t, h)

	if view.Mode != fabricReportOnly {
		t.Fatalf("mode = %q, want %q -- nothing is carrying anything", view.Mode, fabricReportOnly)
	}
	if !strings.Contains(view.Error, "the privileged helper is not installed") {
		t.Errorf("error = %q, want why the interface could not be created", view.Error)
	}
	if !view.Capability.Degraded || view.Capability.Reason != view.Error {
		t.Errorf("capability = %+v, want degraded with that same reason", view.Capability)
	}
	if len(view.Capability.Limits) == 0 {
		t.Error("a report with no limits reads as a description of a working interface")
	}
}

// The counters are listed in the order the connections are configured, because map order is
// not an order: listed straight out of the interface they would reshuffle on every poll, and
// a number a person is trying to read would move under the cursor.
func TestWhatEachConnectionCarriedIsListedInTheOrderTheyAreConfigured(t *testing.T) {
	stored := []config.Tunnel{{ID: "tn_first"}, {ID: "tn_second"}}
	// A connection that has since been deleted, and the addresses that belonged to none.
	// Both still have flows counted against them, and both have to land somewhere fixed.
	carried := []httpapi.FabricCarriedView{
		{TunnelID: ""},
		{TunnelID: "tn_gone_b"},
		{TunnelID: "tn_second"},
		{TunnelID: "tn_gone_a"},
		{TunnelID: "tn_first"},
	}

	sortCarriedByConfigured(carried, stored)

	got := make([]string, 0, len(carried))
	for _, entry := range carried {
		got = append(got, entry.TunnelID)
	}
	want := []string{"tn_first", "tn_second", "tn_gone_a", "tn_gone_b", ""}
	if !slices.Equal(got, want) {
		t.Errorf("listed as %v, want %v -- configured order, then whatever is no longer "+
			"configured by name, then the addresses no connection carried", got, want)
	}
}

// carriedFor is what one connection put across the interface, by id. The empty id is what
// belonged to no connection.
func carriedFor(t *testing.T, view httpapi.FabricView, id string) httpapi.FabricCarriedView {
	t.Helper()
	for _, carried := range view.Carried {
		if carried.TunnelID == id {
			return carried
		}
	}
	t.Fatalf("the report says nothing about what %q carried: %+v", id, view.Carried)
	return httpapi.FabricCarriedView{}
}

// Carrying everything is not a network to be presented. Taken as one it would make whichever
// connection declared a default route first the one this machine's internet traffic leaves
// by -- decided by the order two connections came up in rather than by the setting that
// exists to decide it.
func TestAConnectionCarryingEverythingIsNotPresentedAsANetwork(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setSubnets(
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("172.30.0.0/16"),
	)
	h.bringUp()

	view := fabricView(t, h)

	for _, network := range view.Networks {
		if network.Prefix == "0.0.0.0/0" {
			t.Errorf("the report presents %s on %s, so everything this machine sends goes there "+
				"whether or not it was chosen to carry it", network.Prefix, network.TunnelID)
		}
	}
	// The networks it really carries are still presented.
	networkFor(t, view, config.PrimaryTunnelID, "172.30.0.0/16")
}
