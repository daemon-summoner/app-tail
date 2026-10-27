// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// The connections screen reads one answer. Fetching configuration and status separately
// would render a connection that exists with a status belonging to a different poll.
func TestTheTailnetAppearsAsAConnectionWithItsLiveState(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setState(tsnode.StateRunning)

	list := h.agent.TunnelsAPI().List()

	if len(list) != 1 {
		t.Fatalf("got %d connections, want the one every install has: %+v", len(list), list)
	}
	held := list[0]
	if held.ID != config.PrimaryTunnelID {
		t.Errorf("id = %q, want %q", held.ID, config.PrimaryTunnelID)
	}
	if held.State != "connected" {
		t.Errorf("state = %q, want the running node reported as connected", held.State)
	}
	if !held.Live {
		t.Error("a running connection is not reported as carrying traffic")
	}
	if held.StateLabel == "" {
		t.Error("no state label, so every surface would have to hold its own word for this state")
	}
}

// A rebuild replaces the node the connection is a view of. The registration has to move
// with it: left pointing at the old one, the connections screen would go on reporting the
// status of a node that has been closed, which reads as a working tailnet.
func TestARebuildRepointsTheConnectionAtTheNodeThatIsNowRunning(t *testing.T) {
	const replacementName = "rebuilt.example.ts.net"
	built := 0
	h := newHarnessWith(t, nil, func(o *Options) {
		// The first build stays the harness's own node, which is the one it waits on
		// before handing this test an agent. Only the replacement is ours, and it carries
		// a name that tells the two apart from the outside.
		first := o.NewNode
		o.NewNode = func(p tsnode.Options) NodeController {
			if built++; built == 1 {
				return first(p)
			}
			node := newFakeNode()
			node.status.DNSName = replacementName
			return node
		}
	})

	if err := h.agent.RestartNode(context.Background()); err != nil {
		t.Fatalf("restarting the node: %v", err)
	}

	if built < 2 {
		t.Fatal("no replacement node was built, so this proves nothing about the rebuild")
	}
	if h.agent.tunnels.Len() != 1 {
		t.Fatalf("the registry holds %d connections after a rebuild, want 1", h.agent.tunnels.Len())
	}
	live, ok := h.agent.tunnels.Get(config.PrimaryTunnelID)
	if !ok {
		t.Fatal("the tailnet is not registered after a rebuild")
	}
	names := live.Status().Names
	if len(names) != 1 || names[0] != replacementName {
		t.Errorf("the connection reports %v, want the node the rebuild put in place (%s)",
			names, replacementName)
	}
}

// A connection with nothing running under it is off, not broken. That is the state before
// the agent has finished starting, and reporting it as a failure would show a fault where
// there is none.
func TestAConnectionWithNoLiveNodeIsOffRatherThanFailed(t *testing.T) {
	agent := newUnstartedAgent(t)

	list := agent.TunnelsAPI().List()

	if len(list) != 1 {
		t.Fatalf("got %d connections, want the stored one: %+v", len(list), list)
	}
	if list[0].State != "off" {
		t.Errorf("state = %q, want %q before anything is running", list[0].State, "off")
	}
	if list[0].Live {
		t.Error("a connection with no node reports that traffic can cross it")
	}
}

func TestAConnectionThatIsNotStoredIsNotFound(t *testing.T) {
	agent := newUnstartedAgent(t)

	if _, err := agent.TunnelsAPI().Get("tn_absent"); !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
}

func TestRenamingAConnectionIsStored(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.TunnelsAPI().Update(context.Background(), config.PrimaryTunnelID,
		patchOf(t, map[string]any{"name": "Work", "slug": "work"}))
	if err != nil {
		t.Fatalf("renaming: %v", err)
	}

	if view.Name != "Work" || view.Slug != "work" {
		t.Errorf("view = %+v, want the connection as it now stands", view)
	}
	stored, ok := h.store.Get().Tunnel(config.PrimaryTunnelID)
	if !ok {
		t.Fatal("the connection is gone from the stored document")
	}
	if stored.Name != "Work" || stored.Slug != "work" {
		t.Errorf("stored = %+v, want the write persisted", stored)
	}
}

// Two connections under one slug means two networks answer for one name suffix. The
// whole document is validated on every write, so the second is refused rather than
// discovered later by a resolver with two answers to one question.
func TestARenameOntoASlugAnotherConnectionHoldsIsRefused(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Tunnels = append(c.Tunnels, config.Tunnel{
			ID: "tn_other", Slug: "office", Name: "Office", Type: config.TunnelWireGuard,
		})
	})

	_, err := h.agent.TunnelsAPI().Update(context.Background(), config.PrimaryTunnelID,
		patchOf(t, map[string]any{"slug": "office"}))

	if err == nil {
		t.Fatal("two connections were allowed to answer for one name suffix")
	}
	if !strings.Contains(err.Error(), "office") {
		t.Errorf("error = %v, want it to name the collision", err)
	}
	stored, _ := h.store.Get().Tunnel(config.PrimaryTunnelID)
	if stored.Slug != config.PrimaryTunnelSlug {
		t.Errorf("slug = %q, want the refused write not persisted", stored.Slug)
	}
}

func TestWritingToAConnectionThatIsNotStoredIsNotFound(t *testing.T) {
	h := newHarness(t, nil)

	_, err := h.agent.TunnelsAPI().Update(context.Background(), "tn_absent",
		patchOf(t, map[string]any{"name": "Work"}))

	if !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
}

// Adding a connection is the whole point of a hub: this is the first one that is not the
// tailnet the app was built around, and it has to be stored, started, and registered where
// everything that reaches a network looks.
func TestAddingAConnectionStartsItBesideThePrimaryOne(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.TunnelsAPI().Create(context.Background(), httpapi.TunnelSpec{
		Type: config.TunnelTailscale, Name: "Office",
	})
	if err != nil {
		t.Fatalf("adding a connection: %v", err)
	}

	if view.ID == config.PrimaryTunnelID {
		t.Fatal("the new connection took the primary connection's id")
	}
	if view.Slug != "office" {
		t.Errorf("slug = %q, want one derived from the name", view.Slug)
	}
	if _, stored := h.store.Get().Tunnel(view.ID); !stored {
		t.Error("the connection is not in the stored document, so it would be gone at the next start")
	}

	waitFor(t, 5*time.Second, "the new connection to be registered", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})
	if h.agent.tunnels.Len() != 2 {
		t.Errorf("the registry holds %d connections, want the primary one and the new one",
			h.agent.tunnels.Len())
	}
}

// A device id only means something on the network that issued it, so the device list has
// to come from the node running the connection that was asked about. Answering every
// connection from the primary node would offer devices the selected network cannot reach,
// and a forward built on one would fail with a name nothing can resolve.
func TestEachConnectionsDevicesComeFromItsOwnNode(t *testing.T) {
	h := newHarness(t, nil)
	h.node.setPeers(tsnode.Peer{ID: "nHome", HostName: "home", Online: true})

	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, view.ID)
	waitFor(t, 5*time.Second, "the new connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})
	built := h.nodes.nodesFor(dir)
	if len(built) != 1 {
		t.Fatalf("%d nodes were built for the new connection, want one", len(built))
	}
	built[0].setPeers(tsnode.Peer{ID: "nOffice", HostName: "office", Online: true})

	ctx := context.Background()
	for _, want := range []struct{ id, device string }{
		{config.PrimaryTunnelID, "nHome"},
		{view.ID, "nOffice"},
	} {
		peers, err := h.agent.TunnelsAPI().Peers(ctx, want.id)
		if err != nil {
			t.Fatalf("reading the devices on %q: %v", want.id, err)
		}
		if len(peers) != 1 || peers[0].ID != want.device {
			t.Errorf("connection %q reports %+v, want only device %q", want.id, peers, want.device)
		}
	}
}

// A connection nothing is running has no device list rather than an empty one. Reporting
// none would present a network that is merely switched off as one with no devices on it.
func TestTheDevicesOfAConnectionThatIsNotRunningAreRefusedWithTheReason(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	if _, err := h.agent.TunnelsAPI().Update(context.Background(), view.ID,
		patchOf(t, map[string]any{"enabled": false})); err != nil {
		t.Fatalf("switching the connection off: %v", err)
	}
	waitFor(t, 5*time.Second, "the connection to stop", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return !registered
	})

	_, err := h.agent.TunnelsAPI().Peers(context.Background(), view.ID)

	if !errors.Is(err, tsnode.ErrNotRunning) {
		t.Errorf("error = %v, want it to report the connection is not running", err)
	}
}

// Two Tailscale nodes sharing a state directory overwrite each other's identity with
// neither reporting anything -- nothing locks it -- so the separation is the only thing
// keeping them apart, and it is asserted rather than assumed.
func TestASecondConnectionRunsOnItsOwnStateDirectory(t *testing.T) {
	h := newHarness(t, nil)

	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, view.ID)

	waitFor(t, 5*time.Second, "the new connection to be built", func() bool {
		_, built := h.nodes.paramsFor(dir)
		return built
	})
	params, _ := h.nodes.paramsFor(dir)
	if params.Dir == h.stateDir {
		t.Fatalf("the new connection was built on %q, the directory the primary one already "+
			"holds; the two would overwrite each other's identity", params.Dir)
	}
	if len(h.nodes.nodesFor(dir)) != 1 {
		t.Errorf("%d nodes were built for one connection, want exactly one",
			len(h.nodes.nodesFor(dir)))
	}
}

// A machine has one network interface for this app and the primary connection owns it. A
// second node built in interface mode would either fail to create one or take the one the
// first is already carrying traffic on, so the mode is forced whatever the installation
// asked for.
func TestASecondConnectionIsBuiltContainedEvenWhenTheInterfaceModeIsOn(t *testing.T) {
	h := newHarness(t, nil)
	// Written straight to the document rather than through the settings API: turning the
	// interface mode on there asks this machine for administrator rights, which a test
	// suite must never do.
	storeSetting(h, func(s *config.Settings) {
		s.InterfaceEnabled = true
		s.InterfaceMode = config.NetworkTUN
	})

	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, view.ID)

	waitFor(t, 5*time.Second, "the new connection to be built", func() bool {
		_, built := h.nodes.paramsFor(dir)
		return built
	})
	params, _ := h.nodes.paramsFor(dir)
	if params.Network != config.NetworkUserspace {
		t.Errorf("the new connection was built on the %q stack, want %q: only one node on "+
			"this machine can own the interface", params.Network, config.NetworkUserspace)
	}
	if params.InterfaceName != "" {
		t.Errorf("the new connection names interface %q, which the primary one owns",
			params.InterfaceName)
	}
}

// Switching a connection off is how a user stops one without losing what they configured,
// so it has to actually stop: a node left running is a device still on a tailnet the user
// believes they have left.
func TestSwitchingAConnectionOffStopsIt(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, view.ID)
	waitFor(t, 5*time.Second, "the new connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})
	started := h.nodes.nodesFor(dir)
	if len(started) != 1 {
		t.Fatalf("%d nodes were built for the new connection, want one", len(started))
	}

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), view.ID,
		patchOf(t, map[string]any{"enabled": false})); err != nil {
		t.Fatalf("switching the connection off: %v", err)
	}

	if _, registered := h.agent.tunnels.Get(view.ID); registered {
		t.Error("a switched-off connection is still registered, so a forward could still dial it")
	}
	if !started[0].wasClosed() {
		t.Error("a switched-off connection's node is still running, so the device is still on that tailnet")
	}
	if state := viewOfTunnel(t, h, view.ID).State; state != "off" {
		t.Errorf("state = %q, want %q: it was switched off, which is a state rather than a fault", state, "off")
	}
}

// Removing a connection has to stop it in the same breath. A node still running for a
// connection nothing describes any more could not be stopped from anywhere: it is absent
// from every screen that would offer the switch.
func TestRemovingAConnectionStopsIt(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, view.ID)
	waitFor(t, 5*time.Second, "the new connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})
	started := h.nodes.nodesFor(dir)

	if err := h.agent.TunnelsAPI().Delete(context.Background(), view.ID); err != nil {
		t.Fatalf("removing the connection: %v", err)
	}

	if _, stored := h.store.Get().Tunnel(view.ID); stored {
		t.Error("the connection is still in the stored document")
	}
	if _, registered := h.agent.tunnels.Get(view.ID); registered {
		t.Error("a removed connection is still registered")
	}
	if len(started) != 1 || !started[0].wasClosed() {
		t.Error("a removed connection's node is still running, with nothing left on screen to stop it")
	}
}

// A forward on a removed connection would name a network that is not there, which the
// document refuses. Left to the validator, the refusal names a field; the user has to be
// told which forwards to move, and that their configuration was not silently deleted for
// them.
func TestAConnectionWithForwardsOnItIsNotRemovedUntilTheyAre(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	created, err := h.agent.Forwards().Create(context.Background(), httpapi.ForwardSpec{
		Name: ptr("office db"), TunnelID: ptr(view.ID),
		Target: ptr("db:5432"), ListenPort: ptr(15432),
		Direction: ptr(config.ToLocal), Protocol: ptr(config.TCP),
	})
	if err != nil {
		t.Fatalf("adding a forward on the new connection: %v", err)
	}

	err = h.agent.TunnelsAPI().Delete(context.Background(), view.ID)

	if err == nil {
		t.Fatal("the connection was removed with a forward still crossing it")
	}
	if !strings.Contains(err.Error(), "office db") {
		t.Errorf("error = %v, want it to name the forward that is in the way", err)
	}
	if _, stored := h.store.Get().Tunnel(view.ID); !stored {
		t.Error("the connection was removed anyway")
	}
	if _, err := h.agent.Forwards().Get(created.ID); err != nil {
		t.Errorf("the forward was deleted as a side effect: %v", err)
	}
}

// The identity a node enrolls with is baked in at enrollment, so changing it is a rebuild
// rather than an edit. Without one the connection would go on running as the device it was
// while every screen reported the device the user asked for.
func TestChangingAConnectionsIdentityRebuildsIt(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, view.ID)
	waitFor(t, 5*time.Second, "the new connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), view.ID,
		patchOf(t, map[string]any{"hostname": "office-gateway"})); err != nil {
		t.Fatalf("renaming the device: %v", err)
	}

	waitFor(t, 5*time.Second, "the connection to be rebuilt", func() bool {
		return len(h.nodes.nodesFor(dir)) == 2
	})
	built := h.nodes.nodesFor(dir)
	if !built[0].wasClosed() {
		t.Error("the previous node is still running, so the device is on the tailnet twice")
	}
	params, _ := h.nodes.paramsFor(dir)
	if params.Hostname != "office-gateway" {
		t.Errorf("the rebuilt node enrolls as %q, want the name that was just set", params.Hostname)
	}
	if _, registered := h.agent.tunnels.Get(view.ID); !registered {
		t.Error("the connection is not registered after a rebuild")
	}
}

// A rename that changes nothing the node was built from must not rebuild it: a rebuild
// drops every connection crossing that network, and doing it because somebody edited a
// display name would be an outage caused by a label.
func TestRenamingAConnectionOnScreenDoesNotRebuildIt(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	dir := config.TunnelStateDir(h.stateDir, view.ID)
	waitFor(t, 5*time.Second, "the new connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), view.ID,
		patchOf(t, map[string]any{"name": "Head office"})); err != nil {
		t.Fatalf("renaming: %v", err)
	}

	if built := h.nodes.nodesFor(dir); len(built) != 1 {
		t.Errorf("%d nodes were built, want the running one left alone", len(built))
	}
	if built := h.nodes.nodesFor(dir); built[0].wasClosed() {
		t.Error("the running node was closed for a change to a display name")
	}
}

// The primary connection is where this installation's own tailnet settings, environment
// variables and flags are applied. Removing it would leave those inputs with nowhere to go,
// so it is refused with the alternative named rather than half-performed.
func TestThePrimaryConnectionCannotBeRemoved(t *testing.T) {
	h := newHarness(t, nil)

	err := h.agent.TunnelsAPI().Delete(context.Background(), config.PrimaryTunnelID)

	if err == nil {
		t.Fatal("the primary connection was removed")
	}
	var validation *config.ValidationError
	if !errors.As(err, &validation) {
		t.Errorf("error = %v, want a validation error so it maps to a rejection rather than a fault", err)
	}
	if !strings.Contains(err.Error(), "Switch it off") {
		t.Errorf("error = %v, want it to name what the user can do instead", err)
	}
	if _, stored := h.store.Get().Tunnel(config.PrimaryTunnelID); !stored {
		t.Error("the primary connection is gone from the stored document anyway")
	}
}

func TestRemovingAConnectionThatIsNotStoredIsNotFound(t *testing.T) {
	h := newHarness(t, nil)

	if err := h.agent.TunnelsAPI().Delete(context.Background(), "tn_absent"); !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
}

// withoutOpenVPN is an agent whose privileged side cannot run OpenVPN connections.
//
// Whether a kind can be started is a property of the platform: an OpenVPN connection needs
// a privileged side that can check who owns the program it would run as root, and there
// are platforms where that check has no meaning. The harness answers yes everywhere, since
// the side it substitutes can, so the refusals below are exercised on every machine
// running the suite rather than only on the one nobody tests.
func withoutOpenVPN(o *Options) {
	o.RunsOpenVPN = func() bool { return false }
}

// A kind of network this build cannot bring up is refused at the point somebody asks for
// it. Accepting it would store a connection that reports off forever with nothing on
// screen able to explain or fix it, which is worse than saying so now.
func TestAddingAConnectionOfAKindThisBuildCannotStartIsRefused(t *testing.T) {
	h := newHarnessWith(t, nil, withoutOpenVPN)

	_, err := h.agent.TunnelsAPI().Create(context.Background(),
		httpapi.TunnelSpec{Type: config.TunnelOpenVPN, Name: "Lab"})

	if err == nil {
		t.Fatal("a connection nothing here can start was accepted")
	}
	if !strings.Contains(err.Error(), "openvpn") {
		t.Errorf("error = %v, want it to name what was refused", err)
	}
	if len(h.store.Get().Tunnels) != 1 {
		t.Error("the refused connection was stored anyway")
	}
}

// A document from another version, or one edited by hand, can carry a connection this
// build cannot start. It stays off rather than failed -- nothing is broken -- but the
// reason has to be on screen, or it reads as a connection somebody switched off.
func TestAStoredConnectionThisBuildCannotStartSaysWhyItIsOff(t *testing.T) {
	h := newHarnessWith(t, func(c *config.Config) {
		c.Tunnels = append(c.Tunnels, config.Tunnel{
			ID: "tn_lab", Slug: "lab", Name: "Lab", Type: config.TunnelOpenVPN, Enabled: true,
		})
	}, withoutOpenVPN)

	view := viewOfTunnel(t, h, "tn_lab")

	if view.State != "off" {
		t.Errorf("state = %q, want %q: nothing about it is broken", view.State, "off")
	}
	if !strings.Contains(view.Detail, "OpenVPN") {
		t.Errorf("detail = %q, want it to say why nothing is running", view.Detail)
	}
	if _, registered := h.agent.tunnels.Get("tn_lab"); registered {
		t.Error("a connection nothing here can start was registered as one that carries traffic")
	}
}

// The add menu is served rather than held by each client, so a kind that cannot be brought
// up is never offered and then refused after somebody has filled the form in.
func TestOnlyTheKindsThisBuildCanStartAreOfferedToAdd(t *testing.T) {
	h := newHarness(t, nil)

	types := h.agent.TunnelsAPI().Types()

	if len(types) == 0 {
		t.Fatal("no kind of connection is offered, so nothing can be added at all")
	}
	for _, offered := range types {
		if _, err := h.agent.TunnelsAPI().Create(context.Background(),
			httpapi.TunnelSpec{Type: offered.Value, Name: "Probe " + offered.Label}); err != nil {
			t.Errorf("%q is offered but adding one is refused: %v", offered.Value, err)
		}
		if offered.Label == "" {
			t.Errorf("%q is offered with no label, so a menu would have nothing to show", offered.Value)
		}
	}
}

// A kind the privileged side cannot run is left off the menu, which is where the refusal
// belongs: before anybody has filled a form in for it.
func TestAKindThisBuildCannotStartIsNotOfferedToAdd(t *testing.T) {
	h := newHarnessWith(t, nil, withoutOpenVPN)

	for _, offered := range h.agent.TunnelsAPI().Types() {
		if offered.Value == config.TunnelOpenVPN {
			t.Fatalf("%q is offered by an agent whose privileged side cannot run it", offered.Value)
		}
	}
}

// A protocol this build has never heard of is the caller's mistake, and it has to be
// refused by name: stored, it would be a connection every later load of the document
// rejects.
func TestAddingAConnectionOfAnUnknownTypeIsRefused(t *testing.T) {
	h := newHarness(t, nil)

	_, err := h.agent.TunnelsAPI().Create(context.Background(),
		httpapi.TunnelSpec{Type: config.TunnelType("ipsec"), Name: "Datacentre"})

	if err == nil {
		t.Fatal("a connection of an unknown kind was accepted")
	}
	var validation *config.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %v, want a validation error so it maps to a rejection rather than a fault", err)
	}
	if !strings.Contains(err.Error(), "ipsec") {
		t.Errorf("error = %v, want it to name what was refused", err)
	}
	if len(h.store.Get().Tunnels) != 1 {
		t.Error("the refused connection was stored anyway")
	}
}

// Two connections added under one name must not end up under one DNS label: the label is
// what a name on that network is spelled with, and two networks answering for one suffix
// means a lookup has two answers.
func TestASecondConnectionWithTheSameNameGetsADistinctLabel(t *testing.T) {
	h := newHarness(t, nil)

	first := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})
	second := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})

	if first.Slug == second.Slug {
		t.Fatalf("both connections answer for %q, so a name under it has two answers", first.Slug)
	}
	if second.Slug != "office-2" {
		t.Errorf("second slug = %q, want the numbered form a person would have typed", second.Slug)
	}
}

// mustCreateTunnel adds a connection and fails the test if it could not be added.
// A client decides whether to offer removal from the view, so the view has to agree with
// what a removal would actually do. Two answers here means a button on screen whose only
// outcome is a refusal, or a connection nobody is offered a way to get rid of.
func TestWhatTheViewSaysCanBeRemovedIsWhatCanBeRemoved(t *testing.T) {
	h := newHarness(t, nil)
	added := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelTailscale, Name: "Office"})

	for _, held := range []struct {
		id        string
		removable bool
	}{
		{id: config.PrimaryTunnelID, removable: false},
		{id: added.ID, removable: true},
	} {
		if got := viewOfTunnel(t, h, held.id).Removable; got != held.removable {
			t.Errorf("connection %s reports removable=%v, want %v", held.id, got, held.removable)
		}
		err := h.agent.TunnelsAPI().Delete(context.Background(), held.id)
		if (err == nil) != held.removable {
			t.Errorf("removing connection %s: error = %v, but the view says removable=%v",
				held.id, err, held.removable)
		}
	}
}

func mustCreateTunnel(t *testing.T, h *harness, spec httpapi.TunnelSpec) httpapi.TunnelView {
	t.Helper()
	view, err := h.agent.TunnelsAPI().Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("adding a %s connection: %v", spec.Type, err)
	}
	return view
}

// viewOfTunnel is one connection as the API reports it now.
func viewOfTunnel(t *testing.T, h *harness, id string) httpapi.TunnelView {
	t.Helper()
	view, err := h.agent.TunnelsAPI().Get(id)
	if err != nil {
		t.Fatalf("reading connection %s: %v", id, err)
	}
	return view
}

// The form is rendered from the schema, so an installation that served no fields would
// show an empty connection page with no explanation.
func TestTheConnectionSchemaIsServedForThisInstallation(t *testing.T) {
	agent := newUnstartedAgent(t)

	schema := agent.TunnelsAPI().Schema()

	if len(schema) == 0 {
		t.Fatal("the connection schema is empty")
	}
	for _, f := range schema {
		if f.Available == nil {
			t.Errorf("field %q does not say whether it is available here", f.Key)
		}
	}
}

// The list the machine-wide resolver and the auto-config file are both built from. A
// connection missing from it is a name that leaves this machine for a public resolver, and
// a connection named by nothing is a refusal a reader cannot act on.
func TestEveryConnectionIsListedUnderTheNameItAnswersFor(t *testing.T) {
	app := config.Settings{}
	held := []config.Tunnel{
		{ID: "tn_office", Slug: "office", Name: "Office"},
		// Named by nothing but its short name, which is what a connection added without a
		// display name looks like.
		{ID: "tn_lab", Slug: "lab"},
		// Neither a short name nor an id, which only a hand-edited document produces. It
		// answers for no suffix, and a suffix of just the zone would be every other
		// connection's parent.
		{},
	}

	got := tunnelSuffixesOf(held, app)

	want := []dnsfwd.TunnelSuffix{
		// The id travels with the suffix because it is what a name on the connection is
		// resolved through once one interface is carrying it.
		{Suffix: "office." + config.DefaultDNSZone, Name: "Office", ID: "tn_office"},
		{Suffix: "lab." + config.DefaultDNSZone, Name: "lab", ID: "tn_lab"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("suffixes = %+v, want %+v", got, want)
	}
}

// A connection added with no name still has to be listed under something. A blank row is one
// nobody can pick out of a list, and the kind it is is the only thing known about it yet.
func TestAConnectionAddedWithNoNameIsListedUnderItsKind(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.TunnelsAPI().Create(context.Background(),
		httpapi.TunnelSpec{Type: config.TunnelWireGuard, Name: "   "})
	if err != nil {
		t.Fatalf("adding a connection: %v", err)
	}

	if view.Name == "" {
		t.Fatal("the connection is listed under nothing at all")
	}
	if view.Name != config.TunnelWireGuard.Label() {
		t.Errorf("name = %q, want the kind of connection it is", view.Name)
	}
	if view.Slug == "" {
		t.Error("the connection answers for no name suffix, so nothing on it can be resolved")
	}
}

// Reading the devices on a connection that is not stored is a not-found rather than an empty
// list: a form told "no devices" for a connection that does not exist sends somebody looking
// for a network problem that is not there.
func TestReadingTheDevicesOnAConnectionThatIsNotStoredIsNotFound(t *testing.T) {
	h := newHarness(t, nil)

	_, err := h.agent.TunnelsAPI().Peers(context.Background(), "tn_absent")

	if !errors.Is(err, config.ErrNotFound) {
		t.Errorf("error = %v, want a not-found", err)
	}
}

// A refusal that names the forwards in the way is the difference between an instruction and
// a complaint. It names a handful and then says there are more, because a message listing
// forty forwards is one nobody reads -- and a forward with no name of its own is named by
// the port it opens, which is what its row shows.
func TestRemovingAConnectionNamesTheForwardsInTheWayAndStopsNamingThem(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Tunnels = append(c.Tunnels, config.NewTunnel("tn_lab", "lab", "Lab", config.TunnelWireGuard))
		for i, name := range []string{"LLM", "Files", "Shell", ""} {
			c.Forwards = append(c.Forwards, config.Forward{
				ID: "fwd_" + strconv.Itoa(i), Name: name, TunnelID: "tn_lab",
				Direction: config.ToLocal, Protocol: config.TCP,
				BindAddr: "127.0.0.1", ListenPort: 19000 + i,
				Target: "10.9.0.5:8100", Enabled: false,
			})
		}
	})

	err := h.agent.TunnelsAPI().Delete(context.Background(), "tn_lab")

	if err == nil {
		t.Fatal("a connection was removed out from under the forwards crossing it")
	}
	for _, want := range []string{"LLM", "Files", "Shell", "and others"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name %q", err, want)
		}
	}
	// The unnamed forward is past the handful, so it is covered by "and others" rather than
	// named -- what must not happen is a bare empty pair of quotes in the sentence.
	if strings.Contains(err.Error(), `""`) {
		t.Errorf("error = %v, want no forward listed under a blank name", err)
	}
	if _, stored := h.store.Get().Tunnel("tn_lab"); !stored {
		t.Error("the connection was removed despite the refusal")
	}
}

// Removing the connection carrying this machine's internet traffic is refused for the same
// reason the forwards are: the document that would result names a connection that is gone.
// Without this the refusal arrives from the validator naming a field, and the alternative
// -- clearing the setting on the user's behalf -- would put every request on the ISP link
// as a side effect of removing something else.
func TestRemovingTheConnectionCarryingInternetTrafficSaysToPointItElsewhereFirst(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Tunnels = append(c.Tunnels, config.NewTunnel("tn_lab", "lab", "Lab", config.TunnelWireGuard))
		c.Settings.EgressMode = config.EgressTunnel
		c.Settings.EgressTunnelID = "tn_lab"
	})

	err := h.agent.TunnelsAPI().Delete(context.Background(), "tn_lab")

	if err == nil {
		t.Fatal("the connection carrying internet traffic was removed out from under it")
	}
	// The name rather than the id: the id is not on any screen the person is looking at.
	if !strings.Contains(err.Error(), "internet traffic") || !strings.Contains(err.Error(), "Lab") {
		t.Errorf("error = %v, want it to say what this connection is carrying", err)
	}
	if _, stored := h.store.Get().Tunnel("tn_lab"); !stored {
		t.Error("the connection was removed despite the refusal")
	}
	if h.store.Get().Settings.EgressTunnelID != "tn_lab" {
		t.Error("the refusal moved this machine's internet traffic anyway")
	}
}

// A connection named as the carrier while the traffic leaves directly is not carrying
// anything, and refusing to remove it would make an old choice able to block a delete
// forever. The document accepts an id left behind that way, so nothing has to be checked.
func TestRemovingAConnectionNamedForInternetTrafficThatIsNotCarryingItIsAllowed(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Tunnels = append(c.Tunnels, config.NewTunnel("tn_lab", "lab", "Lab", config.TunnelWireGuard))
		c.Settings.EgressMode = config.EgressDirect
		c.Settings.EgressTunnelID = "tn_lab"
	})

	if err := h.agent.TunnelsAPI().Delete(context.Background(), "tn_lab"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, stored := h.store.Get().Tunnel("tn_lab"); stored {
		t.Error("the connection is still stored")
	}
}

// Moving a connection to another control server drops its stored key, and the answer to
// the write is where the person who made it learns that and what to do next.
func TestMovingAConnectionToAnotherControlServerSaysItsCredentialWasCleared(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Settings.AdvancedNetworking = true
		primary, err := c.PrimaryTailscale()
		if err != nil {
			t.Fatalf("primary tailnet: %v", err)
		}
		primary.AuthKey = "tskey-auth-kOLD-secret"
	})

	view, err := h.agent.TunnelsAPI().Update(context.Background(), config.PrimaryTunnelID,
		patchOf(t, map[string]any{"controlURL": "https://control.example.net"}))
	if err != nil {
		t.Fatalf("changing the control server: %v", err)
	}

	want := "The credential was cleared because the control server changed; enter it again for https://control.example.net."
	if !strings.Contains(view.Detail, want) {
		t.Errorf("detail = %q, want it to contain %q", view.Detail, want)
	}
	stored, _ := h.store.Get().Tunnel(config.PrimaryTunnelID)
	if stored.TS().AuthKey != "" {
		t.Errorf("authKey = %q, want it cleared", stored.TS().AuthKey)
	}
}
