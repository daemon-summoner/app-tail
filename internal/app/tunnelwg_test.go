// SPDX-License-Identifier: MIT

package app

// What the agent does with a WireGuard connection: when it builds one, when it leaves one
// alone, when it takes one down and what it says when one will not come up.
//
// The device itself is covered against a second real device where it lives. These are about
// the wiring, which is where a connection that is configured and never started, or restarted
// on every pass, actually comes from.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// wgSettings is a complete WireGuard connection as the settings form writes one.
func wgSettings() map[string]any {
	return map[string]any{
		"wg.privateKey":        "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=",
		"wg.addresses":         []string{"10.7.0.4/24"},
		"wg.peer.publicKey":    "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=",
		"wg.peer.endpoint":     "gateway.example.com:51820",
		"wg.peer.allowedIPs":   []string{"10.7.0.0/24"},
		"wg.peer.keepaliveSec": 25,
		"wg.mtu":               1420,
	}
}

// wgTunnelID is the connection these tests seed. It is fixed so a test can name it before
// the agent has started.
const wgTunnelID = "tn_office"

// seedWireGuard puts one complete WireGuard connection in the document.
//
// Seeded rather than added through the API, so the agent starts with it already configured
// and builds one device. Adding one and configuring it afterwards is two documents and two
// devices, which is a different thing to assert and is covered on its own.
func seedWireGuard(c *config.Config) {
	held := config.NewTunnel(wgTunnelID, "office", "Office", config.TunnelWireGuard)
	held.WireGuard = &config.WireGuardTunnel{
		PrivateKey: "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=",
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.7.0.4/24")},
		MTU:        config.DefaultWireGuardMTU,
		Peer: config.WireGuardPeer{
			PublicKey:    "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=",
			Endpoint:     "gateway.example.com:51820",
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.7.0.0/24")},
			KeepaliveSec: config.DefaultWireGuardKeepaliveSec,
		},
	}
	c.Tunnels = append(c.Tunnels, held)
}

// runningWireGuard is a harness whose seeded WireGuard connection is up.
func runningWireGuard(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, seedWireGuard)
	waitFor(t, 5*time.Second, "the seeded connection to be registered", func() bool {
		_, registered := h.agent.tunnels.Get(wgTunnelID)
		return registered
	})
	return h
}

// A configured WireGuard connection has to end up in the registry: that is what the proxy,
// the forwards and the automatic mapper reach a network through, so a connection that is up
// and not registered is one nothing on this machine can use.
func TestAConfiguredWireGuardConnectionIsStartedAndRegistered(t *testing.T) {
	h := runningWireGuard(t)

	built := h.wireguards.devicesFor(wgTunnelID)
	if len(built) != 1 {
		t.Fatalf("%d devices were built for one connection, want exactly one", len(built))
	}
	if !built[0].wasStarted() {
		t.Error("the device was built and never started")
	}
	if got := built[0].held.Peer.Endpoint; got != "gateway.example.com:51820" {
		t.Errorf("the device was built with the server %q, want the one that was configured", got)
	}
	if got := viewOfTunnel(t, h, wgTunnelID).State; got != string(tunnel.StateConnected) {
		t.Errorf("the connection reports %q, want what the device reports", got)
	}
}

// A WireGuard connection carries no login and no enrollment: the device is the connection,
// so every setting that describes it is one the device has to be rebuilt to pick up. A
// change saved and never applied is a connection running on the previous server with the new
// one on screen.
func TestChangingAWireGuardSettingRebuildsTheDeviceWithIt(t *testing.T) {
	h := runningWireGuard(t)
	first := h.wireguards.devicesFor(wgTunnelID)[0]

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), wgTunnelID,
		patchOf(t, map[string]any{"wg.peer.endpoint": "backup.example.com:51820"})); err != nil {
		t.Fatalf("changing the server: %v", err)
	}

	waitFor(t, 5*time.Second, "the connection to be rebuilt", func() bool {
		return len(h.wireguards.devicesFor(wgTunnelID)) == 2
	})
	built := h.wireguards.devicesFor(wgTunnelID)
	if got := built[1].held.Peer.Endpoint; got != "backup.example.com:51820" {
		t.Errorf("the new device dials %q, want the server that was just set", got)
	}
	if !first.wasClosed() {
		t.Error("the device on the previous server is still running, so both are up at once")
	}
}

// A pass that changes nothing must leave the connection alone. Rebuilding on every reconcile
// would drop every connection through it a few times a minute, which reads as a network
// problem and is not one.
func TestAReconcileThatChangesNothingLeavesAWireGuardConnectionRunning(t *testing.T) {
	h := runningWireGuard(t)

	// A setting that has nothing to do with this connection, applied the way any other
	// change arrives: through the store and a reconcile.
	storeSetting(h, func(s *config.Settings) { s.AutoMapMax = 7 })
	h.agent.pokeReconcile()
	h.agent.pokeReconcile()

	built := h.wireguards.devicesFor(wgTunnelID)
	if len(built) != 1 {
		t.Fatalf("%d devices were built for one unchanged connection, want exactly one", len(built))
	}
	if built[0].wasClosed() {
		t.Error("the running connection was taken down by a pass that changed nothing about it")
	}
}

// A device that will not come up is the ordinary WireGuard failure: a wrong key, a server
// that does not resolve. The reason has to reach the connection, because it is the only
// thing on screen that tells a connection that failed from one somebody switched off.
func TestAWireGuardConnectionThatCannotStartReportsWhy(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelWireGuard, Name: "Office"})
	h.wireguards.refuseToStart(view.ID, errors.New("the server gateway.example.com resolved to no addresses"))

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), view.ID,
		patchOf(t, wgSettings())); err != nil {
		t.Fatalf("configuring the connection: %v", err)
	}

	waitFor(t, 5*time.Second, "the connection to report why it is not running", func() bool {
		return viewOfTunnel(t, h, view.ID).Detail != ""
	})
	got := viewOfTunnel(t, h, view.ID)
	if got.State != string(tunnel.StateFailed) {
		t.Errorf("the connection reports %q, want %q", got.State, tunnel.StateFailed)
	}
	if got.Detail != "the server gateway.example.com resolved to no addresses" {
		t.Errorf("the reason given is %q, want the one the device refused with", got.Detail)
	}
	if _, registered := h.agent.tunnels.Get(view.ID); registered {
		t.Error("a connection that never came up was registered as one that carries traffic")
	}
}

// Switching a connection off has to close the device and take it out of the registry, or a
// connection reported as off goes on carrying traffic for anything already pointed at it.
func TestSwitchingAWireGuardConnectionOffClosesTheDevice(t *testing.T) {
	h := runningWireGuard(t)
	built := h.wireguards.devicesFor(wgTunnelID)[0]

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), wgTunnelID,
		patchOf(t, map[string]any{"enabled": false})); err != nil {
		t.Fatalf("switching the connection off: %v", err)
	}

	waitFor(t, 5*time.Second, "the connection to stop", func() bool {
		_, registered := h.agent.tunnels.Get(wgTunnelID)
		return !registered
	})
	if !built.wasClosed() {
		t.Error("the device is still running after the connection was switched off")
	}
	if got := viewOfTunnel(t, h, wgTunnelID).State; got != string(tunnel.StateOff) {
		t.Errorf("the connection reports %q, want %q", got, tunnel.StateOff)
	}
}

// Removing a connection has to stop it too. A device left running on a connection nobody can
// see any more is one nothing can stop short of ending the process.
func TestRemovingAWireGuardConnectionClosesTheDevice(t *testing.T) {
	h := runningWireGuard(t)
	built := h.wireguards.devicesFor(wgTunnelID)[0]

	if err := h.agent.TunnelsAPI().Delete(context.Background(), wgTunnelID); err != nil {
		t.Fatalf("removing the connection: %v", err)
	}

	waitFor(t, 5*time.Second, "the connection to stop", func() bool {
		_, registered := h.agent.tunnels.Get(wgTunnelID)
		return !registered
	})
	if !built.wasClosed() {
		t.Error("the device is still running after the connection was removed")
	}
}

// WireGuard has no network monitor of its own. Without something telling it, a connection
// that was up on one network stays bound to a socket that network owned: the laptop closes
// at the desk and is quiet at the coffee shop until someone restarts the app.
func TestAWireGuardConnectionIsToldWhenTheMachineMoves(t *testing.T) {
	h := runningWireGuard(t)

	built := h.wireguards.devicesFor(wgTunnelID)
	if len(built) != 1 {
		t.Fatalf("%d devices were built for one connection, want exactly one", len(built))
	}
	if built[0].links == nil {
		t.Error("the device was built with nothing to tell it the machine's networking moved")
	}
}

// The watcher costs a subscription to the operating system's own notifications, so it ends
// with the connection it was opened for. One left running per connection ever started is a
// process that gets more expensive the longer it is up.
func TestWatchingTheMachineStopsWithTheConnection(t *testing.T) {
	h := runningWireGuard(t)
	watchers := h.links.watchers()
	if len(watchers) != 1 {
		t.Fatalf("%d watchers were opened for one connection, want exactly one", len(watchers))
	}

	if err := h.agent.TunnelsAPI().Delete(context.Background(), wgTunnelID); err != nil {
		t.Fatalf("removing the connection: %v", err)
	}

	waitFor(t, 5*time.Second, "the machine's networking to stop being watched", func() bool {
		return watchers[0].Err() != nil
	})
}

// A machine that will not report interface changes is a connection that works and does not
// roam, not a connection that cannot start. Refusing to bring it up would take a working
// network away over a monitor.
func TestAConnectionStartsOnAMachineThatCannotBeWatched(t *testing.T) {
	h := newHarnessWith(t, seedWireGuard, func(o *Options) {
		o.WatchLinkChanges = func(context.Context) (<-chan struct{}, error) {
			return nil, errors.New("this platform does not report interface changes")
		}
	})

	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(wgTunnelID)
		return registered
	})
	built := h.wireguards.devicesFor(wgTunnelID)
	if len(built) != 1 || !built[0].wasStarted() {
		t.Fatalf("the connection did not start on a machine whose networking cannot be watched")
	}
}

// And it has to say so. A connection that will not notice this machine moving networks goes
// quiet after a move with nothing to distinguish it from a server that stopped answering, and
// the only thing that would have said why is a warning in a log the user never opens.
func TestAConnectionThatCannotBeWatchedSaysWhatThatCostsThem(t *testing.T) {
	h := newHarnessWith(t, seedWireGuard, func(o *Options) {
		o.WatchLinkChanges = func(context.Context) (<-chan struct{}, error) {
			return nil, errors.New("this platform does not report interface changes")
		}
	})

	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(wgTunnelID)
		return registered
	})

	view := viewOfTunnel(t, h, wgTunnelID)
	if view.State != string(tunnel.StateConnected) {
		t.Fatalf("the connection reports %q, want %q: it works, it just does not roam",
			view.State, tunnel.StateConnected)
	}
	if view.Detail != "" {
		t.Errorf("the connection reports %q as a fault, want a limit rather than a failure", view.Detail)
	}
	stated := strings.Join(view.Limits, " ")
	if !strings.Contains(stated, "changes networks") {
		t.Errorf("the connection states its limits as %v, none of which mentions this machine "+
			"changing networks", view.Limits)
	}
}

// The other half: a connection whose watcher was attached must state no such limit, or every
// connection on every machine carries a warning about a thing that is working.
func TestAWatchedConnectionStatesNoSuchLimit(t *testing.T) {
	h := runningWireGuard(t)

	for _, limit := range viewOfTunnel(t, h, wgTunnelID).Limits {
		if strings.Contains(limit, "changes networks") {
			t.Errorf("a connection that is watched still reports %q", limit)
		}
	}
}

// The file a server issues is how a WireGuard connection is actually configured: nobody
// transcribes one. Importing it has to leave the connection running on what the file says,
// or the user is back to typing keys by hand.
func TestImportingAServersFileConfiguresAndStartsTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelWireGuard, Name: "Office"})

	imported, err := h.agent.TunnelsAPI().Import(context.Background(), view.ID, `
[Interface]
PrivateKey = aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=
Address = 10.7.0.4/24
DNS = 10.7.0.1

[Peer]
PublicKey = vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=
AllowedIPs = 10.7.0.0/24
Endpoint = gateway.example.com:51820
PersistentKeepalive = 25
`)
	if err != nil {
		t.Fatalf("importing a configuration file: %v", err)
	}

	if got := imported.Settings["wg.peer.endpoint"]; got != "gateway.example.com:51820" {
		t.Errorf("the connection reports the server %q, want the one the file named", got)
	}
	// The private key is a secret, so the form reports that there is one rather than what it
	// is. An import that stored nothing would report the same absence as one that failed.
	if got := imported.Settings["wg.hasPrivateKey"]; got != true {
		t.Errorf("the connection reports no private key after importing a file that carries one")
	}
	waitFor(t, 5*time.Second, "the imported connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})
	built := h.wireguards.devicesFor(view.ID)
	last := built[len(built)-1]
	if last.held.Peer.Endpoint != "gateway.example.com:51820" {
		t.Errorf("the device dials %q, want the server the file named", last.held.Peer.Endpoint)
	}
	if len(last.held.DNS) != 1 || last.held.DNS[0] != netip.MustParseAddr("10.7.0.1") {
		t.Errorf("the device resolves through %v, want the resolver the file named", last.held.DNS)
	}
}

// A file naming something this app cannot honour is refused whole, and nothing is written.
// Importing the rest would leave a connection that looks like the one the file describes and
// silently does less -- which is exactly how a firewall rule in a PostUp goes missing.
func TestAFileThisAppCannotHonourIsRefusedAndNothingIsStored(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelWireGuard, Name: "Office"})
	before, _ := h.store.Get().Tunnel(view.ID)

	_, err := h.agent.TunnelsAPI().Import(context.Background(), view.ID, `
[Interface]
PrivateKey = aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=
Address = 10.7.0.4/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=
AllowedIPs = 10.7.0.0/24
Endpoint = gateway.example.com:51820
`)

	if err == nil {
		t.Fatal("a file carrying a command to run on this machine was imported")
	}
	var refusal *config.ValidationError
	if !errors.As(err, &refusal) || refusal.Field != "file" {
		t.Errorf("error = %v, want a rejection naming the file so the form can mark it", err)
	}
	stored, _ := h.store.Get().Tunnel(view.ID)
	if !stored.WireGuard.SameAs(*before.WireGuard) {
		t.Errorf("the refused file changed the connection to %+v, want it left at %+v",
			stored.WireGuard, before.WireGuard)
	}
}

// A configuration file describes a WireGuard connection and nothing else. Reading one into a
// tailnet connection would either do nothing or overwrite settings that came from a control
// plane, so it is refused with what this connection actually is.
func TestAConfigurationFileCannotBeImportedIntoATailnetConnection(t *testing.T) {
	h := newHarness(t, nil)

	_, err := h.agent.TunnelsAPI().Import(context.Background(), config.PrimaryTunnelID,
		"[Interface]\nPrivateKey = aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=\n")

	if err == nil {
		t.Fatal("a WireGuard configuration was imported into a tailnet connection")
	}
	if !strings.Contains(err.Error(), "Tailscale") {
		t.Errorf("error = %v, want it to say what this connection is", err)
	}
}

// A WireGuard connection has no tailnet node behind it, and the surfaces that push tailnet
// preferences ask for one by connection id. Handing them the primary node -- the only other
// node in the process -- would apply one network's preferences to another.
func TestAWireGuardConnectionHasNoTailnetNodeBehindIt(t *testing.T) {
	h := runningWireGuard(t)

	if node := h.agent.nodeFor(wgTunnelID); node != nil {
		t.Error("a WireGuard connection reports a tailnet node, so tailnet preferences " +
			"would be pushed at another network's node")
	}
}

// What a connection has carried travels with it. The state word is "connected" for a
// connection that is working and for one that is up and moving nothing, and these figures are
// the only thing on the screen that tells them apart.
func TestWhatAConnectionCarriedIsServedWithIt(t *testing.T) {
	h := runningWireGuard(t)
	built := h.wireguards.devicesFor(wgTunnelID)[0]
	handshake := time.Now().Add(-90 * time.Second)
	built.carries(tunnel.Carried{
		Up:            2048,
		Down:          4096,
		Since:         time.Now().Add(-time.Hour),
		LastHandshake: handshake,
		Dropped:       7,
	})

	health := viewOfTunnel(t, h, wgTunnelID).Health
	if health == nil {
		t.Fatal("a running WireGuard connection reports nothing about what it has carried")
	}
	if health.Up != 2048 || health.Down != 4096 {
		t.Errorf("the connection reports %d up and %d down, want 2048 up and 4096 down",
			health.Up, health.Down)
	}
	if !health.LastHandshake.Equal(handshake) {
		t.Errorf("the connection reports its last handshake at %s, want %s", health.LastHandshake, handshake)
	}
	if health.Since.IsZero() {
		t.Error("the connection reports no moment it was built, so nothing can say how long it has been up")
	}
	if health.Dropped != 7 {
		t.Errorf("the connection reports %d dropped packets, want 7", health.Dropped)
	}
}

// A connection that is not running has carried nothing this process can vouch for. Reporting
// the last figures it had would put a total on screen beside a connection that is down, which
// reads as traffic crossing right now.
func TestAConnectionThatIsNotRunningReportsNothingAboutWhatItCarried(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		seedWireGuard(c)
		c.Tunnels[len(c.Tunnels)-1].Enabled = false
	})

	if health := viewOfTunnel(t, h, wgTunnelID).Health; health != nil {
		t.Errorf("a connection that is switched off reports %+v about what it carried, want nothing", *health)
	}
}
