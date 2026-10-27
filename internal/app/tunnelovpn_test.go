// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tunnel/ovpntunnel"
)

const ovpnTunnelID = "tn_ovpn01"

// seedOpenVPN stores one configured OpenVPN connection, switched on.
func seedOpenVPN(edit func(*config.OpenVPNTunnel)) func(*config.Config) {
	return func(c *config.Config) {
		held := config.OpenVPNTunnel{
			Remote:       "vpn.example.com:1194",
			Proto:        config.OpenVPNProtoUDP,
			CA:           "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
			AuthUserPass: true,
			Username:     "alice",
			Password:     "s3cret",
			Routes:       []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
		}
		if edit != nil {
			edit(&held)
		}
		c.Tunnels = append(c.Tunnels, config.Tunnel{
			ID: ovpnTunnelID, Slug: "lab", Name: "Lab", Type: config.TunnelOpenVPN,
			Enabled: true, OpenVPN: &held,
		})
	}
}

// A configured OpenVPN connection is started by the same reconcile that starts every other
// kind, and it is what the registry hands a caller asking for that network.
func TestAStoredOpenVPNConnectionIsStartedAndRegistered(t *testing.T) {
	h := newHarness(t, seedOpenVPN(nil))

	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		_, registered := h.agent.tunnels.Get(ovpnTunnelID)
		return registered
	})
	built := h.openvpns.connectionsFor(ovpnTunnelID)
	if len(built) != 1 || !built[0].wasStarted() {
		t.Fatalf("the connection was built %d times and did not start", len(built))
	}
	if built[0].held.Remote != "vpn.example.com:1194" {
		t.Errorf("the connection dials %q, want the server it was configured with", built[0].held.Remote)
	}
	// One claim while a connection is up. Every OpenVPN connection runs through the same one,
	// and dropping it stops all of them.
	if held := h.openvpns.held(); held != 1 {
		t.Errorf("%d claims on the privileged side are outstanding, want 1", held)
	}
}

// Administrator rights are asked for when the first OpenVPN connection needs them and given
// back when the last one stops. Holding them for the life of the process would mean a machine
// with no OpenVPN connection configured asking for rights it never uses.
func TestTheClaimOnAdministratorRightsLastsExactlyAsLongAsAConnectionDoes(t *testing.T) {
	h := newHarness(t, seedOpenVPN(nil))

	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		return h.openvpns.held() == 1
	})

	if err := h.agent.TunnelsAPI().Delete(context.Background(), ovpnTunnelID); err != nil {
		t.Fatalf("removing the connection: %v", err)
	}

	waitFor(t, 5*time.Second, "the claim to be given back", func() bool {
		return h.openvpns.held() == 0
	})
	built := h.openvpns.connectionsFor(ovpnTunnelID)
	if !built[len(built)-1].wasClosed() {
		t.Error("the connection was not closed")
	}
}

// An OpenVPN connection has to be told when this machine moves networks too. Without it the
// program goes on sending from an address that no longer exists until the server's own ping
// timeout expires, which is the server's to choose and is usually a minute or more of a laptop
// that looks connected and reaches nothing.
func TestAnOpenVPNConnectionIsToldWhenTheMachineMoves(t *testing.T) {
	h := newHarness(t, seedOpenVPN(nil))

	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) == 1
	})

	if built := h.openvpns.connectionsFor(ovpnTunnelID); built[0].links == nil {
		t.Error("the connection was built with nothing to tell it the machine's networking moved")
	}
}

// And the watcher ends with the connection: one subscription to the operating system's own
// notifications left per connection ever started is a process that gets more expensive the
// longer it runs.
func TestWatchingTheMachineStopsWithAnOpenVPNConnection(t *testing.T) {
	h := newHarness(t, seedOpenVPN(nil))

	waitFor(t, 5*time.Second, "the machine's networking to be watched", func() bool {
		return len(h.links.watchers()) == 1
	})
	watchers := h.links.watchers()

	if err := h.agent.TunnelsAPI().Delete(context.Background(), ovpnTunnelID); err != nil {
		t.Fatalf("removing the connection: %v", err)
	}

	waitFor(t, 5*time.Second, "the machine's networking to stop being watched", func() bool {
		return watchers[0].Err() != nil
	})
}

// A machine that will not grant administrator rights is a connection that cannot start, and
// the reason has to be on the connection: it is the one thing the user can act on, and
// without it the connection reads as broken for no stated reason.
func TestAMachineThatWillNotGrantRightsIsReportedOnTheConnection(t *testing.T) {
	h := newHarnessWith(t, seedOpenVPN(nil), nil)
	// Set before the first pass this test drives, rather than at construction, so the harness
	// itself is not racing the refusal it is about to install.
	h.openvpns.refuseToClaim(errors.New("this machine has no helper installed"))
	if err := h.agent.TunnelsAPI().Delete(context.Background(), ovpnTunnelID); err != nil {
		t.Fatalf("removing the connection: %v", err)
	}
	if _, err := h.agent.TunnelsAPI().Create(context.Background(),
		httpapi.TunnelSpec{Type: config.TunnelOpenVPN, Name: "Lab"}); err != nil {
		t.Fatalf("adding a connection: %v", err)
	}

	var detail string
	waitFor(t, 5*time.Second, "the refusal to be reported", func() bool {
		for _, view := range h.agent.TunnelsAPI().List() {
			if view.Type == config.TunnelOpenVPN && view.Detail != "" {
				detail = view.Detail
				return true
			}
		}
		return false
	})
	if !strings.Contains(detail, "no helper installed") {
		t.Errorf("detail = %q, want the machine's own reason", detail)
	}
}

// Whether this connection carries the machine's internet traffic is decided when the program
// starts and cannot be changed while it runs, so choosing a different connection to carry it
// has to rebuild this one. An edit that is saved and never reaches the running connection is
// the failure this pins.
func TestChoosingThisConnectionToCarryTheInternetRebuildsIt(t *testing.T) {
	h := newHarness(t, seedOpenVPN(func(o *config.OpenVPNTunnel) {
		o.Routes = append(o.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	}))

	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) == 1
	})
	if built := h.openvpns.connectionsFor(ovpnTunnelID); built[0].carry != ovpntunnel.CarryNone {
		t.Fatalf("the connection was built carrying this machine's internet traffic as %q before "+
			"it was chosen to", built[0].carry)
	}

	storeSetting(h, func(s *config.Settings) {
		s.EgressMode = config.EgressTunnel
		s.EgressTunnelID = ovpnTunnelID
	})

	waitFor(t, 5*time.Second, "the connection to be rebuilt", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) == 2
	})
	built := h.openvpns.connectionsFor(ovpnTunnelID)
	if built[1].carry != ovpntunnel.CarryDefault {
		t.Errorf("the rebuilt connection carries this machine's internet traffic as %q, want it "+
			"taking the machine's own default route", built[1].carry)
	}
	if !built[0].wasClosed() {
		t.Error("the connection that was replaced is still running")
	}
}

// With the one-interface mode on, carrying this machine's internet traffic is a route beside
// the connection rather than a line in what started openvpn -- so the running connection is
// told, and the program it is holding is left alone.
//
// Rebuilding it instead is what the user reported: switching which connection carries the
// traffic dropped a working VPN, asked its server for the account again, and took this machine
// off the internet for the length of a handshake. This pins that the program is not restarted
// and that the choice still reaches the connection.
func TestChoosingThisConnectionToCarryTheInternetOnItsOwnInterfaceKeepsItRunning(t *testing.T) {
	h := newHarness(t, seedOpenVPN(func(o *config.OpenVPNTunnel) {
		o.Routes = append(o.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	}))
	storeSetting(h, func(s *config.Settings) {
		s.InterfaceEnabled = true
		s.InterfaceMode = config.NetworkFabric
	})

	waitFor(t, 5*time.Second, "the connection to start", func() bool {
		return len(h.openvpns.connectionsFor(ovpnTunnelID)) == 1
	})
	built := h.openvpns.connectionsFor(ovpnTunnelID)[0]
	if got := built.carriedAs(); got != ovpntunnel.CarryNone {
		t.Fatalf("the connection was built carrying this machine's internet traffic as %q before "+
			"it was chosen to", got)
	}

	storeSetting(h, func(s *config.Settings) {
		s.EgressMode = config.EgressTunnel
		s.EgressTunnelID = ovpnTunnelID
	})

	waitFor(t, 5*time.Second, "the running connection to be told it carries the traffic", func() bool {
		return built.carriedAs() == ovpntunnel.CarryScoped
	})
	if again := h.openvpns.connectionsFor(ovpnTunnelID); len(again) != 1 {
		t.Errorf("openvpn was started %d times, want the running program left alone", len(again))
	}
	if built.wasClosed() {
		t.Error("the connection was closed, so the program carrying the traffic was restarted")
	}

	storeSetting(h, func(s *config.Settings) {
		s.EgressMode = config.EgressDirect
		s.EgressTunnelID = ""
	})
	waitFor(t, 5*time.Second, "the connection to be told it no longer carries the traffic", func() bool {
		return built.carriedAs() == ovpntunnel.CarryNone
	})
	if again := h.openvpns.connectionsFor(ovpnTunnelID); len(again) != 1 {
		t.Errorf("openvpn was started %d times, want the running program left alone", len(again))
	}
}

// The file a server issues is how an OpenVPN connection is actually configured: nobody
// transcribes the certificates by hand.
func TestImportingAnOpenVPNFileConfiguresTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelOpenVPN, Name: "Lab"})

	imported, err := h.agent.TunnelsAPI().Import(context.Background(), view.ID, `client
dev tun
proto udp
remote vpn.example.com 1194
auth-user-pass
remote-cert-tls server
route 10.8.0.0 255.255.0.0
dhcp-option DNS 10.8.0.1
<ca>
-----BEGIN CERTIFICATE-----
Zm9vYmFyYmF6
-----END CERTIFICATE-----
</ca>
`)
	if err != nil {
		t.Fatalf("importing a configuration file: %v", err)
	}

	if got := imported.Settings["ovpn.remote"]; got != "vpn.example.com:1194" {
		t.Errorf("the connection reports the server %q, want the one the file named", got)
	}
	stored, _ := h.store.Get().Tunnel(view.ID)
	held := stored.OVPN()
	if len(held.Routes) != 1 || held.Routes[0] != netip.MustParsePrefix("10.8.0.0/16") {
		t.Errorf("the connection carries %v, want the network the file named", held.Routes)
	}
	if len(held.DNS) != 1 || held.DNS[0] != netip.MustParseAddr("10.8.0.1") {
		t.Errorf("the connection resolves through %v, want the resolver the file named", held.DNS)
	}
	if held.CA == "" {
		t.Error("the file's certificate authority was not stored, so the server would go unchecked")
	}
}

// A .ovpn file naming a program to run is refused whole, and nothing is written. The process
// that would run it holds administrator rights, so this is the sharpest version of the same
// rule the WireGuard reader applies.
func TestAnOpenVPNFileThatWouldRunAProgramIsRefusedAndNothingIsStored(t *testing.T) {
	h := newHarness(t, nil)
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelOpenVPN, Name: "Lab"})

	_, err := h.agent.TunnelsAPI().Import(context.Background(), view.ID, `client
remote vpn.example.com 1194
auth-user-pass
up /etc/openvpn/up.sh
<ca>
-----BEGIN CERTIFICATE-----
Zm9vYmFyYmF6
-----END CERTIFICATE-----
</ca>
`)

	if err == nil {
		t.Fatal("a file carrying a program to run as root was imported")
	}
	var refusal *config.ValidationError
	if !errors.As(err, &refusal) || refusal.Field != "file" {
		t.Errorf("error = %v, want a rejection naming the file so the form can mark it", err)
	}
	stored, _ := h.store.Get().Tunnel(view.ID)
	if stored.OVPN().Remote != "" {
		t.Errorf("the refused file configured the connection anyway: %+v", stored.OVPN())
	}
}
