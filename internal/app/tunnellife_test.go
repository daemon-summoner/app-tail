// SPDX-License-Identifier: MIT

package app

// What the agent does with a connection beside the primary one that cannot be brought up,
// and what the surfaces built on the running set answer while it is down.
//
// The two ways a connection fails are deliberately separate: one is a document nothing can
// be built from, which is a configuration the user can fix, and the other is a node that
// was built and refused to come up, which is usually the network. Both have to reach the
// connections screen, because the only other thing on screen is "off" -- and a connection
// somebody switched off looks exactly the same.

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tunnel/ovpntunnel"
)

// secondaryTailnetID is the tailnet connection these tests seed beside the primary one.
const secondaryTailnetID = "tn_lab"

// seedSecondaryTailnet puts one enabled tailnet connection in the document, adjusted by the
// caller so each test can break exactly one thing about it.
func seedSecondaryTailnet(adjust func(*config.Tunnel)) func(*config.Config) {
	return func(c *config.Config) {
		held := config.NewTunnel(secondaryTailnetID, "lab", "Lab", config.TunnelTailscale)
		held.Enabled = true
		if adjust != nil {
			adjust(&held)
		}
		c.Tunnels = append(c.Tunnels, held)
	}
}

// A connection whose stored settings render to nothing that could be built -- here a
// credentials file that is not there -- must say so against that connection. Nothing is
// started, so without the reason the screen shows a connection that is switched on, has no
// node, and offers no account of either.
func TestAConnectionNothingCanBeBuiltFromSaysSoAgainstItself(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "client-secret")

	h := newHarness(t, seedSecondaryTailnet(func(held *config.Tunnel) {
		held.Tailscale.OAuthClientSecretFile = missing
	}))

	waitFor(t, 5*time.Second, "the connection to report why nothing was built", func() bool {
		return h.agent.connectionProblem(secondaryTailnetID) != ""
	})

	problem := h.agent.connectionProblem(secondaryTailnetID)
	if !strings.Contains(problem, missing) {
		t.Errorf("the reason given is %q, want it to name the file that could not be read", problem)
	}
	if _, registered := h.agent.tunnels.Get(secondaryTailnetID); registered {
		t.Error("a connection nothing could be built from was registered as one that carries traffic")
	}
	// Nothing to reach the tailnet-only surfaces through, and a nil rather than a panic is
	// what every one of them is written against.
	if node := h.agent.nodeFor(secondaryTailnetID); node != nil {
		t.Error("a connection that was never started has a node behind it")
	}
}

// A node that was built and refused to come up is the ordinary tailnet failure: a rejected
// auth key, a control plane that cannot be reached. The reason has to reach the connection
// and the node has to be closed -- one kept on the credentials that just failed would make
// the next pass believe there is nothing to do.
func TestATailnetConnectionThatCannotStartReportsWhyAndIsClosed(t *testing.T) {
	const refusal = "the control plane refused this auth key"

	// The node is built on the reconcile's own goroutine and asserted against on this one,
	// so it is handed over rather than shared: a plain field would be a race whatever the
	// timing happened to be.
	secondaries := make(chan *fakeNode, 1)
	h := newHarnessWith(t, seedSecondaryTailnet(nil), func(o *Options) {
		// The first build is the primary connection, which the harness waits on before it
		// hands the test an agent. Only what comes after it is this connection's.
		primary := o.NewNode
		built := 0
		o.NewNode = func(p tsnode.Options) NodeController {
			if built++; built == 1 {
				return primary(p)
			}
			node := newFakeNode()
			node.startErr = errors.New(refusal)
			select {
			case secondaries <- node:
			default:
			}
			return node
		}
	})

	waitFor(t, 5*time.Second, "the connection to report why it is not running", func() bool {
		return h.agent.connectionProblem(secondaryTailnetID) != ""
	})

	if got := h.agent.connectionProblem(secondaryTailnetID); got != refusal {
		t.Errorf("the reason given is %q, want the one the node refused with", got)
	}
	select {
	case secondary := <-secondaries:
		if !secondary.wasClosed() {
			t.Error("the node that would not start was left holding its state directory")
		}
	default:
		t.Error("no node was built for the connection, so nothing refused to start")
	}
	if _, registered := h.agent.tunnels.Get(secondaryTailnetID); registered {
		t.Error("a connection that never came up was registered as one that carries traffic")
	}
}

// Stopping a connection that is not running is what every caller does rather than first
// asking whether there is anything to stop -- the reconcile stops whatever no longer
// matches, without knowing which of those it already stopped.
func TestStoppingAConnectionThatIsNotRunningIsNothingHappening(t *testing.T) {
	h, _ := carryingFabric(t, labRange)
	office := h.wireguards.devicesFor(wgTunnelID)[0]

	h.agent.stopTunnel("tn_never_started")

	if problem := h.agent.connectionProblem("tn_never_started"); problem != "" {
		t.Errorf("stopping nothing recorded %q against the connection", problem)
	}
	// The connections that are running are not what was asked about, and stay up.
	if office.wasClosed() {
		t.Error("stopping a connection that never ran took down one that was running")
	}
	for _, id := range []string{wgTunnelID, labTunnelID} {
		if _, registered := h.agent.tunnels.Get(id); !registered {
			t.Errorf("%s is no longer registered after a stop that named a different connection", id)
		}
	}
}

// A kind this build can add but not bring up must say so against the connection.
//
// Both halves are asserted because they fail apart: the plan is what the reconcile asks for
// first, and the start is what runs once a plan exists. A kind added to the startable table
// without a branch in either would leave a connection switched on, never started, and with
// nothing on the screen to explain it -- the one state the connections screen cannot tell
// apart from a connection somebody turned off.
func TestAKindThisBuildCannotBringUpSaysSoRatherThanBeingSkipped(t *testing.T) {
	const unknown = config.TunnelType("carrier-pigeon")
	held := config.NewTunnel("tn_odd001", "odd", "Odd", unknown)
	held.Enabled = true

	_, err := tunnelPlanFor(held, config.Defaults().Settings, t.TempDir())
	if err == nil {
		t.Fatal("a kind with no plan was planned, so the reconcile would start nothing and say nothing")
	}
	if !strings.Contains(err.Error(), string(unknown)) {
		t.Errorf("planning failed with %q, want it to name the kind", err)
	}

	h := newHarness(t, func(*config.Config) {})
	// A plan of no kind at all is what a kind added above without a branch below produces.
	h.agent.startTunnel(t.Context(), held, nil)

	problem := h.agent.connectionProblem(held.ID)
	if problem == "" {
		t.Fatal("a connection nothing could start was left with no reason against it")
	}
	if !strings.Contains(problem, string(unknown)) {
		t.Errorf("the reason given is %q, want it to name the kind", problem)
	}
}

// Two things claiming this machine's default route at once end up with whichever asked first,
// which is not a choice anybody made. So an OpenVPN connection takes the default itself only
// while the interface mode is off; with it on, the interface carries the traffic to the
// connection and the connection gets a route on its own interface instead.
//
// The failure this prevents is not theoretical: an OpenVPN connection routes through the
// address its server handed out, two connections to the same provider are handed the same one,
// and the machine's default then resolves through whichever of them the routing table happens
// to hold -- including one that has just gone away, which takes the machine off the network.
func TestAnOpenVPNConnectionTakesTheMachinesDefaultOnlyWhenNothingElseCarriesIt(t *testing.T) {
	held := config.NewTunnel("tn_ovpn01", "vpn", "VPN", config.TunnelOpenVPN)
	held.Enabled = true

	settings := config.Defaults().Settings
	settings.EgressMode = config.EgressTunnel
	settings.EgressTunnelID = held.ID
	settings.InterfaceEnabled = false

	plan, err := tunnelPlanFor(held, settings, t.TempDir())
	if err != nil {
		t.Fatalf("plan the connection: %v", err)
	}
	if got := plan.(openvpnPlan).carry; got != ovpntunnel.CarryDefault {
		t.Errorf("the connection carries the traffic as %q; nothing else is carrying this "+
			"machine's internet traffic, so this one has to take the default route or the "+
			"traffic leaves through this machine's own network", got)
	}

	settings.InterfaceEnabled = true
	settings.InterfaceMode = config.NetworkFabric
	plan, err = tunnelPlanFor(held, settings, t.TempDir())
	if err != nil {
		t.Fatalf("plan the connection with the interface mode on: %v", err)
	}
	if got := plan.(openvpnPlan).carry; got != ovpntunnel.CarryScoped {
		t.Errorf("the connection carries the traffic as %q; the interface already carries this "+
			"machine's default, so this one has to carry it on a route of its own interface", got)
	}

	settings.EgressTunnelID = "tn_other"
	plan, err = tunnelPlanFor(held, settings, t.TempDir())
	if err != nil {
		t.Fatalf("plan a connection that was not chosen: %v", err)
	}
	if got := plan.(openvpnPlan).carry; got != ovpntunnel.CarryNone {
		t.Errorf("a connection nobody chose carries this machine's internet traffic as %q", got)
	}
}
