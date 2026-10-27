// SPDX-License-Identifier: MIT

package tstunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// fakeNode answers with whatever the test set. Everything here is a translation of what
// the node reported, so a fake that only reports is enough to reach every branch.
type fakeNode struct {
	status    tsnode.Status
	routes    []netip.Prefix
	approved  []netip.Prefix
	peers     []tsnode.Peer
	lookup    tsnode.TailnetLookup
	lookupErr error
	reach     tsnode.Reach
	reachErr  error
	rtt       time.Duration
	pingErr   error
	routesErr error
}

func (f *fakeNode) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not dialled in these tests")
}
func (f *fakeNode) Listen(string, uint16) (net.Listener, error) {
	return nil, errors.New("not listened on in these tests")
}
func (f *fakeNode) ListenPacket(string, uint16) (net.PacketConn, error) {
	return nil, errors.New("not listened on in these tests")
}
func (f *fakeNode) Start(context.Context) error { return nil }
func (f *fakeNode) Close() error                { return nil }
func (f *fakeNode) Status() tsnode.Status       { return f.status }
func (f *fakeNode) Events() <-chan struct{}     { return nil }
func (f *fakeNode) Routes(context.Context) ([]netip.Prefix, error) {
	return f.routes, f.routesErr
}
func (f *fakeNode) ApprovedRoutes(context.Context) ([]netip.Prefix, error) {
	return f.approved, nil
}
func (f *fakeNode) Peers(context.Context) ([]tsnode.Peer, error) { return f.peers, nil }
func (f *fakeNode) LookupTailnet(context.Context, string) (tsnode.TailnetLookup, error) {
	return f.lookup, f.lookupErr
}
func (f *fakeNode) PingPeer(context.Context, netip.Addr) (time.Duration, error) {
	return f.rtt, f.pingErr
}
func (f *fakeNode) Reach(context.Context, string, string) (tsnode.Reach, error) {
	return f.reach, f.reachErr
}

func wrap(s tsnode.Status) *Tunnel { return New("tn_test", &fakeNode{status: s}) }

// The whole point of the shared vocabulary: whatever word the backend uses, every surface
// reads one of these eight. A backend state translated wrongly is a connection that looks
// broken while it works, or working while it is stuck.
func TestEveryBackendStateReadsAsOneSharedState(t *testing.T) {
	cases := []struct {
		name   string
		status tsnode.Status
		want   tunnel.State
	}{
		{"running", tsnode.Status{BackendState: tsnode.StateRunning}, tunnel.StateConnected},
		{"starting", tsnode.Status{BackendState: tsnode.StateStarting}, tunnel.StateConnecting},
		{"needs login", tsnode.Status{BackendState: tsnode.StateNeedsLogin}, tunnel.StateNeedsLogin},
		{"needs machine auth", tsnode.Status{BackendState: tsnode.StateNeedsMachineAuth}, tunnel.StateNeedsLogin},
		{"stopped", tsnode.Status{BackendState: tsnode.StateStopped}, tunnel.StateOff},
		{"no state yet", tsnode.Status{BackendState: tsnode.StateNoState}, tunnel.StateStarting},
		{"a word this build does not know", tsnode.Status{BackendState: "Reticulating"}, tunnel.StateStarting},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stateOf(c.status); got != c.want {
				t.Errorf("stateOf(%q) = %q, want %q", c.status.BackendState, got, c.want)
			}
		})
	}
}

// The backend reports NoState both before it has started and after a failure it could
// diagnose. Reporting the second as "off" would present a broken connection as a
// configured one and give the user nothing to act on.
func TestANodeThatFailedBeforeStartingReadsAsFailedNotOff(t *testing.T) {
	got := stateOf(tsnode.Status{
		BackendState: tsnode.StateNoState,
		Problem:      "the control server refused the auth key",
	})

	if got != tunnel.StateFailed {
		t.Errorf("state = %q, want %q", got, tunnel.StateFailed)
	}
}

// Traffic crosses, so it is not failed; something the user asked for is not happening, so
// it is not simply connected. This is the state most worth reporting on its own, because
// everything looks fine from every other angle.
func TestARunningNodeWithAProblemIsDegraded(t *testing.T) {
	status := wrap(tsnode.Status{
		BackendState: tsnode.StateRunning,
		Problem:      "the tailnet policy refuses this device's tags",
	}).Status()

	if status.State != tunnel.StateDegraded {
		t.Errorf("state = %q, want %q", status.State, tunnel.StateDegraded)
	}
	if status.Detail != "the tailnet policy refuses this device's tags" {
		t.Errorf("detail = %q, want the node's own diagnosis carried through", status.Detail)
	}
}

// An offline exit node blackholes everything rather than falling back to a direct route,
// so the machine looks like it has no connectivity and nothing else explains why.
func TestASelectedExitNodeThatIsOfflineIsNamedInTheDetail(t *testing.T) {
	status := wrap(tsnode.Status{
		BackendState:   tsnode.StateRunning,
		ExitNodeActive: true,
		ExitNodeOnline: false,
	}).Status()

	if status.State != tunnel.StateDegraded {
		t.Fatalf("state = %q, want %q", status.State, tunnel.StateDegraded)
	}
	if !strings.Contains(status.Detail, "exit node") {
		t.Errorf("detail = %q, want it to name the offline exit node", status.Detail)
	}
}

func TestAnOnlineExitNodeIsJustConnected(t *testing.T) {
	status := wrap(tsnode.Status{
		BackendState:   tsnode.StateRunning,
		ExitNodeActive: true,
		ExitNodeOnline: true,
	}).Status()

	if status.State != tunnel.StateConnected {
		t.Errorf("state = %q, want %q", status.State, tunnel.StateConnected)
	}
	if status.Detail != "" {
		t.Errorf("detail = %q, want none for a connection with nothing wrong", status.Detail)
	}
}

// Containment is the design promise, so it is stated up front. A user who discovers it by
// hitting it files a bug instead.
func TestUserspaceStatesWhatItDoesNotCarry(t *testing.T) {
	limits := wrap(tsnode.Status{
		BackendState: tsnode.StateRunning,
		Network:      config.NetworkUserspace,
	}).Status().Limits

	if len(limits) == 0 {
		t.Fatal("a userspace connection reported no limits, so nothing tells the user why other programs cannot reach it")
	}
	for _, limit := range limits {
		if !strings.HasSuffix(limit, ".") {
			t.Errorf("limit %q is not a sentence; these are shown verbatim", limit)
		}
	}
}

// In interface mode the machine really is on the network, so carrying the userspace
// caveats would be a false warning on the mode that does not have them.
func TestInterfaceModeCarriesNoLimits(t *testing.T) {
	limits := wrap(tsnode.Status{
		BackendState: tsnode.StateRunning,
		Network:      config.NetworkTUN,
	}).Status().Limits

	if len(limits) != 0 {
		t.Errorf("limits = %v, want none in interface mode", limits)
	}
}

func TestTheDeviceAddressesAreReportedAsAddresses(t *testing.T) {
	tun := New("tn_test", &fakeNode{status: tsnode.Status{
		TailscaleIPs: []string{"100.64.0.1", "not an address", "fd7a::1"},
	}})

	addrs := tun.Addrs()

	// The unparseable entry is dropped rather than reported as a zero address, which
	// would route traffic at 0.0.0.0.
	if len(addrs) != 2 {
		t.Fatalf("Addrs() = %v, want the two parseable ones", addrs)
	}
	if addrs[0].String() != "100.64.0.1" || addrs[1].String() != "fd7a::1" {
		t.Errorf("Addrs() = %v, want the addresses the node reported", addrs)
	}
}

func TestTheTailnetNameIsReportedAsAName(t *testing.T) {
	status := wrap(tsnode.Status{
		BackendState: tsnode.StateRunning,
		DNSName:      "workstation.example.ts.net",
	}).Status()

	if len(status.Names) != 1 || status.Names[0] != "workstation.example.ts.net" {
		t.Errorf("names = %v, want the node's MagicDNS name", status.Names)
	}
}

// A node with no name yet must report no names rather than one empty string, which every
// surface would render as a blank row.
func TestANodeWithNoNameYetReportsNone(t *testing.T) {
	if names := wrap(tsnode.Status{BackendState: tsnode.StateStarting}).Status().Names; len(names) != 0 {
		t.Errorf("names = %v, want none", names)
	}
}

// The exit-carrier answer is consumed as a reason shown to the user, so a false answer
// with no reason would leave the egress picker refusing a connection silently.
func TestWhyThisConnectionCannotCarryTheInternet(t *testing.T) {
	cases := []struct {
		name   string
		status tsnode.Status
		can    bool
	}{
		{"not up", tsnode.Status{BackendState: tsnode.StateStarting}, false},
		{"no exit node chosen", tsnode.Status{BackendState: tsnode.StateRunning}, false},
		{"chosen but offline", tsnode.Status{BackendState: tsnode.StateRunning, ExitNodeActive: true}, false},
		{"chosen and online", tsnode.Status{
			BackendState: tsnode.StateRunning, ExitNodeActive: true, ExitNodeOnline: true,
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			can, why := wrap(c.status).CanCarryExit(context.Background())
			if can != c.can {
				t.Errorf("CanCarryExit = %v, want %v", can, c.can)
			}
			if !can && why == "" {
				t.Error("refused with no reason, so the picker has nothing to show")
			}
			if can && why != "" {
				t.Errorf("allowed with reason %q, want none", why)
			}
		})
	}
}

// A peer reached without a relay is direct. The pair is one fact, and reading them apart
// would show a relayed peer as direct whenever the relay name happened to be set.
func TestAPeerWithNoCurrentAddressIsNotDirect(t *testing.T) {
	tun := New("tn_test", &fakeNode{peers: []tsnode.Peer{
		{ID: "p1", HostName: "nas", CurAddr: "203.0.113.4:41641", Relay: "sea"},
		{ID: "p2", HostName: "laptop", CurAddr: "", Relay: "sea"},
	}})

	peers, err := tun.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}

	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(peers))
	}
	if !peers[0].Direct {
		t.Error("a peer with a current address was reported as relayed")
	}
	if peers[1].Direct {
		t.Error("a peer with no current address was reported as direct")
	}
}

// A peer with no hostname still has to appear as something a person can pick out of a
// list, or the row would be blank.
func TestAPeerWithNoHostnameFallsBackToItsDNSName(t *testing.T) {
	tun := New("tn_test", &fakeNode{peers: []tsnode.Peer{
		{ID: "p1", DNSName: "nas.example.ts.net"},
	}})

	peers, err := tun.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if peers[0].Name != "nas.example.ts.net" {
		t.Errorf("name = %q, want the DNS name", peers[0].Name)
	}
}

// A failed lookup is the caller's to handle. Returning no addresses and no error would
// read as "this name does not exist", which is a different answer from "we could not ask".
func TestAFailedLookupIsReportedRatherThanReadAsNoSuchName(t *testing.T) {
	tun := New("tn_test", &fakeNode{lookupErr: errors.New("the resolver is not up")})

	lookup, err := tun.LookupHost(context.Background(), "nas")

	if err == nil {
		t.Fatal("a failed lookup returned no error")
	}
	if lookup.Addrs != nil {
		t.Errorf("addrs = %v, want none alongside an error", lookup.Addrs)
	}
}

func TestPingReportsTheRoundTripInMilliseconds(t *testing.T) {
	tun := New("tn_test", &fakeNode{rtt: 25 * time.Millisecond})

	got, err := tun.Ping(context.Background(), netip.MustParseAddr("100.64.0.2"))
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}

	if !got.OK {
		t.Error("a successful ping reported OK false")
	}
	if got.LatencyMs != 25 {
		t.Errorf("LatencyMs = %v, want 25", got.LatencyMs)
	}
}

// An unreachable peer must not come back as a zero-latency success, which every surface
// would render as an excellent connection.
func TestAFailedPingIsNotAZeroLatencySuccess(t *testing.T) {
	tun := New("tn_test", &fakeNode{pingErr: errors.New("no route")})

	got, err := tun.Ping(context.Background(), netip.MustParseAddr("100.64.0.2"))

	if err == nil {
		t.Fatal("a failed ping returned no error")
	}
	if got.OK {
		t.Error("a failed ping reported OK true")
	}
}

// Advertised and approved are different questions -- what this device offers to carry
// versus what the tailnet actually routes here -- and the gap between them is the thing
// the routes screen exists to show.
func TestAdvertisedAndApprovedAreAskedSeparately(t *testing.T) {
	node := &fakeNode{
		routes:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.1.0/24")},
		approved: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}
	tun := New("tn_test", node)

	advertised, err := tun.Advertised(context.Background())
	if err != nil {
		t.Fatalf("Advertised: %v", err)
	}
	approved, err := tun.Approved(context.Background())
	if err != nil {
		t.Fatalf("Approved: %v", err)
	}

	if len(advertised) != 2 || len(approved) != 1 {
		t.Errorf("advertised %v / approved %v, want the two answers kept apart", advertised, approved)
	}
}

// The seam's whole promise: the forwarding engine keeps working against any kind of
// tunnel because these three methods did not change shape.
func TestATailscaleTunnelIsUsableWhereverATunnelIs(t *testing.T) {
	var _ tunnel.Tunnel = New("tn_test", &fakeNode{})

	if k := New("tn_test", &fakeNode{}).Kind(); k != tunnel.KindTailscale {
		t.Errorf("Kind = %q, want %q", k, tunnel.KindTailscale)
	}
	if id := New("tn_test", &fakeNode{}).ID(); id != "tn_test" {
		t.Errorf("ID = %q, want the id it was registered under", id)
	}
}
