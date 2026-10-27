// SPDX-License-Identifier: MIT

package tsnode

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// nodeKey mints a distinct map key per peer; the value itself is not asserted on.
func nodeKey() key.NodePublic { return key.NewNode().Public() }

func TestPeersFromStatus(t *testing.T) {
	tags := views.SliceOf([]string{"tag:services"})
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			nodeKey(): {
				ID:           "n1",
				HostName:     "buildbox",
				DNSName:      "buildbox.tail1234.ts.net.",
				OS:           "linux",
				Online:       true,
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
				Tags:         &tags,
			},
			nodeKey(): {
				ID:           "n2",
				HostName:     "laptop",
				DNSName:      "laptop.tail1234.ts.net.",
				OS:           "macOS",
				Online:       false,
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
			},
		},
	}

	peers := peersFromStatus(st)
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(peers))
	}
	// Online devices sort first so the picker surfaces reachable targets.
	if peers[0].HostName != "buildbox" {
		t.Errorf("first peer = %q, want the online device buildbox", peers[0].HostName)
	}
	// The DNS name is used directly as a dial target, so the trailing dot must go.
	if peers[0].DNSName != "buildbox.tail1234.ts.net" {
		t.Errorf("DNSName = %q, want the trailing dot stripped", peers[0].DNSName)
	}
	if len(peers[0].Tags) != 1 || peers[0].Tags[0] != "tag:services" {
		t.Errorf("Tags = %v, want [tag:services]", peers[0].Tags)
	}
	if len(peers[0].IPs) != 1 || peers[0].IPs[0] != "100.64.0.2" {
		t.Errorf("IPs = %v, want [100.64.0.2]", peers[0].IPs)
	}
	if peers[1].Online {
		t.Error("offline peer reported as online")
	}
	if peers[1].Tags != nil {
		t.Errorf("Tags = %v, want nil for an untagged peer", peers[1].Tags)
	}
}

func TestPeersFromStatusSkipsSharedNodes(t *testing.T) {
	// Shared-in nodes belong to another tailnet and are not valid forward targets.
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			nodeKey(): {HostName: "mine", Online: true},
			nodeKey(): {HostName: "shared", Online: true, ShareeNode: true},
		},
	}
	peers := peersFromStatus(st)
	if len(peers) != 1 || peers[0].HostName != "mine" {
		t.Fatalf("peers = %+v, want only the tailnet's own device", peers)
	}
}

// The API layer branches on nil specifically -- handlers_node.go:91 substitutes an
// empty slice so the dashboard receives `[]` rather than `null` and can iterate the
// reply unconditionally. A len==0 assertion cannot tell the two apart, so it would
// pass against a projection that returned an empty non-nil slice and quietly retire
// that substitution's only reason to exist.
func TestNoStatusAtAllProjectsToANilPeerList(t *testing.T) {
	got := peersFromStatus(nil)

	if got != nil {
		t.Errorf("peersFromStatus(nil) = %#v, want a nil slice", got)
	}
}

// A status that simply has no peers -- a node connected to a tailnet of one -- is a
// different thing from no status at all, and it also produces nothing to render.
func TestAStatusCarryingNoPeersProjectsToNoPeers(t *testing.T) {
	got := peersFromStatus(&ipnstate.Status{})

	if len(got) != 0 {
		t.Errorf("peersFromStatus(empty) = %+v, want no peers", got)
	}
}

// The dial target is what a generated forward stores as its destination, so an empty one
// has to be distinguishable rather than turned into ":22". The MagicDNS name wins over an
// address because it keeps working when the peer's tailnet address changes.
func TestAPeerIsDialledByItsNameWhenItHasOneAndByAddressOtherwise(t *testing.T) {
	tests := []struct {
		name string
		peer Peer
		want string
	}{
		{"a name and an address", Peer{DNSName: "buildbox.tail1234.ts.net", IPs: []string{"100.64.0.2"}}, "buildbox.tail1234.ts.net"},
		{"an address only", Peer{IPs: []string{"100.64.0.2", "fd7a:115c::1"}}, "100.64.0.2"},
		{"a hostname is not a dial target", Peer{HostName: "buildbox"}, ""},
		{"nothing to dial yet", Peer{ID: "n1"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.peer.DialTarget(); got != tc.want {
				t.Errorf("DialTarget() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The label is the only name a person sees for a peer in a picker. Falling through to the
// numeric ID is deliberate: a device the control plane has not named yet still has to be
// selectable, and a blank row is not.
func TestAPeerIsNamedByTheFirstNameItActuallyHas(t *testing.T) {
	tests := []struct {
		name string
		peer Peer
		want string
	}{
		{"a hostname", Peer{HostName: "buildbox", DNSName: "buildbox.tail1234.ts.net", ID: "n1"}, "buildbox"},
		{"only a DNS name", Peer{DNSName: "buildbox.tail1234.ts.net", ID: "n1"}, "buildbox.tail1234.ts.net"},
		{"neither, so the id", Peer{ID: "n1"}, "n1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.peer.Label(); got != tc.want {
				t.Errorf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A location names a place the way an exit-node picker has to render it. City and country
// together are what tells two nodes in one country apart, and a location the control plane
// never filled in -- the usual case for a self-hosted exit node -- must render as nothing
// rather than as a stray comma.
func TestALocationIsNamedTheWayAPersonNamesAPlace(t *testing.T) {
	tests := []struct {
		name string
		loc  PeerLocation
		want string
	}{
		{"city and country", PeerLocation{City: "Berlin", Country: "Germany"}, "Berlin, Germany"},
		{"a city with no country", PeerLocation{City: "Berlin"}, "Berlin"},
		{"a country with no city", PeerLocation{Country: "Germany"}, "Germany"},
		{"nothing the control plane filled in", PeerLocation{}, ""},
		{"a country code alone names no place", PeerLocation{CountryCode: "DE"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.loc.Label(); got != tc.want {
				t.Errorf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPeersAndDialRequireARunningNode(t *testing.T) {
	// Every tailnet operation must refuse before the node is up rather than
	// panicking on a nil client or binding a listener that can never work.
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)

	if _, err := n.Peers(t.Context()); err == nil {
		t.Error("Peers succeeded on a node that is not running")
	}
	if _, err := n.Dial(t.Context(), "tcp", "box:22"); err == nil {
		t.Error("Dial succeeded on a node that is not running")
	}
	if _, err := n.Listen("tcp", 8080); err == nil {
		t.Error("Listen succeeded on a node that is not running")
	}
	if _, err := n.ListenPacket("udp", 5353); err == nil {
		t.Error("ListenPacket succeeded on a node that is not running")
	}
	if err := n.StartLogin(t.Context()); err == nil {
		t.Error("StartLogin succeeded with no local client")
	}
	if err := n.Logout(t.Context()); err == nil {
		t.Error("Logout succeeded with no local client")
	}
}

func TestListenPacketRefusesWithoutATailnetIP(t *testing.T) {
	// tsnet rejects a bare ":port" for UDP, so a Running node with no cached IP
	// must fail with a clear reason instead of passing an invalid address down.
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
	n.mu.Lock()
	n.status.BackendState = StateRunning
	n.mu.Unlock()

	_, err := n.ListenPacket("udp", 5353)
	if err == nil {
		t.Fatal("ListenPacket succeeded with no tailnet IP assigned")
	}
	if !strings.Contains(err.Error(), "no tailnet IP") {
		t.Errorf("error %q does not explain the missing tailnet IP", err)
	}
}

// The traffic figures are WireGuard's own, cumulative per peer, and they are the whole
// reason the dashboard can say which machines this one is actually talking to. They
// arrive on every status call and were previously dropped on the floor here, so a peer
// projection that silently stops carrying them would take the traffic view with it.
func TestPeersFromStatusCarriesWhatTheTailnetMoved(t *testing.T) {
	shook := time.Date(2026, 7, 29, 10, 30, 0, 0, time.UTC)
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			nodeKey(): {
				ID:            "n1",
				HostName:      "nas",
				Online:        true,
				RxBytes:       9_000_000,
				TxBytes:       412_000,
				CurAddr:       "100.64.0.2:41641",
				LastHandshake: shook,
				Active:        true,
			},
		},
	}

	peers := peersFromStatus(st)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	got := peers[0]
	if got.RxBytes != 9_000_000 || got.TxBytes != 412_000 {
		t.Errorf("rx/tx = %d/%d, want 9000000/412000", got.RxBytes, got.TxBytes)
	}
	if got.CurAddr != "100.64.0.2:41641" {
		t.Errorf("curAddr = %q, want the direct address", got.CurAddr)
	}
	if !got.LastHandshake.Equal(shook) {
		t.Errorf("lastHandshake = %v, want %v", got.LastHandshake, shook)
	}
	if !got.Active {
		t.Error("a peer the backend calls active was reported idle")
	}
}

// The engine and socket flags are the only thing that separates a device this node can
// carry traffic to from one it merely knows the name of. A projection that dropped them
// would put every peer back to being judged by Online alone, which is what made a node
// the tailnet listed, resolved nowhere and answered nothing look perfectly healthy.
func TestPeersFromStatusCarriesWhetherTheLowerLayersKnowThePeer(t *testing.T) {
	expiry := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			nodeKey(): {
				ID:          "n1",
				HostName:    "gone",
				Online:      true,
				InEngine:    false,
				InMagicSock: true,
				Expired:     true,
				KeyExpiry:   &expiry,
			},
		},
	}

	peers := peersFromStatus(st)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	got := peers[0]
	if got.InEngine {
		t.Error("a peer the engine is not tracking was reported as tracked")
	}
	if !got.InMagicSock {
		t.Error("inMagicSock was dropped")
	}
	if !got.Expired {
		t.Error("an expired node key was not carried")
	}
	if !got.KeyExpiry.Equal(expiry) {
		t.Errorf("keyExpiry = %v, want %v", got.KeyExpiry, expiry)
	}
	// The verdict has to travel with the peer: the dashboard cannot run the derivation,
	// so a projection that left this empty would put the UI back to guessing from Online.
	if got.Reach.State != PeerExpired {
		t.Errorf("Reach.State = %q, want the derived %q on the projected peer", got.Reach.State, PeerExpired)
	}
	if got.Reach != reachOf(got) {
		t.Errorf("carried verdict %+v disagrees with the derivation %+v", got.Reach, reachOf(got))
	}
}

// A control plane that names no expiry must produce a zero time rather than panic on the
// nil pointer it actually sends for every non-expiring node -- which is most of them.
func TestPeersFromStatusToleratesAPeerWithNoNamedExpiry(t *testing.T) {
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			nodeKey(): {ID: "n1", HostName: "box", Online: true, KeyExpiry: nil},
		},
	}

	peers := peersFromStatus(st)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	if !peers[0].KeyExpiry.IsZero() {
		t.Errorf("keyExpiry = %v, want the zero time", peers[0].KeyExpiry)
	}
}

// This is the whole point of the type. Each state has to be distinguishable, because the
// bug it exists to catch -- a peer the tailnet lists that no lower layer is tracking --
// is indistinguishable from a healthy one by name, address and Online alone.
func TestAPeerReportsWhyThisNodeCannotReachIt(t *testing.T) {
	tests := []struct {
		name string
		peer Peer
		want PeerState
		ok   bool
	}{
		{
			"a direct path is ready",
			Peer{Online: true, InEngine: true, InMagicSock: true, CurAddr: "100.64.0.2:41641"},
			PeerReady, true,
		},
		{
			"an idle peer nobody has dialled is still ready",
			Peer{Online: true, InEngine: true, InMagicSock: true},
			PeerReady, true,
		},
		{
			"a relay carries it, slowly",
			Peer{Online: true, InEngine: true, InMagicSock: true, Relay: "fra"},
			PeerRelayed, true,
		},
		{
			"a direct address wins over a relay that is also named",
			Peer{Online: true, InEngine: true, InMagicSock: true, CurAddr: "100.64.0.2:41641", Relay: "fra"},
			PeerReady, true,
		},
		{
			// Tailscale configures a peer in the WireGuard engine on the first packet sent
			// to it, so this is the ordinary state of a peer nobody has dialled yet. Calling
			// it unreachable reports most of a quiet tailnet as broken and sends people
			// restarting a node that is working.
			"idle out of the engine is still ready",
			Peer{Online: true, InEngine: false, InMagicSock: true},
			PeerReady, true,
		},
		{
			// The relay named for an idle peer is where a path would be built, not one it is
			// already paying for on every packet.
			"an idle peer is not reported as paying for a relay",
			Peer{Online: true, InEngine: false, InMagicSock: true, Relay: "fra"},
			PeerReady, true,
		},
		{
			"listed but the socket layer is not tracking it",
			Peer{Online: true, InEngine: true, InMagicSock: false},
			PeerNoPath, false,
		},
		{
			"offline outranks a missing engine entry, which it explains",
			Peer{Online: false, InEngine: false, InMagicSock: false},
			PeerOffline, false,
		},
		{
			"an expired key outranks everything, because it causes the rest",
			Peer{Online: true, InEngine: false, InMagicSock: false, Expired: true},
			PeerExpired, false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := reachOf(tc.peer)
			if got.State != tc.want {
				t.Errorf("State = %q, want %q", got.State, tc.want)
			}
			if got.OK() != tc.ok {
				t.Errorf("OK() = %v, want %v", got.OK(), tc.ok)
			}
			if tc.want == PeerReady && got.Reason != "" {
				t.Errorf("Reason = %q, want nothing to say about a ready peer", got.Reason)
			}
			if tc.want != PeerReady && got.Reason == "" {
				t.Errorf("state %q gave no reason, leaving nothing to act on", got.State)
			}
		})
	}
}

// The expiry date is the actionable half of an expired key: "reauthenticate it" is not
// useful without knowing this happened months ago rather than during this session. A
// control plane that names no date must still produce a usable sentence.
func TestAnExpiredPeerNamesTheDateWhenTheTailnetGaveOne(t *testing.T) {
	dated := Peer{Online: true, Expired: true, KeyExpiry: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	if got := reachOf(dated).Reason; !strings.Contains(got, "2026-06-01") {
		t.Errorf("reason %q does not name the expiry date", got)
	}

	undated := Peer{Online: true, Expired: true}
	reason := reachOf(undated).Reason
	if reason == "" {
		t.Fatal("an expired peer with no named date gave no reason at all")
	}
	if strings.Contains(reason, "expired )") || strings.Contains(reason, "0001-01-01") {
		t.Errorf("reason %q leaks the zero time", reason)
	}
}

// A peer reachable only through a relay reports no direct address and names the region
// instead. The pair is one fact: a device that works and feels slow is usually this.
func TestPeersFromStatusDistinguishesARelayedPathFromADirectOne(t *testing.T) {
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			nodeKey(): {ID: "n1", HostName: "far", Online: true, Relay: "fra"},
		},
	}

	peers := peersFromStatus(st)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	if peers[0].Relay != "fra" {
		t.Errorf("relay = %q, want the DERP region carrying it", peers[0].Relay)
	}
	if peers[0].CurAddr != "" {
		t.Errorf("curAddr = %q, want empty for a relayed peer", peers[0].CurAddr)
	}
}

// An empty state is silence, not a verdict. Every consumer that renders a peer has to
// tell the two apart, because a value can arrive from an agent that predates the field,
// and reading the empty string literally would report a whole healthy tailnet as broken.
func TestAStateNobodySetFallsBackToWhatTheTailnetSaid(t *testing.T) {
	cases := []struct {
		name   string
		state  PeerState
		online bool
		want   PeerState
	}{
		{"nothing stated, tailnet says online", "", true, PeerReady},
		{"nothing stated, tailnet says offline", "", false, PeerOffline},
		{"a stated verdict survives an online flag that disagrees", PeerNoPath, true, PeerNoPath},
		{"a stated verdict survives an offline flag that disagrees", PeerRelayed, false, PeerRelayed},
		{"a state this build does not know is passed through, not swallowed", PeerState("quarantined"), true, PeerState("quarantined")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.Or(tc.online); got != tc.want {
				t.Errorf("PeerState(%q).Or(%v) = %q, want %q", tc.state, tc.online, got, tc.want)
			}
		})
	}
}

// OK is what callers branch on to decide whether traffic will arrive, so a state added
// later must not default into the reachable half.
func TestOnlyAStateTrafficSurvivesCountsAsOK(t *testing.T) {
	cases := []struct {
		state PeerState
		want  bool
	}{
		{PeerReady, true},
		{PeerRelayed, true},
		{PeerNoPath, false},
		{PeerOffline, false},
		{PeerExpired, false},
		{PeerState(""), false},
		{PeerState("quarantined"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			if got := tc.state.OK(); got != tc.want {
				t.Errorf("PeerState(%q).OK() = %v, want %v", tc.state, got, tc.want)
			}
			if got := (PeerReach{State: tc.state}).OK(); got != tc.want {
				t.Errorf("PeerReach{%q}.OK() = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}
