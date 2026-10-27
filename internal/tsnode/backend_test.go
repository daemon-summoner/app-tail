// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// --- backend failure wrapping ---------------------------------------------

// Every tailnet operation goes through the local backend, and every one of them can be
// refused. The refusal is the only thing the dashboard can show, so it has to carry the
// backend's own words and name the operation that failed -- "500" alone tells a user
// nothing about whether to retry, re-authenticate, or fix their policy file.
func TestABackendRefusalIsReportedWithItsReasonAndTheOperationThatFailed(t *testing.T) {
	tests := []struct {
		name      string
		reason    string
		call      func(context.Context, *Node) error
		wantWraps string
	}{
		{
			name:   "interactive login",
			reason: "backend is in state Stopped",
			call: func(ctx context.Context, n *Node) error {
				return n.StartLogin(ctx)
			},
			wantWraps: "start interactive login",
		},
		{
			name:   "logout",
			reason: "not logged in",
			call: func(ctx context.Context, n *Node) error {
				return n.Logout(ctx)
			},
			wantWraps: "log out",
		},
		{
			name:   "peer listing",
			reason: "backend not ready",
			call: func(ctx context.Context, n *Node) error {
				_, err := n.Peers(ctx)
				return err
			},
			wantWraps: "fetch tailnet status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
				return errorResponse(http.StatusInternalServerError, tt.reason), nil
			})

			err := tt.call(t.Context(), n)

			if err == nil {
				t.Fatal("the call succeeded against a backend that refused it")
			}
			if !strings.Contains(err.Error(), tt.wantWraps) {
				t.Errorf("err = %v, want it to name the operation (%q)", err, tt.wantWraps)
			}
			if !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("err = %v, want it to carry the backend's own reason (%q)", err, tt.reason)
			}
		})
	}
}

// The happy paths have to reach the backend at all: a login that silently did nothing
// would leave the user staring at a QR code that never appears.
func TestLoginAndLogoutReachTheBackend(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		// The backend answers both of these with 204 and no body; anything else is
		// read as a refusal, body included.
		return noContentResponse(), nil
	})

	if err := n.StartLogin(t.Context()); err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if err := n.Logout(t.Context()); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 {
		t.Fatalf("the backend saw %d requests, want 2: %v", len(paths), paths)
	}
	if !strings.Contains(paths[0], "login") {
		t.Errorf("login reached %q", paths[0])
	}
	if !strings.Contains(paths[1], "logout") {
		t.Errorf("logout reached %q", paths[1])
	}
}

// The device picker is populated from a live backend query, not the cached status. A
// peer list that never left the process would show the tailnet as it was at enrollment
// and miss every device added since.
func TestPeersAreFetchedLiveFromTheBackend(t *testing.T) {
	body, err := json.Marshal(ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {
				ID:           "n1",
				HostName:     "buildbox",
				DNSName:      "buildbox.tail1234.ts.net.",
				OS:           "linux",
				Online:       true,
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal the backend status: %v", err)
	}

	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse(string(body)), nil
	})

	peers, err := n.Peers(t.Context())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}

	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1: %+v", len(peers), peers)
	}
	if peers[0].HostName != "buildbox" {
		t.Errorf("HostName = %q, want the peer the backend reported", peers[0].HostName)
	}
	// The DNS name is used verbatim as a dial target, so the trailing dot has to be
	// gone by the time it reaches the picker.
	if peers[0].DNSName != "buildbox.tail1234.ts.net" {
		t.Errorf("DNSName = %q, want the trailing dot stripped", peers[0].DNSName)
	}
}

// --- peer ordering --------------------------------------------------------

// The picker's order is the only thing that makes it usable on a tailnet of any size,
// and the peer list arrives from a Go map, so without the comparator it is genuinely
// random per call. The existing coverage has one online and one offline peer, which
// returns from the online branch before the names are ever compared.
func TestEquallyOnlinePeersAreOrderedAlphabeticallyByTheirDisplayName(t *testing.T) {
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	// Insertion order is deliberately reverse-alphabetical, though map iteration makes
	// it irrelevant -- which is the point.
	for _, host := range []string{"zulu", "mike", "alpha", "quebec", "bravo"} {
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{
			HostName: host, Online: true,
		}
	}
	// Offline devices sort after every online one regardless of name.
	for _, host := range []string{"aardvark", "abacus"} {
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{
			HostName: host, Online: false,
		}
	}

	want := []string{"alpha", "bravo", "mike", "quebec", "zulu", "aardvark", "abacus"}

	// Repeated because map iteration order changes between runs: one pass could agree
	// by luck.
	for attempt := 1; attempt <= 5; attempt++ {
		peers := peersFromStatus(st)
		if len(peers) != len(want) {
			t.Fatalf("got %d peers, want %d", len(peers), len(want))
		}
		for i, name := range want {
			if peers[i].HostName != name {
				t.Fatalf("attempt %d, peer %d = %q, want %q\nfull order: %s",
					attempt, i, peers[i].HostName, name, hostNames(peers))
			}
		}
	}
}

// A peer with no hostname is still a valid target -- its DNS name is what the user
// types -- so it has to sort by that rather than by an empty string, which would park
// every unnamed device at the top of the list.
func TestAPeerWithNoHostnameSortsByItsDNSName(t *testing.T) {
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): {ID: "n1", HostName: "mike", Online: true},
		key.NewNode().Public(): {ID: "n2", DNSName: "bravo.tail1234.ts.net.", Online: true},
		key.NewNode().Public(): {ID: "n3", HostName: "zulu", Online: true},
	}}

	for attempt := 1; attempt <= 5; attempt++ {
		peers := peersFromStatus(st)
		want := []string{"bravo.tail1234.ts.net", "mike", "zulu"}
		for i, name := range want {
			got := peers[i].HostName
			if got == "" {
				got = peers[i].DNSName
			}
			if got != name {
				t.Fatalf("attempt %d, peer %d = %q, want %q", attempt, i, got, name)
			}
		}
	}
}

func hostNames(peers []Peer) string {
	names := make([]string, len(peers))
	for i, p := range peers {
		names[i] = p.HostName
	}
	return strings.Join(names, ", ")
}

// --- status projection ----------------------------------------------------

// The backend reports this node's addresses in two places and does not always fill the
// top-level one. Without the fallback the node looks like it has no tailnet IP, and
// ListenPacket -- which resolves a concrete address from exactly this list -- refuses
// every UDP forward on a node that is fully connected.
func TestThisNodesAddressesFallBackToTheSelfPeerWhenTheTopLevelListIsEmpty(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: StateRunning,
		Self: &ipnstate.PeerStatus{
			HostName: "workstation",
			DNSName:  "workstation.tail1234.ts.net.",
			TailscaleIPs: []netip.Addr{
				netip.MustParseAddr("100.64.0.7"),
				netip.MustParseAddr("fd7a:115c:a1e0::7"),
			},
		},
	}

	got := statusFromBackend(st, AuthInteractive)

	want := []string{"100.64.0.7", "fd7a:115c:a1e0::7"}
	if len(got.TailscaleIPs) != len(want) {
		t.Fatalf("TailscaleIPs = %v, want %v", got.TailscaleIPs, want)
	}
	for i, ip := range want {
		if got.TailscaleIPs[i] != ip {
			t.Errorf("TailscaleIPs[%d] = %q, want %q", i, got.TailscaleIPs[i], ip)
		}
	}
}

// The top-level list wins when it is present: it is the authoritative one, and taking
// the self peer's instead would mask a backend that is reporting a change of address.
func TestTheTopLevelAddressListIsPreferredOverTheSelfPeers(t *testing.T) {
	st := &ipnstate.Status{
		BackendState: StateRunning,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Self: &ipnstate.PeerStatus{
			HostName:     "workstation",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.99")},
		},
	}

	got := statusFromBackend(st, AuthInteractive)

	if len(got.TailscaleIPs) != 1 || got.TailscaleIPs[0] != "100.64.0.1" {
		t.Errorf("TailscaleIPs = %v, want the top-level [100.64.0.1]", got.TailscaleIPs)
	}
}

// The exit node in use is named, not just flagged. Every panel that says where traffic
// is leaving names the device, and whether that device is online is the difference
// between "your traffic goes through Berlin" and "nothing leaves this machine at all" --
// the backend blackholes the default route through an exit node that is down.
func TestTheExitNodeInUseArrivesWithItsIdentityAndWhetherItIsUp(t *testing.T) {
	st := &ipnstate.Status{
		BackendState:   StateRunning,
		ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: "nMULLVAD", Online: true},
		CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "tail1a2b3c.ts.net"},
	}

	got := statusFromBackend(st, AuthInteractive)

	if !got.ExitNodeActive {
		t.Error("an exit node is in use and the status reports none")
	}
	if got.ExitNodeID != "nMULLVAD" {
		t.Errorf("ExitNodeID = %q, want the device the backend named", got.ExitNodeID)
	}
	if !got.ExitNodeOnline {
		t.Error("the exit node in use is up and the status reports it down")
	}
	// The suffix is what every MagicDNS name on this tailnet ends in, so the proxy's
	// PAC file and the forwards dialog both build names out of it. An empty one sends
	// every tailnet name past the proxy.
	if got.MagicDNSSuffix != "tail1a2b3c.ts.net" {
		t.Errorf("MagicDNSSuffix = %q, want the tailnet's own", got.MagicDNSSuffix)
	}
}

// A backend that reports nothing must not produce a status claiming an identity. The
// auth mode is local knowledge and survives, because it is how the dashboard explains
// why a node with no status is stuck.
func TestAnAbsentBackendStatusProjectsToAnEmptyOneCarryingTheAuthMode(t *testing.T) {
	got := statusFromBackend(nil, AuthKey)

	if got.BackendState != "" || got.Hostname != "" || len(got.TailscaleIPs) != 0 {
		t.Errorf("status = %+v, want an empty projection", got)
	}
	if got.AuthMode != AuthKey {
		t.Errorf("AuthMode = %q, want it preserved as %q", got.AuthMode, AuthKey)
	}
}

// --- shutdown -------------------------------------------------------------

// Close has to wait for the watcher, because the watcher holds the bus and the bus
// holds the backend. Returning first would race the tsnet server's own teardown and
// leave the state directory locked for the replacement node a restart is building.
func TestCloseWaitsForItsWatcherToFinish(t *testing.T) {
	watcherCtx, watcherCancel := context.WithCancel(context.Background())
	defer watcherCancel()

	// The bus watches the context Close cancels. On any other context the watcher
	// never leaves Next, and Close blocks on it until the package timeout fires.
	bus := newCancellableBus(watcherCtx)
	// Pinning the watcher inside the bus past its cancellation is the whole method
	// here. Left to exit at its own speed it is gone microseconds after cancel(), and
	// a Close that never waited reaches the assertions looking exactly like one that
	// did -- which is how this test previously passed against that very mutation.
	release := bus.holdAfterCancel()
	n := newTestNode(t, AuthInteractive, bus, nil)

	n.mu.Lock()
	n.cancel = watcherCancel
	n.mu.Unlock()

	go n.watch(watcherCtx)
	// Waiting until the watcher is parked on the bus is what makes this a test of the
	// wait: against a watcher that had already returned, any Close would look correct.
	<-bus.entered

	closed := make(chan error, 1)
	go func() { closed <- n.Close() }()

	// The watcher is held, so a Close that waits for it cannot yet have returned. The
	// window costs a fixed 200ms and cannot flake: nothing releases the watcher until
	// this check is over, so only a Close that skipped the wait can report here.
	select {
	case <-closed:
		t.Fatal("Close returned while its watcher was still running; the backend " +
			"connection outlives the node that owns it")
	case <-time.After(200 * time.Millisecond):
	}

	release()

	// A deadline rather than a bare receive, so a Close that waits on a watcher which
	// can never finish fails here naming the cause instead of hanging the package.
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close never returned after its watcher was released")
	}

	select {
	case <-n.watchDone:
	default:
		t.Fatal("Close returned before its watcher signalled that it had finished")
	}

	// The backend client is dropped, so a request issued after Close reports the node
	// is down rather than reaching a torn-down backend.
	if _, err := n.Peers(context.Background()); err == nil {
		t.Error("Peers succeeded after Close")
	}
}

// Close is reached from shutdown and from a restart, sometimes both. A second call
// must be a no-op rather than a second wait on a watcher that has already finished.
func TestCloseIsSafeToCallMoreThanOnce(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 3 {
			if err := n.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a repeated Close blocked; shutdown would hang behind it")
	}
}
