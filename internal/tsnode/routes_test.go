// SPDX-License-Identifier: MIT

package tsnode

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/routecheck"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// prefixes parses a list of CIDR strings, so a test case reads as the routes it means.
func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// peerWithRoutes is one peer carrying the given primary routes.
func peerWithRoutes(t *testing.T, cidrs ...string) *ipnstate.PeerStatus {
	t.Helper()
	routes := views.SliceOf(prefixes(t, cidrs...))
	return &ipnstate.PeerStatus{HostName: "router", PrimaryRoutes: &routes}
}

func statusWithPeers(peers ...*ipnstate.PeerStatus) *ipnstate.Status {
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	for _, p := range peers {
		st.Peer[key.NewNode().Public()] = p
	}
	return st
}

// A subnet route is the one kind of address that is reachable over the tailnet without
// being a tailnet address, so anything deciding what to send through the tailnet has to
// be told about it separately. Getting this wrong sends a LAN address the long way round
// or, worse, out to the internet.
func TestAcceptedRoutesReportsWhatPeersActuallyCarry(t *testing.T) {
	tests := []struct {
		name string
		st   *ipnstate.Status
		want []string
	}{
		{
			name: "a subnet router's route",
			st:   statusWithPeers(peerWithRoutes(t, "192.168.1.0/24")),
			want: []string{"192.168.1.0/24"},
		},
		{
			// A default route means the peer is offering itself as an exit node, which
			// routes everything rather than a subnet. Reporting it here would make a
			// caller treat the whole internet as a tailnet destination.
			name: "never a default route",
			st:   statusWithPeers(peerWithRoutes(t, "0.0.0.0/0", "::/0", "10.1.0.0/16")),
			want: []string{"10.1.0.0/16"},
		},
		{
			// The tailnet's own ranges are reachable regardless, so restating one adds
			// nothing and would duplicate a rule the caller already has.
			name: "never the tailnet's own ranges",
			st:   statusWithPeers(peerWithRoutes(t, "100.64.0.0/10", "fd7a:115c:a1e0::/48", "172.16.0.0/12")),
			want: []string{"172.16.0.0/12"},
		},
		{
			// Two peers advertise the same prefix for failover; control elects one, but
			// both can report it in the window around a handover.
			name: "the same route from two peers appears once",
			st: statusWithPeers(
				peerWithRoutes(t, "192.168.1.0/24"),
				peerWithRoutes(t, "192.168.1.0/24"),
			),
			want: []string{"192.168.1.0/24"},
		},
		{
			name: "a peer advertising nothing at all",
			st:   statusWithPeers(&ipnstate.PeerStatus{HostName: "laptop"}),
			want: nil,
		},
		{name: "no status at all", st: nil, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := acceptedRoutes(tt.st)
			if len(got) != len(tt.want) {
				t.Fatalf("routes = %v, want %v", got, tt.want)
			}
			for i, want := range tt.want {
				if got[i].String() != want {
					t.Errorf("routes[%d] = %v, want %v", i, got[i], want)
				}
			}
		})
	}
}

// The peer list arrives from a Go map, so without a comparator the same tailnet answers
// in a different order every call -- and anything derived from it, a proxy auto-config
// file above all, changes bytes on every fetch for no reason.
func TestAcceptedRoutesAreOrderedTheSameWayEveryTime(t *testing.T) {
	st := statusWithPeers(
		peerWithRoutes(t, "192.168.9.0/24"),
		peerWithRoutes(t, "10.1.0.0/16"),
		peerWithRoutes(t, "172.16.0.0/12"),
	)

	first := acceptedRoutes(st)
	for range 20 {
		got := acceptedRoutes(st)
		if len(got) != len(first) {
			t.Fatalf("routes = %v, want %v", got, first)
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("routes = %v, want the same order every call (%v)", got, first)
			}
		}
	}
}

// Accepting routes is a choice the user makes. A node that has not made it does not
// reach any of these subnets, and reporting them anyway would have a caller send LAN
// traffic into a tailnet that drops it.
func TestRoutesAreEmptyWhileTheNodeIsNotAcceptingThem(t *testing.T) {
	statusCalls := 0
	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "prefs") {
			body, err := json.Marshal(ipn.Prefs{RouteAll: false})
			if err != nil {
				t.Fatalf("marshal prefs: %v", err)
			}
			return jsonResponse(string(body)), nil
		}
		statusCalls++
		return jsonResponse(`{}`), nil
	})

	routes, err := n.Routes(t.Context())
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("routes = %v, want none while route acceptance is off", routes)
	}
	// Fetching the peer list is the expensive half of the call; there is nothing it
	// could report that would change the answer.
	if statusCalls != 0 {
		t.Errorf("the backend was asked for %d peer lists, want 0", statusCalls)
	}
}

func TestRoutesReportsThePeersRoutesOnceAcceptanceIsOn(t *testing.T) {
	peers, err := json.Marshal(statusWithPeers(peerWithRoutes(t, "192.168.1.0/24")))
	if err != nil {
		t.Fatalf("marshal the backend status: %v", err)
	}
	prefs, err := json.Marshal(ipn.Prefs{RouteAll: true})
	if err != nil {
		t.Fatalf("marshal prefs: %v", err)
	}

	n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "prefs") {
			return jsonResponse(string(prefs)), nil
		}
		return jsonResponse(string(peers)), nil
	})

	routes, err := n.Routes(t.Context())
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(routes) != 1 || routes[0].String() != "192.168.1.0/24" {
		t.Errorf("routes = %v, want [192.168.1.0/24]", routes)
	}
}

// A backend that cannot answer must not read as "this node reaches no subnets": the
// caller would send LAN traffic direct and quietly bypass the tailnet.
func TestRoutesReportsABackendRefusalRatherThanAnEmptyList(t *testing.T) {
	tests := []struct {
		name  string
		match string
	}{
		{"the preferences cannot be read", "prefs"},
		{"the peer list cannot be read", "status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := requireStubbedNode(t, func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, tt.match) {
					return errorResponse(http.StatusInternalServerError, "backend is wedged"), nil
				}
				body, err := json.Marshal(ipn.Prefs{RouteAll: true})
				if err != nil {
					t.Fatalf("marshal prefs: %v", err)
				}
				return jsonResponse(string(body)), nil
			})

			if _, err := n.Routes(t.Context()); err == nil {
				t.Fatal("Routes reported no error for a backend that refused")
			} else if !strings.Contains(err.Error(), "backend is wedged") {
				t.Errorf("Routes error = %v, want it to carry the backend's own reason", err)
			}
		})
	}
}

func TestRoutesRefusesBeforeTheNodeHasStarted(t *testing.T) {
	n := newBareNode(t)

	if _, err := n.Routes(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Routes before start = %v, want ErrNotRunning", err)
	}
}

// selfWithRoutes is this node as the control plane reports it, carrying the routes an
// admin has approved for it.
func selfWithRoutes(t *testing.T, cidrs ...string) *ipnstate.Status {
	t.Helper()
	routes := views.SliceOf(prefixes(t, cidrs...))
	return &ipnstate.Status{Self: &ipnstate.PeerStatus{HostName: "self", PrimaryRoutes: &routes}}
}

// Advertising is a request; only an admin's approval routes a network to this device.
// A subnet router serving what it asked for rather than what it was granted answers
// connections the tailnet never sent it.
func TestApprovedRoutesReportsWhatTheTailnetActuallyRoutesHere(t *testing.T) {
	tests := []struct {
		name string
		st   *ipnstate.Status
		want []string
	}{
		{
			name: "an approved subnet",
			st:   selfWithRoutes(t, "192.168.1.0/24"),
			want: []string{"192.168.1.0/24"},
		},
		{
			// The default routes are the exit-node advertisement. Carrying them here
			// would turn an approval of "offer yourself as an exit node" into this
			// process proxying every destination on the internet, over a router that
			// cannot carry UDP.
			name: "the exit-node routes",
			st:   selfWithRoutes(t, "0.0.0.0/0", "::/0", "192.168.1.0/24"),
			want: []string{"192.168.1.0/24"},
		},
		{
			// A flow to a tailnet address is either this node's own, answered by a
			// listener before it ever reaches the subnet hook, or another peer's, which
			// this node has no business intercepting.
			name: "the tailnet's own ranges",
			st:   selfWithRoutes(t, "100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.1.0.0/16"),
			want: []string{"10.1.0.0/16"},
		},
		{
			name: "a stable order whatever the control plane sends",
			st:   selfWithRoutes(t, "192.168.1.0/24", "10.1.0.0/16", "172.16.0.0/12"),
			want: []string{"10.1.0.0/16", "172.16.0.0/12", "192.168.1.0/24"},
		},
		{
			name: "nothing approved at all",
			st:   &ipnstate.Status{Self: &ipnstate.PeerStatus{HostName: "self"}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.st)
			if err != nil {
				t.Fatalf("marshal the backend status: %v", err)
			}
			n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
				return jsonResponse(string(body)), nil
			})

			got, err := n.ApprovedRoutes(t.Context())
			if err != nil {
				t.Fatalf("ApprovedRoutes: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ApprovedRoutes() = %v, want %v", got, tt.want)
			}
			for i, want := range tt.want {
				if got[i].String() != want {
					t.Errorf("ApprovedRoutes()[%d] = %s, want %s", i, got[i], want)
				}
			}
		})
	}
}

// An unreadable approval set must not read as "nothing is approved" either: the router
// distinguishes the two, refusing everything on a failure rather than treating a wedged
// control plane as a decision.
func TestApprovedRoutesReportsABackendRefusalRatherThanAnEmptyList(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return errorResponse(http.StatusInternalServerError, "backend is wedged"), nil
	})

	if _, err := n.ApprovedRoutes(t.Context()); err == nil {
		t.Fatal("ApprovedRoutes reported no error for a backend that refused")
	} else if !strings.Contains(err.Error(), "backend is wedged") {
		t.Errorf("ApprovedRoutes error = %v, want it to carry the backend's own reason", err)
	}
}

func TestApprovedRoutesRefusesBeforeTheNodeHasStarted(t *testing.T) {
	n := newBareNode(t)

	if _, err := n.ApprovedRoutes(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("ApprovedRoutes before start = %v, want ErrNotRunning", err)
	}
}

// The hook is the only way a userspace node serves a route at all, so installing it
// before the node runs would hand connections to a stack that does not exist.
func TestServingSubnetsRefusesBeforeTheNodeIsRunning(t *testing.T) {
	n := newBareNode(t)

	_, err := n.ServeSubnets(func(netip.AddrPort, netip.AddrPort) func(net.Conn) { return nil })
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("ServeSubnets before start = %v, want ErrNotRunning", err)
	}
}

// A nil handler would install a hook that intercepts every flow to a routed address and
// then refuses it, which is indistinguishable from a subnet router that is up and broken.
func TestServingSubnetsRefusesWithoutAHandler(t *testing.T) {
	n := newBareNode(t)

	if _, err := n.ServeSubnets(nil); err == nil {
		t.Fatal("ServeSubnets accepted a nil handler")
	} else if errors.Is(err, ErrNotRunning) {
		t.Errorf("ServeSubnets(nil) = %v, want the missing handler reported as its own fault", err)
	}
}

// Once the node is up the hook goes in, and the caller is handed the way to take it back
// out. Without that, turning the subnet router off leaves a handler behind that keeps
// claiming flows for routes this node no longer serves.
func TestServingSubnetsInstallsTheHookAndHandsBackTheWayToRemoveIt(t *testing.T) {
	n := newBareNode(t)
	n.status = Status{BackendState: StateRunning}

	stop, err := n.ServeSubnets(func(netip.AddrPort, netip.AddrPort) func(net.Conn) { return nil })
	if err != nil {
		t.Fatalf("serve subnets on a running node: %v", err)
	}
	if stop == nil {
		t.Fatal("the hook was installed with no way to remove it")
	}
	stop()
}

// The hook is the authority on a flow to a routed address. Declining one hands it to
// whatever else is registered instead of refusing it, so a destination this node decided
// not to serve would quietly reach some other handler -- and a refusal has to be carried
// by the nil handler, which is the only refusal netstack acts on.
func TestTheSubnetHookClaimsEveryFlowIncludingTheOnesItRefuses(t *testing.T) {
	src := netip.MustParseAddrPort("100.64.0.9:51000")
	dst := netip.MustParseAddrPort("10.9.0.5:22")

	var gotSrc, gotDst netip.AddrPort
	served := interceptAll(func(s, d netip.AddrPort) func(net.Conn) {
		gotSrc, gotDst = s, d
		return func(net.Conn) {}
	})
	handler, ok := served(src, dst)
	if !ok {
		t.Error("a flow this node serves was declined, so it reaches another handler instead")
	}
	if handler == nil {
		t.Error("a flow this node serves was refused")
	}
	if gotSrc != src || gotDst != dst {
		t.Errorf("the handler was asked about %v -> %v, want %v -> %v", gotSrc, gotDst, src, dst)
	}

	refused := interceptAll(func(netip.AddrPort, netip.AddrPort) func(net.Conn) { return nil })
	handler, ok = refused(src, dst)
	if !ok {
		t.Error("a refused flow was declined rather than claimed, so it reaches another handler")
	}
	if handler != nil {
		t.Error("a flow the node refused was served anyway")
	}
}

// reachableNodes is a routecheck report as the backend serializes one: the nodes that
// answered a probe, each carrying the networks it routes.
func reachableNodes(t *testing.T, nodes ...routecheck.Node) string {
	t.Helper()
	set := make(routecheck.NodeSet, len(nodes))
	for _, n := range nodes {
		set[n.ID] = n
	}
	// Marshalled through a pointer: the node set renders itself as a sorted array, and
	// that method is on the pointer, so a value here silently produces the map form the
	// backend never sends and the client cannot read.
	body, err := json.Marshal(&routecheck.Report{Reachable: set})
	if err != nil {
		t.Fatalf("marshal the routecheck report: %v", err)
	}
	return string(body)
}

// A route in the netmap whose device does not answer is indistinguishable from a working
// one everywhere else, which is the whole reason this probe exists. It has to name the
// devices that answered, and it has to leave out the two prefix classes that are not
// subnet routes at all.
func TestRouteReachabilityNamesTheDevicesCarryingEachNetwork(t *testing.T) {
	tests := []struct {
		name  string
		nodes []routecheck.Node
		want  map[string][]string
		// wantOrder is the order the networks must come back in, for the cases where
		// there is more than one and the order is the thing being asserted.
		wantOrder []string
	}{{
		name: "two devices carrying the same network are both named",
		nodes: []routecheck.Node{
			{ID: 2, Name: "backup.tail1a2b3c.ts.net.", Routes: prefixes(t, "192.168.1.0/24")},
			{ID: 1, Name: "gateway.tail1a2b3c.ts.net.", Routes: prefixes(t, "192.168.1.0/24")},
		},
		// Sorted, and without the trailing dot the backend puts on an FQDN: this list is
		// read by a person deciding which device to go and look at.
		want: map[string][]string{
			"192.168.1.0/24": {"backup.tail1a2b3c.ts.net", "gateway.tail1a2b3c.ts.net"},
		},
	}, {
		// A default route is an exit-node advertisement, and the tailnet's own ranges are
		// how every peer is reached. Reporting either as a subnet route this device
		// reaches would put a line on the card for something that is not one.
		name: "the exit-node routes and the tailnet's own ranges are left out",
		nodes: []routecheck.Node{{
			ID: 1, Name: "gateway.tail1a2b3c.ts.net.",
			Routes: prefixes(t, "0.0.0.0/0", "::/0", "100.64.0.0/10", "10.1.0.0/16"),
		}},
		want: map[string][]string{"10.1.0.0/16": {"gateway.tail1a2b3c.ts.net"}},
	}, {
		// The backend hands these back in map order, which is different on every call.
		// A card whose rows moved between polls would be unreadable.
		name: "a stable order whatever order the backend reports",
		nodes: []routecheck.Node{{
			ID: 1, Name: "gateway.tail1a2b3c.ts.net.",
			Routes: prefixes(t, "192.168.1.0/24", "10.1.0.0/16", "172.16.0.0/12"),
		}},
		wantOrder: []string{"10.1.0.0/16", "172.16.0.0/12", "192.168.1.0/24"},
		want: map[string][]string{
			"10.1.0.0/16":    {"gateway.tail1a2b3c.ts.net"},
			"172.16.0.0/12":  {"gateway.tail1a2b3c.ts.net"},
			"192.168.1.0/24": {"gateway.tail1a2b3c.ts.net"},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := reachableNodes(t, tt.nodes...)
			n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
				return jsonResponse(body), nil
			})

			got, err := n.RouteReachability(t.Context())
			if err != nil {
				t.Fatalf("RouteReachability: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("RouteReachability() = %+v, want %v", got, tt.want)
			}
			for i, want := range tt.wantOrder {
				if got[i].Prefix.String() != want {
					t.Errorf("RouteReachability()[%d] = %s, want %s", i, got[i].Prefix, want)
				}
			}
			for _, reach := range got {
				want, ok := tt.want[reach.Prefix.String()]
				if !ok {
					t.Errorf("RouteReachability() reported %s, which is not a network it should", reach.Prefix)
					continue
				}
				if strings.Join(reach.Via, ",") != strings.Join(want, ",") {
					t.Errorf("%s is carried by %v, want %v", reach.Prefix, reach.Via, want)
				}
			}
		})
	}
}

// A node that has just started has no netmap to probe, which is an ordinary state rather
// than a failure. Reporting it as an error would put a red notice on the card for the
// first few seconds of every run.
func TestRouteReachabilityTreatsAMissingNetmapAsNothingToReport(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return noContentResponse(), nil
	})

	got, err := n.RouteReachability(t.Context())
	if err != nil {
		t.Fatalf("RouteReachability: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("RouteReachability() = %+v, want nothing reported before there is a netmap", got)
	}
}

// A probe that ran and compiled no report at all is the same "nothing to say" as one that
// had no netmap. Reading the routes out of a nil report is a panic in the API handler.
func TestRouteReachabilityHandlesAProbeThatCompiledNoReport(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse("null"), nil
	})

	got, err := n.RouteReachability(t.Context())
	if err != nil {
		t.Fatalf("RouteReachability: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("RouteReachability() = %+v, want nothing reported for a report that is not there", got)
	}
}

// Any other refusal is a real one. Turning it into an empty list would say every device
// carrying a route is unreachable, which is a far larger claim than "could not ask".
func TestRouteReachabilityReportsABackendRefusalRatherThanAnEmptyList(t *testing.T) {
	n := requireStubbedNode(t, func(*http.Request) (*http.Response, error) {
		return errorResponse(http.StatusInternalServerError, "the probe failed"), nil
	})

	if _, err := n.RouteReachability(t.Context()); err == nil {
		t.Fatal("RouteReachability reported no error although the backend refused")
	} else if !strings.Contains(err.Error(), "the probe failed") {
		t.Errorf("RouteReachability() error = %v, want the backend's own reason", err)
	}
}

// Probing needs a running backend to probe with.
func TestRouteReachabilityRefusesBeforeTheNodeHasStarted(t *testing.T) {
	n := newBareNode(t)

	if _, err := n.RouteReachability(t.Context()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("RouteReachability() error = %v, want ErrNotRunning", err)
	}
}

// The ranges decide what counts as a tailnet address everywhere downstream. Written out
// as constants they would drift from the library the node actually routes with.
func TestTailnetRangesAreTheOnesTailscaleAllocatesFrom(t *testing.T) {
	ranges := TailnetRanges()
	if len(ranges) != 2 {
		t.Fatalf("TailnetRanges() = %v, want the IPv4 and IPv6 ranges", ranges)
	}

	inRange := func(addr string) bool {
		ip := netip.MustParseAddr(addr)
		for _, r := range ranges {
			if r.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, addr := range []string{"100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1"} {
		if !inRange(addr) {
			t.Errorf("%s is not in any tailnet range %v, so tailnet traffic would be classed as public", addr, ranges)
		}
	}
	for _, addr := range []string{"192.168.1.1", "8.8.8.8", "100.128.0.1", "2606:4700::1111"} {
		if inRange(addr) {
			t.Errorf("%s is inside a tailnet range %v, so public traffic would be classed as tailnet", addr, ranges)
		}
	}
}
