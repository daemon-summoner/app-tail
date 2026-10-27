// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"

	// The reachability check below is served by an extension the backend only registers
	// when this package is linked in. tsnet imports a fixed, short list of features and
	// this is not one of them, so without this line every call to it answers 404 and the
	// feature fails in a way that looks like a bug in app-tail.
	_ "tailscale.com/feature/routecheck"
)

// TailnetRanges returns the address ranges a tailnet allocates its own devices from:
// the CGNAT block for IPv4 and the ULA prefix for IPv6. They are read from the library
// rather than written out here so an upstream change cannot leave a stale constant
// deciding what counts as tailnet traffic.
func TailnetRanges() []netip.Prefix {
	return []netip.Prefix{tsaddr.CGNATRange(), tsaddr.TailscaleULARange()}
}

// ServeSubnets carries flows destined for the networks this node advertises, and returns
// the function that stops carrying them.
//
// The handler decides what to do with one TCP flow that arrived for an address this node
// routes rather than for the node itself. Returning nil refuses the connection; a
// returned function takes ownership of the connection and must close it. The signature is
// spelled out rather than named so the seam a caller declares for this method carries no
// dependency on this package.
//
// It is the only way a userspace node can serve a route at all. tsnet answers a flow
// with no listener for its destination by resetting it, so a node that advertises a
// subnet and installs no handler here refuses every connection to that subnet -- which
// looks to the rest of the tailnet like a subnet router that is up and broken. TCP is
// the whole surface: there is no equivalent hook for UDP, which is why what this serves
// is labelled TCP-only everywhere it is offered.
func (n *Node) ServeSubnets(h func(src, dst netip.AddrPort) func(net.Conn)) (func(), error) {
	if h == nil {
		return nil, errors.New("serve subnets: no handler was given")
	}
	if !n.Status().Running() {
		return nil, ErrNotRunning
	}
	return n.srv.RegisterFallbackTCPHandler(interceptAll(h)), nil
}

// ApprovedRoutes are the networks this node is actually carrying traffic for: the ones an
// admin approved out of what it advertised, as the control plane reports them back.
//
// Advertising is a request, not a fact. Serving what was asked for rather than what was
// approved would have this node answer connections the tailnet never routed to it, so
// this is the set the subnet router is held to.
func (n *Node) ApprovedRoutes(ctx context.Context) ([]netip.Prefix, error) {
	st, err := n.fullStatus(ctx)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Self == nil || st.Self.PrimaryRoutes == nil {
		return nil, nil
	}
	return carriedRoutes(st.Self.PrimaryRoutes.AsSlice()), nil
}

// carriedRoutes narrows an approved set to the subnets a userspace router can serve.
//
// The default routes are dropped because they are the exit-node advertisement, which is
// a different feature with different rules -- carrying them here would turn an approval
// of "offer yourself as an exit node" into this process proxying every destination on
// the internet. The tailnet's own ranges are dropped because a flow to one of those is
// either this node's own, and answered by a listener before reaching here, or another
// peer's, which this node has no business intercepting.
func carriedRoutes(approved []netip.Prefix) []netip.Prefix {
	tailnet := TailnetRanges()
	var out []netip.Prefix
	for _, p := range approved {
		if p.Bits() == 0 || containsAny(tailnet, p) {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// RouteReach is one network this node accepts and the devices carrying it that answered
// a probe just now. Several devices may advertise the same network for failover, so the
// list matters: a route with an empty one is in the netmap and reaches nothing.
type RouteReach struct {
	Prefix netip.Prefix
	Via    []string
}

// RouteReachability probes the devices advertising each network this node accepts and
// reports which of them answered.
//
// It is the answer to a subnet route that looks right and does not work: the prefix is
// in the netmap, the addresses are correct, and the device meant to be carrying it is
// unreachable. Nothing else on the node distinguishes that from a misconfigured LAN.
func (n *Node) RouteReachability(ctx context.Context) ([]RouteReach, error) {
	lc := n.client()
	if lc == nil {
		return nil, ErrNotRunning
	}
	report, err := lc.RouteCheckProbe(ctx)
	if err != nil {
		if errors.Is(err, local.ErrRouteCheckReportUnavailable) {
			// The node has no netmap yet, which is a normal state moments after start
			// rather than a failure: there is nothing to probe and nothing is wrong.
			return nil, nil
		}
		return nil, fmt.Errorf("probe the devices carrying this tailnet's routes: %w", err)
	}
	if report == nil {
		return nil, nil
	}

	tailnet := TailnetRanges()
	var out []RouteReach
	for prefix, nodes := range report.RoutablePrefixes() {
		if prefix.Bits() == 0 || containsAny(tailnet, prefix) {
			continue
		}
		via := make([]string, 0, len(nodes))
		for _, node := range nodes {
			via = append(via, strings.TrimSuffix(node.Name, "."))
		}
		sort.Strings(via)
		out = append(out, RouteReach{Prefix: prefix, Via: via})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix.String() < out[j].Prefix.String() })
	return out, nil
}

// Routes returns the subnet ranges this node reaches through tailnet peers -- a LAN
// behind a subnet router, say -- which is the set that is reachable over the tailnet
// without being a tailnet address. A node that is not accepting routes reaches none of
// them, and reports an empty list rather than the routes it would reach if it were.
//
// Only the peer elected primary for a route is counted. Several peers may advertise the
// same prefix for failover, and only one of them carries traffic at a time.
func (n *Node) Routes(ctx context.Context) ([]netip.Prefix, error) {
	lc := n.client()
	if lc == nil {
		return nil, ErrNotRunning
	}
	prefs, err := lc.GetPrefs(ctx)
	if err != nil {
		return nil, fmt.Errorf("read tailnet preferences: %w", err)
	}
	if prefs == nil || !prefs.RouteAll {
		return nil, nil
	}
	st, err := n.fullStatus(ctx)
	if err != nil {
		return nil, err
	}
	return acceptedRoutes(st), nil
}

// acceptedRoutes collects the subnet prefixes peers currently carry traffic for.
//
// The tailnet's own ranges are dropped: a peer advertising one would add nothing, since
// every tailnet address is reachable regardless, and a caller building a routing rule
// out of the result would state the same range twice. Default routes are dropped for a
// stronger reason -- a peer advertising 0.0.0.0/0 is offering itself as an exit node,
// which is a separate choice the user makes explicitly and which routes everything
// rather than a subnet.
func acceptedRoutes(st *ipnstate.Status) []netip.Prefix {
	if st == nil {
		return nil
	}
	tailnet := TailnetRanges()
	seen := make(map[netip.Prefix]bool)
	var out []netip.Prefix
	for _, ps := range st.Peer {
		if ps == nil || ps.PrimaryRoutes == nil {
			continue
		}
		for _, p := range ps.PrimaryRoutes.All() {
			if p.Bits() == 0 || seen[p] || containsAny(tailnet, p) {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	// The peer map iterates in map order, so without this the same tailnet produces a
	// different PAC file on every fetch and nothing downstream can be compared or cached.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// containsAny reports whether any of ranges covers p entirely.
func containsAny(ranges []netip.Prefix, p netip.Prefix) bool {
	for _, r := range ranges {
		if r.Overlaps(p) && r.Bits() <= p.Bits() {
			return true
		}
	}
	return false
}
