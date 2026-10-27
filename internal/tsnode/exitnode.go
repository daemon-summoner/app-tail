// SPDX-License-Identifier: MIT

package tsnode

// The exit-node operations that need the backend rather than the preference table: the
// tailnet's own suggestion, and a latency measurement of a candidate. Selection itself
// is a preference, so it goes through EditPrefs like every other one.

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// Suggestion is the exit node the tailnet recommends for this device.
type Suggestion struct {
	ID       string
	Name     string
	Location PeerLocation
}

// SuggestExitNode asks the tailnet which exit node it would pick for this device.
//
// Only peers the control plane has flagged as suggestable are considered, which on most
// tailnets means Tailscale's own hosted nodes and never a device someone runs
// themselves. A caller offering this has to say so, or a tailnet whose only exit nodes
// are self-hosted looks broken rather than unflagged.
func (n *Node) SuggestExitNode(ctx context.Context) (Suggestion, error) {
	lc := n.client()
	if lc == nil {
		return Suggestion{}, ErrNotRunning
	}
	resp, err := lc.SuggestExitNode(ctx)
	if err != nil {
		return Suggestion{}, fmt.Errorf("ask the tailnet for an exit node: %w", err)
	}
	return suggestionOf(resp), nil
}

// suggestionOf is the tailnet's answer in this package's own types. A device someone runs
// themselves carries no location, so the place is filled only when the control plane
// published one.
func suggestionOf(resp apitype.ExitNodeSuggestionResponse) Suggestion {
	out := Suggestion{ID: string(resp.ID), Name: resp.Name}
	if resp.Location.Valid() {
		out.Location = locationOf(resp.Location.AsStruct())
	}
	return out
}

// PingPeer measures the round trip to a peer and reports how long it took.
//
// It uses a disco ping, which the peer's WireGuard layer answers directly: a device that
// drops ICMP or runs no reachable service still answers, so a candidate is never ruled
// out by a firewall that has nothing to do with whether it can carry traffic.
func (n *Node) PingPeer(ctx context.Context, ip netip.Addr) (time.Duration, error) {
	lc := n.client()
	if lc == nil {
		return 0, ErrNotRunning
	}
	res, err := lc.Ping(ctx, ip, tailcfg.PingDisco)
	if err != nil {
		return 0, fmt.Errorf("ping %s: %w", ip, err)
	}
	return roundTripOf(ip, res)
}

// roundTripOf is the measurement a ping result carries, or why it carries none. A result
// that reports no round trip is a failure rather than a zero: zero would sort ahead of
// every device that did answer, which is the opposite of what the measurement is for.
func roundTripOf(ip netip.Addr, res *ipnstate.PingResult) (time.Duration, error) {
	if res == nil {
		return 0, fmt.Errorf("ping %s: the backend returned no result", ip)
	}
	if res.Err != "" {
		return 0, fmt.Errorf("ping %s: %s", ip, res.Err)
	}
	if res.LatencySeconds <= 0 {
		return 0, fmt.Errorf("ping %s: no round trip was measured", ip)
	}
	return time.Duration(res.LatencySeconds * float64(time.Second)), nil
}
