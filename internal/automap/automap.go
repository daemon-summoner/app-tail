// SPDX-License-Identifier: MIT

// Package automap turns discovered tailnet peers into local port forwards, so a peer's
// SSH or web port is reachable at a loopback address without anyone configuring it.
//
// The whole feature is port stability. A local port that moved between runs would be
// worse than no feature at all: every bookmark, ssh_config Host block and shell alias
// naming it would break on a restart, silently, and point at whichever peer happened to
// take the number. So allocation happens once per peer-and-port and is written to the
// configuration, and every later run reads it back rather than recomputing it.
package automap

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// IDPrefix marks a forward this package derives. Nothing with this prefix is stored in
// the forwards list, so a user editing one would be editing something that is rebuilt
// from the peer list on the next reconcile; the API refuses those writes by this prefix.
const IDPrefix = "auto_"

// Plan is one reconcile's worth of derived forwards.
type Plan struct {
	// Forwards are the derived entries, ready to merge with the stored ones.
	Forwards []config.Forward
	// Allocations are the port assignments to persist, including the ones that already
	// existed. It is the whole map rather than the new entries so a caller can store it
	// without merging, and is nil when nothing changed.
	Allocations map[string]int
	// Truncated is how many peer-and-port pairs the limit left out. Reported rather
	// than dropped: a user whose newest device is missing needs to know the limit is
	// why, not conclude the feature is broken.
	Truncated int
}

// Allocator hands out a local port not already spoken for. It is injected because the
// caller decides what "already spoken for" means -- stored forwards, the dashboard's
// own port, every port in Existing -- and because a planner that binds sockets could
// not be tested.
//
// It must never return a port already assigned in Existing or handed out earlier in the
// same plan. Build checks and fails rather than trusting it: two peers sharing a local
// port means one of them silently never listens.
type Allocator func(preferred int) (int, error)

// Params is everything a plan is computed from.
type Params struct {
	// TunnelID is the connection these peers were discovered on. It is part of every
	// assignment key and of every derived forward, because a device id is only unique
	// within the network that issued it: without it, a device on a second network could
	// be handed the local port a device on the first already answers on.
	TunnelID string
	Peers    []tsnode.Peer
	// Ports are the remote ports to map on every peer, in the order they were configured.
	Ports []int
	// Max caps how many forwards this package will produce at once.
	Max int
	// PortBase is where allocation starts looking for a free local port.
	PortBase int
	// Existing is the persisted allocation map, keyed by allocationKey.
	Existing map[string]int
	// Allocate hands out a local port for a pair that has none yet.
	Allocate Allocator
	// Disabled are the derived forwards, by id, somebody switched off. They are still
	// planned and still hold their assignment: dropping one would take its row off the
	// screen with nothing left to switch it back on, and releasing its port would hand
	// that number to another device.
	Disabled map[string]bool
	// BindAddr is the local address the derived forwards listen on.
	BindAddr string
}

// allocationKey identifies one peer-and-port pair on one connection across runs. The
// peer's stable ID is what makes it survive: a peer that re-registers keeps it, while its
// netmap handle and even its hostname can change underneath a user who bookmarked the
// local port. The connection is in front of it because that id is only unique within the
// network that issued it.
func allocationKey(tunnelID, stableID string, port int) string {
	return tunnelID + "/" + stableID + "/" + strconv.Itoa(port)
}

// TunnelOf reads the connection out of an assignment key, empty for a key from before
// assignments named one. It is exported because pruning is the one operation that has to
// tell one connection's assignments from another's.
func TunnelOf(key string) string {
	tunnelID, rest, ok := strings.Cut(key, "/")
	if !ok || !strings.Contains(rest, "/") {
		return ""
	}
	return tunnelID
}

// forwardID is the derived forward's identity. It is a function of the connection and the
// pair, so the live counters, the dashboard row and the stored allocation all agree across
// restarts without anything being written down.
func forwardID(tunnelID, stableID string, port int) string {
	return IDPrefix + safeIDPart(tunnelID) + "_" + safeIDPart(stableID) + "_" + strconv.Itoa(port)
}

// safeIDPart keeps a forward id free of the separator its own parts are joined with, so
// two different pairs cannot render to one id.
func safeIDPart(s string) string { return strings.ReplaceAll(s, "/", "-") }

// Build computes the derived forwards for one reconcile.
//
// Peers arrive in the order the node reports them, which is online first and then by
// name, and that order decides who gets a slot when there are more pairs than the limit
// allows. Allocations are never revoked, so a peer that drops out of the limit and comes
// back later returns to the same local port.
func Build(p Params) (Plan, error) {
	if p.Max <= 0 || len(p.Ports) == 0 {
		return Plan{}, nil
	}

	allocations := make(map[string]int, len(p.Existing)+len(p.Peers))
	for k, v := range p.Existing {
		allocations[k] = v
	}
	changed := false

	// Ports taken within this plan. A pair allocated a moment ago is not yet visible to
	// the caller's allocator, so without this two peers would be handed the same port
	// and the second forward would fail to bind.
	taken := make(map[int]bool, len(allocations))
	for _, port := range allocations {
		taken[port] = true
	}

	plan := Plan{Forwards: make([]config.Forward, 0, p.Max)}
	for _, peer := range p.Peers {
		// A peer with no stable ID could not be given a port that survives a restart,
		// and a port that silently moves is the outcome this package exists to prevent.
		// One with nothing to dial would produce a forward that can only fail.
		if peer.ID == "" || peer.DialTarget() == "" {
			continue
		}
		for _, port := range p.Ports {
			if len(plan.Forwards) >= p.Max {
				plan.Truncated++
				continue
			}
			key := allocationKey(p.TunnelID, peer.ID, port)
			local, ok := allocations[key]
			if !ok {
				assigned, err := p.Allocate(nextPreferred(p.PortBase, taken))
				if err != nil {
					return Plan{}, fmt.Errorf("allocate a local port for %s:%d: %w", peer.Label(), port, err)
				}
				if taken[assigned] {
					return Plan{}, fmt.Errorf("allocate a local port for %s:%d: port %d is already assigned to another device",
						peer.Label(), port, assigned)
				}
				local, allocations[key], changed = assigned, assigned, true
			}
			taken[local] = true
			derived := forwardFor(p.TunnelID, peer, port, local, p.BindAddr)
			derived.Enabled = !p.Disabled[derived.ID]
			plan.Forwards = append(plan.Forwards, derived)
		}
	}

	if changed {
		plan.Allocations = allocations
	}
	return plan, nil
}

// nextPreferred is where to start looking for a free port: the first number at or above
// the base that this plan has not already handed out. Without it every allocation in one
// pass would ask for the same base port and the allocator would walk the same run of
// taken numbers again for each.
func nextPreferred(base int, taken map[int]bool) int {
	for port := base; port <= 65535; port++ {
		if !taken[port] {
			return port
		}
	}
	// Nothing free above the base; the allocator falls back to an OS-assigned port.
	return 0
}

func forwardFor(tunnelID string, peer tsnode.Peer, remote, local int, bindAddr string) config.Forward {
	return config.Forward{
		ID:         forwardID(tunnelID, peer.ID, remote),
		Name:       fmt.Sprintf("%s:%d", peer.Label(), remote),
		TunnelID:   tunnelID,
		Direction:  config.ToLocal,
		Protocol:   config.TCP,
		BindAddr:   bindAddr,
		ListenPort: local,
		Target:     fmt.Sprintf("%s:%d", peer.DialTarget(), remote),
		Enabled:    true,
	}
}

// Prune drops allocations for peers the given connection no longer reports, and reports
// how many went. It is deliberately not called from the reconcile loop: an empty peer list
// is what a node that has not finished starting looks like, and pruning on that would hand
// every port out again on the next pass. It runs only when a user asks for it.
//
// Assignments belonging to another connection are kept untouched. peers describes one
// network, and a device absent from it says nothing at all about a device on another --
// dropping those would move the local ports of every connection but the one being pruned.
func Prune(tunnelID string, existing map[string]int, peers []tsnode.Peer) (map[string]int, int) {
	live := make(map[string]bool, len(peers))
	for _, peer := range peers {
		live[peer.ID] = true
	}

	kept := make(map[string]int, len(existing))
	removed := 0
	for key, port := range existing {
		if TunnelOf(key) != tunnelID {
			kept[key] = port
			continue
		}
		_, rest, _ := strings.Cut(key, "/")
		stableID, _, _ := strings.Cut(rest, "/")
		if live[stableID] {
			kept[key] = port
			continue
		}
		removed++
	}
	return kept, removed
}
