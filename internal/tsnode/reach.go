// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// ErrNoDialPlan is returned when the node cannot say where an address would go.
// The backend builds the dialer during Start, so a running node always can; a caller
// that has to decide whether an address is in scope must refuse rather than guess.
var ErrNoDialPlan = errors.New("the tailnet node cannot classify addresses yet")

// Reach is what the tailnet would do with an address.
type Reach struct {
	// Addr is what the address resolved to. A MagicDNS name resolves from the
	// netmap; anything else goes to the host resolver.
	Addr netip.AddrPort
	// ViaTailnet reports whether a dial to Addr leaves through the tailnet rather
	// than through this machine's own network. It is the answer a caller enforcing
	// a tailnet-only scope acts on.
	ViaTailnet bool
}

// Reach reports where a dial to address would go, without dialing it.
//
// It is the classification half of Dial: the same resolution and the same routing
// table, asked ahead of time. Callers that must not dial off-tailnet use it to
// decide, then dial Addr rather than the original name -- resolving twice invites the
// answer to change in between, and the direction that changes is the unsafe one.
func (n *Node) Reach(ctx context.Context, network, address string) (Reach, error) {
	if !n.Status().Running() {
		return Reach{}, ErrNotRunning
	}
	plan := n.dialPlan()
	if plan == nil {
		return Reach{}, ErrNoDialPlan
	}
	addr, viaTailnet, err := plan(ctx, network, address)
	if err != nil {
		return Reach{}, fmt.Errorf("resolving %s: %w", address, err)
	}
	return Reach{Addr: addr, ViaTailnet: viaTailnet}, nil
}

// dialPlan returns the classifier, or nil before Start and after Close.
func (n *Node) dialPlan() dialPlanner {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.plan
}
