// SPDX-License-Identifier: MIT

package app

// Answering a name on a connected network with an address this machine can reach.
//
// A private network's own resolver answers with that network's own addresses, and handing
// one of those to a program on this machine is only right while nothing else claims them.
// Once two networks carry the same addresses one of them is reached somewhere else here, and
// the answer has to be translated on the way out exactly as the packets are -- otherwise the
// name resolves, the program connects, and it reaches the other network's host of the same
// address, which is the failure with no symptom.
//
// Only the interface mode can do this: it is the only one where an address belonging to a
// connection means anything to the rest of the machine. In every other mode a name on a
// connection is answered "no such name" by routing alone and nothing here is asked.

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsfwd"
	"github.com/sellitus/app-tail/internal/fabric"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// fabricResolver answers names inside the connections one interface is carrying.
type fabricResolver struct{ a *Agent }

var _ dnsfwd.TunnelResolver = fabricResolver{}

// fabricAddressing is the addressing this machine reaches its connections by, together with
// the connections it covers. Both are zero in every mode but the one that puts every
// connection on one interface.
func (a *Agent) fabricAddressing() (*fabric.Table, map[string]bool) {
	runner := a.currentFabric()
	if runner == nil {
		return nil, nil
	}
	table := runner.carriedTable()
	if table == nil {
		return nil, nil
	}
	carried := make(map[string]bool)
	for _, m := range table.Mappings() {
		carried[m.TunnelID] = true
	}
	return table, carried
}

// LookupTunnel resolves a name through one connection's own resolver and translates every
// address in the answer into the one this machine reaches it at.
func (f fabricResolver) LookupTunnel(ctx context.Context, tunnelID, host string) ([]netip.Addr, error) {
	table, _ := f.a.fabricAddressing()
	if table == nil {
		// The mode went off between the routing decision and this lookup. Reported rather
		// than answered as "no such name": the name may well exist, and this machine has
		// just stopped being able to reach it.
		return nil, fmt.Errorf("this machine is no longer reaching your connections by address")
	}

	live, running := f.a.tunnels.Get(tunnelID)
	if !running {
		return nil, fmt.Errorf("the connection that answers for this name is not running")
	}
	resolver, ok := live.(tunnel.Resolving)
	if !ok {
		// A network that publishes no resolver of its own -- a WireGuard peer with no DNS=
		// line. Nothing knows its names, so no name on it exists, which is an answer rather
		// than a failure.
		return nil, nil
	}

	answer, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if !answer.Served() {
		return nil, nil
	}

	out := make([]netip.Addr, 0, len(answer.Addrs))
	for _, addr := range answer.Addrs {
		here, ok := table.Present(tunnelID, addr)
		if !ok {
			// An address the network never said it carries, so this machine has nowhere to
			// send it. Handing it back untranslated is the one thing that must not happen:
			// it is somebody else's address here.
			continue
		}
		out = append(out, here)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the network answered with %d address(es) it does not carry, so this machine has nowhere to reach them", len(answer.Addrs))
	}
	return out, nil
}

// virtualPrefixesOf are the ranges this machine reaches moved networks at, which are the
// ones no resolver anywhere holds a name for.
//
// Only the moved ones. A network reached at its own addresses has real reverse names inside
// it, and the machine's existing rules already send those lookups somewhere that might
// answer; these are addresses app-tail invented, and the only thing to do with a question
// about one is to say so.
func virtualPrefixesOf(table *fabric.Table, stored []config.Tunnel) []dnsfwd.VirtualPrefix {
	if table == nil {
		return nil
	}
	var out []dnsfwd.VirtualPrefix
	for _, m := range table.Mappings() {
		if !m.Moved() {
			continue
		}
		out = append(out, dnsfwd.VirtualPrefix{
			Prefix: m.PresentedAs,
			Name:   tunnelName(stored, m.TunnelID),
		})
	}
	return out
}
