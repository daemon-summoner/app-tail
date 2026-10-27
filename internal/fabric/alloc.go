// SPDX-License-Identifier: MIT

// Where each private network is reachable from this machine when two of them carry the
// same addresses.
//
// Connecting to several networks at once means their address space can collide: two
// companies both using 10.0.0.0/8, or a network whose addresses are the ones this machine
// already uses at home. Only one of them can be reached at those addresses, so the rest
// have to be presented somewhere else -- an address this machine picks, which nothing else
// on it is using, and which is translated back on the way out.
//
// Nothing here changes anything on the machine. Allocate is a pure function that says what
// the addressing would have to be; carrying it out needs the interface that terminates and
// re-dials traffic, which is a later piece of work. Until then this is what the dashboard
// reports, which is the part that matters first: a collision nobody is told about is a
// network that silently answers for another one's addresses.
//
// Limits stated rather than discovered: the default pool is IPv4 only, so a collision
// between two IPv6 networks is reported with no address to move it to. A network larger
// than the pool cannot be moved either -- presenting a /8 somewhere else needs a spare /8,
// which no reserved range provides.
package fabric

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// DefaultPool is the address space a moved network is presented from.
//
// 198.18.0.0/15 is reserved for benchmarking (RFC 2544), so nothing routes it on a real
// network and nothing else on this machine should be using it. Deliberately not
// 100.64.0.0/10, which this app already treats as tailnet space, and not 240.0.0.0/4,
// which Windows refuses to route.
var DefaultPool = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}

// Network is one address range a connection carries.
type Network struct {
	// TunnelID is the connection that carries it.
	TunnelID string
	// Name is what a person calls that connection. The sentences a plan carries are
	// written with it, so a caller that has a display name gets "reached through office"
	// rather than an identifier nobody recognises. Empty falls back to the id.
	Name   string
	Prefix netip.Prefix
}

// Placement is where this machine would reach one network.
type Placement struct {
	TunnelID string
	// Prefix is the network's own addresses, as the connection carrying it reports them.
	Prefix netip.Prefix
	// PresentedAs is the address space this machine would reach it at. It is the zero
	// value when the network is reachable at its own addresses -- the ordinary case, with
	// no surprises -- and also when it has to move but nothing in the pool fits it.
	PresentedAs netip.Prefix
	// Reason says why the network cannot be reached at its own addresses, and is empty
	// exactly when it can. A consumer never has to explain a move it was given no reason
	// for, and never has to guess that an address it was not given means "fine".
	Reason string
}

// Moved reports whether this network has to be presented somewhere other than its own
// addresses, whether or not somewhere was found for it.
func (p Placement) Moved() bool { return p.Reason != "" }

// Collision is one address range claimed by more than one network, or by a network and
// this machine.
type Collision struct {
	Prefix netip.Prefix
	// Holder is the connection reachable at these addresses as they are, or empty when
	// that is this machine itself -- in which case every connection claiming them moves.
	Holder string
	// HolderName is what that connection is called, empty for the same two reasons Holder
	// is: this machine holds the range, or the holder was given no name.
	HolderName string
	// Claimants are the connections that carry these addresses and cannot be reached at
	// them, in the order they were given.
	Claimants []string
	Detail    string
}

// Plan is the whole addressing answer: where each network sits, and what collided.
type Plan struct {
	Pool       []netip.Prefix
	Placements []Placement
	Collisions []Collision
}

// Moves is how many networks cannot be reached at their own addresses, which is what
// decides whether there is anything to report at all.
func (p Plan) Moves() int {
	n := 0
	for _, placed := range p.Placements {
		if placed.Moved() {
			n++
		}
	}
	return n
}

// claim is one address range already spoken for, and by whom. An empty owner is this
// machine's own network, which nothing takes away from it.
type claim struct {
	prefix netip.Prefix
	owner  string
	label  string
}

// display is what a sentence calls the connection holding a claim: its name when it has
// one, and its id when it does not.
func (c claim) display() string {
	if c.label != "" {
		return c.label
	}
	return c.owner
}

/*
Allocate decides where each network is reachable from this machine.

Order is the answer to "who keeps the address": the first network given that claims a
range keeps it, and every later one claiming the same range moves. Callers pass the
connections in a stable order -- the configured one -- so the answer does not change
between two runs that were given the same networks, and a connection does not lose the
address it has been reachable at because another one reconnected first.

`host` is the address space this machine is already on. It is never moved and never
reported as a claimant: a network of this machine's own is not something a connection can
take over, so a connection colliding with it is the one that has to move.
*/
func Allocate(networks []Network, host []netip.Prefix, pool []netip.Prefix) Plan {
	if len(pool) == 0 {
		pool = DefaultPool
	}
	plan := Plan{Pool: slices.Clone(pool)}

	claims := make([]claim, 0, len(host)+len(networks))
	for _, prefix := range host {
		if prefix.IsValid() {
			claims = append(claims, claim{prefix: prefix.Masked()})
		}
	}
	// Where each colliding range is already reported, so several connections claiming one
	// range become one collision rather than one report per latecomer.
	reported := make(map[netip.Prefix]int, len(networks))

	for _, network := range networks {
		if !network.Prefix.IsValid() {
			continue
		}
		held := network.Prefix.Masked()

		mine := claim{prefix: held, owner: network.TunnelID, label: network.Name}
		blocking, holder := blockers(claims, held)
		if len(blocking) == 0 {
			claims = append(claims, mine)
			plan.Placements = append(plan.Placements, Placement{TunnelID: network.TunnelID, Prefix: held})
			continue
		}

		why := collisionDetail(held, holder, blocking)
		if at, seen := reported[held]; seen {
			plan.Collisions[at].Claimants = append(plan.Collisions[at].Claimants, network.TunnelID)
		} else {
			reported[held] = len(plan.Collisions)
			plan.Collisions = append(plan.Collisions, Collision{
				Prefix:     held,
				Holder:     holder.owner,
				HolderName: holder.label,
				Claimants:  []string{network.TunnelID},
				Detail:     why,
			})
		}

		placement := Placement{TunnelID: network.TunnelID, Prefix: held, Reason: why}
		if moved, ok := carve(pool, claims, held); ok {
			placement.PresentedAs = moved
			claims = append(claims, claim{prefix: moved, owner: network.TunnelID, label: network.Name})
		} else {
			placement.Reason = fmt.Sprintf("%s, and %s has no free range of that size to "+
				"present it from, so reaching it needs an address range you choose",
				why, poolText(pool))
		}
		plan.Placements = append(plan.Placements, placement)
	}

	return plan
}

// blockers are the claims overlapping this range, and which of them keeps it: the first
// connection already claiming it, or a claim with no owner when one of this machine's own
// networks is among them. The holder is the zero claim when nothing blocks at all, which
// callers tell apart by the empty list.
func blockers(claims []claim, want netip.Prefix) ([]claim, claim) {
	var blocking []claim
	var holder claim
	for _, held := range claims {
		if !held.prefix.Overlaps(want) {
			continue
		}
		blocking = append(blocking, held)
		// This machine's own network wins over every connection: it is the network the
		// user is sitting on, and taking its addresses away would cut them off from their
		// own printer in order to reach someone else's.
		if held.owner == "" {
			return blocking, claim{}
		}
		if holder.owner == "" {
			holder = held
		}
	}
	return blocking, holder
}

func collisionDetail(prefix netip.Prefix, holder claim, blocking []claim) string {
	first := blocking[0].prefix
	if holder.owner == "" {
		if first == prefix {
			return fmt.Sprintf("%s is a network this machine is already on", prefix)
		}
		return fmt.Sprintf("%s overlaps %s, a network this machine is already on", prefix, first)
	}
	if first == prefix {
		return fmt.Sprintf("%s is already reached through %s", prefix, holder.display())
	}
	return fmt.Sprintf("%s overlaps %s, which is reached through %s", prefix, first, holder.display())
}

// carve finds a free range the size of `want` in the pool.
//
// It walks the pool in order and returns the first range of that size nothing has claimed,
// so the answer depends on what is already claimed and not on when this ran.
func carve(pool []netip.Prefix, claims []claim, want netip.Prefix) (netip.Prefix, bool) {
	for _, from := range pool {
		if from.Addr().Is4() != want.Addr().Is4() || want.Bits() < from.Bits() {
			continue
		}
		candidate := netip.PrefixFrom(from.Addr(), want.Bits()).Masked()
		for from.Contains(candidate.Addr()) {
			if !claimedAlready(claims, candidate) {
				return candidate, true
			}
			after, ok := next(candidate)
			if !ok {
				break
			}
			candidate = after
		}
	}
	return netip.Prefix{}, false
}

func claimedAlready(claims []claim, want netip.Prefix) bool {
	for _, held := range claims {
		if held.prefix.Overlaps(want) {
			return true
		}
	}
	return false
}

// next is the range of the same size immediately after this one, and false past the end of
// the address family -- where a walk has to stop rather than wrap around to zero and hand
// out an address it has already given away.
//
// It adds one at the last bit the prefix covers, which steps a whole range at a time. A
// walk that stepped one address at a time would take 2^(32-bits) steps to reach the next
// candidate.
func next(p netip.Prefix) (netip.Prefix, bool) {
	if p.Bits() == 0 {
		return netip.Prefix{}, false
	}
	raw := p.Addr().AsSlice()
	carry := byte(1) << (7 - uint((p.Bits()-1)%8))
	for i := (p.Bits() - 1) / 8; i >= 0; i-- {
		raw[i] += carry
		// A byte that came out smaller than what was added to it wrapped, so the carry
		// moves to the byte above; anything else is done.
		if raw[i] >= carry {
			addr, ok := netip.AddrFromSlice(raw)
			return netip.PrefixFrom(addr, p.Bits()), ok
		}
		carry = 1
	}
	return netip.Prefix{}, false
}

func poolText(pool []netip.Prefix) string {
	parts := make([]string, 0, len(pool))
	for _, prefix := range pool {
		parts = append(parts, prefix.String())
	}
	return strings.Join(parts, ", ")
}
