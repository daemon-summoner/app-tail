// SPDX-License-Identifier: MIT

package fabric

// Which connection an address on this machine belongs to, and what to dial inside it.
//
// Allocate says where each network would have to sit; this is that answer turned into a
// lookup. A packet arriving on the interface carries an address and nothing else -- no name,
// no connection -- so this table is the only thing that can say which of several networks it
// was meant for, and it is the only place the translation between the two address spaces
// happens.
//
// The translation is a prefix substitution and nothing more: a network presented somewhere
// else keeps every host bit, so 10.1.2.3 on a network moved to 198.18.0.0/8-worth of space
// is reached at the same last three octets. Rewriting the host part as well would mean a
// user could not read an address off this machine and recognise it on the network it came
// from, which is the one thing that makes a moved network usable at all.

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/sellitus/app-tail/internal/spread"
)

// Mapping is where one connection's network sits on this machine.
type Mapping struct {
	// TunnelID is the connection that carries the network.
	TunnelID string
	// Members are the connections that carry it together, when more than one does. Each
	// flow is given one of them and keeps it; TunnelID is then whichever of them an
	// unkeyed lookup lands on, and nothing dials the entry as a whole.
	//
	// A network belongs to exactly one connection, so this is only ever set on the entry
	// for everything no network claims -- this machine's internet traffic.
	Members []string
	// Prefix is the network's own addresses, as the connection reports them.
	Prefix netip.Prefix
	// PresentedAs is the range this machine reaches it at. It is the zero value when the
	// network is reached at its own addresses, which is the ordinary case: only a network
	// whose addresses collide with another's has to move.
	PresentedAs netip.Prefix
}

// Blocked is the connection id of an entry nothing may leave through. No carrier is ever
// registered under it, so every flow the entry covers is refused.
//
// It exists so that "the connections carrying my internet traffic are all down" is a route
// that is still installed and a carrier that is absent, rather than a route that is not
// installed: the interface keeps claiming the traffic, and the traffic stops. Without it
// the same state is every request on this machine quietly going out over the ISP link,
// which is the one outcome choosing connections for internet traffic exists to prevent.
//
// The leading NUL is what keeps it apart from a real connection: an id is generated from
// an alphabet this byte is not in, so nothing a user can create collides with it.
const Blocked = "\x00blocked"

// Here is the range this machine reaches the network at, which is the network's own range
// unless it had to move.
func (m Mapping) Here() netip.Prefix {
	if m.PresentedAs.IsValid() {
		return m.PresentedAs
	}
	return m.Prefix
}

// Moved reports that this machine reaches the network somewhere other than its own
// addresses.
func (m Mapping) Moved() bool { return m.PresentedAs.IsValid() }

// Destination is one connection and the address to dial inside it.
type Destination struct {
	TunnelID string
	Addr     netip.Addr
}

// Table is the whole machine-side addressing: every network the interface carries, and
// which connection each address belongs to.
//
// It is immutable. Connections come and go, and a flow already being carried was decided
// against the table that was current when it started; replacing the table wholesale means a
// flow is never re-judged halfway through against addressing that changed under it.
type Table struct {
	entries []Mapping
}

// NewTable builds the lookup from a set of mappings, refusing one that cannot be carried
// out.
//
// A move to a range of a different size is refused rather than approximated: the
// substitution below preserves every host bit, so a /16 presented from a /24 would produce
// addresses outside the range this machine routes, and the flows would leave through the
// machine's own network instead. That is the wrong-network-right-address failure, arrived at
// by arithmetic.
func NewTable(mappings []Mapping) (*Table, error) {
	entries := make([]Mapping, 0, len(mappings))
	for _, m := range mappings {
		if len(m.Members) > 0 {
			m.Members = slices.Clone(m.Members)
			if m.TunnelID == "" {
				// The unkeyed answer, so a lookup with nothing to pin by still names one of
				// the connections carrying the range rather than none of them.
				m.TunnelID = spread.Pick(m.Members, 0)
			}
		}
		if m.TunnelID == "" {
			return nil, fmt.Errorf("the range %s is mapped to no connection", m.Prefix)
		}
		if !m.Prefix.IsValid() {
			return nil, fmt.Errorf("connection %s carries a range that is not an address range", m.TunnelID)
		}
		m.Prefix = m.Prefix.Masked()
		if m.PresentedAs.IsValid() {
			m.PresentedAs = m.PresentedAs.Masked()
			if m.PresentedAs.Bits() != m.Prefix.Bits() {
				return nil, fmt.Errorf("connection %s carries %s and would be reached at %s, "+
					"which is a different number of addresses", m.TunnelID, m.Prefix, m.PresentedAs)
			}
			if m.PresentedAs.Addr().Is4() != m.Prefix.Addr().Is4() {
				return nil, fmt.Errorf("connection %s carries %s and would be reached at %s, "+
					"which is the other kind of address", m.TunnelID, m.Prefix, m.PresentedAs)
			}
		}
		entries = append(entries, m)
	}
	// Narrowest first, so the lookup below can stop at its first hit. A connection carrying
	// both 10.0.0.0/8 and 10.1.0.0/16 has to be reached at the narrower of the two for an
	// address inside it, and two connections cannot overlap here at all -- Allocate moved
	// one of them before it got this far.
	slices.SortStableFunc(entries, func(a, b Mapping) int { return b.Here().Bits() - a.Here().Bits() })
	return &Table{entries: entries}, nil
}

// Lookup says which connection an address on this machine belongs to, and what to dial
// inside it.
//
// For a range several connections carry together this is the answer for the key nothing
// asked with, which is one of them and always the same one. A flow picks its own with
// Choose; this is for the callers that have no flow to speak for -- counting a refusal
// against the range's connection, and the tests that read the table back.
func (t *Table) Lookup(addr netip.Addr) (Destination, bool) { return t.Choose(addr, 0) }

// Choose says where a flow keyed by key goes, which is Lookup's answer for every range one
// connection carries.
//
// For a range several carry, the key decides, and it decides by rendezvous hashing rather
// than by an index into the list. That is the whole of why a member going away is survivable:
// with an index, losing one of five members would move four destinations in five to a
// different connection -- and every flow whose answer changed is cut -- so a single member
// dropping would cut every flow on the machine. Here only the destinations that were on the
// lost member move.
func (t *Table) Choose(addr netip.Addr, key uint64) (Destination, bool) {
	m, inside, ok := t.entryFor(addr)
	if !ok {
		return Destination{}, false
	}
	id := m.TunnelID
	if len(m.Members) > 0 {
		id = spread.Pick(m.Members, key)
	}
	return Destination{TunnelID: id, Addr: inside}, true
}

// Still reports that an answer already given still stands.
//
// For a range several connections carry, it asks whether the answer is still one of them
// rather than whether it is the one they would be given now. That is deliberate: a member
// that comes back must not move a flow that is already working, and re-deciding on every
// pass would cut live flows every time any connection changed.
func (t *Table) Still(addr netip.Addr, dest Destination) bool {
	m, inside, ok := t.entryFor(addr)
	if !ok || inside != dest.Addr {
		return false
	}
	if len(m.Members) > 0 {
		return slices.Contains(m.Members, dest.TunnelID)
	}
	return m.TunnelID == dest.TunnelID
}

// entryFor is the entry covering an address and the address to dial inside it.
func (t *Table) entryFor(addr netip.Addr) (Mapping, netip.Addr, bool) {
	if t == nil {
		return Mapping{}, netip.Addr{}, false
	}
	addr = addr.Unmap()
	for _, m := range t.entries {
		here := m.Here()
		if !here.Contains(addr) {
			continue
		}
		if !m.Moved() {
			return m, addr, true
		}
		inside, ok := remap(addr, here, m.Prefix)
		if !ok {
			continue
		}
		return m, inside, true
	}
	return Mapping{}, netip.Addr{}, false
}

// Present is the reverse: where this machine reaches an address that a connection's own
// network calls by another name.
//
// It is what a name lookup is answered with. A resolver inside a moved network answers with
// the network's own address, and handing that to a program on this machine would send it to
// whichever other network holds those addresses -- so the answer is translated on the way
// out, exactly as the packets are.
func (t *Table) Present(tunnelID string, addr netip.Addr) (netip.Addr, bool) {
	if t == nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	for _, m := range t.entries {
		if m.TunnelID != tunnelID || !m.Prefix.Contains(addr) {
			continue
		}
		if !m.Moved() {
			return addr, true
		}
		return remap(addr, m.Prefix, m.PresentedAs)
	}
	return netip.Addr{}, false
}

// Routes are the ranges the interface carries, which is what this machine's routing table
// has to point at it for any of this to be reached at all.
func (t *Table) Routes() []netip.Prefix {
	if t == nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(t.entries))
	for _, m := range t.entries {
		here := m.Here()
		if !slices.Contains(out, here) {
			out = append(out, here)
		}
	}
	return out
}

// Mappings are the entries this table was built from, narrowest range first.
func (t *Table) Mappings() []Mapping {
	if t == nil {
		return nil
	}
	return slices.Clone(t.entries)
}

// remap moves an address from one range to another of the same size, keeping every bit
// below the prefix. It reports false for an address the source range does not contain,
// which is a caller that looked the address up against a different range than it translated
// it with.
func remap(addr netip.Addr, from, to netip.Prefix) (netip.Addr, bool) {
	if from.Bits() != to.Bits() || from.Addr().Is4() != to.Addr().Is4() {
		return netip.Addr{}, false
	}
	if !from.Contains(addr) {
		return netip.Addr{}, false
	}
	host := addr.AsSlice()
	network := to.Masked().Addr().AsSlice()
	if len(host) != len(network) {
		return netip.Addr{}, false
	}
	whole := to.Bits() / 8
	copy(host[:whole], network[:whole])
	// The byte the prefix ends inside, if it ends inside one: its high bits come from the
	// range being moved to and its low bits stay with the address.
	if spare := to.Bits() % 8; spare != 0 {
		mask := byte(0xff) << (8 - spare)
		host[whole] = (network[whole] & mask) | (host[whole] &^ mask)
	}
	out, ok := netip.AddrFromSlice(host)
	if !ok {
		return netip.Addr{}, false
	}
	return out.Unmap(), true
}

// MappingsOf is the addressing a plan produces.
//
// A network the plan found nowhere to move is returned separately rather than dropped: the
// interface carries nothing for it, and a network that is connected and unreachable with
// nothing anywhere saying so is the failure this whole module exists to prevent.
func MappingsOf(plan Plan) (mapped []Mapping, unreachable []Placement) {
	for _, placed := range plan.Placements {
		if placed.Moved() && !placed.PresentedAs.IsValid() {
			unreachable = append(unreachable, placed)
			continue
		}
		mapped = append(mapped, Mapping{
			TunnelID:    placed.TunnelID,
			Prefix:      placed.Prefix,
			PresentedAs: placed.PresentedAs,
		})
	}
	return mapped, unreachable
}
