// SPDX-License-Identifier: MIT

// Package routing decides which connection this machine's traffic to one destination
// leaves through.
//
// It is the per-destination half of the egress setting. That setting is one answer for
// everything this machine reaches that no private network carries; these rules are the
// exceptions to it -- send everything under a company's domain through one connection,
// keep a bank direct, refuse a range outright -- and a destination no rule names still
// leaves the way the setting says.
//
// The model is therefore fall-through, not default-deny: an empty list changes nothing,
// which is the opposite of internal/access, where an empty list carries nothing. The two
// answer different questions. Access asks whether a program may reach a destination at
// all; this asks which way an already-permitted destination goes.
//
// Decide is a pure function of the rules and the request, so the dashboard can ask "which
// way would this go" and get the answer a real dial would get, without dialling.
package routing

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/sellitus/app-tail/internal/access"
)

// ThisMachine is what a rule sending traffic out of this machine's own network resolves
// to, and is the same sentinel an access rule uses for the machine app-tail runs on.
const ThisMachine = access.ThisMachine

// Action is what a matching rule does with the destination.
type Action string

const (
	// Via sends the destination through the connection the rule names.
	Via Action = "via"
	// Direct sends it out of this machine's own network, even while an egress connection
	// is set. It is the exception a rule exists to write: a bank that refuses a foreign
	// address, a work service that only answers the office IP.
	Direct Action = "direct"
	// Block refuses the destination outright, on every surface. Nothing is dialled and no
	// name is looked up, so a blocked destination leaks neither traffic nor the query.
	Block Action = "block"
)

// Actions are every action a rule may carry, in the order a picker offers them.
var Actions = []Action{Via, Direct, Block}

// Rule is one line of the routing table the user writes.
//
// Host and CIDR are two halves of one destination and both are matched when both are
// given: Host against the name that was asked for, CIDR against the address it resolved
// to. A rule must state at least one of them -- a rule that stated neither would cover
// every destination, which is the egress setting rather than an exception to it.
type Rule struct {
	ID string `json:"id"`
	// Action decides the destination when this rule matches. Order is the meaning: the
	// first matching rule wins, so a narrow exception belongs above the broad rule it is
	// an exception to.
	Action Action `json:"action"`
	// Tunnel is the connection to send the destination through, by id. It is required by
	// Via and meaningless to the other two actions.
	Tunnel string `json:"tunnel,omitempty"`
	// Host is a label-anchored glob matched against the name that was asked for, in the
	// same pattern language an access rule uses. Empty states no condition on the name.
	//
	// A name is only known where something resolved one. On the interface a rule about a
	// host cannot apply, because a packet arriving there carries an address and nothing
	// else -- see Prefixes.
	Host string `json:"host,omitempty"`
	// CIDR is matched against the address. The zero prefix states no condition on it.
	CIDR netip.Prefix `json:"cidr,omitzero"`
	// Note is the user's own words about why this rule exists, carried through to the
	// table and to the reason a decision reports.
	Note string `json:"note,omitempty"`
}

// Request is one destination being routed.
type Request struct {
	// Host is the name that was asked for, empty when there was none -- an address
	// literal, or a packet on the interface.
	Host string
	// Addr is the address the destination is at, invalid when nothing has resolved it yet.
	Addr netip.Addr
}

// Decision is which way a destination goes and which rule said so.
//
// Decided separates "a rule sends this out of this machine" from "no rule covered it", two
// states that both leave through this machine's own network today and mean opposite things
// the moment an egress connection is chosen.
type Decision struct {
	// Decided reports that a rule matched. When it is false every other field is zero and
	// the caller routes the destination the way it would with no rules at all.
	Decided bool
	Action  Action
	// Tunnel is the connection to send it through, set only for Via.
	Tunnel string
	// Rule is the id of the rule that decided, and Index its position in the list, -1 when
	// nothing matched. Naming the line is what makes a routing table one a person can edit
	// rather than one they have to experiment against.
	Index  int
	Rule   string
	Reason string
}

// Decide says which way a destination goes.
//
// The first matching rule decides. A destination no rule matches is not decided here at
// all: it leaves whichever way the egress setting says, which is what makes these rules
// exceptions rather than a replacement for it.
func Decide(rules []Rule, req Request) Decision {
	for i, r := range rules {
		if !r.matches(req) {
			continue
		}
		return Decision{
			Decided: true,
			Action:  r.Action,
			Tunnel:  r.Tunnel,
			Index:   i,
			Rule:    r.ID,
			Reason:  fmt.Sprintf("rule %d %s", i+1, r.Describe()),
		}
	}
	return Decision{Index: -1}
}

// matches reports whether every condition this rule states holds. A condition the rule
// left out is not a condition; validation refuses a rule that states neither, so nothing
// here matches everything.
func (r Rule) matches(req Request) bool {
	if r.Host != "" && !access.MatchHost(r.Host, req.Host) {
		return false
	}
	if r.CIDR.IsValid() && !r.CIDR.Contains(req.Addr.Unmap()) {
		return false
	}
	return true
}

// SameRules reports whether two lists would route every destination identically. Order is
// part of the answer, because order is the semantics: the same rules rearranged are a
// different table. A caller uses it to know whether a reconcile actually changed where
// traffic goes, which is what decides whether flows already carried may be left alone.
func SameRules(a, b []Rule) bool {
	return slices.EqualFunc(a, b, func(x, y Rule) bool {
		return x.ID == y.ID &&
			x.Action == y.Action &&
			x.Tunnel == y.Tunnel &&
			x.Host == y.Host &&
			x.CIDR == y.CIDR
	})
}

// Clone copies a rule list, so a stored document and a running registry never share the
// slice one of them is about to rewrite.
func Clone(in []Rule) []Rule {
	if in == nil {
		return nil
	}
	return slices.Clone(in)
}

// PrefixRoute is one rule reduced to what a routing table can carry: a range and where it
// goes. It is what the interface is programmed from.
type PrefixRoute struct {
	Prefix netip.Prefix
	Action Action
	Tunnel string
	// Rule is the id of the rule it came from, so a route on the interface can be traced
	// back to the line that put it there.
	Rule string
}

// Prefixes reduces the rules to the ranges an interface can be programmed with, in an
// order a longest-prefix-match table resolves the same way Decide does.
//
// Two things are dropped, and both are dropped because the interface cannot honour them:
//
// A rule that states a host is dropped entirely. A packet arriving on the interface
// carries an address and nothing else, so there is no name to match and a rule about one
// can only be applied where something resolved it -- the proxy, and the app's own
// resolver. This is a real limit of running as an interface rather than an oversight, and
// the surfaces say so rather than leaving such a rule looking like it applies.
//
// A range an earlier rule already covers is dropped, because the first matching rule wins
// here and longest-prefix wins in a routing table -- opposite answers for the same pair.
// Dropping the narrower later range makes the table agree with Decide. Two ranges are
// either disjoint or one contains the other, so there is no third case to get wrong.
func Prefixes(rules []Rule) []PrefixRoute {
	var out []PrefixRoute
	for _, r := range rules {
		if r.Host != "" || !r.CIDR.IsValid() {
			continue
		}
		prefix := r.CIDR.Masked()
		if slices.ContainsFunc(out, func(kept PrefixRoute) bool { return covers(kept.Prefix, prefix) }) {
			continue
		}
		out = append(out, PrefixRoute{Prefix: prefix, Action: r.Action, Tunnel: r.Tunnel, Rule: r.ID})
	}
	return out
}

// Shadowed is the ids of the rules Prefixes dropped for being covered by an earlier range,
// which is a rule that sits in the list looking like it applies and never does. The
// surfaces show it against the rule so the fix -- move it above the broader one -- is one
// the user can see, rather than one they arrive at by experiment.
//
// A rule dropped for stating a host is not shadowed: it applies wherever a name is known,
// and only the interface cannot honour it.
func Shadowed(rules []Rule) []string {
	var kept []netip.Prefix
	var out []string
	for _, r := range rules {
		if r.Host != "" || !r.CIDR.IsValid() {
			continue
		}
		prefix := r.CIDR.Masked()
		if slices.ContainsFunc(kept, func(k netip.Prefix) bool { return covers(k, prefix) }) {
			out = append(out, r.ID)
			continue
		}
		kept = append(kept, prefix)
	}
	return out
}

// covers reports that one range holds another whole, which for prefixes is the wider one
// containing the narrower one's first address.
func covers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// Describe is the rule as one sentence, which is what a decision reports and what the
// table reads back.
func (r Rule) Describe() string { return r.DescribeWith(nil) }

// DescribeWith is the same sentence with the connection named as a person calls it. The
// lookup turns a connection id into a name; one that returns "" for an id, or a nil
// lookup, leaves the id in place, which is the honest reading for a rule naming a
// connection the document no longer holds.
func (r Rule) DescribeWith(name func(id string) string) string {
	var b strings.Builder
	switch {
	case r.Host != "" && r.CIDR.IsValid():
		b.WriteString(r.Host + " within " + r.CIDR.String())
	case r.Host != "":
		b.WriteString(r.Host)
	case r.CIDR.IsValid():
		b.WriteString(r.CIDR.String())
	default:
		// Validation refuses this shape, so it is a document edited past it. Saying so
		// beats a sentence that reads as though the rule covers one thing.
		b.WriteString("a destination it does not name")
	}
	switch r.Action {
	case Direct:
		b.WriteString(" goes out of this machine's own network")
	case Block:
		b.WriteString(" is refused")
	case Via:
		named := r.Tunnel
		if name != nil {
			if called := name(r.Tunnel); called != "" {
				named = called
			}
		}
		b.WriteString(" goes through " + named)
	default:
		b.WriteString(" is routed by an action this build does not know")
	}
	return b.String()
}
