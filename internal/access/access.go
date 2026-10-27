// SPDX-License-Identifier: MIT

// Package access decides whether one connection a local program asked for is carried.
//
// It is the permission half of a proxy instance: the instance owns a listener and a set
// of rules, and every dial it is asked to make comes through Decide first. The decision
// is a pure function of the rules and the request, so every arm is reachable in a test
// without a socket -- which is also what lets the dashboard ask "would this be allowed"
// and get the same answer a real dial would get, without dialling.
//
// The model is default-deny. An instance with no rules reaches nothing, and that is a
// state rather than a fault: the alternative reading, where an empty list means "carry
// everything", would make the least-configured instance the most powerful one.
package access

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ThisMachine is the tunnel sentinel for the machine app-tail is running on: its
// loopback, its LAN, and the internet beyond it. It is a value rather than an absence
// because an absent tunnel means "any tunnel", and reaching this machine is a grant an
// instance has to be given deliberately -- a proxy that can reach localhost can reach
// every other service the user is running.
const ThisMachine = "-"

// Action is what a matching rule does.
type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// Actions are every action a rule may carry, in the order a picker offers them.
var Actions = []Action{Allow, Deny}

// Protocol is the transport a rule covers. The empty value covers every transport,
// which is what a rule written about a service rather than about a wire means.
type Protocol string

const (
	AnyProtocol Protocol = ""
	TCP         Protocol = "tcp"
	UDP         Protocol = "udp"
)

// Protocols are every transport a rule may name, in the order a picker offers them.
var Protocols = []Protocol{AnyProtocol, TCP, UDP}

// Rule is one line of a proxy instance's permissions.
//
// Host and CIDR are two halves of one destination and both are matched when both are
// given: Host against the name the program asked for, CIDR against the address that name
// resolved to. That is deliberate rather than redundant -- a rule naming only a host
// carries whatever that name resolves to today, and a rule naming only a prefix carries
// whatever name points into it.
type Rule struct {
	ID string `json:"id"`
	// Action decides the request when this rule matches. Order is the meaning: the
	// first matching rule wins, so a deny placed above a broad allow is how an
	// exception is written.
	Action Action `json:"action"`
	// Tunnel is the connection this rule is about, by id. Empty means any connection;
	// ThisMachine means the machine app-tail runs on.
	Tunnel string `json:"tunnel,omitempty"`
	// Host is a label-anchored glob matched against what the program asked for, before
	// resolution. Empty matches any host.
	Host string `json:"host,omitempty"`
	// CIDR is matched against the resolved address. The zero prefix matches any address.
	CIDR netip.Prefix `json:"cidr,omitzero"`
	// Ports are single ports and inclusive ranges ("5432", "8000-8100"). An absent list
	// covers every port; a list that is present and empty is refused at validation,
	// because the two readings of it are opposites.
	Ports    []string `json:"ports,omitempty"`
	Protocol Protocol `json:"protocol,omitempty"`
	// Note is the user's own words about why this rule exists, carried through to the
	// rules table and to the reason a decision reports.
	Note string `json:"note,omitempty"`
}

// Request is one connection a program asked a proxy instance to make.
type Request struct {
	// Host is exactly what the program asked for, with no resolution applied: a name, or
	// the text of an address literal.
	Host string
	// Addr is what Host resolved to, and it is the address that will actually be dialled.
	// Matching the resolved address and then dialling that same address is what keeps a
	// second lookup from resolving in the permissive direction.
	Addr netip.Addr
	Port uint16
	// Protocol is the transport of the connection. AnyProtocol is not a request: a real
	// connection has a transport, and a request that left it out would match a rule
	// written about TCP alone.
	Protocol Protocol
	// Tunnel is which connection carries Addr, by id, or ThisMachine when the address is
	// reachable without any of them.
	Tunnel string
}

// Decision is whether a request is carried and which rule decided it.
//
// The rule is named because rule order is the whole difficulty of a permission model:
// "allowed" without "by which line" leaves a user editing rules and guessing which one
// they are actually changing.
type Decision struct {
	Allowed bool
	// Rule is the id of the rule that decided, empty when nothing matched.
	Rule string
	// Index is the rule's position in the list, or -1 when nothing matched.
	Index  int
	Reason string
}

// Decide answers whether the request is carried.
//
// The first matching rule decides, and a request no rule matches is refused. That
// terminal deny is not a rule anyone can edit or reorder: it is what makes the list a
// grant of access rather than a list of exceptions to unrestricted access.
func Decide(rules []Rule, req Request) Decision {
	for i, r := range rules {
		if !r.matches(req) {
			continue
		}
		return Decision{
			Allowed: r.Action == Allow,
			Rule:    r.ID,
			Index:   i,
			Reason:  fmt.Sprintf("rule %d %s", i+1, r.Describe()),
		}
	}
	return Decision{
		Index:  -1,
		Reason: "no rule covers this, and this proxy carries only what a rule allows",
	}
}

// SameRules reports whether two rule lists would decide every request identically.
//
// Order is part of the answer, because order is semantics here: the same rules in a
// different order are a different permission set. A caller uses this to know whether a
// reconcile actually changed what an instance carries, which is what decides whether
// connections opened under the old rules may be reused.
func SameRules(a, b []Rule) bool {
	return slices.EqualFunc(a, b, func(x, y Rule) bool {
		return x.ID == y.ID &&
			x.Action == y.Action &&
			x.Tunnel == y.Tunnel &&
			x.Host == y.Host &&
			x.CIDR == y.CIDR &&
			x.Protocol == y.Protocol &&
			slices.Equal(x.Ports, y.Ports)
	})
}

// matches reports whether every condition this rule states holds for the request. A
// condition the rule left out is not a condition, so a rule with nothing set matches
// everything -- which is how "allow this connection entirely" is written.
func (r Rule) matches(req Request) bool {
	if r.Tunnel != "" && r.Tunnel != req.Tunnel {
		return false
	}
	if r.Protocol != AnyProtocol && r.Protocol != req.Protocol {
		return false
	}
	if r.Host != "" && !MatchHost(r.Host, req.Host) {
		return false
	}
	if r.CIDR.IsValid() && !prefixHolds(r.CIDR, req.Addr) {
		return false
	}
	return matchPorts(r.Ports, req.Port)
}

// prefixHolds reports that an address sits inside a prefix, treating an IPv4-mapped IPv6
// address as the IPv4 address it stands for. A resolver that answered ::ffff:10.0.0.5
// would otherwise slip past a rule naming 10.0.0.0/8 -- the same address, refused or
// carried depending on which form the lookup happened to return.
func prefixHolds(p netip.Prefix, addr netip.Addr) bool {
	return p.Contains(addr.Unmap())
}

// matchPorts reports whether a port is covered. An empty list covers every port; the
// list is validated as non-empty-when-present, so an empty one here is an absent one.
func matchPorts(specs []string, port uint16) bool {
	if len(specs) == 0 {
		return true
	}
	for _, spec := range specs {
		low, high, err := ParsePorts(spec)
		if err != nil {
			// Validation refuses a rule that cannot be parsed, so this is a stored
			// document edited past it. Refusing the port is the safe reading: a rule
			// nobody can parse must not be the one that grants access.
			continue
		}
		if port >= low && port <= high {
			return true
		}
	}
	return false
}

// ParsePorts reads one port specification into the inclusive range it stands for.
func ParsePorts(spec string) (low, high uint16, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, errors.New("a port is missing")
	}
	first, second, isRange := strings.Cut(spec, "-")
	low, err = parsePort(first)
	if err != nil {
		return 0, 0, err
	}
	if !isRange {
		return low, low, nil
	}
	high, err = parsePort(second)
	if err != nil {
		return 0, 0, err
	}
	if high < low {
		return 0, 0, fmt.Errorf("the range %q ends before it starts", spec)
	}
	return low, high, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number", s)
	}
	// Zero is not a port a connection can be made to; it means "any free port" to a
	// listener, and a rule granting it would grant nothing while looking like a grant.
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d is outside 1-65535", n)
	}
	return uint16(n), nil
}

// MatchHost reports whether a name is covered by a label-anchored glob.
//
// Anchored at both ends, so "corp.internal" covers that name and nothing else. Within a
// label "*" stands for any run of characters, so "db-*.corp.internal" covers "db-1" and
// not "db.1". A leading "**" stands for one or more whole labels, matching the way a
// wildcard certificate reads: "**.corp.internal" covers "db.corp.internal" and
// "db.eu.corp.internal", and not the bare "corp.internal" -- an apex is granted by
// naming it, never by a wildcard that was written about what sits under it.
//
// Globs only. A regular expression in a permission rule is a rule nobody can read back.
func MatchHost(pattern, name string) bool {
	pat := strings.Split(normalizeHost(pattern), ".")
	got := strings.Split(normalizeHost(name), ".")
	if len(pat) > 0 && pat[0] == "**" {
		rest := pat[1:]
		// One or more leading labels, so the name must be strictly longer than what
		// follows the wildcard.
		if len(got) <= len(rest) {
			return false
		}
		got = got[len(got)-len(rest):]
		pat = rest
	}
	if len(pat) != len(got) {
		return false
	}
	for i := range pat {
		if !matchLabel(pat[i], got[i]) {
			return false
		}
	}
	return true
}

// normalizeHost lowercases a name and strips the trailing dot a fully-qualified one
// carries, so a rule and a request written in different conventions are one name.
func normalizeHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// matchLabel matches one label against a pattern in which "*" stands for any run of
// characters, including none.
func matchLabel(pattern, label string) bool {
	if pattern == "*" {
		// A whole label of wildcard still has to be a label: "*.corp.internal" covering
		// an empty label would make "..corp.internal" a match.
		return label != ""
	}
	if !strings.Contains(pattern, "*") {
		return pattern == label
	}

	// Greedy scan with one backtrack point, which is all a single wildcard class needs:
	// on a mismatch the last "*" gives up one more character to the label.
	var (
		p, l         int
		star         = -1
		afterStarPos int
	)
	for l < len(label) {
		switch {
		case p < len(pattern) && (pattern[p] == label[l]):
			p, l = p+1, l+1
		case p < len(pattern) && pattern[p] == '*':
			star, afterStarPos = p, l
			p++
		case star >= 0:
			afterStarPos++
			p, l = star+1, afterStarPos
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// Describe is the rule as one sentence, which is what a decision reports and what the
// rules table reads back. It names only the conditions the rule actually states, because
// a sentence listing "any protocol to any host on any port" for a rule about one port is
// a sentence a user has to decode rather than read.
func (r Rule) Describe() string { return r.DescribeWith(nil) }

// DescribeWith is the same sentence with the connection named as a person calls it. The
// lookup turns a connection id into a name; one that returns "" for an id, or a nil lookup,
// leaves the id in place -- which is the honest reading for a rule naming a connection the
// document no longer holds.
//
// It exists because a rule stores an id and nobody recognises an id: a grants list reading
// "over tn_a1b2c3" is a list that has to be decoded rather than read.
func (r Rule) DescribeWith(name func(id string) string) string {
	var b strings.Builder
	if r.Action == Deny {
		b.WriteString("refuses ")
	} else {
		b.WriteString("allows ")
	}
	if r.Protocol != AnyProtocol {
		b.WriteString(string(r.Protocol))
		b.WriteString(" ")
	}
	switch {
	case len(r.Ports) == 0:
		b.WriteString("any port")
	case len(r.Ports) == 1:
		b.WriteString("port " + r.Ports[0])
	default:
		b.WriteString("ports " + strings.Join(r.Ports, ", "))
	}
	switch {
	case r.Host != "" && r.CIDR.IsValid():
		b.WriteString(" on " + r.Host + " within " + r.CIDR.String())
	case r.Host != "":
		b.WriteString(" on " + r.Host)
	case r.CIDR.IsValid():
		b.WriteString(" within " + r.CIDR.String())
	default:
		b.WriteString(" anywhere")
	}
	switch r.Tunnel {
	case "":
		b.WriteString(", over any connection")
	case ThisMachine:
		b.WriteString(", on this machine")
	default:
		named := r.Tunnel
		if name != nil {
			if called := name(r.Tunnel); called != "" {
				named = called
			}
		}
		b.WriteString(", over " + named)
	}
	return b.String()
}
