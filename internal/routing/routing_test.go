// SPDX-License-Identifier: MIT

package routing

import (
	"net/netip"
	"strings"
	"testing"
)

func via(id, host, tunnel string) Rule {
	return Rule{ID: id, Action: Via, Host: host, Tunnel: tunnel}
}

func within(id, cidr string, action Action, tunnel string) Rule {
	return Rule{ID: id, Action: action, CIDR: netip.MustParsePrefix(cidr), Tunnel: tunnel}
}

func at(host, addr string) Request {
	req := Request{Host: host}
	if addr != "" {
		req.Addr = netip.MustParseAddr(addr)
	}
	return req
}

// The whole model rests on this: rules are exceptions to the egress setting, so a
// destination none of them names is not decided here at all. The opposite reading -- an
// empty list meaning "everything is refused", the way an empty access list does -- would
// stop the machine reaching anything the moment the feature was switched on.
func TestADestinationNoRuleNamesIsLeftToTheEgressSetting(t *testing.T) {
	rules := []Rule{via("r1", "**.corp.example", "tn_office")}

	got := Decide(rules, at("news.example.com", "93.184.216.34"))

	if got.Decided {
		t.Fatalf("a destination no rule names was decided here: %+v", got)
	}
	if got.Index != -1 || got.Tunnel != "" || got.Action != "" {
		t.Errorf("decision = %+v, want an entirely empty answer", got)
	}
}

func TestAnEmptyTableDecidesNothing(t *testing.T) {
	if got := Decide(nil, at("anything.example", "1.1.1.1")); got.Decided {
		t.Fatalf("an empty table decided a destination: %+v", got)
	}
}

// Order is the meaning of the list: a narrow exception above a broad rule is how every
// exception in this model is written.
func TestTheFirstMatchingRuleDecides(t *testing.T) {
	rules := []Rule{
		{ID: "bank", Action: Direct, Host: "bank.example"},
		via("everything-else", "**.example", "tn_vpn"),
	}

	got := Decide(rules, at("bank.example", "203.0.113.9"))

	if !got.Decided || got.Action != Direct {
		t.Fatalf("decision = %+v, want the direct rule above the broad one to win", got)
	}
	if got.Rule != "bank" || got.Index != 0 {
		t.Errorf("decision named rule %q at %d, want bank at 0", got.Rule, got.Index)
	}
	if !strings.Contains(got.Reason, "out of this machine") {
		t.Errorf("reason = %q, want it to say where the traffic goes", got.Reason)
	}
}

// The reason has to name the line, because rule order is the whole difficulty of a
// routing table: "goes through the VPN" without "by which line" leaves a user editing
// rules and guessing which one they are changing.
func TestTheReasonNamesThePositionInTheList(t *testing.T) {
	rules := []Rule{
		{ID: "first", Action: Direct, Host: "a.example"},
		via("second", "b.example", "tn_vpn"),
	}

	got := Decide(rules, at("b.example", "198.51.100.7"))

	if !strings.HasPrefix(got.Reason, "rule 2 ") {
		t.Errorf("reason = %q, want it to start by naming rule 2", got.Reason)
	}
}

// A packet on the interface carries an address and no name. A rule about a host must not
// match it: doing so would make one rule about a company's domain quietly capture every
// destination the machine reaches in interface mode.
func TestARuleAboutAHostDoesNotMatchADestinationWithNoName(t *testing.T) {
	rules := []Rule{via("r1", "**.corp.example", "tn_office")}

	if got := Decide(rules, at("", "10.9.9.9")); got.Decided {
		t.Fatalf("a host rule matched a nameless destination: %+v", got)
	}
}

// The two halves are conditions, both of which must hold. A rule naming a host inside a
// range is how "this name, but only when it resolves where I expect" is written.
func TestARuleStatingBothAHostAndARangeNeedsBoth(t *testing.T) {
	rules := []Rule{{
		ID: "r1", Action: Via, Tunnel: "tn_office",
		Host: "db.corp.example", CIDR: netip.MustParsePrefix("10.0.0.0/8"),
	}}

	tests := []struct {
		name    string
		req     Request
		decided bool
	}{
		{"both hold", at("db.corp.example", "10.0.0.5"), true},
		{"the name is right and the address is not", at("db.corp.example", "93.184.216.34"), false},
		{"the address is right and the name is not", at("www.example.com", "10.0.0.5"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(rules, tt.req); got.Decided != tt.decided {
				t.Fatalf("decided = %v, want %v (%+v)", got.Decided, tt.decided, got)
			}
		})
	}
}

// A resolver that answered ::ffff:10.0.0.5 would otherwise slip past a rule naming
// 10.0.0.0/8 -- the same address routed two different ways depending on which form the
// lookup happened to return.
func TestAnIPv4AddressWrittenAsIPv6IsStillInsideAnIPv4Range(t *testing.T) {
	rules := []Rule{within("r1", "10.0.0.0/8", Direct, "")}

	got := Decide(rules, Request{Addr: netip.MustParseAddr("::ffff:10.0.0.5")})

	if !got.Decided || got.Action != Direct {
		t.Fatalf("decision = %+v, want the v4 range to hold the mapped address", got)
	}
}

// A blocked destination is a decision like any other, and the surfaces above turn it into
// a refusal. Reading it as "no rule matched" would send the traffic out instead.
func TestABlockingRuleDecidesRatherThanFallingThrough(t *testing.T) {
	rules := []Rule{within("no-telemetry", "192.0.2.0/24", Block, "")}

	got := Decide(rules, at("", "192.0.2.44"))

	if !got.Decided || got.Action != Block {
		t.Fatalf("decision = %+v, want a block", got)
	}
	if got.Tunnel != "" {
		t.Errorf("a block named the connection %q", got.Tunnel)
	}
}

// Prefixes is what the interface is programmed from, so a rule that cannot be honoured
// there has to be left out rather than approximated into a range it never stated.
func TestOnlyRangesReachTheInterface(t *testing.T) {
	rules := []Rule{
		via("by-name", "**.corp.example", "tn_office"),
		within("by-range", "10.0.0.0/8", Via, "tn_office"),
		{ID: "both", Action: Direct, Host: "db.corp.example", CIDR: netip.MustParsePrefix("172.16.0.0/12")},
	}

	got := Prefixes(rules)

	if len(got) != 1 {
		t.Fatalf("Prefixes returned %d entries (%+v), want only the range-only rule", len(got), got)
	}
	if got[0].Rule != "by-range" || got[0].Prefix.String() != "10.0.0.0/8" || got[0].Tunnel != "tn_office" {
		t.Errorf("entry = %+v, want the by-range rule", got[0])
	}
}

// First match wins here and longest prefix wins in a routing table: opposite answers for
// the same pair. Dropping the narrower later range is what makes the interface agree with
// Decide, and without it a rule the user wrote second would silently override the one they
// wrote first.
func TestARangeAnEarlierRuleAlreadyCoversNeverReachesTheInterface(t *testing.T) {
	rules := []Rule{
		within("broad", "10.0.0.0/8", Via, "tn_office"),
		within("narrow", "10.1.0.0/16", Direct, ""),
	}

	got := Prefixes(rules)

	if len(got) != 1 || got[0].Rule != "broad" {
		t.Fatalf("Prefixes = %+v, want only the broad rule that decides first", got)
	}
	if shadowed := Shadowed(rules); len(shadowed) != 1 || shadowed[0] != "narrow" {
		t.Errorf("Shadowed = %v, want the narrow rule reported so the user can move it", shadowed)
	}
	// The same pair the other way round is the order that works, and neither is shadowed.
	both := Prefixes([]Rule{rules[1], rules[0]})
	if len(both) != 2 {
		t.Errorf("with the narrow rule first, Prefixes = %+v, want both ranges", both)
	}
	if shadowed := Shadowed([]Rule{rules[1], rules[0]}); len(shadowed) != 0 {
		t.Errorf("Shadowed = %v, want nothing shadowed in the order that works", shadowed)
	}
}

// A rule left out for stating a host still applies wherever a name is known, so calling it
// shadowed would send the user to reorder a list that is already right.
func TestARuleAboutAHostIsNotReportedAsShadowed(t *testing.T) {
	rules := []Rule{
		within("broad", "10.0.0.0/8", Via, "tn_office"),
		{ID: "named", Action: Direct, Host: "db.corp.example"},
	}

	if got := Shadowed(rules); len(got) != 0 {
		t.Errorf("Shadowed = %v, want nothing: a host rule applies where names are known", got)
	}
}

// Two ranges are either disjoint or one holds the other, so disjoint ranges must both
// survive however they are ordered.
func TestDisjointRangesAllReachTheInterface(t *testing.T) {
	rules := []Rule{
		within("a", "10.0.0.0/8", Via, "tn_a"),
		within("b", "172.16.0.0/12", Via, "tn_b"),
		within("c", "2001:db8::/32", Block, ""),
	}

	if got := Prefixes(rules); len(got) != 3 {
		t.Fatalf("Prefixes = %+v, want all three disjoint ranges", got)
	}
}

// Order is semantics, so a reconcile that reordered the list has changed where traffic
// goes and the surfaces above must treat it as a change.
func TestTheSameRulesInADifferentOrderAreADifferentTable(t *testing.T) {
	a := []Rule{via("r1", "a.example", "tn_a"), via("r2", "b.example", "tn_b")}
	b := []Rule{a[1], a[0]}

	if SameRules(a, b) {
		t.Error("SameRules called a reordered list the same table")
	}
	if !SameRules(a, Clone(a)) {
		t.Error("SameRules called a copy of a list a different table")
	}
}

func TestChangingWhereARuleSendsTrafficIsAChange(t *testing.T) {
	a := []Rule{via("r1", "a.example", "tn_a")}
	b := []Rule{via("r1", "a.example", "tn_b")}

	if SameRules(a, b) {
		t.Error("SameRules ignored the connection a rule points at")
	}
}

// A rule reads back as a sentence, and the connection in it has to be the name a person
// gave it: a table reading "goes through tn_a1b2c3" is one that must be decoded rather
// than read.
func TestARuleReadsBackAsASentenceNamingTheConnection(t *testing.T) {
	r := via("r1", "**.corp.example", "tn_a1b2c3")

	if got := r.Describe(); !strings.Contains(got, "tn_a1b2c3") {
		t.Errorf("Describe = %q, want the id when nothing can name it", got)
	}
	got := r.DescribeWith(func(id string) string {
		if id == "tn_a1b2c3" {
			return "Office"
		}
		return ""
	})
	if !strings.Contains(got, "Office") || strings.Contains(got, "tn_a1b2c3") {
		t.Errorf("DescribeWith = %q, want the connection's own name", got)
	}
	if !strings.Contains(got, "**.corp.example") {
		t.Errorf("DescribeWith = %q, want the destination it is about", got)
	}
}

func TestEachActionReadsBackDifferently(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		want string
	}{
		{"direct", Rule{ID: "r", Action: Direct, Host: "bank.example"}, "out of this machine"},
		{"block", within("r", "192.0.2.0/24", Block, ""), "refused"},
		{"via", via("r", "a.example", "tn_a"), "goes through tn_a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.Describe(); !strings.Contains(got, tt.want) {
				t.Errorf("Describe = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}
