// SPDX-License-Identifier: MIT

package access

import (
	"net/netip"
	"strings"
	"testing"
)

// req is a request that would be allowed by a rule naming nothing, so each test varies
// only the one thing it is about.
func req(host string, addr string, port uint16, tunnel string) Request {
	return Request{
		Host:     host,
		Addr:     netip.MustParseAddr(addr),
		Port:     port,
		Protocol: TCP,
		Tunnel:   tunnel,
	}
}

func rule(id string, mutate func(*Rule)) Rule {
	r := Rule{ID: id, Action: Allow}
	mutate(&r)
	return r
}

// The whole model rests on this: an instance nobody has written a rule for reaches
// nothing. The opposite reading -- an empty list meaning "everything" -- would make the
// least configured instance the most powerful one on the machine.
func TestAProxyWithNoRulesCarriesNothing(t *testing.T) {
	got := Decide(nil, req("db.corp.internal", "10.0.0.5", 5432, "tn_office"))

	if got.Allowed {
		t.Fatal("a proxy with no rules carried a connection")
	}
	if got.Index != -1 || got.Rule != "" {
		t.Errorf("decision = %+v, want no rule named", got)
	}
	if !strings.Contains(got.Reason, "only what a rule allows") {
		t.Errorf("reason = %q, want it to say why nothing was carried", got.Reason)
	}
}

// A request nothing in the list matches falls through to the same terminal refusal. The
// list is a grant of access, not a set of exceptions to unrestricted access.
func TestARequestNoRuleCoversIsRefused(t *testing.T) {
	rules := []Rule{rule("r1", func(r *Rule) { r.Tunnel = "tn_office"; r.Ports = []string{"5432"} })}

	got := Decide(rules, req("db.corp.internal", "10.0.0.5", 5433, "tn_office"))

	if got.Allowed {
		t.Fatalf("port 5433 was carried by a rule about 5432: %+v", got)
	}
}

// Order is the meaning of the list, so the first match has to be the one that decides --
// a deny written above a broad allow is how every exception in this model is expressed.
func TestTheFirstMatchingRuleDecides(t *testing.T) {
	rules := []Rule{
		rule("deny-admin", func(r *Rule) { r.Action = Deny; r.Ports = []string{"22"}; r.Tunnel = "tn_office" }),
		rule("allow-office", func(r *Rule) { r.Tunnel = "tn_office" }),
	}

	refused := Decide(rules, req("box.corp.internal", "10.0.0.5", 22, "tn_office"))
	carried := Decide(rules, req("box.corp.internal", "10.0.0.5", 5432, "tn_office"))

	if refused.Allowed {
		t.Errorf("the deny above the allow did not decide: %+v", refused)
	}
	if refused.Rule != "deny-admin" || refused.Index != 0 {
		t.Errorf("decision = %+v, want the first rule named", refused)
	}
	if !carried.Allowed || carried.Rule != "allow-office" {
		t.Errorf("decision = %+v, want the broad allow to carry the other port", carried)
	}
}

// Reordering the same two rules reverses the outcome. Asserted because it is the reason
// the list is a JSON array rather than a map, and the reason the table has up/down
// controls rather than sorting itself.
func TestReorderingTheSameRulesChangesTheAnswer(t *testing.T) {
	deny := rule("deny-admin", func(r *Rule) { r.Action = Deny; r.Ports = []string{"22"}; r.Tunnel = "tn_office" })
	allow := rule("allow-office", func(r *Rule) { r.Tunnel = "tn_office" })
	ssh := req("box.corp.internal", "10.0.0.5", 22, "tn_office")

	if Decide([]Rule{deny, allow}, ssh).Allowed {
		t.Error("deny first carried the connection")
	}
	if !Decide([]Rule{allow, deny}, ssh).Allowed {
		t.Error("allow first refused the connection")
	}
}

// Two instances with different rule sets, each provably refusing what the other allows.
// This is the shape the whole feature exists to deliver.
func TestTwoInstancesEachRefuseWhatTheOtherAllows(t *testing.T) {
	psql := []Rule{rule("r1", func(r *Rule) {
		r.Tunnel = "tn_office"
		r.CIDR = netip.MustParsePrefix("10.0.0.5/32")
		r.Ports = []string{"5432"}
	})}
	web := []Rule{rule("r1", func(r *Rule) {
		r.Tunnel = "tn_lab"
		r.Ports = []string{"443"}
	})}

	database := req("db.corp.internal", "10.0.0.5", 5432, "tn_office")
	site := req("wiki.lab.internal", "10.9.0.2", 443, "tn_lab")

	if !Decide(psql, database).Allowed || Decide(psql, site).Allowed {
		t.Error("the database instance did not carry exactly its own destination")
	}
	if !Decide(web, site).Allowed || Decide(web, database).Allowed {
		t.Error("the web instance did not carry exactly its own destination")
	}
}

// The narrow grant in full: one address, one port, one connection, and nothing else --
// not the neighbouring address, not the neighbouring port, not the same address reached
// over a different connection.
func TestAGrantOfOneServiceReachesNothingElse(t *testing.T) {
	rules := []Rule{rule("r1", func(r *Rule) {
		r.Tunnel = "tn_office"
		r.CIDR = netip.MustParsePrefix("10.0.0.5/32")
		r.Ports = []string{"5432"}
	})}

	cases := []struct {
		name    string
		request Request
		want    bool
	}{
		{"the granted service", req("db.corp.internal", "10.0.0.5", 5432, "tn_office"), true},
		{"the next address along", req("web.corp.internal", "10.0.0.6", 5432, "tn_office"), false},
		{"the next port along", req("db.corp.internal", "10.0.0.5", 5433, "tn_office"), false},
		{"the same address on another connection", req("db.lab.internal", "10.0.0.5", 5432, "tn_lab"), false},
		{"this machine's own loopback", req("localhost", "127.0.0.1", 5432, ThisMachine), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(rules, tc.request); got.Allowed != tc.want {
				t.Errorf("allowed = %v, want %v (%s)", got.Allowed, tc.want, got.Reason)
			}
		})
	}
}

// Reaching localhost is a grant of its own. A proxy that could reach this machine could
// reach every other service the user has running, including app-tail's own API.
func TestThisMachineIsReachedOnlyByARuleThatNamesIt(t *testing.T) {
	anyTunnel := []Rule{rule("r1", func(r *Rule) { r.Ports = []string{"5432"} })}
	named := []Rule{rule("r1", func(r *Rule) { r.Tunnel = ThisMachine; r.Ports = []string{"5432"} })}
	local := req("localhost", "127.0.0.1", 5432, ThisMachine)

	// A rule with no connection named covers every connection, and this machine is one of
	// them: the sentinel is a value, so "any" includes it.
	if !Decide(anyTunnel, local).Allowed {
		t.Error("a rule about any connection refused this machine")
	}
	if !Decide(named, local).Allowed {
		t.Error("a rule naming this machine refused it")
	}
	if Decide(named, req("db.corp.internal", "10.0.0.5", 5432, "tn_office")).Allowed {
		t.Error("a rule naming this machine carried a connection over a tunnel")
	}
}

// Host is matched against what was asked for and CIDR against what it resolved to, and
// both have to hold. A name that resolves outside the prefix is the case the pair exists
// for: without it, whoever controls the name controls where the connection goes.
func TestAHostAndAnAddressAreBothConditions(t *testing.T) {
	rules := []Rule{rule("r1", func(r *Rule) {
		r.Host = "db.corp.internal"
		r.CIDR = netip.MustParsePrefix("10.0.0.0/8")
	})}

	if !Decide(rules, req("db.corp.internal", "10.0.0.5", 5432, "tn_office")).Allowed {
		t.Error("the name and the address both matched and the rule refused")
	}
	if Decide(rules, req("db.corp.internal", "192.0.2.5", 5432, "tn_office")).Allowed {
		t.Error("the name matched but resolved outside the prefix, and the rule carried it")
	}
	if Decide(rules, req("other.corp.internal", "10.0.0.5", 5432, "tn_office")).Allowed {
		t.Error("the address matched but the name did not, and the rule carried it")
	}
}

// A resolver answering in IPv4-mapped IPv6 form returns the same address in a different
// spelling. A rule naming 10.0.0.0/8 has to hold for both, or which form the lookup
// happened to return decides whether the connection is carried.
func TestAnAddressWrittenTheOtherWayIsTheSameAddress(t *testing.T) {
	rules := []Rule{rule("r1", func(r *Rule) { r.CIDR = netip.MustParsePrefix("10.0.0.0/8") })}

	mapped := Request{
		Host:     "db.corp.internal",
		Addr:     netip.MustParseAddr("::ffff:10.0.0.5"),
		Port:     5432,
		Protocol: TCP,
		Tunnel:   "tn_office",
	}

	if !Decide(rules, mapped).Allowed {
		t.Error("an IPv4-mapped address slipped past a rule naming its own prefix")
	}
}

func TestARuleAboutOneTransportLeavesTheOtherAlone(t *testing.T) {
	rules := []Rule{rule("r1", func(r *Rule) { r.Protocol = UDP; r.Ports = []string{"53"} })}

	dns := req("resolver.corp.internal", "10.0.0.1", 53, "tn_office")
	dns.Protocol = UDP
	overTCP := req("resolver.corp.internal", "10.0.0.1", 53, "tn_office")

	if !Decide(rules, dns).Allowed {
		t.Error("a UDP rule refused a UDP request")
	}
	if Decide(rules, overTCP).Allowed {
		t.Error("a UDP rule carried a TCP request")
	}
}

func TestAPortRangeCoversItsEndsAndNothingBeyondThem(t *testing.T) {
	rules := []Rule{rule("r1", func(r *Rule) { r.Tunnel = "tn_office"; r.Ports = []string{"8000-8100", "443"} })}

	cases := []struct {
		port uint16
		want bool
	}{{7999, false}, {8000, true}, {8050, true}, {8100, true}, {8101, false}, {443, true}}
	for _, tc := range cases {
		got := Decide(rules, req("app.corp.internal", "10.0.0.5", tc.port, "tn_office"))
		if got.Allowed != tc.want {
			t.Errorf("port %d allowed = %v, want %v", tc.port, got.Allowed, tc.want)
		}
	}
}

// A rule the validator would refuse can still be reached by hand-editing the stored
// document. Its port list must not be the thing that grants access.
func TestAPortNobodyCanParseGrantsNothing(t *testing.T) {
	rules := []Rule{rule("r1", func(r *Rule) { r.Tunnel = "tn_office"; r.Ports = []string{"five thousand"} })}

	if Decide(rules, req("db.corp.internal", "10.0.0.5", 5000, "tn_office")).Allowed {
		t.Error("a port specification nothing can read was treated as a grant")
	}
}

func TestAHostGlobMatchesByLabel(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"corp.internal", "corp.internal", true},
		{"corp.internal", "db.corp.internal", false},
		{"corp.internal", "notcorp.internal", false},
		{"*.corp.internal", "db.corp.internal", true},
		{"*.corp.internal", "db.eu.corp.internal", false},
		{"*.corp.internal", "corp.internal", false},
		{"**.corp.internal", "db.corp.internal", true},
		{"**.corp.internal", "db.eu.corp.internal", true},
		{"**.corp.internal", "corp.internal", false},
		{"db-*.corp.internal", "db-1.corp.internal", true},
		{"db-*.corp.internal", "db-primary.corp.internal", true},
		{"db-*.corp.internal", "db.1.corp.internal", false},
		{"db-*.corp.internal", "web-1.corp.internal", false},
		// A star at the end of a label matches the empty rest of it, so a prefix pattern
		// covers the bare name it was written for and not the label beside it.
		{"db*.corp.internal", "db.corp.internal", true},
		{"db*.corp.internal", "web.corp.internal", false},
		{"DB.Corp.Internal", "db.corp.internal", true},
		{"db.corp.internal", "db.corp.internal.", true},
		{"10.0.0.5", "10.0.0.5", true},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+" vs "+tc.name, func(t *testing.T) {
			if got := MatchHost(tc.pattern, tc.name); got != tc.want {
				t.Errorf("MatchHost(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
			}
		})
	}
}

// A port specification is read by the validator that refuses a rule and by the matcher
// that carries one, so every shape it can be wrong in has to come back as an error rather
// than as a range. A silent zero here is a rule that grants a port nobody asked for.
func TestAPortSpecificationIsReadOrRefused(t *testing.T) {
	cases := []struct {
		spec      string
		low, high uint16
		wantErr   string
	}{
		{spec: "5432", low: 5432, high: 5432},
		{spec: " 8000-8100 ", low: 8000, high: 8100},
		{spec: "", wantErr: "a port is missing"},
		{spec: "   ", wantErr: "a port is missing"},
		{spec: "8000-", wantErr: "port"},
		{spec: "8000-abc", wantErr: "port"},
		{spec: "8100-8000", wantErr: "ends before it starts"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			low, high, err := ParsePorts(tc.spec)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParsePorts(%q) = %d-%d, want an error", tc.spec, low, high)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
				}
				if low != 0 || high != 0 {
					t.Errorf("a refused specification still returned %d-%d", low, high)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePorts(%q): %v", tc.spec, err)
			}
			if low != tc.low || high != tc.high {
				t.Errorf("ParsePorts(%q) = %d-%d, want %d-%d", tc.spec, low, high, tc.low, tc.high)
			}
		})
	}
}

// The sentence is what a decision reports and what the rules table reads back, so it has
// to name what the rule actually says and leave out what it does not.
func TestARuleReadsBackAsASentence(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want []string
	}{
		{
			"one service on one connection",
			rule("r1", func(r *Rule) {
				r.Tunnel = "tn_office"
				r.Host = "db.corp.internal"
				r.Ports = []string{"5432"}
				r.Protocol = TCP
			}),
			[]string{"allows", "tcp", "port 5432", "db.corp.internal", "tn_office"},
		},
		{
			"a whole connection",
			rule("r2", func(r *Rule) { r.Tunnel = "tn_office" }),
			[]string{"allows", "any port", "anywhere", "tn_office"},
		},
		{
			"a refusal on this machine",
			rule("r3", func(r *Rule) { r.Action = Deny; r.Tunnel = ThisMachine; r.Ports = []string{"22"} }),
			[]string{"refuses", "port 22", "this machine"},
		},
		{
			"an address range over any connection",
			rule("r4", func(r *Rule) { r.CIDR = netip.MustParsePrefix("10.0.0.0/8"); r.Ports = []string{"80", "443"} }),
			[]string{"ports 80, 443", "within 10.0.0.0/8", "any connection"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.rule.Describe()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("Describe() = %q, want it to carry %q", got, want)
				}
			}
		})
	}
}

// A connection id is not what anyone calls their network, so the sentence uses the name
// when a lookup has one. A lookup that does not know the id leaves it in place: naming a
// connection the document no longer holds as "" would read as a rule over no connection at
// all, which is the one thing an unmatched id does not mean.
func TestASentenceNamesTheConnectionWhenItCan(t *testing.T) {
	r := rule("r1", func(r *Rule) { r.Tunnel = "tn_office"; r.Ports = []string{"5432"} })
	name := func(id string) string {
		if id == "tn_office" {
			return "Office"
		}
		return ""
	}

	named := r.DescribeWith(name)
	if !strings.Contains(named, "over Office") {
		t.Errorf("DescribeWith = %q, want the connection named as a person calls it", named)
	}
	if strings.Contains(named, "tn_office") {
		t.Errorf("DescribeWith = %q, want the id replaced by the name", named)
	}

	gone := rule("r2", func(r *Rule) { r.Tunnel = "tn_removed" }).DescribeWith(name)
	if !strings.Contains(gone, "over tn_removed") {
		t.Errorf("DescribeWith = %q, want an unknown connection left as its id", gone)
	}
}

// The decision names the rule by its position as the user sees it, counting from one.
// Reporting the slice index would send somebody to the line above the one that decided.
func TestTheDecisionNamesTheRuleTheUserWouldEdit(t *testing.T) {
	rules := []Rule{
		rule("r1", func(r *Rule) { r.Tunnel = "tn_lab" }),
		rule("r2", func(r *Rule) { r.Tunnel = "tn_office"; r.Ports = []string{"5432"} }),
	}

	got := Decide(rules, req("db.corp.internal", "10.0.0.5", 5432, "tn_office"))

	if got.Index != 1 {
		t.Errorf("index = %d, want the second rule", got.Index)
	}
	if !strings.HasPrefix(got.Reason, "rule 2 ") {
		t.Errorf("reason = %q, want it to name rule 2", got.Reason)
	}
}

// Every condition a rule states is part of what it grants, so a change to any one of them
// is a change to the permission set. The caller drops its pooled connections on a true
// answer here, and a pooled connection was established under the rules that no longer
// apply: a field this comparison forgot is traffic still being carried to a destination
// the instance now refuses, with nothing on any surface saying so.
func TestEveryConditionARuleStatesIsPartOfWhetherItChanged(t *testing.T) {
	base := rule("r1", func(r *Rule) {
		r.Tunnel = "tn_office"
		r.Host = "db.corp.internal"
		r.CIDR = netip.MustParsePrefix("10.0.0.0/24")
		r.Ports = []string{"5432"}
		r.Protocol = TCP
	})

	tests := []struct {
		field  string
		mutate func(*Rule)
	}{
		{"id", func(r *Rule) { r.ID = "r2" }},
		{"action", func(r *Rule) { r.Action = Deny }},
		{"tunnel", func(r *Rule) { r.Tunnel = "tn_lab" }},
		{"host", func(r *Rule) { r.Host = "web.corp.internal" }},
		{"cidr", func(r *Rule) { r.CIDR = netip.MustParsePrefix("10.0.1.0/24") }},
		{"protocol", func(r *Rule) { r.Protocol = UDP }},
		// Narrowing a port list is the tightening this comparison exists to notice.
		{"ports", func(r *Rule) { r.Ports = []string{"5432", "5433"} }},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			changed := base
			changed.Ports = append([]string(nil), base.Ports...)
			tt.mutate(&changed)

			if SameRules([]Rule{base}, []Rule{changed}) {
				t.Errorf("a change of %s read as the same permission set", tt.field)
			}
		})
	}

	if !SameRules([]Rule{base}, []Rule{base}) {
		t.Error("an unchanged list read as changed, which drops every pooled connection on each reconcile")
	}
	if SameRules([]Rule{base}, []Rule{base, base}) {
		t.Error("a longer list read as the same one")
	}
	// Order is semantics here, so the same rules in a different order are a different
	// permission set -- the reason this compares position by position rather than as sets.
	other := rule("r2", func(r *Rule) { r.Action = Deny; r.Tunnel = "tn_office" })
	if SameRules([]Rule{base, other}, []Rule{other, base}) {
		t.Error("reordering read as the same permission set")
	}
}
