// SPDX-License-Identifier: MIT

package access

import (
	"net/netip"
	"strings"
	"testing"
)

func TestAValueThatWouldMakeARuleUnusableIsRefused(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want string
	}{
		{"no id", Rule{Action: Allow, Tunnel: "tn_office"}, "id"},
		{"no action", Rule{ID: "r1", Tunnel: "tn_office"}, "allows or refuses"},
		{"an action nothing does", Rule{ID: "r1", Action: "maybe", Tunnel: "tn_office"}, "not an action"},
		{"a transport nothing speaks", Rule{ID: "r1", Action: Allow, Protocol: "sctp"}, "not a transport"},
		{"an empty port list", Rule{ID: "r1", Action: Allow, Tunnel: "tn_office", Ports: []string{}}, "leave the list out"},
		{"a port that is not a number", Rule{ID: "r1", Action: Allow, Ports: []string{"postgres"}}, "not a port number"},
		{"a port outside the range", Rule{ID: "r1", Action: Allow, Ports: []string{"70000"}}, "outside 1-65535"},
		{"port zero", Rule{ID: "r1", Action: Allow, Ports: []string{"0"}}, "outside 1-65535"},
		{"a range that ends before it starts", Rule{ID: "r1", Action: Allow, Ports: []string{"9000-8000"}}, "ends before it starts"},
		{"a rule that names nothing at all", Rule{ID: "r1", Action: Allow}, "covers everything"},
		{"a blank host", Rule{ID: "r1", Action: Allow, Tunnel: "tn_office", Host: "   "}, "cannot be blank"},
		{"a wildcard in the middle", Rule{ID: "r1", Action: Allow, Host: "db.**.internal"}, "belongs at the front"},
		{"a doubled wildcard inside a label", Rule{ID: "r1", Action: Allow, Host: "db**x.corp.internal"}, "inside a label"},
		{"an empty label", Rule{ID: "r1", Action: Allow, Host: "db..internal"}, "empty label"},
		{"a character no host carries", Rule{ID: "r1", Action: Allow, Host: "db corp.internal"}, "cannot appear"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.Validate()
			if err == nil {
				t.Fatalf("%+v was accepted", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to carry %q", err, tc.want)
			}
		})
	}
}

func TestARuleSomebodyCouldHaveMeantIsAccepted(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{"a whole connection", Rule{ID: "r1", Action: Allow, Tunnel: "tn_office"}},
		{"this machine", Rule{ID: "r1", Action: Allow, Tunnel: ThisMachine}},
		{"one service", Rule{ID: "r1", Action: Allow, Tunnel: "tn_office", Host: "db.corp.internal", Ports: []string{"5432"}, Protocol: TCP}},
		{"a range of ports", Rule{ID: "r1", Action: Allow, Tunnel: "tn_office", Ports: []string{"8000-8100"}}},
		{"a prefix", Rule{ID: "r1", Action: Deny, CIDR: netip.MustParsePrefix("10.0.0.0/8")}},
		{"every label under a suffix", Rule{ID: "r1", Action: Allow, Host: "**.corp.internal"}},
		{"a wildcard inside a label", Rule{ID: "r1", Action: Allow, Host: "db-*.corp.internal"}},
		{"a name with an underscore", Rule{ID: "r1", Action: Allow, Host: "_pgsql._tcp.corp.internal"}},
		{"a rule with no port list at all", Rule{ID: "r1", Action: Allow, Tunnel: "tn_office", Ports: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rule.Validate(); err != nil {
				t.Errorf("%+v was refused: %v", tc.rule, err)
			}
		})
	}
}

// Two rules under one id makes "which rule decided this" unanswerable, which is the one
// question a permission model has to be able to answer.
func TestOneIDCannotBeUsedTwiceInAList(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Action: Allow, Tunnel: "tn_office"},
		{ID: "r1", Action: Deny, Tunnel: "tn_lab"},
	}

	err := ValidateRules(rules)

	if err == nil {
		t.Fatal("a list naming one rule twice was accepted")
	}
	if !strings.Contains(err.Error(), "repeats") || !strings.Contains(err.Error(), "r1") {
		t.Errorf("error = %q, want the repeated id named", err)
	}
}

// The list is validated as a list, so a refusal has to say which line to go and fix.
func TestARefusalNamesTheLineToFix(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Action: Allow, Tunnel: "tn_office"},
		{ID: "r2", Action: Allow, Tunnel: "tn_lab", Ports: []string{"nope"}},
	}

	err := ValidateRules(rules)

	if err == nil {
		t.Fatal("a list holding an unusable rule was accepted")
	}
	if !strings.HasPrefix(err.Error(), "rule 2:") {
		t.Errorf("error = %q, want it to name rule 2", err)
	}
}

func TestAnEmptyListIsAValidSetOfRules(t *testing.T) {
	if err := ValidateRules(nil); err != nil {
		t.Errorf("an instance with no rules was refused: %v", err)
	}
}
