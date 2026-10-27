// SPDX-License-Identifier: MIT

package routing

import (
	"net/netip"
	"strings"
	"testing"
)

func TestARuleNamingNoDestinationIsRefused(t *testing.T) {
	err := Rule{ID: "r1", Action: Direct}.Validate()

	if err == nil {
		t.Fatal("a rule naming neither a host nor a range was accepted; it would cover every destination")
	}
	if !strings.Contains(err.Error(), "every destination") {
		t.Errorf("error = %q, want it to say why the rule is refused", err)
	}
}

func TestSendingTrafficThroughAConnectionRequiresNamingIt(t *testing.T) {
	err := Rule{ID: "r1", Action: Via, Host: "a.example"}.Validate()

	if err == nil {
		t.Fatal("a via rule with no connection was accepted")
	}
}

// A connection id on a rule that never reads it is how a rule ends up looking like it
// points somewhere it does not: the table would read "direct" and carry a connection.
func TestAnActionThatGoesNowhereMayNotNameAConnection(t *testing.T) {
	for _, action := range []Action{Direct, Block} {
		t.Run(string(action), func(t *testing.T) {
			err := Rule{ID: "r1", Action: action, Host: "a.example", Tunnel: "tn_a"}.Validate()
			if err == nil {
				t.Fatalf("a %s rule naming a connection was accepted", action)
			}
		})
	}
}

func TestARuleWithNoActionOrAnUnknownOneIsRefused(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		want   string
	}{
		{"none at all", "", "must say where"},
		{"one this build does not know", "tunnel-maybe", "not an action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Rule{ID: "r1", Action: tt.action, Host: "a.example"}.Validate()
			if err == nil {
				t.Fatalf("the action %q was accepted", tt.action)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestARuleNeedsAnID(t *testing.T) {
	if err := (Rule{Action: Direct, Host: "a.example"}).Validate(); err == nil {
		t.Fatal("a rule with no id was accepted; nothing could then say which rule decided")
	}
}

// A pattern nothing can match is a rule that sits in the table doing nothing, which is
// worse than a missing one.
func TestAHostPatternNothingCanMatchIsRefused(t *testing.T) {
	if err := (Rule{ID: "r1", Action: Direct, Host: "a..example"}).Validate(); err == nil {
		t.Fatal("a pattern with an empty label was accepted")
	}
}

// A prefix carrying host bits is ambiguous to read back: 10.1.2.3/8 looks like a rule
// about one host and behaves like a rule about sixteen million.
func TestARangeWrittenWithHostBitsIsRefusedWithTheFormThatWorks(t *testing.T) {
	err := Rule{ID: "r1", Action: Direct, CIDR: netip.MustParsePrefix("10.1.2.3/8")}.Validate()

	if err == nil {
		t.Fatal("a prefix with host bits below it was accepted")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Errorf("error = %q, want it to name the form that works", err)
	}
}

// Two rules under one id make "which rule decided" unanswerable, which is the one
// question a routing table has to be able to answer.
func TestTwoRulesUnderOneIDAreRefused(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Action: Direct, Host: "a.example"},
		{ID: "r1", Action: Direct, Host: "b.example"},
	}

	err := ValidateRules(rules)

	if err == nil {
		t.Fatal("a list repeating an id was accepted")
	}
	if !strings.Contains(err.Error(), "rule 2") {
		t.Errorf("error = %q, want it to name the position of the repeat", err)
	}
}

// The position is what the user edits by, so a failure that names only the reason leaves
// them reading the whole list to find it.
func TestAListNamesThePositionOfTheRuleThatIsWrong(t *testing.T) {
	rules := []Rule{
		{ID: "ok", Action: Direct, Host: "a.example"},
		{ID: "bad", Action: Via, Host: "b.example"},
	}

	err := ValidateRules(rules)

	if err == nil {
		t.Fatal("a list holding an unusable rule was accepted")
	}
	if !strings.Contains(err.Error(), "rule 2") {
		t.Errorf("error = %q, want it to name rule 2", err)
	}
}

func TestAWholeUsableListIsAccepted(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Action: Direct, Host: "bank.example"},
		{ID: "r2", Action: Via, Host: "**.corp.example", Tunnel: "tn_office"},
		{ID: "r3", Action: Block, CIDR: netip.MustParsePrefix("192.0.2.0/24")},
	}

	if err := ValidateRules(rules); err != nil {
		t.Fatalf("a usable list was refused: %v", err)
	}
	if err := ValidateRules(nil); err != nil {
		t.Fatalf("an empty list was refused: %v", err)
	}
}
