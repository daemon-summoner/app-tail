// SPDX-License-Identifier: MIT

package app

// The per-destination routing rules as the management API reads and writes them.

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/routing"
)

// A rule arrives from a form with no id: the id exists so a decision can name the line that
// made it, which is bookkeeping the person writing the rule should not have to do.
func TestARuleWrittenWithoutAnIDIsGivenOne(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{Action: routing.Direct, Host: "bank.example"},
	})
	if err != nil {
		t.Fatalf("storing the rule: %v", err)
	}

	if len(view.Rules) != 1 {
		t.Fatalf("read back %d rules, want the one that was written", len(view.Rules))
	}
	if strings.TrimSpace(view.Rules[0].ID) == "" {
		t.Error("the stored rule has no id, so nothing a decision reports could name it")
	}
	if stored := h.store.Get().Routes; len(stored) != 1 || stored[0].ID != view.Rules[0].ID {
		t.Errorf("the document holds %+v, want the rule the caller read back", stored)
	}
}

// The order the caller sent is the meaning -- the first matching rule decides -- so it is
// the order the document keeps.
func TestTheListIsStoredInTheOrderItWasWritten(t *testing.T) {
	h := newHarness(t, nil)

	if _, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
		{ID: "rt_2", Action: routing.Via, Tunnel: config.PrimaryTunnelID, Host: "**.example"},
	}); err != nil {
		t.Fatalf("storing the rules: %v", err)
	}

	stored := h.store.Get().Routes
	if len(stored) != 2 || stored[0].ID != "rt_1" || stored[1].ID != "rt_2" {
		t.Errorf("the document holds %+v, want both rules in the order they were sent", stored)
	}
}

// A rule naming a connection that does not exist is refused, and refused before anything is
// stored: half a list is a routing table nobody wrote.
func TestARuleNamingAConnectionThatDoesNotExistIsRefusedAndStoresNothing(t *testing.T) {
	h := newHarness(t, nil)

	_, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_1", Action: routing.Via, Tunnel: "tn_absent", Host: "a.example"},
	})

	if err == nil {
		t.Fatal("storing a rule through a connection that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("refusal = %v, want it to say the connection does not exist", err)
	}
	if stored := h.store.Get().Routes; len(stored) != 0 {
		t.Errorf("the document holds %+v after a refusal, want nothing", stored)
	}
}

// The list reads back as sentences naming each connection the way a person calls it, so a
// client renders the table without joining it against the connection list itself.
func TestEachRuleReadsBackAsASentenceNamingTheConnection(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		for i := range c.Tunnels {
			if c.Tunnels[i].ID == config.PrimaryTunnelID {
				c.Tunnels[i].Name = "Head office"
			}
		}
	})

	view, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_1", Action: routing.Via, Tunnel: config.PrimaryTunnelID, Host: "**.corp.example",
			Note: "the ticket system only answers there"},
	})
	if err != nil {
		t.Fatalf("storing the rule: %v", err)
	}

	if len(view.Describe) != 1 {
		t.Fatalf("described %d rules, want one sentence per rule", len(view.Describe))
	}
	sentence := view.Describe[0]
	if !strings.Contains(sentence, "Head office") {
		t.Errorf("sentence = %q, want the connection named as a person calls it", sentence)
	}
	if !strings.Contains(sentence, "the ticket system only answers there") {
		t.Errorf("sentence = %q, want the user's own note carried through", sentence)
	}
}

// A range an earlier rule already covers decides nothing on the network interface, because
// the addressing there is a routing table rather than a first-match list. Reported rather
// than silently dropped: a rule that does nothing and says nothing is the worst of both.
func TestARangeAnEarlierRuleCoversIsReportedAsShadowed(t *testing.T) {
	h := newHarness(t, nil)

	view, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_wide", Action: routing.Block, CIDR: netip.MustParsePrefix("192.0.2.0/24")},
		{ID: "rt_inner", Action: routing.Direct, CIDR: netip.MustParsePrefix("192.0.2.128/25")},
	})
	if err != nil {
		t.Fatalf("storing the rules: %v", err)
	}

	if len(view.Shadowed) != 1 || view.Shadowed[0] != "rt_inner" {
		t.Errorf("shadowed = %v, want the narrower rule the wider one already covers", view.Shadowed)
	}
}

// A rule sending traffic through a connection that is not running is not an error: it is the
// rule doing what it says, which is refusing those destinations. Saying so is what keeps the
// refusal from reading as the app being broken.
func TestARuleThroughAConnectionThatIsNotRunningReadsAsDegraded(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		seedFabric(c, labRange)
		for i := range c.Tunnels {
			if c.Tunnels[i].ID == wgTunnelID {
				c.Tunnels[i].Enabled = false
			}
		}
	})

	view, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_1", Action: routing.Via, Tunnel: wgTunnelID, Host: "a.example"},
	})
	if err != nil {
		t.Fatalf("storing the rule: %v", err)
	}

	if !view.Capability.Available {
		t.Error("the rules read as unavailable; they apply whatever the connections are doing")
	}
	if !view.Capability.Degraded || !strings.Contains(view.Capability.Reason, "not running") {
		t.Errorf("capability = %+v, want it to say the connection the rule names is not running",
			view.Capability)
	}
}

func TestCheckingANameNamesTheRuleThatDecidesIt(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
		{ID: "rt_2", Action: routing.Via, Tunnel: config.PrimaryTunnelID, Host: "**.corp.example"},
	}); err != nil {
		t.Fatalf("storing the rules: %v", err)
	}

	got, err := h.agent.RoutingAPI().Check(httpapi.RoutingCheckRequest{Destination: "db.corp.example"})
	if err != nil {
		t.Fatalf("checking a destination: %v", err)
	}

	if !got.Decided || got.Rule != "rt_2" {
		t.Errorf("check = %+v, want the second rule to decide it", got)
	}
	if got.RuleIndex != 2 {
		t.Errorf("rule index = %d, want the row as the table numbers it", got.RuleIndex)
	}
	if got.Action != string(routing.Via) || got.Tunnel != config.PrimaryTunnelID {
		t.Errorf("check = %+v, want it sent through the connection the rule names", got)
	}
	// The sentence is what a person reads, so it names the connection the way they do. The
	// decision itself works on the stored rules, where a connection is an id nobody chose.
	if want := h.agent.connectionName(config.PrimaryTunnelID); !strings.Contains(got.Reason, want) {
		t.Errorf("reason = %q, want it to name %q rather than the stored id", got.Reason, want)
	}
	if strings.Contains(got.Reason, config.PrimaryTunnelID) {
		t.Errorf("reason = %q, want the connection named rather than its id", got.Reason)
	}
}

// An address literal is put to the rules as an address, which is what makes a range rule
// answerable without dialling or resolving anything.
func TestCheckingAnAddressIsDecidedByARangeRule(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_1", Action: routing.Block, CIDR: netip.MustParsePrefix("192.0.2.0/24")},
	}); err != nil {
		t.Fatalf("storing the rule: %v", err)
	}

	got, err := h.agent.RoutingAPI().Check(httpapi.RoutingCheckRequest{Destination: "192.0.2.44"})
	if err != nil {
		t.Fatalf("checking a destination: %v", err)
	}

	if !got.Decided || got.Action != string(routing.Block) {
		t.Errorf("check = %+v, want the range rule to refuse it", got)
	}
}

// Most destinations are decided by no rule at all, which is the ordinary answer and not an
// empty result: they leave whichever way the internet traffic setting says.
func TestADestinationNoRuleNamesSaysSoRatherThanAnsweringNothing(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.agent.RoutingAPI().SetRules(context.Background(), []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
	}); err != nil {
		t.Fatalf("storing the rule: %v", err)
	}

	got, err := h.agent.RoutingAPI().Check(httpapi.RoutingCheckRequest{Destination: "example.com"})
	if err != nil {
		t.Fatalf("checking a destination: %v", err)
	}

	if got.Decided {
		t.Errorf("check = %+v, want no rule to decide a destination none names", got)
	}
	if !strings.Contains(got.Reason, "no rule names this destination") {
		t.Errorf("reason = %q, want it to say no rule covers it", got.Reason)
	}
}
