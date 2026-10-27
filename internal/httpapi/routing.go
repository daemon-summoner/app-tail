// SPDX-License-Identifier: MIT

package httpapi

import (
	"context"

	"github.com/sellitus/app-tail/internal/routing"
)

// Routing is the per-destination exceptions to the egress setting as the API needs them.
//
// It is separate from Routes, which is the tailnet's subnet routing: that reports which
// networks this device reaches through its peers, and this decides which connection a
// destination nothing else claims leaves through.
type Routing interface {
	View() RoutingView
	// SetRules replaces the whole ordered list. It takes a context because it waits for the
	// engine to pick the change up, so the view it returns describes the rules in force
	// rather than the ones about to be.
	SetRules(ctx context.Context, rules []routing.Rule) (RoutingView, error)
	// Check answers which way one destination goes, without dialling it.
	Check(req RoutingCheckRequest) (RoutingCheckResult, error)
}

// RoutingView is the whole rule list plus everything a client needs to render it without
// holding a second copy of the vocabulary.
type RoutingView struct {
	// Rules is the ordered list, always an array rather than null: a client reads its
	// length, and null would blank the page.
	Rules []routing.Rule `json:"rules"`
	// Describe is one sentence per rule, in the same order, with every connection named as
	// a person calls it. Rendered here rather than in each client so the dashboard, the CLI
	// and the tray state a rule identically.
	Describe []string `json:"describe"`
	// Shadowed names the rules that decide nothing on the network interface because an
	// earlier rule already covers their range. They still apply on the proxy path, where
	// first-match order is what runs; on the interface the addressing is a routing table,
	// and a range inside an earlier one never gets its own entry.
	Shadowed []string `json:"shadowed,omitempty"`
	// Actions is the vocabulary of a rule, served for the reason the proxy's is: a client
	// holding its own list would offer a value the agent refuses.
	Actions []routing.Action `json:"actions"`
	// Tunnels are the connections a rule may name, so a picker offers what exists.
	Tunnels []RoutingTunnel `json:"tunnels"`
	// Limits are what these rules do not do, stated up front rather than discovered.
	Limits     []string   `json:"limits,omitempty"`
	Capability Capability `json:"capability"`
}

// RoutingTunnel is one connection a rule may send a destination through.
type RoutingTunnel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Running reports the connection up right now. A rule may name one that is not: the
	// rule stays the rule, and the destination is refused rather than quietly sent out the
	// way everything else goes.
	Running bool `json:"running"`
}

// RoutingCheckRequest is one destination to decide, as a host name or an address.
type RoutingCheckRequest struct {
	Destination string `json:"destination"`
}

// RoutingCheckResult is which way that destination goes and which rule said so.
//
// Decided false is the ordinary answer for most destinations: no rule names it, so it
// leaves whichever way the egress setting says. That is not a failure and is reported as
// its own sentence rather than as an empty result.
type RoutingCheckResult struct {
	Destination string `json:"destination"`
	Decided     bool   `json:"decided"`
	Action      string `json:"action,omitempty"`
	Tunnel      string `json:"tunnel,omitempty"`
	TunnelName  string `json:"tunnelName,omitempty"`
	// Rule is the id of the rule that decided and RuleIndex its one-based position, so the
	// answer names the row as the table numbers it.
	Rule      string `json:"rule,omitempty"`
	RuleIndex int    `json:"ruleIndex,omitempty"`
	Reason    string `json:"reason"`
}

// The limits of per-destination routing, stated wherever the rules are shown. Neither is a
// defect a later release fixes: they follow from what each surface can see.
const (
	hostRuleLimit = "A rule about a host name applies to traffic app-tail resolves for -- " +
		"through the proxy, or through its own resolver. Traffic that reaches the network " +
		"interface carries an address and no name, so only a rule naming a range decides it."
	rangeQueryLimit = "A rule naming a range moves the traffic to that range, not the name " +
		"lookup that found it: the query still goes to whichever resolver the connection " +
		"carrying everything else uses."
	blockedNameLimit = "A blocked destination is refused before anything is dialled and " +
		"before its name is looked up, so neither the traffic nor the query leaves."
)

// RoutingLimits are what these rules do not do, served rather than written into each
// client so every surface states them identically.
func RoutingLimits() []string {
	return []string{hostRuleLimit, rangeQueryLimit, blockedNameLimit}
}
