// SPDX-License-Identifier: MIT

package app

// The per-destination exceptions to the egress setting, as the management API reads and
// writes them.
//
// The rules live in the stored document rather than in the runtime, for the reason the
// proxies do: nothing overrides them, so the document is the whole truth, and reading it
// here is what makes an edit take effect on the next pass.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/routing"
)

type routingAPI struct{ a *Agent }

var _ httpapi.Routing = routingAPI{}

// RoutingAPI exposes the per-destination routing rules.
func (a *Agent) RoutingAPI() httpapi.Routing { return routingAPI{a: a} }

func (r routingAPI) View() httpapi.RoutingView {
	cfg := r.a.store.Get()
	rules := routing.Clone(cfg.Routes)
	if rules == nil {
		rules = []routing.Rule{}
	}

	name := func(id string) string { return r.a.connectionName(id) }
	describe := make([]string, 0, len(rules))
	for _, rule := range rules {
		sentence := rule.DescribeWith(name)
		if note := strings.TrimSpace(rule.Note); note != "" {
			sentence += " -- " + note
		}
		describe = append(describe, sentence)
	}

	view := httpapi.RoutingView{
		Rules:    rules,
		Describe: describe,
		Shadowed: routing.Shadowed(rules),
		Actions:  routing.Actions,
		Tunnels:  r.choices(cfg),
		Limits:   httpapi.RoutingLimits(),
		Capability: httpapi.Capability{
			Available: true,
			Limits:    httpapi.RoutingLimits(),
		},
	}
	if down := r.namingSomethingDown(rules); down != "" {
		// Degraded rather than an error: the rule is doing exactly what it says, and what it
		// says while its connection is down is that the destination is refused. A user who is
		// not told reads the refusal as the app being broken.
		view.Capability.Degraded = true
		view.Capability.Reason = down
	}
	return view
}

// choices are the connections a rule may name, which is every configured one: a rule about
// a connection that is switched off or not up yet is a rule waiting for it, not an error.
func (r routingAPI) choices(cfg *config.Config) []httpapi.RoutingTunnel {
	out := make([]httpapi.RoutingTunnel, 0, len(cfg.Tunnels))
	for _, held := range cfg.Tunnels {
		_, running := r.a.tunnels.Get(held.ID)
		out = append(out, httpapi.RoutingTunnel{ID: held.ID, Name: held.Name, Running: running})
	}
	return out
}

// namingSomethingDown is the first rule sending traffic through a connection that is not
// running, as a sentence, empty when every rule can be honoured.
func (r routingAPI) namingSomethingDown(rules []routing.Rule) string {
	for i, rule := range rules {
		if rule.Action != routing.Via {
			continue
		}
		if _, running := r.a.tunnels.Get(rule.Tunnel); running {
			continue
		}
		return fmt.Sprintf("rule %d sends traffic through %s, which is not running, so those "+
			"destinations are refused rather than sent out another way",
			i+1, r.a.connectionName(rule.Tunnel))
	}
	return ""
}

// SetRules replaces the whole ordered list.
//
// A rule with no id is minted one here rather than refused, exactly as a proxy's rules are:
// the id exists so a decision can name the line that made it, which is bookkeeping the
// person writing the rule should not have to do. Everything else -- what a rule may say,
// that two rules cannot share an id, that every connection named exists -- is the
// document's own rule and is checked by the store.
func (r routingAPI) SetRules(ctx context.Context, rules []routing.Rule) (httpapi.RoutingView, error) {
	minted := make([]routing.Rule, len(rules))
	for i, rule := range rules {
		if strings.TrimSpace(rule.ID) == "" {
			id, err := config.NewRuleID()
			if err != nil {
				return httpapi.RoutingView{}, err
			}
			rule.ID = id
		}
		minted[i] = rule
	}

	if _, err := r.a.store.Update(func(c *config.Config) error {
		c.Routes = routing.Clone(minted)
		return nil
	}); err != nil {
		return httpapi.RoutingView{}, err
	}

	r.a.reconcileNow(ctx)
	return r.View(), nil
}

// Check answers which way one destination goes, without dialling it or looking it up.
//
// It decides the destination as written, which is what makes the answer readable: a name is
// put to the rules as a name, an address as an address. A rule naming a range therefore does
// not answer for a host name here, and that is the truth of it -- on the real path that rule
// applies once something has resolved the name, and this endpoint resolves nothing.
func (r routingAPI) Check(req httpapi.RoutingCheckRequest) (httpapi.RoutingCheckResult, error) {
	destination := strings.TrimSpace(req.Destination)
	asked := routing.Request{Host: destination}
	if addr, err := netip.ParseAddr(destination); err == nil {
		asked = routing.Request{Addr: addr}
	}

	rules := r.a.routes()
	decided := routing.Decide(rules, asked)
	out := httpapi.RoutingCheckResult{Destination: destination, Decided: decided.Decided}
	if !decided.Decided {
		out.Reason = "no rule names this destination, so it leaves whichever way the internet " +
			"traffic setting says"
		return out, nil
	}
	out.Action = string(decided.Action)
	out.Tunnel = decided.Tunnel
	out.Rule = decided.Rule
	// One-based, so it names the row as the rules table numbers it.
	out.RuleIndex = decided.Index + 1
	// Restated with the connection named as a person calls it, which the decision itself
	// cannot do: it works on the stored rules, where a connection is an id.
	out.Reason = fmt.Sprintf("rule %d %s", out.RuleIndex,
		rules[decided.Index].DescribeWith(func(id string) string { return r.a.connectionName(id) }))
	if decided.Tunnel != "" {
		out.TunnelName = r.a.connectionName(decided.Tunnel)
	}
	return out, nil
}
