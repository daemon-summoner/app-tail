// SPDX-License-Identifier: MIT

package cli

// The per-destination routing rules on the command line: which connection a destination
// leaves through, as an exception to the one internet-traffic setting.
//
// The list is edited a rule at a time here and replaced whole over HTTP, because order is
// the meaning -- the first matching rule decides -- and a person adding one exception
// should not have to resend the ones already there.

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/routing"
)

// Routing reads the rule list and everything needed to render it.
func (c *Client) Routing(ctx context.Context) (httpapi.RoutingView, error) {
	var out httpapi.RoutingView
	err := c.do(ctx, http.MethodGet, "/api/routing", nil, &out)
	return out, err
}

// SetRoutingRules replaces the whole ordered list.
func (c *Client) SetRoutingRules(ctx context.Context, rules []routing.Rule) (httpapi.RoutingView, error) {
	if rules == nil {
		rules = []routing.Rule{}
	}
	body := struct {
		Rules []routing.Rule `json:"rules"`
	}{Rules: rules}
	var out httpapi.RoutingView
	err := c.do(ctx, http.MethodPut, "/api/routing/rules", body, &out)
	return out, err
}

// CheckRoute asks which way one destination goes, without dialling it.
func (c *Client) CheckRoute(ctx context.Context, destination string) (httpapi.RoutingCheckResult, error) {
	var out httpapi.RoutingCheckResult
	err := c.do(ctx, http.MethodPost, "/api/routing/check",
		httpapi.RoutingCheckRequest{Destination: destination}, &out)
	return out, err
}

// runRoute dispatches the routing subcommands, listing the rules when given none.
func runRoute(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runRouteList(ctx, args, env)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runRouteList(ctx, rest, env)
	case "add":
		return runRouteAdd(ctx, rest, env)
	case "rm":
		return runRouteRemove(ctx, rest, env)
	case "move":
		return runRouteMove(ctx, rest, env)
	case "check":
		return runRouteCheck(ctx, rest, env)
	case "clear":
		return runRouteClear(ctx, rest, env)
	default:
		return usagef("unknown route subcommand %q; use `route`, `route add`, `route rm`, "+
			"`route move`, `route check` or `route clear`", sub)
	}
}

func runRouteList(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("route list", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "route list"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.Routing(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}
	writeRoutingRules(env, view)
	return nil
}

// writeRoutingRules prints the table, then the things about it a table cannot say: rules
// that decide nothing on the network interface, and a connection a rule names that is down.
func writeRoutingRules(env Env, view httpapi.RoutingView) {
	if len(view.Rules) == 0 {
		fmt.Fprintln(env.Stdout, "No routing rules. Every destination leaves the way the "+
			"internet traffic setting says.")
		fmt.Fprintln(env.Stdout, "Add one with: app-tail route add --host '**.corp.example' --via office")
		return
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "#\tID\tRULE")
	for i, rule := range view.Rules {
		sentence := rule.ID
		if i < len(view.Describe) {
			sentence = view.Describe[i]
		}
		fmt.Fprintf(writer, "%d\t%s\t%s\n", i+1, rule.ID, sentence)
	}
	// Flushed before the notes below so they cannot be pulled into the table's columns.
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(env.Stderr, "the rules could not be printed in full: %v\n", err)
	}

	if len(view.Shadowed) > 0 {
		fmt.Fprintf(env.Stdout, "\nOn the network interface these rules decide nothing, "+
			"because an earlier rule already covers their range: %s\n",
			strings.Join(view.Shadowed, ", "))
	}
	if view.Capability.Degraded && view.Capability.Reason != "" {
		fmt.Fprintf(env.Stdout, "\n%s\n", view.Capability.Reason)
	}
}

func runRouteAdd(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("route add", env)
	loc := addLocationFlags(fs)
	host := fs.String("host", "", "name pattern this rule is about, e.g. **.corp.example")
	cidr := fs.String("range", "", "address range this rule is about, e.g. 192.0.2.0/24")
	via := fs.String("via", "", "send the destination through this connection, by name or id")
	direct := fs.Bool("direct", false, "send the destination out of this machine's own network")
	block := fs.Bool("block", false, "refuse the destination")
	note := fs.String("note", "", "why this rule exists, kept beside it")
	at := fs.Int("at", 0, "position in the list, 1 for first; the default appends")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "route add"); err != nil {
		return err
	}

	rule := routing.Rule{Host: strings.TrimSpace(*host), Note: strings.TrimSpace(*note)}
	if raw := strings.TrimSpace(*cidr); raw != "" {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return usagef("--range %q is not an address range, e.g. 192.0.2.0/24", raw)
		}
		if masked := prefix.Masked(); masked != prefix {
			return usagef("--range %q carries host bits below its prefix; write it as %s", raw, masked)
		}
		rule.CIDR = prefix
	}
	if rule.Host == "" && !rule.CIDR.IsValid() {
		return usagef("say which destinations this rule is about, with --host or --range")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	if err := chooseRouteAction(ctx, client, &rule, *via, *direct, *block); err != nil {
		return err
	}

	view, err := client.Routing(ctx)
	if err != nil {
		return err
	}
	rules, err := insertRule(view.Rules, rule, *at)
	if err != nil {
		return err
	}
	after, err := client.SetRoutingRules(ctx, rules)
	if err != nil {
		return err
	}
	writeRoutingRules(env, after)
	return nil
}

// chooseRouteAction reads the one action flag the rule carries, refusing a rule that names
// none or several: an action is what the rule does, and guessing it would be guessing where
// somebody's traffic goes.
func chooseRouteAction(ctx context.Context, client *Client, rule *routing.Rule, via string, direct, block bool) error {
	named := 0
	if strings.TrimSpace(via) != "" {
		named++
	}
	if direct {
		named++
	}
	if block {
		named++
	}
	switch named {
	case 1:
	case 0:
		return usagef("say what happens to these destinations: --via CONNECTION, --direct or --block")
	default:
		return usagef("name one of --via, --direct and --block; a rule does one thing")
	}

	switch {
	case direct:
		rule.Action = routing.Direct
	case block:
		rule.Action = routing.Block
	default:
		tunnel, err := findTunnel(ctx, client, strings.TrimSpace(via))
		if err != nil {
			return err
		}
		rule.Action = routing.Via
		rule.Tunnel = tunnel.ID
	}
	return nil
}

// insertRule puts a rule at a one-based position, appending when none is given. A position
// past the end is refused rather than clamped: order is the meaning here, and a rule quietly
// landing somewhere other than where it was asked for is a rule that decides the wrong
// destinations.
func insertRule(rules []routing.Rule, rule routing.Rule, at int) ([]routing.Rule, error) {
	if at == 0 {
		return append(rules, rule), nil
	}
	if at < 1 || at > len(rules)+1 {
		return nil, usagef("--at %d is outside the list; it holds %d rules, so 1 to %d",
			at, len(rules), len(rules)+1)
	}
	out := make([]routing.Rule, 0, len(rules)+1)
	out = append(out, rules[:at-1]...)
	out = append(out, rule)
	return append(out, rules[at-1:]...), nil
}

func runRouteRemove(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("route rm", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: app-tail route rm ID-OR-POSITION")
	}
	wanted := pos[0]

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.Routing(ctx)
	if err != nil {
		return err
	}
	index, err := findRule(view.Rules, wanted)
	if err != nil {
		return err
	}

	rules := append(routing.Clone(view.Rules[:index]), view.Rules[index+1:]...)
	after, err := client.SetRoutingRules(ctx, rules)
	if err != nil {
		return err
	}
	writeRoutingRules(env, after)
	return nil
}

func runRouteMove(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("route move", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usagef("usage: app-tail route move ID-OR-POSITION POSITION")
	}
	wanted := pos[0]
	to, err := strconv.Atoi(pos[1])
	if err != nil {
		return usagef("%q is not a position; give the row number to move it to", pos[1])
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.Routing(ctx)
	if err != nil {
		return err
	}
	from, err := findRule(view.Rules, wanted)
	if err != nil {
		return err
	}
	if to < 1 || to > len(view.Rules) {
		return usagef("position %d is outside the list; it holds %d rules", to, len(view.Rules))
	}

	moving := view.Rules[from]
	without := append(routing.Clone(view.Rules[:from]), view.Rules[from+1:]...)
	rules, err := insertRule(without, moving, to)
	if err != nil {
		return err
	}
	after, err := client.SetRoutingRules(ctx, rules)
	if err != nil {
		return err
	}
	writeRoutingRules(env, after)
	return nil
}

// findRule accepts a rule id or a one-based position, and returns the index into the list.
func findRule(rules []routing.Rule, wanted string) (int, error) {
	for i, rule := range rules {
		if rule.ID == wanted {
			return i, nil
		}
	}
	if position, err := strconv.Atoi(wanted); err == nil {
		if position < 1 || position > len(rules) {
			return 0, fmt.Errorf("there is no rule %d; the list holds %d", position, len(rules))
		}
		return position - 1, nil
	}
	return 0, fmt.Errorf("no rule with id %q; run `app-tail route` to see them", wanted)
}

func runRouteCheck(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("route check", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: app-tail route check DESTINATION")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	result, err := client.CheckRoute(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, result)
	}

	if !result.Decided {
		fmt.Fprintf(env.Stdout, "%s: %s\n", result.Destination, result.Reason)
		return nil
	}
	switch routing.Action(result.Action) {
	case routing.Via:
		fmt.Fprintf(env.Stdout, "%s goes through %s (rule %d, %s)\n",
			result.Destination, orElse(result.TunnelName, result.Tunnel), result.RuleIndex, result.Rule)
	case routing.Direct:
		fmt.Fprintf(env.Stdout, "%s leaves through this machine's own network (rule %d, %s)\n",
			result.Destination, result.RuleIndex, result.Rule)
	default:
		fmt.Fprintf(env.Stdout, "%s is refused (rule %d, %s)\n",
			result.Destination, result.RuleIndex, result.Rule)
	}
	return nil
}

func runRouteClear(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("route clear", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "route clear"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	after, err := client.SetRoutingRules(ctx, nil)
	if err != nil {
		return err
	}
	writeRoutingRules(env, after)
	return nil
}
