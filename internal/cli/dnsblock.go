// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// DNSBlockState reads which lists are on, what each contributed and what is blocked.
func (c *Client) DNSBlockState(ctx context.Context) (httpapi.DNSBlockView, error) {
	var out httpapi.DNSBlockView
	err := c.do(ctx, http.MethodGet, "/api/dns/block", nil, &out)
	return out, err
}

// RefreshDNSBlock downloads every enabled list now.
func (c *Client) RefreshDNSBlock(ctx context.Context) (httpapi.DNSBlockView, error) {
	var out httpapi.DNSBlockView
	err := c.do(ctx, http.MethodPost, "/api/dns/block/refresh", nil, &out)
	return out, err
}

// PauseDNSBlock stops blocking for a number of minutes.
func (c *Client) PauseDNSBlock(ctx context.Context, minutes int) (httpapi.DNSBlockView, error) {
	var out httpapi.DNSBlockView
	body := map[string]int{"minutes": minutes}
	err := c.do(ctx, http.MethodPost, "/api/dns/block/pause", body, &out)
	return out, err
}

// ResumeDNSBlock ends a pause.
func (c *Client) ResumeDNSBlock(ctx context.Context) (httpapi.DNSBlockView, error) {
	var out httpapi.DNSBlockView
	err := c.do(ctx, http.MethodPost, "/api/dns/block/resume", nil, &out)
	return out, err
}

// ApplyDNSBlockPreset switches the shipped lists to one rung of the curated ladder.
func (c *Client) ApplyDNSBlockPreset(ctx context.Context, id string) (httpapi.DNSBlockView, error) {
	var out httpapi.DNSBlockView
	body := map[string]string{"preset": id}
	err := c.do(ctx, http.MethodPost, "/api/dns/block/preset", body, &out)
	return out, err
}

// CheckDNSBlock asks whether one name is blocked and by what.
func (c *Client) CheckDNSBlock(ctx context.Context, name string) (httpapi.DNSBlockCheckView, error) {
	var out httpapi.DNSBlockCheckView
	err := c.do(ctx, http.MethodGet, "/api/dns/block/check?name="+url.QueryEscape(name), nil, &out)
	return out, err
}

// CreateDNSBlockList adds one of the user's own lists.
func (c *Client) CreateDNSBlockList(ctx context.Context, l config.Blocklist) (config.Blocklist, error) {
	var out config.Blocklist
	err := c.do(ctx, http.MethodPost, "/api/dns/block/lists", l, &out)
	return out, err
}

// DeleteDNSBlockList removes one of the user's own lists. Built-ins and lists that are
// switched on are refused by the agent.
func (c *Client) DeleteDNSBlockList(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/dns/block/lists/"+url.PathEscape(id), nil, nil)
}

// runDNSBlock dispatches the blocking subcommands, showing the state when given none.
func runDNSBlock(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runDNSBlockShow(ctx, args, env)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "on":
		return runDNSBlockSwitch(ctx, rest, env, true)
	case "off":
		return runDNSBlockSwitch(ctx, rest, env, false)
	case "list":
		return runDNSBlockList(ctx, rest, env)
	case "level":
		return runDNSBlockLevel(ctx, rest, env)
	case "add":
		return runDNSBlockAdd(ctx, rest, env)
	case "rm":
		return runDNSBlockRemove(ctx, rest, env)
	case "enable":
		return runDNSBlockEnable(ctx, rest, env, true)
	case "disable":
		return runDNSBlockEnable(ctx, rest, env, false)
	case "refresh":
		return runDNSBlockRefresh(ctx, rest, env)
	case "pause":
		return runDNSBlockPause(ctx, rest, env)
	case "resume":
		return runDNSBlockResume(ctx, rest, env)
	case "allow":
		return runDNSBlockNames(ctx, rest, env, "dnsBlock.allow", "allow")
	case "deny":
		return runDNSBlockNames(ctx, rest, env, "dnsBlock.deny", "deny")
	case "check":
		return runDNSBlockCheck(ctx, rest, env)
	default:
		return usagef("unknown dns block command %q; use on, off, level, list, add, rm, enable, "+
			"disable, refresh, pause, resume, allow, deny or check", sub)
	}
}

func runDNSBlockShow(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns block"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}
	writeDNSBlock(env, view)
	return nil
}

// writeDNSBlock prints the state both switches produce, plus every list that is on.
//
// The two switches are printed separately because they reach different things: one is what
// app-tail resolves for itself, the other is what this machine resolves, and a user reading
// "blocking: on" has no other way to learn which of the two they got.
func writeDNSBlock(env Env, view httpapi.DNSBlockView) {
	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(writer, "Blocking\t%s\n", onOff(view.Enabled))
	fmt.Fprintf(writer, "app-tail's own resolution\t%s\n", onOff(view.Own))
	fmt.Fprintf(writer, "This machine's resolution\t%s\n", onOff(view.System))
	fmt.Fprintf(writer, "Level\t%s\n", dnsBlockLevelName(view))
	fmt.Fprintf(writer, "Blocked names answer with\t%s\n", view.Answer)
	fmt.Fprintf(writer, "Names in force\t%d\n", view.Rules)
	fmt.Fprintf(writer, "Queries refused\t%d\n", view.Blocked)
	fmt.Fprintf(writer, "Re-download every\t%d hours\n", view.RefreshHours)
	if view.NextRefresh != "" {
		fmt.Fprintf(writer, "Next download\t%s\n", localTime(view.NextRefresh))
	}
	if view.PausedUntil != "" {
		fmt.Fprintf(writer, "Paused until\t%s\n", localTime(view.PausedUntil))
	}
	if len(view.Allow) > 0 {
		fmt.Fprintf(writer, "Never blocked\t%s\n", strings.Join(view.Allow, ", "))
	}
	if len(view.Deny) > 0 {
		fmt.Fprintf(writer, "Always blocked\t%s\n", strings.Join(view.Deny, ", "))
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(env.Stderr, "printing the blocking state failed: %v\n", err)
		return
	}

	on := make([]httpapi.DNSBlockListView, 0, len(view.Lists))
	for _, l := range view.Lists {
		if l.Enabled {
			on = append(on, l)
		}
	}
	if len(on) > 0 {
		fmt.Fprintln(env.Stdout)
		writeDNSBlockLists(env, on)
	}
	if view.Capability.Reason != "" {
		fmt.Fprintf(env.Stdout, "\n%s\n", view.Capability.Reason)
	}
}

// dnsBlockLevelName names the rung in force. A set of lists that is nobody's rung is said
// so in words: "custom" is the state somebody produced by switching one list on top of a
// level, and reading a level name there would be a lie about what is on.
func dnsBlockLevelName(view httpapi.DNSBlockView) string {
	for _, p := range view.Presets {
		if p.ID == view.Preset {
			return p.Name
		}
	}
	return "custom"
}

// writeDNSBlockLists prints the catalog grouped by who publishes it. The provider is named
// on the first row of its run and left blank on the rest, which keeps one aligned table
// while reading as the groups the picker shows.
func writeDNSBlockLists(env Env, lists []httpapi.DNSBlockListView) {
	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "PROVIDER\tID\tNAME\tON\tNAMES\tSKIPPED\tUPDATED")
	var shown string
	for _, l := range groupDNSBlockLists(lists) {
		provider := l.Provider
		if provider == shown {
			provider = ""
		} else {
			shown = l.Provider
		}
		updated := "never"
		if l.UpdatedAt != "" {
			updated = localTime(l.UpdatedAt)
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			provider, l.ID, l.Name, yesNo(l.Enabled), l.Rules, l.Skipped, updated)
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(env.Stderr, "printing the blocklists failed: %v\n", err)
		return
	}
	for _, l := range lists {
		if l.Error != "" {
			// After the table rather than in it: the reason is a sentence, and a column wide
			// enough to hold one makes every other column unreadable.
			fmt.Fprintf(env.Stderr, "%s: %s\n", l.Name, l.Error)
		}
	}
}

// groupDNSBlockLists puts the lists of one provider next to each other, providers in the
// order they first appear. The agent already sends them that way; grouping here is what
// keeps the printed provider column honest if a caller hands over a set that is not.
func groupDNSBlockLists(lists []httpapi.DNSBlockListView) []httpapi.DNSBlockListView {
	order := make([]string, 0, len(lists))
	byProvider := make(map[string][]httpapi.DNSBlockListView, len(lists))
	for _, l := range lists {
		if _, seen := byProvider[l.Provider]; !seen {
			order = append(order, l.Provider)
		}
		byProvider[l.Provider] = append(byProvider[l.Provider], l)
	}
	out := make([]httpapi.DNSBlockListView, 0, len(lists))
	for _, provider := range order {
		out = append(out, byProvider[provider]...)
	}
	return out
}

// localTime renders an RFC 3339 timestamp in this machine's own zone, and leaves anything
// it cannot read exactly as the agent sent it.
func localTime(stamp string) string {
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return stamp
	}
	return t.Local().Format("2006-01-02 15:04")
}

// runDNSBlockSwitch turns blocking on or off. Turning it on turns on both halves, because
// blocking that filters nothing is the state people report as broken.
func runDNSBlockSwitch(ctx context.Context, args []string, env Env, on bool) error {
	name := "dns block off"
	if on {
		name = "dns block on"
	}
	fs := newFlagSet(name, env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, name); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	patch := map[string]json.RawMessage{
		"dnsBlock.enabled": json.RawMessage(fmt.Sprintf("%t", on)),
	}
	if on {
		// Named only when going on: turning the module off resets the settings it owns back
		// to their defaults, and naming one in that write is naming a setting the same write
		// has just made unavailable.
		patch["dnsBlock.own"] = json.RawMessage("true")
		patch["dnsBlock.system"] = json.RawMessage("true")
	}
	result, err := client.UpdateSettings(ctx, patch)
	if err != nil {
		return err
	}

	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return fmt.Errorf("stored the switch, but could not read back what blocking is doing: %w", err)
	}
	writeDNSBlock(env, view)
	noteRestart(env.Stdout, result)
	return nil
}

func runDNSBlockList(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block list", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the lists as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns block list"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		lists := view.Lists
		if lists == nil {
			lists = []httpapi.DNSBlockListView{}
		}
		return writeJSON(env, lists)
	}
	writeDNSBlockLists(env, view.Lists)
	return nil
}

// runDNSBlockLevel shows the curated ladder, or switches to one rung of it. Naming no rung
// prints them: choosing a level is a decision somebody makes once, and they make it by
// reading what each one blocks rather than by knowing the ids.
func runDNSBlockLevel(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block level", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the levels as JSON")
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usagef("dns block level takes at most one level name")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		wanted, err := resolveDNSBlockLevel(view.Presets, pos[0])
		if err != nil {
			return err
		}
		view, err = client.ApplyDNSBlockPreset(ctx, wanted)
		if err != nil {
			return err
		}
		writeDNSBlock(env, view)
		return nil
	}
	if *asJSON {
		presets := view.Presets
		if presets == nil {
			presets = []httpapi.DNSBlockPresetView{}
		}
		return writeJSON(env, presets)
	}
	writeDNSBlockLevels(env, view)
	return nil
}

// resolveDNSBlockLevel reads what the user typed as a rung, by id or by the name shown in
// the table, so `dns block level High` works as well as `dns block level high`.
func resolveDNSBlockLevel(presets []httpapi.DNSBlockPresetView, typed string) (string, error) {
	wanted := strings.ToLower(strings.TrimSpace(typed))
	names := make([]string, 0, len(presets))
	for _, p := range presets {
		names = append(names, p.ID)
		if strings.ToLower(p.ID) == wanted || strings.ToLower(p.Name) == wanted {
			return p.ID, nil
		}
	}
	return "", usagef("%q is not one of the levels; use %s", typed, strings.Join(names, ", "))
}

// writeDNSBlockLevels prints the ladder with the rung in force marked, and what each one
// turns on. The count is the honest measure of a rung: it is the number of lists, not the
// number of names, because the names arrive only once each list is downloaded.
func writeDNSBlockLevels(env Env, view httpapi.DNSBlockView) {
	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "\tLEVEL\tLISTS\tWHAT IT BLOCKS")
	for _, p := range view.Presets {
		marker := ""
		if p.ID == view.Preset {
			marker = "*"
		}
		name := p.ID
		if p.Recommended {
			name += " (recommended)"
		}
		fmt.Fprintf(writer, "%s\t%s\t%d\t%s\n", marker, name, len(p.Lists), p.Summary)
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(env.Stderr, "printing the levels failed: %v\n", err)
		return
	}
	if view.Preset == "" {
		fmt.Fprintln(env.Stdout, "\nThe lists switched on are not one of these levels.")
	}
	fmt.Fprintln(env.Stdout, "\nSwitch to one with: app-tail dns block level high")
	fmt.Fprintln(env.Stdout, "A level replaces the shipped lists that are on and leaves the ones you added alone.")
}

func runDNSBlockAdd(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block add", env)
	loc := addLocationFlags(fs)
	name := fs.String("name", "", "label for the list (required)")
	address := fs.String("url", "", "where to download it from (required)")
	format := fs.String("format", "auto", "how to read it: auto, hosts or abp")
	enable := fs.Bool("enable", true, "switch the list on once it is added")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns block add"); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return usagef("dns block add needs --name")
	}
	if strings.TrimSpace(*address) == "" {
		return usagef("dns block add needs --url")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	created, err := client.CreateDNSBlockList(ctx, config.Blocklist{
		Name: *name, URL: *address, Format: *format,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Added blocklist %s (%s): %s\n", created.Name, created.ID, created.URL)
	if !*enable {
		fmt.Fprintf(env.Stdout, "Switch it on with: app-tail dns block enable %s\n", created.ID)
		return nil
	}
	return switchDNSBlockList(ctx, client, env, created.ID, true)
}

func runDNSBlockRemove(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block rm", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("dns block rm takes exactly one list name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return err
	}
	list, err := resolveDNSBlockList(view.Lists, pos[0])
	if err != nil {
		return err
	}
	if list.BuiltIn {
		return fmt.Errorf("%q ships with app-tail and cannot be removed; switch it off instead", pos[0])
	}
	if err := client.DeleteDNSBlockList(ctx, list.ID); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed blocklist %s\n", list.Name)
	return nil
}

func runDNSBlockEnable(ctx context.Context, args []string, env Env, on bool) error {
	name := "dns block disable"
	if on {
		name = "dns block enable"
	}
	fs := newFlagSet(name, env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("%s takes exactly one list name or id", name)
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return err
	}
	list, err := resolveDNSBlockList(view.Lists, pos[0])
	if err != nil {
		return err
	}
	return switchDNSBlockList(ctx, client, env, list.ID, on)
}

// switchDNSBlockList adds or removes one id from dnsBlock.lists.
//
// The whole list is written rather than the one id, because the setting is a list and the
// registry replaces what it is given. Reading it back from the agent first is what keeps
// two terminals switching different lists on from each undoing the other's write.
func switchDNSBlockList(ctx context.Context, client *Client, env Env, id string, on bool) error {
	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return err
	}
	wanted := make([]string, 0, len(view.Lists)+1)
	for _, l := range view.Lists {
		switch {
		case l.ID == id:
			if on {
				wanted = append(wanted, l.ID)
			}
		case l.Enabled:
			wanted = append(wanted, l.ID)
		}
	}
	if on && !slices.Contains(wanted, id) {
		wanted = append(wanted, id)
	}

	encoded, err := json.Marshal(wanted)
	if err != nil {
		return fmt.Errorf("encode the list of blocklists: %w", err)
	}
	result, err := client.UpdateSettings(ctx, map[string]json.RawMessage{"dnsBlock.lists": encoded})
	if err != nil {
		return err
	}
	if on {
		fmt.Fprintf(env.Stdout, "%s is on. It downloads on the next pass; `app-tail dns block` "+
			"shows how many names it contributed.\n", id)
	} else {
		fmt.Fprintf(env.Stdout, "%s is off.\n", id)
	}
	noteRestart(env.Stdout, result)
	return nil
}

func runDNSBlockRefresh(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block refresh", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns block refresh"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.RefreshDNSBlock(ctx)
	if err != nil {
		return err
	}
	writeDNSBlock(env, view)
	return nil
}

func runDNSBlockPause(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block pause", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usagef("dns block pause takes one length, such as 15m")
	}
	length := 15 * time.Minute
	if len(pos) == 1 {
		length, err = time.ParseDuration(pos[0])
		if err != nil {
			return usagef("read %q as a length of time, such as 15m or 1h: %v", pos[0], err)
		}
	}
	minutes := int((length + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		return usagef("a pause lasts at least a minute")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.PauseDNSBlock(ctx, minutes)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Blocking is paused until %s.\n", localTime(view.PausedUntil))
	return nil
}

func runDNSBlockResume(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block resume", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dns block resume"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.ResumeDNSBlock(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Blocking is on again: %d names in force.\n", view.Rules)
	return nil
}

// runDNSBlockNames edits one of the two lists of names the user types: the ones never
// blocked and the ones always blocked.
func runDNSBlockNames(ctx context.Context, args []string, env Env, field, verb string) error {
	if len(args) == 0 {
		return usagef("dns block %s takes add or rm followed by a domain", verb)
	}
	sub, rest := args[0], args[1:]
	if sub != "add" && sub != "rm" {
		return usagef("unknown dns block %s command %q; use add or rm", verb, sub)
	}

	fs := newFlagSet("dns block "+verb+" "+sub, env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, rest)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("dns block %s %s takes exactly one domain", verb, sub)
	}
	name := strings.ToLower(strings.Trim(strings.TrimSpace(pos[0]), "."))
	if name == "" {
		return usagef("dns block %s %s takes exactly one domain", verb, sub)
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.DNSBlockState(ctx)
	if err != nil {
		return err
	}
	current := view.Allow
	if field == "dnsBlock.deny" {
		current = view.Deny
	}

	wanted := make([]string, 0, len(current)+1)
	for _, held := range current {
		if !strings.EqualFold(held, name) {
			wanted = append(wanted, held)
		}
	}
	if sub == "add" {
		wanted = append(wanted, name)
	} else if len(wanted) == len(current) {
		return fmt.Errorf("%s is not on the %s list", name, verb)
	}

	encoded, err := json.Marshal(wanted)
	if err != nil {
		return fmt.Errorf("encode the %s list: %w", verb, err)
	}
	result, err := client.UpdateSettings(ctx, map[string]json.RawMessage{field: encoded})
	if err != nil {
		return err
	}
	if sub == "add" {
		fmt.Fprintf(env.Stdout, "%s is on the %s list.\n", name, verb)
	} else {
		fmt.Fprintf(env.Stdout, "%s is off the %s list.\n", name, verb)
	}
	noteRestart(env.Stdout, result)
	return nil
}

func runDNSBlockCheck(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dns block check", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("dns block check takes exactly one name")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	result, err := client.CheckDNSBlock(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, result)
	}
	if result.Blocked {
		fmt.Fprintf(env.Stdout, "%s is blocked: %s\n", result.Name, result.Reason)
		return nil
	}
	fmt.Fprintf(env.Stdout, "%s is not blocked: %s\n", result.Name, result.Reason)
	return nil
}

// resolveDNSBlockList accepts an id or a name. A name matching more than one list is
// refused rather than guessed at.
func resolveDNSBlockList(lists []httpapi.DNSBlockListView, wanted string) (httpapi.DNSBlockListView, error) {
	for _, l := range lists {
		if l.ID == wanted {
			return l, nil
		}
	}

	var matches []httpapi.DNSBlockListView
	for _, l := range lists {
		if strings.EqualFold(l.Name, wanted) {
			matches = append(matches, l)
		}
	}
	switch len(matches) {
	case 0:
		return httpapi.DNSBlockListView{}, fmt.Errorf("no blocklist called %q; `app-tail dns block list` shows them", wanted)
	case 1:
		return matches[0], nil
	}
	ids := make([]string, 0, len(matches))
	for _, l := range matches {
		ids = append(ids, l.ID)
	}
	return httpapi.DNSBlockListView{}, fmt.Errorf("more than one blocklist is called %q; name one by id: %s",
		wanted, strings.Join(ids, ", "))
}
