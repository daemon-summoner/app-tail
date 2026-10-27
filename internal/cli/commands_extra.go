// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/licenses"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// runForward dispatches the per-forward subcommands.
func runForward(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usagef("forward needs a subcommand: get, update, enable, disable or toggle")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "get":
		return runForwardGet(ctx, rest, env)
	case "update":
		return runForwardUpdate(ctx, rest, env)
	case "enable":
		return runForwardSetEnabled(ctx, rest, env, true)
	case "disable":
		return runForwardSetEnabled(ctx, rest, env, false)
	case "toggle":
		return runForwardToggle(ctx, rest, env)
	default:
		return usagef("unknown forward command %q; use get, update, enable, disable or toggle", sub)
	}
}

// resolveOneForward finds the forward a name-or-id argument refers to on the agent.
func resolveOneForward(ctx context.Context, client *Client, wanted string) (string, error) {
	forwards, err := client.Forwards(ctx)
	if err != nil {
		return "", err
	}
	return resolveForward(forwards, wanted)
}

func runForwardGet(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("forward get", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the forward as JSON")
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("forward get takes exactly one forward name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	id, err := resolveOneForward(ctx, client, pos[0])
	if err != nil {
		return err
	}
	view, err := client.GetForward(ctx, id)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}
	return printForward(env, view)
}

func runForwardUpdate(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("forward update", env)
	loc := addLocationFlags(fs)
	var (
		name       = fs.String("name", "", "new label for this forward")
		connection = fs.String("connection", "", "id of the connection this forward crosses")
		target     = fs.String("target", "", "new HOST:PORT to send traffic to")
		port       = fs.Int("port", 0, "new local port to listen on")
		bindAddr   = fs.String("bind", "", "new address to listen on")
		protocol   = fs.String("protocol", "", "tcp, udp, or both")
		direction  = fs.String("direction", "", "to_local or to_tailnet")
		udpTimeout = fs.Int("udp-timeout", 0, "idle seconds before a UDP session is evicted")
		enabled    = fs.Bool("enabled", false, "whether the forward is running")
		expose     = fs.Bool("expose", false, "whether other machines on your network may use this forward")
	)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("forward update takes exactly one forward name or id")
	}

	var spec httpapi.ForwardSpec
	changed := false
	if wasSet(fs, "name") {
		spec.Name, changed = name, true
	}
	if wasSet(fs, "connection") {
		spec.TunnelID, changed = connection, true
	}
	if wasSet(fs, "target") {
		spec.Target, changed = target, true
	}
	if wasSet(fs, "port") {
		spec.ListenPort, changed = port, true
	}
	if wasSet(fs, "bind") {
		spec.BindAddr, changed = bindAddr, true
	}
	if wasSet(fs, "protocol") {
		spec.Protocol, changed = ptr(config.Protocol(*protocol)), true
	}
	if wasSet(fs, "direction") {
		spec.Direction, changed = ptr(config.Direction(*direction)), true
	}
	if wasSet(fs, "udp-timeout") {
		spec.UDPTimeoutSec, changed = udpTimeout, true
	}
	if wasSet(fs, "enabled") {
		spec.Enabled, changed = enabled, true
	}
	if wasSet(fs, "expose") {
		spec.ExposeToNetwork, changed = expose, true
	}
	if !changed {
		return usagef("forward update needs at least one field flag to change")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	id, err := resolveOneForward(ctx, client, pos[0])
	if err != nil {
		return err
	}
	updated, err := client.UpdateForward(ctx, id, spec)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Updated %s (%s)\n", updated.Name, updated.ID)
	return printForward(env, updated)
}

// runForwardSetEnabled backs both `forward enable` and `forward disable`.
func runForwardSetEnabled(ctx context.Context, args []string, env Env, enabled bool) error {
	verb, done := "enable", "Enabled"
	if !enabled {
		verb, done = "disable", "Disabled"
	}
	fs := newFlagSet("forward "+verb, env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("forward %s takes exactly one forward name or id", verb)
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	id, err := resolveOneForward(ctx, client, pos[0])
	if err != nil {
		return err
	}
	updated, err := client.ToggleForward(ctx, id, enabled)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s %s (%s); it is now %s.\n", done, updated.Name, updated.ID, forwardState(updated))
	return nil
}

func runForwardToggle(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("forward toggle", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("forward toggle takes exactly one forward name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	id, err := resolveOneForward(ctx, client, pos[0])
	if err != nil {
		return err
	}
	current, err := client.GetForward(ctx, id)
	if err != nil {
		return err
	}
	updated, err := client.ToggleForward(ctx, id, !current.Enabled)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s (%s) is now %s.\n", updated.Name, updated.ID, forwardState(updated))
	return nil
}

// printForward renders one forward's configuration and live status. A failed flush
// means the output the operator is reading is truncated, so it is reported rather
// than dropped.
func printForward(env Env, f httpapi.ForwardView) error {
	rows := [][2]string{
		{"ID", f.ID},
		{"Name", f.Name},
		{"Connection", f.TunnelID},
		{"Direction", string(f.Direction)},
		{"Protocol", string(f.Protocol)},
		{"Listens on", f.Endpoint},
		{"Target", f.Target},
		{"State", forwardState(f)},
		// A forward listening beyond this machine reports itself running, because it is:
		// the sentence is the only place that fact appears.
		{"Warning", f.Warning},
	}
	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		if row[1] == "" {
			continue
		}
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	return writer.Flush()
}

func runPeers(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("peers", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the peers as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "peers"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	peers, err := client.Peers(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		if peers == nil {
			peers = []tsnode.Peer{}
		}
		return writeJSON(env, peers)
	}
	if len(peers) == 0 {
		fmt.Fprintln(env.Stdout, "No peers are visible. Log in and connect first with `app-tail login`.")
		return nil
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "HOSTNAME\tADDRESS\tOS\tSTATE\tTAGS")
	type note struct{ label, reason string }
	var notes []note
	for _, p := range peers {
		address := p.DNSName
		if address == "" && len(p.IPs) > 0 {
			address = p.IPs[0]
		}
		reach := peerReachOf(p)
		if reach.Reason != "" {
			notes = append(notes, note{p.Label(), reach.Reason})
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
			p.HostName, address, p.OS, reach.State, strings.Join(p.Tags, ", "))
	}
	// The state word alone says a device is not usable; only the sentence says what to do
	// about it, and printing it per row would push the table past a terminal's width.
	// These carry no tabs, so the writer passes them through instead of aligning them
	// into the columns above.
	for _, n := range notes {
		fmt.Fprintf(writer, "\n%s: %s\n", n.label, n.reason)
	}
	return writer.Flush()
}

// peerReachOf is the agent's verdict about a device, or the best one this CLI can give
// without it.
//
// The CLI and the agent are routinely different builds -- the copy on PATH and the copy
// inside the installed app drift apart between rebuilds -- so an agent that predates the
// verdict has to degrade to what it does report. Printing its empty string would mark
// every device on the tailnet as a problem with nothing to say about any of them.
func peerReachOf(p tsnode.Peer) tsnode.PeerReach {
	if p.Reach.State != "" {
		return p.Reach
	}
	// No reason to carry: the agent that sent this never derived one.
	return tsnode.PeerReach{State: p.Reach.State.Or(p.Online)}
}

// runPreset dispatches the service-template subcommands.
func runPreset(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usagef("preset needs a subcommand: list, add or rm")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runPresetList(ctx, rest, env)
	case "add":
		return runPresetAdd(ctx, rest, env)
	case "rm":
		return runPresetRemove(ctx, rest, env)
	default:
		return usagef("unknown preset command %q; use list, add or rm", sub)
	}
}

func runPresetList(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("preset list", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the presets as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "preset list"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	presets, err := client.Presets(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		if presets == nil {
			presets = []config.Preset{}
		}
		return writeJSON(env, presets)
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tNAME\tPROTOCOL\tREMOTE PORT\tSOURCE")
	for _, p := range presets {
		source := "user"
		if p.BuiltIn {
			source = "built-in"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%d\t%s\n", p.ID, p.Name, p.Protocol, p.RemotePort, source)
	}
	return writer.Flush()
}

func runPresetAdd(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("preset add", env)
	loc := addLocationFlags(fs)
	name := fs.String("name", "", "label for the preset (required)")
	protocol := fs.String("protocol", string(config.TCP), "tcp, udp, or both")
	port := fs.Int("port", 0, "remote port the preset connects to (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "preset add"); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return usagef("preset add needs --name")
	}
	if *port == 0 {
		return usagef("preset add needs --port")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	created, err := client.CreatePreset(ctx, config.Preset{
		Name:       *name,
		Protocol:   config.Protocol(*protocol),
		RemotePort: *port,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Added preset %s (%s): %s port %d\n",
		created.Name, created.ID, created.Protocol, created.RemotePort)
	return nil
}

func runPresetRemove(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("preset rm", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("preset rm takes exactly one preset name or id")
	}
	wanted := pos[0]

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	presets, err := client.Presets(ctx)
	if err != nil {
		return err
	}
	id, err := resolvePreset(presets, wanted)
	if err != nil {
		return err
	}
	if err := client.DeletePreset(ctx, id); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed preset %s\n", wanted)
	return nil
}

// resolvePreset accepts an id or a name, refusing built-ins and ambiguous names so a
// destructive call never guesses.
func resolvePreset(presets []config.Preset, wanted string) (string, error) {
	for _, p := range presets {
		if p.ID == wanted {
			if p.BuiltIn {
				return "", fmt.Errorf("%q is a built-in preset and cannot be removed", wanted)
			}
			return p.ID, nil
		}
	}

	var matches []config.Preset
	for _, p := range presets {
		if !p.BuiltIn && strings.EqualFold(p.Name, wanted) {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].ID, nil
	case 0:
		return "", fmt.Errorf("no user preset named %q; run `app-tail preset list` to see them", wanted)
	default:
		ids := make([]string, 0, len(matches))
		for _, p := range matches {
			ids = append(ids, p.ID)
		}
		return "", fmt.Errorf("%d presets are named %q; remove one by id instead (%s)",
			len(matches), wanted, strings.Join(ids, ", "))
	}
}

// runAutostart reports whether the login item is installed. Installing and removing it
// stay with `install-autostart`, which is where the offline management already lives.
func runAutostart(ctx context.Context, args []string, env Env) error {
	sub := "status"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest = args[0], args[1:]
	}
	if sub != "status" {
		return usagef("unknown autostart command %q; use status", sub)
	}
	return runAutostartStatus(ctx, rest, env)
}

func runAutostartStatus(_ context.Context, args []string, env Env) error {
	fs := newFlagSet("autostart status", env)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "autostart status"); err != nil {
		return err
	}

	manager, err := loginItem(env)
	if err != nil {
		return err
	}
	enabled, err := manager.Enabled()
	if err != nil {
		return err
	}
	if enabled {
		fmt.Fprintf(env.Stdout, "app-tail starts at login.\n  %s: %s\n", manager.Kind(), manager.Path())
		stale, err := manager.NeedsReinstall()
		if err != nil {
			return err
		}
		if stale {
			fmt.Fprintln(env.Stdout, manager.ReinstallReason()+
				" Run `app-tail install-autostart` to correct it.")
		}
		return nil
	}
	fmt.Fprintln(env.Stdout, "app-tail does not start at login. Enable it with `app-tail install-autostart`.")
	return nil
}

// runHealth reports whether the agent is ready to carry traffic, exiting non-zero
// when it is not. It exists so a container healthcheck, a monitoring probe and an
// operator at a shell all ask the same question the dashboard does -- and so the
// probe finds the agent through Discover rather than a hardcoded port, which under
// `network_mode: host` would otherwise check whichever app-tail owns 8377.
func runHealth(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("health", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "health"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := writeJSON(env, health); err != nil {
			return err
		}
		if !health.Healthy {
			return errors.New(healthReason(health))
		}
		return nil
	}

	if health.Healthy {
		if health.BackendState != "" {
			fmt.Fprintf(env.Stdout, "healthy (%s)\n", health.BackendState)
		} else {
			fmt.Fprintln(env.Stdout, "healthy")
		}
		return nil
	}
	// Returned rather than printed, so the process exits non-zero: a healthcheck that
	// reports the reason and still exits 0 is worse than no healthcheck.
	return errors.New(healthReason(health))
}

func healthReason(h HealthView) string {
	reason := h.Reason
	if reason == "" {
		reason = "the agent did not say why"
	}
	if h.BackendState != "" {
		return fmt.Sprintf("unhealthy: %s (%s)", reason, h.BackendState)
	}
	return "unhealthy: " + reason
}

// runLicenses prints the third-party notices this binary is required to carry. They
// are embedded, so they survive the archive being deleted.
//
// Wintun's is printed on every platform even though only Windows loads it. The notice
// covers a file the Windows archive ships, and a Windows user reading it in a console is
// the case it exists for; leaving it out of the other builds would mean the answer to
// "what is in this" differs by which binary you happen to have.
func runLicenses(_ context.Context, args []string, env Env) error {
	fs := newFlagSet("licenses", env)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "licenses"); err != nil {
		return err
	}
	fmt.Fprint(env.Stdout, licenses.ThirdParty())
	fmt.Fprintf(env.Stdout, "\n\n%s\n%s\n%s\n\n",
		strings.Repeat("=", 80), "wintun.dll (shipped beside the Windows binary, not linked into it)", strings.Repeat("=", 80))
	fmt.Fprint(env.Stdout, licenses.WintunNotice())
	return nil
}
