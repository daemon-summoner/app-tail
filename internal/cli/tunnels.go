// SPDX-License-Identifier: MIT

package cli

// Connections from a terminal: every private network this machine is attached to, and the
// whole of adding, importing, changing and removing one.
//
// It exists because a machine with no dashboard had no supported way to do any of that.
// Every subcommand goes through the same agent endpoints the dashboard uses, so a
// connection made here and one made there are the same connection made the same way --
// and a refusal reads the same sentence in both places.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// Tunnels lists every configured connection with its live status.
func (c *Client) Tunnels(ctx context.Context) ([]httpapi.TunnelView, error) {
	var out struct {
		Tunnels []httpapi.TunnelView `json:"tunnels"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/tunnels", nil, &out); err != nil {
		return nil, err
	}
	return out.Tunnels, nil
}

// Tunnel returns one connection with its live status.
func (c *Client) Tunnel(ctx context.Context, id string) (httpapi.TunnelView, error) {
	var out httpapi.TunnelView
	err := c.do(ctx, http.MethodGet, "/api/tunnels/"+url.PathEscape(id), nil, &out)
	return out, err
}

// TunnelSchema is the connection form's fields and the kinds of network one can be added
// as, resolved against this installation. The CLI asks the agent rather than reading its
// own compiled-in copy, so a field gated off on this machine says so instead of being
// offered and then refused.
func (c *Client) TunnelSchema(ctx context.Context) (httpapi.TunnelSchemaView, error) {
	var out httpapi.TunnelSchemaView
	err := c.do(ctx, http.MethodGet, "/api/tunnels/schema", nil, &out)
	return out, err
}

// CreateTunnel adds a connection of the given kind.
func (c *Client) CreateTunnel(ctx context.Context, spec httpapi.TunnelSpec) (httpapi.TunnelView, error) {
	var out httpapi.TunnelView
	err := c.do(ctx, http.MethodPost, "/api/tunnels", spec, &out)
	return out, err
}

// UpdateTunnel writes the fields the patch carries, leaving absent ones untouched.
func (c *Client) UpdateTunnel(ctx context.Context, id string, patch map[string]json.RawMessage) (httpapi.TunnelView, error) {
	var out httpapi.TunnelView
	err := c.do(ctx, http.MethodPut, "/api/tunnels/"+url.PathEscape(id), patch, &out)
	return out, err
}

// DeleteTunnel removes a connection and stops it.
func (c *Client) DeleteTunnel(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/tunnels/"+url.PathEscape(id), nil, nil)
}

// ImportTunnel replaces one connection's settings with the configuration file its server
// issued.
func (c *Client) ImportTunnel(ctx context.Context, id, file string) (httpapi.TunnelView, error) {
	var out httpapi.TunnelView
	err := c.do(ctx, http.MethodPost, "/api/tunnels/"+url.PathEscape(id)+"/import",
		httpapi.TunnelImport{File: file}, &out)
	return out, err
}

// RetryTunnel builds one connection again now.
func (c *Client) RetryTunnel(ctx context.Context, id string) (httpapi.TunnelView, error) {
	var out httpapi.TunnelView
	err := c.do(ctx, http.MethodPost, "/api/tunnels/"+url.PathEscape(id)+"/retry", nil, &out)
	return out, err
}

// runConnection dispatches the connection subcommands. Bare `connection` lists them,
// which is the most common thing to want and the thing every other subcommand needs a
// name from.
func runConnection(ctx context.Context, args []string, env Env) error {
	sub := "list"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest = args[0], args[1:]
	}
	switch sub {
	case "list":
		return runConnectionList(ctx, rest, env)
	case "get":
		return runConnectionGet(ctx, rest, env)
	case "add":
		return runConnectionAdd(ctx, rest, env)
	case "set":
		return runConnectionSet(ctx, rest, env)
	case "import":
		return runConnectionImport(ctx, rest, env)
	case "rm":
		return runConnectionRemove(ctx, rest, env)
	case "enable":
		return runConnectionEnabled(ctx, rest, env, true)
	case "disable":
		return runConnectionEnabled(ctx, rest, env, false)
	case "retry":
		return runConnectionRetry(ctx, rest, env)
	default:
		return usagef("unknown connection command %q; use list, get, add, set, import, rm, "+
			"enable, disable or retry", sub)
	}
}

func runConnectionList(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("connection list", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "connection list"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	tunnels, err := client.Tunnels(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		if tunnels == nil {
			tunnels = []httpapi.TunnelView{}
		}
		return writeJSON(env, tunnels)
	}
	if len(tunnels) == 0 {
		fmt.Fprintln(env.Stdout, "No connections configured. Add one with "+
			"`app-tail connection add --type wireguard`.")
		return nil
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tNAME\tKIND\tADDRESSES\tSTATE")
	for _, t := range tunnels {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Name, t.TypeLabel, orDash(strings.Join(t.Addrs, ", ")), tunnelState(t))
	}
	return writer.Flush()
}

// tunnelState renders the state column, folding in the reason a connection is not
// carrying so a broken one never shows as a bare "failed".
func tunnelState(t httpapi.TunnelView) string {
	if !t.Enabled {
		return "disabled"
	}
	if t.Detail != "" {
		return t.StateLabel + ": " + t.Detail
	}
	if t.StateLabel == "" {
		return "pending"
	}
	return t.StateLabel
}

// orDash renders an empty column as a dash. A blank cell in a table reads as a value that
// failed to load rather than as one there is none of.
func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func runConnectionGet(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("connection get", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("connection get takes exactly one connection name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := findTunnel(ctx, client, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}

	rows := [][2]string{
		{"Name", view.Name},
		{"ID", view.ID},
		{"Kind", view.TypeLabel},
		{"Slug", view.Slug},
		{"State", tunnelState(view)},
		{"Addresses", strings.Join(view.Addrs, ", ")},
		{"Names", strings.Join(view.Names, ", ")},
	}
	if view.AuthURL != "" {
		rows = append(rows, [2]string{"Login URL", view.AuthURL})
	}
	if h := view.Health; h != nil {
		rows = append(rows,
			[2]string{"Carried", fmt.Sprintf("%s sent, %s received", formatBytes(h.Up), formatBytes(h.Down))})
		if !h.Since.IsZero() {
			rows = append(rows, [2]string{"Up for", formatSince(h.Since)})
		}
		if !h.LastHandshake.IsZero() {
			rows = append(rows, [2]string{"Last handshake", formatSince(h.LastHandshake) + " ago"})
		}
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		if row[1] == "" {
			continue
		}
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	for _, limit := range view.Limits {
		fmt.Fprintf(env.Stdout, "  note: %s\n", limit)
	}

	// The settings follow the status because the question that brings somebody here is
	// usually what the connection is doing, and the answer to what it is configured with is
	// the longer half.
	schema, err := client.TunnelSchema(ctx)
	if err != nil {
		return err
	}
	fields := fieldsForTunnel(schema.Fields, view.Type)
	if len(fields) == 0 {
		return nil
	}
	fmt.Fprintln(env.Stdout)
	settings := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(settings, "SETTING\tVALUE\tNOTES")
	for _, f := range fields {
		fmt.Fprintf(settings, "%s\t%s\t%s\n", settingName(f), renderValue(f, view.Settings), fieldNotes(f))
	}
	return settings.Flush()
}

// fieldsForTunnel is the fields that apply to one kind of connection, in schema order. A
// field of another protocol is left out rather than shown empty: it is not a setting this
// connection has, and printing it blank invites somebody to try to set it.
func fieldsForTunnel(fields []config.FieldSchema, kind config.TunnelType) []config.FieldSchema {
	var out []config.FieldSchema
	for _, f := range fields {
		if f.Variant == "" || f.Variant == string(kind) {
			out = append(out, f)
		}
	}
	return out
}

// fieldNotes summarizes what a caller has to know about a field before writing it. A
// field the installation has gated off carries the agent's own reason, which is the one
// thing that explains a value somebody cannot change.
func fieldNotes(f config.FieldSchema) string {
	var notes []string
	if f.Available != nil && !*f.Available {
		notes = append(notes, orElse(f.AvailableReason, "not available on this machine"))
	}
	if f.ReadOnly {
		notes = append(notes, "read-only")
	}
	if f.Secret {
		notes = append(notes, "secret; set it with --value-file")
	}
	if f.Restart == config.RestartNode {
		notes = append(notes, "change needs a node restart")
	}
	return strings.Join(notes, ", ")
}

func orElse(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func runConnectionAdd(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("connection add", env)
	loc := addLocationFlags(fs)
	var (
		kind     = fs.String("type", "", "kind of network to add, e.g. wireguard or openvpn (required)")
		name     = fs.String("name", "", "label for this connection; the kind's own name when omitted")
		slug     = fs.String("slug", "", "DNS label this connection answers for; derived from the name when omitted")
		fromFile = fs.String("from-file", "", "configuration file the server issued, imported once the connection exists")
		disabled = fs.Bool("disabled", false, "add the connection without bringing it up")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "connection add"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	// The kinds are the agent's answer, so both the refusal and the missing-flag message
	// name what this installation can actually bring up rather than what the CLI was
	// compiled believing.
	schema, err := client.TunnelSchema(ctx)
	if err != nil {
		return err
	}
	if err := checkTunnelType(strings.TrimSpace(*kind), schema.Types); err != nil {
		return err
	}

	// Read before anything is created, so an unreadable file leaves no half-made
	// connection behind for somebody to find and wonder about.
	var file string
	if *fromFile != "" {
		file, err = readImportFile(*fromFile)
		if err != nil {
			return err
		}
	}

	created, err := client.CreateTunnel(ctx, httpapi.TunnelSpec{
		Type: config.TunnelType(*kind),
		Name: strings.TrimSpace(*name),
		Slug: strings.TrimSpace(*slug),
	})
	if err != nil {
		return err
	}

	// Switched off before the file lands rather than after: a connection is added running,
	// and the point of --disabled is that this one never dials.
	if *disabled {
		created, err = setTunnelEnabled(ctx, client, created.ID, false)
		if err != nil {
			return err
		}
	}
	if file != "" {
		created, err = client.ImportTunnel(ctx, created.ID, file)
		if err != nil {
			return err
		}
	}

	fmt.Fprintf(env.Stdout, "Added %s (%s), a %s connection.\n", created.Name, created.ID, created.TypeLabel)
	if file != "" {
		fmt.Fprintf(env.Stdout, "  Imported %s.\n", *fromFile)
	}
	switch {
	case !created.Enabled:
		fmt.Fprintf(env.Stdout, "  It is switched off; run `app-tail connection enable %s` when you want it up.\n", created.ID)
	case created.Detail != "":
		fmt.Fprintf(env.Stdout, "  It is not carrying yet: %s\n", created.Detail)
	}
	return nil
}

// checkTunnelType refuses a kind this build cannot bring up, naming the ones it can. The
// list comes from the agent, so it is this installation's answer rather than a compiled-in
// guess about the machine the CLI happens to be running on.
func checkTunnelType(kind string, types []httpapi.TunnelTypeInfo) error {
	offered := make([]string, 0, len(types))
	for _, t := range types {
		if kind != "" && string(t.Value) == kind {
			return nil
		}
		offered = append(offered, string(t.Value))
	}
	if len(offered) == 0 {
		return fmt.Errorf("this build offers no kind of connection to add")
	}
	if kind == "" {
		return usagef("connection add needs --type; this build can add %s", strings.Join(offered, ", "))
	}
	return usagef("%q is not a kind of connection this build can add; it offers %s",
		kind, strings.Join(offered, ", "))
}

func runConnectionSet(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("connection set", env)
	loc := addLocationFlags(fs)
	var (
		valueFile  = fs.String("value-file", "", "read the value from this file instead of the command line")
		valueStdin = fs.Bool("value-stdin", false, "read the value from standard input instead of the command line")
	)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	fromElsewhere := *valueFile != "" || *valueStdin
	if *valueFile != "" && *valueStdin {
		return usagef("connection set takes --value-file or --value-stdin, not both")
	}
	switch {
	case fromElsewhere && len(pos) != 2:
		return usagef("connection set takes a connection and a setting name when the value comes from a file or standard input")
	case !fromElsewhere && len(pos) != 3:
		return usagef("connection set takes a connection, a setting name and a value")
	}
	wanted, key := pos[0], pos[1]

	field, ok := config.TunnelFieldByName(key)
	if !ok {
		return usagef("unknown connection setting %q; run `app-tail connection get NAME` to see them", key)
	}
	// Read-only, deprecated and unavailable fields are refused by the agent's own patch
	// decoder rather than here. That refusal carries the replacement for a field kept only
	// to answer callers who still name it, and a second copy of the rule here would
	// eventually give a worse answer than the one it duplicates.
	//
	// A secret in argv is readable by every process on the machine and lands in the shell
	// history of the person who typed it, so it is refused rather than accepted with a
	// warning.
	if field.Secret && !fromElsewhere {
		return usagef("%s is a secret; pass it with --value-file FILE or --value-stdin so it is never placed in a command line", key)
	}

	value := ""
	switch {
	case *valueFile != "":
		raw, err := os.ReadFile(*valueFile)
		if err != nil {
			return fmt.Errorf("read the value: %w", err)
		}
		value = strings.TrimRight(string(raw), "\r\n")
	case *valueStdin:
		raw, err := io.ReadAll(env.Stdin)
		if err != nil {
			return fmt.Errorf("read the value from standard input: %w", err)
		}
		value = strings.TrimRight(string(raw), "\r\n")
	default:
		value = pos[2]
	}

	wire, parsed, err := config.ParseTunnelValue(key, value)
	if err != nil {
		return usagef("%s: %v", key, err)
	}
	raw, err := json.Marshal(parsed)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := findTunnel(ctx, client, wanted)
	if err != nil {
		return err
	}
	updated, err := client.UpdateTunnel(ctx, view.ID, map[string]json.RawMessage{wire: raw})
	if err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "Updated %s on %s.\n", key, updated.Name)
	if field.Restart == config.RestartNode {
		fmt.Fprintln(env.Stdout, "  A node restart is needed to apply this; run `app-tail restart`.")
	}
	if updated.Detail != "" {
		fmt.Fprintf(env.Stdout, "  It is not carrying: %s\n", updated.Detail)
	}
	return nil
}

func runConnectionImport(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("connection import", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usagef("connection import takes a connection name or id and a configuration file")
	}

	file, err := readImportFile(pos[1])
	if err != nil {
		return err
	}
	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := findTunnel(ctx, client, pos[0])
	if err != nil {
		return err
	}
	imported, err := client.ImportTunnel(ctx, view.ID, file)
	if err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "Imported %s into %s.\n", pos[1], imported.Name)
	if imported.Detail != "" {
		fmt.Fprintf(env.Stdout, "  It is not carrying: %s\n", imported.Detail)
	}
	return nil
}

// readImportFile reads a configuration file a server issued. It is refused empty here
// rather than sent on, because the agent's answer to an empty file is that it names no
// server -- true, and no help at all to somebody who pointed at the wrong path.
func readImportFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the configuration file: %w", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return "", fmt.Errorf("%s is empty, so it describes no connection", path)
	}
	return string(raw), nil
}

func runConnectionRemove(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("connection rm", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("connection rm takes exactly one connection name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := findTunnel(ctx, client, pos[0])
	if err != nil {
		return err
	}
	if err := client.DeleteTunnel(ctx, view.ID); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed %s.\n", view.Name)
	return nil
}

func runConnectionEnabled(ctx context.Context, args []string, env Env, enabled bool) error {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	fs := newFlagSet("connection "+verb, env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("connection %s takes exactly one connection name or id", verb)
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := findTunnel(ctx, client, pos[0])
	if err != nil {
		return err
	}
	updated, err := setTunnelEnabled(ctx, client, view.ID, enabled)
	if err != nil {
		return err
	}

	if !enabled {
		fmt.Fprintf(env.Stdout, "Switched %s off.\n", updated.Name)
		return nil
	}
	fmt.Fprintf(env.Stdout, "Switched %s on; it is %s.\n", updated.Name, tunnelState(updated))
	return nil
}

func setTunnelEnabled(ctx context.Context, client *Client, id string, enabled bool) (httpapi.TunnelView, error) {
	raw, err := json.Marshal(enabled)
	if err != nil {
		return httpapi.TunnelView{}, fmt.Errorf("encode enabled: %w", err)
	}
	return client.UpdateTunnel(ctx, id, map[string]json.RawMessage{"enabled": raw})
}

func runConnectionRetry(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("connection retry", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("connection retry takes exactly one connection name or id")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := findTunnel(ctx, client, pos[0])
	if err != nil {
		return err
	}
	// The reply describes the attempt this command asked for rather than the state before
	// it, so what is printed is what happened.
	built, err := client.RetryTunnel(ctx, view.ID)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Built %s again; it is %s.\n", built.Name, tunnelState(built))
	return nil
}

// findTunnel resolves what somebody typed against the connections the agent has.
func findTunnel(ctx context.Context, client *Client, wanted string) (httpapi.TunnelView, error) {
	tunnels, err := client.Tunnels(ctx)
	if err != nil {
		return httpapi.TunnelView{}, err
	}
	return resolveTunnel(tunnels, wanted)
}

// resolveTunnel accepts an id, a slug or a name. An ambiguous name is refused rather than
// resolved arbitrarily: the commands that take one remove connections and rewrite their
// settings, and neither is recoverable from the CLI.
func resolveTunnel(tunnels []httpapi.TunnelView, wanted string) (httpapi.TunnelView, error) {
	for _, t := range tunnels {
		if t.ID == wanted || t.Slug == wanted {
			return t, nil
		}
	}

	var matches []httpapi.TunnelView
	for _, t := range tunnels {
		if strings.EqualFold(t.Name, wanted) {
			matches = append(matches, t)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return httpapi.TunnelView{}, fmt.Errorf(
			"no connection named %q; run `app-tail connection list` to see them", wanted)
	default:
		ids := make([]string, 0, len(matches))
		for _, t := range matches {
			ids = append(ids, t.ID)
		}
		return httpapi.TunnelView{}, fmt.Errorf(
			"%d connections are named %q; name one by id instead (%s)",
			len(matches), wanted, strings.Join(ids, ", "))
	}
}

// byteUnits are the suffixes formatBytes steps through, each 1024 times the last.
var byteUnits = []string{"KB", "MB", "GB", "TB", "PB"}

// formatBytes renders a byte count the way the dashboard does, so the same connection
// reads the same on both surfaces.
func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n) / 1024
	unit := 0
	for value >= 1024 && unit < len(byteUnits)-1 {
		value /= 1024
		unit++
	}
	if value < 10 {
		return fmt.Sprintf("%.1f %s", value, byteUnits[unit])
	}
	return fmt.Sprintf("%.0f %s", value, byteUnits[unit])
}

// formatSince is how long ago a served moment was, to one unit. A moment in the future --
// which a clock that moved makes possible -- reads as no time at all rather than as a
// negative duration.
func formatSince(at time.Time) string {
	elapsed := time.Since(at)
	switch {
	case elapsed < time.Minute:
		return fmt.Sprintf("%ds", max(int(elapsed.Seconds()), 0))
	case elapsed < time.Hour:
		return fmt.Sprintf("%dm", int(elapsed.Minutes()))
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("%dh", int(elapsed.Hours()))
	default:
		return fmt.Sprintf("%dd", int(elapsed.Hours())/24)
	}
}
