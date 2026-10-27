// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/sellitus/app-tail/internal/config"
)

// runSettings dispatches the settings subcommands. Bare `settings` lists current
// values, which is the most common thing to want.
func runSettings(ctx context.Context, args []string, env Env) error {
	sub := "list"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest = args[0], args[1:]
	}
	switch sub {
	case "list":
		return runSettingsList(ctx, rest, env)
	case "get":
		return runSettingsGet(ctx, rest, env)
	case "set":
		return runSettingsSet(ctx, rest, env)
	case "menu":
		return runSettingsMenu(ctx, rest, env)
	default:
		return usagef("unknown settings command %q; use get, list, set or menu", sub)
	}
}

func runSettingsList(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("settings list", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the settings as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "settings list"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.Settings(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "SETTING\tVALUE\tNOTES")
	for _, s := range config.SettingsCLISchema() {
		fmt.Fprintf(writer, "%s\t%s\t%s\n", settingName(s), renderValue(s, view), settingNotes(s))
	}
	return writer.Flush()
}

func runSettingsGet(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("settings get", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the value as JSON")
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("settings get takes exactly one setting name")
	}
	schema, ok := config.SettingByName(pos[0])
	if !ok {
		return usagef("unknown setting %q; run `app-tail settings list` to see them", pos[0])
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.Settings(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view[schema.ViewKey])
	}
	fmt.Fprintln(env.Stdout, renderValue(schema, view))
	return nil
}

func runSettingsSet(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("settings set", env)
	loc := addLocationFlags(fs)
	// A flag per settable field lets `settings set --udp-timeout=120 --show-tray=true`
	// change several at once; the two-positional form handles the single-value case.
	fieldFlags := map[string]*string{}
	for _, f := range config.SettingsCLISchema() {
		if f.Write != config.WritePatch || f.CLIName == "" {
			continue
		}
		fieldFlags[f.CLIName] = fs.String(f.CLIName, "", f.Help)
	}
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}

	patch := map[string]json.RawMessage{}
	switch len(pos) {
	case 0:
	case 2:
		if err := addSetting(patch, pos[0], pos[1]); err != nil {
			return err
		}
	default:
		return usagef("settings set takes a <key> <value> pair or --<name>=<value> flags")
	}
	for name, valPtr := range fieldFlags {
		if !wasSet(fs, name) {
			continue
		}
		if err := addSetting(patch, name, *valPtr); err != nil {
			return err
		}
	}
	if len(patch) == 0 {
		return usagef("settings set needs a setting to change; run `app-tail settings list` to see them")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	result, err := client.UpdateSettings(ctx, patch)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Updated settings.")
	warnPinned(env.Stdout, patch, result.View)
	noteRestart(env.Stdout, result)
	return nil
}

// addSetting resolves key (a CLI name or JSON key), rejects the writes that must not
// go through a patch, parses the value, and records it.
func addSetting(patch map[string]json.RawMessage, key, value string) error {
	field, ok := config.SettingByName(key)
	if !ok {
		return usagef("unknown setting %q; run `app-tail settings list` to see them", key)
	}
	if field.Write == config.WriteNone {
		return usagef("%s is read-only", key)
	}
	if field.Write == config.WriteAutostart {
		return usagef("%s is managed with `app-tail install-autostart`", key)
	}
	if field.Secret {
		return usagef("%s is a secret; set it with `app-tail settings menu` so it is never placed in a command line", key)
	}
	wire, v, err := config.ParseSettingValue(key, value)
	if err != nil {
		return usagef("%s: %v", key, err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	patch[wire] = raw
	return nil
}

// warnPinned reports any changed field whose effective value did not move, which
// happens when an environment variable or flag pins it above the stored config.
func warnPinned(out io.Writer, patch map[string]json.RawMessage, view map[string]any) {
	for _, f := range config.SettingsCLISchema() {
		raw, ok := patch[f.Key]
		// A secret's value is never echoed back, so there is nothing to compare.
		if !ok || f.Secret {
			continue
		}
		if sameJSON(raw, view[f.Key]) {
			continue
		}
		culprit := "an environment variable or flag"
		if len(f.Pinnable) > 0 {
			culprit = strings.Join(f.Pinnable, " or ")
		}
		fmt.Fprintf(out, "  note: %s still reads as %q; it is pinned by %s, so the stored value applies only once that is unset.\n",
			settingName(f), formatValue(f.Kind, view[f.Key]), culprit)
	}
}

// adminRelaunchNote is what a save that restarted the agent for administrator rights says.
const adminRelaunchNote = "Stored; app-tail is restarting so Windows can ask for administrator rights. " +
	"Answer the prompt to turn this on."

// noteRestart prints what a non-interactive change still needs to fully take effect.
func noteRestart(out io.Writer, r SettingsResult) {
	noteDeferred(out, r)
	if r.AdminRelaunch {
		fmt.Fprintln(out, "  "+adminRelaunchNote)
		return
	}
	if r.UIRelisten {
		fmt.Fprintln(out, "  The dashboard address changed; restart the app-tail process for it to take effect.")
	}
	if r.AppRestart {
		fmt.Fprintln(out, "  Stored; the app reads this when it starts, so it applies the next time app-tail runs.")
	}
	if r.AdminRestart {
		fmt.Fprintln(out, "  Stored; this needs administrator rights, which app-tail asks for when it starts. "+
			"Restart it to be asked.")
	}
	if r.NodeRestart {
		fmt.Fprintln(out, "  A node restart is needed to apply this; run `app-tail restart`.")
	}
}

// noteDeferred prints the settings that were stored without reaching the tailnet node,
// each with the reason the agent gave.
func noteDeferred(out io.Writer, r SettingsResult) {
	for _, d := range r.Deferred {
		fmt.Fprintf(out, "  note: %s was %s\n", d.Label, d.Reason)
	}
}

// sameJSON reports whether a raw patch value and a decoded view value are equal once
// both are marshaled canonically, so 120 and 120.0 or a reordered map do not disagree.
func sameJSON(raw json.RawMessage, got any) bool {
	var want any
	if err := json.Unmarshal(raw, &want); err != nil {
		return false
	}
	wb, err := json.Marshal(want)
	if err != nil {
		return false
	}
	gb, err := json.Marshal(got)
	if err != nil {
		return false
	}
	return string(wb) == string(gb)
}

// writableSchemas is the settable subset, in authored order.
func writableSchemas() []config.FieldSchema {
	var out []config.FieldSchema
	for _, s := range config.SettingsCLISchema() {
		if s.Write == config.WritePatch {
			out = append(out, s)
		}
	}
	return out
}

// settingName is the name a user types for a field: its CLI name, or its JSON key for
// the read-only fields that have none.
func settingName(s config.FieldSchema) string {
	if s.CLIName != "" {
		return s.CLIName
	}
	return s.Key
}

// settingNotes summarizes a field's constraints for the list view.
func settingNotes(s config.FieldSchema) string {
	var notes []string
	if s.ReadOnly {
		notes = append(notes, "read-only")
	}
	if s.Secret {
		notes = append(notes, "secret")
	}
	if s.Module != config.ModuleCore {
		notes = append(notes, "needs the "+config.ModuleLabel(s.Module)+" module on")
	}
	switch s.Restart {
	case config.RestartNode:
		notes = append(notes, "change needs node restart")
	case config.RestartUI:
		notes = append(notes, "change needs process restart")
	}
	return strings.Join(notes, ", ")
}

// renderValue formats a field's current value for display. Secrets show only whether
// one is set.
func renderValue(s config.FieldSchema, view map[string]any) string {
	if s.Secret {
		if set, ok := view[s.ViewKey].(bool); ok && set {
			return "set"
		}
		return "not set"
	}
	return formatValue(s.Kind, view[s.ViewKey])
}

// formatValue renders a decoded JSON value by the field's kind. JSON numbers decode to
// float64, so an int field is printed without a spurious decimal point.
func formatValue(kind config.FieldKind, v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(value)
	case float64:
		if kind == config.KindInt {
			return strconv.FormatInt(int64(value), 10)
		}
		return strconv.FormatFloat(value, 'g', -1, 64)
	case []any:
		parts := make([]string, 0, len(value))
		for _, e := range value {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, ", ")
	case string:
		return value
	default:
		return fmt.Sprint(value)
	}
}
