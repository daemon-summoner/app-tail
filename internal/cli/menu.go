// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/sellitus/app-tail/internal/config"
)

// errAborted signals the user ended input with Ctrl-D, so the menu stops without
// saving rather than treating the empty read as a value.
var errAborted = errors.New("input aborted")

// prompter abstracts terminal input so the menu logic is testable without a real TTY.
type prompter interface {
	line(prompt string) (string, error)
	secret(prompt string) (string, error)
}

// ttyPrompter reads from a real terminal, keeping secret input off the screen.
type ttyPrompter struct {
	in  *bufio.Reader
	out io.Writer
	fd  int
}

func (p ttyPrompter) line(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	text, err := p.in.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && strings.TrimRight(text, "\r\n") == "" {
			return "", errAborted
		}
		if !errors.Is(err, io.EOF) {
			return "", err
		}
	}
	return strings.TrimRight(text, "\r\n"), nil
}

func (p ttyPrompter) secret(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	raw, err := term.ReadPassword(p.fd)
	// ReadPassword swallows the newline the user typed, so echo one to end the line.
	fmt.Fprintln(p.out)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

func runSettingsMenu(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("settings menu", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "settings menu"); err != nil {
		return err
	}

	// A non-interactive stdin would hang on the first prompt, so refuse it with a
	// pointer to the scriptable command instead.
	file, ok := env.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return errors.New("settings menu needs an interactive terminal; use `app-tail settings set` in scripts")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	p := ttyPrompter{in: bufio.NewReader(file), out: env.Stdout, fd: int(file.Fd())}
	return settingsMenu(ctx, client, p, env.Stdout)
}

// settingsMenu is the interactive loop, split from the terminal setup so a test can
// drive it with a scripted prompter and a stubbed agent client.
func settingsMenu(ctx context.Context, client *Client, p prompter, out io.Writer) error {
	view, err := client.Settings(ctx)
	if err != nil {
		return err
	}
	fields := writableSchemas()
	pending := map[string]json.RawMessage{}

	for {
		printMenu(out, fields, view, pending)
		choice, err := p.line("\nSelect a number to edit, s to save, q to quit: ")
		if err != nil {
			return menuInterrupted(err)
		}
		switch choice = strings.TrimSpace(choice); {
		case choice == "q":
			fmt.Fprintln(out, "No changes saved.")
			return nil
		case choice == "s":
			if len(pending) == 0 {
				fmt.Fprintln(out, "Nothing changed.")
				return nil
			}
			return saveMenu(ctx, client, p, out, pending)
		default:
			idx, ok := menuIndex(choice, len(fields))
			if !ok {
				fmt.Fprintln(out, "Enter one of the listed numbers, s to save, or q to quit.")
				continue
			}
			if err := editField(p, out, fields[idx], view, pending); err != nil {
				if errors.Is(err, errAborted) {
					return menuInterrupted(err)
				}
				// A parse error is the user's, not the program's: report it and re-loop.
				fmt.Fprintf(out, "  %v\n", err)
			}
		}
	}
}

// menuInterrupted turns a Ctrl-D abort into a clean stop; any other error passes through.
func menuInterrupted(err error) error {
	if errors.Is(err, errAborted) {
		return nil
	}
	return err
}

// editField prompts for one field's new value and records it in pending. Blank input
// leaves the field unchanged; a secret is read without echo.
func editField(p prompter, out io.Writer, s config.FieldSchema, view map[string]any, pending map[string]json.RawMessage) error {
	if s.Secret {
		val, err := p.secret(fmt.Sprintf("New value for %s (blank leaves it unchanged): ", s.CLIName))
		if err != nil {
			return err
		}
		if val == "" {
			return nil
		}
		raw, err := json.Marshal(val)
		if err != nil {
			return err
		}
		pending[s.Key] = raw
		return nil
	}

	entry, err := p.line(fmt.Sprintf("New value for %s [%s]: ", s.CLIName, currentDisplay(s, view, pending)))
	if err != nil {
		return err
	}
	if entry = strings.TrimSpace(entry); entry == "" {
		return nil
	}
	_, v, err := config.ParseSettingValue(s.CLIName, entry)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	pending[s.Key] = raw
	return nil
}

// printMenu lists every editable field with its current value, marking unsaved edits.
func printMenu(out io.Writer, fields []config.FieldSchema, view map[string]any, pending map[string]json.RawMessage) {
	fmt.Fprintln(out, "\nSettings")
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for i, s := range fields {
		marker := " "
		if _, ok := pending[s.Key]; ok {
			marker = "*"
		}
		fmt.Fprintf(w, "  %s %d)\t%s\t%s\n", marker, i+1, s.CLIName, currentDisplay(s, view, pending))
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(out, "  (could not render the menu: %v)\n", err)
	}
	fmt.Fprintln(out, "  (* marks an unsaved change)")
}

// currentDisplay shows a field's pending value when one is queued, otherwise its saved
// value. A secret is only ever shown as set/not set.
func currentDisplay(s config.FieldSchema, view map[string]any, pending map[string]json.RawMessage) string {
	raw, ok := pending[s.Key]
	if !ok {
		return renderValue(s, view)
	}
	if s.Secret {
		return "set (unsaved)"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "?"
	}
	return formatValue(s.Kind, v) + " (unsaved)"
}

// saveMenu writes the queued changes and then handles what they need to take effect.
func saveMenu(ctx context.Context, client *Client, p prompter, out io.Writer, pending map[string]json.RawMessage) error {
	result, err := client.UpdateSettings(ctx, pending)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Saved.")
	warnPinned(out, pending, result.View)
	noteDeferred(out, result)
	return offerRestart(ctx, client, p, out, result)
}

// offerRestart surfaces the restart a change needs, offering to apply a node restart
// in place and explaining that a dashboard-address change needs a full process restart.
func offerRestart(ctx context.Context, client *Client, p prompter, out io.Writer, result SettingsResult) error {
	if result.AdminRelaunch {
		fmt.Fprintln(out, adminRelaunchNote)
		return nil
	}
	if result.UIRelisten {
		fmt.Fprintln(out, "The dashboard address changed. Restart the app-tail process for it to take effect; the dashboard and CLI use the new address afterward.")
	}
	// No question for this one: the value is stored and correct, and the only thing left is
	// a start that has not happened yet. Offering to restart the whole app over a menu-bar
	// icon would be a bigger interruption than the change is worth.
	if result.AppRestart {
		fmt.Fprintln(out, "Stored. The app reads this when it starts, so it applies the next time app-tail runs.")
	}
	if result.AdminRestart {
		fmt.Fprintln(out, "Stored. This needs administrator rights, which app-tail asks for when it starts. "+
			"Restart it to be asked.")
	}
	if !result.NodeRestart {
		return nil
	}
	answer, err := p.line("A node restart is needed to apply the change. Restart now? [y/N]: ")
	if err != nil {
		return menuInterrupted(err)
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		fmt.Fprintln(out, "Run `app-tail restart` when you are ready.")
		return nil
	}
	if err := client.Restart(ctx); err != nil {
		return err
	}
	fmt.Fprintln(out, "Node restarted.")
	return nil
}

// menuIndex parses a 1-based menu choice into a slice index.
func menuIndex(choice string, n int) (int, bool) {
	i, err := strconv.Atoi(choice)
	if err != nil || i < 1 || i > n {
		return 0, false
	}
	return i - 1, true
}
