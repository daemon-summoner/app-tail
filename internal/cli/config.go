// SPDX-License-Identifier: MIT

package cli

// Looking at the config document, and going back to one that worked.
//
// These are the commands for the state everything else hangs off. They work on the file
// rather than through the agent, because the case they exist for is a document the agent
// could not load -- and they never open the store, since opening it is what writes a fresh
// document over the one somebody may want back.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// runConfig dispatches the config-document subcommands. Bare `config` checks, which is the
// reading of it that changes nothing.
func runConfig(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runConfigCheck(ctx, args, env)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "check":
		return runConfigCheck(ctx, rest, env)
	case "restore":
		return runConfigRestore(ctx, rest, env)
	case "reset":
		return runConfigReset(ctx, rest, env)
	default:
		return usagef("unknown config subcommand %q; use `config check`, `config restore` or `config reset`", sub)
	}
}

func runConfigCheck(_ context.Context, args []string, env Env) error {
	fs := newFlagSet("config check", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "config check"); err != nil {
		return err
	}
	path, err := loc.path(env)
	if err != nil {
		return err
	}
	report, err := config.Inspect(path)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, report)
	}

	fmt.Fprintf(env.Stdout, "%s\n", report.Path)
	switch {
	case !report.Exists:
		fmt.Fprintf(env.Stdout, "  %s\n", report.Reason)
	case report.Usable:
		fmt.Fprintf(env.Stdout, "  Loads cleanly (document version %d, this build writes %d).\n",
			report.Version, report.Current)
	default:
		fmt.Fprintf(env.Stdout, "  Cannot be used: %s\n", report.Reason)
		fmt.Fprintln(env.Stdout, "  app-tail starts with the defaults and keeps this document beside it.")
	}

	if len(report.Saved) == 0 {
		if !report.Usable && report.Exists {
			fmt.Fprintln(env.Stdout, "  There is no saved copy to go back to; `app-tail config reset` starts over.")
		}
		return nil
	}
	fmt.Fprintln(env.Stdout, "\nSaved beside it, newest first:")
	w := tabwriter.NewWriter(env.Stdout, 0, 0, 3, ' ', 0)
	restorable := false
	for _, one := range report.Saved {
		state := "usable"
		if one.Usable {
			restorable = true
		} else {
			state = "unusable: " + one.Reason
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			filepath.Base(one.Path), one.Kind, one.At.Local().Format(time.RFC3339), state)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("write the list of saved copies: %w", err)
	}
	// Offering the restore against a list where nothing can be restored sends the reader
	// to a command that can only refuse them.
	if restorable {
		fmt.Fprintln(env.Stdout, "\nRun `app-tail config restore` for the newest usable one, or name a file to pick one.")
	} else {
		fmt.Fprintln(env.Stdout, "\nNone of these can be restored; `app-tail config reset` starts from the defaults.")
	}
	return nil
}

func runConfigRestore(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("config restore", env)
	loc := addLocationFlags(fs)
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) > 1 {
		return usagef("config restore takes at most one file, got %q", strings.Join(rest, " "))
	}
	path, err := loc.path(env)
	if err != nil {
		return err
	}
	from := ""
	if len(rest) == 1 {
		if from, err = filepath.Abs(rest[0]); err != nil {
			return fmt.Errorf("resolve %s: %w", rest[0], err)
		}
	}

	// Asked before the write: a restore replaces the address the agent published, so
	// afterwards the file no longer says where to look for it.
	running := agentAt(path)

	installed, moved, err := config.Restore(path, from)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Restored %s to %s\n", filepath.Base(installed), path)
	if moved != nil {
		fmt.Fprintf(env.Stdout, "The document it replaced is at %s\n", moved.Path)
	}
	reportRunningAgent(ctx, env, running)
	return nil
}

func runConfigReset(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("config reset", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "config reset"); err != nil {
		return err
	}
	path, err := loc.path(env)
	if err != nil {
		return err
	}

	running := agentAt(path)

	moved, err := config.Reset(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Wrote the default configuration to %s\n", path)
	if moved != nil {
		fmt.Fprintf(env.Stdout, "The settings it replaced are at %s; `app-tail config restore %s` puts them back.\n",
			moved.Path, filepath.Base(moved.Path))
	}
	reportRunningAgent(ctx, env, running)
	return nil
}

// agentAt is a client for the agent the stored document says is listening. It reads the
// document without opening the store, because opening it is what writes a fresh document
// over one the caller may be about to restore.
func agentAt(path string) *Client {
	return NewClient("http://" + config.DashboardAddr(path))
}

// reportRunningAgent says so when an agent is up, because it holds the previous document
// in memory and writes its own copy back on the next change: a repair made underneath a
// running agent lasts exactly until the next setting is saved.
//
// It is a report, not a check that can fail the command: the file has already been
// written, and no answer from the agent changes that.
func reportRunningAgent(ctx context.Context, env Env, client *Client) {
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := client.Health(probe); err == nil {
		fmt.Fprintln(env.Stdout,
			"app-tail is running and still holds the previous settings; restart it to read what was just written.")
	}
}
