// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"text/tabwriter"

	"github.com/sellitus/app-tail/internal/httpapi"
)

// Lock reads what tailnet lock means for this device.
func (c *Client) Lock(ctx context.Context) (httpapi.LockView, error) {
	var out httpapi.LockView
	err := c.do(ctx, http.MethodGet, "/api/lock", nil, &out)
	return out, err
}

// LockLog reads the tailnet's key authority history.
func (c *Client) LockLog(ctx context.Context) ([]httpapi.LockUpdate, error) {
	var out []httpapi.LockUpdate
	err := c.do(ctx, http.MethodGet, "/api/lock/log", nil, &out)
	return out, err
}

// SignForLock authorizes another device for a locked tailnet.
func (c *Client) SignForLock(ctx context.Context, nodeKey, rotationKey string) (httpapi.LockView, error) {
	body := map[string]string{"nodeKey": nodeKey, "rotationKey": rotationKey}
	var out httpapi.LockView
	err := c.do(ctx, http.MethodPost, "/api/lock/sign", body, &out)
	return out, err
}

// runLock dispatches the tailnet-lock subcommands.
func runLock(ctx context.Context, args []string, env Env) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest := args[0], args[1:]
		switch sub {
		case "log":
			return runLockLog(ctx, rest, env)
		case "sign":
			return runLockSign(ctx, rest, env)
		default:
			return usagef("unknown lock subcommand %q; use `lock`, `lock log` or `lock sign NODEKEY`", sub)
		}
	}
	return runLockStatus(ctx, args, env)
}

func runLockStatus(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("lock", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "lock"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.Lock(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}

	if !view.Enabled {
		fmt.Fprintln(env.Stdout, "Tailnet lock is off for your tailnet.")
		if view.Capability.Reason != "" && !view.Capability.Available {
			fmt.Fprintln(env.Stdout, view.Capability.Reason)
		}
		return nil
	}

	rows := [][2]string{
		{"Tailnet lock", "on"},
		{"This device", lockSignedWord(view.Signed)},
	}
	if view.NodeKey != "" {
		rows = append(rows, [2]string{"Node key", view.NodeKey})
	}
	if view.LockKey != "" {
		rows = append(rows, [2]string{"Lock key", view.LockKey})
	}
	rows = append(rows, [2]string{"Devices visible", fmt.Sprint(view.Visible)})
	if len(view.Filtered) > 0 {
		names := make([]string, 0, len(view.Filtered))
		for _, p := range view.Filtered {
			names = append(names, p.Name)
		}
		rows = append(rows, [2]string{"Held back by lock", strings.Join(names, ", ")})
	}
	if len(view.Trusted) > 0 {
		labels := make([]string, 0, len(view.Trusted))
		for _, k := range view.Trusted {
			label := k.ID
			if k.Label != "" {
				label = k.ID + " (" + k.Label + ")"
			}
			if k.Self {
				label += " -- this device"
			}
			labels = append(labels, label)
		}
		rows = append(rows, [2]string{"Trusted keys", strings.Join(labels, "\n\t")})
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	if view.Capability.Reason != "" {
		fmt.Fprintf(env.Stdout, "\n%s\n", view.Capability.Reason)
	}
	// The command is the whole remedy for a device nothing can reach, so it is printed
	// on its own line ready to copy rather than folded into the table above.
	if !view.Signed && view.SignCommand != "" {
		fmt.Fprintf(env.Stdout, "\nRun this on a device that holds a trusted key:\n  %s\n",
			view.SignCommand)
	}
	return nil
}

func lockSignedWord(signed bool) string {
	if signed {
		return "signed"
	}
	return "not signed -- it can reach no device on your tailnet"
}

func runLockLog(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("lock log", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "lock log"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	entries, err := client.LockLog(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, entries)
	}
	if len(entries) == 0 {
		fmt.Fprintln(env.Stdout, "Your tailnet's key authority has no recorded changes.")
		return nil
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, e := range entries {
		fmt.Fprintf(writer, "%s\t%s\n", e.Hash, e.Change)
	}
	return writer.Flush()
}

// runLockSign authorizes another device. The rotation key is the second positional
// argument because that is the order `tailscale lock sign` takes them, and someone
// copying a command between the two tools should not have to reorder it.
func runLockSign(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("lock sign", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 || len(pos) > 2 {
		return usagef("lock sign takes the device's nodekey:... and optionally its tlpub:...")
	}
	nodeKey := pos[0]
	rotationKey := ""
	if len(pos) == 2 {
		rotationKey = pos[1]
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.SignForLock(ctx, nodeKey, rotationKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Signed %s. Your tailnet's key authority now trusts %d key(s).\n",
		nodeKey, len(view.Trusted))
	return nil
}
