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

// AutoMap reads the automatic port mapping module's state.
func (c *Client) AutoMap(ctx context.Context) (httpapi.AutoMapView, error) {
	var out httpapi.AutoMapView
	err := c.do(ctx, http.MethodGet, "/api/automap", nil, &out)
	return out, err
}

// autoMapForgetResult is the agent's reply to a forget: how many assignments went, and
// the module's state afterwards.
type autoMapForgetResult struct {
	Removed int                 `json:"removed"`
	AutoMap httpapi.AutoMapView `json:"automap"`
}

// ForgetAutoMappings drops the port assignments for devices the tailnet no longer
// reports.
func (c *Client) ForgetAutoMappings(ctx context.Context) (autoMapForgetResult, error) {
	var out autoMapForgetResult
	err := c.do(ctx, http.MethodPost, "/api/automap/forget", nil, &out)
	return out, err
}

// runAutoMap dispatches the automatic-ports subcommands.
func runAutoMap(ctx context.Context, args []string, env Env) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest := args[0], args[1:]
		if sub != "forget" {
			return usagef("unknown automap subcommand %q; use `automap` or `automap forget`", sub)
		}
		return runAutoMapForget(ctx, rest, env)
	}
	return runAutoMapStatus(ctx, args, env)
}

func runAutoMapStatus(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("automap", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "automap"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.AutoMap(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, view)
	}

	if !view.Enabled {
		fmt.Fprintln(env.Stdout, "Automatic ports are off.")
		fmt.Fprintln(env.Stdout, "Turn them on with: app-tail settings set automap true")
		return nil
	}

	ports := make([]string, len(view.Ports))
	for i, port := range view.Ports {
		ports[i] = fmt.Sprint(port)
	}
	rows := [][2]string{
		{"Mapping", strings.Join(ports, ", ") + " on every device"},
		{"Open now", fmt.Sprintf("%d local ports", view.Mapped)},
		{"Remembered", fmt.Sprintf("%d assignments, including devices not currently reachable", view.Stored)},
	}
	if view.Reason != "" {
		rows = append(rows, [2]string{"Note", view.Reason})
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "\nThe ports themselves are listed by `app-tail list`.")
	return nil
}

// runAutoMapForget drops the assignments for devices that are gone.
//
// It is a deliberate action rather than part of the reconcile because an assignment is
// what keeps a port stable across restarts: dropping one renumbers a device the next
// time it appears, breaking every bookmark and config that named the old port.
func runAutoMapForget(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("automap forget", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "automap forget"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	result, err := client.ForgetAutoMappings(ctx)
	if err != nil {
		return err
	}
	if result.Removed == 0 {
		fmt.Fprintln(env.Stdout, "Every remembered port belongs to a device still on the tailnet.")
		return nil
	}
	fmt.Fprintf(env.Stdout, "Forgot %d port assignment(s) for devices no longer on the tailnet; %d remain.\n",
		result.Removed, result.AutoMap.Stored)
	return nil
}
