// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tlsmint"
)

// IPS reads traffic inspection as the agent reports it.
func (c *Client) IPS(ctx context.Context) (httpapi.IPSView, error) {
	var out httpapi.IPSView
	err := c.do(ctx, http.MethodGet, "/api/ips", nil, &out)
	return out, err
}

// RemoveInterceptRoot has the agent delete the interception root's key and certificate.
func (c *Client) RemoveInterceptRoot(ctx context.Context) (httpapi.IPSView, error) {
	var out httpapi.IPSView
	err := c.do(ctx, http.MethodPost, "/api/ips/intercept/remove-root", nil, &out)
	return out, err
}

// trustGOOS is the system whose trust store the removal commands are for.
var trustGOOS = runtime.GOOS

// runTrustCommand runs one trust-store command in this terminal, so sudo or an administrator
// prompt asks the person at it. The agent never runs these: it cannot change what the machine
// trusts, and the root helper deliberately has no root-of-trust operation.
var runTrustCommand = func(ctx context.Context, env Env, c tlsmint.Command) error {
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = env.Stdin, env.Stdout, env.Stderr
	return cmd.Run()
}

// impersonationWarning is said wherever the root is shown, because it is the one fact about the
// root that matters most and is easiest to forget once it is installed.
const impersonationWarning = "Anyone who holds this root's private key can impersonate websites to this machine. " +
	"Keep the key file private, and remove the root when you stop using interception."

// runIPS dispatches the traffic-inspection subcommands.
func runIPS(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usagef("use `ips root` to show the traffic-interception root or `ips remove-root` to remove it")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "root":
		return runIPSRoot(ctx, rest, env)
	case "remove-root":
		return runIPSRemoveRoot(ctx, rest, env)
	}
	return usagef("unknown ips subcommand %q; use `ips root` or `ips remove-root`", sub)
}

func runIPSRoot(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("ips root", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "ips root"); err != nil {
		return err
	}
	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.IPS(ctx)
	if err != nil {
		return err
	}
	in := view.Intercept
	if *asJSON {
		return writeJSON(env, in)
	}
	if in.RootError != "" {
		return errors.New(in.RootError)
	}
	if in.Fingerprint == "" {
		fmt.Fprintln(env.Stdout, "app-tail holds no traffic-interception root. One is generated when interception is switched on.")
		return nil
	}

	installed := "only known while interception is on"
	if in.Running {
		installed = "no"
		if in.Installed {
			installed = "yes"
		}
	}
	rows := [][2]string{
		{"File", in.CertPath},
		{"SHA-256", colonFingerprint(in.Fingerprint)},
		{"Expires", rootExpiryDate(in.Expires)},
		{"Can sign for", in.RootScope},
		{"Installed", installed},
		{"Interception", onWord(in.On)},
	}
	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "\n%s\n", impersonationWarning)
	for _, warning := range []string{in.ExpiryWarning, in.NewRootReason} {
		if warning != "" {
			fmt.Fprintf(env.Stdout, "\n%s\n", warning)
		}
	}
	fmt.Fprintln(env.Stdout, "\nTo take it out of this machine's trust store and delete it: app-tail ips remove-root")
	return nil
}

func runIPSRemoveRoot(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("ips remove-root", env)
	loc := addLocationFlags(fs)
	filesOnly := fs.Bool("files-only", false,
		"delete the root's key and certificate without touching the trust store, for a root that was never installed or was removed by hand")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "ips remove-root"); err != nil {
		return err
	}
	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	view, err := client.IPS(ctx)
	if err != nil {
		return err
	}
	in := view.Intercept
	if in.On {
		return errors.New("traffic interception is switched on, so a new root would be generated straight away; " +
			"switch it off first with `app-tail settings set ips.intercept off`")
	}
	if in.Fingerprint == "" && in.RootError == "" {
		fmt.Fprintln(env.Stdout, "app-tail holds no traffic-interception root, so there is nothing to delete.")
		if in.Remove != "" {
			fmt.Fprintf(env.Stdout, "If an earlier one is still in this machine's trust store, this takes it out:\n  %s\n", in.Remove)
		}
		return nil
	}

	if !*filesOnly {
		// The trust store first: on macOS the command that drops the trust setting reads the
		// certificate file, and a failure here has to leave the files to run it again with.
		commands := tlsmint.RemovalCommands(trustGOOS, in.CertPath)
		if len(commands) == 0 {
			return errors.New("app-tail does not know how this system's trust store is changed; " +
				"take the root out by hand, then run `app-tail ips remove-root --files-only`")
		}
		fmt.Fprintln(env.Stdout, "Taking the root out of this machine's trust store:")
		for _, c := range commands {
			line := tlsmint.CommandLine(trustGOOS, c)
			fmt.Fprintf(env.Stdout, "  %s\n", line)
			if err := runTrustCommand(ctx, env, c); err != nil {
				return fmt.Errorf("`%s` failed: %w; the root's files were kept, so this can be run again. "+
					"If the root was never installed, run `app-tail ips remove-root --files-only`", line, err)
			}
		}
	}

	if _, err := client.RemoveInterceptRoot(ctx); err != nil {
		return err
	}
	if in.Fingerprint != "" {
		fmt.Fprintf(env.Stdout, "Deleted the root %s and its key.\n", colonFingerprint(in.Fingerprint))
	} else {
		fmt.Fprintln(env.Stdout, "Deleted the root's files.")
	}
	if !*filesOnly {
		fmt.Fprintln(env.Stdout, "Programs already running may go on trusting it until they restart.")
	}
	return nil
}

// colonFingerprint writes a hex SHA-256 the way certificate viewers show one: upper case, in
// colon-separated pairs, so it can be compared by eye against what a trust store lists.
func colonFingerprint(hex string) string {
	if len(hex) != 64 {
		return hex
	}
	pairs := make([]string, 0, 32)
	for i := 0; i < len(hex); i += 2 {
		pairs = append(pairs, strings.ToUpper(hex[i:i+2]))
	}
	return strings.Join(pairs, ":")
}

// rootExpiryDate is the expiry as a date, which is all a person needs of it.
func rootExpiryDate(rfc3339 string) string {
	at, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	return at.UTC().Format(time.DateOnly)
}

func onWord(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
