// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/browser"
	"github.com/sellitus/app-tail/internal/sockerr"
)

// openBrowser launches a URL in the user's browser. Tests substitute a recorder.
var openBrowser = browser.Open

// runDashboard opens the dashboard already signed in. A browser cannot read the token
// file, so the agent mints a one-time link for it -- the same link the tray menu opens.
func runDashboard(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("dashboard", env)
	loc := addLocationFlags(fs)
	printOnly := fs.Bool("print", false, "print the sign-in link instead of opening a browser")
	base := fs.String("base", "", "open the link on this scheme://host:port instead, such as the Vite dev server or an SSH tunnel")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "dashboard"); err != nil {
		return err
	}
	var rebaseTo *url.URL
	if *base != "" {
		parsed, err := parseBase(*base)
		if err != nil {
			return err
		}
		rebaseTo = parsed
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	link, err := client.DashboardLink(ctx, *printOnly)
	if err != nil {
		return err
	}
	if rebaseTo != nil {
		if link, err = rebase(link, rebaseTo); err != nil {
			return err
		}
	}

	if *printOnly {
		fmt.Fprintln(env.Stdout, link)
		return nil
	}
	if err := openBrowser(link); err != nil {
		return fmt.Errorf("open a browser: %w; run `app-tail dashboard --print` and open the link yourself", err)
	}
	fmt.Fprintln(env.Stdout, "Opened the dashboard in your browser. The link signs in once and expires in two minutes.")
	return nil
}

// parseBase reads --base, which replaces only the scheme and the authority of the link:
// the path and the launch token are the agent's.
func parseBase(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, usagef("--base takes scheme://host:port, such as http://localhost:5173, not %q", raw)
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, usagef("--base takes only scheme://host:port; %q carries a path or a query", raw)
	}
	return parsed, nil
}

func rebase(link string, base *url.URL) (string, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return "", fmt.Errorf("read the sign-in link the agent returned: %w", err)
	}
	parsed.Scheme, parsed.Host = base.Scheme, base.Host
	return parsed.String(), nil
}

// runAuth manages the API token. Rotating it is how every signed-in dashboard is signed
// out at once, for instance after a link was shared by mistake.
func runAuth(ctx context.Context, args []string, env Env) error {
	// The subcommand may come before or after the location flags: `auth rotate --config X`
	// and `auth --config X rotate` both read naturally.
	rest, named := args, false
	if len(args) > 0 && args[0] == "rotate" {
		rest, named = args[1:], true
	}
	fs := newFlagSet("auth rotate", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, rest); err != nil {
		return err
	}
	positional := fs.Args()
	if !named && len(positional) > 0 && positional[0] == "rotate" {
		positional, named = positional[1:], true
	}
	switch {
	case !named && len(positional) == 0:
		return usagef("auth needs a subcommand; the only one is `auth rotate`")
	case !named:
		return usagef("unknown auth subcommand %q; the only one is `auth rotate`", positional[0])
	case len(positional) > 0:
		return usagef("auth rotate takes no positional arguments, got %q", strings.Join(positional, " "))
	}

	// The file is removed only when no agent can be holding the token: no address is
	// recorded to find one at, or the recorded port actively refuses. A timeout or any
	// other failure may be a live agent that is busy, and deleting the file under it
	// would lock the CLI out until it restarts. Once the rotate request is on its way
	// the agent may already have written a new token, so a failure there never deletes.
	client, err := loc.connect(env)
	if err != nil && !errors.Is(err, ErrNoAgent) {
		return err
	}
	if err == nil {
		if err := client.prove(ctx); err != nil {
			if !sockerr.Refused(err) {
				return fmt.Errorf("could not tell whether an agent is running, so the API token was left in place: %w", err)
			}
		} else {
			if err := client.RotateToken(ctx); err != nil {
				return err
			}
			fmt.Fprintln(env.Stdout, "Replaced the API token. Every open dashboard is signed out; "+
				"open it again from the app-tail menu or with `app-tail dashboard`.")
			return nil
		}
	}

	// No agent is running, so nothing holds the token in memory: removing the file is the
	// whole rotation, and the next agent to start writes a new one.
	path, err := loc.path(env)
	if err != nil {
		return err
	}
	if err := apiauth.Remove(filepath.Dir(path)); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "No agent is running; removed the API token. The agent writes a new one when it next starts.")
	return nil
}
