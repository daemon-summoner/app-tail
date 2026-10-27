// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
)

// command is one top-level subcommand. Keeping the whole set in one table means the
// help overview and the dispatcher cannot drift: a command that dispatches is
// documented, and one that is documented dispatches.
type command struct {
	name string
	// args is the argument form shown in the help overview, e.g. "--target HOST:PORT".
	args    string
	summary string
	run     func(ctx context.Context, args []string, env Env) error
}

// commands is the authored command table, in the order the help overview lists them.
var commands = []command{
	{"run", "[flags]", "start the agent and its dashboard", runAgent},
	{"status", "[--json]", "show the tailnet connection state", runStatus},
	{"dashboard", "[--print] [--base URL]", "open the dashboard, already signed in", runDashboard},
	{"login", "", "start an interactive login", runLogin},
	{"logout", "", "disconnect this device from the tailnet", runLogout},
	{"restart", "", "rebuild the tailnet node to apply settings", runRestart},
	{"list", "[--json]", "list configured forwards", runList},
	{"add", "--target HOST:PORT", "add a forward", runAdd},
	{"rm", "NAME-OR-ID", "remove a forward", runRemove},
	{"forward", "get|update|enable|disable|toggle ID", "inspect or change one forward", runForward},
	{"connection", "list|get|add|set|import|rm|enable|disable|retry", "manage the private networks this machine is attached to", runConnection},
	{"route", "list|add|rm|move|check|clear", "send some destinations through a different connection", runRoute},
	{"peers", "[--json]", "list tailnet devices this node can see", runPeers},
	{"exec", "-- COMMAND", "run a command with the tailnet proxy set for it", runExec},
	{"proxy", "status|system|connect|probe", "use or inspect the tailnet proxy", runProxy},
	{"automap", "[forget]", "inspect the ports opened for every device", runAutoMap},
	{"lock", "[log|sign NODEKEY]", "show why tailnet lock is holding this device back", runLock},
	{"ips", "root|remove-root", "show or remove the traffic-interception root certificate", runIPS},
	{"dns", "[use NAME|profile|block|setup|restore]", "show or switch how this machine and app-tail resolve names", runDNS},
	{"tun", "setup|doctor|install-helper|uninstall-helper|grant", "set up or inspect the network-interface mode", runTun},
	{"health", "[--json]", "report whether the agent is ready to carry traffic", runHealth},
	{"log", "[--follow] [filters]", "show what the agent has been doing", runLog},
	{"settings", "get|list|set|menu", "read or change agent settings", runSettings},
	{"config", "check|restore|reset", "inspect or repair the configuration document", runConfig},
	{"auth", "rotate", "replace the API token and sign out every dashboard", runAuth},
	{"preset", "list|add|rm", "manage service templates", runPreset},
	{"autostart", "status", "show whether app-tail starts at login", runAutostart},
	{"provision", "--profile FILE", "apply a fleet profile to the local config", runProvision},
	{"install", "", "install app-tail for all users in Program Files (Windows)", runInstall},
	{"install-autostart", "", "start app-tail when you log in", runInstallAutostart},
	{"bootstrap-policy", "", "prepare a tailnet policy for a fleet", runBootstrapPolicy},
	{"version", "", "print the version", runVersion},
	{"licenses", "", "print the third-party license notices", runLicenses},
}

// commandByName finds a command by its invoked name.
func commandByName(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

func runVersion(_ context.Context, _ []string, env Env) error {
	fmt.Fprintln(env.Stdout, env.Version)
	return nil
}

// usageText is the help overview, built once from the command table so it always
// matches what the dispatcher accepts.
var usageText = buildUsageText()

const usagePreamble = `app-tail connects this machine to several VPNs and zero-trust networks at once --
Tailscale, WireGuard and OpenVPN -- and lets you choose how much of the machine
each one gets: forwarded ports, a proxy, or one network interface for all of them.

Usage:
`

const usageFooter = `
Run any command with --help for its own flags. The agent must be running for
status, dashboard, login, logout, restart, list, add, rm, forward, connection,
peers, health, log, settings, preset and ips; version, licenses, provision,
install, install-autostart, autostart, tun, config, auth and bootstrap-policy
work offline.
`

func buildUsageText() string {
	var b strings.Builder
	b.WriteString(usagePreamble)

	w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
	for _, c := range commands {
		invocation := "app-tail " + c.name
		if c.name == "run" {
			invocation = "app-tail [run]"
		}
		if c.args != "" {
			invocation += " " + c.args
		}
		fmt.Fprintf(w, "  %s\t%s\n", invocation, c.summary)
	}
	if err := w.Flush(); err != nil {
		// The writer is a strings.Builder, which never fails to write; a non-nil error
		// here would mean the standard library changed under us.
		panic(fmt.Sprintf("render usage text: %v", err))
	}

	b.WriteString(usageFooter)
	return b.String()
}
