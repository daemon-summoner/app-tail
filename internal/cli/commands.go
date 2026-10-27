// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/policy"
)

// location carries the two flags every command needs to find the right config.
type location struct {
	configPath *string
	stateDir   *string
}

func addLocationFlags(fs *flag.FlagSet) location {
	return location{
		configPath: fs.String("config", "", "path to the config file"),
		stateDir:   fs.String("state-dir", "", "directory holding config and tailnet state"),
	}
}

func (l location) connect(env Env) (*Client, error) { return connect(env, *l.configPath, *l.stateDir) }

func (l location) store(env Env) (*config.Store, error) {
	return openStore(env, *l.configPath, *l.stateDir)
}

// path reports where the config file is without opening it.
func (l location) path(env Env) (string, error) {
	path, _, err := resolveConfigLocation(env, *l.configPath, *l.stateDir)
	return path, err
}

// storeAndDir opens the stored config and reports the directory it belongs to, for the
// few commands that also act on a file beside it rather than only on the agent.
func (l location) storeAndDir(env Env) (*config.Store, string, error) {
	return openStoreIn(env, *l.configPath, *l.stateDir)
}

// connectWithStore finds the running agent and hands back the stored config it was
// found through, for the commands that read a stored value as well.
func (l location) connectWithStore(env Env) (*Client, *config.Store, error) {
	return connectWithStore(env, *l.configPath, *l.stateDir)
}

// writeJSON prints a value as indented JSON, which is what --json promises.
func writeJSON(env Env, value any) error {
	encoder := json.NewEncoder(env.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func runStatus(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("status", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "status"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	status, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env, status)
	}

	rows := [][2]string{
		{"State", status.BackendState},
		{"Device", status.Hostname},
	}
	if status.DNSName != "" {
		rows = append(rows, [2]string{"MagicDNS", status.DNSName})
	}
	if len(status.TailscaleIPs) > 0 {
		rows = append(rows, [2]string{"Tailnet IPs", strings.Join(status.TailscaleIPs, ", ")})
	}
	if status.LoginName != "" {
		rows = append(rows, [2]string{"Account", status.LoginName})
	}
	if len(status.Tags) > 0 {
		rows = append(rows, [2]string{"Tags", strings.Join(status.Tags, ", ")})
	}
	rows = append(rows, [2]string{"Auth mode", status.AuthMode})
	rows = append(rows, [2]string{"Network", networkModeLabel(status.Network)})
	// Printed as its own row rather than folded into the one above, because this is the
	// case where every other line reads as a healthy node: it is up, it has an address,
	// and it is not doing the thing that was asked for.
	if status.NetworkFallback != "" {
		rows = append(rows, [2]string{"Interface mode", "not in force: " + status.NetworkFallback})
	}
	// The status says only that a login is waiting; the URL that completes it is asked for
	// separately. A failure to fetch it is not a failure of the status: the pending login
	// is itself the thing worth printing, and the command that starts a fresh one is what
	// somebody does about it either way.
	if status.AuthPending {
		pending, err := client.LoginURL(ctx)
		switch {
		case err != nil:
			rows = append(rows, [2]string{"Login", "waiting to be completed; run `app-tail login` for the URL"})
		default:
			rows = append(rows, [2]string{"Login URL", pending.AuthURL})
		}
	}
	if status.Problem != "" {
		rows = append(rows, [2]string{"Problem", status.Problem})
	}
	rows = append(rows, [2]string{"Dashboard", client.BaseURL()})

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		if row[1] == "" {
			continue
		}
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	return writer.Flush()
}

// networkModeLabel says which stack the node is on in the words the README uses. The
// stored value is an identifier, and the question somebody reads this line to answer is
// whether the machine itself is carrying tailnet addresses -- which is the one thing the
// identifier does not say. An unset value comes back empty and its row is dropped, which
// is what an agent too old to report the mode gives.
func networkModeLabel(mode string) string {
	switch config.NetworkMode(mode) {
	case config.NetworkTUN:
		return "a network interface -- the whole machine reaches the tailnet"
	case config.NetworkUserspace:
		return "contained -- only app-tail's forwards and proxy reach the tailnet"
	default:
		return mode
	}
}

func runLogin(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("login", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "login"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	result, err := client.Login(ctx)
	if err != nil {
		return err
	}

	switch {
	case result.AuthURL != "":
		fmt.Fprintf(env.Stdout, "Open this URL to connect this device to your tailnet:\n\n  %s\n\n", result.AuthURL)
		fmt.Fprintln(env.Stdout, "Then run `app-tail status` to confirm.")
	case strings.EqualFold(result.BackendState, "Running"):
		fmt.Fprintln(env.Stdout, "This device is already connected.")
	default:
		// No URL and not running means the node is mid-transition or authenticating
		// with a key. Saying so beats printing nothing.
		fmt.Fprintf(env.Stdout, "Login started; the node is %s. Run `app-tail status` to follow it.\n", result.BackendState)
	}
	return nil
}

func runLogout(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("logout", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "logout"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	if err := client.Logout(ctx); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Disconnected from the tailnet. Forwards stay configured and resume after the next login.")
	return nil
}

func runRestart(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("restart", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "restart"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	if err := client.Restart(ctx); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Tailnet node restarted. Active forwards were interrupted briefly and resume once the node reconnects.")
	return nil
}

func runList(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("list", env)
	loc := addLocationFlags(fs)
	asJSON := fs.Bool("json", false, "print the agent's reply as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "list"); err != nil {
		return err
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	forwards, err := client.Forwards(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		if forwards == nil {
			forwards = []httpapi.ForwardView{}
		}
		return writeJSON(env, forwards)
	}
	if len(forwards) == 0 {
		fmt.Fprintln(env.Stdout, "No forwards configured. Add one with `app-tail add --target HOST:PORT`.")
		return nil
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tNAME\tDIRECTION\tLISTENS ON\tTARGET\tSTATE")
	for _, f := range forwards {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID, f.Name, f.Direction, f.Endpoint, f.Target, forwardState(f))
	}
	return writer.Flush()
}

// forwardState renders the state column, folding in the reason a forward is not
// running so a broken forward never shows as a bare "error".
func forwardState(f httpapi.ForwardView) string {
	if !f.Enabled {
		return "disabled"
	}
	if f.Error != "" {
		return f.State + ": " + f.Error
	}
	if f.State == "" {
		return "pending"
	}
	return f.State
}

func runAdd(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("add", env)
	loc := addLocationFlags(fs)
	var (
		name      = fs.String("name", "", "label for this forward; one is generated when omitted")
		direction = fs.String("direction", string(config.ToLocal),
			"to_local exposes a tailnet service on this machine; to_tailnet exposes a local service on the tailnet")
		protocol   = fs.String("protocol", string(config.TCP), "tcp, udp, or both")
		connection = fs.String("connection", "", "id of the connection this forward crosses; the primary one when omitted")
		target     = fs.String("target", "", "HOST:PORT this forward sends traffic to (required)")
		port       = fs.Int("port", 0, "local port to listen on; a free one is chosen when omitted")
		bindAddr   = fs.String("bind", config.DefaultBindAddr, "address to listen on")
		udpTimeout = fs.Int("udp-timeout", 0, "idle seconds before a UDP session is evicted; 0 uses the agent default")
		disabled   = fs.Bool("disabled", false, "add the forward without starting it")
		expose     = fs.Bool("expose", false, "let other machines on your network use this forward; needed for a --bind they can reach")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "add"); err != nil {
		return err
	}
	if strings.TrimSpace(*target) == "" {
		return usagef("add needs --target HOST:PORT")
	}

	client, err := loc.connect(env)
	if err != nil {
		return err
	}

	listenPort := *port
	if listenPort == 0 {
		listenPort, err = client.SuggestPort(ctx, config.Protocol(*protocol), *target)
		if err != nil {
			return fmt.Errorf("choose a local port: %w", err)
		}
	}

	enabled := !*disabled
	spec := httpapi.ForwardSpec{
		Direction:  ptr(config.Direction(*direction)),
		Protocol:   ptr(config.Protocol(*protocol)),
		BindAddr:   bindAddr,
		ListenPort: &listenPort,
		Target:     target,
		Enabled:    &enabled,
	}
	if strings.TrimSpace(*name) != "" {
		spec.Name = name
	}
	if strings.TrimSpace(*connection) != "" {
		spec.TunnelID = connection
	}
	if wasSet(fs, "udp-timeout") {
		spec.UDPTimeoutSec = udpTimeout
	}
	if wasSet(fs, "expose") {
		spec.ExposeToNetwork = expose
	}

	created, err := client.CreateForward(ctx, spec)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Added %s (%s)\n  %s  ->  %s\n", created.Name, created.ID, created.Endpoint, created.Target)
	if !created.Enabled {
		fmt.Fprintln(env.Stdout, "  It is disabled; enable it from the dashboard when you want it running.")
	}
	return nil
}

func runRemove(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("rm", env)
	loc := addLocationFlags(fs)
	pos, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("rm takes exactly one forward name or id")
	}
	wanted := pos[0]

	client, err := loc.connect(env)
	if err != nil {
		return err
	}
	forwards, err := client.Forwards(ctx)
	if err != nil {
		return err
	}

	id, err := resolveForward(forwards, wanted)
	if err != nil {
		return err
	}
	if err := client.DeleteForward(ctx, id); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Removed %s\n", wanted)
	return nil
}

// resolveForward accepts an id or a name. An ambiguous name is refused rather than
// resolved arbitrarily: deleting the wrong forward is not recoverable from the CLI.
func resolveForward(forwards []httpapi.ForwardView, wanted string) (string, error) {
	for _, f := range forwards {
		if f.ID == wanted {
			return f.ID, nil
		}
	}

	var matches []httpapi.ForwardView
	for _, f := range forwards {
		if strings.EqualFold(f.Name, wanted) {
			matches = append(matches, f)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].ID, nil
	case 0:
		return "", fmt.Errorf("no forward named %q; run `app-tail list` to see them", wanted)
	default:
		ids := make([]string, 0, len(matches))
		for _, f := range matches {
			ids = append(ids, f.ID)
		}
		return "", fmt.Errorf("%d forwards are named %q; remove one by id instead (%s)",
			len(matches), wanted, strings.Join(ids, ", "))
	}
}

func runProvision(_ context.Context, args []string, env Env) error {
	fs := newFlagSet("provision", env)
	loc := addLocationFlags(fs)
	profilePath := fs.String("profile", "", "path to the provisioning profile to apply (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "provision"); err != nil {
		return err
	}
	if strings.TrimSpace(*profilePath) == "" {
		return usagef("provision needs --profile FILE")
	}

	profile, err := config.LoadProfile(*profilePath)
	if err != nil {
		return err
	}
	store, err := loc.store(env)
	if err != nil {
		return err
	}
	applied, err := config.Provision(store, profile)
	if err != nil {
		return err
	}

	fmt.Fprintf(env.Stdout, "Applied %s to %s\n", *profilePath, store.Path())
	// A profile's tailnet settings land on the connection this app has always run, so
	// that is where they are read back from to report what the profile did.
	primary, _ := applied.Tunnel(config.PrimaryTunnelID)
	tailnet := primary.TS()
	fmt.Fprintf(env.Stdout, "  hostname template: %s\n", tailnet.HostnameTemplate)
	if len(tailnet.Tags) > 0 {
		fmt.Fprintf(env.Stdout, "  tags:              %s\n", strings.Join(tailnet.Tags, ", "))
	}
	fmt.Fprintf(env.Stdout, "  forwards:          %d\n", len(applied.Forwards))
	fmt.Fprintln(env.Stdout, "Re-running this command with the same profile changes nothing further.")
	return nil
}

func runInstallAutostart(_ context.Context, args []string, env Env) error {
	fs := newFlagSet("install-autostart", env)
	remove := fs.Bool("remove", false, "remove the login item instead of installing it")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "install-autostart"); err != nil {
		return err
	}

	// No arguments are recorded: the login item runs plain `app-tail`, which picks
	// tray or headless mode from whatever session it lands in.
	manager, err := loginItem(env)
	if err != nil {
		return err
	}
	if err := manager.SetEnabled(!*remove); err != nil {
		return err
	}

	if *remove {
		fmt.Fprintf(env.Stdout, "Removed the app-tail login item (%s).\n", manager.Path())
		return nil
	}
	fmt.Fprintf(env.Stdout, "app-tail will start when you log in.\n  %s: %s\n  runs: %s\n",
		manager.Kind(), manager.Path(), manager.ExecPath)
	if warning := manager.TemporaryPathWarning(); warning != "" {
		fmt.Fprintf(env.Stderr, "Warning: %s\n", warning)
	}
	return nil
}

func runBootstrapPolicy(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("bootstrap-policy", env)
	var (
		clientID    = fs.String("client-id", "", "OAuth client id with policy_file scope (required)")
		secretFile  = fs.String("client-secret-file", "", "file holding the OAuth client secret")
		tailnet     = fs.String("tailnet", policy.DefaultTailnet, "tailnet to edit; \"-\" means the client's own")
		tag         = fs.String("tag", config.DefaultTag, "tag app-tail nodes self-assign")
		owners      = fs.String("owners", "", "comma-separated owners allowed to apply the tag")
		grantDsts   = fs.String("grant-dst", "", "comma-separated destinations tagged nodes may reach")
		grantIPs    = fs.String("grant-ip", "", "comma-separated port specs for the grant; empty means all ports")
		dryRun      = fs.Bool("dry-run", false, "show what would change without writing it")
		apiURL      = fs.String("api-url", policy.DefaultBaseURL, "Tailscale API base URL")
		allowAnyAPI = fs.Bool("allow-foreign-api-url", false,
			"permit --api-url to name a host outside tailscale.com (still requires https)")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "bootstrap-policy"); err != nil {
		return err
	}
	if strings.TrimSpace(*clientID) == "" {
		return usagef("bootstrap-policy needs --client-id")
	}
	// Checked before the secret is even read, so a bad --api-url never gets near it.
	// policy.Authenticate enforces the same rule again as the real boundary.
	if err := policy.ValidateBaseURL(*apiURL, *allowAnyAPI); err != nil {
		return usagef("%s", err)
	}

	secret, err := bootstrapSecret(env, *secretFile)
	if err != nil {
		return err
	}

	opts := policy.Options{
		Tag:       *tag,
		Owners:    splitList(*owners),
		GrantDsts: splitList(*grantDsts),
		GrantIPs:  splitList(*grantIPs),
	}
	if err := opts.Validate(); err != nil {
		return err
	}

	client := policy.NewClient(*apiURL, *tailnet, nil)
	client.AllowForeignHost = *allowAnyAPI
	if err := client.Authenticate(ctx, *clientID, secret); err != nil {
		return err
	}

	if *dryRun {
		doc, err := client.Fetch(ctx)
		if err != nil {
			return err
		}
		plan, err := policy.PlanBootstrap(doc.Raw, opts)
		if err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "Would %s.\n", plan.Summary())
		printNotes(env, plan.Notes)
		return nil
	}

	result, err := policy.Bootstrap(ctx, client, opts)
	if err != nil {
		return err
	}
	if result.Changed {
		fmt.Fprintf(env.Stdout, "Updated the tailnet policy: %s.\n", result.Plan.Summary())
	} else {
		fmt.Fprintln(env.Stdout, "The tailnet policy already allows this fleet; nothing changed.")
	}
	printNotes(env, result.Plan.Notes)
	return nil
}

func printNotes(env Env, notes []string) {
	for _, note := range notes {
		fmt.Fprintf(env.Stdout, "  note: %s\n", note)
	}
}

// bootstrapSecret reads the policy_file OAuth secret. There is deliberately no
// --client-secret flag: a secret in argv is visible to every process on the machine.
func bootstrapSecret(env Env, secretFile string) (string, error) {
	if path := strings.TrimSpace(secretFile); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read the client secret: %w", err)
		}
		secret := strings.TrimSpace(string(data))
		if secret == "" {
			return "", fmt.Errorf("the client secret file %s is empty", path)
		}
		return secret, nil
	}
	for _, key := range []string{config.EnvOAuthSecret, config.EnvTSClientSecret} {
		if secret := strings.TrimSpace(env.Getenv(key)); secret != "" {
			return secret, nil
		}
	}
	return "", usagef("no OAuth client secret was supplied; set %s or pass --client-secret-file",
		config.EnvOAuthSecret)
}

// splitList parses a comma-separated flag value, dropping empty entries.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func ptr[T any](v T) *T { return &v }
