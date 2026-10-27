// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/grants/grantwrite"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// runTun dispatches the network-interface subcommands.
//
// These are the only commands that work on the machine rather than through the agent, so
// none of them connects to it: two of them run as root, and one of them is what the system
// starts at boot, long before any agent exists.
func runTun(ctx context.Context, args []string, env Env) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runTunDoctor(ctx, args, env)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "doctor":
		return runTunDoctor(ctx, rest, env)
	case "setup":
		return runTunSetup(ctx, rest, env)
	case "install-helper":
		return runTunInstallHelper(ctx, rest, env)
	case "uninstall-helper":
		return runTunUninstallHelper(ctx, rest, env)
	case "helper":
		return runTunHelper(ctx, rest, env)
	case "grant":
		return runTunGrant(rest, env)
	default:
		return usagef("unknown tun subcommand %q; use `tun doctor`, `tun setup`, `tun install-helper`, `tun uninstall-helper` or `tun grant`", sub)
	}
}

// runTunSetup gets this machine ready for the interface mode, asking macOS for the rights
// it needs instead of requiring the command to be run as root.
//
// It exists beside install-helper rather than replacing it: install-helper is what the
// dialog itself runs, and what a fleet deployment scripts with its own escalation.
func runTunSetup(ctx context.Context, args []string, env Env) error {
	return tunSetup(ctx, args, env, supportsHelperInstall(), tsnode.ProvisionInterface)
}

// tunSetup is what the setup command does, separated from the machine it does it to.
//
// The arrangement is a value because the real one raises the system's password dialog,
// which a suite must never raise, and the platform's answer is passed in so both replies
// are reachable from any machine -- otherwise each is only ever exercised where it belongs,
// and the other is whatever it was last edited to say.
func tunSetup(ctx context.Context, args []string, env Env, canInstall bool, provision func(context.Context, func(string, ...any), bool, string) error) error {
	fs := newFlagSet("tun setup", env)
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "tun setup"); err != nil {
		return err
	}
	if !canInstall {
		return errors.New(noInstallerHere)
	}
	configPath, err := setupConfigPath(env, loc)
	if err != nil {
		return err
	}

	fmt.Fprintln(env.Stdout, "Setting this machine up for the network-interface mode.")
	fmt.Fprintln(env.Stdout, "macOS will ask for your password, because creating a network interface needs administrator rights.")
	if configPath != "" {
		fmt.Fprintf(env.Stdout, "The same password will also approve the network changes the settings in %s use.\n", configPath)
	}
	// Always allowed to elevate: raising the dialog is what somebody ran this command for.
	if err := provision(ctx, tunLogf(env), true, configPath); err != nil {
		if errors.Is(err, hostnet.ErrDeclined) {
			return errors.New("the request for administrator rights was declined, so this machine is not set up. " +
				"app-tail keeps working in the contained mode, where only its own forwards and proxy reach the tailnet")
		}
		return err
	}
	fmt.Fprintln(env.Stdout, "\nThis machine is ready. Turn the network-interface mode on in Settings, or with:")
	fmt.Fprintf(env.Stdout, "  %s\n", tunEnableCommand)
	return nil
}

// setupConfigPath is the config whose network changes the setup also approves, or "" when there
// is none to read. A machine set up before its first run has no config yet, which is fine; a
// config named on the command line that is not there is a mistake worth stopping for.
func setupConfigPath(env Env, loc location) (string, error) {
	path, err := loc.path(env)
	if err != nil {
		return "", err
	}
	_, err = os.Stat(path)
	switch {
	case err == nil:
		return path, nil
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("read the config at %s: %w", path, err)
	case *loc.configPath != "" || *loc.stateDir != "":
		return "", usagef("there is no config file at %s", path)
	default:
		return "", nil
	}
}

func runTunDoctor(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("tun doctor", env)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "tun doctor"); err != nil {
		return err
	}

	report := tsnode.InspectInterface(ctx, tunLogf(env))
	if *asJSON {
		return writeJSON(env, tunDoctorJSON{InterfaceReport: report, CallerCheck: helperCallerCheck()})
	}
	return writeTunReport(env, report)
}

// tunDoctorJSON is the doctor's report with how the helper tells app-tail from other
// programs, which belongs to this build rather than to the interface report.
type tunDoctorJSON struct {
	tsnode.InterfaceReport
	CallerCheck hostnet.CallerCheck `json:"callerCheck,omitempty"`
}

// tunLogf carries the privileged side's own account of what it did to the terminal that
// asked for it. The install and the removal each have steps whose failure does not stop
// them, and a half-done change to a machine that says nothing is the worst version of one.
func tunLogf(env Env) func(format string, args ...any) {
	return func(format string, args ...any) {
		fmt.Fprintf(env.Stderr, format+"\n", args...)
	}
}

// writeTunReport renders the report for a person. The order is the order the questions get
// asked in: can this machine do it, is the privileged part there, and is anything already
// wrong.
func writeTunReport(env Env, r tsnode.InterfaceReport) error {
	if !r.Supported {
		fmt.Fprintf(env.Stdout, "app-tail cannot run on a network interface on %s.\n", r.Platform)
		fmt.Fprintln(env.Stdout, "The contained mode works everywhere and needs no rights at all.")
		return nil
	}

	rows := [][2]string{
		{"Platform", r.Platform},
		{"Interface mode", "available on this platform"},
		{"This process", tunPrivilegeWord(r.Privileged)},
	}
	if r.Interface != "" {
		rows = append(rows, [2]string{"Interface name", r.Interface})
	} else {
		rows = append(rows, [2]string{"Interface name", "chosen by the system when it is created"})
	}
	rows = append(rows, [2]string{"Privileged helper", tunHelperWord(r)})
	if r.Helper.Socket != "" && r.Helper.Design {
		rows = append(rows, [2]string{"Helper socket", r.Helper.Socket})
	}
	if r.Helper.Version != "" {
		rows = append(rows, [2]string{"Helper version", r.Helper.Version})
	}
	// How far the helper's trust in a caller goes, so someone deciding whether to install it
	// on a shared machine reads what it accepts rather than assuming.
	if r.Helper.Design {
		rows = append(rows, [2]string{"Helper accepts", helperCallerCheck().Describe()})
	}

	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "%s:\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	if r.Helper.Problem != "" && !r.Helper.Running {
		fmt.Fprintf(env.Stdout, "\n%s\n", r.Helper.Problem)
	}
	if r.Missing != "" {
		fmt.Fprintf(env.Stdout, "\nMissing: %s\n", r.Missing)
	}
	if r.Conflict != "" {
		fmt.Fprintf(env.Stdout, "\nConflict: %s\n", r.Conflict)
	}
	if len(r.Leftovers) > 0 {
		fmt.Fprintf(env.Stdout, "\nA previous run left these behind:\n")
		for _, item := range r.Leftovers {
			fmt.Fprintf(env.Stdout, "  %s\n", item)
		}
		fmt.Fprintln(env.Stdout, "Starting in the interface mode clears them. To remove them by hand:")
		for _, cmd := range r.Undo {
			fmt.Fprintf(env.Stdout, "  %s\n", cmd)
		}
	}
	// Reported here and not only on the DNS card, because this is the command someone runs
	// to ask what app-tail has done to their machine. A redirected resolver is the one
	// change that outlives the process that made it, so a report that called the machine
	// clean while it was in force would be the report that hides the only leftover that
	// can stop this machine resolving anything.
	if r.StaleOverride != "" {
		fmt.Fprintf(env.Stdout, "\nName resolution: %s\n", r.StaleOverride)
		fmt.Fprintln(env.Stdout, "To put it back now:")
		fmt.Fprintf(env.Stdout, "  %s\n", restoreDNSCommand(runtime.GOOS))
	}
	if r.Conflict == "" && r.Missing == "" && len(r.Leftovers) == 0 && r.StaleOverride == "" {
		fmt.Fprintln(env.Stdout, "\nThis machine is clean: app-tail has nothing installed on it outside its own folder.")
	}
	return nil
}

// restoreDNSCommand is the command that puts this machine's resolver back, written the way
// the platform obtains administrator rights. `sudo` is not a program on Windows, so a user
// who pastes that line gets "not recognized" instead of their resolver back.
//
// The platform is passed in rather than read here so both lines are reachable from any
// machine, and not only from the one each belongs to.
func restoreDNSCommand(goos string) string {
	if goos == "windows" {
		return "app-tail dns restore   (from a Command Prompt or PowerShell started as administrator)"
	}
	return "sudo app-tail dns restore"
}

func tunPrivilegeWord(privileged bool) string {
	if privileged {
		return "has administrator rights, so it needs no helper"
	}
	return "runs as you, without administrator rights"
}

// tunHelperWord is one sentence covering every combination of the helper's four states,
// because a table cell reading "false" answers none of the questions someone running the
// doctor actually has.
func tunHelperWord(r tsnode.InterfaceReport) string {
	switch {
	case !r.Helper.Design && r.Privileged:
		return "not used on this platform, and this process already has the rights"
	case !r.Helper.Design:
		return "not used on this platform: app-tail asks for administrator rights when it needs them"
	case r.Helper.Running:
		return "installed and answering"
	case r.Helper.Installed:
		return "installed, but not answering"
	case !r.Helper.Installable:
		return "not installed: start it with `sudo app-tail tun helper`"
	default:
		return "not installed: run `app-tail tun setup` and app-tail will ask for your password"
	}
}

// The privileged install step is behind package variables for the reason showAlert is: the
// real one edits launchd and asks for a password, and what this command prints and refuses
// around it has to be reachable from a test on any platform.
var (
	supportsHelperInstall = hostnet.SupportsHelperInstall
	installHelper         = hostnet.InstallHelper
	uninstallHelper       = hostnet.UninstallHelper
	helperCallerCheck     = hostnet.HelperCallerCheck
)

// The approvals file is root's, and the machine's networks are the suite's machine's, so
// both are behind package variables for the same reason.
var (
	grantsPath       = grants.Path
	loadGrants       = grants.Load
	writeGrants      = grantwrite.Write
	grantsPrivileged = hostnet.Privileged
	attachedNetworks = hostnet.AttachedNetworks
)

func runTunInstallHelper(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("tun install-helper", env)
	owner := fs.String("owner", "", "user id the helper takes commands from, defaulting to the account that ran sudo")
	grant := fs.Bool("grant", false, "also approve everything the current config asks the helper for (see `tun grant`)")
	loc := addLocationFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "tun install-helper"); err != nil {
		return err
	}
	if !supportsHelperInstall() {
		return errors.New(noInstallerHere)
	}

	uid, err := helperOwner(env, *owner)
	if err != nil {
		return err
	}
	// Worked out before anything is installed, so a config that cannot be read stops the
	// command while the machine is still as it was.
	var needed []grants.Need
	var configPath string
	if *grant {
		if configPath, err = loc.path(env); err != nil {
			return err
		}
		if needed, err = configNeeds(configPath); err != nil {
			return err
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program's own path to install it: %w", err)
	}
	if err := installHelper(ctx, tunLogf(env), exe, uid); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Installed the app-tail helper, serving user %d.\n", uid)
	if *grant {
		if len(needed) == 0 {
			fmt.Fprintf(env.Stdout, "Nothing in %s needs an approval.\n", configPath)
		} else {
			fmt.Fprintf(env.Stdout, "Approving what %s asks for:\n", configPath)
			add, err := needsDocument(needed)
			if err != nil {
				return err
			}
			if err := approve(env, add); err != nil {
				return err
			}
		}
	}
	fmt.Fprintln(env.Stdout, "Turn on the network-interface mode in Settings, or with:")
	fmt.Fprintf(env.Stdout, "  %s\n", tunEnableCommand)
	return nil
}

// grantList is a flag that may be given more than once.
type grantList []string

func (g *grantList) String() string { return strings.Join(*g, ",") }

func (g *grantList) Set(v string) error {
	*g = append(*g, v)
	return nil
}

// runTunGrant records what an administrator approves app-tail to do to this machine. The
// helper refuses the rest, and every refusal names the `tun grant` flags that approve it.
// Approvals are added to what is already there; nothing here takes one away.
func runTunGrant(args []string, env Env) error {
	fs := newFlagSet("tun grant", env)
	fullTunnel := fs.Bool("full-tunnel", false, "approve carrying all of this machine's internet traffic through app-tail")
	var routes, domains, remotes grantList
	fs.Var(&routes, "route", "approve sending an address range (CIDR) through app-tail; repeatable")
	systemDNS := fs.Bool("system-dns", false, "approve app-tail deciding how this machine resolves every name")
	fs.Var(&domains, "dns-domain", "approve app-tail answering lookups for a domain and everything under it; repeatable")
	fs.Var(&remotes, "openvpn", "approve an OpenVPN server, as host:port=SHA256[,SHA256...] naming the SHA-256 of each "+
		"certificate its certificate authority may hold; repeatable")
	tls := fs.Bool("tls-interception", false, "approve opening encrypted connections so the intrusion prevention feature can inspect them")
	show := fs.Bool("show", false, "print what is approved and change nothing")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "tun grant"); err != nil {
		return err
	}

	add := grants.Document{
		Version:         grants.Version,
		FullTunnel:      *fullTunnel,
		SystemDNS:       *systemDNS,
		DNSDomains:      domains,
		TLSInterception: *tls,
	}
	for _, raw := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return usagef("--route %q is not an address range such as 203.0.113.0/24", raw)
		}
		add.Routes = append(add.Routes, prefix)
	}
	for _, raw := range remotes {
		remote, err := parseOpenVPNGrant(raw)
		if err != nil {
			return err
		}
		add.OpenVPN = append(add.OpenVPN, remote)
	}
	adding := add.FullTunnel || add.SystemDNS || add.TLSInterception ||
		len(add.Routes) > 0 || len(add.DNSDomains) > 0 || len(add.OpenVPN) > 0

	if *show {
		if adding {
			return usagef("--show prints what is approved and changes nothing, so it takes no approvals to add")
		}
		path, err := grantsPath()
		if err != nil {
			return err
		}
		current, err := loadGrants(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "Approvals in %s:\n", path)
		return writeGrantsSummary(env, current)
	}
	if !adding {
		return usagef("name what to approve (--full-tunnel, --route, --system-dns, --dns-domain, --openvpn, --tls-interception), or pass --show")
	}
	return approve(env, add)
}

// approve adds add to the approvals file and reads the result back the way the helper will.
func approve(env Env, add grants.Document) error {
	if !grantsPrivileged() {
		return errors.New(grantNeedsAdmin(runtime.GOOS))
	}
	path, err := grantsPath()
	if err != nil {
		return err
	}
	// The existing approvals are read through the same check the helper applies, so a file
	// somebody else could have written is reported rather than merged into one root signs.
	current, err := loadGrants(path)
	if err != nil {
		return err
	}
	merged, err := current.With(add)
	if err != nil {
		return err
	}
	if err := writeGrants(path, merged); err != nil {
		return err
	}
	stored, err := loadGrants(path)
	if err != nil {
		return fmt.Errorf("the approvals were written to %s, and the helper would not accept the file: %w", path, err)
	}
	fmt.Fprintf(env.Stdout, "Approved. Everything approved in %s:\n", path)
	return writeGrantsSummary(env, stored)
}

// grantNeedsAdmin is the refusal for a command run without administrator rights, written the
// way the platform obtains them.
func grantNeedsAdmin(goos string) string {
	if goos == "windows" {
		return "approving needs administrator rights: run it from a Command Prompt or PowerShell started as administrator"
	}
	return "approving needs administrator rights: run it with sudo, as `sudo app-tail tun grant ...`"
}

// parseOpenVPNGrant reads host:port=SHA256[,SHA256...]. The split is on the last "=" because
// nothing in a digest is one.
func parseOpenVPNGrant(raw string) (grants.OpenVPNRemote, error) {
	i := strings.LastIndex(raw, "=")
	if i < 0 {
		return grants.OpenVPNRemote{}, usagef("--openvpn %q needs the certificate authority it is approved with, as host:port=SHA256[,SHA256...]", raw)
	}
	remote := grants.OpenVPNRemote{Remote: strings.TrimSpace(raw[:i])}
	for _, pin := range strings.Split(raw[i+1:], ",") {
		if pin = strings.TrimSpace(pin); pin != "" {
			remote.CASHA256 = append(remote.CASHA256, pin)
		}
	}
	// Checked here so a mistyped digest is a usage error on this line rather than a refusal
	// from deep inside the write.
	if _, err := (grants.Document{Version: grants.Version, OpenVPN: []grants.OpenVPNRemote{remote}}).With(grants.None()); err != nil {
		return grants.OpenVPNRemote{}, usagef("--openvpn %q: %v", raw, err)
	}
	return remote, nil
}

// writeGrantsSummary lists what a document approves, one kind per line.
func writeGrantsSummary(env Env, doc grants.Document) error {
	yes := func(b bool) string {
		if b {
			return "approved"
		}
		return "not approved"
	}
	list := func(items []string) string {
		if len(items) == 0 {
			return "none"
		}
		return strings.Join(items, ", ")
	}
	var routes []string
	for _, p := range doc.Routes {
		routes = append(routes, p.String())
	}
	var servers []string
	for _, r := range doc.OpenVPN {
		servers = append(servers, r.Remote+" (certificate authority "+strings.Join(r.CASHA256, ", ")+")")
	}
	writer := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(writer, "  All traffic:\t%s\n", yes(doc.FullTunnel))
	fmt.Fprintf(writer, "  Address ranges:\t%s\n", list(routes))
	fmt.Fprintf(writer, "  Name resolution:\t%s\n", yes(doc.SystemDNS))
	fmt.Fprintf(writer, "  DNS domains:\t%s\n", list(doc.DNSDomains))
	fmt.Fprintf(writer, "  OpenVPN servers:\t%s\n", list(servers))
	fmt.Fprintf(writer, "  TLS interception:\t%s\n", yes(doc.TLSInterception))
	return writer.Flush()
}

// needsDocument is the approvals that answer every need.
func needsDocument(needs []grants.Need) (grants.Document, error) {
	doc := grants.None()
	for _, need := range needs {
		switch need.Kind {
		case grants.KindFullTunnel:
			doc.FullTunnel = true
		case grants.KindRoute:
			p, err := netip.ParsePrefix(need.Value)
			if err != nil {
				return grants.Document{}, fmt.Errorf("the config asks for a route the approvals cannot name: %w", err)
			}
			doc.Routes = append(doc.Routes, p)
		case grants.KindSystemDNS:
			doc.SystemDNS = true
		case grants.KindDNSDomain:
			doc.DNSDomains = append(doc.DNSDomains, need.Value)
		case grants.KindOpenVPNRemote:
			doc.OpenVPN = append(doc.OpenVPN, grants.OpenVPNRemote{Remote: need.Value, CASHA256: need.CASHA256})
		case grants.KindTLSInterception:
			doc.TLSInterception = true
		default:
			return grants.Document{}, fmt.Errorf("the config asks for an approval of a kind this command does not know: %q", need.Kind)
		}
	}
	return doc, nil
}

// configNeeds is every approval the config at path will ask the helper for.
//
// The file is decoded rather than opened as a store. This runs as root, and opening the store
// writes -- a fresh document where none exists, a quarantined copy of one it cannot use --
// which would leave root-owned files in the account's own folder that its agent then cannot
// replace.
func configNeeds(path string) ([]grants.Need, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the config the approvals are for (%s; pass --config or --state-dir to name another): %w", path, err)
	}
	var cfg config.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("read the config the approvals are for (%s): %w", path, err)
	}
	attached, err := attachedNetworks()
	if err != nil {
		return nil, err
	}
	return tsnode.NeedsOf(&cfg, attached)
}

// tunEnableCommand turns the mode on. Both settings travel in one command because the
// mode is refused while the module switch that reveals it is off.
const tunEnableCommand = "app-tail settings set --interface=true --interface-mode=tun"

// noInstallerHere is the message for a platform that has no install step. It is a constant
// rather than the package's own error text so the CLI says what to do here rather than
// what this platform is not.
const noInstallerHere = "there is nothing to install on this platform: " +
	"on Windows app-tail asks for administrator rights when it needs them, " +
	"and elsewhere the helper runs in the foreground with `sudo app-tail tun helper`"

// helperOwner resolves the account the helper will serve.
//
// The default comes from SUDO_UID because the command is run under sudo, and the account
// that ran sudo is the one whose agent will connect. Getting this wrong is not a cosmetic
// problem: the recorded owner is the whole access control on a root socket, so an
// unresolvable one is a refusal rather than a guess.
func helperOwner(env Env, flagValue string) (int, error) {
	raw := flagValue
	if raw == "" {
		raw = env.Getenv("SUDO_UID")
	}
	if raw == "" {
		return 0, errors.New("app-tail could not tell which account the helper should serve. " +
			"Run this as `sudo app-tail tun install-helper` from your own account, " +
			"or pass --owner with your user id (`id -u`)")
	}
	uid, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("read the user id %q the helper should serve: %w", raw, err)
	}
	if uid == 0 {
		return 0, errors.New("the helper serves an ordinary account, and root is not one. " +
			"Run `sudo app-tail tun install-helper` from your own account rather than from a root shell")
	}
	return uid, nil
}

func runTunUninstallHelper(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("tun uninstall-helper", env)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "tun uninstall-helper"); err != nil {
		return err
	}
	if !supportsHelperInstall() {
		return errors.New(noInstallerHere)
	}
	if err := uninstallHelper(ctx, tunLogf(env)); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Removed the app-tail helper and everything it had installed.")
	fmt.Fprintln(env.Stdout, "The contained mode still works, and needs no rights at all.")
	return nil
}

// runTunHelper is the helper process itself: what the system starts, not what a person
// runs. It stays in the foreground until it is stopped, which is what a service manager
// expects and what makes the connection-drop teardown work.
func runTunHelper(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("tun helper", env)
	socket := fs.String("socket", "", "path to listen on, defaulting to the standard location")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "tun helper"); err != nil {
		return err
	}
	logf := func(format string, a ...any) {
		fmt.Fprintf(env.Stderr, format+"\n", a...)
	}
	return hostnet.RunHelper(ctx, *socket, logf)
}
