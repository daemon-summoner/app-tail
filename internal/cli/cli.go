// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/alert"
	"github.com/sellitus/app-tail/internal/autostart"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/elevate"
	"github.com/sellitus/app-tail/internal/fileown"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// Env is the process context a command runs in. Every side effect a command has
// beyond the network goes through here, so the whole surface is testable.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	Getenv config.Getenv

	// RunAgent starts the long-lived agent. main supplies it because only main can
	// own the goroutine the system tray's event loop requires.
	RunAgent func(ctx context.Context, flags config.Flags) error

	// Claim is how a run takes sole ownership of the state directory it was pointed at.
	// main supplies it for the same reason it supplies RunAgent: what it holds outlives
	// this command, and main is what starts a replacement on a restart.
	Claim Claim

	// Version is the build this binary reports.
	Version string
}

// Claim is one app-tail per state directory, as the agent's runner needs it.
//
// Taking it stops whatever agent already has that directory, so the two never share the
// dashboard port, the config file, or -- with the network-interface mode on -- this
// machine's resolver, proxy settings and routes.
type Claim interface {
	// Take claims the directory these flags resolve to, returning once this process is the
	// only app-tail on it. It blocks while the agent already running shuts down.
	Take(ctx context.Context, flags config.Flags) error
	// Release gives the claim up, and is safe to call more than once.
	Release() error
}

// ErrUsage marks a mistake in how the command was invoked, so main can exit 2 and
// keep that distinct from the command running and failing.
var ErrUsage = errors.New("usage")

// usagef builds a usage error.
func usagef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, args...))
}

// Run dispatches one invocation. args excludes the program name.
func Run(ctx context.Context, args []string, env Env) error {
	if env.Getenv == nil {
		env.Getenv = config.OSGetenv
	}

	name := "run"
	rest := args
	switch {
	// Matched before the bare-flag case below, which would otherwise route a
	// leading -h into run's flag set and report it as a usage error.
	case len(args) > 0 && (args[0] == "-h" || args[0] == "--help"):
		name, rest = "help", args[1:]
	case len(args) > 0 && !strings.HasPrefix(args[0], "-"):
		name, rest = args[0], args[1:]
	}

	// help is handled here rather than in the command table: its body reads usageText,
	// which is built from the table, so listing it there would be an initialization cycle.
	if name == "help" {
		fmt.Fprint(env.Stdout, usageText)
		return nil
	}

	cmd, ok := commandByName(name)
	if !ok {
		return usagef("unknown command %q; run `app-tail help` for the list", name)
	}
	return cmd.run(ctx, rest, env)
}

// runAgent parses the agent's flags and hands off to main's runner.
func runAgent(ctx context.Context, args []string, env Env) error {
	fs := newFlagSet("run", env)

	var (
		headless         = fs.Bool("headless", false, "run without a system tray, dashboard only")
		verbose          = fs.Bool("verbose", false, "log tailscale internals at debug level")
		configPath       = fs.String("config", "", "path to the config file")
		stateDir         = fs.String("state-dir", "", "directory holding config and tailnet state")
		uiAddr           = fs.String("ui-addr", "", "loopback address for the dashboard, e.g. 127.0.0.1:8377")
		hostname         = fs.String("hostname", "", "device name to present on the tailnet")
		tags             = fs.String("tags", "", "comma-separated tags to advertise, e.g. tag:app-tail")
		controlURL       = fs.String("control-url", "", "control plane URL for Headscale or a custom coordinator")
		ephemeral        = fs.Bool("ephemeral", false, "leave no device record behind when this process exits")
		advTags          = fs.Bool("advertise-tags-on-login", false, "advertise tags during interactive browser login (login user must own them in tagOwners)")
		noElevate        = fs.Bool("no-elevate", false, "never ask for administrator rights, even when the network-interface mode needs them")
		allowUnprotected = fs.Bool(allowUnprotectedElevationFlag, false,
			"ask for administrator rights even when app-tail is in a folder other accounts' programs could change (unsafe; run `app-tail install` instead)")
	)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := noPositionalArgs(fs, "run"); err != nil {
		return err
	}
	if env.RunAgent == nil {
		return errors.New("this build cannot start the agent")
	}
	// Refused rather than skipped: a build wired without a claim would start a second agent
	// beside the one already running, which is the state this whole path exists to prevent.
	if env.Claim == nil {
		return errors.New("this build cannot claim its state directory, so it cannot start the agent")
	}

	flags := config.Flags{
		ConfigPath:           setString(fs, "config", configPath),
		StateDir:             setString(fs, "state-dir", stateDir),
		UIAddr:               setString(fs, "ui-addr", uiAddr),
		Hostname:             setString(fs, "hostname", hostname),
		Tags:                 setString(fs, "tags", tags),
		ControlURL:           setString(fs, "control-url", controlURL),
		Ephemeral:            setBool(fs, "ephemeral", ephemeral),
		AdvertiseTagsOnLogin: setBool(fs, "advertise-tags-on-login", advTags),
		Headless:             setBool(fs, "headless", headless),
		Verbose:              setBool(fs, "verbose", verbose),
		NoElevate:            setBool(fs, "no-elevate", noElevate),
	}

	// Before any credential is read into memory: another process under this account could
	// otherwise attach to the agent and read them, or speak to the root helper as it.
	if err := hostnet.RefuseSameUserDebugging(); err != nil {
		return err
	}

	// Before anything binds a port or a state directory, because the answer may be that
	// a second copy of this program should own both.
	handedOff, err := elevateIfNeeded(ctx, env, flags, args, *noElevate, *allowUnprotected)
	if err != nil {
		return err
	}
	if handedOff {
		return nil
	}
	// Before the repair below and before the agent: what a *running* agent installed on this
	// machine is taken back by that agent's own shutdown, so a repair that ran first would be
	// undoing the live one's work, and an agent that started first would be the second on one
	// machine. Taking the claim ends that agent and waits for it.
	if err := env.Claim.Take(ctx, flags); err != nil {
		return err
	}
	defer func() {
		if err := env.Claim.Release(); err != nil {
			fmt.Fprintf(env.Stderr, "giving up the single-instance claim: %v\n", err)
		}
	}()

	// After the elevation question is settled, so the process holding the rights is the one
	// that undoes what a previous run left, and before the agent starts, so nothing this run
	// installs is taken back along with it.
	hostnet.RepairPreviousRun(ctx, tunLogf(env))
	return env.RunAgent(ctx, flags)
}

// elevateIfNeeded restarts app-tail with administrator rights when the stored settings
// select the network-interface mode and this process does not have them, and reports
// whether it handed off.
//
// Elevation happens here, at the very start, rather than at the moment the mode is
// switched on: a running agent holds the dashboard port and the state directory, so
// handing those to a second process would mean an ordered shutdown racing an ordered
// start. Starting the elevated copy before anything is bound has no such window -- there
// are two processes for a moment and only ever one that binds.
func elevateIfNeeded(ctx context.Context, env Env, flags config.Flags, args []string, noElevate, allowUnprotected bool) (bool, error) {
	// Answered from the platform first, so no machine that cannot elevate reads a config
	// file to find that out.
	if !elevate.Supported() {
		return false, nil
	}
	wants, err := storedRightsWants(ctx, env, flags)
	if err != nil {
		return false, err
	}
	if !elevate.Needed(rightsFacts(wants, noElevate)) {
		// The relaunched copy carries --no-elevate, so a machine where the prompt was granted
		// and the rights were then stripped by policy lands here with nothing said. Left
		// pointed at app-tail, that machine resolves no names and has just been told nothing
		// at all about why.
		if wants.staleOverride && noElevate && !hostnet.Privileged() && !hostnet.HasHelper() {
			warnStaleOverride(wants, nil)
		}
		return false, nil
	}
	// The machine is asked before anybody is: a feature that cannot run here is unavailable
	// whether or not this process holds administrator rights, so the prompt would buy
	// nothing and still has to be answered at every single start. The reason is the same one
	// the dashboard's cards report, so the two cannot disagree about what is in the way.
	if blocker := elevationBlocker(tsnode.InspectInterface(ctx, env.logf), wants); blocker != "" {
		fmt.Fprintf(env.Stderr, "Not asking for administrator rights: %s\n", blocker)
		fmt.Fprintln(env.Stderr, "app-tail will run in the contained mode, which forwards the ports you "+
			"configured and changes nothing on this machine.")
		return false, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("find this program's own path to restart it with administrator rights: %w", err)
	}
	// An elevated process starts in the system directory rather than where it was
	// launched from, so a relative --config or --state-dir would resolve somewhere else
	// entirely and the new process would come up against an empty configuration.
	dir, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("read the current directory to restart app-tail in it: %w", err)
	}

	// The path is settled here rather than at the prompt, because whatever is there when the
	// prompt is answered is what receives the rights. A refusal is one feature that cannot
	// start, as in the default branch below, so the rest of the app still runs.
	if err := vetElevationTarget(exe, allowUnprotected, fileown.ReplaceableByOtherAccounts, env.Stderr); err != nil {
		if !errors.Is(err, errUnprotectedElevation) {
			return false, err
		}
		fmt.Fprintf(env.Stderr, "Not asking for administrator rights: %v\n", err)
		fmt.Fprintln(env.Stderr, "app-tail will run in the contained mode, which forwards the ports you "+
			"configured and changes nothing on this machine.")
		warnStaleOverride(wants, err)
		return false, nil
	}

	// The subcommand name is put back because `app-tail --headless` reaches here as the
	// default command, and the new process is started from a path rather than from a
	// shell that would apply the same default.
	relaunch := elevate.Request{Exe: exe, Args: append([]string{"run"}, args...), Dir: dir}
	switch err := elevate.Relaunch(relaunch); {
	case err == nil:
		fmt.Fprintln(env.Stderr, "app-tail restarted with the administrator rights the network-interface mode needs.")
		return true, nil
	case errors.Is(err, elevate.ErrDeclined):
		fmt.Fprintln(env.Stderr, "Continuing without administrator rights: app-tail will run in the contained mode, "+
			"which forwards the ports you configured and changes nothing on this machine.")
		warnStaleOverride(wants, err)
		return false, nil
	default:
		// A relaunch that could not happen is one feature that cannot start, not a machine
		// that cannot run app-tail: the forwards and the proxy need no rights at all, and
		// exiting here would leave a user whose account cannot be elevated, or whose policy
		// blocks the verb, with nothing running rather than with most of the app.
		fmt.Fprintf(env.Stderr, "Could not restart app-tail with administrator rights: %v\n", err)
		fmt.Fprintln(env.Stderr, "app-tail will run in the contained mode, which forwards the ports you "+
			"configured and changes nothing on this machine.")
		warnStaleOverride(wants, err)
		return false, nil
	}
}

// allowUnprotectedElevationFlag lets one run elevate from a folder that is not protected.
//
// It is a flag and only a flag. An environment variable or a stored setting would be a
// switch the very program this guards against can flip once and leave on: anything running
// as this account can write HKCU\Environment and the config file, and cannot type on the
// command line of a run somebody else starts.
const allowUnprotectedElevationFlag = "allow-unprotected-elevation"

// errUnprotectedElevation marks a refusal to elevate a binary other programs could replace.
var errUnprotectedElevation = errors.New("app-tail is not installed where only administrators can change it")

// vetElevationTarget decides whether the program at exe may be started with administrator
// rights, and refuses with errUnprotectedElevation when it may not.
//
// Whatever is at that path when the prompt is answered is what receives the rights, and a
// folder this account can write is one anything already running as this account can put
// its own program into -- or its own wintun.dll, which the elevated copy loads from beside
// itself. That is code running as Administrator behind a prompt that names app-tail, so it
// is refused rather than warned about. allowUnprotected, from the per-run flag, lets one run
// through anyway with a warning.
//
// replaceable is the same check the login task makes before it registers a binary that runs
// elevated at every logon, passed in so every branch is reachable from a test on any
// platform.
func vetElevationTarget(exe string, allowUnprotected bool, replaceable func(string) (bool, string, error), stderr io.Writer) error {
	isReplaceable, reason, err := replaceable(exe)
	if err != nil {
		return fmt.Errorf("check whether app-tail could be replaced before it is started with administrator rights: %w", err)
	}
	if !isReplaceable {
		return nil
	}
	if allowUnprotected {
		fmt.Fprintf(stderr, "Warning: %s. --%s was passed, so it is being started with administrator rights anyway, "+
			"and anything else running as this account could replace it, or the wintun.dll beside it, before the "+
			"elevated copy starts. Run `app-tail install` to close that.\n", reason, allowUnprotectedElevationFlag)
		return nil
	}
	return fmt.Errorf("%w: %s, so anything else running as this account could replace it, or plant a wintun.dll "+
		"beside it, and have its own code started with administrator rights. Run `app-tail install` -- here, "+
		"\"%s\" install -- to put app-tail where only administrators can change it, then start it from there. "+
		"To accept that risk for one run, pass --%s", errUnprotectedElevation, reason, exe, allowUnprotectedElevationFlag)
}

// elevationBlocker reports what would stop the feature the stored settings ask for from
// running here, empty when nothing would.
//
// Which question is asked follows what was asked for: the two features are refused for
// different reasons -- a second tailnet client blocks the interface mode and says nothing
// about DNS, a busy port 53 is the other way round -- and reporting either one's blocker
// against the other is how a working feature reads as broken.
//
// Taking the report rather than reading the machine keeps the decision reachable from a
// test on any platform: the branch that matters only ever fires on the one that elevates.
//
// What it must never report is the rights themselves. Ready and ResolverReady answer "could
// this run now", and on a platform with no privileged helper the honest answer without the
// rights is "app-tail needs administrator rights" -- which, read here, refuses to ask for
// them because they are missing.
func elevationBlocker(report tsnode.InterfaceReport, wants rightsWants) string {
	// A machine an earlier run left pointed at app-tail is worth the rights whatever else is
	// in the way. Putting its resolver back is a teardown: a port 53 something else holds, or
	// a second tailnet client, says nothing about whether it can be done, and refusing here
	// leaves a machine that resolves no names with nothing that will ever repair it.
	if wants.staleOverride {
		return ""
	}
	if !wants.interfaceMode {
		return report.ResolverBlockerDespiteRights()
	}
	return report.BlockerDespiteRights()
}

// logf carries the interface scan's own diagnostics to the same stream every other line
// this command prints goes to. It is not discarded: a scan that had something to say
// about the machine is what explains a mode that then does not come up.
func (e Env) logf(format string, args ...any) {
	fmt.Fprintf(e.Stderr, "app-tail: "+format+"\n", args...)
}

// loginItem builds the login-item manager for the network mode this machine is set to.
//
// The mode is part of the manager rather than of one call because it decides which login
// item exists on Windows, not just how one behaves: a manager built without it would
// report on one form and remove the other.
func loginItem(env Env) (*autostart.Manager, error) {
	manager, err := autostart.New()
	if err != nil {
		return nil, err
	}
	// The default locations, because this is the login item for this machine's own
	// installation rather than for whichever config file a flag happened to name.
	wants, err := storedRightsWants(context.Background(), env, config.Flags{})
	if err != nil {
		return nil, err
	}
	// Either machine-level feature needs the same rights, so a login item that started
	// contained would leave whichever one is on unable to do its work at every login.
	manager.Elevated = wants.interfaceMode || wants.systemDNS
	return manager, nil
}

// rightsWants is what this machine's own state asks of administrator rights, decided
// before any agent exists to ask it.
type rightsWants struct {
	// interfaceMode is the stored settings selecting the network-interface mode.
	interfaceMode bool
	// systemDNS is the stored settings asking for this machine's own resolver to be
	// changed. The System default profile does not count: it deliberately changes nothing,
	// and prompting for it would be a password dialog for a setting that does nothing.
	systemDNS bool
	// staleOverride is a previous run that left this machine's name resolution pointed at
	// app-tail. It is a want of its own, because putting it back needs the same rights and
	// the feature being switched off now is exactly why nothing else would repair it.
	staleOverride bool
}

// storedRightsWants reports what the config on disk asks for, plus what an earlier run
// left behind on this machine.
//
// A config file that is not there yet is not opened, and that is deliberate: opening one
// creates it, and whether it existed is how the agent tells a first run from a later one
// and decides whether to open a browser.
func storedRightsWants(ctx context.Context, env Env, flags config.Flags) (rightsWants, error) {
	// Read first, and from the machine rather than the config: a stale override outlives
	// the settings that produced it, so it is the one want a missing config cannot rule out.
	wants := rightsWants{staleOverride: staleOverrideOnThisMachine(ctx)}

	dir, err := config.ResolveStateDir(flags, env.Getenv)
	if err != nil {
		return rightsWants{}, err
	}
	path := config.ResolveConfigPath(flags, env.Getenv, dir)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return wants, nil
		}
		return rightsWants{}, fmt.Errorf("read %s: %w", path, err)
	}
	store, err := config.Open(path)
	if err != nil {
		return rightsWants{}, err
	}
	s := store.Settings()
	wants.interfaceMode = s.InterfaceSelected()
	wants.systemDNS = dnsprofiles.OverrideWanted(s)
	return wants, nil
}

// newFlagSet builds a flag set that reports errors through the returned error
// rather than exiting the process, and prints its help to the command's own stderr.
func newFlagSet(name string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

// ErrHelpShown reports that a command printed its own flag list because the user
// asked for it. The overview tells people to run `app-tail <command> --help`, so
// it is a success, not the misuse that ErrUsage stands for.
var ErrHelpShown = errors.New("help shown")

// parseFlags parses args for one subcommand, keeping a help request distinct from
// a genuine mistake.
func parseFlags(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, flag.ErrHelp):
		return ErrHelpShown
	default:
		return usagef("%v", err)
	}
}

// noPositionalArgs rejects leftover arguments. Without this a typo like
// `app-tail add --target host:22 extra` would be silently ignored.
func noPositionalArgs(fs *flag.FlagSet, name string) error {
	if fs.NArg() > 0 {
		return usagef("%s takes no positional arguments, got %q", name, strings.Join(fs.Args(), " "))
	}
	return nil
}

// parsePositionals parses args where positional arguments may appear before, after,
// or between flags. Go's flag package stops at the first positional, so a natural
// `forward update dns --target X` would leave --target unparsed; this peels off one
// positional each time parsing halts on a non-flag, then re-parses the remainder, so
// the flag/positional order no longer matters.
func parsePositionals(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := parseFlags(fs, args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// setString returns the flag's value only when it was actually passed, which is what
// keeps an unset flag from overriding the config file with an empty string.
func setString(fs *flag.FlagSet, name string, value *string) *string {
	if !wasSet(fs, name) {
		return nil
	}
	return value
}

func setBool(fs *flag.FlagSet, name string, value *bool) *bool {
	if !wasSet(fs, name) {
		return nil
	}
	return value
}

func wasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// openStore resolves the config location the same way the agent does and opens it.
// Commands that work offline use this; commands that talk to a running agent use it
// only to discover where that agent is listening.
func openStore(env Env, configPath, stateDir string) (*config.Store, error) {
	store, _, err := openStoreIn(env, configPath, stateDir)
	return store, err
}

// openStoreIn opens the stored config and reports the state directory it belongs to.
// The two are resolved together because a command that acts on a file beside the config
// -- the system-proxy restore record -- has to act in the directory the store came from,
// and resolving it separately would be a second answer to the same question.
func openStoreIn(env Env, configPath, stateDir string) (*config.Store, string, error) {
	path, dir, err := resolveConfigLocation(env, configPath, stateDir)
	if err != nil {
		return nil, "", err
	}
	store, err := config.Open(path)
	if err != nil {
		return nil, "", err
	}
	return store, dir, nil
}

// resolveConfigLocation reports where the config file is and which state directory it
// belongs to, without opening or creating it. The commands that repair a config need the
// path on its own: opening the store is what writes a fresh document over one that could
// not be loaded, which is the very thing they exist to let a person decide about.
func resolveConfigLocation(env Env, configPath, stateDir string) (string, string, error) {
	flags := config.Flags{}
	if configPath != "" {
		flags.ConfigPath = &configPath
	}
	if stateDir != "" {
		flags.StateDir = &stateDir
	}

	dir, err := config.ResolveStateDir(flags, env.Getenv)
	if err != nil {
		return "", "", err
	}
	return config.ResolveConfigPath(flags, env.Getenv, dir), dir, nil
}

// connect finds the running agent.
func connect(env Env, configPath, stateDir string) (*Client, error) {
	client, _, err := connectWithStore(env, configPath, stateDir)
	return client, err
}

// connectWithStore finds the running agent and hands back the stored config it was
// found through, for the commands that need a stored value as well as the agent. They
// go through one lookup with one failure path rather than opening the same file twice.
func connectWithStore(env Env, configPath, stateDir string) (*Client, *config.Store, error) {
	store, err := openStore(env, configPath, stateDir)
	if err != nil {
		return nil, nil, err
	}
	client, err := Discover(store)
	if err != nil {
		return nil, nil, err
	}
	return client, store, nil
}

// AdminRestartNeeded builds the predicate the agent reports a needs-rights save from.
//
// It lives here because answering it reads internal/hostnet, the privilege boundary
// internal/app is deliberately outside of, and because this package already makes the
// same decision at startup in elevateIfNeeded. One implementation, asked at two moments:
// once before anything is bound, and again whenever a save changes what the settings ask
// for.
//
// --no-elevate is read once and carried, because relaunch hands the replacement this
// process's own arguments: a copy that was told not to ask would restart into another
// copy that will not ask either, and offering a restart that cannot prompt is worse than
// saying nothing.
func AdminRestartNeeded(flags config.Flags) func(config.Settings) bool {
	facts := adminRestartFacts(flags)
	return func(s config.Settings) bool { return elevate.Needed(facts(s)) }
}

// RightsByRestart builds the predicate the agent asks before setting this machine up for a
// feature that needs administrator rights: whether this process gets them by starting again,
// which on Windows is the only way they are granted.
//
// It is the start-up decision asked about a want the stored settings may not hold yet --
// the agent asks at the moment somebody turns the feature on -- so a process the start-up
// would not prompt for (one already holding the rights, one whose rights live in a helper,
// one started with --no-elevate) answers no, and the agent's own setup path explains why.
func RightsByRestart(flags config.Flags) func() bool {
	noElevate := flags.NoElevate != nil && *flags.NoElevate
	return func() bool { return elevate.Needed(rightsFacts(rightsWants{systemDNS: true}, noElevate)) }
}

// adminRestartFacts is what AdminRestartNeeded decides from, separate from the decision so the
// mapping from a save to the facts is reachable from a test on a platform that never elevates.
func adminRestartFacts(flags config.Flags) func(config.Settings) elevate.Facts {
	noElevate := flags.NoElevate != nil && *flags.NoElevate
	return func(s config.Settings) elevate.Facts {
		return rightsFacts(rightsWants{
			interfaceMode: s.InterfaceSelected(),
			systemDNS:     dnsprofiles.OverrideWanted(s),
			// Asked of the machine here as well as at startup, because leaving it out is how
			// the two moments end up disagreeing about the same machine. This predicate is
			// behind the dashboard's restart banner, which after a declined prompt is the only
			// way back to one -- and a machine an earlier run left unable to resolve names is
			// the state that needs it most.
			staleOverride: staleOverrideOnThisMachine(context.Background()),
		}, noElevate)
	}
}

// rightsFacts turns what was asked for into the facts the elevation decision is made from.
// Both moments go through it so they cannot drift apart.
func rightsFacts(wants rightsWants, noElevate bool) elevate.Facts {
	return elevate.Facts{
		WantsInterface: wants.interfaceMode,
		WantsSystemDNS: wants.systemDNS,
		StaleOverride:  wants.staleOverride,
		Privileged:     hostnet.Privileged(),
		HasHelper:      hostnet.HasHelper(),
		AlreadyAsked:   noElevate,
	}
}

// staleOverrideProbeTimeout bounds the machine read below. It is on the startup path and on
// every settings save, and a resolver setting that will not answer must not be what stops
// app-tail coming up.
const staleOverrideProbeTimeout = 5 * time.Second

// staleOverrideOnThisMachine reports whether a previous run left this machine's name
// resolution pointed at app-tail and it still is.
//
// Read fresh on every call rather than carried: the way out of this state is `app-tail dns
// restore` from another process, and a cached yes would go on offering a restart to a machine
// somebody has already put back. A record that cannot be read answers no, which is what an
// unprivileged process on macOS and Linux always gets -- and what those platforms should get,
// since neither elevates.
func staleOverrideOnThisMachine(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, staleOverrideProbeTimeout)
	defer cancel()
	overridden, err := systemDNSOverridden(ctx)
	return err == nil && overridden
}

// systemDNSOverridden reads the machine's record, behind a variable so a test can put the
// machine in each state the answer above is decided from.
var systemDNSOverridden = hostnet.SystemDNSOverridden

// showAlert is how a refusal reaches somebody on a build with nowhere to print one. Behind a
// package variable for the reason internal/elevate holds ShellExecute behind one: the decision
// above it then stays a pure function, reachable from a test on any platform.
var showAlert = alert.Show

// staleOverrideWarning is what to tell somebody whose machine an earlier run left unable to
// resolve names, empty when there is nothing to tell them.
//
// Empty for an ordinary declined prompt. Somebody who said no to a feature they are not using
// is not owed a dialog, and one raised at every start is how a warning stops being read. It
// fires only when this machine is the one the elevation existed to repair.
//
// goos is a parameter for the reason restoreDNSCommand takes one: both branches of the command
// it names have to be reachable from a test that is not running on Windows.
func staleOverrideWarning(wants rightsWants, goos, reason string) string {
	if !wants.staleOverride {
		return ""
	}
	out := "This machine's name resolution is still pointed at app-tail from an earlier run, so " +
		"names will not resolve until it is put back, and app-tail needs administrator rights to do that."
	if reason != "" {
		out += "\n\n" + reason
	}
	return out + "\n\nTo put it back by hand, run:\n\n" + restoreDNSCommand(goos)
}

// warnStaleOverride raises that warning when there is one to raise. err is the refusal that
// led here, carried into the message so that a declined prompt and an account that cannot be
// elevated in place read as the different things they are.
func warnStaleOverride(wants rightsWants, err error) {
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	if message := staleOverrideWarning(wants, runtime.GOOS, reason); message != "" {
		showAlert(message)
	}
}
