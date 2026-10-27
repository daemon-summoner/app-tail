// SPDX-License-Identifier: MIT

// Command app-tail attaches this machine to several private networks at once --
// Tailscale, WireGuard and OpenVPN -- and carries traffic to them in whichever
// shape the configuration asks for: port forwards, a proxy, or a network interface.
//
// Nothing on the machine is installed or changed until the interface mode is
// switched on: every other shape runs as a plain user process.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sellitus/app-tail/internal/app"
	"github.com/sellitus/app-tail/internal/autostart"
	"github.com/sellitus/app-tail/internal/browser"
	"github.com/sellitus/app-tail/internal/buildinfo"
	"github.com/sellitus/app-tail/internal/cli"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/instance"
	"github.com/sellitus/app-tail/internal/logsink"
	"github.com/sellitus/app-tail/internal/relaunch"
	"github.com/sellitus/app-tail/internal/sessionend"
	"github.com/sellitus/app-tail/internal/tray"
	"github.com/sellitus/app-tail/ui"
)

// build is the one identity this binary reports, everywhere. Release builds link it
// in through scripts/version.sh; anything else derives it from the module's own VCS
// stamps. See internal/buildinfo for the resolution order.
var build = buildinfo.Get()

// Exit codes. 2 is reserved for a misuse of the command line so a script can tell
// "you typed it wrong" from "it ran and failed".
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// autoOpenWindow bounds how long the first-run watcher waits for a reason to open
// the dashboard. Past this the user has clearly not been sitting there waiting.
const autoOpenWindow = 30 * time.Second

// autoOpenInterval is how often that watcher re-checks.
const autoOpenInterval = 250 * time.Millisecond

func main() {
	// SIGINT and SIGTERM both mean "stop": the first is a user at a terminal, the
	// second a service manager. Both lead to the same ordered shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stderr, closeSink, err := openLogSink()
	if err != nil {
		// Not written to standard error directly: the build that fails here is the one
		// that has none, and this is the failure that leaves nothing else to read.
		reportFatal(err.Error())
		os.Exit(exitFailure)
	}

	// One object, held by both halves: the runner takes the claim before anything this run
	// installs, and the agent gives it up -- at the end of the run, and again before a restart
	// starts the replacement that has to take it next.
	claim := &singleInstance{
		getenv: config.OSGetenv,
		logf:   func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) },
	}

	code := run(ctx, os.Args[1:], cli.Env{
		Stdout: os.Stdout,
		Stderr: stderr,
		Stdin:  os.Stdin,
		Getenv: config.OSGetenv,
		Claim:  claim,
		RunAgent: func(ctx context.Context, flags config.Flags) error {
			return runAgent(ctx, flags, stderr, claim)
		},
		Version: build.String(),
	})
	if err := closeSink(); err != nil {
		reportFatal(err.Error())
	}
	// Rather than a deferred exit: the sink has to be closed before the process ends,
	// and os.Exit runs no deferred call.
	os.Exit(code)
}

// openLogSink resolves where this run writes what it has to say.
//
// The state directory is resolved from the environment and the default alone, because
// this runs before the command line is parsed: a message about the command line being
// wrong is one of the things that has to land somewhere. A --state-dir flag therefore
// moves the config file without moving the log; APP_TAIL_STATE_DIR moves both.
func openLogSink() (io.Writer, func() error, error) {
	return logsink.Open(func() (string, error) {
		return config.ResolveStateDir(config.Flags{}, config.OSGetenv)
	})
}

// run dispatches one invocation and maps its outcome to an exit code.
func run(ctx context.Context, args []string, env cli.Env) int {
	err := cli.Run(ctx, args, env)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, cli.ErrHelpShown):
		// The flag set already printed what was asked for.
		return exitOK
	case errors.Is(err, cli.ErrUsage):
		fmt.Fprintf(env.Stderr, "app-tail: %s\n", strings.TrimPrefix(err.Error(), "usage: "))
		return exitUsage
	case errors.Is(err, context.Canceled):
		// A signal during shutdown is the expected way to stop the agent.
		return exitOK
	default:
		// A command run under `app-tail exec` chose its own status, and already wrote
		// whatever it wanted to stderr. Passing the status through unannotated is what
		// makes app-tail invisible to the shell that invoked it.
		var exited *cli.ExitError
		if errors.As(err, &exited) {
			return exited.Code
		}
		fmt.Fprintf(env.Stderr, "app-tail: %s\n", err)
		return exitFailure
	}
}

// runAgent starts the long-lived agent and, when this session has somewhere to put
// it, the tray front end. It returns once the agent has stopped.
//
// diagnostics is where the run's log goes, chosen by main: standard error, or a file on
// the build that has none. claim is the single-instance claim the runner already took, held
// here so the restart path can give it up before the replacement has to take it.
func runAgent(ctx context.Context, flags config.Flags, diagnostics io.Writer, claim *singleInstance) error {
	// Before anything builds a tailnet node: the environment is read once here and the
	// variables the tailnet library would consult on its own are taken out of it, so a
	// single TS_AUTHKEY cannot enroll a connection whose credentials were left empty on
	// purpose. What it held is still honored -- it is layered on by the resolver below.
	getenv, err := config.CaptureEnv()
	if err != nil {
		return err
	}

	stateDir, err := config.ResolveStateDir(flags, getenv)
	if err != nil {
		return err
	}
	configPath := config.ResolveConfigPath(flags, getenv, stateDir)

	// Checked before opening the store, which creates the file: a first run is the
	// one case where the dashboard is worth opening even without a login prompt.
	firstRun := !fileExists(configPath)

	store, err := config.Open(configPath)
	if err != nil {
		return err
	}
	runtime, err := config.Resolve(flags, getenv, store.Get(), stateDir, configPath)
	if err != nil {
		return err
	}

	logger := newLogger(runtime, diagnostics)
	moved, err := store.MoveInlineCredentials()
	if err != nil {
		return fmt.Errorf("move the credentials in %s into secrets.json: %w", configPath, err)
	}
	if moved {
		logger.Info("moved credentials out of config.json into secrets.json")
	}
	unread, err := store.ScrubSavedCopies()
	if err != nil {
		return fmt.Errorf("take the credentials out of the copies kept beside %s: %w", configPath, err)
	}
	for _, saved := range unread {
		logger.Warn("a saved copy of the config is not a config document, so any credentials in it were left there", "file", saved)
	}

	// From here on a reboot or a logoff is a shutdown like any other. Without this the
	// Windows build -- a GUI binary, so no console, so no signal Go can deliver -- is ended
	// by the machine with none of its teardown run, and the machine-wide resolver override
	// it wrote into the registry outlives the reboot.
	ctx, session := sessionend.Notify(ctx, sessionend.Options{
		Reason: "app-tail is putting this machine's name resolution, proxy settings and routes back.",
		Logf:   func(format string, args ...any) { logger.Info(fmt.Sprintf(format, args...)) },
	})
	defer session.Stop()

	dashboard, err := ui.FS()
	if err != nil {
		return err
	}

	agent, err := app.New(app.Options{
		Store:     store,
		Runtime:   runtime,
		Flags:     flags,
		Getenv:    getenv,
		Logger:    logger,
		UI:        dashboard,
		Autostart: loginItem(runtime, logger),
		Version:   build.String(),
		// Built in internal/cli, which is on the allowed side of the privilege boundary
		// and already makes this decision at startup.
		NeedsAdminRestart: cli.AdminRestartNeeded(flags),
		RightsByRestart:   cli.RightsByRestart(flags),
	})
	if err != nil {
		return err
	}

	// Shared by both openers below so this run shows the dashboard once, however many
	// reasons it has to.
	opened := new(atomic.Bool)

	// A headless run has nobody at a browser, so it never opens one.
	if runtime.Settings.AutoOpenDashboard && !runtime.Headless {
		opener := dashboardOpener{
			agent:    agent,
			open:     browser.Open,
			logger:   logger,
			firstRun: firstRun,
			opened:   opened,
			window:   autoOpenWindow,
			interval: autoOpenInterval,
		}
		go opener.run(ctx)
	}

	var runErr error
	if !showTray(runtime) {
		logger.Info("running headless", "reason", headlessReason(runtime))
		runErr = agent.Run(ctx)
	} else {
		runErr = runWithTray(ctx, agent, logger, dashboardOpener{
			agent:      agent,
			open:       browser.Open,
			logger:     logger,
			noFrontEnd: true,
			opened:     opened,
			window:     autoOpenWindow,
			interval:   autoOpenInterval,
		})
	}

	// Run has returned, so everything this machine was told to do on app-tail's behalf has
	// been undone. A session end waiting on that stops waiting here rather than at the end
	// of its budget.
	session.Finished()

	// Only here, once Run has returned: the shutdown it performs on the way out is what
	// releases the dashboard port, and a replacement started before that would find the
	// port busy, bind another one and record it -- moving the dashboard out from under
	// the browser tab that asked for the restart. A failed run is not restarted, because
	// starting the same binary again would fail the same way.
	if runErr == nil && agent.RelaunchRequested() {
		logger.Info("restarting app-tail")
		// The claim is given up before the replacement starts. On Windows the replacement is a
		// second process, and it would otherwise have to take the claim off this one while it
		// is still on its way out -- a wait, and a replacement reporting that it stopped an
		// agent nobody was running. Failing to release is worth saying and not worth
		// abandoning the restart over: this process image is about to be gone either way.
		if err := claim.Release(); err != nil {
			logger.Warn("could not give up the single-instance claim before restarting", "error", err)
		}
		if err := relaunch.Exec(); err != nil {
			return err
		}
	}
	return runErr
}

// singleInstance is this process's claim on its state directory: one app-tail per config
// document, so a second start takes over from the first rather than fighting it over the
// dashboard port, the config file and -- with the interface mode on -- this machine's
// resolver, proxy settings and routes.
//
// It is split between the two halves of a run on purpose. The runner takes it before
// anything else touches the machine, because a repair or an agent that started first would
// be undoing what a *live* agent installed; main gives it up, because main is what starts
// the replacement on a restart and the replacement needs the claim.
type singleInstance struct {
	getenv config.Getenv
	logf   func(format string, args ...any)
	lock   *instance.Lock
}

// Take claims the state directory this run was pointed at, stopping the agent already
// holding it. It returns once this process is the only app-tail on that directory.
func (s *singleInstance) Take(ctx context.Context, flags config.Flags) error {
	stateDir, err := config.ResolveStateDir(flags, s.getenv)
	if err != nil {
		return err
	}
	lock, err := instance.Acquire(ctx, instance.Options{
		ConfigPath: config.ResolveConfigPath(flags, s.getenv, stateDir),
		Logf:       s.logf,
	})
	if err != nil {
		return err
	}
	s.lock = lock
	return nil
}

// Release gives the claim up. It is safe before a claim was taken and safe twice, so the
// restart path can release early and the runner can still release on its way out.
func (s *singleInstance) Release() error { return s.lock.Release() }

// runWithTray runs the agent alongside the menu-bar front end. systray owns the main
// goroutine, so the agent runs beside it and either one ending stops the other.
//
// noIcon is what the user is left with when the tray cannot start: the dashboard is the
// only surface this process has left, so it is opened rather than described in a log
// nobody is reading.
func runWithTray(ctx context.Context, agent *app.Agent, logger *slog.Logger, noIcon dashboardOpener) error {
	return runBesideTray(ctx, agent.Run, tray.Run, agent, logger, noIcon)
}

// runBesideTray is runWithTray with the agent's run and the native event loop passed in,
// so the handoff between them is exercised without a tailnet or a desktop.
func runBesideTray(ctx context.Context, run func(context.Context) error, showTray func(context.Context, tray.Options) error,
	agent agentView, logger *slog.Logger, noIcon dashboardOpener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	agentDone := make(chan error, 1)
	go func() {
		agentDone <- run(ctx)
		// The agent ending on its own -- a second copy asked it to quit, or the dashboard
		// asked for a restart -- has to end the tray as well. Nothing else would: the native
		// loop below runs until this context ends or the user picks Quit, and a process parked
		// in it after its agent is gone is an icon with nothing behind it, and a restart that
		// never starts.
		cancel()
	}()

	trayErr := showTray(ctx, tray.Options{
		Controller: newTrayController(agent, cancel),
		OnError:    func(err error) { logger.Error("tray action failed", "error", err) },
	})
	if trayErr != nil {
		// The tray could not start, but the agent can already serve its dashboard, so the
		// honest response is to keep running. Without the browser this leaves a process
		// with no icon, no window and no address on screen: running, invisible, and only
		// stoppable by somebody who thinks to look for it.
		logger.Error("the menu-bar icon could not be started; opening the dashboard instead",
			"reason", trayErr)
		go noIcon.run(ctx)
		<-ctx.Done()
	}

	// Whichever side ended, stop the other and report what the agent did.
	cancel()
	return <-agentDone
}

// showTray decides between the tray and headless modes.
func showTray(runtime config.Runtime) bool {
	if runtime.Headless || !runtime.Settings.ShowTray {
		return false
	}
	return tray.Supported()
}

// headlessReason explains the mode choice in the startup log, so an operator who
// expected an icon can see which of the three reasons applied.
func headlessReason(runtime config.Runtime) string {
	switch {
	case runtime.Headless:
		return "--headless was requested"
	case !runtime.Settings.ShowTray:
		return "showTray is off in the config"
	default:
		return "this session has no display"
	}
}

// newLogger picks a format for the mode: JSON for headless runs, which are read by
// machines, and text for a desktop run, which is read by a person.
func newLogger(runtime config.Runtime, out io.Writer) *slog.Logger {
	level := slog.LevelInfo
	if runtime.Verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}

	if runtime.Headless {
		return slog.New(slog.NewJSONHandler(out, opts))
	}
	return slog.New(slog.NewTextHandler(out, opts))
}

// loginItem builds the start-at-login manager. Failing to resolve one is not fatal:
// the rest of the app works, and the API reports the capability as unavailable
// rather than pretending a toggle took effect.
func loginItem(runtime config.Runtime, logger *slog.Logger) httpapi.Autostart {
	manager, err := autostart.New()
	if err != nil {
		logger.Warn("start-at-login is unavailable", "error", err)
		return nil
	}
	// Either machine-level feature needs administrator rights, and on Windows the login
	// item's form is how they are held without a prompt at every login: a Run value cannot
	// start an elevated process, so a machine that only switched its resolver would come up
	// contained and unable to put its own override back.
	manager.Elevated = runtime.Settings.TunSelected() || dnsprofiles.OverrideWanted(runtime.Settings)
	correctLoginItem(manager, logger)
	return manager
}

// loginItemForMode is the part of the login-item manager the correction below needs. It
// is an interface for one reason: the state it corrects exists on Windows only, so on
// every other machine -- including the one this is tested on -- a real manager can never
// be in it.
type loginItemForMode interface {
	NeedsReinstall() (bool, error)
	SetEnabled(enabled bool) error
	TemporaryPathWarning() string
	Kind() string
	Path() string
}

// correctLoginItem re-installs the login item when it has stopped matching the machine
// it was installed on.
//
// What counts as stale is the platform's to say: on Windows the network mode has moved
// out from under it and the item now starts app-tail with the wrong rights, and on macOS
// the app has moved and the item names a program that is no longer there, or an older
// build wrote it with a launchd class that throttles the agent. All share the shape this
// exists for -- nothing corrects them before the next login, and a setting that goes on
// reporting itself as on. Correcting it is not fatal either way: the agent's job is the
// forwards, and it does those with no login item at all.
func correctLoginItem(manager loginItemForMode, logger *slog.Logger) {
	stale, err := manager.NeedsReinstall()
	if err != nil {
		logger.Warn("could not check whether the login item still starts this machine's app-tail", "error", err)
		return
	}
	if !stale {
		return
	}
	// Re-installing records this process's own path, so from a build directory the
	// correction would trade a login item that is broken now for one that breaks at the
	// next reboot -- and report itself as fixed. Saying so is the whole of what can be
	// done from here.
	if warning := manager.TemporaryPathWarning(); warning != "" {
		logger.Warn("the login item needs correcting, but not from this copy of app-tail",
			"reason", warning, "fix", "app-tail install-autostart")
		return
	}
	if err := manager.SetEnabled(true); err != nil {
		logger.Warn("the login item will not start app-tail correctly at the next login",
			"error", err, "fix", "app-tail install-autostart")
		return
	}
	logger.Info("re-installed the login item, which no longer matched this machine",
		"item", manager.Kind(), "at", manager.Path())
}

// fileExists reports whether path is present, treating any other stat failure as
// present: guessing "first run" for an unreadable config would pop a browser open
// on every start.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}
