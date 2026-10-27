// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sellitus/app-tail/internal/sysdns"
)

// The helper is a root LaunchDaemon, and everything here exists to make that one fact
// safe. A daemon running as root executes whatever is at the path its configuration
// names, so the binary is copied somewhere only root can write rather than referenced
// where it happens to sit: an app in a downloads folder or a home directory is writable by
// the user, and pointing root at it hands root to anyone who can write there. "Only root
// can write" covers every directory above the copy too, since an account that can rename
// one of them can swap in a whole directory of its own.

// HelperLabel is the launchd job name, and the name of its configuration file.
const HelperLabel = "com.github.sellitus.app-tail.helper"

// helperPlist is where launchd reads the daemon's configuration.
var helperPlist = "/Library/LaunchDaemons/" + HelperLabel + ".plist"

// helperDir and HelperPath are where the copy of this binary lives. They are under
// /Library/PrivilegedHelperTools, the directory macOS keeps for programs launchd runs as
// root: root owns it and every directory above it on a stock install, and no package
// manager hands any of them to the user the way Homebrew hands out /usr/local. The install
// checks that every one of those directories is still only root's to change before it puts
// anything there, and re-secures helperDir itself every time rather than trusting it.
const helperDir = "/Library/PrivilegedHelperTools/app-tail"

// HelperPath is the binary launchd runs.
const HelperPath = helperDir + "/app-tail-helper"

// legacyHelperDir is where an older app-tail installed the helper. It is under /usr/local,
// which Homebrew gives to the user on many Macs, so a root daemon's binary left there sits in
// a folder an ordinary account may be able to rearrange. Installing and uninstalling both
// remove it -- when it is still the root-owned directory the install made, and never
// anything else at that path.
const legacyHelperDir = "/usr/local/libexec/app-tail"

// SupportsHelperInstall reports whether this platform can install the helper for the user.
//
// Distinct from HasHelper, which says whether the split-process design exists here at all:
// Linux has the helper but no install step, because there is no one service manager to
// write a unit for, so the helper is started by hand there.
func SupportsHelperInstall() bool { return true }

// HelperInstalled reports whether a helper is installed, whatever its state.
func HelperInstalled() bool {
	_, err := os.Stat(helperPlist)
	return err == nil
}

// machineApproveSteps reads this machine for ApproveGrants: the installed helper binary is
// the program an approval runs as root, so a machine without one has nothing to run.
func machineApproveSteps() approveSteps {
	steps := approveSteps{goos: "darwin", elevate: runCombined}
	if _, err := os.Stat(HelperPath); err == nil && HelperInstalled() {
		steps.helper = HelperPath
	}
	return steps
}

// InstallHelper copies this binary somewhere root-owned and registers it as a daemon.
//
// exe is the running program's path and owner is the account the helper will take commands
// from -- the user who ran the install, not the root it runs as. logf receives the steps
// whose failure does not stop the install, which are the ones that otherwise leave no
// trace of a half-done change to a machine.
func InstallHelper(ctx context.Context, logf func(format string, args ...any), exe string, owner int) error {
	if !Privileged() {
		return errors.New("installing the helper needs administrator rights: run `sudo app-tail tun install-helper`")
	}
	if owner == 0 {
		return errors.New("the helper needs the account it will serve, and root is not it. Run the install with sudo from your own account rather than as root")
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("find the app-tail binary to install: %w", err)
	}
	// exe is this running program, and the helper copied from it would refuse to start.
	if err := refuseInjectableHelper(); err != nil {
		return fmt.Errorf("not installing the helper: %w", err)
	}

	if err := installBinary(resolved); err != nil {
		return err
	}
	if err := os.WriteFile(helperPlist, []byte(helperPlistBody(owner)), 0o644); err != nil {
		return fmt.Errorf("write the helper's launch configuration: %w", err)
	}
	if err := os.Chown(helperPlist, 0, 0); err != nil {
		return fmt.Errorf("give the helper's launch configuration to root: %w", err)
	}

	if err := registerHelper(ctx, logf, machineLaunchdSteps()); err != nil {
		return err
	}
	// After the registration, so the configuration launchd reads already names the new
	// binary when the old one goes.
	if err := removeLegacyHelper(rootTrust, legacyHelperDir); err != nil {
		return fmt.Errorf("the helper is installed and running from %s, but the copy an older install left behind was not removed: %w",
			HelperPath, err)
	}
	return nil
}

// bootoutSettle bounds the wait for launchd to let go of a previous helper, and bootoutPoll
// is how often it is asked. The bound is past launchd's own patience with a process that
// will not stop, so reaching it means something other than a slow teardown.
const (
	bootoutSettle = 30 * time.Second
	bootoutPoll   = 250 * time.Millisecond
)

// helperTarget names the helper's job to launchd.
const helperTarget = "system/" + HelperLabel

// launchdSteps are the three acts registering the daemon performs and the window it waits
// in. They are values rather than direct calls because the middle act is a wait on a machine
// state a suite has no way to produce: a helper that will not stop is the one case whose
// answer a person reads, and it is otherwise only reachable from a machine it is happening
// on.
type launchdSteps struct {
	bootout    func(ctx context.Context) error
	registered func(ctx context.Context) bool
	bootstrap  func(ctx context.Context) error
	settle     time.Duration
	poll       time.Duration
}

// machineLaunchdSteps are the real acts, performed against this machine's launchd.
func machineLaunchdSteps() launchdSteps {
	return launchdSteps{
		bootout:    func(ctx context.Context) error { return runLaunchctl(ctx, "bootout", helperTarget) },
		registered: func(ctx context.Context) bool { return labelRegistered(ctx, helperTarget) },
		bootstrap:  bootstrapHelper,
		settle:     bootoutSettle,
		poll:       bootoutPoll,
	}
}

// registerHelper replaces the registered daemon with the one the configuration names.
func registerHelper(ctx context.Context, logf func(format string, args ...any), steps launchdSteps) error {
	// Unloaded first so an install over a running helper replaces it rather than failing
	// on a label that is already registered. Unloading a job that is not registered fails,
	// and that is the state this wanted, so it is reported and not returned.
	if err := steps.bootout(ctx); err != nil {
		logf("no previous helper was unloaded (%v), which is expected on a first install", err)
	}
	// launchd lets go of the label after bootout returns, not before, and a bootstrap
	// issued while the old one is still registered fails with an I/O error that names
	// nothing. A helper that was serving a node unwinds this machine's routing and
	// resolver state before its process exits, so the window is a teardown's worth of
	// time rather than an instant.
	if !awaitBootout(ctx, steps.registered, steps.settle, steps.poll) {
		return fmt.Errorf("the previous helper was still shutting down after %s, so the new one "+
			"could not be registered. This machine has no helper until the install is run again",
			steps.settle)
	}
	return steps.bootstrap(ctx)
}

// bootstrapHelper registers the daemon. What launchd wrote travels with the failure: its
// exit status alone is an errno, and the sentence beside it is the part anyone can act on.
func bootstrapHelper(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", "system", helperPlist).CombinedOutput()
	if err != nil {
		return fmt.Errorf("register the helper with launchd: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// labelRegistered reports whether launchd still knows a job. It is the observable for a
// bootout having finished: the label stays in the domain until it has.
func labelRegistered(ctx context.Context, target string) bool {
	return runLaunchctl(ctx, "print", target) == nil
}

// awaitBootout waits for launchd to let go of the helper's label, reporting whether it did.
func awaitBootout(ctx context.Context, registered func(context.Context) bool, settle, poll time.Duration) bool {
	deadline := time.Now().Add(settle)
	for {
		// Before the probe, never after: a cancelled context makes launchctl fail, and
		// reading that as the label being gone would report the one state this exists to
		// wait for.
		if ctx.Err() != nil {
			return false
		}
		if !registered(ctx) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-time.After(poll):
		case <-ctx.Done():
			return false
		}
	}
}

// installBinary copies the running program to a directory only root can write, and makes
// sure the directory really is that even if it already existed.
func installBinary(src string) error { return installHelperBinary(rootTrust, helperDir, src) }

// installHelperBinary is installBinary into dir, with the directories around it judged by pt.
func installHelperBinary(pt programTrust, dir, src string) (reterr error) {
	if err := pt.helperHome(dir); err != nil {
		return fmt.Errorf("refusing to install the helper in %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create the helper's directory: %w", err)
	}
	// Asked again now that every directory above it exists, which covers the ones just
	// created under whatever umask the install ran with.
	if err := pt.helperHome(dir); err != nil {
		return fmt.Errorf("refusing to install the helper in %s: %w", dir, err)
	}
	// A link left where the directory belongs would carry the ownership and mode changes
	// below to wherever it points, so only a real directory is secured and written into.
	info, err := pt.lstat(dir)
	if err != nil {
		return fmt.Errorf("look at the helper's directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to install the helper in %s: it is %s rather than a directory", dir, info.Mode().Type())
	}
	// Re-applied rather than assumed: a pre-existing directory could have been created
	// by anyone, and a user-writable parent is the same problem as a user-writable
	// binary.
	if err := os.Chown(dir, 0, 0); err != nil {
		return fmt.Errorf("give the helper's directory to root: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("restrict the helper's directory: %w", err)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("read the app-tail binary: %w", err)
	}
	defer func() { reterr = errors.Join(reterr, in.Close()) }()

	// Written beside the target and renamed into place, so a helper that is running from
	// the old file is replaced atomically rather than truncated under itself.
	target := filepath.Join(dir, filepath.Base(HelperPath))
	tmp := target + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create the helper binary: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		return discard(tmp, fmt.Errorf("copy the app-tail binary into place: %w", err), out.Close())
	}
	if err := out.Close(); err != nil {
		return discard(tmp, fmt.Errorf("finish writing the helper binary: %w", err))
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return discard(tmp, fmt.Errorf("give the helper binary to root: %w", err))
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return discard(tmp, fmt.Errorf("restrict the helper binary: %w", err))
	}
	if err := os.Rename(tmp, target); err != nil {
		return discard(tmp, fmt.Errorf("put the helper binary in place: %w", err))
	}
	return nil
}

// helperHome checks that the directories dir would be created in leave it to root.
//
// Every directory from / down to the deepest one that exists already has to belong to root
// and be writable by no other account: one that another account can write is one where it
// renames dir away and puts its own in its place, and launchd then runs that account's
// binary as root. The directories below that point do not exist yet, and the install
// creates them as root inside a parent only root can change.
func (pt programTrust) helperHome(dir string) error {
	existing := filepath.Dir(dir)
	for {
		_, err := pt.lstat(existing)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) || existing == "/" {
			return err
		}
		existing = filepath.Dir(existing)
	}
	if err := pt.reach(existing); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return err
	}
	info, err := pt.lstat(resolved)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is on the way to %s and is not a directory", resolved, dir)
	}
	owner, _, err := ownerOf(info, resolved)
	if err != nil {
		return err
	}
	if !pt.trusted(owner) {
		return fmt.Errorf("%s would be created in %s, which belongs to %s rather than to root, so that account can replace it",
			dir, resolved, describeUser(owner))
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s would be created in %s, which %s can write to (mode %#o), so any of them can replace it",
			dir, resolved, writers(info), perm)
	}
	return nil
}

// discard removes the half-written binary and reports why it was being written. Leaving it
// would leave a root-owned executable nothing runs; failing to remove it is worth saying so
// beside the reason, which is what the caller acts on.
func discard(tmp string, reasons ...error) error {
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		reasons = append(reasons, fmt.Errorf("remove the half-written helper binary %s: %w", tmp, err))
	}
	return errors.Join(reasons...)
}

// removeLegacyHelper removes the helper binary an older install left in dir, and dir with it
// when nothing else is in there.
//
// It removes only from the directory that install made: a real directory, not a link, that
// still belongs to root. Anything else at that path was put there or changed by another
// account, and removing names as root inside a place another account controls deletes
// whatever that account arranged for those names to be. That case is an error naming the
// path, so the person running the install can look at it rather than learn nothing.
func removeLegacyHelper(pt programTrust, dir string) error {
	info, err := pt.lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("left %s alone: it is %s rather than the directory an install makes", dir, info.Mode().Type())
	}
	owner, _, err := ownerOf(info, dir)
	if err != nil {
		return err
	}
	if !pt.trusted(owner) {
		return fmt.Errorf("left %s alone: it belongs to %s rather than to root, so what is in it is not the install's to remove",
			dir, describeUser(owner))
	}
	if err := os.Remove(filepath.Join(dir, filepath.Base(HelperPath))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) && !isNotEmpty(err) {
		return err
	}
	return nil
}

// helperPlistBody renders launchd's configuration for the daemon.
//
// The owner is the only value substituted in, and it is an integer, so nothing a caller
// controls can end up as markup in a file root acts on.
func helperPlistBody(owner int) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + HelperLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + HelperPath + `</string>
		<string>tun</string>
		<string>helper</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>` + ownerEnv + `</key>
		<string>` + strconv.Itoa(owner) + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
`
}

// UninstallHelper stops the daemon and removes everything the install put on the machine.
//
// Every step runs even after an earlier one failed, and the failures are reported
// together: stopping halfway is how a machine ends up with a registered job whose binary
// is gone, which launchd retries forever.
func UninstallHelper(ctx context.Context, logf func(format string, args ...any)) error {
	if !Privileged() {
		return errors.New("removing the helper needs administrator rights: run `sudo app-tail tun uninstall-helper`")
	}
	return uninstall(ctx, logf, machineUninstallSteps())
}

// uninstallSteps are the acts removing the helper performs. They are values for the same
// reason the install's are: the first one is what makes this machine resolve names again,
// and the order it happens in is the part worth pinning -- which is only observable from
// outside the calls themselves.
type uninstallSteps struct {
	// restoreDNS puts this machine's name resolution back, reporting whether there was
	// anything to put back.
	restoreDNS func(ctx context.Context) (bool, error)
	// unload stops the running helper.
	unload func(ctx context.Context) error
	// remove deletes one path the install put on the machine. Each is named so a failure
	// says which one, and they are removed in the order they are listed.
	remove []removal
	// cleanUp removes what the last session left behind.
	cleanUp func()
}

// removal is one path the uninstall deletes, with the sentence a failure carries.
type removal struct {
	what string
	drop func() error
	// shared marks a directory app-tail may not be the only occupant of. One that still
	// holds something is left alone: something else put a file there, and removing it is
	// not this app's business.
	shared bool
}

func machineUninstallSteps() uninstallSteps {
	return uninstallSteps{
		// Past the serving lock on purpose: once the helper is gone nothing will ever put this
		// machine back, so a session it is serving is restored now rather than trusted to.
		restoreDNS: func(ctx context.Context) (bool, error) {
			return repairSystemDNS(ctx, sysdns.New(sysdns.DefaultRecordPath(), discardLog))
		},
		unload: func(ctx context.Context) error { return runLaunchctl(ctx, "bootout", helperTarget) },
		remove: []removal{
			{what: "the helper's launch configuration", drop: func() error { return os.Remove(helperPlist) }},
			{what: "the helper binary", drop: func() error { return os.Remove(HelperPath) }},
			{what: "the helper's directory", drop: func() error { return os.Remove(helperDir) }, shared: true},
			{what: "the helper an older install left in " + legacyHelperDir, drop: func() error { return removeLegacyHelper(rootTrust, legacyHelperDir) }},
			{what: "the helper's socket directory", drop: func() error { return os.RemoveAll(socketDir) }},
		},
		cleanUp: func() { CleanUpLeftovers(discardLog) },
	}
}

// discardLog is what the machine's own steps log through: they are called from uninstall,
// which has the caller's log function and reports what happened itself.
func discardLog(string, ...any) {}

// uninstall performs the removal.
//
// The resolver restore is first, and it is the one step whose failure stops the rest: after
// the launch configuration is gone nothing on this machine will ever restore its resolver
// again, and a machine pointed at an address no process listens on resolves no names at all.
// Refusing leaves a helper that repairs it at the next boot, which is the better of the two
// states to be stuck in.
//
// Past that point every step runs even after an earlier one failed, and the failures are
// reported together: stopping halfway is how a machine ends up with a registered job whose
// binary is gone, which launchd retries forever.
func uninstall(ctx context.Context, logf func(format string, args ...any), steps uninstallSteps) error {
	restored, err := steps.restoreDNS(ctx)
	if err != nil {
		return fmt.Errorf("restore this machine's resolver before removing the helper: %w", err)
	}
	if restored {
		logf("restored this machine's resolver, which app-tail had pointed at itself")
	}

	var errs []error
	// Unloading a job that is not registered fails, and that is the state this command
	// wants, so it is reported rather than returned: distinguishing the two would mean
	// reading launchctl's exit codes, which differ by macOS release. A real failure
	// surfaces at the next step, where it is about a file rather than an exit status.
	if err := steps.unload(ctx); err != nil {
		logf("no running helper was unloaded (%v), which is expected when none was", err)
	}
	for _, item := range steps.remove {
		if err := item.drop(); err != nil && !errors.Is(err, os.ErrNotExist) && !(item.shared && isNotEmpty(err)) {
			errs = append(errs, fmt.Errorf("remove %s: %w", item.what, err))
		}
	}
	// Anything the last session left on the machine goes with the helper that would
	// otherwise have cleaned it up on its next start.
	steps.cleanUp()
	return errors.Join(errs...)
}

// runLaunchctl runs a launchctl subcommand and reports how it went. Both callers treat the
// answer as something to say rather than something to fail on -- see each for why.
func runLaunchctl(ctx context.Context, args ...string) error {
	return exec.CommandContext(ctx, "/bin/launchctl", args...).Run()
}

// isNotEmpty reports a directory that still holds something. Leaving it is correct:
// something else put a file there, and removing it is not this app's business.
func isNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY)
}
