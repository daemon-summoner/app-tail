// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file is what launchd reads to decide what to run as root and how. Everything about
// it is load-bearing: the path it names is the binary root executes, and the owner it
// records is the entire access control on the socket that binary listens on.
func TestTheDaemonConfigurationRunsTheRootOwnedCopy(t *testing.T) {
	body := helperPlistBody(501)

	if !strings.Contains(body, "<string>"+HelperPath+"</string>") {
		t.Errorf("the configuration does not run %s:\n%s", HelperPath, body)
	}
	// The one reason the binary is copied at all: /Library/PrivilegedHelperTools is
	// root's, and an app in a downloads folder or a home directory is writable by the user.
	// Pointing a root daemon at one hands root to anyone who can write there.
	if !strings.HasPrefix(HelperPath, "/Library/PrivilegedHelperTools/") {
		t.Errorf("the helper runs from %s, which is not a location only root can write", HelperPath)
	}
	if !strings.Contains(body, "<string>tun</string>") || !strings.Contains(body, "<string>helper</string>") {
		t.Errorf("the configuration does not start the helper subcommand:\n%s", body)
	}
	if !strings.Contains(body, "<key>"+ownerEnv+"</key>") {
		t.Errorf("the configuration records no owner, so the helper would refuse every connection:\n%s", body)
	}
	if !strings.Contains(body, "<string>501</string>") {
		t.Errorf("the configuration does not record the account it was given:\n%s", body)
	}
	if !strings.Contains(body, "<key>Label</key>") || !strings.Contains(body, HelperLabel) {
		t.Errorf("the configuration carries no label, so it could not be unloaded again:\n%s", body)
	}
}

// The owner is the only value substituted into a file root acts on, and it is an integer
// on the way in. Nothing a caller controls can therefore end up as markup -- which is
// checked rather than assumed, because the day someone widens it to a user name is the day
// it stops being true.
func TestNothingACallerControlsBecomesMarkup(t *testing.T) {
	for _, uid := range []int{0, 1, 501, 4294967294} {
		body := helperPlistBody(uid)
		want := "<string>" + strconv.Itoa(uid) + "</string>"
		if !strings.Contains(body, want) {
			t.Errorf("helperPlistBody(%d) does not carry %s", uid, want)
		}
		// A plist that will not parse is a daemon launchd silently never starts, which
		// looks from the app's side exactly like a machine where the mode does not work.
		if err := plistParses(t, body); err != nil {
			t.Errorf("helperPlistBody(%d) produced a file launchd cannot read: %v", uid, err)
		}
	}
}

// plistParses runs the configuration through the system's own parser, which is the one
// that decides whether launchd will read it. A file it cannot read is a daemon launchd
// silently never starts, which from the app's side is indistinguishable from a machine
// where the mode does not work.
func plistParses(t *testing.T, body string) error {
	t.Helper()
	cmd := exec.Command("/usr/bin/plutil", "-lint", "-")
	cmd.Stdin = strings.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// The install and the removal have to refuse without administrator rights, and say so.
// Without the check they fail on a permission error from whichever file they reached
// first, which names a path rather than the thing to do differently.
func TestInstallingAndRemovingRefuseWithoutRights(t *testing.T) {
	if Privileged() {
		t.Skip("this test is about the refusal when the process is not root, and this one is")
	}
	quiet := func(string, ...any) {}
	if err := InstallHelper(t.Context(), quiet, "/bin/ls", 501); err == nil {
		t.Error("the install went ahead without administrator rights")
	} else if !strings.Contains(err.Error(), "sudo app-tail tun install-helper") {
		t.Errorf("the refusal said %q, which does not say how to run it", err)
	}
	if err := UninstallHelper(t.Context(), quiet); err == nil {
		t.Error("the removal went ahead without administrator rights")
	} else if !strings.Contains(err.Error(), "sudo app-tail tun uninstall-helper") {
		t.Errorf("the refusal said %q, which does not say how to run it", err)
	}
}

// The removal takes the helper's own directory away and leaves anything else alone, so it
// has to tell "someone else put a file in there" apart from every other reason a remove
// fails. Getting it wrong turns an ordinary uninstall into a reported failure -- or hides a
// real one.
func TestADirectorySomeoneElseIsUsingIsNotAFailedRemoval(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "someone-elses-file"), nil, 0o600); err != nil {
		t.Fatalf("put a file in the directory: %v", err)
	}
	err := os.Remove(dir)
	if err == nil {
		t.Fatal("a directory with a file in it was removed, so this is not the case under test")
	}
	if !isNotEmpty(err) {
		t.Errorf("removing a directory someone else is using reported %v, which would be treated as a failed uninstall", err)
	}

	missing := os.Remove(filepath.Join(dir, "was-never-there"))
	if missing == nil {
		t.Fatal("removing a path that does not exist reported success")
	}
	if isNotEmpty(missing) {
		t.Errorf("%v was read as a directory in use, which would hide a real failure", missing)
	}
}

// The undo is printed by the doctor, and it has to remove exactly what was reported: an
// undo derived from its own scan would name a shorter list than the one on screen, and a
// user who ran it would believe the machine was clean when it is not. The resolver cache
// flush is part of it, because removing the files alone leaves the machine resolving
// through an address that is gone.
func TestTheUndoRemovesExactlyWhatWasReported(t *testing.T) {
	if got := UndoFor(nil); got != nil {
		t.Errorf("UndoFor(nil) = %v, want nothing to run on a clean machine", got)
	}

	leftovers := []string{"/etc/resolver/a.ts.net", "/etc/resolver/b.ts.net"}
	got := UndoFor(leftovers)
	joined := strings.Join(got, "\n")
	for _, path := range leftovers {
		if !strings.Contains(joined, "rm "+path) {
			t.Errorf("the undo does not remove %s:\n%s", path, joined)
		}
	}
	if !strings.Contains(joined, "mDNSResponder") {
		t.Errorf("the undo does not flush the resolver cache, so the machine keeps the old answers:\n%s", joined)
	}
}

// The build script refreshes the installed helper when a rebuild leaves it behind, and it
// finds it by path. That path is decided here, so a move that the script did not follow
// would leave it silently checking a file that is not there -- the build would look clean
// and every rebuild after it would run against a stale root binary.
func TestTheBuildScriptLooksForTheHelperWhereTheInstallPutsIt(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "build_install.sh"))
	if err != nil {
		t.Fatalf("read the build script: %v", err)
	}
	if !strings.Contains(string(script), HelperPath) {
		t.Errorf("build_install.sh does not name %s, so it cannot tell whether the installed helper is this build", HelperPath)
	}
}

// launchd lets go of a booted-out job after the command that asked for it has returned, and
// a helper serving a node takes a teardown's worth of time to stop. Registering the
// replacement inside that window fails with an I/O error naming nothing, and leaves the
// machine with the old helper gone and no new one -- which is what a person who ran the
// install to fix their helper is left holding.
func TestAnInstallWaitsForLaunchdToLetGoOfThePreviousHelper(t *testing.T) {
	asked := 0
	registered := func(context.Context) bool {
		asked++
		return asked < 3
	}

	if !awaitBootout(t.Context(), registered, time.Minute, time.Millisecond) {
		t.Fatal("the install gave up on a helper that did stop, so it would report a machine it could have set up")
	}
	if asked < 3 {
		t.Errorf("the label was asked about %d times, so the install did not wait for the previous helper at all", asked)
	}
}

// A label nothing holds is the first install and every install after a clean stop, which is
// almost all of them. Waiting there would put the whole window into a command that had
// nothing to wait for.
func TestAnInstallOntoAFreeLabelDoesNotWait(t *testing.T) {
	start := time.Now()

	if !awaitBootout(t.Context(), func(context.Context) bool { return false }, time.Minute, time.Minute) {
		t.Fatal("a free label was reported as still held")
	}

	if waited := time.Since(start); waited > 10*time.Second {
		t.Errorf("an install onto a free label waited %v", waited)
	}
}

// A helper that never stops is not something to keep waiting on: launchd's own patience with
// a process that will not exit runs out inside this window, so past it the reason is
// something else. The sentence the caller gets is what says the machine now has no helper,
// and it is reachable only by this answer.
func TestAnInstallThatOutlastsItsPatienceGivesUpRatherThanRegisteringIntoATeardown(t *testing.T) {
	// Waited for from beside the call, because an install that never gives up does not
	// return at all, and a test that only checked the answer would hang instead of saying
	// so.
	freed := make(chan bool, 1)
	go func() {
		freed <- awaitBootout(t.Context(), func(context.Context) bool { return true },
			20*time.Millisecond, time.Millisecond)
	}()

	select {
	case got := <-freed:
		if got {
			t.Fatal("a label that was never let go of was reported as free, so the install would register into a teardown")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the install is still waiting on a helper that never stopped, so it never gives up and never says why")
	}
}

// The probe is a launchctl command, and a cancelled install makes it fail the same way a
// missing label does. Read as the label being free, a cancelled install would go on to
// register into the teardown it was waiting out -- the exact failure, reached by the path
// meant to prevent it.
func TestACancelledInstallDoesNotReadAStoppedProbeAsAFreedLabel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if awaitBootout(ctx, func(context.Context) bool { return false }, time.Minute, time.Millisecond) {
		t.Fatal("a cancelled install reported the label as free, which it never found out")
	}
}

// A bootout that failed is the state an install wants -- there was no previous helper -- so
// it is said and not returned. Returning it would make every first install fail.
func TestAFirstInstallIsNotStoppedByHavingNothingToUnload(t *testing.T) {
	said := ""
	bootstrapped := false
	steps := launchdSteps{
		bootout:    func(context.Context) error { return errors.New("Boot-out failed: 3: No such process") },
		registered: func(context.Context) bool { return false },
		bootstrap:  func(context.Context) error { bootstrapped = true; return nil },
		settle:     time.Minute,
		poll:       time.Millisecond,
	}

	err := registerHelper(t.Context(), func(f string, a ...any) { said = fmt.Sprintf(f, a...) }, steps)

	if err != nil {
		t.Fatalf("a first install failed on having nothing to unload: %v", err)
	}
	if !bootstrapped {
		t.Error("the helper was never registered, so the install would report a machine with no daemon on it")
	}
	if !strings.Contains(said, "No such process") {
		t.Errorf("the install said %q, which does not carry what launchd reported", said)
	}
}

// The whole point of the wait: registering into a teardown is what fails with an errno that
// names nothing, so the second act may not happen until the first one has finished.
func TestTheHelperIsNotRegisteredWhileTheOldOneIsStillHeld(t *testing.T) {
	held := 2
	registeredWhenBootstrapped := -1
	steps := launchdSteps{
		bootout:    func(context.Context) error { return nil },
		registered: func(context.Context) bool { held--; return held > 0 },
		bootstrap:  func(context.Context) error { registeredWhenBootstrapped = held; return nil },
		settle:     time.Minute,
		poll:       time.Millisecond,
	}

	if err := registerHelper(t.Context(), func(string, ...any) {}, steps); err != nil {
		t.Fatalf("register the helper: %v", err)
	}

	if registeredWhenBootstrapped < 0 {
		t.Fatal("the helper was never registered")
	}
	if registeredWhenBootstrapped > 0 {
		t.Error("the helper was registered while launchd still held the old label, which is the failure the wait exists to prevent")
	}
}

// A helper that will not stop leaves the machine with the old one gone and no new one, and
// that is the whole of what a person needs told: an errno from launchd sends them looking at
// a daemon that is not there.
func TestAHelperThatWillNotStopIsReportedAsAMachineLeftWithoutOne(t *testing.T) {
	steps := launchdSteps{
		bootout:    func(context.Context) error { return nil },
		registered: func(context.Context) bool { return true },
		bootstrap:  func(context.Context) error { return errors.New("a teardown was registered into") },
		settle:     20 * time.Millisecond,
		poll:       time.Millisecond,
	}

	err := registerHelper(t.Context(), func(string, ...any) {}, steps)

	if err == nil {
		t.Fatal("an install that could not register the helper reported success")
	}
	if !strings.Contains(err.Error(), "no helper") {
		t.Errorf("the failure said %q, which does not say the machine is left without one", err)
	}
	if !strings.Contains(err.Error(), "run again") {
		t.Errorf("the failure said %q, which does not say what to do about it", err)
	}
}

// The wait is only as good as the probe under it. One that always answered "gone" would put
// every install back to registering into a teardown, and nothing above it could tell.
func TestTheProbeTellsARegisteredJobFromAnAbsentOne(t *testing.T) {
	if labelRegistered(t.Context(), helperTarget+".no-such-job") {
		t.Error("a label launchd has never heard of was reported as registered, so every install would wait out its whole window")
	}

	// Any one of them is enough: what is being proved is that the probe can answer yes at
	// all, and naming a single Apple daemon would tie this to one macOS release.
	core := []string{"com.apple.diskarbitrationd", "com.apple.notifyd", "com.apple.opendirectoryd", "com.apple.securityd"}
	for _, label := range core {
		if labelRegistered(t.Context(), "system/"+label) {
			return
		}
	}
	t.Errorf("none of %v was reported as registered, so the probe cannot tell a running daemon from an absent one", core)
}

// The steps are values so the wait is testable, which means the real ones are wiring nothing
// exercises until an install runs as root. One left nil is a panic in the middle of a
// half-installed machine.
func TestTheRealStepsAreWiredToLaunchd(t *testing.T) {
	steps := machineLaunchdSteps()

	if steps.bootout == nil || steps.registered == nil || steps.bootstrap == nil {
		t.Fatalf("an install act is missing: bootout=%v registered=%v bootstrap=%v",
			steps.bootout != nil, steps.registered != nil, steps.bootstrap != nil)
	}
	if steps.settle != bootoutSettle || steps.poll != bootoutPoll {
		t.Errorf("the install waits %s every %s, want %s every %s", steps.settle, steps.poll, bootoutSettle, bootoutPoll)
	}
	// Asked about the helper's own label, which is what makes the wait a wait for the
	// helper rather than for whatever else launchd is running.
	if steps.registered(t.Context()) != labelRegistered(t.Context(), helperTarget) {
		t.Error("the install waits on a different job from the helper's own")
	}
}

// The wait is a sleep between probes, so a caller that gives up during one has to be let go
// rather than held to the end of the window it is no longer waiting out.
func TestAnInstallCancelledInsideTheWaitStopsThere(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	// Long enough that returning can only be the cancellation, never the poll elapsing.
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()

	freed := make(chan bool, 1)
	go func() {
		freed <- awaitBootout(ctx, func(context.Context) bool { return true }, time.Hour, time.Hour)
	}()

	select {
	case got := <-freed:
		if got {
			t.Error("a cancelled install reported the label as free, which it never found out")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled install is still asleep between probes, so it waits out a window nobody is waiting for")
	}
}

// Removing the helper is the last moment anything on this machine will ever put its resolver
// back: after the launch configuration is gone, nothing runs at boot to repair it.
func TestUninstallingTheHelperRestoresDNSBeforeItRemovesAnything(t *testing.T) {
	var order []string
	steps := uninstallSteps{
		restoreDNS: func(context.Context) (bool, error) {
			order = append(order, "restore")
			return true, nil
		},
		unload: func(context.Context) error {
			order = append(order, "unload")
			return nil
		},
		remove: []removal{
			{what: "the plist", drop: func() error { order = append(order, "remove"); return nil }},
		},
		cleanUp: func() { order = append(order, "clean") },
	}
	if err := uninstall(context.Background(), func(string, ...any) {}, steps); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	want := []string{"restore", "unload", "remove", "clean"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("the uninstall ran %v, want %v", order, want)
	}
}

// And a restore that failed stops the uninstall: leaving the helper installed means the
// machine is repaired at the next boot, which is the better of the two states to be stuck in.
func TestAResolverThatCouldNotBeRestoredStopsTheUninstall(t *testing.T) {
	removed := false
	steps := uninstallSteps{
		restoreDNS: func(context.Context) (bool, error) {
			return false, errors.New("networksetup refused")
		},
		unload: func(context.Context) error { return nil },
		remove: []removal{
			{what: "the plist", drop: func() error { removed = true; return nil }},
		},
		cleanUp: func() {},
	}
	err := uninstall(context.Background(), func(string, ...any) {}, steps)
	if err == nil {
		t.Fatal("the uninstall reported success although this machine's resolver was left pointed at app-tail")
	}
	if removed {
		t.Error("the helper was removed anyway, so nothing on this machine will ever restore its resolver")
	}
	if !strings.Contains(err.Error(), "networksetup refused") {
		t.Errorf("the failure was %q, which loses the machine's own reason", err)
	}
}

// The helper's directory is only as private as every directory above it. One an ordinary
// account can write is one where it renames the helper's directory away and puts its own in
// its place, and launchd then runs that account's binary as root at the next boot -- however
// carefully the directory and the file inside it were secured. So the install looks at the
// whole way down before it creates anything, and refuses rather than repairs: the directories
// above are not this app's to change.
func TestTheHelperIsNotInstalledUnderAWritableAncestor(t *testing.T) {
	root := realTempDir(t)
	src := filepath.Join(root, "app-tail")
	writeProgram(t, src, []byte("the build"), 0o755)

	open := filepath.Join(root, "open")
	mkdirMode(t, open, 0o777)
	theirs := filepath.Join(root, "theirs")
	mkdirMode(t, theirs, 0o755)
	pt := testTrust(map[string]uint32{theirs: someoneElse})

	cases := []struct {
		name, dir, ancestor, why string
	}{
		{"a directory every account can write", filepath.Join(open, "app-tail"), open, "can write to"},
		{"a directory another account owns", filepath.Join(theirs, "app-tail"), theirs, "belongs to"},
		// Nothing below the open directory exists yet. Creating it would be creating it
		// inside a directory someone else can rearrange, so that is refused too.
		{"a directory that does not exist yet under one every account can write", filepath.Join(open, "missing", "app-tail"), open, "can write to"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := installHelperBinary(pt, tc.dir, src)
			if err == nil {
				t.Fatalf("the helper was installed into %s", tc.dir)
			}
			if !strings.Contains(err.Error(), tc.ancestor) {
				t.Errorf("the refusal does not name %s, the directory that makes it unsafe: %v", tc.ancestor, err)
			}
			if !strings.Contains(err.Error(), tc.why) {
				t.Errorf("the refusal does not say what makes %s unsafe (%q): %v", tc.ancestor, tc.why, err)
			}
			created := tc.dir
			for created != tc.ancestor {
				if _, statErr := os.Lstat(created); !errors.Is(statErr, os.ErrNotExist) {
					t.Errorf("%s was created before the install was refused (%v)", created, statErr)
				}
				created = filepath.Dir(created)
			}
		})
	}

	// The same check passes a home whose every ancestor is closed, so what refuses above is
	// the ancestor and not something every directory would fail.
	closed := filepath.Join(root, "closed")
	mkdirMode(t, closed, 0o755)
	if err := pt.helperHome(filepath.Join(closed, "app-tail")); err != nil {
		t.Errorf("a directory under ancestors only trusted accounts can write was refused: %v", err)
	}
}

// The real location is checked on this machine as well as the suite's stand-ins. A stock
// macOS gives /Library/PrivilegedHelperTools to root and lets nobody else write it, which is
// why it is where the helper lives; a machine where that is not so is one this install must
// refuse.
func TestTheHelpersHomeOnThisMachineIsOnlyRootsToChange(t *testing.T) {
	if !strings.HasPrefix(helperDir, "/Library/PrivilegedHelperTools/") {
		t.Errorf("the helper lives in %s, outside the directory macOS keeps for root's helper programs", helperDir)
	}
	if err := rootTrust.helperHome(helperDir); err != nil {
		t.Errorf("the helper's home on this machine is not one only root can change: %v", err)
	}
}

// An older install put the helper under /usr/local, which many Macs give to the user, and a
// root daemon's binary left in a folder an ordinary account can rearrange is the hazard the
// move exists to end. So it is removed -- but only from the directory the install made,
// still root's and still a directory. Anything else at that path was put there by someone
// else, and deleting files as root from a place another account controls is how a removal
// becomes a way to delete whatever that account points it at.
func TestAnOldCopyOfTheHelperIsRemovedOnlyFromTheDirectoryTheInstallMade(t *testing.T) {
	binary := filepath.Base(HelperPath)
	seed := func(t *testing.T, dir string, extra ...string) {
		t.Helper()
		mkdirMode(t, dir, 0o755)
		for _, name := range append([]string{binary}, extra...) {
			writeProgram(t, filepath.Join(dir, name), []byte("an old build"), 0o755)
		}
	}
	gone := func(t *testing.T, path string) {
		t.Helper()
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there (%v)", path, err)
		}
	}
	kept := func(t *testing.T, path string) {
		t.Helper()
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s was removed: %v", path, err)
		}
	}

	t.Run("the install's own directory", func(t *testing.T) {
		dir := filepath.Join(realTempDir(t), "app-tail")
		seed(t, dir)
		if err := removeLegacyHelper(testTrust(nil), dir); err != nil {
			t.Fatalf("the old helper was not removed: %v", err)
		}
		gone(t, filepath.Join(dir, binary))
		gone(t, dir)
	})

	t.Run("a directory something else also uses", func(t *testing.T) {
		dir := filepath.Join(realTempDir(t), "app-tail")
		seed(t, dir, "someone-elses-file")
		if err := removeLegacyHelper(testTrust(nil), dir); err != nil {
			t.Fatalf("a directory holding someone else's file was reported as a failed removal: %v", err)
		}
		gone(t, filepath.Join(dir, binary))
		kept(t, filepath.Join(dir, "someone-elses-file"))
	})

	t.Run("nothing there", func(t *testing.T) {
		if err := removeLegacyHelper(testTrust(nil), filepath.Join(realTempDir(t), "app-tail")); err != nil {
			t.Errorf("a machine with no old helper reported %v", err)
		}
	})

	t.Run("a directory another account owns", func(t *testing.T) {
		dir := filepath.Join(realTempDir(t), "app-tail")
		seed(t, dir)
		err := removeLegacyHelper(testTrust(map[string]uint32{dir: someoneElse}), dir)
		if err == nil || !strings.Contains(err.Error(), dir) {
			t.Errorf("removing from a directory another account owns reported %v, which does not say it was left alone", err)
		}
		kept(t, filepath.Join(dir, binary))
	})

	t.Run("a link where the directory was", func(t *testing.T) {
		root := realTempDir(t)
		elsewhere := filepath.Join(root, "elsewhere")
		seed(t, elsewhere)
		dir := filepath.Join(root, "app-tail")
		if err := os.Symlink(elsewhere, dir); err != nil {
			t.Fatalf("make the link: %v", err)
		}
		err := removeLegacyHelper(testTrust(nil), dir)
		if err == nil || !strings.Contains(err.Error(), dir) {
			t.Errorf("removing through a link reported %v, which does not say it was left alone", err)
		}
		kept(t, filepath.Join(elsewhere, binary))
		kept(t, dir)
	})
}
