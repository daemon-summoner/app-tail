// SPDX-License-Identifier: MIT

package sysproxy

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const pacURL = "http://127.0.0.1:8088/proxy.pac"

// fakeMachine stands in for the real per-user proxy setting. It is the one external
// boundary here: everything above it -- the record of what was replaced, and the
// decisions about when to put it back -- is the code under test, and runs identically on
// every platform.
type fakeMachine struct {
	value     string
	ok        bool
	reason    string
	readErr   error
	writeErr  error
	writes    int
	lastWrote string
}

func (f *fakeMachine) supported() (bool, string) { return f.ok, f.reason }

func (f *fakeMachine) get() (string, error) {
	if f.readErr != nil {
		return "", f.readErr
	}
	return f.value, nil
}

func (f *fakeMachine) set(url string) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes++
	f.lastWrote = url
	f.value = url
	return nil
}

// newManager builds a manager over a supported fake machine already pointing at prior.
func newManager(t *testing.T, prior string) (*Manager, *fakeMachine) {
	t.Helper()
	machine := &fakeMachine{value: prior, ok: true}
	m := &Manager{
		machine:     machine,
		restorePath: filepath.Join(t.TempDir(), RestoreFileName),
		logger:      slog.New(slog.DiscardHandler),
	}
	return m, machine
}

func mustApply(t *testing.T, m *Manager, url string) {
	t.Helper()
	if err := m.Apply(url); err != nil {
		t.Fatalf("Apply(%q): %v", url, err)
	}
}

func mustClear(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
}

// The core promise: whatever a user had configured before is still there after they turn
// the module on and off again. Losing a corporate PAC URL is the one unforgivable
// outcome of a convenience feature.
func TestTurningItOnAndOffLeavesTheMachineExactlyAsItWas(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)

	mustApply(t, m, pacURL)
	if machine.value != pacURL {
		t.Fatalf("the machine points at %q, want the app's own %q", machine.value, pacURL)
	}

	mustClear(t, m)
	if machine.value != theirs {
		t.Errorf("the machine points at %q, want the %q it had before", machine.value, theirs)
	}
	if _, err := os.Stat(m.restorePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the restore record outlived the restore it described: %v", err)
	}
}

// A machine with nothing configured must end up with nothing configured, not with an
// empty string standing where a value used to be.
func TestAMachineThatHadNoProxyEndsWithNone(t *testing.T) {
	m, machine := newManager(t, "")

	mustApply(t, m, pacURL)
	mustClear(t, m)

	if machine.value != "" {
		t.Errorf("the machine points at %q, want nothing", machine.value)
	}
}

// Applying repeatedly is what a reconcile loop does. The first application is the only
// one that saw the user's own setting, so a later one must not overwrite the record with
// the app's own URL -- that would quietly make restoring a no-op forever.
func TestReapplyingDoesNotForgetWhatWasReplaced(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)

	mustApply(t, m, pacURL)
	for range 3 {
		mustApply(t, m, pacURL)
	}
	if machine.writes != 1 {
		t.Errorf("the setting was written %d times, want the one that changed it", machine.writes)
	}

	mustClear(t, m)
	if machine.value != theirs {
		t.Errorf("the machine points at %q, want the %q it had before", machine.value, theirs)
	}
}

// A record that survived a crash, with the app's URL never actually written, must still
// restore correctly: Apply records before it writes precisely so this case is recoverable.
func TestARecordWrittenBeforeACrashStillRestores(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)

	machine.writeErr = errors.New("the registry is not writable")
	if err := m.Apply(pacURL); err == nil {
		t.Fatal("a failed write was reported as success")
	}
	machine.writeErr = nil

	// The machine never moved, so there is nothing to put back -- and the stale record
	// must not survive to be acted on later.
	mustClear(t, m)
	if machine.value != theirs {
		t.Errorf("the machine points at %q, want the untouched %q", machine.value, theirs)
	}
	if _, err := os.Stat(m.restorePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a record for a change that never happened was kept: %v", err)
	}
}

// Something else set the value after we did. Restoring an older value over a newer one
// is the same class of damage this package exists to avoid, in the opposite direction.
func TestAValueChangedBySomethingElseIsLeftAlone(t *testing.T) {
	const (
		theirs = "http://proxy.corp.example.com/company.pac"
		newer  = "http://proxy.corp.example.com/replacement.pac"
	)
	m, machine := newManager(t, theirs)
	mustApply(t, m, pacURL)

	machine.value = newer
	mustClear(t, m)

	if machine.value != newer {
		t.Errorf("the machine points at %q, want the %q something else set", machine.value, newer)
	}
	if _, err := os.Stat(m.restorePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record was kept, so this would be reconsidered on every start: %v", err)
	}
}

// Clearing with nothing ever applied happens on every start of every install that never
// turned the module on. It must be silent and must not write anything.
func TestClearingWithNothingAppliedChangesNothing(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)

	mustClear(t, m)

	if machine.writes != 0 {
		t.Errorf("the setting was written %d times with nothing ever applied", machine.writes)
	}
	if machine.value != theirs {
		t.Errorf("the machine points at %q, want the untouched %q", machine.value, theirs)
	}
}

// The record must not be believed on a platform that cannot act on it -- a state
// directory synced or copied between machines is the ordinary way that happens.
func TestARecordFromAnotherPlatformIsDiscardedNotApplied(t *testing.T) {
	m, machine := newManager(t, "")
	mustApply(t, m, pacURL)

	machine.ok, machine.reason = false, "this platform has no such setting"
	mustClear(t, m)

	if machine.writes != 1 {
		t.Errorf("the setting was written %d times, want only the original apply", machine.writes)
	}
	if _, err := os.Stat(m.restorePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record survived, so every start would reconsider it: %v", err)
	}
}

// An unreadable setting must stop the whole operation. Treating a read error as "nothing
// was configured" is exactly how the user's value gets recorded as empty and then lost.
func TestAnUnreadableSettingStopsRatherThanAssumingItIsEmpty(t *testing.T) {
	m, machine := newManager(t, "http://proxy.corp.example.com/company.pac")
	machine.readErr = errors.New("permission denied")

	if err := m.Apply(pacURL); err == nil {
		t.Fatal("Apply succeeded against a setting it could not read")
	}
	if machine.writes != 0 {
		t.Errorf("the setting was written %d times despite being unreadable", machine.writes)
	}
	if _, err := os.Stat(m.restorePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a record was written from a value that was never read: %v", err)
	}
}

// Refusing on an unsupported platform is what makes the whole design honest: the switch
// must say why it did nothing rather than report success.
func TestAnUnsupportedPlatformRefusesAndSaysWhy(t *testing.T) {
	m, machine := newManager(t, "")
	machine.ok, machine.reason = false, "needs an administrator here"

	err := m.Apply(pacURL)
	if err == nil {
		t.Fatal("Apply reported success on a platform that cannot apply anything")
	}
	if !strings.Contains(err.Error(), machine.reason) {
		t.Errorf("error %q does not carry the reason the platform gave", err)
	}
}

// State is what the dashboard card renders, so it must distinguish "we set this" from
// "something else did" -- the difference between offering to turn it off and warning
// that another program owns it.
func TestStateSeparatesWhatWeSetFromWhatSomethingElseSet(t *testing.T) {
	m, machine := newManager(t, "http://proxy.corp.example.com/company.pac")

	if state := m.State(pacURL); state.Managed {
		t.Error("someone else's proxy URL is reported as one app-tail manages")
	}

	mustApply(t, m, pacURL)
	state := m.State(pacURL)
	if !state.Managed {
		t.Error("the URL app-tail just wrote is not reported as managed")
	}
	if state.AutoConfigURL != pacURL {
		t.Errorf("AutoConfigURL = %q, want %q", state.AutoConfigURL, pacURL)
	}

	machine.value = "http://somewhere.else/other.pac"
	if state := m.State(pacURL); state.Managed {
		t.Error("a URL something else replaced ours with is still reported as managed")
	}
}

// The limits are the honest part of the feature. A card that offered the switch without
// them would be promising machine-wide interception it does not deliver anywhere.
func TestEveryPlatformStatesWhatTheSwitchDoesNotReach(t *testing.T) {
	m, _ := newManager(t, "")

	state := m.State(pacURL)
	if len(state.Limits) == 0 {
		t.Fatalf("%s offers the switch with no limits stated", runtime.GOOS)
	}
	for _, limit := range state.Limits {
		if strings.TrimSpace(limit) == "" {
			t.Error("a blank limit would render as an empty bullet")
		}
	}
}

// A machine-wide command is offered exactly where this package will not write the
// setting itself, and each one has to be runnable as printed: a label saying what it does
// and the running proxy's own address in it.
func TestTheManualCommandsBelongToThePlatformsThisWillNotChange(t *testing.T) {
	m, machine := newManager(t, "")
	machine.ok, machine.reason = runtime.GOOS == "windows", "not this platform"

	got := m.State(pacURL).Manual
	if machine.ok && len(got) != 0 {
		t.Fatalf("%s writes the setting itself and still offers %d commands to do it by hand", runtime.GOOS, len(got))
	}
	if runtime.GOOS == "darwin" && len(got) == 0 {
		t.Fatal("macOS will not write the setting and offers no command for doing it by hand")
	}

	for _, cmd := range got {
		if cmd.Label == "" {
			t.Errorf("command %q has no label, so nothing explains what it does", cmd.Command)
		}
		if !strings.Contains(cmd.Command, "networksetup") {
			t.Errorf("command %q does not change this machine's own setting, which is all this list is for", cmd.Command)
		}
	}
	// The one that turns it on must name where to point; the one that turns it off must
	// not, or it would read as pointing somewhere rather than stopping.
	if len(got) > 0 && !strings.Contains(got[0].Command, pacURL) {
		t.Errorf("command %q does not name the running proxy", got[0].Command)
	}
}

// Nothing is listening, so a command would name an address that answers nothing.
func TestNoCommandsAreOfferedWhileTheProxyIsNotListening(t *testing.T) {
	if got := ManualCommands(""); got != nil {
		t.Errorf("offered %d commands with no proxy running: %+v", len(got), got)
	}
}

// Only macOS has a machine-wide setting this package refuses to write for itself. Windows
// writes its own, and no other system has one to write -- so offering either of them a
// `networksetup` line would print a command that does not exist on the machine reading it.
func TestOnlyThePlatformWithAnUnwritableSettingIsOfferedACommandForIt(t *testing.T) {
	if got := manualCommandsFor("darwin", pacURL); len(got) == 0 {
		t.Error("macOS will not write the setting and is offered no command for doing it by hand")
	}
	for _, goos := range []string{"windows", "linux", "freebsd"} {
		if got := manualCommandsFor(goos, pacURL); got != nil {
			t.Errorf("%s is offered %d machine-wide commands: %+v", goos, len(got), got)
		}
	}
}

// A corrupt record must fail loudly. Silently treating it as absent would leave the
// user's own setting overwritten with no way back.
func TestACorruptRecordIsReportedRatherThanIgnored(t *testing.T) {
	m, machine := newManager(t, "http://proxy.corp.example.com/company.pac")
	mustApply(t, m, pacURL)
	if err := os.WriteFile(m.restorePath, []byte("{not json"), fileMode); err != nil {
		t.Fatalf("write a corrupt record: %v", err)
	}

	if err := m.Clear(); err == nil {
		t.Fatal("a corrupt record was treated as though nothing had been applied")
	}
	if machine.value != pacURL {
		t.Errorf("the machine was changed to %q on the strength of a record that could not be read", machine.value)
	}
	if state := m.State(pacURL); !strings.Contains(state.Reason, "could not be read") {
		t.Errorf("State reason = %q, want it to surface the unreadable record", state.Reason)
	}
}

// New is what the agent actually builds, and the platform pieces underneath it are the
// half a fake machine never reaches: on every system except Windows they must refuse
// rather than report an empty setting, because an empty string reads as "nothing is
// configured" and is exactly how a user's own value gets recorded as blank and lost.
func TestTheRealManagerRefusesWhereThisPlatformCannotBeChanged(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, slog.New(slog.DiscardHandler))

	state := m.State(pacURL)
	if runtime.GOOS == "windows" {
		if !state.Supported {
			t.Fatalf("Windows reports its own proxy setting as unchangeable: %q", state.Reason)
		}
		return
	}

	if state.Supported {
		t.Fatalf("%s reports a setting this package cannot write as changeable", runtime.GOOS)
	}
	if state.Reason == "" {
		t.Error("the refusal carries no reason, so nothing explains why the switch did nothing")
	}
	if err := m.Apply(pacURL); err == nil {
		t.Error("Apply reported success on a platform with no setting to write")
	}
	if _, err := os.Stat(filepath.Join(dir, RestoreFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a restore record was written for a change that cannot happen: %v", err)
	}
	// Clear is called on every start of every install; with nothing applied it must be
	// silent rather than surfacing the platform refusal as a failure.
	if err := m.Clear(); err != nil {
		t.Errorf("Clear on a fresh state dir: %v", err)
	}
}

// A read that fails is not "nothing is set". The card has to say the setting could not
// be read, or a user sees an empty value and concludes something removed theirs.
func TestStateReportsAnUnreadableSettingRatherThanAnEmptyOne(t *testing.T) {
	m, machine := newManager(t, "http://proxy.corp.example.com/company.pac")
	machine.readErr = errors.New("permission denied")

	state := m.State(pacURL)
	if state.AutoConfigURL != "" {
		t.Errorf("AutoConfigURL = %q, want nothing reported from a read that failed", state.AutoConfigURL)
	}
	if !strings.Contains(state.Reason, "permission denied") {
		t.Errorf("Reason = %q, want the read failure named", state.Reason)
	}
	if state.Managed {
		t.Error("a setting that could not be read is reported as one app-tail manages")
	}
}

// Applying with no URL is a caller bug, and answering it with a write would remove the
// user's own value -- the same damage as a bad restore, reached the other way.
func TestApplyingNothingIsRefusedRatherThanClearingTheSetting(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)

	if err := m.Apply(""); err == nil {
		t.Fatal("Apply(\"\") reported success")
	}
	if machine.writes != 0 || machine.value != theirs {
		t.Errorf("the machine was changed to %q by an empty apply", machine.value)
	}
}

// The address the proxy serves from moves when the dashboard rebinds. The record has to
// follow it, or switching the module off would leave the newer URL in place with nothing
// remembering that it was ours.
func TestARecordAlreadyInPlaceIsUpdatedWhenTheAddressMoves(t *testing.T) {
	const (
		theirs = "http://proxy.corp.example.com/company.pac"
		moved  = "http://127.0.0.1:9999/proxy.pac"
	)
	m, machine := newManager(t, theirs)
	mustApply(t, m, pacURL)

	// The dashboard rebound, and something outside this process already points here.
	machine.value = moved
	mustApply(t, m, moved)

	mustClear(t, m)
	if machine.value != theirs {
		t.Errorf("the machine points at %q, want the %q it had before any of this", machine.value, theirs)
	}
}

// The record is the only thing that can put a user's setting back, so failing to write
// it must stop the change rather than proceed unrecorded.
func TestAnUnwritableRecordStopsTheChange(t *testing.T) {
	m, machine := newManager(t, "http://proxy.corp.example.com/company.pac")
	// A directory where the record should be: os.WriteFile cannot replace one, and this
	// is reachable on every platform without depending on file permissions.
	if err := os.Mkdir(m.restorePath, 0o700); err != nil {
		t.Fatalf("make the record path unwritable: %v", err)
	}

	if err := m.Apply(pacURL); err == nil {
		t.Fatal("Apply succeeded without recording what it replaced")
	}
	if machine.writes != 0 {
		t.Error("this machine was changed with nothing recording what it replaced")
	}
}

// The guard behind supported(): a platform that says it cannot be changed must fail its
// reads and writes rather than answer them. An empty string from a read reads as
// "nothing is configured", which is precisely how a user's own value gets recorded as
// blank and then lost -- so the refusal is the safe answer, not a formality.
func TestAPlatformThatCannotBeChangedRefusesToReadOrWriteAtAll(t *testing.T) {
	machine := newMachineProxy()
	if supported, _ := machine.supported(); supported {
		if _, err := machine.get(); err != nil {
			t.Errorf("%s says it can be changed but its setting could not be read: %v", runtime.GOOS, err)
		}
		return
	}

	if _, err := machine.get(); err == nil {
		t.Errorf("%s reports a proxy setting it cannot actually read", runtime.GOOS)
	}
	if err := machine.set(pacURL); err == nil {
		t.Errorf("%s reported writing a proxy setting it cannot change", runtime.GOOS)
	}
}

// The agent passes its own logger, and a caller that has none must not panic on the
// first log line -- which is inside Apply, long after construction looked fine.
func TestAManagerBuiltWithNoLoggerStillLogs(t *testing.T) {
	m := New(t.TempDir(), nil)
	if m.logger == nil {
		t.Fatal("a manager built with no logger holds none, so the first log line panics")
	}
}

// A record that cannot be parsed must stop an apply as well as a restore. Proceeding
// would overwrite the record with our own URL as the prior value, making the user's real
// setting unrecoverable.
func TestApplyStopsOnARecordItCannotRead(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)
	if err := os.WriteFile(m.restorePath, []byte("{not json"), fileMode); err != nil {
		t.Fatalf("write a corrupt record: %v", err)
	}

	if err := m.Apply(pacURL); err == nil {
		t.Fatal("Apply proceeded past a record it could not read")
	}
	if machine.writes != 0 || machine.value != theirs {
		t.Errorf("the machine points at %q, want the untouched %q", machine.value, theirs)
	}
}

// Applying again after something else moved the setting must still remember the user's
// own value, not the one we left behind. Taking the current value as the prior here is
// how a corporate PAC URL becomes unrecoverable on the second apply.
func TestASecondApplyKeepsTheUsersOwnValueRatherThanOurLeftoverOne(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)
	mustApply(t, m, pacURL)

	// Something else on the machine points it somewhere new, and then the module is
	// reconciled again with a proxy that has moved port.
	machine.value = "http://something.else.example.com/other.pac"
	const moved = "http://127.0.0.1:9099/proxy.pac"
	mustApply(t, m, moved)
	mustClear(t, m)

	if machine.value != theirs {
		t.Errorf("the machine points at %q, want the %q the user configured", machine.value, theirs)
	}
}

// A record that cannot be written is the same failure whether or not one was there
// before: without it there is nothing that can put the user's setting back.
func TestARecordThatCannotBeCreatedStopsTheChange(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	machine := &fakeMachine{value: theirs, ok: true}
	m := &Manager{
		machine: machine,
		// A directory that does not exist, so reading the record succeeds with nothing
		// and only the write fails.
		restorePath: filepath.Join(t.TempDir(), "no-such-dir", RestoreFileName),
		logger:      slog.New(slog.DiscardHandler),
	}

	err := m.Apply(pacURL)

	if err == nil {
		t.Fatal("Apply succeeded without recording what it replaced")
	}
	if machine.writes != 0 || machine.value != theirs {
		t.Errorf("the machine points at %q, want the untouched %q", machine.value, theirs)
	}
}

// The same guard on the already-pointing-here path. It is reached on every reconcile
// while the module is on, so a corrupt record there must stop rather than be replaced
// with one naming our own URL as the user's.
func TestARecordThatCannotBeReadStopsAReapplyToo(t *testing.T) {
	m, machine := newManager(t, pacURL)
	if err := os.WriteFile(m.restorePath, []byte("{not json"), fileMode); err != nil {
		t.Fatalf("write a corrupt record: %v", err)
	}

	if err := m.Apply(pacURL); err == nil {
		t.Fatal("a reapply proceeded past a record it could not read")
	}
	if machine.writes != 0 {
		t.Error("this machine was changed off an unreadable record")
	}
}

// Restoring blind is worse than not restoring: the check that the value is still ours is
// what stops this package overwriting whatever replaced it, and it cannot run on a
// setting that could not be read.
func TestAClearThatCannotReadTheSettingStopsRatherThanRestoringBlind(t *testing.T) {
	m, machine := newManager(t, "http://proxy.corp.example.com/company.pac")
	mustApply(t, m, pacURL)
	machine.readErr = errors.New("the registry key could not be opened")

	err := m.Clear()

	if err == nil {
		t.Fatal("Clear reported success without reading what is there now")
	}
	if !strings.Contains(err.Error(), "could not be opened") {
		t.Errorf("err = %v, want the reason the setting could not be read", err)
	}
	if machine.lastWrote != pacURL {
		t.Errorf("the machine was written with %q on a read that failed", machine.lastWrote)
	}
}

// A restore that failed leaves the machine pointing at app-tail. Reporting success would
// drop the record as well, so the next start would find nothing to put back and the
// user's setting would be gone for good.
func TestAFailedRestoreIsReportedAndKeepsTheRecord(t *testing.T) {
	const theirs = "http://proxy.corp.example.com/company.pac"
	m, machine := newManager(t, theirs)
	mustApply(t, m, pacURL)
	machine.writeErr = errors.New("the registry key is read-only")

	if err := m.Clear(); err == nil {
		t.Fatal("Clear reported the setting put back after the write failed")
	}
	if _, err := os.Stat(m.restorePath); err != nil {
		t.Fatalf("the record was dropped after a failed restore: %v", err)
	}

	// The record survived, so a later attempt still knows what to put back.
	machine.writeErr = nil
	mustClear(t, m)
	if machine.value != theirs {
		t.Errorf("the machine points at %q, want the %q the record held", machine.value, theirs)
	}
}

// A record that could not be removed is still on disk, so the next start would try to
// restore over whatever the user has since set. Reporting it is what stops that.
func TestARecordThatCannotBeRemovedIsReportedRatherThanAssumedGone(t *testing.T) {
	m, _ := newManager(t, "")
	// A non-empty directory where the record should be: os.Remove refuses it, which is
	// the shape of every removal that fails, without depending on file permissions.
	if err := os.MkdirAll(filepath.Join(m.restorePath, "occupied"), 0o700); err != nil {
		t.Fatalf("make the record path unremovable: %v", err)
	}

	if err := m.removeRecord(); err == nil {
		t.Fatal("a record that is still on disk was reported as removed")
	}
}
