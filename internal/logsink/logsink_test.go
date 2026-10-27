// SPDX-License-Identifier: MIT

package logsink

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

func TestARunWithNoConsoleKeepsWhatEarlierRunsWrote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte("first run\n"), config.FileMode); err != nil {
		t.Fatalf("seed the log: %v", err)
	}

	sink, closeSink, err := openFile(dir)
	if err != nil {
		t.Fatalf("openFile: %v", err)
	}
	if _, err := sink.Write([]byte("second run\n")); err != nil {
		t.Fatalf("write to the log: %v", err)
	}
	if err := closeSink(); err != nil {
		t.Fatalf("close the log: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the log back: %v", err)
	}
	if got := string(body); got != "first run\nsecond run\n" {
		t.Fatalf("the log lost what an earlier run wrote: %q", got)
	}
}

func TestTheLogIsCreatedAlongWithAStateDirectoryThatIsNotThereYet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")

	sink, closeSink, err := openFile(dir)
	if err != nil {
		t.Fatalf("openFile: %v", err)
	}
	if _, err := sink.Write([]byte("started\n")); err != nil {
		t.Fatalf("write to the log: %v", err)
	}
	if err := closeSink(); err != nil {
		t.Fatalf("close the log: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatalf("the log was not created: %v", err)
	}
	if runtime.GOOS == "windows" {
		// Windows reports a mode this test cannot assert on: the permissions there come
		// from the directory's ACL, not from the bits passed to OpenFile.
		return
	}
	if info.Mode().Perm() != config.FileMode.Perm() {
		t.Fatalf("the log is readable by more than its owner: %v", info.Mode().Perm())
	}
}

func TestALogPastTheCapIsSetAsideRatherThanGrowing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	old := strings.Repeat("x", maxBytes)
	if err := os.WriteFile(path, []byte(old), config.FileMode); err != nil {
		t.Fatalf("seed the log: %v", err)
	}

	sink, closeSink, err := openFile(dir)
	if err != nil {
		t.Fatalf("openFile: %v", err)
	}
	if _, err := sink.Write([]byte("this run\n")); err != nil {
		t.Fatalf("write to the log: %v", err)
	}
	if err := closeSink(); err != nil {
		t.Fatalf("close the log: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the log back: %v", err)
	}
	if got := string(body); got != "this run\n" {
		t.Fatalf("the oversized log was not started fresh: %d bytes", len(got))
	}
	previous, err := os.ReadFile(path + previousSuffix)
	if err != nil {
		t.Fatalf("the previous log was discarded rather than set aside: %v", err)
	}
	if len(previous) != len(old) {
		t.Fatalf("the previous log was truncated: %d bytes of %d", len(previous), len(old))
	}
}

func TestALogThatCannotBeSetAsideStillTakesThisRunsDiagnostics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxBytes)), config.FileMode); err != nil {
		t.Fatalf("seed the log: %v", err)
	}
	// A directory in the place the set-aside generation belongs: the rename cannot happen,
	// which is the shape a Windows process holding the log open produces.
	occupied := path + previousSuffix
	if err := os.Mkdir(occupied, config.DirMode); err != nil {
		t.Fatalf("occupy the set-aside name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(occupied, "in the way"), []byte("x"), config.FileMode); err != nil {
		t.Fatalf("fill the occupying directory: %v", err)
	}

	sink, closeSink, err := openFile(dir)
	if err != nil {
		t.Fatalf("a log that could not be set aside stopped this run from having anywhere to write: %v", err)
	}
	if _, err := sink.Write([]byte("this run\n")); err != nil {
		t.Fatalf("write to the log: %v", err)
	}
	if err := closeSink(); err != nil {
		t.Fatalf("close the log: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the log back: %v", err)
	}
	if !strings.Contains(string(body), "this run\n") {
		t.Fatal("this run's diagnostics were not written")
	}
	if !strings.Contains(string(body), "set aside") {
		t.Fatalf("the rotation failure went unrecorded: %q", string(body)[max(0, len(body)-200):])
	}
}

func TestAStateDirectoryThatCannotHoldALogIsReportedRatherThanIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a file in the path of a directory is not the failure Windows produces here")
	}
	// A file where the state directory belongs: MkdirAll cannot make it, and a build with
	// no console must say so rather than run with its diagnostics going nowhere.
	blocker := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(blocker, []byte("not a directory"), config.FileMode); err != nil {
		t.Fatalf("seed the blocker: %v", err)
	}

	if _, _, err := openFile(blocker); err == nil {
		t.Fatal("opening a log under a file that is not a directory reported success")
	}
}

// Where there is a standard error, that is where the diagnostics go: creating a log file
// beside the config on a Mac or a Linux box would hide from the terminal the very message
// somebody started app-tail by hand to read.
func TestAProcessWithAConsoleWritesToItAndCreatesNoLog(t *testing.T) {
	if !StderrUsable() {
		t.Skip("this build has no standard error, which the file half of Open covers")
	}
	dir := t.TempDir()

	sink, closeSink, err := Open(func() (string, error) { return dir, nil })
	if err != nil {
		t.Fatalf("open the sink: %v", err)
	}
	t.Cleanup(func() {
		if err := closeSink(); err != nil {
			t.Errorf("close the sink: %v", err)
		}
	})

	if sink != os.Stderr {
		t.Errorf("the sink is %T, want this process's standard error", sink)
	}
	// And the closer is safe to call twice, because it closes nothing: closing standard
	// error would take the terminal's output away from everything that runs after it.
	if err := closeSink(); err != nil {
		t.Fatalf("close the sink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a log file was created at %s alongside a working standard error", dir)
	}
}

// The state directory is resolved from the account this process runs as, and the root helper
// launchd starts has none: asking for one there fails. A run with somewhere to print needs no
// directory at all, so that failure must never reach the caller -- a process that exits on it
// is a helper that never opens its socket.
func TestARunWithSomewhereToPrintNeverAsksWhereItsStateDirectoryIs(t *testing.T) {
	if !StderrUsable() {
		t.Skip("this build has no standard error, so it needs the directory the log goes in")
	}
	asked := false

	sink, closeSink, err := Open(func() (string, error) {
		asked = true
		return "", errors.New("$HOME is not defined")
	})

	if err != nil {
		t.Fatalf("a state directory nobody needs stopped the sink from opening: %v", err)
	}
	if asked {
		t.Error("the state directory was resolved for a run that writes to standard error")
	}
	if sink != os.Stderr {
		t.Errorf("the sink is %T, want this process's standard error", sink)
	}
	if err := closeSink(); err != nil {
		t.Fatalf("close the sink: %v", err)
	}
}

// And the other half of the same rule: where a file is the only place to write, a directory
// that cannot be located is the reason there is nowhere to write, and has to be said.
func TestARunWithNoConsoleReportsAStateDirectoryItCannotLocate(t *testing.T) {
	if StderrUsable() {
		t.Skip("this build writes to standard error, which needs no directory")
	}

	_, _, err := Open(func() (string, error) { return "", errors.New("$HOME is not defined") })

	if err == nil {
		t.Fatal("a build with nowhere to print opened a sink over a directory it could not locate")
	}
	if !strings.Contains(err.Error(), "$HOME is not defined") {
		t.Errorf("the failure reads %q, want it to carry why the directory could not be located", err)
	}
}
