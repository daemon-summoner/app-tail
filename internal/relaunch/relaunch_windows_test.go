// SPDX-License-Identifier: MIT

package relaunch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The replacement has to be started and given the arguments it was called with. Windows
// cannot replace a running image, so the whole restart is this one call: if it starts
// nothing, the caller exits a moment later and the machine is left with no app-tail at
// all, which is the failure nobody is around to see.
func TestTheReplacementIsStartedWithTheArgumentsItWasGiven(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("resolve the system directory: %v", err)
	}
	cmd := filepath.Join(system, "cmd.exe")
	marker := filepath.Join(t.TempDir(), "started.txt")

	if err := exec(cmd, []string{"/c", "copy", "/y", "nul", marker}); err != nil {
		t.Fatalf("start the replacement: %v", err)
	}

	// Polled rather than waited on: the handle is released by design, so there is
	// nothing left to wait for.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the replacement never ran: nothing created %s", marker)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A path that cannot be started has to come back as an error naming it. Exec is reached
// from a restart the user asked for in the dashboard, and the agent has already released
// the port by then -- a silent failure there leaves nothing running and nothing said.
func TestAProgramThatCannotBeStartedIsReportedRatherThanLeavingNothingRunning(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "app-tail.exe")

	err := exec(missing, []string{"run"})

	if err == nil {
		t.Fatal("starting a program that does not exist was reported as a successful restart")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("the failure does not name the program: %v", err)
	}
}

// The replacement starts where this process is, so a relative --state-dir on its command
// line resolves to the same directory it did before the restart.
func TestTheReplacementStartsInTheSameDirectoryAsThisProcess(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("read this process's working directory: %v", err)
	}

	if got := workingDir(); got != wd {
		t.Errorf("the replacement starts in %q, want %q", got, wd)
	}
}
