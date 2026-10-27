// SPDX-License-Identifier: MIT

//go:build !windows

package relaunch

import (
	"fmt"
	"os"
	osexec "os/exec"
	"strings"
	"testing"
)

// helperEnv turns this test binary into the process being replaced. The property under
// test is that nothing after exec runs, which cannot be observed from inside the process
// making the call.
const helperEnv = "APP_TAIL_RELAUNCH_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "1" {
		os.Exit(m.Run())
	}
	if err := exec("/bin/sh", []string{"-c", "printf replacement"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Print("the caller kept running")
	os.Exit(3)
}

// The image is replaced rather than a second process started, and the PID is kept.
//
// Both halves matter and neither is visible from inside the call: launchd and systemd are
// watching that PID, so a fork here reads to them as app-tail having exited and counts
// against a restart throttle, and a caller that resumes after exec would run the shutdown
// path of a process that no longer exists.
func TestTheReplacementTakesOverThisProcessRatherThanRunningBesideIt(t *testing.T) {
	cmd := osexec.Command(os.Args[0], "-test.run=TestTheReplacementTakesOverThisProcessRatherThanRunningBesideIt")
	cmd.Env = append(os.Environ(), helperEnv+"=1")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the replaced process exited with %v; it wrote:\n%s", err, out)
	}
	if got := string(out); got != "replacement" {
		if strings.Contains(got, "the caller kept running") {
			t.Fatalf("exec returned instead of replacing the image, so the caller ran on: %q", got)
		}
		t.Fatalf("the replacement wrote %q, want %q", got, "replacement")
	}
}

// A path that cannot be started has to come back as an error naming it. Exec is reached
// from a restart the user asked for in the dashboard, and the agent has already released
// the port by then -- a silent failure there leaves nothing running and nothing said.
func TestAProgramThatCannotBeStartedIsReportedRatherThanLeavingNothingRunning(t *testing.T) {
	missing := t.TempDir() + "/app-tail"

	err := exec(missing, []string{"run"})

	if err == nil {
		t.Fatal("starting a program that does not exist was reported as a successful restart")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("the failure does not name the program: %v", err)
	}
}
