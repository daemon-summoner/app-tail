// SPDX-License-Identifier: MIT

//go:build !windows

package instance

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The default ask is a terminate signal, which is what main turns into the ordered shutdown
// that puts this machine's resolver, proxy settings and routes back. A takeover that reached
// for the kill instead would leave every one of them behind, pointed at an agent that is gone.
func TestTheAgentAlreadyRunningIsAskedWithATerminateSignal(t *testing.T) {
	configPath := configIn(t)
	running := startHolder(t, configPath, false)

	lock, err := Acquire(t.Context(), Options{ConfigPath: configPath, Grace: 30 * time.Second})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if !running.gone(10 * time.Second) {
		t.Fatal("the takeover finished while the agent it took over from was still running")
	}
	status, ok := running.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("the agent's exit could not be read: %v", running.cmd.ProcessState)
	}
	if got := status.Signal(); got != syscall.SIGTERM {
		t.Errorf("the agent already running was stopped by %v, want %v: anything else skips its shutdown",
			got, syscall.SIGTERM)
	}
}

// An agent that no longer acts on the signal -- wedged, or stuck in a shutdown that never
// finishes -- still has to go, or the user is left with an app that never opens. This is the
// real ending, not a stand-in: nothing else proves the platform's own kill runs.
func TestAnAgentThatIgnoresTheSignalIsEndedOutright(t *testing.T) {
	configPath := configIn(t)
	running := startHolder(t, configPath, false, holderDeafVar+"=1")

	lock, err := Acquire(t.Context(), Options{ConfigPath: configPath, Grace: testGrace})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if !running.gone(10 * time.Second) {
		t.Fatal("the takeover finished while the agent that ignored the signal was still running")
	}
	status, ok := running.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("the agent's exit could not be read: %v", running.cmd.ProcessState)
	}
	if got := status.Signal(); got != syscall.SIGKILL {
		t.Errorf("the agent that ignored the ask ended by %v, want %v", got, syscall.SIGKILL)
	}
}

// The process id comes out of a file, and the file outlives the agent that wrote it: by the
// time it is read it can name whatever the system gave that id to next. Ending that process
// is not a mistake anything can undo, so a process running some other program is left alone.
func TestAProcessRunningAnotherProgramIsNotEnded(t *testing.T) {
	bystander := exec.Command("sleep", "60")
	if err := bystander.Start(); err != nil {
		t.Fatalf("start a process that is not app-tail: %v", err)
	}
	exited := make(chan struct{})
	go func() {
		_ = bystander.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = bystander.Process.Kill()
		<-exited
	})

	err := killHolder(t.Context(), bystander.Process.Pid)

	if err == nil {
		t.Error("a process running another program was ended without complaint")
	}
	select {
	case <-exited:
		t.Fatal("a process that is not app-tail was ended because a claim named its process id")
	case <-time.After(200 * time.Millisecond):
	}
}

// The ask is held to the same rule as the ending. A terminate signal stops most programs just as
// finally, so one sent to whatever now holds the agent's old process id is the same mistake.
func TestAProcessRunningAnotherProgramIsNotSignalledToStop(t *testing.T) {
	bystander := exec.Command("sleep", "60")
	if err := bystander.Start(); err != nil {
		t.Fatalf("start a process that is not app-tail: %v", err)
	}
	exited := make(chan struct{})
	go func() {
		_ = bystander.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = bystander.Process.Kill()
		<-exited
	})

	// No agent recorded an address beside this config, so the signal is the only ask there is.
	err := stopHolder(t.Context(), configIn(t), bystander.Process.Pid)

	if err == nil {
		t.Error("a process running another program was asked to stop without complaint")
	}
	select {
	case <-exited:
		t.Fatal("a process that is not app-tail was stopped because a claim named its process id")
	case <-time.After(200 * time.Millisecond):
	}
}

// A process that has already gone is the outcome the ending wanted, whatever used to run there.
func TestEndingAProcessThatIsAlreadyGoneIsNotAFailure(t *testing.T) {
	gone := exec.Command("sleep", "0")
	if err := gone.Run(); err != nil {
		t.Fatalf("run a process to its end: %v", err)
	}

	if err := killHolder(t.Context(), gone.Process.Pid); err != nil {
		t.Errorf("ending a process that had already gone: %v", err)
	}
}

func TestOnlyAnotherCopyOfThisProgramCountsAsTheAgent(t *testing.T) {
	for _, tc := range []struct {
		running, self string
		same          bool
	}{
		{"/usr/local/bin/app-tail", "/usr/local/bin/app-tail", true},
		{"/opt/old/app-tail", "/usr/local/bin/app-tail", true},
		// What Linux reports for a program replaced on disk while it runs, which is every upgrade.
		{"/usr/local/bin/app-tail (deleted)", "/usr/local/bin/app-tail", true},
		{"/bin/sleep", "/usr/local/bin/app-tail", false},
		{"/usr/local/bin/app-tail-helper", "/usr/local/bin/app-tail", false},
		{"", "/usr/local/bin/app-tail", false},
	} {
		if got := sameProgramName(tc.running, tc.self); got != tc.same {
			t.Errorf("a process running %q beside this program at %q: same = %v, want %v", tc.running, tc.self, got, tc.same)
		}
	}
}
