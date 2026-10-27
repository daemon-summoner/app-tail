// SPDX-License-Identifier: MIT

//go:build !windows

package instance

import (
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
