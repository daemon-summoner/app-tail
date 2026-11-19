// SPDX-License-Identifier: MIT

//go:build !windows

package instance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// stopHolder asks the agent running as pid to shut down.
//
// SIGTERM is what the process is already built around: main turns it into the same ordered
// shutdown a Ctrl-C gets, and that shutdown is what puts this machine's resolver, proxy
// settings and routes back. The API is the fallback for the case the signal cannot cover --
// an agent another account started, which refuses a signal from this one.
//
// The signal goes only to another copy of this program, for the reason sameProgram gives. A
// process that is not one is left to the API, which the agent alone can answer.
func stopHolder(ctx context.Context, configPath string, pid int) error {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return nil
	}
	sigErr := sameProgram(pid)
	if sigErr == nil {
		sigErr = syscall.Kill(pid, syscall.SIGTERM)
	}
	if sigErr == nil || errors.Is(sigErr, syscall.ESRCH) {
		return nil
	}
	apiErr := askAgentToQuit(ctx, configPath)
	if apiErr == nil {
		return nil
	}
	return errors.Join(fmt.Errorf("ask process %d to stop: %w", pid, sigErr), apiErr)
}

// killHolder ends a process that did not stop when it was asked. A process that has gone in
// the meantime is the outcome this wanted, not a failure.
func killHolder(_ context.Context, pid int) error {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err := sameProgram(pid); err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("end process %d: %w", pid, err)
	}
	return nil
}

// sameProgram refuses to end a process that is not another copy of this program.
//
// The process id came out of the claim file, which outlives the agent that wrote it, and the
// system hands an id back out once the process holding it is gone: between the claim being
// written and this call it can have come to name something else entirely, and ending the
// wrong process is not a recoverable mistake.
func sameProgram(pid int) error {
	running, err := runningProgram(pid)
	if err != nil {
		return fmt.Errorf("read what process %d is running: %w", pid, err)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program: %w", err)
	}
	if !sameProgramName(running, self) {
		return fmt.Errorf("process %d is running %s, not another copy of %s",
			pid, filepath.Base(running), filepath.Base(self))
	}
	return nil
}

// sameProgramName compares two program paths by file name. The directory is left out because
// a copy started from somewhere else is still the agent, and Linux marks a program replaced on
// disk while it runs -- which every upgrade does -- by adding a suffix to its path.
func sameProgramName(running, self string) bool {
	if running == "" {
		return false
	}
	running = strings.TrimSuffix(running, " (deleted)")
	return filepath.Base(running) == filepath.Base(self)
}
