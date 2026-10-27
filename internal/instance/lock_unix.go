// SPDX-License-Identifier: MIT

//go:build !windows

package instance

import (
	"context"
	"errors"
	"fmt"
	"syscall"
)

// stopHolder asks the agent running as pid to shut down.
//
// SIGTERM is what the process is already built around: main turns it into the same ordered
// shutdown a Ctrl-C gets, and that shutdown is what puts this machine's resolver, proxy
// settings and routes back. The API is the fallback for the case the signal cannot cover --
// an agent another account started, which refuses a signal from this one.
func stopHolder(ctx context.Context, configPath string, pid int) error {
	sigErr := syscall.Kill(pid, syscall.SIGTERM)
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
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("end process %d: %w", pid, err)
	}
	return nil
}
