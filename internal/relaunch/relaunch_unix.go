// SPDX-License-Identifier: MIT

//go:build !windows

package relaunch

import (
	"fmt"
	"os"
	"syscall"
)

// exec replaces the running image, so nothing after it in this process runs -- including
// deferred cleanup. Everything the agent holds is therefore already released by the time
// this is called, which is the caller's contract rather than something this can enforce.
//
// Keeping the PID is the point: launchd and systemd are watching it, and a process that
// swapped its own image is not a process that exited, so neither sees a restart to react
// to and neither counts it against a restart throttle.
func exec(path string, args []string) error {
	argv := append([]string{path}, args...)
	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		return fmt.Errorf("relaunch: start %s again: %w", path, err)
	}
	// Unreachable: a successful Exec never returns.
	return nil
}
