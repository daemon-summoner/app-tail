// SPDX-License-Identifier: MIT

// Package relaunch starts this program again, in place of the process calling it.
//
// It exists because nothing supervises app-tail on most of the machines it runs on. A
// launchd agent and a systemd unit both restart it only after a *failure* exit, an
// instance started from a terminal or from the .app bundle has no supervisor at all, and
// Windows has none in either form. So a restart the user asked for cannot be "exit and
// hope something notices" -- the process has to start its own replacement.
//
// The caller's contract is the important half: relaunch must happen only after the agent
// has finished shutting down. The dashboard listener falls back to an OS-assigned port
// when the configured one is busy and then records that port, so a replacement started
// while the old process still holds the port would quietly move the dashboard and write
// the move down, stranding the browser tab that asked for the restart.
package relaunch

import (
	"fmt"
	"os"
)

// Exec replaces this process with a fresh copy of the same binary, run with the same
// arguments in the same directory.
//
// On unix it does not return: the process image is replaced, so the PID survives and a
// supervisor watching it sees nothing happen at all. On Windows it starts a detached
// copy and returns, leaving the caller to exit.
func Exec() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("relaunch: find this program: %w", err)
	}
	return exec(exe, os.Args[1:])
}
