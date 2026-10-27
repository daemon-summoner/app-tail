// SPDX-License-Identifier: MIT

//go:build !windows

package logsink

// StderrUsable is true everywhere else: no other platform links a build that is handed
// no standard error, and a process started from a launch agent or a systemd unit has one
// pointing at that supervisor's own log.
func StderrUsable() bool { return true }
