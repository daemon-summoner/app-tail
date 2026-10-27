// SPDX-License-Identifier: MIT

//go:build !notray

package tray

import "os"

// hasDisplay reports whether this session can show a menu-bar icon.
//
// macOS always has a window server, but a process started over SSH has no GUI
// session to attach to, and trying to show an icon there fails in a way the user
// never sees. Treating a remote shell as headless is the difference between a
// working `app-tail` on a build server and one that appears to hang.
func hasDisplay() bool {
	for _, key := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if os.Getenv(key) != "" {
			return false
		}
	}
	return true
}
