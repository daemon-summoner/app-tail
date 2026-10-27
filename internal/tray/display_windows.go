// SPDX-License-Identifier: MIT

//go:build !notray

package tray

// hasDisplay reports whether this session can show a tray icon. Every interactive
// Windows session has a notification area; a service session has no user to show it
// to, but app-tail installs itself as a per-user login item rather than a service,
// so it always runs inside the user's own desktop session.
func hasDisplay() bool {
	return true
}
