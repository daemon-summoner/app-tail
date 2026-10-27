// SPDX-License-Identifier: MIT

//go:build !notray

package tray

import "testing"

// Windows is the one platform where every session app-tail runs in can show the icon: it
// installs itself as a per-user login item rather than a service, so it is always inside
// the user's own desktop session. The session markers a remote shell or a headless Unix
// sets mean nothing here, and reading them would drop the tray for anyone using app-tail
// over an RDP session or from a shell with a Unix-shaped environment.
func TestEveryWindowsSessionCanShowTheTrayIcon(t *testing.T) {
	markers := map[string]string{
		"SSH_CONNECTION":  "10.0.0.2 51000 10.0.0.3 22",
		"SSH_CLIENT":      "10.0.0.2 51000 22",
		"SSH_TTY":         "/dev/pts/0",
		"DISPLAY":         ":0",
		"WAYLAND_DISPLAY": "wayland-0",
	}
	for key, value := range markers {
		t.Run(key, func(t *testing.T) {
			// Set, not cleared: a session that carries these is the case worth pinning. An
			// OpenSSH server on Windows sets them, and a user who signed in that way is still
			// in a desktop session that can show the icon.
			t.Setenv(key, value)

			if !hasDisplay() {
				t.Errorf("a session carrying %s=%s was treated as unable to show a tray icon", key, value)
			}
			if !Supported() {
				t.Error("Supported() disagrees with hasDisplay(), so the caller falls back to headless anyway")
			}
		})
	}
}
