// SPDX-License-Identifier: MIT

//go:build !darwin && !windows && !notray

package tray

import (
	"os"
	"testing"
)

// On Linux and the other Unixes a tray icon needs a running graphical session. A
// container or a server has neither, and trying to attach an icon there is the case
// that has to fall back to headless rather than block: `app-tail` in a Docker image
// would otherwise appear to start and then do nothing.
func TestOnlyAGraphicalSessionCanShowATrayIcon(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"a container with no session at all", map[string]string{}, false},
		{"an X session", map[string]string{"DISPLAY": ":0"}, true},
		{"a Wayland session", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, true},
		// XWayland sets both, which must not be read as a conflict.
		{"XWayland", map[string]string{"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"}, true},
		// A profile that exports the variable blank is not a session; treating it as
		// one would show the icon path on a headless box.
		{"a blank DISPLAY", map[string]string{"DISPLAY": ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearDisplayEnvironment(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			if got := hasDisplay(); got != tt.want {
				t.Errorf("hasDisplay() = %v, want %v", got, tt.want)
			}
			if got := Supported(); got != tt.want {
				t.Errorf("Supported() = %v, want %v; the caller branches on this, not on "+
					"hasDisplay", got, tt.want)
			}
		})
	}
}

// clearDisplayEnvironment removes both session markers so a test describes the session
// it means rather than the one the CI runner happens to have.
func clearDisplayEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}
