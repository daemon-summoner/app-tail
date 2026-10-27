// SPDX-License-Identifier: MIT

//go:build !notray

package tray

import (
	"os"
	"testing"
)

// macOS always has a window server, so the only thing that makes a session unable to
// show a menu-bar icon is being someone else's shell. Getting this wrong is invisible
// in the worst way: `app-tail` over SSH to a build Mac would try to attach an icon to
// a session that cannot show one and appear to hang, with nothing on screen to say so.
func TestARemoteShellIsTreatedAsHavingNoMenuBar(t *testing.T) {
	// Every variable ssh sets, because which ones are present depends on whether the
	// login allocated a tty and on the sshd configuration. Any one of them alone has
	// to be enough.
	tests := []struct {
		name string
		key  string
		val  string
	}{
		{"a plain ssh command", "SSH_CONNECTION", "10.0.0.2 51000 10.0.0.9 22"},
		{"an older client that only sets SSH_CLIENT", "SSH_CLIENT", "10.0.0.2 51000 22"},
		{"an interactive ssh login", "SSH_TTY", "/dev/ttys004"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearSSHEnvironment(t)
			t.Setenv(tt.key, tt.val)

			if hasDisplay() {
				t.Errorf("a session with %s set claims it can show a menu-bar icon; "+
					"app-tail would try to attach one and appear to hang", tt.key)
			}
			if Supported() {
				t.Error("Supported() disagrees with hasDisplay(), so the caller would " +
					"take the tray path anyway")
			}
		})
	}
}

// A local login has a window server and must get the tray, or every desktop user
// silently falls back to headless and loses the menu bar icon entirely.
func TestALocalMacSessionCanShowTheMenuBarIcon(t *testing.T) {
	clearSSHEnvironment(t)

	if !hasDisplay() {
		t.Error("a local macOS session was treated as headless")
	}
	if !Supported() {
		t.Error("Supported() refused a session that hasDisplay() accepts")
	}
}

// An empty variable is not a remote session: ssh sets these to real values, and a
// shell profile that exports them blank would otherwise disable the tray for good.
func TestAnEmptySSHVariableIsNotARemoteSession(t *testing.T) {
	clearSSHEnvironment(t)
	t.Setenv("SSH_CONNECTION", "")

	if !hasDisplay() {
		t.Error("a blank SSH_CONNECTION was treated as a remote session")
	}
}

// clearSSHEnvironment unsets every marker, so the test describes the session it means
// rather than inheriting whatever the developer's own terminal happens to carry.
// t.Setenv first registers the restore; Unsetenv then removes the variable outright.
func clearSSHEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}
