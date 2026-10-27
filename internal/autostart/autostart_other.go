// SPDX-License-Identifier: MIT

//go:build !darwin && !linux && !windows

package autostart

import (
	"fmt"
	"runtime"
)

// Kind names the sort of login item this manager installs, as the label beside Path
// in messages and docs. There is none here.
func (m *Manager) Kind() string { return "unsupported" }

// errUnsupported is returned rather than a silent no-op: a user who asks for
// start-at-login and gets "OK" while nothing was installed would only find out after
// a reboot.
func errUnsupported() error {
	return fmt.Errorf("app-tail cannot install a login item on %s; start it from your own session manager", runtime.GOOS)
}

// Path describes where the login item would live, which is nowhere here.
func (m *Manager) Path() string {
	return ""
}

// Enabled always reports false: nothing can have been installed. Asking is a question and
// not a request, so it is answered rather than refused -- a status read that fails would put
// an error on every surface that shows whether start-at-login is on. Asking for one is what
// SetEnabled refuses.
func (m *Manager) Enabled() (bool, error) {
	return false, nil
}

// SetEnabled always fails, including for the disable direction, so a caller never
// believes it removed something that was never there.
func (m *Manager) SetEnabled(bool) error {
	return errUnsupported()
}

// NeedsReinstall reports whether the installed login item starts app-tail with the wrong
// rights. Nothing can have been installed, so nothing can be wrong -- and unlike Enabled
// and SetEnabled, nobody asked for a login item here, so there is nothing to refuse.
func (m *Manager) NeedsReinstall() (bool, error) { return false, nil }

// ReinstallReason is what a surface would print about a stale login item. Nothing here
// reports one, so this is never reached; it exists because the surfaces are shared.
func (m *Manager) ReinstallReason() string {
	return "The installed login item no longer matches this machine."
}
