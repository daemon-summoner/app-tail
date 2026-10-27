// SPDX-License-Identifier: MIT

package autostart

import (
	"fmt"
	"os"
	"path/filepath"
)

// Kind names the sort of login item this manager installs, as the label beside Path
// in messages and docs.
func (m *Manager) Kind() string { return "systemd user unit" }

// Path is where the systemd user unit is written.
func (m *Manager) Path() string {
	return filepath.Join(m.configHome(), "systemd", "user", ServiceName+".service")
}

// configHome honours XDG_CONFIG_HOME so the unit lands where the user's systemd
// actually looks.
func (m *Manager) configHome() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" && filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(m.Home, ".config")
}

// wantedByPath is the symlink systemd reads when starting the user session. It is
// created directly rather than by shelling out to `systemctl --user enable`, which
// fails outside a live user session.
func (m *Manager) wantedByPath() string {
	return filepath.Join(m.configHome(), "systemd", "user", "default.target.wants", ServiceName+".service")
}

// Enabled reports whether the unit is installed and wired into default.target.
func (m *Manager) Enabled() (bool, error) {
	if err := m.Validate(); err != nil {
		return false, err
	}
	unit, err := fileExists(m.Path())
	if err != nil || !unit {
		return false, err
	}
	// A unit file that nothing wants never starts, so both halves must be present.
	return fileExists(m.wantedByPath())
}

// SetEnabled writes or removes the unit and its default.target.wants symlink.
func (m *Manager) SetEnabled(enabled bool) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if !enabled {
		if err := removeFile(m.wantedByPath()); err != nil {
			return err
		}
		return removeFile(m.Path())
	}

	if err := writeFile(m.Path(), m.systemdUnit()); err != nil {
		return err
	}

	link := m.wantedByPath()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(link), err)
	}
	// Replace any stale link so a moved binary is picked up.
	if err := removeFile(link); err != nil {
		return err
	}
	if err := os.Symlink(m.Path(), link); err != nil {
		return fmt.Errorf("link %s: %w", link, err)
	}
	return nil
}

// NeedsReinstall reports whether the installed login item starts app-tail with the wrong
// rights. There is only one form here: the privileged work is done by a root process
// started separately, so the login item never carries rights and never needs correcting.
func (m *Manager) NeedsReinstall() (bool, error) { return false, nil }

// ReinstallReason is what a surface would print about a stale login item. Nothing here
// reports one, so this is never reached; it exists because the surfaces are shared.
func (m *Manager) ReinstallReason() string {
	return "The installed login item no longer matches this machine."
}
