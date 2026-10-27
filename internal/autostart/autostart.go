// SPDX-License-Identifier: MIT

// Package autostart installs and removes a per-user login item so the agent starts
// with the user's session.
//
// The templates are hand-written and deliberately small: an operator has to be able
// to read the file this app dropped on their machine, understand it, and delete it
// by hand. A generic service library would emit something opaque instead.
package autostart

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Label identifies the login item across all three platforms.
const Label = "com.sellitus.app-tail"

// ServiceName is the bare name used where a reverse-DNS label does not fit, such as
// a systemd unit or a registry value.
const ServiceName = "app-tail"

// Manager installs and removes the login item for the current user.
type Manager struct {
	// ExecPath is the binary the login item launches.
	ExecPath string
	// Args are appended to ExecPath to form the command the login item runs. Empty
	// starts app-tail the way starting it by hand does.
	Args []string
	// Home overrides the user's home directory. Tests point it at a temp dir so no
	// real login item is ever touched.
	Home string
	// Elevated asks for a login item that starts app-tail with administrator rights.
	// Only the network-interface mode needs them, and only Windows can grant them this
	// way; everywhere else the privileged work is a separate helper and this is false.
	//
	// It changes which login item is installed on Windows, not just how one behaves, so
	// a manager built with the wrong value reports on the wrong thing. It is set from
	// the stored network mode by whoever builds the manager.
	Elevated bool
}

// New builds a manager for the running binary.
func New(args ...string) (*Manager, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate this executable: %w", err)
	}
	// A symlinked or relocated binary would otherwise be recorded by a path that
	// stops resolving later.
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = resolved
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locate the user home directory: %w", err)
	}
	return &Manager{ExecPath: exe, Args: args, Home: home}, nil
}

// Validate checks that the manager could plausibly install a working login item.
func (m *Manager) Validate() error {
	if strings.TrimSpace(m.ExecPath) == "" {
		return fmt.Errorf("no executable path was resolved for the login item")
	}
	if !filepath.IsAbs(m.ExecPath) {
		return fmt.Errorf("login item needs an absolute executable path, got %q", m.ExecPath)
	}
	if strings.TrimSpace(m.Home) == "" {
		return fmt.Errorf("no home directory was resolved for the login item")
	}
	return nil
}

// TemporaryPathWarning returns a warning when the binary sits somewhere a login item
// cannot rely on, and an empty string otherwise. Installing from `go run` output or
// a build directory produces a login item that breaks on the next reboot, which the
// user would otherwise discover only when the app silently stopped starting.
func (m *Manager) TemporaryPathWarning() string {
	path := m.ExecPath
	for _, prefix := range temporaryPrefixes() {
		if prefix != "" && pathHasPrefix(path, prefix, runtime.GOOS == "windows") {
			return fmt.Sprintf(
				"the login item points at %s, which is a temporary build location; "+
					"install app-tail to a stable path first or it will not start after a reboot", path)
		}
	}
	return ""
}

// pathHasPrefix reports whether path is prefix or sits under it. The comparison is by whole
// path element, so a binary at /tmpfoo is not read as living in /tmp, and both sides are
// cleaned first because one of them comes from the environment and the other from the
// running process.
//
// fold is what Windows needs: the path a process reports for itself and the path the
// environment gives for the temporary directory routinely differ only in the case of the
// user's name, and comparing those byte for byte misses every temporary build there.
func pathHasPrefix(path, prefix string, fold bool) bool {
	path, prefix = filepath.Clean(path), filepath.Clean(prefix)
	if fold {
		path, prefix = strings.ToLower(path), strings.ToLower(prefix)
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+string(os.PathSeparator))
}

func temporaryPrefixes() []string {
	prefixes := []string{"/tmp", "/var/folders", "/private/var/folders"}
	if tmp := os.TempDir(); tmp != "" {
		prefixes = append(prefixes, tmp)
	}
	if cache, err := os.UserCacheDir(); err == nil {
		prefixes = append(prefixes, filepath.Join(cache, "go-build"))
	}
	return prefixes
}

// staleLoginItem reports whether an installed login item starts app-tail with the wrong
// rights, given which forms are installed. Only Windows has two forms; the decision is
// kept here, away from the registry and the Task Scheduler, because it is the part that
// can be wrong on a machine nobody is looking at.
//
// Nothing installed means nothing is wrong: a mode change must not conjure a login item
// out of a machine whose owner never asked for one.
func staleLoginItem(elevated, runValue, task bool) bool {
	if !runValue && !task {
		return false
	}
	if runValue && task {
		// Both forms start app-tail at the same login, so this machine gets two copies
		// racing for the dashboard port and the state directory -- and the one that loses
		// exits with an error nobody is there to read. Installing again is what removes
		// whichever form the current mode does not use.
		return true
	}
	if elevated {
		return !task
	}
	return !runValue
}

// Problem describes an installed login item that will not start app-tail correctly, and
// is empty when there is nothing wrong with the one this machine has.
//
// It is recomputed from the machine each time rather than remembering an earlier failed
// correction: the same fault is also what a start attempts to repair, and a stored
// verdict would go on being served after the repair worked. What it exists for is the
// case where the repair could not: the switch reads as on, the item is there, and
// nothing about the machine says the next login will not start app-tail.
func (m *Manager) Problem() string {
	stale, err := m.NeedsReinstall()
	if err != nil {
		return fmt.Sprintf("whether the login item still starts this machine's app-tail could not be checked: %v", err)
	}
	if !stale {
		return ""
	}
	if warning := m.TemporaryPathWarning(); warning != "" {
		return warning
	}
	return m.ReinstallReason() + " Run app-tail install-autostart from the copy of app-tail you want started."
}

// command renders the executable and its arguments as one list.
func (m *Manager) command() []string {
	return append([]string{m.ExecPath}, m.Args...)
}

// writeFile writes a login-item file, creating its directory. The file is
// deliberately world-readable: it holds no secrets and an operator must be able to
// inspect it.
func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// removeFile deletes a login-item file, treating an already-absent one as success.
func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", path, err)
}
