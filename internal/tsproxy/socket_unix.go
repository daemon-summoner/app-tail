// SPDX-License-Identifier: MIT

//go:build unix

package tsproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
)

// listenLocal opens one instance's socket, replacing one a previous run left behind.
//
// The socket is 0600 inside a 0700 directory, both owned by the account running this app.
// A proxy is a grant: anything that can connect to it reaches everything the instance's
// rules allow, so a socket another account on the machine could open would hand that grant
// away with nothing on screen saying so.
func listenLocal(path string) (net.Listener, error) {
	// Shut while the socket inside is created: a socket is created at the process umask, so
	// between the bind and the chmod below it is briefly reachable by anyone who can enter
	// the directory.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the proxy socket directory: %w", err)
	}
	// Re-applied because MkdirAll leaves the mode of a directory that already exists, and
	// one an earlier version left behind carries whatever mode that version chose.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("close the proxy socket directory: %w", err)
	}
	// A socket file outlives the process that made it, so a start after a crash would
	// bind-fail on this app's own leftover. Removing it is safe because the directory is
	// this account's and closed: nothing else can have put a file here.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove the previous proxy socket: %w", err)
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on the proxy socket %s: %w", path, err)
	}
	// The close travels with the reason: a socket left listening at a mode another account
	// could open is the failure this whole function exists to prevent.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("restrict the proxy socket: %w", err), ln.Close())
	}
	return ln, nil
}

// removeLocal deletes the socket file a stopped instance left behind. The listener is
// already closed, so a failure here costs nothing at run time and is reported rather than
// raised: the next start removes whatever is in the way itself.
func removeLocal(path string, logger *slog.Logger) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Debug("removing the proxy's local socket failed", "path", path, "error", err)
	}
}
