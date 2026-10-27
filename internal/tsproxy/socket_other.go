// SPDX-License-Identifier: MIT

//go:build !unix

package tsproxy

import (
	"log/slog"
	"net"
)

// listenLocal opens no socket on this platform, and says so by opening none.
//
// The unix build gets a socket whose access is settled by the filesystem: a 0600 socket in
// a 0700 directory is reachable by exactly one account. Windows has no equivalent for a
// path -- the boundary there is a named pipe with the connecting process read off the
// pipe, which is a different mechanism with a different security model, not a rename of
// this one. Until that is built, an instance here is reachable on its loopback port only,
// which the status reports by carrying no socket path.
func listenLocal(string) (net.Listener, error) { return nil, nil }

// removeLocal has nothing to remove, because nothing was created.
func removeLocal(string, *slog.Logger) {}
