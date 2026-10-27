// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/tailscale/peercred"
)

// socketDir is where the helper's socket lives. It is a system directory rather than one
// under the user's home because the helper runs as root and creates it: a path any user
// can rename is a path any user can point at their own listener.
const socketDir = "/var/run/app-tail"

// SocketPath is where the helper listens.
func SocketPath() string { return socketDir + "/helper.sock" }

// ownerEnv names the account the helper takes commands from. The helper is started by
// the system with no session of its own, so the user it serves is recorded when it is
// installed rather than inferred at run time.
const ownerEnv = "APPTAIL_HELPER_OWNER"

// peerIsOwner reports whether the process at the other end may command this one.
//
// The socket's own mode is not enough. It is created 0600 and given to the account the
// helper serves, which stops another user from connecting -- but the helper is the piece
// of this app that holds root, so it checks rather than assumes: a mode set wrongly by an
// installer, or a directory replaced between creation and bind, would otherwise hand
// root-level network control to whoever got there first.
//
// The check is the peer's uid, taken from the kernel rather than from anything the peer
// says. A process cannot lie about it, and it cannot be changed after the connection is
// made. asRoot reports a peer running as root, which the program check that follows this one
// does not apply to.
func peerIsOwner(conn net.Conn) (asRoot bool, err error) {
	want, err := ownerUID()
	if err != nil {
		return false, err
	}
	creds, err := peercred.Get(conn)
	if err != nil {
		return false, fmt.Errorf("read the connecting process's identity: %w", err)
	}
	uid, ok := creds.UserID()
	if !ok {
		return false, errors.New("the connecting process has no identity the kernel will vouch for")
	}
	got, err := strconv.Atoi(uid)
	if err != nil {
		return false, fmt.Errorf("read the connecting process's user id %q: %w", uid, err)
	}
	// Root is always allowed: it can already do everything the helper does, so refusing
	// it would protect nothing and would break a machine where the agent runs as root.
	if got == 0 || got == want {
		return got == 0, nil
	}
	return false, fmt.Errorf("this helper takes commands from user %d, and the connection came from user %d", want, got)
}

// errNoRecordedOwner reports that nothing was written into the helper's launch
// configuration saying which account it serves. It is a sentinel because the two sides of
// the socket answer it differently: the access check has no expected answer to compare a
// connection against, and the listener has no account to open the socket for.
var errNoRecordedOwner = errors.New("this helper was installed without recording which account it serves (" +
	ownerEnv + " is unset), so it will not take commands")

// ownerUID is the account the helper serves.
//
// It is read from the environment the installer wrote into the helper's own launch
// configuration, not from the connection: the whole point is to have an expected answer
// to compare the connection against. A helper with no owner recorded refuses everything
// rather than defaulting to "anyone", because the default that is wrong here hands out
// root.
func ownerUID() (int, error) {
	raw := os.Getenv(ownerEnv)
	if raw == "" {
		return 0, errNoRecordedOwner
	}
	if uid, err := strconv.Atoi(raw); err == nil {
		return uid, nil
	}
	u, err := user.Lookup(raw)
	if err != nil {
		return 0, fmt.Errorf("look up the account %q this helper was installed for: %w", raw, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("read the user id of %q: %w", raw, err)
	}
	return uid, nil
}

// ListenHelper opens the helper's socket, replacing one a previous run left behind.
//
// The socket belongs to the one account the installer recorded, and is 0600. That is an
// owner rather than only a mode because the helper runs as root: a mode on a root-owned
// socket can only choose between root and every account on the machine, and the account
// this exists to serve is neither. The directory holding it stays root-owned so no other
// account can put a listener of its own beside this one.
func ListenHelper(path string) (*net.UnixListener, error) {
	return listenHelper(path, os.Chmod)
}

// listenHelper takes the mode change as a parameter because it is the step here that only
// fails on a machine a test cannot make: one holding a directory this process may write to
// and may not change. A socket left listening at the wrong mode is the failure that
// matters, so both of its paths are exercised rather than reasoned about.
func listenHelper(path string, chmod func(name string, mode os.FileMode) error) (*net.UnixListener, error) {
	if path == "" {
		path = SocketPath()
	}
	owner, err := ownerUID()
	// A helper with no account recorded has none to open the socket for. It opens one
	// anyway: every connection is then refused with the sentence naming what is unset,
	// which a socket that was never created cannot say.
	hasOwner := err == nil
	if err != nil && !errors.Is(err, errNoRecordedOwner) {
		return nil, err
	}

	// Shut while the socket inside is opened: a socket is created at the process umask,
	// so between the bind and the chmod below it is briefly reachable by anyone who can
	// enter the directory.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the helper's socket directory: %w", err)
	}
	// Re-applied because MkdirAll leaves the mode of a directory that already exists, and
	// one an earlier install left behind carries whatever mode that install chose.
	if err := chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("close the helper's socket directory: %w", err)
	}
	// A socket file outlives the process that made it, so a helper restarting after a
	// crash would bind-fail on its own leftover. Removing it is safe because the
	// directory is root-owned: nothing else can have put a file here.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove the previous helper socket: %w", err)
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on the helper socket %s: %w", path, err)
	}
	// Each failure below leaves a socket that is listening at an owner or a mode another
	// account could reach, so the close travels with the reason it is being closed.
	if hasOwner {
		if err := os.Chown(path, owner, -1); err != nil {
			return nil, errors.Join(fmt.Errorf("give the helper socket to the account it serves: %w", err), ln.Close())
		}
	}
	if err := chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("restrict the helper socket: %w", err), ln.Close())
	}
	// Opened last, and only far enough to walk through: the account the socket belongs to
	// has to reach it, and no other account may create anything beside it.
	if err := chmod(dir, 0o755); err != nil {
		return nil, errors.Join(fmt.Errorf("open the helper's socket directory: %w", err), ln.Close())
	}
	return ln, nil
}
