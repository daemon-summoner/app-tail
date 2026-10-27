// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

// openvpnManagementOwner is the account allowed to drive a connection over its management
// socket.
//
// In the helper that is the account it was installed to serve, which is the one whose agent
// dials in. With no account recorded this is not the helper but an agent already holding the
// rights, and the answer is the account that agent is running as -- which is this process's
// own.
func openvpnManagementOwner() (int, error) {
	owner, err := ownerUID()
	switch {
	case err == nil:
		return owner, nil
	case errors.Is(err, errNoRecordedOwner):
		return os.Geteuid(), nil
	default:
		return 0, err
	}
}

// openvpnManagementUser is the name of the account openvpn is told may connect to its
// management socket.
//
// openvpn takes a name rather than a number for --management-client-user, and the name
// becomes an argument to a program running as root, so it is checked as well as looked up:
// one that is empty, starts like an option, or carries a space or a control character is
// refused rather than passed on.
func openvpnManagementUser() (string, error) {
	uid, err := openvpnManagementOwner()
	if err != nil {
		return "", err
	}
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("look up the name of account %d, which openvpn has to be told is the one allowed to drive this connection: %w", uid, err)
	}
	name := account.Username
	if name == "" || strings.HasPrefix(name, "-") || strings.IndexFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return "", fmt.Errorf("account %d is named %q, which is not a name openvpn can be given as the one allowed to drive this connection", uid, name)
	}
	return name, nil
}

// prepareManagementSocket readies the directory openvpn creates its management socket in,
// and clears the socket's path.
//
// The directory has to be a real directory belonging to this process's own account -- root,
// in the helper -- and is set to 0711 every time, because MkdirAll leaves the mode of one that
// already exists alone. A link in its place is refused rather than followed: whoever made it
// would be choosing where root creates the socket. The path is cleared because a socket file
// outlives the program that made it, and openvpn will not bind over one a crash left behind.
func prepareManagementSocket(dir, socket string) error {
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return fmt.Errorf("create the directory for this connection's management socket: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("read the directory for this connection's management socket: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory (it is %s), so this side will not have openvpn create its management socket there",
			dir, info.Mode().Type())
	}
	owner, _, err := ownerOf(info, dir)
	if err != nil {
		return err
	}
	if int(owner) != os.Geteuid() {
		return fmt.Errorf("%s belongs to %s rather than to this side's own account, so that account could replace the management socket inside it",
			dir, describeUser(owner))
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		return fmt.Errorf("close the directory for this connection's management socket: %w", err)
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the management socket a previous run left behind: %w", err)
	}
	return nil
}

// terminate asks a process to close rather than killing it. openvpn handles this signal by
// telling its server the client is leaving and taking its own interface and routes down,
// which a kill does not give it the chance to do.
func terminate(p *os.Process) error { return p.Signal(syscall.SIGTERM) }

// askToClose and killProcess are the same two asks aimed at a process number rather than at a
// process this side started. That is what a reclaim has: a number read back from a record
// written by a run that is gone, with no handle left anywhere to go with it.
func askToClose(pid int) error { return signalProcess(pid, syscall.SIGTERM) }

func killProcess(pid int) error { return signalProcess(pid, syscall.SIGKILL) }

// signalProcess answers a number that names nothing with os.ErrProcessDone, so a caller reads
// "it is already gone" the same way whichever of the two it holds.
func signalProcess(pid int, sig syscall.Signal) error {
	err := syscall.Kill(pid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

// processAlive reports whether a process with this number exists.
//
// Signal zero is the kernel's own way of asking: it looks the process up and runs the
// permission check, and delivers nothing. A process that is there and may not be signalled is
// still there, so that answer counts as alive -- reading it as gone is what would let a stop
// report success over a process that is still running.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
