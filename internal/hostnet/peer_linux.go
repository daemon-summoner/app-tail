// SPDX-License-Identifier: MIT

package hostnet

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// HelperCallerCheck is how this platform's helper tells app-tail from other programs.
func HelperCallerCheck() CallerCheck { return CallerCheckExecutable }

// peerRunsThisProgram refuses a connection from a process that is not running this program.
// The pid is the one the kernel recorded when the process connected.
func peerRunsThisProgram(conn *net.UnixConn) error {
	pid, err := peerPID(conn)
	if err != nil {
		return err
	}
	return procPeer{root: "/proc"}.check(pid)
}

// refuseInjectableHelper refuses to serve from a program another process could load its own
// code into while it stays the same file (see refuseLoaderStartedProgram).
func refuseInjectableHelper() error {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("read the helper's own program: %w", err)
	}
	defer f.Close()
	name, err := os.Executable()
	if err != nil {
		name = "/proc/self/exe"
	}
	return refuseLoaderStartedProgram(name, f)
}

func peerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("read the connecting process's identity: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("read the connecting process's identity: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("read the connecting process's identity: %w", credErr)
	}
	return int(cred.Pid), nil
}

// RefuseSameUserDebugging stops other processes running as this account from attaching a
// debugger to this one or reading its memory. The agent calls it first thing: the helper
// accepts the agent's program, so a program that could take over a running agent would get
// everything the agent may ask for.
func RefuseSameUserDebugging() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("stop other processes from debugging this one: %w", err)
	}
	return nil
}
