// SPDX-License-Identifier: MIT

package hostnet

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The kernel interfaces the check reads. None has a wrapper in x/sys: csops and
// csops_audittoken are the calls codesign itself uses, and LOCAL_PEERTOKEN is the socket
// option launchd and XPC use to learn who connected.
const (
	csOpsStatus = 0 // CS_OPS_STATUS: the code signing flags of a process
	csOpsCDHash = 5 // CS_OPS_CDHASH: the hash of its code directory
	cdHashSize  = 20

	csValid        = 0x00000001 // CS_VALID: every page it has run so far matched its signature
	csGetTaskAllow = 0x00000004 // CS_GET_TASK_ALLOW: any process of the account may debug it
	csRuntime      = 0x00010000 // CS_RUNTIME: signed with the hardened runtime
	csDebugged     = 0x10000000 // CS_DEBUGGED: a debugger has been allowed to change it

	pTraced = 0x00000800 // P_TRACED: a debugger is attached
)

// auditToken is the kernel's record of one process incarnation: its pid together with a
// version the kernel bumps every time that pid runs a new program. A call made with it fails
// rather than answer about whatever runs under the pid now.
type auditToken [8]uint32

func (t auditToken) pid() int { return int(t[5]) }

// darwinPeer is the check with the kernel calls as fields, so a suite can reach each refusal.
type darwinPeer struct {
	selfHash   func() ([cdHashSize]byte, error)
	peerHash   func(auditToken) ([cdHashSize]byte, error)
	peerStatus func(auditToken) (uint32, error)
	traced     func(pid int) (bool, error)
}

var machinePeer = darwinPeer{
	selfHash:   ownCDHash,
	peerHash:   tokenCDHash,
	peerStatus: tokenStatus,
	traced:     tracedPID,
}

// HelperCallerCheck is how this platform's helper tells app-tail from other programs. A helper
// with no code signature has nothing to compare a caller against.
func HelperCallerCheck() CallerCheck {
	if _, err := ownCDHash(); err != nil {
		return CallerCheckUnavailable
	}
	return CallerCheckCodeHash
}

// peerRunsThisProgram refuses a connection from a process that is not running this program.
func peerRunsThisProgram(conn *net.UnixConn) error {
	token, err := peerToken(conn)
	if err != nil {
		return err
	}
	return machinePeer.check(token)
}

// check compares the connecting process's code directory hash with this helper's own. Both
// are read from the kernel, which computed them from the signature the program was started
// with; the peer's is asked for with its audit token, so a process that has run another
// program since it connected is refused rather than answered about.
//
// The helper and the agent are byte-for-byte the same file, signed once before the helper was
// copied from it, so a match is the agent and nothing else is.
func (d darwinPeer) check(token auditToken) error {
	self, err := d.selfHash()
	if err != nil {
		return fmt.Errorf("this helper has no code signature to compare callers against, so it takes commands from root alone; reinstall it from a signed build: %w", err)
	}
	peer, err := d.peerHash(token)
	if err != nil {
		return fmt.Errorf("read the connecting process's code signature (pid %d): %w", token.pid(), err)
	}
	if !bytes.Equal(self[:], peer[:]) {
		return fmt.Errorf("the connecting process (pid %d) is running a different program from this helper, so it is not app-tail", token.pid())
	}
	traced, err := d.traced(token.pid())
	if err != nil {
		return fmt.Errorf("read whether the connecting process (pid %d) is traced: %w", token.pid(), err)
	}
	// Read after the trace flag, by token: a pid that has changed hands since the flag was read
	// fails here, so the flag above was about the process that connected.
	status, err := d.peerStatus(token)
	if err != nil {
		return fmt.Errorf("read the connecting process's code signing state (pid %d): %w", token.pid(), err)
	}
	switch {
	case traced:
		return fmt.Errorf("the connecting process (pid %d) has a debugger attached, which could make it ask for anything", token.pid())
	case status&csDebugged != 0:
		return fmt.Errorf("the connecting process (pid %d) has been changed by a debugger, so its signature no longer says what it runs", token.pid())
	case status&csValid == 0:
		return fmt.Errorf("the connecting process (pid %d) is running code its signature does not cover", token.pid())
	}
	return nil
}

// peerToken reads the audit token the kernel recorded when the other end connected.
func peerToken(conn *net.UnixConn) (auditToken, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return auditToken{}, fmt.Errorf("read the connecting process's identity: %w", err)
	}
	var token auditToken
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(token))
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_LOCAL, unix.LOCAL_PEERTOKEN,
			uintptr(unsafe.Pointer(&token)), uintptr(unsafe.Pointer(&size)), 0)
	}); err != nil {
		return auditToken{}, fmt.Errorf("read the connecting process's identity: %w", err)
	}
	if errno != 0 {
		return auditToken{}, fmt.Errorf("read the connecting process's identity: %w", errno)
	}
	return token, nil
}

// ownCDHash is read once: this process's code cannot change while it runs.
var ownCDHash = sync.OnceValues(func() ([cdHashSize]byte, error) {
	var hash [cdHashSize]byte
	_, _, errno := unix.Syscall6(unix.SYS_CSOPS, uintptr(os.Getpid()), csOpsCDHash,
		uintptr(unsafe.Pointer(&hash[0])), cdHashSize, 0, 0)
	if errno != 0 {
		return hash, errno
	}
	if hash == ([cdHashSize]byte{}) {
		return hash, errors.New("the kernel reported no code directory hash")
	}
	return hash, nil
})

func tokenCDHash(token auditToken) ([cdHashSize]byte, error) {
	var hash [cdHashSize]byte
	_, _, errno := unix.Syscall6(unix.SYS_CSOPS_AUDITTOKEN, uintptr(token.pid()), csOpsCDHash,
		uintptr(unsafe.Pointer(&hash[0])), cdHashSize, uintptr(unsafe.Pointer(&token)), 0)
	if errno != 0 {
		return hash, errno
	}
	if hash == ([cdHashSize]byte{}) {
		return hash, errors.New("the kernel reported no code directory hash")
	}
	return hash, nil
}

func tokenStatus(token auditToken) (uint32, error) {
	var status uint32
	_, _, errno := unix.Syscall6(unix.SYS_CSOPS_AUDITTOKEN, uintptr(token.pid()), csOpsStatus,
		uintptr(unsafe.Pointer(&status)), unsafe.Sizeof(status), uintptr(unsafe.Pointer(&token)), 0)
	if errno != 0 {
		return 0, errno
	}
	return status, nil
}

func tracedPID(pid int) (bool, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return false, err
	}
	if int(info.Proc.P_pid) != pid {
		return false, fmt.Errorf("the kernel answered about process %d", info.Proc.P_pid)
	}
	return info.Proc.P_flag&pTraced != 0, nil
}

// refuseInjectableHelper refuses to serve from a program another process could put its own
// code into while it keeps its code hash (see refuseUnhardenedProgram).
func refuseInjectableHelper() error {
	var status uint32
	_, _, errno := unix.Syscall6(unix.SYS_CSOPS, uintptr(os.Getpid()), csOpsStatus,
		uintptr(unsafe.Pointer(&status)), unsafe.Sizeof(status), 0, 0)
	if errno != 0 {
		return fmt.Errorf("read the helper's own code signing state: %w", errno)
	}
	name, err := os.Executable()
	if err != nil {
		name = "this helper"
	}
	return refuseUnhardenedProgram(name, status)
}

// refuseUnhardenedProgram refuses a helper signed so that code can be put into app-tail
// without changing its code hash. The hash is what callers are matched on and the flags are
// signed into it, so every accepted caller carries the same flags as the helper.
func refuseUnhardenedProgram(name string, status uint32) error {
	switch {
	case status&csRuntime == 0:
		return fmt.Errorf("%s is not signed with the hardened runtime, so any program running as "+
			"your account could load its own code into app-tail with DYLD_INSERT_LIBRARIES and pass "+
			"as app-tail; sign it with `codesign --options runtime` (build_install.sh does) and "+
			"reinstall the helper", name)
	case status&csGetTaskAllow != 0:
		return fmt.Errorf("%s is signed to let any program running as your account attach a "+
			"debugger to app-tail and change what it asks for; sign it without the "+
			"get-task-allow entitlement and reinstall the helper", name)
	}
	return nil
}

// RefuseSameUserDebugging has nothing to add here: the hardened runtime the agent is signed
// with already refuses to let a debugger attach.
func RefuseSameUserDebugging() error { return nil }
