// SPDX-License-Identifier: MIT

//go:build !windows

package sockerr

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"testing"
)

// The socket errors a POSIX platform answers with, wrapped the way net hands them over:
// inside an OpError around a SyscallError. A predicate that only recognised the bare errno
// would answer every real failure wrong.
func wrapped(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Err: os.NewSyscallError(op, errno)}
}

func TestRefusedRecognisesTheRefusalThisPlatformAnswersWith(t *testing.T) {
	for name, err := range map[string]error{
		"bare":    syscall.ECONNREFUSED,
		"wrapped": wrapped("dial", syscall.ECONNREFUSED),
		"fmt":     fmt.Errorf("dial tcp: %w", syscall.ECONNREFUSED),
	} {
		if !Refused(err) {
			t.Errorf("%s: %v was not read as a refused connection", name, err)
		}
	}
	for name, err := range map[string]error{
		"reset":   wrapped("read", syscall.ECONNRESET),
		"timeout": wrapped("dial", syscall.ETIMEDOUT),
		"plain":   errors.New("connection refused"),
		"nil":     nil,
	} {
		if Refused(err) {
			t.Errorf("%s: %v was read as a refused connection", name, err)
		}
	}
}

func TestPermissionDeniedRecognisesABindThisProcessMayNotMake(t *testing.T) {
	for name, err := range map[string]error{
		"errno":         wrapped("listen", syscall.EACCES),
		"fs":            fs.ErrPermission,
		"path":          &fs.PathError{Op: "open", Path: "/etc/resolver", Err: fs.ErrPermission},
		"fmt":           fmt.Errorf("bind: %w", fs.ErrPermission),
		"bare errno":    syscall.EACCES,
		"wrapped perm":  wrapped("listen", syscall.EPERM),
		"pathed eacces": &fs.PathError{Op: "bind", Path: "127.0.0.1:53", Err: syscall.EACCES},
	} {
		if !PermissionDenied(err) {
			t.Errorf("%s: %v was not read as a bind this process may not make", name, err)
		}
	}
	for name, err := range map[string]error{
		"in use":       wrapped("listen", syscall.EADDRINUSE),
		"not assigned": wrapped("listen", syscall.EADDRNOTAVAIL),
		"plain":        errors.New("permission denied"),
		"nil":          nil,
	} {
		if PermissionDenied(err) {
			t.Errorf("%s: %v was read as a bind this process may not make", name, err)
		}
	}
}

func TestAddressNotAssignedRecognisesAnAddressThisMachineDoesNotCarry(t *testing.T) {
	for name, err := range map[string]error{
		"bare":    syscall.EADDRNOTAVAIL,
		"wrapped": wrapped("listen", syscall.EADDRNOTAVAIL),
	} {
		if !AddressNotAssigned(err) {
			t.Errorf("%s: %v was not read as an address this machine does not carry", name, err)
		}
	}
	for name, err := range map[string]error{
		"in use":  wrapped("listen", syscall.EADDRINUSE),
		"refused": wrapped("dial", syscall.ECONNREFUSED),
		"nil":     nil,
	} {
		if AddressNotAssigned(err) {
			t.Errorf("%s: %v was read as an address this machine does not carry", name, err)
		}
	}
}
