// SPDX-License-Identifier: MIT

package sockerr

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// The socket errors Winsock answers with, wrapped the way net hands them over on Windows:
// inside an OpError around a SyscallError carrying the WSA errno.
func wrapped(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Err: os.NewSyscallError(op, errno)}
}

func TestRefusedRecognisesTheRefusalWinsockAnswersWith(t *testing.T) {
	for name, err := range map[string]error{
		"bare":    windows.WSAECONNREFUSED,
		"wrapped": wrapped("dial", windows.WSAECONNREFUSED),
		"fmt":     fmt.Errorf("dial tcp: %w", windows.WSAECONNREFUSED),
	} {
		if !Refused(err) {
			t.Errorf("%s: %v was not read as a refused connection", name, err)
		}
	}
	// syscall.ECONNREFUSED on Windows is an invented number no API returns; reading it as a
	// refusal would be a branch that fires only in tests.
	for name, err := range map[string]error{
		"posix name": syscall.ECONNREFUSED,
		"reset":      wrapped("read", windows.WSAECONNRESET),
		"timeout":    wrapped("dial", windows.WSAETIMEDOUT),
		"plain":      errors.New("connection refused"),
		"nil":        nil,
	} {
		if Refused(err) {
			t.Errorf("%s: %v was read as a refused connection", name, err)
		}
	}
}

func TestPermissionDeniedRecognisesABindThisProcessMayNotMake(t *testing.T) {
	for name, err := range map[string]error{
		"wsaeacces": wrapped("listen", windows.WSAEACCES),
		"bare":      windows.WSAEACCES,
		"fs":        fs.ErrPermission,
		"path":      &fs.PathError{Op: "open", Path: `C:\ProgramData\app-tail`, Err: fs.ErrPermission},
		"fmt":       fmt.Errorf("bind: %w", fs.ErrPermission),
		"access":    wrapped("open", windows.ERROR_ACCESS_DENIED),
	} {
		if !PermissionDenied(err) {
			t.Errorf("%s: %v was not read as a bind this process may not make", name, err)
		}
	}
	for name, err := range map[string]error{
		"in use":       wrapped("listen", windows.WSAEADDRINUSE),
		"not assigned": wrapped("listen", windows.WSAEADDRNOTAVAIL),
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
		"bare":    windows.WSAEADDRNOTAVAIL,
		"wrapped": wrapped("listen", windows.WSAEADDRNOTAVAIL),
	} {
		if !AddressNotAssigned(err) {
			t.Errorf("%s: %v was not read as an address this machine does not carry", name, err)
		}
	}
	for name, err := range map[string]error{
		"posix name": syscall.EADDRNOTAVAIL,
		"in use":     wrapped("listen", windows.WSAEADDRINUSE),
		"refused":    wrapped("dial", windows.WSAECONNREFUSED),
		"nil":        nil,
	} {
		if AddressNotAssigned(err) {
			t.Errorf("%s: %v was read as an address this machine does not carry", name, err)
		}
	}
}
