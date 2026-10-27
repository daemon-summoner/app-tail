// SPDX-License-Identifier: MIT

package sockerr

import (
	"errors"
	"io/fs"

	"golang.org/x/sys/windows"
)

func refused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

// WSAEACCES is what Winsock answers with when a bind is refused by the rights this process
// holds or by a port exclusion range -- which is how a machine running Docker Desktop, WSL2
// or Hyper-V refuses port 53 with nothing listening on it. Reported as an address in use it
// would name a DNS server that does not exist.
func permissionDenied(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, windows.WSAEACCES)
}

func addressNotAssigned(err error) bool { return errors.Is(err, windows.WSAEADDRNOTAVAIL) }
