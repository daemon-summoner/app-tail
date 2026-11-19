// SPDX-License-Identifier: MIT

package forward

import "golang.org/x/sys/windows"

// acceptOutOfRoom is what accept fails with when the process or the system has run out of
// something -- descriptors, socket buffers, memory -- or when one connection was gone
// before it could be handed over. None of them says anything about the listener, which
// goes on working once the shortage passes. They are Winsock's and the system's own
// numbers: syscall.EMFILE and its neighbours are invented values here that no API returns.
var acceptOutOfRoom = []error{
	windows.WSAEMFILE, windows.WSAENOBUFS, windows.WSAECONNABORTED,
	windows.ERROR_TOO_MANY_OPEN_FILES, windows.ERROR_NOT_ENOUGH_MEMORY, windows.ERROR_OUTOFMEMORY,
}
