// SPDX-License-Identifier: MIT

package forward

import "golang.org/x/sys/windows"

// The refusal Winsock answers with; syscall.ECONNREFUSED on Windows is an invented value
// no API returns, so a test feeding it would pass a branch production never takes.
var errRefused error = windows.WSAECONNREFUSED

// What accept fails with when the process or the system has run out of room, or a
// connection was gone before it could be handed over, in the numbers Winsock uses.
var errsOutOfRoom = []error{
	windows.WSAEMFILE, windows.WSAENOBUFS, windows.WSAECONNABORTED,
	windows.ERROR_TOO_MANY_OPEN_FILES, windows.ERROR_NOT_ENOUGH_MEMORY,
}
