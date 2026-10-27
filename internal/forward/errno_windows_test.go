// SPDX-License-Identifier: MIT

package forward

import "golang.org/x/sys/windows"

// The refusal Winsock answers with; syscall.ECONNREFUSED on Windows is an invented value
// no API returns, so a test feeding it would pass a branch production never takes.
var errRefused error = windows.WSAECONNREFUSED
