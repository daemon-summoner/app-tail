// SPDX-License-Identifier: MIT

//go:build !windows

package forward

import "syscall"

// The refusal this platform's sockets answer with. Windows uses a Winsock number, and
// syscall.ECONNREFUSED there is an invented value no API returns.
var errRefused error = syscall.ECONNREFUSED
