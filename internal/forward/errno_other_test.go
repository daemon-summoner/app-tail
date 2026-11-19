// SPDX-License-Identifier: MIT

//go:build !windows

package forward

import "syscall"

// The refusal this platform's sockets answer with. Windows uses a Winsock number, and
// syscall.ECONNREFUSED there is an invented value no API returns.
var errRefused error = syscall.ECONNREFUSED

// What accept fails with when the process or the system has run out of room, or a
// connection was gone before it could be handed over.
var errsOutOfRoom = []error{
	syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNABORTED,
}
