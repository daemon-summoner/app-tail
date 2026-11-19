// SPDX-License-Identifier: MIT

//go:build !windows

package forward

import "syscall"

// acceptOutOfRoom is what accept fails with when the process or the system has run out of
// something -- descriptors, socket buffers, memory -- or when one connection was gone
// before it could be handed over. None of them says anything about the listener, which
// goes on working once the shortage passes.
var acceptOutOfRoom = []error{
	syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNABORTED,
}
