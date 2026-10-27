// SPDX-License-Identifier: MIT

//go:build !windows

package hostnet

import "syscall"

// The bind refusal this platform answers with for an address the machine does not carry.
// Windows uses a Winsock number, and syscall.EADDRNOTAVAIL there is an invented value no
// API returns.
var errAddrNotAvail error = syscall.EADDRNOTAVAIL
