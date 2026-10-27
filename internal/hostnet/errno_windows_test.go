// SPDX-License-Identifier: MIT

package hostnet

import "golang.org/x/sys/windows"

// The bind refusal Winsock answers with for an address the machine does not carry;
// syscall.EADDRNOTAVAIL on Windows is an invented value no API returns.
var errAddrNotAvail error = windows.WSAEADDRNOTAVAIL
