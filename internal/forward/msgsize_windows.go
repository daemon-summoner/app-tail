// SPDX-License-Identifier: MIT

package forward

import (
	"errors"

	"golang.org/x/sys/windows"
)

// datagramTooLarge reports whether err says a datagram did not fit the read buffer.
// Windows answers the read with this instead of handing over the part that fit, and it
// names no sender, so that datagram is lost. The socket is unharmed: treating it as a
// read failure would stop the forward for every client because one sent too much.
func datagramTooLarge(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}
