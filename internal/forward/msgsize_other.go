// SPDX-License-Identifier: MIT

//go:build !windows

package forward

// datagramTooLarge reports whether err says a datagram did not fit the read buffer. This
// system hands over the part that fit and reports nothing, so a read that failed here
// failed for another reason entirely.
func datagramTooLarge(error) bool { return false }
