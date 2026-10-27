// SPDX-License-Identifier: MIT

//go:build !windows

package forward

import (
	"io"
	"net"
	"syscall"
	"testing"
)

// This system truncates an oversized datagram and reports nothing, so every error a read
// does return failed for another reason and none of them is survivable. Answering true to
// any of them would drop a real failure and leave the read loop spinning on a socket that
// will never produce another datagram.
func TestNoReadFailureHereIsAnOversizedDatagram(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"a closed socket", net.ErrClosed},
		{"an ordinary end of stream", io.EOF},
		// The one error a reader might mistake for the Windows condition. It reaches a
		// UDP read from a send-side failure reported later, not from a truncated read.
		{"the size error this platform uses elsewhere", &net.OpError{Op: "read", Net: "udp", Err: syscall.EMSGSIZE}},
		{"no error at all", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if datagramTooLarge(tc.err) {
				t.Errorf("datagramTooLarge(%v) = true; this platform never reports an oversized read", tc.err)
			}
		})
	}
}
