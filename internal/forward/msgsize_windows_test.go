// SPDX-License-Identifier: MIT

package forward

import (
	"io"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

// One client sending a datagram larger than the read buffer must cost that client its
// datagram and nothing else. Windows reports the oversized read as an error naming no
// sender, so a forward that treated it as a read failure would stop serving everybody
// because of one packet -- and the code always arrives wrapped in a *net.OpError, never
// bare, so a comparison rather than errors.Is would never match at all.
func TestOnlyAnOversizedDatagramIsSurvivable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{{
		name: "the bare code",
		err:  windows.WSAEMSGSIZE,
		want: true,
	}, {
		// The shape a UDP read actually returns it in.
		name: "wrapped by the net package",
		err:  &net.OpError{Op: "read", Net: "udp", Err: windows.WSAEMSGSIZE},
		want: true,
	}, {
		name: "a closed socket",
		err:  net.ErrClosed,
		want: false,
	}, {
		name: "an ordinary end of stream",
		err:  io.EOF,
		want: false,
	}, {
		// The listening socket never sees this one -- udpsock.SilenceUnreachable turns it
		// off at bind. It reaches a connected socket, where it is what it says: the one
		// host that socket talks to refused the datagram, and reading it again is pointless.
		name: "a connection reset",
		err:  &net.OpError{Op: "read", Net: "udp", Err: windows.WSAECONNRESET},
		want: false,
	}, {
		name: "no error at all",
		err:  nil,
		want: false,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := datagramTooLarge(tc.err); got != tc.want {
				t.Errorf("datagramTooLarge(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
