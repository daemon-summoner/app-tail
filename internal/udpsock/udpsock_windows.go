// SPDX-License-Identifier: MIT

package udpsock

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SilenceUnreachable stops the socket reporting another host's refusal as a failure of its
// own.
//
// Windows answers an ICMP Port Unreachable by queueing WSAECONNRESET on the socket that sent
// the datagram, including a listening socket that is not connected to anything. A read loop
// then sees a fatal-looking error caused by one client that went away, and everybody else
// loses the listener with it. Turning SIO_UDP_CONNRESET off leaves the listener where a
// datagram socket already is: a client that stops listening is not this socket's problem.
func SilenceUnreachable(pc net.PacketConn) error {
	conn, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("this UDP socket (%T) does not carry an operating-system handle", pc)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("reach the UDP socket's handle: %w", err)
	}
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		off := uint32(0)
		var returned uint32
		ioctlErr = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET,
			(*byte)(unsafe.Pointer(&off)), uint32(unsafe.Sizeof(off)),
			nil, 0, &returned, nil, 0)
	}); err != nil {
		return fmt.Errorf("reach the UDP socket's handle: %w", err)
	}
	if ioctlErr != nil {
		return fmt.Errorf("stop the UDP socket reporting connection resets: %w", ioctlErr)
	}
	return nil
}
