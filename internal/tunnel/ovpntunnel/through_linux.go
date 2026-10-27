// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// through makes a socket leave by the named interface whatever this machine's routing table
// says. See the darwin file for why binding the address is not enough.
//
// Binding a socket to a device needs CAP_NET_RAW here, so this fails for an agent running
// without it. That failure is reported rather than worked around: a dial that quietly follows
// the routing table instead would leave through whichever connection is carrying this
// machine's internet traffic, which is not the connection the caller asked for.
func through(name string) (func(network, address string, c syscall.RawConn) error, error) {
	return func(_, _ string, c syscall.RawConn) error {
		var failed error
		if err := c.Control(func(fd uintptr) {
			failed = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
		}); err != nil {
			return err
		}
		if failed != nil {
			return fmt.Errorf("send this connection out %s: %w", name, failed)
		}
		return nil
	}, nil
}
