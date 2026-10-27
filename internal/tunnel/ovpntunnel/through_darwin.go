// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// through makes a socket leave by the named interface whatever this machine's routing table
// says.
//
// Binding the socket's address is not enough, and the difference is the whole reason this
// exists: an address says who the packet is from, and the route for where it is going is what
// picks the interface it leaves by. So a connection dialled "through" this network follows
// whatever route covers the destination -- which, once something else is carrying this
// machine's internet traffic, is that something else. The dial would go back out through the
// interface that was asking for it.
//
// It also settles which of two connections is meant. Two connections to the same provider are
// handed the same address inside the network, so the address alone names both of them.
func through(name string) (func(network, address string, c syscall.RawConn) error, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("find the interface %s this connection is running on: %w", name, err)
	}
	index := iface.Index
	return func(network, _ string, c syscall.RawConn) error {
		var failed error
		if err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				failed = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
				return
			}
			failed = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
		}); err != nil {
			return err
		}
		if failed != nil {
			return fmt.Errorf("send this connection out %s: %w", name, failed)
		}
		return nil
	}, nil
}
