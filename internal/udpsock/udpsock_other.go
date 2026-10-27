// SPDX-License-Identifier: MIT

//go:build !windows

package udpsock

import "net"

// SilenceUnreachable does nothing here. Every other platform already leaves an unconnected
// datagram socket alone when a peer refuses a datagram: the refusal reaches a connected
// socket and nothing else, which is what a listener wants.
func SilenceUnreachable(net.PacketConn) error { return nil }
