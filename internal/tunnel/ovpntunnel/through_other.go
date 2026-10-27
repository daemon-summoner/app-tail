// SPDX-License-Identifier: MIT

//go:build !darwin && !linux

package ovpntunnel

import (
	"errors"
	"syscall"
)

// through reports that this platform has no way to send a socket out a chosen interface.
//
// The caller dials from this connection's own address instead, which is right whenever
// nothing else is claiming the destination's route, and wrong the moment something is. Saying
// so is the honest answer: a build that pretended otherwise would send traffic out whichever
// connection is carrying this machine's internet traffic and report it as this one's.
func through(name string) (func(network, address string, c syscall.RawConn) error, error) {
	return nil, errors.New("this system cannot send a connection out a chosen network interface")
}
