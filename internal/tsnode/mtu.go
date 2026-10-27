// SPDX-License-Identifier: MIT

package tsnode

// The largest packet a tailnet carries.

import "tailscale.com/net/tstun"

// DefaultMTU is the packet size the tailnet uses when nothing has measured the path to a
// peer, which is also what its own interface is set to.
//
// It is read from the backend rather than written down here because it is not a constant: it
// is the safe size the backend picked, and a build that measures path MTU picks a different
// one. A number copied into this app would be right until the day it was not, and the way
// that goes wrong is a datagram silently too big for the tunnel it is sent through.
func DefaultMTU() int { return int(tstun.DefaultTUNMTU()) }
