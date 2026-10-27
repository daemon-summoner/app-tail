// SPDX-License-Identifier: MIT

//go:build !darwin

package hostnet

// The tailnet-route repair is macOS only, and says so rather than half-working elsewhere.
//
// What it puts back is a route another program installed and something removed. Which program,
// and what it would do about the same loss on its own, is a different answer on every platform:
// Linux and Windows clients install their routes through interfaces this side does not share,
// and a repair written against a guess about them would be a root process writing routes on a
// machine nobody has watched it write routes on. So the check reports the platform rather than
// a healthy machine -- a caller told "not here" stops asking, and a caller told "nothing is
// wrong" would go on believing a tailnet it never checked was reachable.

import (
	"context"
	"net/netip"
)

// TailnetRoutesSupported reports the platform.
func TailnetRoutesSupported() error { return ErrTailnetRoutesUnsupported }

func routeInterface(context.Context, netip.Addr) (string, bool, error) {
	return "", false, ErrTailnetRoutesUnsupported
}

func addRangeRoute(context.Context, string, netip.Prefix) error {
	return ErrTailnetRoutesUnsupported
}
