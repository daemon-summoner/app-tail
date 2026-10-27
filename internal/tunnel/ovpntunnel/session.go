// SPDX-License-Identifier: MIT

package ovpntunnel

// The privilege boundary, in this package's own types.
//
// internal/hostnet is what holds -- or talks to what holds -- administrator rights, and the
// set of packages that may reach it is part of the design rather than an accident. So this is
// where the boundary stops: the rest of the app asks for a session and gets an interface
// carrying nothing but a connection id and this package's own run description.
//
// The claim is separate from the one the network interface holds, deliberately. Running an
// OpenVPN connection and putting this machine on a tailnet are not alternatives -- the whole
// point of holding several private networks at once is that they are the same machine -- so
// the privileged side gates them separately and this opens its own connection.

import (
	"context"

	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// Session is a held claim on the privileged side's ability to run OpenVPN connections.
//
// Closing it stops every connection started through it. That is the point rather than a side
// effect: the program carrying the traffic is a separate process holding administrator
// rights, so something has to guarantee it does not outlive the app that asked for it, and
// the privileged side does that when this claim is dropped -- whether the agent exits
// cleanly, is killed, or dies with the machine.
type Session interface {
	Runner
	Close() error
}

// Supported reports whether this build can run an OpenVPN connection at all. It is false on
// the platforms whose privileged side has no way to check who owns the program it would run,
// which is a refusal to guess rather than a missing feature.
func Supported() bool { return hostnet.OpenVPNSupported() }

// Open claims the right to run OpenVPN connections, in this process when it already holds
// administrator rights and over the helper socket when it does not. observer, when set, hears
// whether each connection the helper was asked to run was refused for a missing approval.
func Open(ctx context.Context, logf func(format string, args ...any), observer grants.Observer) (Session, error) {
	return hostnet.OpenOpenVPN(ctx, hostnet.Options{Logf: logf, Grants: observer})
}
