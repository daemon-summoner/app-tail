// SPDX-License-Identifier: MIT

//go:build !darwin && !linux

package hostnet

import "context"

// Giving one interface a default route of its own is written per platform, against that
// platform's own routing. The two the app ships OpenVPN connections for have their own files;
// nothing here ever starts one, so nothing here ever asks for the route either. Reporting the
// refusal rather than doing nothing is what keeps a connection that cannot carry traffic from
// saying that it can.

func scopeDefault(context.Context, string, string, bool) error { return ErrScopedRoutesUnsupported }

func unscopeDefault(context.Context, string, string, bool) error { return ErrScopedRoutesUnsupported }

// hostDefaultRoute reports where this machine sends traffic it has no more specific route for.
// Nothing here can act on the answer, so it is not read.
func hostDefaultRoute(context.Context, bool) (string, string, bool, error) {
	return "", "", false, ErrScopedRoutesUnsupported
}

// ScopedRoutesSupported reports whether this machine can give one interface a default route
// of its own. It cannot.
func ScopedRoutesSupported() error { return ErrScopedRoutesUnsupported }
