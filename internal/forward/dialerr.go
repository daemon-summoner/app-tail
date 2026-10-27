// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/sellitus/app-tail/internal/sockerr"
)

// dialFailure turns a raw dial error into something a user can act on. The bare net
// error a failed forward records ("context deadline exceeded") says nothing about
// what to check; these messages name the likely cause instead.
func dialFailure(target string, err error) error {
	var dnsErr *net.DNSError
	var refused *RefusedDialError
	switch {
	case errors.As(err, &refused):
		return fmt.Errorf("%s resolved to %s, which this forward may not connect to: %w", target, refused.Addr, refused.Err)
	case isTimeout(err):
		return fmt.Errorf(
			"timed out connecting to %s; it may be offline, not listening on that port, or blocked by your tailnet ACLs",
			target)
	case sockerr.Refused(err):
		return fmt.Errorf("%s refused the connection; nothing is listening on that port", target)
	case errors.As(err, &dnsErr):
		return fmt.Errorf("could not resolve %s; check the host name", target)
	default:
		return fmt.Errorf("could not reach %s: %w", target, err)
	}
}

// isTimeout reports whether err is a dial that ran out of time, covering both the
// context deadline and a lower-level i/o timeout.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
