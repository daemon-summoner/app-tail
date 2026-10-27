// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// TailnetRoutesSupported reports whether this machine can be asked where it sends traffic and
// told to send it somewhere else. It can, as long as the program that does both is there --
// the same one the scoped routes need, checked the same way.
func TailnetRoutesSupported() error {
	if err := trustedRootProgram(routeBinary); err != nil {
		return errors.Join(ErrTailnetRoutesUnsupported, err)
	}
	return nil
}

// routeInterface reports the interface this machine would send traffic to one address through.
// An address the machine has no route for at all reports ok false, which for this feature's
// purposes is the same answer as a route to somewhere else: either way the tailnet is not where
// that traffic goes.
func routeInterface(ctx context.Context, addr netip.Addr) (string, bool, error) {
	iface, _, ok, err := routeLookup(ctx, addr.String(), addr.Is6())
	return iface, ok, err
}

// addRangeRoute sends one whole range to one interface.
//
// The route is added rather than replaced, unlike the scoped defaults: this runs only where the
// machine was found to be sending that range's traffic somewhere else entirely, so there is no
// stale entry of this side's own to clear first. A route already in the table under this
// destination is therefore one the check did not see winning -- an interface-scoped entry, or
// one for a family the lookup answered differently -- and route saying so is reported rather
// than passed over as success, because the traffic this exists to move would still not move.
func addRangeRoute(ctx context.Context, iface string, prefix netip.Prefix) error {
	out, err := exec.CommandContext(ctx, routeBinary,
		"-n", "add", familyFlag(prefix.Addr().Is6()), "-net", prefix.String(), "-interface", iface,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("send %s to %s: %w: %s",
			prefix, iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}
