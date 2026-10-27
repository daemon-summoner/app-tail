// SPDX-License-Identifier: MIT

package peeraccount

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// lsofPath is the system copy, which System Integrity Protection keeps from being replaced.
const lsofPath = "/usr/sbin/lsof"

// ownedByThisAccount asks lsof for this account's sockets bound to peer. Without root lsof
// sees only this account's processes, so finding the socket is the answer; another
// account's socket is simply not listed.
func ownedByThisAccount(peer, server netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := peer.Addr().Unmap()
	target := host.String()
	if host.Is6() {
		target = "[" + target + "]"
	}
	cmd := exec.CommandContext(ctx, lsofPath, "-nP", "-a",
		"-u", strconv.Itoa(os.Getuid()),
		"-iTCP@"+target+":"+strconv.Itoa(int(peer.Port())),
		"-Fn")
	out, err := cmd.Output()
	var exit *exec.ExitError
	// lsof exits 1 both when nothing matched and when it could not read something; what it
	// printed is what counts, and a match is only ever trusted from its output.
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
		return fmt.Errorf("list this account's connections with lsof: %w", err)
	}
	if lsofHasConnection(out, peer, server) {
		return nil
	}
	return ErrOtherAccount
}
