// SPDX-License-Identifier: MIT

package peeraccount

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
)

// ownedByThisAccount reads the kernel's socket tables, which name the owning uid of every
// TCP socket in this network namespace.
func ownedByThisAccount(peer, server netip.AddrPort) error {
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		table, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		uid, found, err := procTCPOwner(table, peer, server, binary.NativeEndian)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if !found {
			continue
		}
		if uid != uint32(os.Getuid()) {
			return ErrOtherAccount
		}
		return nil
	}
	return ErrOtherAccount
}
