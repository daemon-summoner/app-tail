// SPDX-License-Identifier: MIT

//go:build !linux && !darwin

package peeraccount

import "net/netip"

// ownedByThisAccount accepts every connection. On Windows a standard account cannot read the
// command line of another account's process, so the link was never where another account
// could see it.
func ownedByThisAccount(netip.AddrPort, netip.AddrPort) error { return nil }
