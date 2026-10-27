// SPDX-License-Identifier: MIT

package fabric

import (
	"net"
	"net/netip"
)

// HostNetworks are the networks this machine is directly attached to: one range per
// address on one of its interfaces.
//
// This is what a connection's addresses are checked against, so it is deliberately the
// attached networks rather than the whole routing table. Reading the routing table needs a
// platform-specific call on every operating system and privileges on some, and the ranges
// it would add are the ones reached through a gateway -- which a connection can claim
// without the machine losing anything of its own. An attached network is the case that
// actually cuts a user off from the desk they are sitting at.
func HostNetworks() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return hostNetworksFrom(addrs), nil
}

// hostNetworksFrom is the classification, kept apart from the read so every rule below is
// reachable in a test without depending on the machine the test runs on.
func hostNetworksFrom(addrs []net.Addr) []netip.Prefix {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]bool, len(addrs))
	for _, held := range addrs {
		ipnet, ok := held.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		// Loopback is this machine talking to itself and link-local is what an interface
		// gives itself when nothing configured it. Neither is a network anything is
		// reached over, and treating them as claimed would move a connection out of the
		// way of an address that answers for nothing.
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
			continue
		}
		bits, total := ipnet.Mask.Size()
		// An IPv4 address is sometimes reported in its 16-byte form with a mask to match.
		// Counting those 96 leading bits against a 4-byte address would produce a /120 and
		// no valid range at all, so the network this machine is on would go unnoticed.
		if addr.Is4() && total == 128 {
			bits -= 96
		}
		prefix := netip.PrefixFrom(addr, bits).Masked()
		if !prefix.IsValid() || seen[prefix] {
			continue
		}
		seen[prefix] = true
		out = append(out, prefix)
	}
	return out
}
