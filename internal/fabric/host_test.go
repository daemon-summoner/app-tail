// SPDX-License-Identifier: MIT

package fabric

import (
	"net"
	"net/netip"
	"testing"
)

func ipnet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	return &net.IPNet{IP: ip, Mask: network.Mask}
}

// The address on an interface is a host address; what is claimed is the network around it.
// Recording 192.168.1.42/24 verbatim would leave the rest of the LAN looking free, and a
// connection would be told it may keep addresses the user's own printer answers at.
func TestAnInterfaceAddressIsRecordedAsTheNetworkAroundIt(t *testing.T) {
	got := hostNetworksFrom([]net.Addr{ipnet(t, "192.168.1.42/24")})

	want := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("networks = %v, want %v", got, want)
	}
}

// Loopback and link-local are not networks anything is reached over. Counting them would
// move a connection out of the way of addresses that answer for nothing.
func TestAddressesThatReachNothingAreNotClaimed(t *testing.T) {
	got := hostNetworksFrom([]net.Addr{
		ipnet(t, "127.0.0.1/8"),
		ipnet(t, "::1/128"),
		ipnet(t, "169.254.7.8/16"),
		ipnet(t, "fe80::1/64"),
		ipnet(t, "10.2.0.5/16"),
	})

	want := netip.MustParsePrefix("10.2.0.0/16")
	if len(got) != 1 || got[0] != want {
		t.Errorf("networks = %v, want only %s", got, want)
	}
}

// An IPv4 address reported in its 16-byte form carries a 128-bit mask. Taken at face value
// it describes a /120 of a 4-byte address, which is no range at all -- and the network this
// machine is on would silently go unreported.
func TestAnIPv4AddressInSixteenByteFormStillYieldsItsNetwork(t *testing.T) {
	four := net.ParseIP("172.16.4.9")
	got := hostNetworksFrom([]net.Addr{&net.IPNet{IP: four.To16(), Mask: net.CIDRMask(96+12, 128)}})

	want := netip.MustParsePrefix("172.16.0.0/12")
	if len(got) != 1 || got[0] != want {
		t.Errorf("networks = %v, want %s", got, want)
	}
}

// Two addresses on one network -- an alias, or the same range on two interfaces -- are one
// claim. Repeating it would make a plan's reasoning list the same range twice.
func TestOneNetworkIsClaimedOnceHoweverManyAddressesAreOnIt(t *testing.T) {
	got := hostNetworksFrom([]net.Addr{ipnet(t, "10.0.0.2/24"), ipnet(t, "10.0.0.3/24")})

	if len(got) != 1 {
		t.Errorf("networks = %v, want one", got)
	}
}

// An address that is not a network is skipped rather than taken for one. The operating
// system reports interface addresses in more than one shape, and a plan built from a claim
// with no range in it would move a connection out of the way of nothing.
func TestAnAddressThatDescribesNoNetworkIsSkipped(t *testing.T) {
	got := hostNetworksFrom([]net.Addr{
		// A bare address with no mask, which carries no network to claim.
		&net.IPAddr{IP: net.ParseIP("10.9.0.1")},
		// And an address of a length that is neither of the two the internet has.
		&net.IPNet{IP: net.IP{10, 9, 0, 1, 0}, Mask: net.CIDRMask(24, 40)},
		ipnet(t, "10.2.0.5/16"),
	})

	want := netip.MustParsePrefix("10.2.0.0/16")
	if len(got) != 1 || got[0] != want {
		t.Errorf("networks = %v, want only %s", got, want)
	}
}

// The read itself has to work on the machine the suite runs on: a failure here means every
// plan is built as though this machine were on no network at all.
func TestThisMachinesNetworksCanBeRead(t *testing.T) {
	got, err := HostNetworks()
	if err != nil {
		t.Fatalf("HostNetworks: %v", err)
	}
	for _, prefix := range got {
		if !prefix.IsValid() || prefix.Addr() != prefix.Masked().Addr() {
			t.Errorf("network %s is not a masked range", prefix)
		}
	}
}
