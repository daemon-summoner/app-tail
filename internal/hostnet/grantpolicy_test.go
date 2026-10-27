// SPDX-License-Identifier: MIT

package hostnet

import "testing"

// The ranges a route may not take over without an approval are compared against routes as
// masked prefixes, so one left unmasked, or carrying an IPv4 address with its 128-bit mask
// length, would never match the LAN it describes. Loopback and link-local are never the LAN.
func TestTheMachinesOwnNetworksAreMaskedRangesWithoutLoopbackOrLinkLocal(t *testing.T) {
	attached, err := AttachedNetworks()
	if err != nil {
		t.Fatalf("reading this machine's networks: %v", err)
	}
	for _, prefix := range attached {
		if !prefix.IsValid() {
			t.Errorf("%v is not a valid range", prefix)
			continue
		}
		if prefix != prefix.Masked() {
			t.Errorf("%v is not masked; it should be %v", prefix, prefix.Masked())
		}
		if prefix.Addr().Is4In6() {
			t.Errorf("%v is an IPv4 address in its IPv6 form", prefix)
		}
		if prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
			t.Errorf("%v is loopback or link-local, which no route takes over", prefix)
		}
	}
}
