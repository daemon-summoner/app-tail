// SPDX-License-Identifier: MIT

package tunnel

import (
	"net/netip"
	"testing"
)

// A resolver that answered with no addresses has not served the name, and the two have to be
// told apart from a resolver that could not be reached: the caller translates every address
// it was given, and an answer of none translated into none would come back as a name that
// resolves to nothing rather than as a name that does not exist.
func TestAnAnswerWithNoAddressesIsNotAServedName(t *testing.T) {
	if (Lookup{}).Served() {
		t.Error("an empty answer reads as the network having served the name")
	}
	if !(Lookup{Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.5")}}).Served() {
		t.Error("an answer carrying an address reads as the network not having served the name")
	}
}
