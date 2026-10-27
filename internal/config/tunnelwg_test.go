// SPDX-License-Identifier: MIT

package config

import (
	"encoding/base64"
	"net/netip"
	"testing"
)

// The test fixtures' keys. They were generated for this suite and unlock nothing: no
// server holds them and no network they reach exists.
const (
	testPrivateKey = "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc="
	testPublicKey  = "majYatxGzfGESWHzcaf6Y+ldZ1CHNgfXsieg+falAgw="
	testPeerKey    = "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM="
)

func wireGuardFixture() WireGuardTunnel {
	return WireGuardTunnel{
		PrivateKey: testPrivateKey,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.7.0.4/24")},
		DNS:        []netip.Addr{netip.MustParseAddr("10.7.0.1")},
		MTU:        1380,
		Peer: WireGuardPeer{
			PublicKey:    testPeerKey,
			Endpoint:     "vpn.example.com:51820",
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.7.0.0/24")},
			KeepaliveSec: 25,
		},
	}
}

// Every value the device is built from has to be compared. A field missed here is an edit
// that is saved, reported as applied, and never reaches the running connection -- which
// looks exactly like a setting that does nothing.
func TestEveryValueTheDeviceIsBuiltFromDecidesWhetherItIsRebuilt(t *testing.T) {
	cases := []struct {
		name   string
		change func(*WireGuardTunnel)
	}{
		{"private key", func(w *WireGuardTunnel) { w.PrivateKey = testPeerKey }},
		{"MTU", func(w *WireGuardTunnel) { w.MTU = 1400 }},
		{"addresses", func(w *WireGuardTunnel) {
			w.Addresses = []netip.Prefix{netip.MustParsePrefix("10.7.0.5/24")}
		}},
		{"resolvers", func(w *WireGuardTunnel) { w.DNS = nil }},
		{"server key", func(w *WireGuardTunnel) { w.Peer.PublicKey = testPublicKey }},
		{"pre-shared key", func(w *WireGuardTunnel) { w.Peer.PresharedKey = testPeerKey }},
		{"server address", func(w *WireGuardTunnel) { w.Peer.Endpoint = "vpn.example.com:51821" }},
		{"keepalive", func(w *WireGuardTunnel) { w.Peer.KeepaliveSec = 15 }},
		{"carried networks", func(w *WireGuardTunnel) {
			w.Peer.AllowedIPs = append(w.Peer.AllowedIPs, netip.MustParsePrefix("192.168.9.0/24"))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored, edited := wireGuardFixture(), wireGuardFixture()
			tc.change(&edited)

			if stored.SameAs(edited) {
				t.Errorf("a changed %s was reported as the same connection", tc.name)
			}
		})
	}
}

func TestAConnectionNothingChangedAboutIsTheSameConnection(t *testing.T) {
	if !wireGuardFixture().SameAs(wireGuardFixture()) {
		t.Error("two identical connections were reported as different, which rebuilds a live connection for nothing")
	}
}

// A stored zero and the default written out are the same packet size, so a form that
// saved the default it was showing must not tear the connection down and hand shake again.
func TestNamingTheSizeAConnectionAlreadyUsesDoesNotRebuildIt(t *testing.T) {
	implied, explicit := wireGuardFixture(), wireGuardFixture()
	implied.MTU = 0
	explicit.MTU = DefaultWireGuardMTU

	if !implied.SameAs(explicit) {
		t.Error("the default MTU written out was read as a change")
	}
}

func TestAConnectionWithNoSizeOfItsOwnUsesTheDefault(t *testing.T) {
	w := wireGuardFixture()
	w.MTU = 0

	if got := w.EffectiveMTU(); got != DefaultWireGuardMTU {
		t.Errorf("EffectiveMTU() = %d, want %d", got, DefaultWireGuardMTU)
	}
}

func TestAConnectionKeepsTheSizeItWasGiven(t *testing.T) {
	if got := wireGuardFixture().EffectiveMTU(); got != 1380 {
		t.Errorf("EffectiveMTU() = %d, want the configured 1380", got)
	}
}

// The stack this connection runs holds addresses, not networks. Handing it the prefix
// would put this device on the whole range rather than at one address in it.
func TestTheAddressesThisDeviceHoldsDropTheNetworkTheyAreIn(t *testing.T) {
	w := wireGuardFixture()
	w.Addresses = []netip.Prefix{
		netip.MustParsePrefix("10.7.0.4/24"),
		netip.MustParsePrefix("fd00::4/64"),
	}

	got := w.InterfaceAddrs()

	want := []netip.Addr{netip.MustParseAddr("10.7.0.4"), netip.MustParseAddr("fd00::4")}
	if len(got) != len(want) {
		t.Fatalf("InterfaceAddrs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d = %s, want %s", i, got[i], want[i])
		}
	}
}

// A default route says every packet should leave here, which is a choice about this
// machine made elsewhere. Reported as a network this connection reaches, it would claim
// every address in existence and collide with every other connection in the report.
func TestTheNetworksAConnectionCarriesLeaveOutTheDefaultRoutes(t *testing.T) {
	w := wireGuardFixture()
	w.Peer.AllowedIPs = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.7.0.0/24"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("fd00::/64"),
	}

	got := w.CarriedRoutes()

	want := []netip.Prefix{netip.MustParsePrefix("10.7.0.0/24"), netip.MustParsePrefix("fd00::/64")}
	if len(got) != len(want) {
		t.Fatalf("CarriedRoutes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("network %d = %s, want %s", i, got[i], want[i])
		}
	}
}

// The value the user pastes into the server. It is derived from the private key rather
// than stored so the two cannot disagree, which makes this the one place a wrong answer
// would produce a configuration that looks right everywhere and never handshakes.
func TestTheKeyToGiveTheServerIsDerivedFromThisDevicesOwn(t *testing.T) {
	w := WireGuardTunnel{PrivateKey: testPrivateKey}

	if got := w.PublicKey(); got != testPublicKey {
		t.Errorf("PublicKey() = %q, want %q", got, testPublicKey)
	}
}

// Before anything is configured there is no key to derive from, and a connection in that
// state is unfinished rather than broken.
func TestAConnectionWithNoUsableKeyPresentsNothing(t *testing.T) {
	for _, private := range []string{"", "not base64", "c2hvcnQ="} {
		w := WireGuardTunnel{PrivateKey: private}
		if got := w.PublicKey(); got != "" {
			t.Errorf("PublicKey() with private key %q = %q, want nothing", private, got)
		}
	}
}

func TestAKeyIsRefusedWithTheReasonItCannotBeUsed(t *testing.T) {
	cases := []struct{ name, key, want string }{
		{"empty", "  ", "must not be empty"},
		{"not base64", "this is not a key", "must be a base64 key as wg(8) writes it"},
		{"too short", base64.StdEncoding.EncodeToString([]byte("short")), "must decode to 32 bytes, got 5"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWireGuardKey(tc.key)
			if err == nil {
				t.Fatalf("%q was accepted as a key", tc.key)
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestAServerAddressIsCheckedForSomethingDialable(t *testing.T) {
	cases := []struct {
		name, endpoint string
		ok             bool
		want           string
	}{
		{name: "a name and a port", endpoint: "vpn.example.com:51820", ok: true},
		{name: "an address and a port", endpoint: "203.0.113.7:51820", ok: true},
		// The bracketed form is the only way to tell an IPv6 address from a host and a
		// port, which is why a bare one is refused rather than read as either.
		{name: "a bracketed IPv6 address", endpoint: "[2001:db8::1]:51820", ok: true},
		{name: "a bare IPv6 address", endpoint: "2001:db8::1", want: "must be the server's address and port, as host:port"},
		{name: "nothing", endpoint: "   ", want: "must not be empty"},
		{name: "no port", endpoint: "vpn.example.com", want: "must be the server's address and port, as host:port"},
		{name: "a bracket that never closes", endpoint: "[2001:db8::1:51820", want: "must be the server's address and port, as host:port"},
		{name: "no server", endpoint: ":51820", want: "must name the server before the port"},
		{name: "a port that is not a number", endpoint: "vpn.example.com:https", want: "must end in a port between 1 and 65535"},
		{name: "a port outside the range", endpoint: "vpn.example.com:70000", want: "must end in a port between 1 and 65535"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := ValidWireGuardEndpoint(tc.endpoint)
			if ok != tc.ok {
				t.Fatalf("ValidWireGuardEndpoint(%q) = %v (%q), want %v", tc.endpoint, ok, why, tc.ok)
			}
			if why != tc.want {
				t.Errorf("reason = %q, want %q", why, tc.want)
			}
		})
	}
}

// A connection is added before it is configured, so every one of these accepts the empty
// state. Refusing it would make an unfinished connection unsavable rather than unstarted.
func TestAnUnconfiguredConnectionIsSavable(t *testing.T) {
	if err := optionalWireGuardKey(any("")); err != nil {
		t.Errorf("an empty key was refused: %v", err)
	}
	if err := optionalWireGuardEndpoint(any("")); err != nil {
		t.Errorf("an empty server address was refused: %v", err)
	}
}

func TestAValueThatCouldNeverWorkIsRefusedWhenItIsEntered(t *testing.T) {
	if err := optionalWireGuardKey(any("not a key")); err == nil {
		t.Error("a key that cannot be decoded was accepted")
	}
	if err := optionalWireGuardEndpoint(any("vpn.example.com")); err == nil {
		t.Error("a server address with no port was accepted")
	}
}

func TestAServerThisConnectionCouldDialIsAccepted(t *testing.T) {
	if err := optionalWireGuardEndpoint(any("vpn.example.com:51820")); err != nil {
		t.Errorf("a dialable server address was refused: %v", err)
	}
	if err := optionalWireGuardKey(any(testPeerKey)); err != nil {
		t.Errorf("a usable key was refused: %v", err)
	}
}

// Two entries for one address are not two addresses: they are one, entered twice. Kept,
// the list would claim the connection holds more than it does.
func TestAnAddressEnteredTwiceIsRefused(t *testing.T) {
	addrs := []netip.Prefix{
		netip.MustParsePrefix("10.7.0.4/24"),
		netip.MustParsePrefix("10.7.0.4/16"),
	}

	err := distinctInterfaceAddrs(any(addrs))

	if err == nil {
		t.Fatal("the same address under two prefixes was accepted")
	}
	if err.Error() != "10.7.0.4 is listed twice" {
		t.Errorf("error = %q, want it to name the repeated address", err)
	}
}

func TestDistinctAddressesAreAccepted(t *testing.T) {
	addrs := []netip.Prefix{
		netip.MustParsePrefix("10.7.0.4/24"),
		netip.MustParsePrefix("fd00::4/64"),
	}

	if err := distinctInterfaceAddrs(any(addrs)); err != nil {
		t.Errorf("two different addresses were refused: %v", err)
	}
}

// A repeat makes the list ambiguous about which entry a later decision -- an address map,
// an egress choice -- was made against.
func TestANetworkListedTwiceIsRefused(t *testing.T) {
	nets := []netip.Prefix{
		netip.MustParsePrefix("10.7.0.0/24"),
		netip.MustParsePrefix("10.7.0.0/24"),
	}

	err := carriedNetworks(any(nets))

	if err == nil {
		t.Fatal("the same network listed twice was accepted")
	}
	if err.Error() != "10.7.0.0/24 is listed twice" {
		t.Errorf("error = %q, want it to name the repeated network", err)
	}
}

// A default route beside real networks is the ordinary way a server's own configuration
// says it carries everything, so it is accepted here even though it is not a route.
func TestACarriedListMaySayTheServerCarriesEverything(t *testing.T) {
	nets := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.7.0.0/24"),
	}

	if err := carriedNetworks(any(nets)); err != nil {
		t.Errorf("a configuration carrying everything was refused: %v", err)
	}
}

func TestAResolverListedTwiceIsRefused(t *testing.T) {
	resolvers := []netip.Addr{
		netip.MustParseAddr("10.7.0.1"),
		netip.MustParseAddr("10.7.0.1"),
	}

	err := reachableResolvers(any(resolvers))

	if err == nil {
		t.Fatal("the same resolver listed twice was accepted")
	}
	if err.Error() != "10.7.0.1 is listed twice" {
		t.Errorf("error = %q, want it to name the repeated resolver", err)
	}
}

func TestTwoDifferentResolversAreAccepted(t *testing.T) {
	resolvers := []netip.Addr{
		netip.MustParseAddr("10.7.0.1"),
		netip.MustParseAddr("10.7.0.2"),
	}

	if err := reachableResolvers(any(resolvers)); err != nil {
		t.Errorf("two different resolvers were refused: %v", err)
	}
}
