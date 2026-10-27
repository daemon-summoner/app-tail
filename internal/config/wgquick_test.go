// SPDX-License-Identifier: MIT

package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The file a WireGuard server's administrator actually hands out, with everything in it.
const wgQuickSample = `# office gateway, issued 2026-01-04
[Interface]
PrivateKey = aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=
Address = 10.7.0.4/24, fd00:7::4/64
DNS = 10.7.0.1, 10.7.0.2
MTU = 1380

[Peer]
PublicKey = vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=
PresharedKey = Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE=
AllowedIPs = 10.7.0.0/24, fd00:7::/64
Endpoint = gateway.example.com:51820
PersistentKeepalive = 25
`

// Every value in the file has to arrive: a connection built from a file with one setting
// missing is a connection running on a default nobody chose, and there is nothing on screen
// that would say which one.
func TestEveryValueInTheServersFileReachesTheConnection(t *testing.T) {
	held, err := ParseWireGuardQuick(wgQuickSample)
	if err != nil {
		t.Fatalf("reading a complete configuration failed: %v", err)
	}

	if held.PrivateKey != "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=" {
		t.Errorf("the private key is %q", held.PrivateKey)
	}
	wantAddrs := []netip.Prefix{
		netip.MustParsePrefix("10.7.0.4/24"),
		netip.MustParsePrefix("fd00:7::4/64"),
	}
	if !slices.Equal(held.Addresses, wantAddrs) {
		t.Errorf("the addresses are %v, want %v", held.Addresses, wantAddrs)
	}
	wantDNS := []netip.Addr{netip.MustParseAddr("10.7.0.1"), netip.MustParseAddr("10.7.0.2")}
	if !slices.Equal(held.DNS, wantDNS) {
		t.Errorf("the resolvers are %v, want %v", held.DNS, wantDNS)
	}
	if held.MTU != 1380 {
		t.Errorf("the MTU is %d, want 1380", held.MTU)
	}
	if held.Peer.PublicKey != "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=" {
		t.Errorf("the server's key is %q", held.Peer.PublicKey)
	}
	if held.Peer.PresharedKey != "Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE=" {
		t.Errorf("the pre-shared key is %q", held.Peer.PresharedKey)
	}
	if held.Peer.Endpoint != "gateway.example.com:51820" {
		t.Errorf("the server address is %q", held.Peer.Endpoint)
	}
	wantCarried := []netip.Prefix{
		netip.MustParsePrefix("10.7.0.0/24"),
		netip.MustParsePrefix("fd00:7::/64"),
	}
	if !slices.Equal(held.Peer.AllowedIPs, wantCarried) {
		t.Errorf("the carried networks are %v, want %v", held.Peer.AllowedIPs, wantCarried)
	}
	if held.Peer.KeepaliveSec != 25 {
		t.Errorf("the keepalive is %d, want 25", held.Peer.KeepaliveSec)
	}
}

// Each of these does something real to the machine the connection runs on. Dropping one
// silently would produce a connection that looks like the one the file describes and does
// less -- a missing firewall rule nobody goes looking for. Every one must be named.
func TestADirectiveThatWouldActOnThisMachineIsRefusedByName(t *testing.T) {
	cases := []struct {
		directive string
		line      string
	}{
		{"PostUp", "PostUp = iptables -A FORWARD -i %i -j ACCEPT"},
		{"PreUp", "PreUp = echo starting"},
		{"PostDown", "PostDown = iptables -D FORWARD -i %i -j ACCEPT"},
		{"PreDown", "PreDown = echo stopping"},
		{"Table", "Table = 51820"},
		{"SaveConfig", "SaveConfig = true"},
		{"FwMark", "FwMark = 0xca6c"},
		{"ListenPort", "ListenPort = 51820"},
	}
	for _, tc := range cases {
		t.Run(tc.directive, func(t *testing.T) {
			text := strings.Replace(wgQuickSample, "MTU = 1380", "MTU = 1380\n"+tc.line, 1)
			held, err := ParseWireGuardQuick(text)
			if err == nil {
				t.Fatalf("a file carrying %s was imported anyway as %+v", tc.directive, held)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.directive)) {
				t.Errorf("the refusal is %q, which does not name %s", err, tc.directive)
			}
		})
	}
}

// One connection dials one server. A file describing several is a mesh or a server's own
// configuration, and importing the first peer silently would leave the rest of the network
// unreachable with nothing saying so.
func TestAFileDescribingSeveralServersIsRefused(t *testing.T) {
	text := wgQuickSample + `
[Peer]
PublicKey = Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE=
AllowedIPs = 10.8.0.0/24
Endpoint = other.example.com:51820
`
	_, err := ParseWireGuardQuick(text)
	if err == nil {
		t.Fatal("a file describing two servers was imported")
	}
	if !strings.Contains(err.Error(), "own connection") {
		t.Errorf("the refusal is %q, which does not say what to do instead", err)
	}
}

// Each of these is a file that would import and then produce a connection that cannot work,
// failing when it is switched on rather than when it is pasted. Naming what is missing at
// import is the difference between a typo and a support call.
func TestAFileMissingSomethingTheConnectionNeedsIsRefusedByName(t *testing.T) {
	cases := []struct {
		name   string
		remove string
		want   string
	}{
		{"no private key", "PrivateKey = aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=", "PrivateKey"},
		{"no address", "Address = 10.7.0.4/24, fd00:7::4/64", "Address"},
		{"no server key", "PublicKey = vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=", "PublicKey"},
		{"no server address", "Endpoint = gateway.example.com:51820", "Endpoint"},
		{"nothing to carry", "AllowedIPs = 10.7.0.0/24, fd00:7::/64", "AllowedIPs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.Replace(wgQuickSample, tc.remove, "", 1)
			held, err := ParseWireGuardQuick(text)
			if err == nil {
				t.Fatalf("a file with %s was imported anyway as %+v", tc.name, held)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal is %q, which does not name %s", err, tc.want)
			}
		})
	}
}

// A file with no [Peer] section names no server. It is the shape a half-pasted file takes
// -- the [Interface] half copied and the rest missed -- so it is named rather than saved as
// a connection with nothing to dial.
func TestAFileNamingNoServerIsRefused(t *testing.T) {
	interfaceOnly, _, found := strings.Cut(wgQuickSample, "[Peer]")
	if !found {
		t.Fatal("the sample file has no [Peer] section to cut")
	}

	held, err := ParseWireGuardQuick(interfaceOnly)

	if err == nil {
		t.Fatalf("a file with no server was imported anyway as %+v", held)
	}
	if !strings.Contains(err.Error(), "[Peer]") {
		t.Errorf("the refusal is %q, which does not say the [Peer] section is missing", err)
	}
}

// A setting before any section heading belongs to nothing. Guessing a section for it would
// store a value under whichever one the guess picked.
func TestASettingBelongingToNoSectionIsRefused(t *testing.T) {
	held, err := ParseWireGuardQuick("MTU = 1380\n" + wgQuickSample)

	if err == nil {
		t.Fatalf("a setting outside every section was imported anyway as %+v", held)
	}
	if !strings.Contains(err.Error(), "before any") {
		t.Errorf("the refusal is %q, which does not say the setting comes before any section", err)
	}
}

// A value that is wrong is refused where it is, with the line it is on: a file is pasted
// whole, so "line 6" is the only thing that turns a refusal into something to go and fix.
func TestAValueThatIsWrongIsRefusedAtItsLine(t *testing.T) {
	cases := []struct {
		name    string
		replace string
		with    string
		want    string
	}{
		{"a key that is not a key", "PrivateKey = aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=", "PrivateKey = hunter2", "PrivateKey"},
		{"an address with no network", "Address = 10.7.0.4/24, fd00:7::4/64", "Address = office", "Address"},
		{"a resolver that is a domain", "DNS = 10.7.0.1, 10.7.0.2", "DNS = corp.example.com", "search domains"},
		{"an MTU below the IPv6 minimum", "MTU = 1380", "MTU = 576", "1280"},
		{"a server address with no port", "Endpoint = gateway.example.com:51820", "Endpoint = gateway.example.com", "Endpoint"},
		{"a carried network that is an address", "AllowedIPs = 10.7.0.0/24, fd00:7::/64", "AllowedIPs = 10.7.0.5", "AllowedIPs"},
		{"a keepalive that is not a number", "PersistentKeepalive = 25", "PersistentKeepalive = often", "PersistentKeepalive"},
		{"a setting that does not exist", "MTU = 1380", "Compression = yes", "Interface"},
		{"a section that does not exist", "[Peer]", "[Server]", "Server"},
		{"a line that is not a setting at all", "MTU = 1380", "MTU", "not a setting and a value"},
		{"a server key that is not a key", "PublicKey = vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=", "PublicKey = hunter2", "PublicKey"},
		{"a pre-shared key that is not a key", "PresharedKey = Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE=", "PresharedKey = hunter2", "PresharedKey"},
		{"an MTU that is not a number", "MTU = 1380", "MTU = large", "MTU must be a number"},
		{"a keepalive longer than the protocol carries", "PersistentKeepalive = 25", "PersistentKeepalive = 70000", "between 0 and 65535"},
		{"a server setting that does not exist", "AllowedIPs = 10.7.0.0/24, fd00:7::/64", "Compression = yes", "Peer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.Replace(wgQuickSample, tc.replace, tc.with, 1)
			held, err := ParseWireGuardQuick(text)
			if err == nil {
				t.Fatalf("a file with %s was imported anyway as %+v", tc.name, held)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal is %q, which does not say %q", err, tc.want)
			}
			if !strings.HasPrefix(err.Error(), "line ") {
				t.Errorf("the refusal is %q, which does not say which line to look at", err)
			}
		})
	}
}

// The forms the same file takes in the wild: wg-quick reads its settings without regard to
// case, a QR code round-trips through tools that reflow it, and a Windows client writes
// carriage returns. Refusing any of these would refuse a file that works everywhere else.
func TestTheFileIsReadTheWayEveryOtherWireGuardToolReadsIt(t *testing.T) {
	held, err := ParseWireGuardQuick(wgQuickSample)
	if err != nil {
		t.Fatalf("reading the plain form failed: %v", err)
	}

	variants := map[string]string{
		"lower case settings":  strings.ReplaceAll(wgQuickSample, "PrivateKey", "privatekey"),
		"carriage returns":     strings.ReplaceAll(wgQuickSample, "\n", "\r\n"),
		"indented settings":    strings.ReplaceAll(wgQuickSample, "MTU", "   MTU"),
		"a trailing comment":   strings.Replace(wgQuickSample, "MTU = 1380", "MTU = 1380  # small link", 1),
		"blank lines anywhere": strings.ReplaceAll(wgQuickSample, "\n", "\n\n"),
	}
	for name, text := range variants {
		t.Run(name, func(t *testing.T) {
			got, err := ParseWireGuardQuick(text)
			if err != nil {
				t.Fatalf("reading it failed: %v", err)
			}
			if got.PrivateKey != held.PrivateKey || got.MTU != held.MTU ||
				got.Peer.Endpoint != held.Peer.Endpoint ||
				!slices.Equal(got.Addresses, held.Addresses) {
				t.Errorf("it read as %+v, want the same connection as the plain form", got)
			}
		})
	}
}

// wg-quick writes "off" rather than 0 for a connection that sends nothing when idle, and a
// number read out of that word would be a keepalive nobody asked for.
func TestAKeepaliveWrittenAsOffIsNone(t *testing.T) {
	text := strings.Replace(wgQuickSample, "PersistentKeepalive = 25", "PersistentKeepalive = off", 1)
	held, err := ParseWireGuardQuick(text)
	if err != nil {
		t.Fatalf("reading a configuration with the keepalive off failed: %v", err)
	}
	if held.Peer.KeepaliveSec != 0 {
		t.Errorf("the keepalive is %d, want none", held.Peer.KeepaliveSec)
	}
}

// A bare address in the Address line means this device alone in its network, which is what
// several servers issue and what wg(8) itself writes.
func TestAnAddressWithNoNetworkSizeIsThisDeviceAlone(t *testing.T) {
	text := strings.Replace(wgQuickSample, "Address = 10.7.0.4/24, fd00:7::4/64", "Address = 10.7.0.4", 1)
	held, err := ParseWireGuardQuick(text)
	if err != nil {
		t.Fatalf("reading a configuration with a bare address failed: %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.7.0.4/32")}
	if !slices.Equal(held.Addresses, want) {
		t.Errorf("the addresses are %v, want %v", held.Addresses, want)
	}
}
