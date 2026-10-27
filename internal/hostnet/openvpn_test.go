// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A connection identifier becomes a file name under a directory the privileged side makes,
// so what it may contain is the point: anything carrying a separator, a traversal or a null
// byte is refused before it can be a path.
func TestAConnectionIdentifierCannotBeAPath(t *testing.T) {
	for _, id := range []string{"tn_a1b2c3", "primary", "A-B_9"} {
		if !validConnectionID(id) {
			t.Errorf("validConnectionID(%q) = false, want true", id)
		}
	}
	for _, id := range []string{"", "../etc/passwd", "a/b", `a\b`, "a b", "a.conf", "tn\x00", "..",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if validConnectionID(id) {
			t.Errorf("validConnectionID(%q) = true, want false", id)
		}
	}
}

// An algorithm name is written into a configuration file a root process reads back, so a
// value carrying a space or a newline would be a second directive rather than a name.
func TestAnAlgorithmNameCannotBecomeASecondDirective(t *testing.T) {
	for _, token := range []string{"AES-256-GCM", "SHA512", "BF-CBC", "aes_128_gcm"} {
		if !openvpnTokenShape(token) {
			t.Errorf("openvpnTokenShape(%q) = false, want true", token)
		}
	}
	for _, token := range []string{"", "AES-256-GCM\nup /tmp/x", "AES 256", "-leading", ".leading",
		"a\tb", "a\x00b", "aes;rm"} {
		if openvpnTokenShape(token) {
			t.Errorf("openvpnTokenShape(%q) = true, want false", token)
		}
	}
}

func TestAServerAddressIsAHostAndAPort(t *testing.T) {
	for _, tc := range []struct{ remote, host, port string }{
		{"vpn.example.com:1194", "vpn.example.com", "1194"},
		{"203.0.113.9:443", "203.0.113.9", "443"},
		{"[2001:db8::1]:1194", "2001:db8::1", "1194"},
		{"vpn_1.example.com.:65535", "vpn_1.example.com.", "65535"},
	} {
		host, port, err := openvpnRemote(tc.remote)
		if err != nil {
			t.Errorf("openvpnRemote(%q) failed: %v", tc.remote, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("openvpnRemote(%q) = %q, %q; want %q, %q", tc.remote, host, port, tc.host, tc.port)
		}
	}
	for _, remote := range []string{
		"", "vpn.example.com", "vpn.example.com:0", "vpn.example.com:65536", "vpn.example.com:https",
		"2001:db8::1:1194", "[2001:db8::1]1194", "vpn.example.com:1194 1195",
		"vpn.example.com\nremote evil.example.com:1194",
		"-vpn.example.com:1194", "vpn..example.com:1194",
	} {
		if _, _, err := openvpnRemote(remote); err == nil {
			t.Errorf("openvpnRemote(%q) was accepted, want a refusal", remote)
		}
	}
}

// netip accepts any bytes after the % of an IPv6 zone, newlines included, and the host is
// written into a configuration root's OpenVPN reads line by line.
func TestAServerAddressCannotCarryAZoneOrAControlCharacter(t *testing.T) {
	for _, remote := range []string{
		"[fe80::1%x\nup /tmp/e\n]:1194",
		"[fe80::1%en0]:1194",
		"[fe80::1%\x00]:1194",
		"[2001:db8::1\r]:1194",
		"vpn.example.com\t:1194",
	} {
		if _, _, err := openvpnRemote(remote); err == nil {
			t.Errorf("openvpnRemote(%q) was accepted, want a refusal", remote)
		}
	}
	if _, _, err := openvpnRemote("[fe80::1]:1194"); err != nil {
		t.Errorf("a link-local address without a zone was refused: %v", err)
	}
}

// The name is written as a quoted argument, so the two characters that would end the quoting
// are refused rather than escaped.
func TestACertificateNameCannotEndItsOwnQuoting(t *testing.T) {
	if err := validOpenVPNVerifyName("", "name"); err != nil {
		t.Errorf("an absent name was refused: %v", err)
	}
	if err := validOpenVPNVerifyName("server.example.com", ""); err != nil {
		t.Errorf("a plain name was refused: %v", err)
	}
	for _, name := range []string{`a" x`, `a\`, "a\nup /tmp/x", "a\x00"} {
		if err := validOpenVPNVerifyName(name, "name"); err == nil {
			t.Errorf("validOpenVPNVerifyName(%q) was accepted, want a refusal", name)
		}
	}
	if err := validOpenVPNVerifyName("server", "regex"); err == nil {
		t.Error("a match kind this side does not have was accepted, want a refusal")
	}
}

func TestARouteIsWrittenWithTheMaskOpenVPNTakes(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		mask   string
	}{
		{"10.0.0.0/8", "255.0.0.0"},
		{"192.168.1.0/24", "255.255.255.0"},
		{"203.0.113.7/32", "255.255.255.255"},
		{"10.1.0.0/12", "255.240.0.0"},
	} {
		got := maskOf(netip.MustParsePrefix(tc.prefix)).String()
		if got != tc.mask {
			t.Errorf("maskOf(%s) = %s, want %s", tc.prefix, got, tc.mask)
		}
	}
}

// The program this side runs as root is looked for in a fixed list, never on a path. A path
// search would let whatever wrote the environment choose what runs with administrator rights,
// which is the shape of problem this whole boundary exists to prevent.
func TestTheProgramIsLookedForInAFixedListRatherThanOnAPath(t *testing.T) {
	candidates := openvpnCandidates()
	if !OpenVPNSupported() {
		if len(candidates) != 0 {
			t.Errorf("a platform that runs no OpenVPN connection offers %v to run", candidates)
		}
		return
	}
	if len(candidates) == 0 {
		t.Fatal("a platform that runs OpenVPN connections has nowhere to look for the program")
	}
	for _, path := range candidates {
		if !filepath.IsAbs(path) {
			t.Errorf("%q is not an absolute path, so what runs would depend on the working directory", path)
		}
	}

	// Either this machine has one, or the refusal names where it looked -- which is the
	// difference between a reader who can install it and one staring at "not supported".
	binary, err := OpenVPNBinary()
	if err == nil {
		if !slices.Contains(candidates, binary) {
			t.Errorf("the program chosen (%q) is not one of the candidates %v", binary, candidates)
		}
		return
	}
	if !errors.Is(err, ErrNoOpenVPN) {
		t.Fatalf("err = %v, want it to report that no program was found", err)
	}
	if !strings.Contains(err.Error(), candidates[0]) {
		t.Errorf("err = %q, want it to name where it looked", err)
	}
}

// The interface name handed to openvpn is the platform's own, and it is never a caller's
// value: it is the one part of the rendered configuration that names a device on this machine.
func TestTheInterfaceNameIsThePlatformsOwn(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections")
	}
	device := openvpnDevice()
	if device == "" {
		t.Fatal("no interface name, so the rendered configuration would carry a bare dev line")
	}
	for _, r := range device {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		default:
			t.Errorf("the interface name %q carries %q, which would be a second word in the "+
				"configuration file", device, r)
		}
	}
}

// OpenVPN holds a session of its own. Folding it into the interface's would make an OpenVPN
// connection and the tailnet interface mutually exclusive, which is the opposite of what a
// client holding several private networks at once is for.
func TestAnOpenVPNConnectionAndTheInterfaceAreHeldSeparately(t *testing.T) {
	for _, op := range []string{opRunOpenVPN, opStopOpenVPN, opScopeOpenVPN, opUnscopeOpenVPN} {
		if got := needsSession(op); got != gateOpenVPN {
			t.Errorf("%s belongs to the %q session, want OpenVPN's", op, got)
		}
	}
	// The fabric's routing ops change this machine's interface, so they belong with the rest of
	// the interface's work rather than beside it. The copy of this machine's own default route
	// is one of them: it exists only while those ranges are installed, and is taken back when
	// the interface session ends.
	for _, op := range []string{opSetHostRoutes, opScopeHostDefault, opUnscopeHostDefault} {
		if got := needsSession(op); got != gateInterface {
			t.Errorf("%s belongs to the %q session, want the interface's", op, got)
		}
	}

	gate := newSessionGate(0)
	ctx := context.Background()
	if !gate.take(ctx, gateInterface) {
		t.Fatal("the interface session was refused to the first caller")
	}
	if !gate.take(ctx, gateOpenVPN) {
		t.Error("holding the interface session withheld OpenVPN's, so the tailnet interface and an " +
			"OpenVPN connection could not run at once")
	}
	if gate.take(ctx, gateOpenVPN) {
		t.Error("the OpenVPN session was handed to two callers at once")
	}
	gate.release(gateOpenVPN)
	if !gate.take(ctx, gateOpenVPN) {
		t.Error("the OpenVPN session was not handed on after its holder released it")
	}
}
