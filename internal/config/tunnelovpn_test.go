// SPDX-License-Identifier: MIT

package config

import (
	"net/netip"
	"strings"
	"testing"
)

// A connection with no OpenVPN block reads as a zero one rather than needing every caller to
// decide what a missing block means, and the first write creates it.
func TestAConnectionWithNoOpenVPNBlockReadsAsAnEmptyOne(t *testing.T) {
	var held Tunnel
	if got := held.OVPN(); got.Remote != "" || len(got.Routes) != 0 {
		t.Errorf("OVPN() = %+v, want the zero value", got)
	}
	held.ovpn().Remote = "vpn.example.com:1194"
	if held.OpenVPN == nil {
		t.Fatal("writing did not create the block")
	}
	if held.OVPN().Remote != "vpn.example.com:1194" {
		t.Errorf("remote = %q, want what was written", held.OVPN().Remote)
	}
}

// A copy shares no slice with the original, so editing one connection cannot change another
// that was cloned from it.
func TestACopySharesNoNetworksWithTheOriginal(t *testing.T) {
	held := OpenVPNTunnel{
		Routes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
		DNS:    []netip.Addr{netip.MustParseAddr("10.8.0.1")},
	}
	copied := held.clone()
	copied.Routes[0] = netip.MustParsePrefix("192.168.0.0/24")
	copied.DNS[0] = netip.MustParseAddr("192.168.0.1")

	if held.Routes[0] != netip.MustParsePrefix("10.8.0.0/16") {
		t.Errorf("the original's routes changed with the copy's: %v", held.Routes)
	}
	if held.DNS[0] != netip.MustParseAddr("10.8.0.1") {
		t.Errorf("the original's resolvers changed with the copy's: %v", held.DNS)
	}
}

// Every field the openvpn program is built from is compared. A field missed here is an edit
// that is saved, reported as applied, and never reaches the running connection -- so the test
// changes each field in turn rather than a representative few.
func TestChangingAnyFieldTheProgramIsBuiltFromMakesItADifferentConnection(t *testing.T) {
	base := OpenVPNTunnel{
		Remote: "vpn.example.com:1194", Proto: OpenVPNProtoUDP,
		CA: "ca", Cert: "cert", Key: "key", KeyPassphrase: "pass",
		TLSCrypt: "crypt", TLSAuth: "auth", KeyDirection: OpenVPNKeyDirectionClient,
		AuthUserPass: true, Username: "alice", Password: "s3cret",
		Cipher: "AES-256-GCM", Auth: "SHA512", VerifyServerCert: true,
		VerifyName: "vpn.example.com", VerifyNameType: OpenVPNVerifyName,
		Routes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
		DNS:    []netip.Addr{netip.MustParseAddr("10.8.0.1")},
		MTU:    1400,
	}
	if !base.SameAs(base.clone()) {
		t.Fatal("a connection is not the same as a copy of itself")
	}

	edits := map[string]func(*OpenVPNTunnel){
		"remote":           func(o *OpenVPNTunnel) { o.Remote = "other.example.com:1194" },
		"proto":            func(o *OpenVPNTunnel) { o.Proto = OpenVPNProtoTCP },
		"ca":               func(o *OpenVPNTunnel) { o.CA = "other" },
		"cert":             func(o *OpenVPNTunnel) { o.Cert = "other" },
		"key":              func(o *OpenVPNTunnel) { o.Key = "other" },
		"keyPassphrase":    func(o *OpenVPNTunnel) { o.KeyPassphrase = "other" },
		"tlsCrypt":         func(o *OpenVPNTunnel) { o.TLSCrypt = "other" },
		"tlsAuth":          func(o *OpenVPNTunnel) { o.TLSAuth = "other" },
		"keyDirection":     func(o *OpenVPNTunnel) { o.KeyDirection = OpenVPNKeyDirectionServer },
		"authUserPass":     func(o *OpenVPNTunnel) { o.AuthUserPass = false },
		"username":         func(o *OpenVPNTunnel) { o.Username = "bob" },
		"password":         func(o *OpenVPNTunnel) { o.Password = "other" },
		"cipher":           func(o *OpenVPNTunnel) { o.Cipher = "AES-128-GCM" },
		"auth":             func(o *OpenVPNTunnel) { o.Auth = "SHA256" },
		"verifyServerCert": func(o *OpenVPNTunnel) { o.VerifyServerCert = false },
		"verifyName":       func(o *OpenVPNTunnel) { o.VerifyName = "other.example.com" },
		"verifyNameType":   func(o *OpenVPNTunnel) { o.VerifyNameType = OpenVPNVerifySubject },
		"mtu":              func(o *OpenVPNTunnel) { o.MTU = 1500 },
		"routes":           func(o *OpenVPNTunnel) { o.Routes = append(o.Routes, netip.MustParsePrefix("10.9.0.0/16")) },
		"dns":              func(o *OpenVPNTunnel) { o.DNS = append(o.DNS, netip.MustParseAddr("10.8.0.2")) },
	}
	for field, edit := range edits {
		t.Run(field, func(t *testing.T) {
			edited := base.clone()
			edit(&edited)
			if base.SameAs(edited) {
				t.Errorf("changing %s left the connection reading as unchanged, so the edit would "+
					"be saved and never reach the running connection", field)
			}
		})
	}
}

// An unset transport reads as UDP, which is what an OpenVPN server runs unless somebody
// changed it, and two connections differing only in saying so out loud are the same.
func TestAnUnsetTransportReadsAsUDP(t *testing.T) {
	var unset OpenVPNTunnel
	if unset.EffectiveProto() != OpenVPNProtoUDP {
		t.Errorf("proto = %q, want udp", unset.EffectiveProto())
	}
	if !unset.SameAs(OpenVPNTunnel{Proto: OpenVPNProtoUDP}) {
		t.Error("a connection with no transport differs from one that says udp")
	}
	tcp := OpenVPNTunnel{Proto: OpenVPNProtoTCP}
	if tcp.EffectiveProto() != OpenVPNProtoTCP {
		t.Errorf("proto = %q, want tcp", tcp.EffectiveProto())
	}
}

// The networks reported as reached exclude a default route: it is the statement that
// everything leaves here, and reporting it as a network reached would have this connection
// claim every address in existence.
func TestTheNetworksReachedExcludeTheDefaultRoute(t *testing.T) {
	held := OpenVPNTunnel{Routes: []netip.Prefix{
		netip.MustParsePrefix("10.8.0.0/16"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}}
	carried := held.CarriedRoutes()
	if len(carried) != 1 || carried[0] != netip.MustParsePrefix("10.8.0.0/16") {
		t.Errorf("carried = %v, want only the network", carried)
	}
	if !held.CarriesDefault() {
		t.Error("a connection with a default route does not report that it carries everything")
	}
	if (OpenVPNTunnel{Routes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")}}).CarriesDefault() {
		t.Error("a connection with no default route reports that it carries everything")
	}
}

// An IPv6 default route counts as carrying everything too. Reading only the IPv4 one would
// have a connection configured to take all traffic report that it takes none.
func TestAnIPv6DefaultRouteAlsoCarriesEverything(t *testing.T) {
	held := OpenVPNTunnel{Routes: []netip.Prefix{netip.MustParsePrefix("::/0")}}
	if !held.CarriesDefault() {
		t.Error("an IPv6 default route does not report that the connection carries everything")
	}
	if len(held.CarriedRoutes()) != 0 {
		t.Errorf("carried = %v, want nothing", held.CarriedRoutes())
	}
}

// A name to check with no match written matches the whole subject, which is what openvpn
// itself does with a bare directive. A stored value that is not a match at all falls back to
// the same rather than being carried into a file.
func TestAnUnsetOrUnknownMatchChecksTheWholeSubject(t *testing.T) {
	for _, stored := range []string{OpenVPNVerifyNone, "nonsense"} {
		held := OpenVPNTunnel{VerifyName: "CN=vpn.example.com", VerifyNameType: stored}
		if got := held.EffectiveVerifyNameType(); got != OpenVPNVerifySubject {
			t.Errorf("with %q stored the match is %q, want %q", stored, got, OpenVPNVerifySubject)
		}
	}
	held := OpenVPNTunnel{VerifyNameType: OpenVPNVerifySubject}
	if held.EffectiveVerifyNameType() != OpenVPNVerifySubject {
		t.Errorf("match = %q, want the one that was stored", held.EffectiveVerifyNameType())
	}
}

// The server address is checked for shape rather than meaning: it ends up in a file a
// privileged process reads, so anything that could be a second directive is refused.
func TestTheServerAddressIsCheckedForShape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
		want string
	}{
		{"a name and a port", "vpn.example.com:1194", true, ""},
		{"an address and a port", "203.0.113.7:1194", true, ""},
		{"a bracketed IPv6 address", "[2001:db8::1]:1194", true, ""},
		{"a trailing dot", "vpn.example.com.:1194", true, ""},
		{"empty", "", false, "must not be empty"},
		{"no port", "vpn.example.com", false, "as host:port"},
		{"no server", ":1194", false, "must name the server before the port"},
		{"port zero", "vpn.example.com:0", false, "between 1 and 65535"},
		{"port past the end", "vpn.example.com:70000", false, "between 1 and 65535"},
		{"a port that is not a number", "vpn.example.com:https", false, "between 1 and 65535"},
		{"a line break in the name", "vpn.example.com\nup /tmp/x:1194", false, "as an address or a host name"},
		{"a space in the name", "vpn example.com:1194", false, "as an address or a host name"},
		{"a label starting with a hyphen", "-lab.example.com:1194", false, "as an address or a host name"},
		{"a name past the length a name can be", strings.Repeat("a.", 200) + "example.com:1194", false, "as an address or a host name"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ok, why := ValidOpenVPNRemote(test.in)
			if ok != test.ok {
				t.Fatalf("ValidOpenVPNRemote(%q) = %v %q, want %v", test.in, ok, why, test.ok)
			}
			if !ok && !strings.Contains(why, test.want) {
				t.Errorf("reason = %q, want it to say %q", why, test.want)
			}
		})
	}
}

// PEM material is re-encoded rather than copied, so anything pasted around the blocks is gone
// from what a privileged process will write rather than trusted to be harmless.
func TestPEMMaterialIsReEncodedRatherThanCopied(t *testing.T) {
	encoded, err := ParseOpenVPNPEM(`# issued by the lab
-----BEGIN CERTIFICATE-----
Zm9vYmFy
-----END CERTIFICATE-----
`)
	if err != nil {
		t.Fatalf("reading a certificate with a comment above it: %v", err)
	}
	if strings.Contains(encoded, "issued by the lab") {
		t.Errorf("what was pasted around the block survived: %q", encoded)
	}
	if !strings.HasPrefix(encoded, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("encoded = %q, want it to begin with the block's own header", encoded)
	}

	twice, err := ParseOpenVPNPEM(encoded + encoded)
	if err != nil {
		t.Fatalf("reading a chain of two blocks: %v", err)
	}
	if strings.Count(twice, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("a chain lost a block: %q", twice)
	}
}

// What is refused, and why. Each of these is a paste that went wrong rather than material
// anybody holds, and each says which.
func TestMaterialThatIsNotPEMIsRefused(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "   \n ", "must not be empty"},
		{"not a block at all", "just some text", "must be a PEM block"},
		{"a directive after the block", "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\nup /tmp/x\n", "after the last PEM block"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseOpenVPNPEM(test.in)
			if err == nil {
				t.Fatal("the material was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to say %q", err, test.want)
			}
		})
	}
}

// A static key comes back as a header, hex lines and a footer, with the case normalised, so
// nothing pasted around it reaches the file.
func TestAStaticKeyIsStoredCanonically(t *testing.T) {
	encoded, err := ParseOpenVPNStaticKey(`#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
0123456789ABCDEF0123456789ABCDEF
FEDCBA9876543210FEDCBA9876543210
-----END OpenVPN Static key V1-----
`)
	if err != nil {
		t.Fatalf("reading a static key: %v", err)
	}
	want := "-----BEGIN OpenVPN Static key V1-----\n" +
		"0123456789abcdef0123456789abcdef\nfedcba9876543210fedcba9876543210\n" +
		"-----END OpenVPN Static key V1-----\n"
	if encoded != want {
		t.Errorf("encoded = %q, want %q", encoded, want)
	}
}

// What a static key is refused for. Each is a paste that went wrong, and each says which.
func TestMaterialThatIsNotAStaticKeyIsRefused(t *testing.T) {
	const header = "-----BEGIN OpenVPN Static key V1-----"
	const footer = "-----END OpenVPN Static key V1-----"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "  ", "must not be empty"},
		{"no header", "0123456789abcdef\n" + footer, "must begin with"},
		{"no footer", header + "\n0123456789abcdef", "must end with"},
		{"nothing between", header + "\n" + footer, "no key material"},
		{"two keys", header + "\n0123456789abcdef\n" + footer + "\n" + header + "\n0123456789abcdef\n" + footer, "more than one key"},
		{"material after the end", header + "\n0123456789abcdef\n" + footer + "\n0123456789abcdef", "after the -----END line"},
		{"a directive in the middle", header + "\nup /tmp/x\n" + footer, "neither the key's own wrapper nor hexadecimal"},
		{"an odd number of digits", header + "\n0123456789abcde\n" + footer, "neither the key's own wrapper nor hexadecimal"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseOpenVPNStaticKey(test.in)
			if err == nil {
				t.Fatal("the material was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to say %q", err, test.want)
			}
		})
	}
}

// A credential crosses the management interface, where a line is a message, so one carrying a
// line break would be read as the next command.
func TestACredentialCarryingALineBreakIsRefused(t *testing.T) {
	if ok, _ := ValidOpenVPNCredential("s3cret"); !ok {
		t.Error("an ordinary password was refused")
	}
	for _, bad := range []string{"a\nhold release", "a\rb", "a\x00b"} {
		ok, why := ValidOpenVPNCredential(bad)
		if ok {
			t.Errorf("%q was accepted, and it would be read as a second command", bad)
		}
		if !strings.Contains(why, "line break") {
			t.Errorf("reason = %q, want it to say the value has a line break", why)
		}
	}
	ok, why := ValidOpenVPNCredential(strings.Repeat("a", MaxOpenVPNCredentialLen+1))
	if ok || !strings.Contains(why, "at most") {
		t.Errorf("a credential past the limit = %v %q, want a refusal naming the limit", ok, why)
	}
}

// The registry's validators accept an empty value -- a connection is added before it is
// configured -- and otherwise apply the checks above.
func TestTheStoredFieldValidatorsAcceptAnEmptyValueAndCheckTheRest(t *testing.T) {
	cases := []struct {
		name  string
		check func(any) error
		empty any
		good  any
		bad   any
	}{
		{"remote", optionalOpenVPNRemote, "", "vpn.example.com:1194", "vpn.example.com"},
		{"pem", optionalOpenVPNPEM, "", "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n", "not a block"},
		{
			"static key", optionalOpenVPNStaticKey, "",
			"-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef\n-----END OpenVPN Static key V1-----\n",
			"not a key",
		},
		{"algorithm name", optionalOpenVPNToken, "", "AES-256-GCM", "AES 256 GCM"},
		{"credential", openVPNCredential, "", "s3cret", "a\nb"},
		{"certificate name", openVPNVerifyName, "", "vpn.example.com", "vpn\"example.com"},
		{"mtu", openVPNMTU, 0, 1400, 99},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.check(test.empty); err != nil {
				t.Errorf("an unconfigured connection's %s was refused: %v", test.name, err)
			}
			if err := test.check(test.good); err != nil {
				t.Errorf("a valid %s was refused: %v", test.name, err)
			}
			if err := test.check(test.bad); err == nil {
				t.Errorf("%v was accepted as a %s", test.bad, test.name)
			}
		})
	}
}

// The name checked against a server's certificate is written into the file as a quoted
// argument, so the two characters that would end the quoting are refused outright.
func TestACertificateNameThatWouldEndItsOwnQuotingIsRefused(t *testing.T) {
	for _, bad := range []string{`vpn"example.com`, `vpn\example.com`} {
		err := openVPNVerifyName(bad)
		if err == nil {
			t.Fatalf("%q was accepted, and it would end the quoting around itself", bad)
		}
		if !strings.Contains(err.Error(), "quotation mark or a backslash") {
			t.Errorf("error = %q, want it to name the characters", err)
		}
	}
	if err := openVPNVerifyName("vpn\nexample.com"); err == nil ||
		!strings.Contains(err.Error(), "line break") {
		t.Errorf("a name with a line break in it = %v, want a refusal naming the line break", err)
	}
	if err := openVPNVerifyName(strings.Repeat("a", 257)); err == nil ||
		!strings.Contains(err.Error(), "at most 256") {
		t.Errorf("a name past the limit = %v, want a refusal naming the limit", err)
	}
}
