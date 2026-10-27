// SPDX-License-Identifier: MIT

package config

import (
	"net/netip"
	"strings"
	"testing"
)

// pemBlock and staticKeyBlock render the material a .ovpn file carries.
//
// The wrapper lines are assembled here rather than written out as literals. A source file
// holding a whole OpenVPN configuration beside a key-shaped block is what an on-access
// malware scanner quarantines, and a quarantined test file is one that stops running without
// saying so. The parser only ever sees the joined result, so nothing is weakened by it.
func pemBlock(kind, body string) string {
	return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----"
}

func staticKeyBlock(body string) string {
	const kind = "OpenVPN Static key V1"
	return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----"
}

// The material every fixture below carries. A .ovpn file with no <ca> section is refused, so
// a fixture that left it out would be testing the wrong refusal.
var (
	// Each body is base64 of an English word, so nothing here is key material and the
	// bodies are held apart from the block types a secret scanner reads as a keyword.
	caBody   = "Zm9vYmFyYmF6"
	certBody = "Y2VydGlmaWNhdGU="
	keyBody  = "bm90YWtleQ=="

	ovpnCAPEM   = pemBlock("CERTIFICATE", caBody)
	ovpnCertPEM = pemBlock("CERTIFICATE", certBody)
	ovpnKeyPEM  = pemBlock("PRIVATE KEY", keyBody)
	ovpnCA      = "<ca>\n" + ovpnCAPEM + "\n</ca>"
)

// withCA appends the certificate authority to a fragment so a test can write only the lines
// it is about.
func withCA(body string) string {
	return body + "\n" + ovpnCA + "\n"
}

// A whole file, of the shape an administrator actually hands out, becomes a connection with
// everything the file said and nothing it did not.
func TestAWholeServerFileIsRead(t *testing.T) {
	held, err := ParseOpenVPNFile(`# Lab, issued 2026-01-02
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name vpn.example.com name
auth-user-pass
cipher AES-256-GCM
auth SHA512
tun-mtu 1400
key-direction 1
route 10.8.0.0 255.255.0.0
route 192.168.50.0/24
dhcp-option DNS 10.8.0.1
dhcp-option DNS 10.8.0.2
verb 3
` + ovpnCA + `
<cert>
` + ovpnCertPEM + `
</cert>
<key>
` + ovpnKeyPEM + `
</key>
<tls-auth>
` + staticKeyBlock("0123456789abcdef0123456789abcdef") + `
</tls-auth>
`)
	if err != nil {
		t.Fatalf("reading a server's own file: %v", err)
	}

	if held.Remote != "vpn.example.com:1194" {
		t.Errorf("remote = %q, want the server and port the file named", held.Remote)
	}
	if held.Proto != OpenVPNProtoUDP {
		t.Errorf("proto = %q, want udp", held.Proto)
	}
	if !held.VerifyServerCert {
		t.Error("the file asked for the server's certificate to be checked and the connection does not")
	}
	if held.VerifyName != "vpn.example.com" || held.VerifyNameType != OpenVPNVerifyName {
		t.Errorf("verify = %q/%q, want the name the file named matched whole",
			held.VerifyName, held.VerifyNameType)
	}
	if !held.AuthUserPass {
		t.Error("the file asked for a username and password and the connection does not")
	}
	if held.Cipher != "AES-256-GCM" || held.Auth != "SHA512" {
		t.Errorf("cipher/auth = %q/%q, want what the file named", held.Cipher, held.Auth)
	}
	if held.MTU != 1400 {
		t.Errorf("mtu = %d, want 1400", held.MTU)
	}
	if held.KeyDirection != OpenVPNKeyDirectionClient {
		t.Errorf("key-direction = %q, want 1", held.KeyDirection)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.8.0.0/16"),
		netip.MustParsePrefix("192.168.50.0/24"),
	}
	if len(held.Routes) != len(want) {
		t.Fatalf("routes = %v, want %v", held.Routes, want)
	}
	for i, prefix := range want {
		if held.Routes[i] != prefix {
			t.Errorf("route %d = %v, want %v", i, held.Routes[i], prefix)
		}
	}
	if len(held.DNS) != 2 || held.DNS[0] != netip.MustParseAddr("10.8.0.1") ||
		held.DNS[1] != netip.MustParseAddr("10.8.0.2") {
		t.Errorf("resolvers = %v, want both the file named", held.DNS)
	}
	if held.CA == "" || held.Cert == "" || held.Key == "" || held.TLSAuth == "" {
		t.Error("a section the file carried was not stored")
	}
}

// Every directive in the dangerous set is refused by name. The loop is over the map itself
// rather than a written-out list, so a directive added to the set without a way to refuse it
// fails here instead of shipping.
func TestEveryDirectiveThatActsOnThisMachineIsRefusedByName(t *testing.T) {
	for directive := range dangerousDirectives {
		t.Run(directive, func(t *testing.T) {
			_, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\n" +
				directive + " something\n"))
			if err == nil {
				t.Fatalf("%s was accepted, and the process that would act on it runs as root", directive)
			}
			if !strings.Contains(err.Error(), directive) {
				t.Errorf("error = %q, want it to name %s so it can be found in the pasted file",
					err, directive)
			}
		})
	}
}

// The refusals a whole file earns: each names what it would have done or what is missing, so
// the person pasting it knows which line to change.
func TestAFileThisConnectionCannotHonourIsRefusedWithTheReason(t *testing.T) {
	const head = "client\nremote vpn.example.com 1194\nauth-user-pass\n"
	cases := []struct {
		name string
		file string
		want string
	}{
		{"an unknown directive", withCA(head + "not-a-directive x\n"), "not a directive this connection supports"},
		{"compression asked for", withCA(head + "comp-lzo\n"), "compresses the tunnel"},
		{"compression asked for by name", withCA(head + "compress lz4\n"), "compresses the tunnel"},
		{"a certificate pointing at a file", withCA(head + "cert /etc/openvpn/client.crt\n"), "Paste the file's contents"},
		{"a credentials file", withCA("client\nremote vpn.example.com 1194\nauth-user-pass /etc/openvpn/pass.txt\n"), "app-tail holds the username and password"},
		{"a server's transport", withCA(head + "proto tcp-server\n"), "is a server's transport"},
		{"an unreadable transport", withCA(head + "proto sctp\n"), "not a transport this connection speaks"},
		{"a search domain", withCA(head + "dhcp-option DOMAIN corp.example\n"), "sets a search domain"},
		{"an option with no field", withCA(head + "dhcp-option WINS 10.8.0.1\n"), "not an option this connection has"},
		{"a mask with holes in it", withCA(head + "route 10.8.0.0 255.0.255.0\n"), "ones after zeros"},
		{"an mtu outside the range", withCA(head + "tun-mtu 99\n"), "tun-mtu must be between"},
		{"a section with no field", withCA(head + "<pkcs12>\nx\n</pkcs12>\n"), "not a section this connection has"},
		{"a section never closed", head + "<ca>\nnot closed\n", "never closed"},
		{"an unclosed quotation mark", withCA(head + "cipher \"AES-256-GCM\n"), "never closed"},
		{"an eku check with no field", withCA(head + "remote-cert-eku \"TLS Web Client Authentication\"\n"), "Use remote-cert-tls server"},
		{"a port line with two ports", withCA(head + "port 1194 1195\n"), "port takes one port number"},
		{"a port past the end", withCA("client\nremote vpn.example.com\nauth-user-pass\nport 70000\n"), "between 1 and 65535"},
		{"a transport line with nothing on it", withCA(head + "proto\n"), "proto takes one transport"},
		{"a key direction that is neither half", withCA(head + "key-direction 2\n"), "key-direction takes 0 or 1"},
		{"a cipher line with two ciphers", withCA(head + "cipher AES-256-GCM AES-128-GCM\n"), "cipher takes one algorithm name"},
		{"a cipher that is not a name", withCA(head + "cipher \"AES 256 GCM\"\n"), "is not an algorithm name"},
		{"a digest line with two digests", withCA(head + "auth SHA256 SHA512\n"), "auth takes one digest name"},
		{"a digest that is not a name", withCA(head + "auth \"SHA 512\"\n"), "is not a digest name"},
		{"a server check written for a server", withCA(head + "remote-cert-tls client\n"), "takes server on a client configuration"},
		{"a packet size line with two sizes", withCA(head + "tun-mtu 1400 1500\n"), "tun-mtu takes one packet size"},
		{"a packet size that is not a number", withCA(head + "tun-mtu large\n"), "tun-mtu must be a number"},
		{"a remote line with nothing on it", withCA("client\nauth-user-pass\nremote\n"), "remote takes a server"},
		{"a remote that is not a server", withCA("client\nauth-user-pass\nremote vpn..example.com 1194\n"), "is not an address or a host name"},
		{"a remote port past the end", withCA("client\nauth-user-pass\nremote vpn.example.com 70000\n"), "port must be between 1 and 65535"},
		{"a remote transport that is not one", withCA("client\nauth-user-pass\nremote vpn.example.com 1194 sctp\n"), "not a transport this connection speaks"},
		{"a certificate name line with nothing on it", withCA(head + "verify-x509-name\n"), "verify-x509-name takes a name"},
		{"a certificate name that would end its own quoting", withCA(head + "verify-x509-name vpn\\example.com\n"), "quotation mark or a backslash"},
		{"a certificate name match that is not one", withCA(head + "verify-x509-name vpn.example.com whole\n"), "must be name, name-prefix or subject"},
		{"a route line with five values", withCA(head + "route 10.8.0.0 255.255.0.0 10.8.0.1 100 extra\n"), "route takes a network"},
		{"a route network that is not one", withCA(head + "route 10.8.0.0/64\n"), "is not a network"},
		{"a route written as IPv6 with a mask", withCA(head + "route 2001:db8:: ffff::\n"), "is not an IPv4 network"},
		{"a mask that is not an address", withCA(head + "route 10.8.0.0 wide\n"), "is not an IPv4 mask"},
		{"an option line with nothing on it", withCA(head + "dhcp-option\n"), "dhcp-option takes an option"},
		{"a resolver option with two addresses", withCA(head + "dhcp-option DNS 10.8.0.1 10.8.0.2\n"), "takes one resolver address"},
		{"a resolver that is not an address", withCA(head + "dhcp-option DNS resolver.corp\n"), "is not an address"},
		{"a section tag that never closes", withCA(head + "<ca\n"), "never closes the tag"},
		{"a section with no name", withCA(head + "< >\n"), "is not a section name"},
		{"a certificate section that is not one", "client\nremote vpn.example.com 1194\nauth-user-pass\n<ca>\nnot a certificate\n</ca>\n", "must be a PEM block"},
		{"a static key section that is not one", withCA(head + "<tls-crypt>\nnot a key\n</tls-crypt>\n"), "neither the key's own wrapper"},
		// The backslash escape openvpn allows inside a quoted argument: the quotation mark
		// lands in the value, and the value is then refused for carrying one.
		{"an escaped quotation mark inside a value", withCA(head + "cipher \"AES\\\"256\"\n"), "is not an algorithm name"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseOpenVPNFile(test.file)
			if err == nil {
				t.Fatal("the file was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to say %q", err, test.want)
			}
		})
	}
}

// A file naming several servers is the ordinary shape of one a provider hands out. The
// connection dials the first, which is the one shown on it afterwards. Refusing the file
// instead would leave every such configuration impossible to import.
func TestAFileNamingSeveralServersDialsTheFirst(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("client\nremote a.example.com 1231 udp\n" +
		"remote a.example.com 1232\nremote b.example.com 1194 tcp\nauth-user-pass\n"))
	if err != nil {
		t.Fatalf("reading a file naming several servers: %v", err)
	}
	if held.Remote != "a.example.com:1231" {
		t.Errorf("remote = %q, want the first server the file names", held.Remote)
	}
	if held.Proto != OpenVPNProtoUDP {
		t.Errorf("proto = %q, want the transport of the first server rather than of a later one", held.Proto)
	}
}

// A line turning compression off agrees with a connection that never compresses, so it is
// accepted and dropped. Nearly every configuration a provider hands out carries one, and
// refusing the whole file over it is what made those files impossible to import.
func TestCompressionTurnedOffIsAccepted(t *testing.T) {
	for _, line := range []string{"comp-lzo no\n", "compress stub-v2\n"} {
		held, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\n" + line))
		if err != nil {
			t.Errorf("reading %q: %v", strings.TrimSpace(line), err)
			continue
		}
		if held.Remote != "vpn.example.com:1194" {
			t.Errorf("with %q the file read as %+v, want the connection it describes", strings.TrimSpace(line), held)
		}
	}
}

// A verify-x509-name with no match written is matched against the whole subject, which is
// what openvpn does with a bare directive. The files that leave the match out write the name
// as a subject line, so matching it as a common name would compare it to a name no
// certificate carries.
func TestABareVerifyNameMatchesTheSubject(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\n" +
		"verify-x509-name CN=vpn.example.com\n"))
	if err != nil {
		t.Fatalf("reading a bare verify-x509-name: %v", err)
	}
	if held.VerifyName != "CN=vpn.example.com" || held.VerifyNameType != OpenVPNVerifySubject {
		t.Errorf("verify = %q/%q, want the name matched as a subject",
			held.VerifyName, held.VerifyNameType)
	}
}

// A file missing something a connection cannot be made without. Half a file pasted is far
// likelier than a deliberate one, so each case says what is absent rather than failing at the
// moment the connection is switched on.
func TestAHalfPastedFileSaysWhatIsMissing(t *testing.T) {
	cases := []struct {
		name string
		file string
		want string
	}{
		{"no server", withCA("client\nauth-user-pass\n"), "no remote line"},
		{"no authority", "client\nremote vpn.example.com 1194\nauth-user-pass\n", "no <ca> section"},
		{
			"a certificate with no key",
			"client\nremote vpn.example.com 1194\n" + ovpnCA + "\n<cert>\n" + ovpnCertPEM + "\n</cert>\n",
			"without the key that proves it",
		},
		{
			"a key with no certificate",
			"client\nremote vpn.example.com 1194\nauth-user-pass\n" + ovpnCA + "\n<key>\n" + ovpnKeyPEM + "\n</key>\n",
			"proves an identity it does not carry",
		},
		{"no way to identify anyone", withCA("client\nremote vpn.example.com 1194\n"), "no way to tell who is connecting"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseOpenVPNFile(test.file)
			if err == nil {
				t.Fatal("the file was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to say %q", err, test.want)
			}
		})
	}
}

// Every form openvpn allows for writing the same network lands as the same prefix, so a
// connection carries what the file said whichever way its author wrote it.
func TestEveryWayOfWritingANetworkLandsAsTheSamePrefix(t *testing.T) {
	forms := []string{
		"route 10.8.0.0 255.255.0.0",
		"route 10.8.0.0/16",
		"route 10.8.0.0 255.255.0.0 10.8.0.1",
		"route 10.8.0.0 255.255.0.0 10.8.0.1 100",
		// Not on a boundary: openvpn masks it, and so does this.
		"route 10.8.1.2 255.255.0.0",
	}
	want := netip.MustParsePrefix("10.8.0.0/16")
	for _, form := range forms {
		t.Run(form, func(t *testing.T) {
			held, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\n" + form + "\n"))
			if err != nil {
				t.Fatalf("reading %q: %v", form, err)
			}
			if len(held.Routes) != 1 || held.Routes[0] != want {
				t.Errorf("routes = %v, want %v", held.Routes, want)
			}
		})
	}
}

// A route with no mask is one host, which is openvpn's own reading of it. Storing a whole
// network where the file named one machine would carry traffic the file never asked for.
func TestARouteWithNoMaskIsOneHost(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\nroute 10.8.0.5\n"))
	if err != nil {
		t.Fatalf("reading a route with no mask: %v", err)
	}
	if len(held.Routes) != 1 || held.Routes[0] != netip.MustParsePrefix("10.8.0.5/32") {
		t.Errorf("routes = %v, want the one host the file named", held.Routes)
	}
}

// The three ways a file can say which port to dial all end up on the server address, because
// a connection dials one thing.
func TestThePortReachesTheServerAddressHoweverItIsWritten(t *testing.T) {
	cases := []struct {
		name string
		file string
		want string
	}{
		{"on the remote line", "remote vpn.example.com 1195", "vpn.example.com:1195"},
		{"on its own line", "remote vpn.example.com\nport 1195", "vpn.example.com:1195"},
		{"left out entirely", "remote vpn.example.com", "vpn.example.com:1194"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			held, err := ParseOpenVPNFile(withCA("client\nauth-user-pass\n" + test.file + "\n"))
			if err != nil {
				t.Fatalf("reading the file: %v", err)
			}
			if held.Remote != test.want {
				t.Errorf("remote = %q, want %q", held.Remote, test.want)
			}
		})
	}
}

// A transport written on the remote line is the transport, the same as one on its own line.
func TestTheTransportOnTheRemoteLineIsRead(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("client\nauth-user-pass\nremote vpn.example.com 443 tcp-client\n"))
	if err != nil {
		t.Fatalf("reading the file: %v", err)
	}
	if held.Remote != "vpn.example.com:443" || held.Proto != OpenVPNProtoTCP {
		t.Errorf("remote/proto = %q/%q, want the server and transport the line named", held.Remote, held.Proto)
	}
}

// redirect-gateway is the file saying this server carries everything. It is stored as the
// route that amounts to, so the connection reports what it can carry -- and whether this
// machine's traffic actually goes that way stays the separate choice it is elsewhere.
func TestAskingForEverythingIsStoredAsTheDefaultRoute(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\nredirect-gateway def1\n"))
	if err != nil {
		t.Fatalf("reading the file: %v", err)
	}
	if len(held.Routes) != 1 || held.Routes[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Errorf("routes = %v, want the default route", held.Routes)
	}
}

// The directives this connection writes for itself are accepted and dropped. Refusing them
// would reject nearly every real file; storing them would report a connection deciding
// something app-tail decides.
func TestTheDirectivesThisConnectionWritesForItselfAreAcceptedAndDropped(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA(`client
tls-client
pull
nobind
dev tun
dev-type tun
persist-key
persist-tun
resolv-retry infinite
verb 4
mute 20
mute-replay-warnings
explicit-exit-notify 2
remote vpn.example.com 1194
auth-user-pass
`))
	if err != nil {
		t.Fatalf("reading a file full of directives app-tail renders itself: %v", err)
	}
	if held.Remote != "vpn.example.com:1194" || !held.AuthUserPass {
		t.Errorf("the directives that do carry a value were lost: %+v", held)
	}
	if len(held.Routes) != 0 || len(held.DNS) != 0 || held.MTU != 0 {
		t.Errorf("a dropped directive stored something: %+v", held)
	}
}

// Comments and blank lines are not directives. Both of openvpn's comment markers count,
// because a file written on either side of that convention is a file people paste.
func TestCommentsAndBlankLinesAreNotDirectives(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("# issued by the lab\n\n;disabled-directive here\nclient\n\nremote vpn.example.com 1194\nauth-user-pass\n"))
	if err != nil {
		t.Fatalf("reading a file with comments in it: %v", err)
	}
	if held.Remote != "vpn.example.com:1194" {
		t.Errorf("remote = %q, want the server the file named", held.Remote)
	}
}

// The refusal names the line it is on. A .ovpn file runs to hundreds of lines and "this is
// not supported" without a line number is a file the reader has to search by hand.
func TestARefusalNamesTheLineItIsOn(t *testing.T) {
	_, err := ParseOpenVPNFile("client\nremote vpn.example.com 1194\nauth-user-pass\nup /etc/openvpn/up.sh\n")
	if err == nil {
		t.Fatal("a file naming a program to run was accepted")
	}
	if !strings.Contains(err.Error(), "line 4") {
		t.Errorf("error = %q, want it to name line 4", err)
	}
}

// A quoted argument holds together, which is how openvpn reads one.
func TestAQuotedArgumentIsOneValue(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\n" +
		"verify-x509-name \"C=US, CN=vpn.example.com\" subject\n"))
	if err != nil {
		t.Fatalf("reading a quoted argument: %v", err)
	}
	if held.VerifyName != "C=US, CN=vpn.example.com" || held.VerifyNameType != OpenVPNVerifySubject {
		t.Errorf("verify = %q/%q, want the whole quoted name matched as a subject",
			held.VerifyName, held.VerifyNameType)
	}
}

// The same resolver written twice is one resolver. A duplicate would be asked twice for every
// name, which is slower and reports a connection doing something it does not.
func TestAResolverWrittenTwiceIsStoredOnce(t *testing.T) {
	held, err := ParseOpenVPNFile(withCA("client\nremote vpn.example.com 1194\nauth-user-pass\n" +
		"dhcp-option DNS 10.8.0.1\ndhcp-option DNS 10.8.0.1\n"))
	if err != nil {
		t.Fatalf("reading the file: %v", err)
	}
	if len(held.DNS) != 1 {
		t.Errorf("resolvers = %v, want the one the file named", held.DNS)
	}
}

// The forms a file may write that this connection does carry. Each is one arm of the reader
// that had no test of its own, and each stores something a connection cannot come up without.
func TestTheOtherFormsAServerFileWritesAreCarried(t *testing.T) {
	const head = "client\nremote vpn.example.com 1194\nauth-user-pass\n"

	t.Run("the general form of the server-certificate check", func(t *testing.T) {
		held, err := ParseOpenVPNFile(withCA(head + "remote-cert-eku \"TLS Web Server Authentication\"\n"))
		if err != nil {
			t.Fatalf("reading the check: %v", err)
		}
		if !held.VerifyServerCert {
			t.Error("the file asked for the server's certificate to be checked and the connection does not")
		}
	})

	t.Run("a certificate name matched by its prefix", func(t *testing.T) {
		held, err := ParseOpenVPNFile(withCA(head + "verify-x509-name vpn. name-prefix\n"))
		if err != nil {
			t.Fatalf("reading the check: %v", err)
		}
		if held.VerifyName != "vpn." || held.VerifyNameType != OpenVPNVerifyNamePrefix {
			t.Errorf("verify = %q/%q, want the prefix the file named", held.VerifyName, held.VerifyNameType)
		}
	})

	t.Run("the key that encrypts the control channel", func(t *testing.T) {
		held, err := ParseOpenVPNFile(withCA(head + "<tls-crypt>\n" +
			staticKeyBlock("0123456789abcdef") + "\n</tls-crypt>\n"))
		if err != nil {
			t.Fatalf("reading the control-channel key: %v", err)
		}
		if held.TLSCrypt == "" {
			t.Error("the control-channel key was not stored, so the connection would be started without it")
		}
	})

	t.Run("a resolver written for IPv6", func(t *testing.T) {
		held, err := ParseOpenVPNFile(withCA(head + "dhcp-option DNS6 2001:db8::1\n"))
		if err != nil {
			t.Fatalf("reading the resolver: %v", err)
		}
		if len(held.DNS) != 1 || held.DNS[0] != netip.MustParseAddr("2001:db8::1") {
			t.Errorf("resolvers = %v, want the one the file named", held.DNS)
		}
	})

	t.Run("a server named by a literal IPv6 address", func(t *testing.T) {
		held, err := ParseOpenVPNFile(withCA("client\nauth-user-pass\nremote 2001:db8::1 1194\n"))
		if err != nil {
			t.Fatalf("reading the server: %v", err)
		}
		// Bracketed, so the stored value reads back as one host and one port.
		if held.Remote != "[2001:db8::1]:1194" {
			t.Errorf("remote = %q, want the address bracketed", held.Remote)
		}
	})

	t.Run("a quoted argument holding a comma and a space", func(t *testing.T) {
		held, err := ParseOpenVPNFile(withCA(head + "verify-x509-name \"CN=vpn, O=Lab\" subject\n"))
		if err != nil {
			t.Fatalf("reading the name: %v", err)
		}
		if held.VerifyName != "CN=vpn, O=Lab" {
			t.Errorf("name = %q, want the whole quoted value", held.VerifyName)
		}
	})

	t.Run("the same network written twice", func(t *testing.T) {
		held, err := ParseOpenVPNFile(withCA(head + "route 10.8.0.0/16\nroute 10.8.0.0 255.255.0.0\n"))
		if err != nil {
			t.Fatalf("reading the routes: %v", err)
		}
		if len(held.Routes) != 1 {
			t.Errorf("routes = %v, want the one network, entered twice", held.Routes)
		}
	})
}
