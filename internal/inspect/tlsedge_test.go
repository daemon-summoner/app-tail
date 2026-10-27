// SPDX-License-Identifier: MIT

package inspect

// The arms of the hello parser a real client never exercises: the values it may legally send
// that nothing in the captures does, and the malformed ones an attacker sends on purpose.
// Every one of them is reached by bytes somebody can choose, so every one of them is a path
// this package runs on attacker input.

import (
	"strings"
	"testing"
)

// alpnList is an ALPN extension body offering the protocols given, in order.
func alpnList(protocols ...string) []byte {
	var list helloWriter
	for _, name := range protocols {
		list.u8(len(name))
		list.raw([]byte(name)...)
	}
	var w helloWriter
	w.u16(len(list.b))
	w.raw(list.b...)
	return w.b
}

// alpnRaw is the same for one protocol whose bytes are chosen rather than written.
func alpnRaw(value []byte) []byte {
	var list helloWriter
	list.u8(len(value))
	list.raw(value...)
	var w helloWriter
	w.u16(len(list.b))
	w.raw(list.b...)
	return w.b
}

// A protocol name is carried into a log line and an event field. One with a control byte in
// it reads as none for the same reason a server name carrying one does.
func TestAProtocolNameThatIsNotOneReadsAsNone(t *testing.T) {
	hello, state := ParseClientHello(buildHello(extension(extALPN, alpnRaw([]byte("h2\r\nX"))), 0))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	if got := hello.ALPN(); got != "" {
		t.Errorf("ALPN = %q, want none for a value carrying a control byte", got)
	}
}

// The version a client will speak is in an extension, and the reserved values scattered
// through that extension are not versions. Reading one as the highest would report every
// greased client as speaking something nobody implements.
func TestTheVersionIgnoresTheValuesSentToBeIgnored(t *testing.T) {
	var body helloWriter
	body.u8(6)
	body.u16(0x8a8a) // reserved, and numerically above every real version
	body.u16(0x0304)
	body.u16(0x0303)

	hello, state := ParseClientHello(buildHello(extension(extSupportedVersions, body.b), 0))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	if got := hello.Version(); got != 0x0304 {
		t.Errorf("version = %#04x, want the highest real one offered", got)
	}
}

// Nothing sends a hello without extensions this century, and the protocol still allows it.
// Reading one as unfinished would hold a window open for a connection that already said
// everything it was going to.
func TestAHelloThatEndsAfterItsCiphersIsFinished(t *testing.T) {
	var body helloWriter
	body.u16(0x0303)
	body.fill(32, 0x11)
	body.u8(0)
	body.u16(2)
	body.u16(0x1301)
	body.u8(1)
	body.u8(0)

	var handshake helloWriter
	handshake.u8(1)
	handshake.u8(len(body.b) >> 16)
	handshake.u16(len(body.b) & 0xffff)
	handshake.raw(body.b...)

	var win helloWriter
	win.raw(0x16, 0x03, 0x01)
	win.u16(len(handshake.b))
	win.raw(handshake.b...)

	hello, state := ParseClientHello(win.b)
	if state != Parsed {
		t.Fatalf("a hello with no extension block read as %v, want Parsed", state)
	}
	if hello.SNI() != "" {
		t.Errorf("SNI = %q, want none: the hello carried no extensions at all", hello.SNI())
	}
}

// Encrypted client hello is the thing that will eventually take the server name away, and a
// user reading a report of what inspection can still see needs to know which connections
// already carry it.
func TestAHelloSaysWhenItsInnerHalfIsEncrypted(t *testing.T) {
	plain, _ := ParseClientHello(buildHello(extension(extServerName, serverName("plain.example")), 0))
	if plain.ECH {
		t.Error("an ordinary hello reads as carrying an encrypted inner half")
	}

	var body helloWriter
	body.raw(extension(extServerName, serverName("outer.example"))...)
	body.raw(extension(extECH, []byte{0x00, 0x01, 0x02})...)
	hidden, state := ParseClientHello(buildHello(body.b, 0))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	if !hidden.ECH {
		t.Error("a hello carrying the encrypted-hello extension does not say so")
	}
	if got := hidden.SNI(); got != "outer.example" {
		t.Errorf("SNI = %q, want the outer name, which is the one that is still readable", got)
	}
}

// The malformed shapes, each of which is a decision the parser must make rather than a place
// it may run off the end.
func TestAMalformedHelloIsNeverReadAsOne(t *testing.T) {
	// A cipher list of odd length is not a list of two-byte ciphers, so it is not this.
	var odd helloWriter
	odd.u16(0x0303)
	odd.fill(32, 0x11)
	odd.u8(0)
	odd.u16(3)
	odd.raw(0x13, 0x01, 0x13)
	odd.u8(1)
	odd.u8(0)
	odd.u16(0)

	var handshake helloWriter
	handshake.u8(1)
	handshake.u8(len(odd.b) >> 16)
	handshake.u16(len(odd.b) & 0xffff)
	handshake.raw(odd.b...)

	var win helloWriter
	win.raw(0x16, 0x03, 0x01)
	win.u16(len(handshake.b))
	win.raw(handshake.b...)

	if _, state := ParseClientHello(win.b); state != NotThis {
		t.Errorf("a hello whose cipher list is an odd number of bytes read as %v, want NotThis", state)
	}

	// A record after the first that is not a handshake record is framing this reader cannot
	// follow, and no later byte can fix it.
	split := buildHello(extension(extServerName, serverName("split.example")), 40)
	if len(split) < 60 {
		t.Fatalf("the split hello is %d bytes, which is not split at all", len(split))
	}
	broken := append([]byte(nil), split...)
	broken[45] = 0x17 // the second record's content type, changed to application data
	if _, state := ParseClientHello(broken); state != Incomplete {
		t.Errorf("a hello whose second record is not a handshake read as %v, want Incomplete", state)
	}

	// An extension whose body reads past its own declared length has walked over the block,
	// and rewinding into it would report extensions nobody sent.
	var over helloWriter
	over.u16(extServerName)
	over.u16(4) // declared shorter than the name list inside it
	over.raw(serverName("over.example")...)
	if _, state := ParseClientHello(buildHello(over.b, 0)); state == Parsed {
		t.Error("an extension that read past its own length was accepted")
	}
}

// The entries inside the two list extensions that are skipped rather than kept. A parser that
// stopped at one would report a hello as unfinished for sending something legal.
func TestEntriesTheParserDoesNotKeepAreSteppedOver(t *testing.T) {
	// A name of a kind that is not a host name, then the host name itself. Only host_name was
	// ever defined, and something else in front of it must not hide it.
	var names helloWriter
	var list helloWriter
	list.u8(0x02) // not host_name
	list.u16(3)
	list.raw('a', 'b', 'c')
	list.u8(nameHostName)
	list.u16(len("kept.example"))
	list.raw([]byte("kept.example")...)
	names.u16(len(list.b))
	names.raw(list.b...)

	hello, state := ParseClientHello(buildHello(extension(extServerName, names.b), 0))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	if got := hello.SNI(); got != "kept.example" {
		t.Errorf("SNI = %q, want the host name that followed one of another kind", got)
	}

	// More protocols than the parser keeps, and one longer than it keeps. The ones it does
	// keep are the first ones, which is the one the connection will speak.
	long := strings.Repeat("p", maxALPNValue+1)
	offered := alpnOf(t, alpnList("h2", "http/1.1", "spdy/3", "h3", "extra", long))
	if offered != "h2" {
		t.Errorf("ALPN = %q, want the first protocol offered", offered)
	}
}

// alpnOf reads a hello carrying the given ALPN body and answers the protocol kept.
func alpnOf(t *testing.T, body []byte) string {
	t.Helper()
	hello, state := ParseClientHello(buildHello(extension(extALPN, body), 0))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	return hello.ALPN()
}

// The signature algorithms are hashed in the order they arrived, and the reserved values in
// that list are not algorithms: keeping one would move the fingerprint on every connection.
func TestReservedSignatureAlgorithmsAreNotPartOfTheFingerprint(t *testing.T) {
	name := extension(extServerName, serverName("sig.example"))

	var plain helloWriter
	plain.u16(4)
	plain.u16(0x0403)
	plain.u16(0x0804)
	one, state := ParseClientHello(buildHello(append(append([]byte(nil), name...),
		extension(extSignatureAlgs, plain.b)...), 0))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}

	var greased helloWriter
	greased.u16(6)
	greased.u16(0x0403)
	greased.u16(0x3a3a) // reserved
	greased.u16(0x0804)
	other, state := ParseClientHello(buildHello(append(append([]byte(nil), name...),
		extension(extSignatureAlgs, greased.b)...), 0))
	if state != Parsed {
		t.Fatalf("the greased hello read as %v, want Parsed", state)
	}

	if got, want := other.JA4(TransportTCP), one.JA4(TransportTCP); got != want {
		t.Errorf("a reserved signature algorithm changed the fingerprint to %q, want %q", got, want)
	}
}
