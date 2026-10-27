// SPDX-License-Identifier: MIT

package inspect

// The fingerprint, and the two properties that make it worth computing at all: it says the
// same thing about the same software however that software shuffles its hello, and it says
// nothing that is not derived from the hello it was given.

import (
	"strings"
	"testing"
)

// A fingerprint that changed between two connections from the same program would be a random
// number with extra steps, which is exactly what happened to the fingerprints this one
// replaced.
func TestTheFingerprintOfOneHelloIsAlwaysTheSame(t *testing.T) {
	win := capture(t, "clienthello-go.hex")
	hello, state := ParseClientHello(win)
	if state != Parsed {
		t.Fatalf("the capture read as %v, want Parsed", state)
	}
	first := hello.JA4(TransportTCP)
	if first == "" {
		t.Fatal("a real hello produced no fingerprint")
	}
	again, _ := ParseClientHello(win)
	if second := again.JA4(TransportTCP); second != first {
		t.Errorf("the same hello fingerprinted as %q and then %q", first, second)
	}
}

// The shape is what a reader acts on: the transport, the version, whether a name was asked
// for, how many ciphers and extensions, and the protocol offered.
func TestTheFingerprintSaysWhatTheHelloWas(t *testing.T) {
	hello, _ := ParseClientHello(capture(t, "clienthello-go.hex"))
	fingerprint := hello.JA4(TransportTCP)

	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		t.Fatalf("the fingerprint %q is not three parts", fingerprint)
	}
	if len(parts[0]) != 10 {
		t.Errorf("the first part of %q is %d characters, want 10", fingerprint, len(parts[0]))
	}
	if got := parts[0][:1]; got != "t" {
		t.Errorf("the transport reads %q, want %q for a connection", got, "t")
	}
	if got := parts[0][1:3]; got != "13" {
		t.Errorf("the version reads %q, want %q for a TLS 1.3 hello", got, "13")
	}
	if got := parts[0][3:4]; got != "d" {
		t.Errorf("the name marker reads %q, want %q for a hello that asked for one", got, "d")
	}
	if got := parts[0][8:]; got != "h2" {
		t.Errorf("the protocol reads %q, want %q", got, "h2")
	}
	for _, half := range parts[1:] {
		if len(half) != 12 {
			t.Errorf("the hash %q is %d characters, want 12", half, len(half))
		}
		if strings.Trim(half, "0123456789abcdef") != "" {
			t.Errorf("the hash %q is not hexadecimal", half)
		}
	}

	// Over QUIC the same hello is the same software, and the transport is the one thing that
	// differs.
	overQUIC := hello.JA4(TransportQUIC)
	if overQUIC[:1] != "q" || overQUIC[1:] != fingerprint[1:] {
		t.Errorf("the same hello over QUIC fingerprinted as %q, want %q with a q", overQUIC, fingerprint)
	}
}

// The values a client scatters through its hello to keep middleboxes honest are not part of
// what the client is, and a fingerprint that moved with them would move on every connection.
func TestValuesSentToBeIgnoredDoNotChangeTheFingerprint(t *testing.T) {
	plain := buildHello(extension(0, serverName("grease.example")), 0)
	hello, state := ParseClientHello(plain)
	if state != Parsed {
		t.Fatalf("the built hello read as %v, want Parsed", state)
	}

	// The same hello with a reserved cipher and a reserved extension added.
	var greased helloWriter
	greased.raw(extension(0x0a0a, nil)...)
	greased.raw(extension(0, serverName("grease.example"))...)
	withGrease := buildHelloWithCiphers([]int{0x1a1a, 0x1301}, greased.b)

	other, state := ParseClientHello(withGrease)
	if state != Parsed {
		t.Fatalf("the greased hello read as %v, want Parsed", state)
	}
	if got, want := other.JA4(TransportTCP), hello.JA4(TransportTCP); got != want {
		t.Errorf("adding reserved values changed the fingerprint to %q, want %q", got, want)
	}
}

// A client is free to offer its ciphers in any order, and two clients offering the same set
// in different orders are the same client.
func TestTheOrderCiphersAreOfferedInDoesNotChangeTheFingerprint(t *testing.T) {
	body := extension(0, serverName("order.example"))
	one, state := ParseClientHello(buildHelloWithCiphers([]int{0x1301, 0x1302, 0x1303}, body))
	if state != Parsed {
		t.Fatalf("the first hello read as %v, want Parsed", state)
	}
	other, state := ParseClientHello(buildHelloWithCiphers([]int{0x1303, 0x1301, 0x1302}, body))
	if state != Parsed {
		t.Fatalf("the reordered hello read as %v, want Parsed", state)
	}
	if got, want := other.JA4(TransportTCP), one.JA4(TransportTCP); got != want {
		t.Errorf("reordering the ciphers changed the fingerprint to %q, want %q", got, want)
	}
}

// A hello offering more than the parser kept is a hello the fingerprint cannot describe, and
// the honest answer is none: a fingerprint computed from a truncated list would be a name for
// something that was never sent.
func TestAHelloTooLargeToDescribeHasNoFingerprint(t *testing.T) {
	ciphers := make([]int, maxCiphers+1)
	for i := range ciphers {
		// Real cipher values rather than reserved ones, so none of them is dropped.
		ciphers[i] = 0x0100 + i
	}
	hello, state := ParseClientHello(buildHelloWithCiphers(ciphers, extension(0, serverName("many.example"))))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	if got := hello.JA4(TransportTCP); got != "" {
		t.Errorf("a hello offering %d ciphers fingerprinted as %q, want no fingerprint", len(ciphers), got)
	}
}

// The fingerprint says whether a name was asked for, which on a hello with no server name is
// the only thing distinguishing it from the same client asking for one.
func TestAHelloThatAsksForNoNameSaysSoInItsFingerprint(t *testing.T) {
	named, state := ParseClientHello(buildHello(extension(extServerName, serverName("named.example")), 0))
	if state != Parsed {
		t.Fatalf("the named hello read as %v, want Parsed", state)
	}
	anonymous, state := ParseClientHello(buildHello(extension(extSupportedVersions, []byte{2, 0x03, 0x04}), 0))
	if state != Parsed {
		t.Fatalf("the hello with no name read as %v, want Parsed", state)
	}

	if got := named.JA4(TransportTCP)[3:4]; got != "d" {
		t.Errorf("the name marker reads %q for a hello that asked for one, want %q", got, "d")
	}
	if got := anonymous.JA4(TransportTCP)[3:4]; got != "i" {
		t.Errorf("the name marker reads %q for a hello that asked for none, want %q", got, "i")
	}
}

// The version in the fingerprint is a name a reader acts on, so a version this does not know
// is written as one it does not know rather than as the nearest one it does.
func TestTheVersionInTheFingerprintIsTheOneThatWasOffered(t *testing.T) {
	cases := []struct {
		version uint16
		want    string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0x0002, "s2"},
		{0x7f17, "00"}, // a draft version, which is not a version this names
	}
	for _, held := range cases {
		var body helloWriter
		body.u8(2)
		body.u16(int(held.version))
		hello, state := ParseClientHello(buildHello(extension(extSupportedVersions, body.b), 0))
		if state != Parsed {
			t.Fatalf("the hello offering %#04x read as %v, want Parsed", held.version, state)
		}
		if got := hello.JA4(TransportTCP)[1:3]; got != held.want {
			t.Errorf("version %#04x reads as %q in the fingerprint, want %q", held.version, got, held.want)
		}
	}
}

// A protocol name is two characters of the fingerprint, and those characters are read by
// somebody. A value chosen to look like a real protocol is written as the hex of its bytes so
// it cannot be mistaken for one.
func TestAProtocolNameThatIsNotOneIsWrittenAsItsBytes(t *testing.T) {
	hello, state := ParseClientHello(buildHello(extension(extALPN, alpnRaw([]byte{0x9f, 'x', 0x0a})), 0))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	if got := hello.JA4(TransportTCP)[8:10]; got != "9a" {
		t.Errorf("the protocol reads %q, want the hex of the first and last bytes", got)
	}
}

// The counts are two digits each, and a client offering more than that is described as
// offering ninety-nine rather than overflowing the field into the characters beside it.
func TestAHelloOfferingMoreThanTheCountCanHoldIsCappedRatherThanOverflowing(t *testing.T) {
	ciphers := make([]int, 120)
	for i := range ciphers {
		ciphers[i] = 0x0100 + i
	}
	hello, state := ParseClientHello(buildHelloWithCiphers(ciphers, extension(extServerName, serverName("many.example"))))
	if state != Parsed {
		t.Fatalf("the hello read as %v, want Parsed", state)
	}
	fingerprint := hello.JA4(TransportTCP)
	if fingerprint == "" {
		t.Fatal("a hello inside the parser's limits produced no fingerprint")
	}
	if got := fingerprint[4:6]; got != "99" {
		t.Errorf("the cipher count reads %q for %d ciphers, want %q", got, len(ciphers), "99")
	}
	if len(fingerprint) != 36 {
		t.Errorf("the fingerprint is %d characters, want 36", len(fingerprint))
	}
}

// buildHelloWithCiphers is buildHello with the offered ciphers chosen by the caller.
func buildHelloWithCiphers(ciphers []int, extensions []byte) []byte {
	var body helloWriter
	body.u16(0x0303)
	body.fill(32, 0x11)
	body.u8(0)
	body.u16(len(ciphers) * 2)
	for _, suite := range ciphers {
		body.u16(suite)
	}
	body.u8(1)
	body.u8(0)
	body.u16(len(extensions))
	body.raw(extensions...)

	var handshake helloWriter
	handshake.u8(1)
	handshake.u8(len(body.b) >> 16)
	handshake.u16(len(body.b) & 0xffff)
	handshake.raw(body.b...)

	var out helloWriter
	out.raw(0x16, 0x03, 0x01)
	out.u16(len(handshake.b))
	out.raw(handshake.b...)
	return out.b
}
