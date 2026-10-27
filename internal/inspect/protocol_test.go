// SPDX-License-Identifier: MIT

package inspect

// What a connection is speaking. The standard here is the opposite of the parsers': a wrong
// name is worse than no name, because the name is the sentence somebody acts on.

import (
	"strings"
	"testing"
)

// The naming runs through the stream, because that is the order the names are decided in: a
// hello and a request head are named by their own parse, and the banners are what is left.
func namedBy(t *testing.T, win string) Handshake {
	t.Helper()
	var found Handshake
	stream := NewStream(StreamOptions{}, func(h Handshake) bool {
		found = h
		return false
	})
	stream.Up([]byte(win))
	stream.Close()
	return found
}

func TestAConnectionIsNamedByWhatItOpensWith(t *testing.T) {
	cases := []struct {
		name string
		win  string
		want string
	}{
		{"a hello", string(buildHello(extension(0, serverName("named.example")), 0)), ProtocolTLS},
		{"a web request", "GET / HTTP/1.1\r\nHost: web.example\r\n\r\n", ProtocolHTTP},
		{"an SSH banner", "SSH-2.0-OpenSSH_9.6\r\n", ProtocolSSH},
		{"an older SSH banner", "SSH-1.99-OpenSSH_3.9\r\n", ProtocolSSH},
		{"a mail greeting", "220 mail.example ESMTP ready\r\n", ProtocolSMTP},
		{"a file transfer greeting", "220-Welcome to the server\r\n", ProtocolFTP},
		{
			"a query over a connection",
			string(append([]byte{0x00, 0x22}, dnsQuery("over.tcp.example")...)),
			ProtocolDNS,
		},
		{"bytes nothing recognises", "\x00\x01\x02\x03\x04\x05", ""},
		{"a length prefix in front of nothing", "\x00\x40", ""},
		{"a record that is not TLS", "\x16\x09\x01\x00\x05", ""},
		{"prose", "hello there, this is not a protocol", ""},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			if got := namedBy(t, held.win).Protocol; got != held.want {
				t.Errorf("the connection read as %q, want %q", got, held.want)
			}
		})
	}
}

// A real hello is TLS however far into it the window reaches, including at the three bytes
// where only the record header has arrived.
func TestARealHelloIsNamedAsTLSFromItsFirstBytes(t *testing.T) {
	win := capture(t, "clienthello-go.hex")
	for _, at := range []int{3, 5, 64} {
		if got := bannerOf(win[:at]); got != ProtocolTLS {
			t.Errorf("%d bytes of a hello read as %q, want %q", at, got, ProtocolTLS)
		}
	}
	if got := namedBy(t, string(win)).Protocol; got != ProtocolTLS {
		t.Errorf("a whole hello read as %q, want %q", got, ProtocolTLS)
	}
}

// The length prefix in front of a query is two bytes of anything, so the message behind it
// has to parse as a question before this says DNS.
func TestALengthPrefixAloneIsNotAQuery(t *testing.T) {
	query := append([]byte{0x00, 0x22}, dnsQuery("real.example")...)
	if !isDNSOverTCP(query) {
		t.Error("a real query over a connection was not recognised")
	}
	for _, held := range [][]byte{
		{0x00, 0x22},
		{0xff, 0xff, 0x01, 0x02, 0x03},
		append([]byte{0x00, 0x05}, dnsQuery("short.example")...),
		append([]byte{0x00, 0x22}, "not a message at all"...),
		nil,
	} {
		if isDNSOverTCP(held) {
			t.Errorf("%q was read as a query over a connection", held)
		}
	}
}

// The five bytes that decide whether a datagram is QUIC, which is the whole of what is read
// off the datagram paths.
func TestAQUICDatagramIsRecognisedAndNothingElseIs(t *testing.T) {
	cases := []struct {
		name     string
		datagram []byte
		want     bool
	}{
		{"a version 1 initial packet", []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08}, true},
		{"a draft version", []byte{0xc3, 0xff, 0x00, 0x00, 0x20}, true},
		{"a short header packet", []byte{0x40, 0x00, 0x00, 0x00, 0x01}, false},
		{"a long header without the fixed bit", []byte{0x80, 0x00, 0x00, 0x00, 0x01}, false},
		{"a version negotiation packet, which a client never sends", []byte{0xc0, 0x00, 0x00, 0x00, 0x00}, false},
		{"a DNS query", dnsQuery("not.quic.example"), false},
		{"four bytes", []byte{0xc0, 0x00, 0x00, 0x00}, false},
		{"nothing at all", nil, false},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			if got := IsQUIC(held.datagram); got != held.want {
				t.Errorf("the datagram read as QUIC=%v, want %v", got, held.want)
			}
		})
	}
}

// A window that names nothing must still name nothing when it is full of it, and must reach
// that verdict rather than hold the window open waiting for a name that is not coming.
func TestAWindowOfNoiseNamesNothingAndStillReachesAVerdict(t *testing.T) {
	found := namedBy(t, strings.Repeat("\x00\xff\x7f\x80", windowSize/4))
	if found.Protocol != "" {
		t.Errorf("a window of noise read as %q, want no name", found.Protocol)
	}
	if found.Name != "" {
		t.Errorf("a window of noise was reported with the name %q", found.Name)
	}
}
