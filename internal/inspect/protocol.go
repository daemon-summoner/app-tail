// SPDX-License-Identifier: MIT

package inspect

// What a connection is speaking, read off its first few bytes.
//
// This is enrichment rather than a rule: it is the difference between "a connection to that
// address" and "SSH to that address on port 443", which is the sentence somebody reading the
// list actually needs. Nothing is refused for it, because a protocol on an unexpected port
// is as often a service somebody moved as it is anything else.

import "bytes"

// The protocols this recognises, in the words the card shows.
const (
	ProtocolTLS  = "tls"
	ProtocolHTTP = "http"
	ProtocolSSH  = "ssh"
	ProtocolSMTP = "smtp"
	ProtocolFTP  = "ftp"
	ProtocolDNS  = "dns"
	ProtocolQUIC = "quic"
)

// Banners that name a protocol outright. Each one is a server greeting rather than a client
// request, which is worth knowing: on the paths that reach here the first bytes are the
// client's, so seeing one means the connection is carrying a server's side of something.
var (
	bannerSSH  = []byte("SSH-2.0-")
	bannerSSH1 = []byte("SSH-1.")
	bannerSMTP = []byte("220 ")
	bannerFTP  = []byte("220-")
)

// bannerOf names what the bytes are from the first few of them alone, empty when they are
// nothing it recognises.
//
// It is deliberately cheap and deliberately shallow: everything it looks at is in the first
// few bytes, and anything it is unsure of is nothing rather than a guess. A wrong name on a
// detection is worse than no name, because the name is what somebody acts on. The stream
// reads it after it has already tried the window as a hello and as a request head, so the
// protocols with a parser of their own are named by that parse rather than twice.
func bannerOf(win []byte) string {
	if len(win) == 0 {
		return ""
	}
	switch {
	case win[0] == recordHandshake && len(win) >= 3 && win[1] == 0x03:
		// A TLS record: the handshake type, then a major version of 3, which every version
		// from SSL 3.0 to TLS 1.3 still carries at the front of a record.
		return ProtocolTLS
	// A banner is a prefix and then the text of the greeting, and every one of these
	// prefixes is short enough that the prefix alone is bytes any protocol could open
	// with. A greeting with nothing after its prefix names nothing rather than guessing.
	case bytes.HasPrefix(win, bannerSSH) && len(win) > len(bannerSSH):
		return ProtocolSSH
	case bytes.HasPrefix(win, bannerSSH1) && len(win) > len(bannerSSH1):
		return ProtocolSSH
	case bytes.HasPrefix(win, bannerSMTP) && len(win) > len(bannerSMTP):
		return ProtocolSMTP
	case bytes.HasPrefix(win, bannerFTP) && len(win) > len(bannerFTP):
		return ProtocolFTP
	}
	return ""
}

// isDNSOverTCP reports the two-byte length prefix and a query header behind it. It is
// checked last because two bytes of length are two bytes of anything: the message behind
// them has to parse as a question before this says DNS.
func isDNSOverTCP(win []byte) bool {
	if len(win) < 2 {
		return false
	}
	size := int(win[0])<<8 | int(win[1])
	if size < dnsHeaderSize || size > maxDNSMessage {
		return false
	}
	_, ok := DNSQuestion(win[2:])
	return ok
}

// QUIC is read on the datagram paths, where there is no stream to accumulate and the whole
// decision has to be made on the first packet of one.
const (
	quicLongHeader = 0x80
	quicFixedBit   = 0x40
)

// IsQUIC reports a datagram being the start of a QUIC connection.
//
// It is read rather than decrypted. The name inside a QUIC initial packet is encrypted with
// keys derived from the connection id, and deriving them is several hundred lines of
// version-specific crypto over bytes an attacker chooses, breaking on every version bump.
// Knowing that a datagram is QUIC is enough for the policy that matters: a browser refused
// QUIC to a destination falls back to TCP on the same port, where the hello is readable.
func IsQUIC(datagram []byte) bool {
	if len(datagram) < 5 {
		return false
	}
	if datagram[0]&quicLongHeader == 0 || datagram[0]&quicFixedBit == 0 {
		return false
	}
	// The version is the four bytes after the first. Version zero is a version negotiation
	// packet, which a client never sends.
	version := uint32(datagram[1])<<24 | uint32(datagram[2])<<16 |
		uint32(datagram[3])<<8 | uint32(datagram[4])
	return version != 0
}
