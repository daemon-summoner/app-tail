// SPDX-License-Identifier: MIT

package inspect

// The TLS client fingerprint, which says what kind of thing made a connection rather than
// where it was going: two programs on one machine reaching the same address look identical
// to every other signal here, and this is what tells them apart.
//
// It is JA4, computed from what the hello parser already read, and it is deliberately an
// observation rather than a rule. Two reasons, both structural: it identifies a TLS stack
// family rather than a program, so a fingerprint shared by every Go program on the machine
// would refuse all of them together; and anything that wanted to avoid it changes one line
// of its own TLS configuration. A signal that can be moved by whoever is being looked for
// is worth reporting and is not worth enforcing.
//
// The scheme is FoxIO's, published as a specification. This is an implementation of that
// specification rather than any of their code, and it is read-only enrichment here.

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// TransportTCP and TransportQUIC are the first character of a fingerprint, which says what
// carried the hello.
const (
	TransportTCP  = 't'
	TransportQUIC = 'q'
)

// ja4Room is how much of a list the joined form can take: every entry is four hex digits
// and a separator, and the lists themselves are already bounded by what the parser keeps.
const ja4Room = (maxCiphers + maxExtension + maxSigAlgs) * 5

// JA4 is the fingerprint of the client that sent the hello, empty when it cannot be
// computed honestly.
//
// It comes back empty rather than approximate when the hello offered more ciphers or
// extensions than the parser keeps: a fingerprint over a truncated list would collide with
// real clients that sent exactly that prefix, which is worse than not having one.
func (h ClientHello) JA4(transport byte) string {
	if h.ciphersSeen > maxCiphers || h.extensionsSeen > maxExtension {
		return ""
	}

	// The three parts, built into one fixed run of bytes: the readable prefix, then the two
	// truncated hashes with their separators.
	var out [36]byte
	out[0] = transport
	v := ja4Version(h.Version())
	out[1], out[2] = v[0], v[1]
	if h.sniLen > 0 {
		out[3] = 'd'
	} else {
		out[3] = 'i'
	}
	writeCount(out[4:6], h.ciphersSeen)
	writeCount(out[6:8], h.extensionsSeen)
	alpn := h.ja4ALPN()
	out[8], out[9] = alpn[0], alpn[1]
	out[10] = '_'

	var scratch [ja4Room]byte

	// The receiver is a copy, so the lists are sorted where they lie rather than into
	// anything new.
	ciphers := h.ciphers[:h.ciphersHeld]
	slices.Sort(ciphers)
	copy(out[11:23], ja4Hash(scratch[:0], ciphers, nil))
	out[23] = '_'

	// The two extensions that are already in the readable half are left out of the hash, so
	// the same client reaching two different names fingerprints the same.
	var room [maxExtension]uint16
	held := 0
	for _, ext := range h.extensions[:h.extensionsHeld] {
		if ext == extServerName || ext == extALPN {
			continue
		}
		room[held] = ext
		held++
	}
	extensions := room[:held]
	slices.Sort(extensions)
	// The signature algorithms stay in the order they arrived: that order is part of what
	// distinguishes one stack from another, and sorting them would throw it away.
	copy(out[24:36], ja4Hash(scratch[:0], extensions, h.sigAlgs[:h.sigAlgsHeld]))

	return string(out[:])
}

// ja4Version is the two characters that name the version, which for anything this does not
// recognise is "00" rather than a guess.
func ja4Version(version uint16) [2]byte {
	switch version {
	case 0x0304:
		return [2]byte{'1', '3'}
	case 0x0303:
		return [2]byte{'1', '2'}
	case 0x0302:
		return [2]byte{'1', '1'}
	case 0x0301:
		return [2]byte{'1', '0'}
	case 0x0300:
		return [2]byte{'s', '3'}
	case 0x0002:
		return [2]byte{'s', '2'}
	}
	return [2]byte{'0', '0'}
}

// ja4ALPN is the first and last character of the protocol offered first: "h2" for HTTP/2,
// "h1" for http/1.1, and "00" where none was offered.
func (h ClientHello) ja4ALPN() [2]byte {
	if h.alpnHeld == 0 || h.alpnLen[0] == 0 {
		return [2]byte{'0', '0'}
	}
	value := h.alpn[0][:h.alpnLen[0]]
	first, last := value[0], value[len(value)-1]
	// A protocol name is printable ASCII. Anything else is written as the hex of the byte,
	// so a value chosen to look like a real one cannot be mistaken for it.
	if !printableASCII(first) || !printableASCII(last) {
		return [2]byte{hexDigit(value[0] >> 4), hexDigit(value[len(value)-1] & 0x0f)}
	}
	return [2]byte{first, last}
}

func printableASCII(b byte) bool { return b >= 0x20 && b < 0x7f }

// writeCount fills two digits, capped at 99 the way the scheme caps them: a client offering
// more than that is reported as offering ninety-nine rather than overflowing the field.
func writeCount(dst []byte, n int) {
	if n > 99 {
		n = 99
	}
	dst[0] = byte('0' + n/10)
	dst[1] = byte('0' + n%10)
}

// ja4Hash is the truncated hash of one or two comma-joined lists, joined by an underscore
// when there are two. It writes into scratch, which the caller owns, so the whole
// fingerprint costs no allocation beyond the string it ends as.
func ja4Hash(scratch []byte, first, second []uint16) string {
	scratch = appendList(scratch, first)
	if second != nil {
		scratch = append(scratch, '_')
		scratch = appendList(scratch, second)
	}
	sum := sha256.Sum256(scratch)
	var out [12]byte
	hex.Encode(out[:], sum[:6])
	return string(out[:])
}

// appendList writes the values as four lowercase hex digits each, comma separated.
func appendList(dst []byte, values []uint16) []byte {
	for i, v := range values {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst,
			hexDigit(byte(v>>12)), hexDigit(byte(v>>8)), hexDigit(byte(v>>4)), hexDigit(byte(v)))
	}
	return dst
}

func hexDigit(b byte) byte {
	b &= 0x0f
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}
