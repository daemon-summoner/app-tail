// SPDX-License-Identifier: MIT

package inspect

// The question inside a DNS message, read where app-tail is carrying the message rather than
// answering it.
//
// This is the one thing that closes a real hole. app-tail's own resolver already checks every
// name it is asked about, and a program that skips it by sending its queries straight to a
// public resolver skips that check with them. On the paths that carry those datagrams the
// name is in the clear, so the same list can be applied to it -- which is the whole point of
// having intercepted the resolver in the first place.

// The shape of a DNS message, as far as this reads it.
const (
	dnsHeaderSize = 12
	// maxDNSMessage is what a message may claim to be over TCP. Nothing is sized by it: it
	// is only ever compared against, so a message claiming more is refused rather than
	// believed.
	maxDNSMessage = 65535
	// maxDNSName and maxDNSLabel are the protocol's own ceilings on a name.
	maxDNSName  = 255
	maxDNSLabel = 63
	// dnsFlagResponse is the bit that says a message is an answer. Only questions are read
	// here: an answer carries the same name and reading both would count every query twice.
	dnsFlagResponse = 0x80
)

// DNSQuestion reads the name a message asks about, and reports whether it is a question at
// all.
//
// Compression pointers are refused rather than followed. A pointer in a question is not
// something any real client sends, and following one is how a parser is made to walk a
// message in a circle -- which no bound on the window would stop, because the walk would
// never leave it.
func DNSQuestion(msg []byte) (string, bool) {
	if len(msg) < dnsHeaderSize {
		return "", false
	}
	if msg[2]&dnsFlagResponse != 0 {
		return "", false
	}
	questions := int(msg[4])<<8 | int(msg[5])
	if questions < 1 {
		return "", false
	}

	// The name is built into fixed room: 255 bytes is what a DNS name is, and a message
	// claiming more is malformed rather than a name this should make space for.
	var name [maxDNSName]byte
	held := 0
	at := dnsHeaderSize
	for {
		if at >= len(msg) {
			return "", false
		}
		size := int(msg[at])
		at++
		if size == 0 {
			break
		}
		// The top two bits set is a compression pointer, and anything else in them is a
		// label type nothing uses.
		if size > maxDNSLabel {
			return "", false
		}
		if at+size > len(msg) {
			return "", false
		}
		if held > 0 {
			if held >= maxDNSName {
				return "", false
			}
			name[held] = '.'
			held++
		}
		if held+size > maxDNSName {
			return "", false
		}
		held += copy(name[held:], msg[at:at+size])
		at += size
	}
	if held == 0 {
		// The root, which is a legitimate question and not a name any rule could name.
		return "", false
	}
	// The type and class behind the name have to be there for this to be a question rather
	// than the first bytes of something that happened to look like one.
	if at+4 > len(msg) {
		return "", false
	}
	// A label may carry any byte the protocol allows, and this name goes on to a log line and
	// an event field, so one carrying a control character is refused for the same reason a
	// server name carrying one is.
	if !printableName(name[:held]) {
		return "", false
	}
	return string(name[:held]), true
}
