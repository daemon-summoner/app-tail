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
	// dnsPointer is the two bits that make a length byte the first half of a compression
	// pointer, and maxDNSPointers is how many of them one name is followed through. A name
	// of the longest length is at most 127 labels, so no honest name needs more, and the
	// bound is what makes a pointer aimed at itself a refusal rather than a walk that never
	// ends.
	dnsPointer     = 0xc0
	maxDNSPointers = 16
	// dnsFlagResponse is the bit that says a message is an answer. Only questions are read
	// here: an answer carries the same name and reading both would count every query twice.
	dnsFlagResponse = 0x80
)

// DNSQuestion reads the name a message asks about, and reports whether it is a question at
// all.
//
// Compression pointers are followed, a bounded number of times. No ordinary client writes one
// in a question, but resolvers answer a query that does, so a name hidden behind one is a name
// asked for all the same -- and refusing to read it would be a way to ask past every rule. The
// bound is what stops a pointer aimed at itself: the walk would otherwise never leave the
// message, and no limit on the message's size would end it.
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
	// end is where the type and class sit: behind the root label, or behind the first pointer
	// when the name goes on somewhere else.
	end, jumps := 0, 0
	for {
		if at >= len(msg) {
			return "", false
		}
		size := int(msg[at])
		at++
		if size == 0 {
			break
		}
		if size&dnsPointer == dnsPointer {
			if at >= len(msg) || jumps == maxDNSPointers {
				return "", false
			}
			if jumps == 0 {
				end = at + 1
			}
			jumps++
			at = (size&^dnsPointer)<<8 | int(msg[at])
			continue
		}
		// Anything else in the top two bits is a label type nothing uses.
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
	if jumps == 0 {
		end = at
	}
	// The type and class behind the name have to be there for this to be a question rather
	// than the first bytes of something that happened to look like one.
	if end+4 > len(msg) {
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
