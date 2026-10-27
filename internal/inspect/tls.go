// SPDX-License-Identifier: MIT

package inspect

// The TLS ClientHello, which is the one thing worth reading on a modern connection: it
// carries the name the program is really going for, in the clear, on a connection that was
// dialled as an address and would otherwise be a blank to every rule written as a domain.
//
// crypto/tls will not hand over a raw hello, so this parses it. Every rule the package
// comment states applies hardest here, because these are the bytes an attacker chooses:
// no recursion, every length checked against the window before the slice it describes is
// read, and nothing sized by anything the network said. The one buffer is the window the
// caller already holds, and everything kept is copied into fixed room inside the result.

// The room a hello is read into. Each of these is a real ceiling rather than a guess: a
// name is 255 bytes because that is what a DNS name is, and the lists are far past what any
// real client sends, so a hello that overflows one is not a client this can fingerprint.
const (
	maxName      = 255
	maxALPNValue = 32
	maxALPNHeld  = 4
	maxCiphers   = 128
	maxExtension = 128
	maxSigAlgs   = 64
	maxVersions  = 16
)

// TLS record and handshake constants, named where they are read.
const (
	recordHandshake  = 0x16
	handshakeHello   = 0x01
	recordHeaderSize = 5

	extServerName        = 0x0000
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
	extSignatureAlgs     = 0x000d
	extECH               = 0xfe0d

	nameHostName = 0x00
)

// State is what a parser could conclude from the bytes it was given.
//
// The three are kept apart because they lead to different things: more bytes may finish an
// Incomplete parse, nothing will ever finish a NotThis, and both are carried rather than
// matched. A parser that folded them together would either keep a window open on bytes that
// are not the protocol at all or give up on a hello that had not finished arriving.
type State int

const (
	// Incomplete means the bytes ran out mid-field. More may finish it.
	Incomplete State = iota
	// Parsed means the whole structure was read.
	Parsed
	// NotThis means the bytes are definitely not this protocol.
	NotThis
)

// ClientHello is what one hello said, in fixed room so that reading it allocates nothing.
//
// The fields are unexported and read through methods because they are arrays with counts
// beside them: the methods are the only place that pairing is interpreted, so no caller can
// read a stale tail of one of them.
type ClientHello struct {
	sni    [maxName]byte
	sniLen int

	alpn     [maxALPNHeld][maxALPNValue]byte
	alpnLen  [maxALPNHeld]int
	alpnHeld int

	ciphers     [maxCiphers]uint16
	ciphersHeld int
	// ciphersSeen counts every cipher offered rather than every one kept, so an overflow
	// is visible instead of reading as a shorter list.
	ciphersSeen int

	extensions     [maxExtension]uint16
	extensionsHeld int
	extensionsSeen int

	sigAlgs     [maxSigAlgs]uint16
	sigAlgsHeld int

	versions     [maxVersions]uint16
	versionsHeld int

	legacyVersion uint16
	// ECH reports an encrypted client hello extension. It is worth knowing on its own: on a
	// connection carrying one the name in this hello is a cover and the real one is not here.
	ECH bool
}

// SNI is the name the program is going for, empty when the hello carried none. It is the
// one field a rule matches on, so it is a string: everything else stays bytes.
func (h ClientHello) SNI() string {
	if h.sniLen == 0 {
		return ""
	}
	return string(h.sni[:h.sniLen])
}

// printableName reports every byte being one a host name or a protocol name can be made of.
// Anything else is a value chosen to be carried somewhere it should not go.
func printableName(b []byte) bool {
	for _, c := range b {
		if !printableASCII(c) || c == ' ' {
			return false
		}
	}
	return len(b) > 0
}

// ALPN is the first application protocol offered, empty when none was.
//
// A value that is not a printable name reads as none. The bytes are still kept, because the
// fingerprint describes the hello as it was sent, but nothing outside this package is handed
// a protocol name with a newline in it.
func (h ClientHello) ALPN() string {
	if h.alpnHeld == 0 {
		return ""
	}
	first := h.alpn[0][:h.alpnLen[0]]
	if !printableName(first) {
		return ""
	}
	return string(first)
}

// Version is the highest TLS version the hello offers, which since TLS 1.3 is in an
// extension rather than in the version field at the front -- that one says 1.2 on every
// modern hello and means nothing.
func (h ClientHello) Version() uint16 {
	highest := uint16(0)
	for _, v := range h.versions[:h.versionsHeld] {
		if isGREASE(v) {
			continue
		}
		if v > highest {
			highest = v
		}
	}
	if highest != 0 {
		return highest
	}
	return h.legacyVersion
}

// ParseClientHello reads a hello out of the window.
//
// It allocates nothing and returns the result by value, so a caller that keeps it local
// pays one struct copy on the stack and no garbage. Anything the window is too short for is
// Incomplete rather than a guess, and anything that is not a handshake record at all is
// NotThis on the first byte.
func ParseClientHello(win []byte) (ClientHello, State) {
	var hello ClientHello
	if len(win) == 0 {
		return hello, Incomplete
	}
	if win[0] != recordHandshake {
		return hello, NotThis
	}

	r := newHelloReader(win)
	kind, ok := r.byte()
	if !ok {
		return hello, Incomplete
	}
	if kind != handshakeHello {
		return hello, NotThis
	}
	// The handshake length is read to tell an unfinished hello from a finished one, and for
	// nothing else. Nothing is sized by it and nothing is skipped by it -- the window stays
	// the only bound on where this reads -- so a length claiming four gigabytes buys an
	// attacker one comparison against a number.
	declared, ok := r.uint24()
	if !ok {
		return hello, Incomplete
	}
	bodyEnd := r.pos + declared

	version, ok := r.uint16()
	if !ok {
		return hello, Incomplete
	}
	hello.legacyVersion = version
	// Random, then the session id, which is a length byte and that many bytes after it.
	if !r.skip(32) || !r.skipVector8() {
		return hello, Incomplete
	}

	ciphersLen, ok := r.uint16()
	if !ok {
		return hello, Incomplete
	}
	if ciphersLen%2 != 0 {
		return hello, NotThis
	}
	for range ciphersLen / 2 {
		suite, ok := r.uint16()
		if !ok {
			return hello, Incomplete
		}
		if isGREASE(suite) {
			continue
		}
		hello.ciphersSeen++
		if hello.ciphersHeld < maxCiphers {
			hello.ciphers[hello.ciphersHeld] = suite
			hello.ciphersHeld++
		}
	}

	// Compression methods, which every modern hello sets to the single null method.
	if !r.skipVector8() {
		return hello, Incomplete
	}

	// A hello may legitimately end here: the extensions block is optional in the protocol,
	// even though nothing has sent a hello without one this century. Which of the two this is
	// -- a hello with no extensions, or a hello whose extensions have not arrived -- is what
	// the declared length answers, and it is the reason that length is read at all.
	extensionsLen, ok := r.uint16()
	if !ok {
		if r.pos >= bodyEnd {
			return hello, Parsed
		}
		return hello, Incomplete
	}
	if state := hello.readExtensions(&r, int(extensionsLen)); state != Parsed {
		return hello, state
	}
	return hello, Parsed
}

// readExtensions walks the extension block. It is a loop rather than a descent, and every
// extension it does not know is skipped by its own declared length, so an unknown one costs
// nothing and cannot steer the walk.
func (h *ClientHello) readExtensions(r *helloReader, total int) State {
	end := r.pos + total
	for r.pos < end {
		kind, ok := r.uint16()
		if !ok {
			return Incomplete
		}
		size, ok := r.uint16()
		if !ok {
			return Incomplete
		}
		after := r.pos + int(size)

		if !isGREASE(kind) {
			h.extensionsSeen++
			if h.extensionsHeld < maxExtension {
				h.extensions[h.extensionsHeld] = kind
				h.extensionsHeld++
			}
		}

		var state State
		switch kind {
		case extServerName:
			state = h.readServerName(r)
		case extALPN:
			state = h.readALPN(r)
		case extSupportedVersions:
			state = h.readSupportedVersions(r)
		case extSignatureAlgs:
			state = h.readSignatureAlgorithms(r)
		case extECH:
			h.ECH = true
			state = Parsed
		default:
			state = Parsed
		}
		if state == Incomplete {
			return Incomplete
		}

		// Every extension leaves the cursor where its own length says it ends, whatever its
		// body did with the bytes. An arm that read short or long would otherwise walk the
		// rest of the block off by that much and report extensions nobody sent.
		if !r.seek(after) {
			return Incomplete
		}
	}
	return Parsed
}

// readServerName keeps the host name. Only the host_name kind exists and only the first is
// kept: a hello carrying two is not a client, and the first is what a server would use.
func (h *ClientHello) readServerName(r *helloReader) State {
	listLen, ok := r.uint16()
	if !ok {
		return Incomplete
	}
	end := r.pos + int(listLen)
	for r.pos < end {
		kind, ok := r.byte()
		if !ok {
			return Incomplete
		}
		size, ok := r.uint16()
		if !ok {
			return Incomplete
		}
		if kind != nameHostName || h.sniLen != 0 || int(size) > maxName {
			if !r.skip(int(size)) {
				return Incomplete
			}
			continue
		}
		if !r.copyInto(h.sni[:size]) {
			return Incomplete
		}
		// A name with a control byte in it is not a name any server was ever asked for, and
		// it is a name that would be carried into a log line and an event field. It is
		// dropped rather than kept: reporting that a connection asked for nothing readable
		// is true, and reporting the bytes is how a newline ends up inside a header.
		if !printableName(h.sni[:size]) {
			continue
		}
		h.sniLen = int(size)
	}
	return Parsed
}

// readALPN keeps the protocols offered, first one first, which is the one the connection
// will almost certainly end up speaking.
func (h *ClientHello) readALPN(r *helloReader) State {
	listLen, ok := r.uint16()
	if !ok {
		return Incomplete
	}
	end := r.pos + int(listLen)
	for r.pos < end {
		size, ok := r.byte()
		if !ok {
			return Incomplete
		}
		if h.alpnHeld >= maxALPNHeld || int(size) > maxALPNValue {
			if !r.skip(int(size)) {
				return Incomplete
			}
			continue
		}
		if !r.copyInto(h.alpn[h.alpnHeld][:size]) {
			return Incomplete
		}
		h.alpnLen[h.alpnHeld] = int(size)
		h.alpnHeld++
	}
	return Parsed
}

// readSupportedVersions keeps what the client will actually speak. This is where a TLS 1.3
// hello says so; the version at the front of the hello says 1.2 for the sake of middleboxes.
func (h *ClientHello) readSupportedVersions(r *helloReader) State {
	listLen, ok := r.byte()
	if !ok {
		return Incomplete
	}
	end := r.pos + int(listLen)
	for r.pos < end {
		version, ok := r.uint16()
		if !ok {
			return Incomplete
		}
		if h.versionsHeld < maxVersions {
			h.versions[h.versionsHeld] = version
			h.versionsHeld++
		}
	}
	return Parsed
}

// readSignatureAlgorithms keeps the list in the order it arrived, because the fingerprint
// hashes it in that order rather than sorted.
func (h *ClientHello) readSignatureAlgorithms(r *helloReader) State {
	listLen, ok := r.uint16()
	if !ok {
		return Incomplete
	}
	end := r.pos + int(listLen)
	for r.pos < end {
		alg, ok := r.uint16()
		if !ok {
			return Incomplete
		}
		if isGREASE(alg) {
			continue
		}
		if h.sigAlgsHeld < maxSigAlgs {
			h.sigAlgs[h.sigAlgsHeld] = alg
			h.sigAlgsHeld++
		}
	}
	return Parsed
}

// isGREASE reports the reserved values clients scatter through their hellos to keep servers
// honest about ignoring what they do not know. They are random per connection, so anything
// that counted them would produce a different fingerprint for every connection one client
// makes.
func isGREASE(v uint16) bool { return byte(v>>8) == byte(v) && v&0x0f == 0x0a }

// helloReader walks the handshake bytes inside one or more TLS records.
//
// A hello larger than one record is ordinary now that keys are post-quantum, and a reader
// that stopped at the first record boundary would read the record header of the second as
// hello content -- so this steps over the headers as it goes, and a field split across two
// records reads as the field it is.
type helloReader struct {
	win []byte
	// at is where the next byte comes from, and end is where the current record's payload
	// stops. next is where the record after this one begins.
	at, end, next int
	// pos counts the handshake bytes read so far, with the record headers left out of the
	// count. Every length in a hello is measured in those, so a structure that spans a
	// record boundary would otherwise be read as five bytes longer per boundary it crossed.
	pos int
	// bad is set when the record framing itself is wrong, which no further byte can fix.
	bad bool
}

func newHelloReader(win []byte) helloReader {
	r := helloReader{win: win}
	r.openRecord(0)
	return r
}

// openRecord starts reading the record whose header begins at p.
func (r *helloReader) openRecord(p int) {
	if p+recordHeaderSize > len(r.win) {
		// Not enough for a header yet: leave the cursor past the end so every read reports
		// that it ran out rather than reading the partial header as content.
		r.at, r.end, r.next = len(r.win)+1, len(r.win), len(r.win)
		return
	}
	if r.win[p] != recordHandshake {
		r.bad = true
		r.at, r.end, r.next = len(r.win)+1, len(r.win), len(r.win)
		return
	}
	size := int(r.win[p+3])<<8 | int(r.win[p+4])
	r.at = p + recordHeaderSize
	r.end = min(r.at+size, len(r.win))
	r.next = r.at + size
}

// advance moves past the current record when the cursor has reached its end, and reports
// whether there is a byte to read.
func (r *helloReader) advance() bool {
	for r.at >= r.end {
		if r.bad || r.at > len(r.win) || r.next > len(r.win) {
			return false
		}
		r.openRecord(r.next)
		if r.at > len(r.win) {
			return false
		}
	}
	return true
}

func (r *helloReader) byte() (byte, bool) {
	if !r.advance() {
		return 0, false
	}
	b := r.win[r.at]
	r.at++
	r.pos++
	return b, true
}

func (r *helloReader) uint16() (uint16, bool) {
	hi, ok := r.byte()
	if !ok {
		return 0, false
	}
	lo, ok := r.byte()
	if !ok {
		return 0, false
	}
	return uint16(hi)<<8 | uint16(lo), true
}

// uint24 reads the three-byte length a handshake message carries.
func (r *helloReader) uint24() (int, bool) {
	hi, ok := r.byte()
	if !ok {
		return 0, false
	}
	rest, ok := r.uint16()
	if !ok {
		return 0, false
	}
	return int(hi)<<16 | int(rest), true
}

// skip moves n bytes on, one at a time, because n bytes from here may cross into the next
// record and the count is bounded by the window either way.
func (r *helloReader) skip(n int) bool {
	for range n {
		if _, ok := r.byte(); !ok {
			return false
		}
	}
	return true
}

// skipVector8 skips a length byte and the bytes it counts.
func (r *helloReader) skipVector8() bool {
	size, ok := r.byte()
	if !ok {
		return false
	}
	return r.skip(int(size))
}

// copyInto fills dst, which is fixed room inside the result rather than anything sized by
// the network.
func (r *helloReader) copyInto(dst []byte) bool {
	for i := range dst {
		b, ok := r.byte()
		if !ok {
			return false
		}
		dst[i] = b
	}
	return true
}

// seek moves the cursor to a count of handshake bytes read, which is how an extension is
// left exactly where its own length said it ends.
func (r *helloReader) seek(to int) bool {
	if to < r.pos {
		// An extension whose body read past its own declared length is a malformed hello,
		// not something to rewind into.
		return false
	}
	return r.skip(to - r.pos)
}
