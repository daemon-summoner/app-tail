// SPDX-License-Identifier: MIT

package inspect

// The first bytes of a connection, which is where the name lives on traffic that was dialled
// as an address.
//
// The shape is what keeps this off the hot path: a bounded window at the start of a
// connection, a verdict forced when it closes, and nothing looked at afterwards. A transfer
// past its first four kilobytes costs one nil comparison per chunk, so there is no case where
// a download is killed halfway through.
//
// What a connection is for is decided before anything of it has been written on, because the
// name is in the opening bytes and those are read before they are passed along. What a
// connection carries is decided over the whole window, so by the time a signature matches, the
// bytes ahead of it in the window have already gone -- refusing on one stops the rest of the
// connection rather than preventing it. The two are separate switches for that reason among
// others, and the difference is stated where the switch is.

import "sync"

const (
	// windowSize is how much of a connection's opening bytes are read. A post-quantum
	// ClientHello runs to about two kilobytes, so this covers one plus the split across two
	// records that a large one arrives in, and an HTTP request head lands inside the first
	// few hundred bytes. It is a constant rather than a setting because a smaller one
	// silently stops seeing modern hellos and a larger one buys nothing.
	windowSize = 4096
	// maxParses is how many times one window is read before the answer is whatever has been
	// worked out by then.
	//
	// Every parser reads the whole window from the front, which is what makes a structure
	// split across chunks read as the structure it is -- and what would make a client sending
	// one byte at a time quadratic in the window. Counting attempts rather than requiring the
	// window to grow by some amount is what keeps both properties: an honest hello is read on
	// the chunk that completes it however small that chunk is, and a client dripping bytes
	// gets sixty-four reads and then a verdict.
	maxParses = 64
)

// Handshake is what the opening bytes of one connection said.
//
// Every field is optional. A window that filled with something unrecognised carries only the
// protocol, and often not even that: reporting a connection as unreadable is a true answer,
// and guessing at a name is not.
type Handshake struct {
	// Protocol is what the bytes are, in the words the card shows.
	Protocol string
	// Name is what the connection is really for -- the SNI of a TLS hello or the Host of an
	// HTTP request. It is the field a rule matches on.
	Name string
	// ALPN is the application protocol offered first, on a TLS connection that offered any.
	ALPN string
	// Fingerprint is the client fingerprint, empty when fingerprinting is off or the hello
	// was too unusual to fingerprint honestly.
	Fingerprint string
	// Version is the TLS version the client offered, zero on anything that is not TLS.
	Version uint16
	// ECH reports the hello carrying an encrypted client hello, which means the name in it
	// is a cover and the real one is not readable here. It is worth reporting on its own.
	ECH bool
}

// Report is what a stream hands its finding to. It returns true when the connection is to be
// stopped, which is a decision about mode and lists that this package does not make.
type Report func(Handshake) bool

// SignatureReport is what a signature match is handed to, alongside what the connection turned
// out to be speaking. It returns true when the connection is to be stopped.
//
// It is separate from Report because the two are different signals reported at different
// moments: what a connection is for is known as soon as its opening parses, and what it
// carries is known only once the window can grow no further.
type SignatureReport func(found Finding, protocol string) bool

// StreamOptions are the parts of the decision the runner owns.
type StreamOptions struct {
	// Fingerprint computes the client fingerprint. It is a switch of its own because it is
	// the one field here that describes the program rather than the destination.
	Fingerprint bool
	// Signatures are the byte patterns the window is read against once it can grow no
	// further, nil when payload signatures are off.
	Signatures *Signatures
	// Matched is where a signature match is reported. Signatures without it would be a
	// window held open to answer nobody, so the two are read together as one switch.
	Matched SignatureReport
}

// scanning reports the window being read against signatures, which is what decides whether it
// is held past the moment the connection is named.
func (o StreamOptions) scanning() bool { return o.Signatures != nil && o.Matched != nil }

// Stream reads one connection's opening bytes.
//
// It is owned by the single goroutine copying that direction, so nothing here is
// synchronised: the window is written by that goroutine and read by it, and the report is
// made on it. That is what makes the cost one copy and one parse rather than a lock per
// chunk.
type Stream struct {
	opts   StreamOptions
	report Report

	win *[windowSize]byte
	// held is how much of the window is filled, and tries how many times it has been read.
	held  int
	tries int
	// named is set once the connection has been reported. With signatures off that is the
	// end of the stream; with them on the window is still held, because what a connection is
	// for and what it carries are answered at different points.
	named bool
	// protocol is what the connection turned out to be speaking, carried so a signature match
	// found later can say so too.
	protocol string
	// done is set once a verdict has been reached, after which every chunk is one field
	// comparison and nothing else.
	done bool
}

// windows holds the opening-bytes buffers between connections.
//
// A window is returned the moment there is nothing further to read from it, rather than when
// the connection closes. That ordering is the whole defence against a client opening thousands
// of connections and sending one byte down each: with signatures off an unrecognised opening
// reaches its verdict on the first chunk, so the adversarial case releases its window sooner
// than an honest one does.
//
// Signatures move that boundary and are the reason they are a switch of their own: the window
// is then held until it fills or its reads run out, so the same thousands of one-byte
// connections hold one window each for as long as they stay open. What bounds it is the same
// four kilobytes -- the cost is transient memory in proportion to open connections, which is
// what the setting says.
var windows sync.Pool

func takeWindow() *[windowSize]byte {
	if held, ok := windows.Get().(*[windowSize]byte); ok {
		return held
	}
	return new([windowSize]byte)
}

// NewStream begins reading one connection. Nothing to report to is a stream that reads
// nothing, so a caller that has not decided cannot end up with a window it never reads.
func NewStream(opts StreamOptions, report Report) *Stream {
	if report == nil && !opts.scanning() {
		return nil
	}
	return &Stream{opts: opts, report: report}
}

// Up is handed each chunk read from the client before it is written on, and reports whether
// the connection is to be stopped.
//
// Before, not after: a parser run on bytes that have already been written has nothing left to
// prevent, and would make every claim about prevention here false.
//
// It recovers from a panic, as Datagrams.Up does: those two are the only places in this
// package that do, and they are the two the data path enters through. Everything they call is
// bounded and checked, but these are bytes an attacker chooses, and the cost of being wrong
// about that must be one connection carried uninspected rather than a data path that stops.
func (s *Stream) Up(b []byte) (stop bool) {
	if s == nil || s.done || len(b) == 0 {
		return false
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.finish()
			stop = false
		}
	}()

	if s.win == nil {
		s.win = takeWindow()
	}
	s.held += copy(s.win[s.held:], b)
	s.tries++

	// The window being full and the reads being used up are the same thing to the parser: in
	// both, no further byte will be looked at, so an unfinished parse is as finished as it is
	// going to get and the verdict is reached now rather than held.
	return s.attempt(s.held >= windowSize || s.tries >= maxParses)
}

// Down is handed each chunk read from upstream. Nothing is read from it: the only thing a
// server sends in the clear that is not already visible on the way up is a plain HTTP
// response head, and the request that asked for it was read here first. Reading the far side
// as well would double the window budget for a second copy of the same answer.
func (s *Stream) Down([]byte) bool { return false }

// Close releases the window. It is called however the connection ended, and doing it twice
// is safe: a stream that reached its verdict has already let go.
func (s *Stream) Close() { s.finish() }

// attempt reads the window for as much of it as has been asked for. full says the window can
// grow no further, which is what turns an unfinished parse into a verdict rather than a wait,
// and what releases the signature scan.
func (s *Stream) attempt(full bool) bool {
	win := s.win[:s.held]

	if !s.named {
		found, settled := s.parse(win, full)
		if !settled {
			return false
		}
		s.named, s.protocol = true, found.Protocol
		if s.report != nil {
			// The window is still held across this call, unlike the case below: a stop
			// decided on the name ends the connection, and four kilobytes held across a call
			// that is about to release them anyway costs nothing.
			if s.report(found) {
				s.finish()
				return true
			}
		}
		if !s.opts.scanning() {
			// Nothing else reads this window, so it goes back now rather than at close.
			s.finish()
			return false
		}
	}

	// The signatures are read once, over as much as the window ever holds, so a pattern split
	// across chunks is still one pattern and no chunk is walked twice.
	if !full {
		return false
	}
	return s.scan(win)
}

// parse reads the window as each thing it might be, in the order of what is actually on the
// wire, and reports whether it has settled on one. Not settled is a parse that would read
// further bytes, which can only be answered while the window can still grow.
func (s *Stream) parse(win []byte, full bool) (Handshake, bool) {
	hello, state := ParseClientHello(win)
	switch state {
	case Parsed:
		found := Handshake{
			Protocol: ProtocolTLS,
			Name:     hello.SNI(),
			ALPN:     hello.ALPN(),
			Version:  hello.Version(),
			ECH:      hello.ECH,
		}
		if s.opts.Fingerprint {
			found.Fingerprint = hello.JA4(TransportTCP)
		}
		return found, true
	case Incomplete:
		if !full {
			return Handshake{}, false
		}
		// A hello that did not fit is still a TLS connection, and saying so is better than
		// saying nothing: it is the difference between a connection nothing could read and
		// one nothing tried to.
		return Handshake{Protocol: ProtocolTLS}, true
	}

	head, state := ParseHTTPHead(win)
	switch state {
	case Parsed:
		return Handshake{Protocol: ProtocolHTTP, Name: head.Host()}, true
	case Incomplete:
		if !full {
			return Handshake{}, false
		}
		return Handshake{Protocol: ProtocolHTTP}, true
	}

	// Neither, and no further byte will make it either, so the answer is reached now.
	protocol := bannerOf(win)
	if protocol == "" && isDNSOverTCP(win) {
		protocol = ProtocolDNS
	}
	return Handshake{Protocol: protocol}, true
}

// scan reads the window against the signatures, which is the last thing a stream does however
// it turns out. The window is released before the report is made, so the report costs nothing
// in held memory however long it takes.
func (s *Stream) scan(win []byte) bool {
	found, matched := s.opts.Signatures.Match(win)
	report, protocol := s.opts.Matched, s.protocol
	s.finish()
	if !matched {
		return false
	}
	return report(found, protocol)
}

// finish drops the window and stops the stream reading. Everything after it is one field
// comparison per chunk.
func (s *Stream) finish() {
	if s == nil {
		return
	}
	if s.win != nil {
		windows.Put(s.win)
		s.win = nil
	}
	s.held, s.tries, s.done = 0, 0, true
}
