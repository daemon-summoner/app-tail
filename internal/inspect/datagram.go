// SPDX-License-Identifier: MIT

package inspect

// The readable part of a flow that has no stream to accumulate.
//
// A datagram flow is not a connection with an opening: every datagram stands alone, and the
// two things worth reading are each whole inside one. A plain DNS query carries the name it
// asks for, which is what catches a program that brought its own resolver and pointed it past
// app-tail's. A QUIC packet says it is QUIC in its first five bytes and says nothing else in
// the clear, which is still worth knowing: the name inside is encrypted, and every browser
// refused QUIC falls back to TCP where the handshake is readable.

// Datagrams reads the datagrams one flow sends.
//
// Like Stream it is owned by the single goroutine moving that direction, so nothing here is
// synchronised. Unlike Stream it does not accumulate: a datagram that says nothing is dropped
// rather than kept, because the next one is a fresh message rather than the rest of this one.
type Datagrams struct {
	opts DatagramOptions
	// done is set once this flow has been named, after which every datagram is one field
	// comparison. It is set only for what a flow is for its whole life: QUIC stays QUIC, and
	// a resolver goes on asking different names.
	done bool
	// protocol is what the flow turned out to be, carried so a signature match can say so.
	protocol string
	// scanned is how many bytes of this flow have been read against the signatures. The
	// budget is the stream's window, spent across as many datagrams as it takes: a datagram
	// flow has no opening to accumulate, so "the first four kilobytes it sends" is the same
	// sentence for both and the same bounded cost.
	scanned int
}

// DatagramOptions are the parts of the decision the runner owns.
type DatagramOptions struct {
	// Report is where what a datagram said is reported. A flow with none is one whose
	// signatures are the only reason it is read.
	Report Report
	// Signatures are the byte patterns the opening datagrams are read against, nil when
	// payload signatures are off, and Matched is where a match is reported.
	Signatures *Signatures
	Matched    SignatureReport
}

// scanning reports the datagrams being read against signatures.
func (o DatagramOptions) scanning() bool { return o.Signatures != nil && o.Matched != nil }

// NewDatagrams begins reading one datagram flow. Nothing to report to reads nothing.
func NewDatagrams(opts DatagramOptions) *Datagrams {
	if opts.Report == nil && !opts.scanning() {
		return nil
	}
	flow := &Datagrams{opts: opts}
	if !opts.scanning() {
		// Nothing reads the bytes, so the budget starts spent and a named flow costs one
		// comparison per datagram.
		flow.scanned = windowSize
	}
	return flow
}

// Up is handed each datagram the local side sends, before it is passed on, and reports
// whether the flow is to be stopped.
//
// It recovers from a panic for the reason Stream.Up does: these are bytes an attacker
// chooses, and the cost of being wrong about them must be one flow carried uninspected rather
// than an interface that stops. Those two are the only places in this package that recover,
// and they are the two the data path enters through.
func (d *Datagrams) Up(b []byte) (stop bool) {
	if d == nil || len(b) == 0 || (d.done && d.scanned >= windowSize) {
		return false
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			d.done, d.scanned = true, windowSize
			stop = false
		}
	}()

	if !d.done && d.name(b) {
		return true
	}
	if d.scanned >= windowSize {
		return false
	}
	return d.match(b)
}

// name works out what the flow is and reports it, and answers whether the flow is to be
// stopped for what it said.
func (d *Datagrams) name(b []byte) bool {
	if IsQUIC(b) {
		// Nothing further about the flow is readable, so this is the last datagram named.
		d.done, d.protocol = true, ProtocolQUIC
		return d.say(Handshake{Protocol: ProtocolQUIC})
	}
	found, ok := DNSQuestion(b)
	if !ok {
		return false
	}
	d.protocol = ProtocolDNS
	return d.say(Handshake{Protocol: ProtocolDNS, Name: found})
}

// match reads one datagram against the signatures, and spends it from the flow's budget.
//
// Each datagram is read whole and on its own. A datagram is a message: a pattern spanning two
// of them is not one pattern the way a pattern spanning two chunks of a stream is, and
// stitching them would be accumulating a stream out of things that are not one.
func (d *Datagrams) match(b []byte) bool {
	d.scanned += len(b)
	found, matched := d.opts.Signatures.Match(b)
	if !matched {
		return false
	}
	return d.opts.Matched(found, d.protocol)
}

// say reports what a datagram said, where there is anything to report it to.
func (d *Datagrams) say(h Handshake) bool {
	if d.opts.Report == nil {
		return false
	}
	return d.opts.Report(h)
}

// Down is handed each datagram the far side sends. Nothing is read from it: a DNS answer
// repeats the question that was already read on the way up, and there is nothing else a
// datagram flow carries in the clear that the outbound side did not say first.
func (d *Datagrams) Down([]byte) bool { return false }

// Close ends the reading. There is no window to release: a datagram is examined and dropped
// where it lands.
func (d *Datagrams) Close() {}
