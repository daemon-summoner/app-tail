// SPDX-License-Identifier: MIT

package app

// The opening bytes of a connection, as the runner reads them.
//
// This is the half of inspection that reaches traffic nothing asked app-tail about. A program
// with its own resolver, or one that dialled an address it was compiled with, gave no name to
// the setup-time check -- but a TLS client still sends the name it wants in the clear, before
// the encryption starts, and a plain web request still carries a host. Reading those is the
// difference between a name list that covers what app-tail resolves and one that covers what
// app-tail carries.

import (
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// Watch answers what should read one connection's opening bytes, and nil for one nothing is
// to read.
//
// Nil is the common answer and is deliberately cheap: the switch being off, inspection being
// paused, and every state before the first compile all reach it without allocating. It must
// be a nil interface rather than a nil stream inside one -- the paths that carry bytes
// compare the interface against nil, and a typed nil would read as an inspector to every one
// of them.
func (r *ipsRunner) Watch(f inspect.Flow) netpipe.Stream {
	if r == nil || !r.handshake.Load() {
		return nil
	}
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return nil
	}
	// Reading the opening bytes is only worth the window if something could match them, which
	// is the name matcher or the signatures.
	signatures := r.signatures.Load()
	if signatures == nil && (!r.names.Load() || r.rules.Load() == nil) {
		return nil
	}

	opts := inspect.StreamOptions{Fingerprint: r.fingerprints.Load(), Signatures: signatures}
	if signatures != nil {
		opts.Matched = func(found inspect.Finding, protocol string) bool {
			return r.carried(f, found, protocol)
		}
	}
	return inspect.NewStream(opts, func(h inspect.Handshake) bool { return r.opened(f, h) })
}

// WatchDatagrams answers what should read one datagram flow, and nil for one nothing is to
// read. The switches are the same ones the connection path reads, for the same reason: a user
// who turned the opening bytes off did not mean "except over UDP".
//
// A name asked for here is a name asked of somebody else's resolver. That is the case this
// reaches and the name path cannot: app-tail's own resolver never saw it.
func (r *ipsRunner) WatchDatagrams(f inspect.Flow) netpipe.Stream {
	if r == nil || !r.handshake.Load() {
		return nil
	}
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return nil
	}
	// The ledger reads the questions even where no rule could match one, because a run of
	// long random names is a finding on a machine with nothing typed into any list.
	signatures := r.signatures.Load()
	if signatures == nil && r.watch.Load() == nil && (!r.names.Load() || r.rules.Load() == nil) {
		return nil
	}

	opts := inspect.DatagramOptions{
		Report:     func(h inspect.Handshake) bool { return r.sent(f, h) },
		Signatures: signatures,
	}
	if signatures != nil {
		opts.Matched = func(found inspect.Finding, protocol string) bool {
			return r.carried(f, found, protocol)
		}
	}
	return inspect.NewDatagrams(opts)
}

// sent is what one datagram said, and answers whether the flow is to be stopped for it.
func (r *ipsRunner) sent(f inspect.Flow, h inspect.Handshake) bool {
	if h.Protocol == inspect.ProtocolDNS && h.Name != "" {
		// The same ledger the app's own resolver writes to. A machine asking a resolver
		// app-tail does not run is exactly where a tunnel would be, so leaving these out
		// would be leaving out the case the detector is for.
		r.question(h.Name)
	}
	return r.opened(f, h)
}

// opened is what one connection's opening bytes said, and answers whether the connection is
// to be stopped for it.
//
// The rules are read again here rather than captured when the stream was made: a set the user
// edited while a connection was still opening should be the set that connection is measured
// against, and the window between the two is long enough for that to happen.
func (r *ipsRunner) opened(f inspect.Flow, h inspect.Handshake) bool {
	if h.Name == "" {
		return false
	}
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return false
	}
	if !r.names.Load() {
		return false
	}
	rules := r.rules.Load()
	if rules == nil {
		return false
	}

	// Only the name is asked. Where the connection is bound was already measured at setup,
	// on every path that knew it, and asking again would record one connection twice.
	found, ok := rules.Name(h.Name)
	if !ok {
		return false
	}
	// The name came off the wire rather than from a program that asked for it, and the
	// sentence a user reads has to say so.
	found.Signal = inspect.SignalHandshake

	refuse := r.prevent.Load()
	r.note(Detection{
		At:          r.now(),
		Signal:      string(found.Signal),
		Value:       found.Value,
		Source:      found.Source,
		Reason:      found.Reason(),
		Where:       f.Where,
		Peer:        f.Peer,
		Protocol:    h.Protocol,
		Fingerprint: h.Fingerprint,
		Refused:     refuse,
	})
	return refuse
}
