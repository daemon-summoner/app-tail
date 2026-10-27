// SPDX-License-Identifier: MIT

package app

// The byte patterns the user wrote, as the runner holds them.
//
// This is the one part of inspection with no feed behind it and no built-in set: what is
// matched against is written entirely by whoever runs app-tail, because no maintained corpus
// of stream signatures exists to download and inventing one would be shipping a guess as a
// threat library. The reason to have it anyway is the question a list of names cannot ask --
// whether a particular string left this machine in the clear.

import (
	"strings"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// compileSignatures brings the live pattern set to what the entries say, reported under
// source.
//
// A set that will not compile leaves the set already in force applying, for the reason the
// rules do: one mistyped line should not silently take a control the user asked for out of
// service. The failure is an event and a log line rather than something handed back, because
// the caller is a reconcile with nothing else it could do with it.
func (r *ipsRunner) compileSignatures(source string, entries []string) {
	// The entries are short enough to key on themselves, unlike the feeds: the ceiling is a
	// few hundred lines of a couple of hundred bytes.
	key := source + "\x00" + strings.Join(entries, "\x00")
	r.mu.Lock()
	unchanged := key == r.builtPatterns
	r.mu.Unlock()
	if unchanged {
		return
	}

	signatures, err := inspect.CompileSignatures(source, entries)
	if err != nil {
		r.record(telemetry.CodeIPSFailed,
			"The traffic-inspection signatures could not be built; the ones already in force "+
				"still apply.",
			map[string]string{"error": err.Error()})
		r.log.Warn("building the traffic-inspection signatures failed", "error", err)
		return
	}

	r.signatures.Store(signatures)
	r.mu.Lock()
	r.builtPatterns = key
	r.mu.Unlock()
}

// clearSignatures takes the patterns out of memory, which is what switching them off means.
func (r *ipsRunner) clearSignatures() {
	r.signatures.Store(nil)
	r.mu.Lock()
	r.builtPatterns = ""
	r.mu.Unlock()
}

// signatureCount is how many patterns are in force, for the card.
func (r *ipsRunner) signatureCount() int {
	if r == nil {
		return 0
	}
	return r.signatures.Load().Count()
}

// carried is what one flow's opening bytes matched, and answers whether the flow is to be
// stopped for it.
//
// Unlike a name or an address, this is not prevention and the report says so by what it does
// rather than by what it claims: the bytes that matched were written on as they arrived, so
// what refusing stops is the rest of the flow.
func (r *ipsRunner) carried(f inspect.Flow, found inspect.Finding, protocol string) bool {
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return false
	}

	refuse := r.prevent.Load()
	r.note(Detection{
		At:       r.now(),
		Signal:   string(found.Signal),
		Value:    found.Value,
		Source:   found.Source,
		Reason:   found.Reason(),
		Where:    f.Where,
		Peer:     f.Peer,
		Protocol: protocol,
		Refused:  refuse,
	})
	return refuse
}
