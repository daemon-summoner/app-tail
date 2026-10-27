// SPDX-License-Identifier: MIT

package inspect

// Byte patterns read over what a connection carries, rather than over what it is for.
//
// # Why there is no feed for this
//
// Everything else here matches names and addresses, and those have feeds because lists of
// them exist, are maintained, and mean the same thing to everybody. Stream signatures have no
// such corpus. The rule languages that have one describe packets -- headers, lengths,
// sequence numbers, offsets into a datagram -- and none of that reaches a reassembled stream
// in a userspace VPN; the other kind describes files at rest, which is not what this carries.
// Inventing a set of patterns and shipping it as a threat library would be the dishonest half
// of the feature, so what is shipped is the matcher and the patterns are the user's.
//
// That is not a smaller feature than it sounds. The case a list of names cannot reach is a
// string that must never leave this machine in the clear: a user who puts a unique token in
// this list is told, on the connection that carried it, that it left. Only they can write that
// pattern, and nothing else in app-tail can answer it.
//
// # What it does not do
//
// The scan is one pass over the same bounded window the rest of this package reads, run once
// per flow, and nothing after it is read. A pattern that appears a megabyte into a transfer is
// not seen. Nor is anything inside TLS: this reads the bytes as they are carried, and carried
// bytes are encrypted on nearly every connection that matters.
//
// It also cannot prevent what it finds. The window is filled by chunks that were written on as
// they arrived, so by the time a pattern completes, the bytes before it have left. Refusing on
// a signature stops the rest of the connection, which is worth having and is not the same
// claim the name and address rules make.

import "github.com/sellitus/app-tail/internal/sigscan"

// Signatures is a compiled pattern set under the name a finding reports it as.
//
// The name lives here rather than in the matcher for the reason Rules keeps its source names:
// what the user calls the thing that matched is a property of where the entries came from, and
// the matcher's job is to find bytes.
type Signatures struct {
	set    *sigscan.Set
	source string
}

// CompileSignatures builds the set from the entries the user wrote, reported under source.
//
// Entries that are blank are skipped, since a settings list round-trips through a text box.
// An entry that will not parse is refused rather than skipped: a signature is a control the
// user asked for by name, and one silently dropped is the failure this must not have.
//
// Nothing to match compiles to nil, which every caller already reads as inspection having
// nothing to say.
func CompileSignatures(source string, entries []string) (*Signatures, error) {
	written := make([]sigscan.Signature, 0, len(entries))
	for _, entry := range entries {
		if isBlank(entry) {
			continue
		}
		sig, err := sigscan.Parse(entry)
		if err != nil {
			return nil, err
		}
		written = append(written, sig)
	}

	set, err := sigscan.Compile(written)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, nil
	}
	return &Signatures{set: set, source: source}, nil
}

// Match reports the first signature the window carries, and whether it carries one.
//
// The finding names the signature rather than the bytes that matched. That is not brevity: the
// bytes are the pattern, the pattern is often a secret the user is watching for, and a finding
// that echoed it would copy that secret into a log line, an event field and a card -- turning
// the thing that watches for a leak into one.
func (s *Signatures) Match(win []byte) (Finding, bool) {
	if s == nil {
		return Finding{}, false
	}
	name, ok := s.set.Match(win)
	if !ok {
		return Finding{}, false
	}
	return Finding{Signal: SignalPayload, Value: name, Source: s.source}, true
}

// Count is how many patterns are in force.
func (s *Signatures) Count() int {
	if s == nil {
		return 0
	}
	return s.set.Count()
}

// isBlank reports a line holding nothing but space, which is what an empty row in a settings
// list arrives as.
func isBlank(entry string) bool {
	for i := 0; i < len(entry); i++ {
		switch entry[i] {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}
	return true
}
