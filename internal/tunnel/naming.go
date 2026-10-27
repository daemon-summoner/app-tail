// SPDX-License-Identifier: MIT

package tunnel

// Which connection a name belongs to.
//
// Two networks can carry the same addresses -- two companies both on 10.0.0.0/8, two
// environments cloned from one template -- and then an address no longer says which
// network was meant. A name can: every connection owns a suffix of its own, so
// db.office.internal and db.lab.internal are two destinations even when both resolve to
// 10.0.0.5, and both are reachable at the same time without anything being switched.
//
// The suffix is built from the connection's short name, which is already unique, so no
// two connections can claim one suffix and nothing here has to enforce that.

import (
	"strings"
)

// Naming is the set of connection suffixes, and the answer to "which connection does this
// name belong to". It is a value: a caller holds the naming it started with rather than
// one another goroutine is rewriting mid-lookup.
type Naming struct {
	// bySuffix maps a lowercase suffix to a connection id. Nil is a complete answer: an
	// installation with no connections named yet belongs to nothing, which is what an
	// empty map already says.
	bySuffix map[string]string
	// byID is the reverse, for the surfaces that show a connection its own suffix.
	byID map[string]string
}

// NewNaming builds the lookup from each connection's suffix, keyed by connection id. A
// connection with an empty suffix is left out rather than mapped to nothing: an empty
// suffix would match every name.
func NewNaming(suffixes map[string]string) Naming {
	n := Naming{
		bySuffix: make(map[string]string, len(suffixes)),
		byID:     make(map[string]string, len(suffixes)),
	}
	for id, suffix := range suffixes {
		suffix = normalizeName(suffix)
		if id == "" || suffix == "" {
			continue
		}
		n.bySuffix[suffix] = id
		n.byID[id] = suffix
	}
	return n
}

// SuffixOf is the suffix names on one connection end in, or empty when it has none.
func (n Naming) SuffixOf(id string) string { return n.byID[id] }

// Len is how many connections are named.
func (n Naming) Len() int { return len(n.byID) }

// Match says which connection a name belongs to.
//
// host is what a caller asked for; the returned name is what to ask that connection --
// the same name with the connection's suffix taken off, which is what the network itself
// knows the host as. A name that is the suffix exactly names the connection and no host on
// it, and comes back with an empty name rather than as no match: it is still that
// connection's name, and sending it to a public resolver because nothing matched is the
// leak this convention exists to prevent.
//
// The longest matching suffix wins. Two connections cannot nest under one zone, but the
// zone is configurable, and the alternative -- the first match in map order -- would decide
// by hash order.
func (n Naming) Match(host string) (id, name string, ok bool) {
	host = normalizeName(host)
	if host == "" {
		return "", "", false
	}
	longest := 0
	for suffix, tunnelID := range n.bySuffix {
		var candidate string
		switch {
		case host == suffix:
			candidate = ""
		case strings.HasSuffix(host, "."+suffix):
			candidate = strings.TrimSuffix(host, "."+suffix)
		default:
			continue
		}
		if ok && len(suffix) <= longest {
			continue
		}
		id, name, ok, longest = tunnelID, candidate, true, len(suffix)
	}
	return id, name, ok
}

// normalizeName lowercases a name and drops the trailing dot a fully qualified one
// carries, so "DB.Office.Internal." and "db.office.internal" are one name.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
