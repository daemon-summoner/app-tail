// SPDX-License-Identifier: MIT

package dnsblock

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Format names how a list's lines are written.
type Format string

const (
	// FormatAuto reads the file and decides, which is what a list added by URL gets
	// until somebody says otherwise.
	FormatAuto Format = "auto"
	// FormatHosts is a hosts file: an address, whitespace, then the names that address
	// is claimed to answer for. A file of bare names parses the same way.
	FormatHosts Format = "hosts"
	// FormatABP is an Adblock-Plus filter list, of which the ||name^ rules and their @@
	// exceptions are the part a resolver can act on.
	FormatABP Format = "abp"
)

// ErrNotAList reports a body that parsed to nothing at all. A sign-in page from a
// captive portal, an error page served with a 200, and a URL that points at something
// else entirely all arrive looking like this, and treating any of them as a list of no
// names would quietly switch a list off.
var ErrNotAList = errors.New("this does not read like a blocklist")

// maxSniffLines bounds how much of a file Detect reads. The header of every list names
// its own syntax within a few dozen lines, and a file that has not shown its shape by
// then is one whose shape the caller should have stated.
const maxSniffLines = 200

// selfNames are the entries a hosts file carries about the machine reading it. They are
// its own boilerplate rather than anything it wants stopped, so they are neither an
// entry nor a rule that had to be skipped.
var selfNames = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"local":                 true,
	"broadcasthost":         true,
	"ip6-localhost":         true,
	"ip6-loopback":          true,
	"ip6-localnet":          true,
	"ip6-mcastprefix":       true,
	"ip6-allnodes":          true,
	"ip6-allrouters":        true,
	"ip6-allhosts":          true,
	"0.0.0.0":               true,
}

// abpModifiers are the rule options that leave a ||name^ rule meaning the same thing to
// a resolver. Every other modifier scopes a rule to something DNS cannot see -- the
// request's type, its originating page, the element it fills -- so a rule carrying one
// is counted as skipped rather than applied more broadly than its author wrote it.
var abpModifiers = map[string]bool{
	"important": true,
	"all":       true,
	"document":  true,
	"doc":       true,
}

// Parse reads a list body in the given format. FormatAuto sniffs it first.
//
// It reports the entries it produced and how many rules it could not express, and fails
// on a body that produced nothing at all.
func Parse(format Format, body []byte) ([]Entry, int, error) {
	if format == "" || format == FormatAuto {
		format = Detect(body)
	}
	var (
		entries []Entry
		skipped int
	)
	switch format {
	case FormatHosts:
		entries, skipped = ParseHosts(body)
	case FormatABP:
		entries, skipped = ParseABP(body)
	default:
		return nil, 0, fmt.Errorf("unknown list format %q", format)
	}
	if len(entries) == 0 || !looksLikeAList(entries) {
		return nil, skipped, ErrNotAList
	}
	return entries, skipped, nil
}

// looksLikeAList reports whether what was parsed reads like names rather than like prose.
//
// A sign-in page, an error page served with a 200 and a README all parse as a hosts file
// of bare words, because a word is a valid single-label name. Every real list is made of
// qualified names, so a body whose entries are mostly single labels is not one -- and
// storing it as a list of a few dozen English words would block them.
func looksLikeAList(entries []Entry) bool {
	qualified := 0
	for _, e := range entries {
		if strings.Contains(e.Name, ".") {
			qualified++
		}
	}
	return qualified*2 >= len(entries)
}

// Detect reads the head of a body and says which format it is written in.
//
// A file of bare names is a hosts file with the address column left out, so hosts is the
// answer when nothing says otherwise: the hosts parser accepts that shape and the
// Adblock one does not.
//
// This and the two parsers walk the body a line at a time rather than splitting it into
// every line first. A list is allowed to be tens of megabytes and a line may be a single
// newline, so a slice of every line costs a large multiple of the body it came from; this
// holds one line instead. Each yielded line keeps its terminator, which the trim takes off
// along with the rest of the surrounding space -- the same trim that reads a CRLF file as
// the same lines as an LF one.
func Detect(body []byte) Format {
	hosts, abp, seen := 0, 0, 0
	for raw := range bytes.Lines(body) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[Adblock") {
			return FormatABP
		}
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		seen++
		if seen > maxSniffLines {
			break
		}
		switch {
		case strings.HasPrefix(line, "||"), strings.HasPrefix(line, "@@"):
			abp++
		default:
			if fields := strings.Fields(line); len(fields) >= 2 && isAddress(fields[0]) {
				hosts++
			}
		}
	}
	if abp > hosts {
		return FormatABP
	}
	return FormatHosts
}

// ParseHosts reads a hosts file. Every name it carries is stopped exactly: the file
// lists what it wants stopped, and reading it as though each line also covered every
// subdomain would block names its author chose not to.
func ParseHosts(body []byte) ([]Entry, int) {
	var (
		entries []Entry
		skipped int
	)
	for raw := range bytes.Lines(body) {
		line := strings.TrimSpace(cutComment(string(raw), "#"))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		names := fields
		if isAddress(fields[0]) {
			names = fields[1:]
		}
		for _, raw := range names {
			match := Exact
			if strings.HasPrefix(raw, "*.") {
				// A wildcard is the file asking for the subtree, which is a different
				// rule from the exact name every other line here means.
				raw, match = raw[2:], Subtree
			}
			name := Normalize(raw)
			if name == "" || selfNames[name] || isAddress(name) {
				continue
			}
			if !validName(name) {
				skipped++
				continue
			}
			entries = append(entries, Entry{Name: name, Match: match})
		}
	}
	return entries, skipped
}

// ParseABP reads an Adblock-Plus filter list, keeping the rules a resolver can act on and
// counting the rest.
//
// The kept shape is ||name^, which stops a name and everything under it, and its @@
// exception, which stops it being stopped. A rule naming a URL path, hiding an element,
// matching a pattern, or scoped by a modifier to something a resolver never sees is
// counted as skipped: applying it to the whole domain would block more than its author
// wrote, and that is how a filter list breaks a site it was never aimed at.
func ParseABP(body []byte) ([]Entry, int) {
	var (
		entries []Entry
		skipped int
	)
	for raw := range bytes.Lines(body) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		if hidesElements(line) {
			skipped++
			continue
		}
		allow := strings.HasPrefix(line, "@@")
		rule := strings.TrimPrefix(line, "@@")
		if before, after, ok := strings.Cut(rule, "$"); ok {
			if !dnsExpressible(after) {
				skipped++
				continue
			}
			rule = before
		}
		rule = strings.TrimSuffix(strings.TrimPrefix(rule, "||"), "^")
		name := Normalize(rule)
		if name == "" || !validName(name) {
			skipped++
			continue
		}
		entries = append(entries, Entry{Name: name, Match: Subtree, Allow: allow})
	}
	return entries, skipped
}

// hidesElements reports a cosmetic rule. Those carry a CSS selector rather than a name
// and belong to a browser.
func hidesElements(line string) bool {
	for _, sep := range []string{"##", "#@#", "#?#", "#$#", "#%#"} {
		if strings.Contains(line, sep) {
			return true
		}
	}
	return false
}

// dnsExpressible reports whether a rule's modifiers leave it meaning the same thing when
// a resolver applies it to the whole domain.
func dnsExpressible(modifiers string) bool {
	for _, m := range strings.Split(modifiers, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		if m == "" {
			continue
		}
		if name, _, ok := strings.Cut(m, "="); ok {
			m = name
		}
		if !abpModifiers[strings.TrimPrefix(m, "~")] {
			return false
		}
	}
	return true
}

// cutComment drops everything from the first comment marker, so a name with a trailing
// note beside it still parses.
func cutComment(line, marker string) string {
	if i := strings.Index(line, marker); i >= 0 {
		return line[:i]
	}
	return line
}

// isAddress reports a literal IP address, which in a hosts file is the column that says
// where a name is sent rather than a name itself.
func isAddress(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// validName reports a name a resolver could be asked about: labels of the length DNS
// allows, made of the characters a list is entitled to carry, and nothing that is really
// a URL, a pattern or a selector wearing a name's clothes.
func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}
