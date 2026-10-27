// SPDX-License-Identifier: MIT

// Package dnsblock turns domain blocklists into the matcher the resolvers ask on every
// query, and holds the catalog of lists that ship with the binary.
//
// A list is a file of names somebody else maintains, in one of two shapes. A hosts file
// names every host it wants stopped, exactly. An Adblock-Plus filter list writes
// ||name^, which stops a name and everything under it. Rules a resolver cannot express
// -- a URL path, an element-hiding selector, a rule scoped to a request context DNS
// never sees -- are counted rather than dropped quietly: a list that contributed almost
// nothing has to be able to say so.
package dnsblock

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// MaxLists bounds how many lists one matcher carries. Which list stopped a name is kept
// as a single byte beside it, a megabyte for a million names against the eight a pointer
// would cost, and this ceiling is what makes one byte enough.
const MaxLists = 255

// Match is how far one rule reaches.
type Match int

const (
	// Exact stops the name written and nothing under it. That is what a hosts file
	// means: it lists every host it wants stopped, and a name it does not list is a
	// name it has no opinion about.
	Exact Match = iota
	// Subtree stops the name and everything under it, which is what ||name^ means and
	// what somebody typing a domain by hand means.
	Subtree
)

// Entry is one rule a list carries.
type Entry struct {
	// Name is the domain, lowercased and without the dots people write around one.
	Name  string
	Match Match
	// Allow inverts the rule: the name and everything under it is never stopped,
	// whatever any list says. Exception rules parse to this.
	Allow bool
}

// ListStat is what one list contributed, for the card and for `app-tail dns block`.
type ListStat struct {
	ID string `json:"id"`
	// Name is the list as the user sees it, and is what a blocked name's reason says.
	Name string `json:"name"`
	// Rules is how many names the list contributed. Skipped is how many of its rules
	// mean nothing to a resolver -- the number that says whether a list is pulling its
	// weight here or is mostly written for a browser.
	Rules   int `json:"rules"`
	Skipped int `json:"skipped"`
}

// arena is a sorted set of names packed into one buffer, with the start of each name in
// an index beside it and the list each came from in another.
//
// Every tier of every shipped list switched on at once is on the order of a million
// names. A map of those costs sixty megabytes and leaves a million pointers for the
// collector to walk on every cycle; this costs about twenty and holds three allocations,
// none of which contain a pointer. Lookup is a binary search over the index.
type arena struct {
	buf []byte
	// start carries one offset per name plus a final one holding len(buf), so name i is
	// buf[start[i]:start[i+1]] and there is no separator to scan for.
	start []uint32
	owner []uint8
}

func (a *arena) len() int {
	if len(a.start) == 0 {
		return 0
	}
	return len(a.start) - 1
}

func (a *arena) at(i int) []byte { return a.buf[a.start[i]:a.start[i+1]] }

// find returns the list that carries name exactly.
func (a *arena) find(name string) (uint8, bool) {
	n := a.len()
	if n == 0 {
		return 0, false
	}
	i := sort.Search(n, func(i int) bool { return compare(a.at(i), name) >= 0 })
	if i < n && compare(a.at(i), name) == 0 {
		return a.owner[i], true
	}
	return 0, false
}

// findSuffix returns the list that carries name or any parent of it, so a rule for
// doubleclick.net answers for ad.doubleclick.net as well.
func (a *arena) findSuffix(name string) (uint8, bool) {
	if a.len() == 0 {
		return 0, false
	}
	for {
		if owner, ok := a.find(name); ok {
			return owner, true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return 0, false
		}
		name = name[dot+1:]
	}
}

// compare orders a stored name against one being looked up without converting either to
// the other's type. A conversion here would allocate on every probe, and one query
// probes once per label.
func compare(b []byte, s string) int {
	n := len(b)
	if len(s) < n {
		n = len(s)
	}
	for i := 0; i < n; i++ {
		switch {
		case b[i] < s[i]:
			return -1
		case b[i] > s[i]:
			return 1
		}
	}
	switch {
	case len(b) < len(s):
		return -1
	case len(b) > len(s):
		return 1
	}
	return 0
}

// Set is a compiled matcher. It is immutable once built and replaced whole, so the
// resolvers read it without a lock and a query in flight keeps the lists it started with.
type Set struct {
	exact   arena
	subtree arena
	allow   arena
	lists   []ListStat
}

// Blocks reports the list that stops a name, and whether one does.
//
// The allowlist is asked first and beats every list. It is what a false positive gets
// fixed with, and a fix a list could override would not be one.
func (s *Set) Blocks(name string) (string, bool) {
	if s == nil {
		return "", false
	}
	n := Normalize(name)
	if n == "" {
		return "", false
	}
	if _, ok := s.allow.findSuffix(n); ok {
		return "", false
	}
	if owner, ok := s.exact.find(n); ok {
		return s.listName(owner), true
	}
	if owner, ok := s.subtree.findSuffix(n); ok {
		return s.listName(owner), true
	}
	return "", false
}

// listName is what a blocked name's reason calls the list. An owner with no entry is a
// build that went wrong rather than a runtime condition, and saying so beats a reason
// that names nothing.
func (s *Set) listName(owner uint8) string {
	if int(owner) >= len(s.lists) {
		return "a list app-tail could not name"
	}
	if name := strings.TrimSpace(s.lists[owner].Name); name != "" {
		return name
	}
	return s.lists[owner].ID
}

// Lists reports what each list contributed, in the order they were compiled.
func (s *Set) Lists() []ListStat {
	if s == nil {
		return nil
	}
	return append([]ListStat(nil), s.lists...)
}

// Rules is how many names the matcher holds, counting a name that two lists both carry
// once.
func (s *Set) Rules() int {
	if s == nil {
		return 0
	}
	return s.exact.len() + s.subtree.len()
}

// Empty reports a matcher that stops nothing, which is a set built from lists that are
// all switched off or that all failed to parse.
func (s *Set) Empty() bool { return s.Rules() == 0 }

// staged accumulates names for one bucket before they are sorted and packed. Names go
// into one growing buffer rather than into a slice of strings: a million separate
// strings is a million allocations the collector then walks.
type staged struct {
	buf   []byte
	items []item
}

type item struct {
	start, end uint32
	owner      uint8
}

func (s *staged) add(name string, owner uint8) {
	start := uint32(len(s.buf))
	s.buf = append(s.buf, name...)
	s.items = append(s.items, item{start: start, end: uint32(len(s.buf)), owner: owner})
}

func (s *staged) name(i item) []byte { return s.buf[i.start:i.end] }

// compact sorts the staged names and packs them into an arena, keeping the first list to
// carry a name as its owner so the reason credits the list the user put first.
func (s *staged) compact() arena {
	if len(s.items) == 0 {
		return arena{}
	}
	sort.SliceStable(s.items, func(i, j int) bool {
		return bytes.Compare(s.name(s.items[i]), s.name(s.items[j])) < 0
	})
	out := arena{
		buf:   make([]byte, 0, len(s.buf)),
		start: make([]uint32, 0, len(s.items)+1),
		owner: make([]uint8, 0, len(s.items)),
	}
	var last []byte
	for n, it := range s.items {
		name := s.name(it)
		if n > 0 && bytes.Equal(name, last) {
			continue
		}
		out.start = append(out.start, uint32(len(out.buf)))
		out.buf = append(out.buf, name...)
		out.owner = append(out.owner, it.owner)
		last = name
	}
	out.start = append(out.start, uint32(len(out.buf)))
	return out
}

// Builder compiles lists into a Set. Add each list in the order the user holds them,
// then call Build. It is single-use and not safe for concurrent use.
type Builder struct {
	exact   staged
	subtree staged
	allow   staged
	lists   []ListStat
}

// Add compiles one list's entries under its own name. The first list to carry a name is
// credited with it, so the reason names the list the user put first rather than whichever
// one happened to sort last.
func (b *Builder) Add(id, name string, entries []Entry, skipped int) error {
	if len(b.lists) >= MaxLists {
		return fmt.Errorf("at most %d lists at once, which is already more than a resolver has any use for", MaxLists)
	}
	owner := uint8(len(b.lists))
	rules := 0
	for _, e := range entries {
		n := Normalize(e.Name)
		if n == "" {
			continue
		}
		switch {
		case e.Allow:
			b.allow.add(n, owner)
		case e.Match == Subtree:
			b.subtree.add(n, owner)
		default:
			b.exact.add(n, owner)
		}
		rules++
	}
	b.lists = append(b.lists, ListStat{ID: id, Name: name, Rules: rules, Skipped: skipped})
	return nil
}

// Build packs everything added so far into the matcher. The builder is spent afterwards.
func (b *Builder) Build() *Set {
	return &Set{
		exact:   b.exact.compact(),
		subtree: b.subtree.compact(),
		allow:   b.allow.compact(),
		lists:   b.lists,
	}
}

// Normalize lowercases a name and strips the dots people write around one, so
// "Doubleclick.net." and "doubleclick.net" are one name.
//
// A name written with characters outside ASCII is put into the form a query carries it in:
// a list says "münchen.example" and the resolver is asked for "xn--mnchen-3ya.example", and
// the two have to meet as one string or the entry blocks nothing. A name the conversion
// refuses is left as written, which is then a name the parser counts as unreadable.
func Normalize(s string) string {
	name := strings.Trim(strings.TrimSpace(s), ".")
	if !ascii(name) {
		if converted, err := idna.Lookup.ToASCII(name); err == nil {
			name = converted
		}
	}
	return strings.ToLower(name)
}

// ascii reports a name made only of single-byte characters, which is every name a query
// carries and nearly every name a list does; the check is what keeps the conversion off the
// path every query takes.
func ascii(name string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return false
		}
	}
	return true
}
