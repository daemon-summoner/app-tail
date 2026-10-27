// SPDX-License-Identifier: MIT

// Package sigscan matches a set of byte patterns against a buffer in one pass, whatever how
// many patterns there are.
//
// It is to bytes what internal/dnsblock is to names: the matcher on its own, with no opinion
// about where the patterns came from or what happens to a match. The automaton is
// Aho-Corasick, flattened into six parallel slices rather than a node per pattern byte, so a
// set at the ceiling is a few megabytes of arena instead of a hundred thousand separately
// allocated maps.
//
// # What it costs
//
// One walk of the buffer, with the work provably bounded at two steps per byte: each byte
// moves the walk at most one level deeper, and every fallback step moves it at least one level
// shallower, so the fallbacks over a whole buffer cannot outnumber the bytes. A pattern set is
// therefore free to be large -- what bounds the cost is the buffer, and the caller bounds
// that.
//
// In numbers, from BenchmarkMatchMiss with a full set of patterns: about 15 microseconds and
// no allocation to walk four kilobytes, which is one walk per connection at the window the
// only caller reads. That is real cost on the path that carries bytes, and it is why matching
// patterns is a switch of its own that is off until somebody turns it on.
package sigscan

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	// MaxPatterns is how many patterns one compiled set carries. The ceiling exists because
	// the arena is sized by the total length of the patterns, and something has to say how
	// large a set somebody may type into a settings field.
	MaxPatterns = 512
	// MinBytes is the shortest pattern accepted. Three bytes appear somewhere inside a few
	// kilobytes of very nearly anything, so a pattern that short is not a signature: it is a
	// switch that reports every connection, which reads as the matcher being broken.
	MinBytes = 4
	// MaxBytes is the longest. A pattern of a quarter kilobyte has stopped identifying
	// something and started describing it, and the buffers this runs over are measured in
	// single-figure kilobytes.
	MaxBytes = 256
	// maxName is the room a name gets. It reaches a log line, an event field and a card, so
	// it is bounded there rather than truncated at each of them.
	maxName = 64
)

// Signature is one pattern under the name a match calls it.
//
// The bytes are matched exactly, including case. Folding them would double the automaton to
// answer a question a second line in the list answers for the cost of one line.
type Signature struct {
	Name    string
	Pattern []byte
}

// Parse reads one written entry.
//
// The shape is a name, an equals sign, and the bytes as a quoted Go string:
//
//	a token that must not leave = "hunter2-9f3a1c"
//	a NUL-terminated marker     = "MARK\x00"
//
// The quoting is what gives \x00, \r and every other byte that is not text without a second
// escape syntax to learn or a hand-rolled unescaper to get wrong, and it is required rather
// than optional: without it, a pattern ending in a space is a pattern whose last byte depends
// on what an editor did when the line was saved.
func Parse(entry string) (Signature, error) {
	text := strings.TrimSpace(entry)
	at := strings.IndexByte(text, '=')
	if at < 0 {
		return Signature{}, fmt.Errorf(
			`%q is not a signature: write it as a name, an equals sign, and the bytes in `+
				`quotes, like  a name = "the bytes"`, entry)
	}

	name := strings.TrimSpace(text[:at])
	switch {
	case name == "":
		return Signature{}, fmt.Errorf("%q has nothing before the equals sign, so a match "+
			"would name nothing", entry)
	case len(name) > maxName:
		return Signature{}, fmt.Errorf("the name %q is longer than %d characters", name, maxName)
	case !printable(name):
		return Signature{}, fmt.Errorf("the name %q holds something that is not plain text; a "+
			"name is read back in a log line and on a card", name)
	}

	quoted := strings.TrimSpace(text[at+1:])
	pattern, err := strconv.Unquote(quoted)
	if err != nil {
		return Signature{}, fmt.Errorf(`the bytes of %q are not a quoted string: write them as `+
			`"like this", with \xNN for a byte that is not text`, name)
	}
	switch {
	case len(pattern) < MinBytes:
		return Signature{}, fmt.Errorf("the pattern for %q is %d bytes; %d or more are needed, "+
			"since anything shorter matches nearly every connection", name, len(pattern), MinBytes)
	case len(pattern) > MaxBytes:
		return Signature{}, fmt.Errorf("the pattern for %q is %d bytes; %d is the most",
			name, len(pattern), MaxBytes)
	}
	return Signature{Name: name, Pattern: []byte(pattern)}, nil
}

// printable reports text made only of the characters a name may be read back as.
func printable(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7e {
			return false
		}
	}
	return true
}

// Set is a compiled pattern set. It is immutable once built and replaced whole, so a caller on
// a data path reads it without a lock.
//
// The arena: a node's outgoing edges are the bytes edge[first[n]:first[n+1]], sorted, with
// next parallel to them, which makes one step a binary search over a handful of bytes rather
// than a map lookup. fail is where the walk goes when no edge matches. match is the pattern
// that ends at this node, and suffix is the nearest node up the fail chain that has one --
// which is what makes a pattern ending inside a longer one still report.
type Set struct {
	first  []int32
	edge   []byte
	next   []int32
	fail   []int32
	match  []int32
	suffix []int32

	names []string
}

// Compile builds the matcher from signatures, in the order given.
//
// A set with nothing in it is nil rather than an empty matcher, so a caller holding one can
// tell "match nothing" from "matcher not built" by the same nil comparison it already makes
// against a switched-off matcher.
//
// Two entries carrying the same bytes are one pattern: the first name wins, because it is the
// one the user wrote first and the second would only ever be reported for the same match.
func Compile(signatures []Signature) (*Set, error) {
	if len(signatures) > MaxPatterns {
		return nil, fmt.Errorf("%d signatures is more than the %d one set holds",
			len(signatures), MaxPatterns)
	}

	kept := make([]Signature, 0, len(signatures))
	seen := make(map[string]struct{}, len(signatures))
	for _, sig := range signatures {
		if len(sig.Pattern) < MinBytes || len(sig.Pattern) > MaxBytes {
			return nil, fmt.Errorf("the pattern for %q is %d bytes, which is outside the %d to "+
				"%d a signature may be", sig.Name, len(sig.Pattern), MinBytes, MaxBytes)
		}
		if _, already := seen[string(sig.Pattern)]; already {
			continue
		}
		seen[string(sig.Pattern)] = struct{}{}
		kept = append(kept, sig)
	}
	if len(kept) == 0 {
		return nil, nil
	}
	return build(kept), nil
}

// node is the trie as it is built, before it is flattened. The map is the build's alone: it is
// what makes adding a pattern a walk rather than a search, and it does not survive into the
// arena the walk reads.
type node struct {
	next  map[byte]int32
	match int32
}

// build turns the patterns into the automaton: a trie, then the fallback links across it, then
// the arena.
func build(signatures []Signature) *Set {
	nodes := []node{{next: map[byte]int32{}, match: -1}}
	names := make([]string, 0, len(signatures))
	for _, sig := range signatures {
		at := int32(0)
		for _, b := range sig.Pattern {
			to, ok := nodes[at].next[b]
			if !ok {
				to = int32(len(nodes))
				nodes = append(nodes, node{next: map[byte]int32{}, match: -1})
				nodes[at].next[b] = to
			}
			at = to
		}
		nodes[at].match = int32(len(names))
		names = append(names, sig.Name)
	}

	fail := make([]int32, len(nodes))
	// Breadth first, so a node's fallback is worked out from its parent's, which was worked
	// out one level earlier. The order within a level is whatever the maps hand back and does
	// not matter: every fallback a level needs was settled by the level above it.
	order := make([]int32, 0, len(nodes))
	for _, to := range nodes[0].next {
		order = append(order, to)
	}
	for head := 0; head < len(order); head++ {
		at := order[head]
		for b, to := range nodes[at].next {
			order = append(order, to)
			// Walk down this node's own fallbacks looking for one that can take this byte.
			// The root takes every byte or none, which is what ends the walk.
			from := fail[at]
			for {
				if landed, ok := nodes[from].next[b]; ok {
					fail[to] = landed
					break
				}
				if from == 0 {
					break
				}
				from = fail[from]
			}
		}
	}

	suffix := make([]int32, len(nodes))
	for i := range suffix {
		suffix[i] = -1
	}
	for _, at := range order {
		if from := fail[at]; nodes[from].match >= 0 {
			suffix[at] = from
		} else {
			suffix[at] = suffix[from]
		}
	}

	edges := 0
	for _, n := range nodes {
		edges += len(n.next)
	}
	set := &Set{
		first:  make([]int32, len(nodes)+1),
		edge:   make([]byte, 0, edges),
		next:   make([]int32, 0, edges),
		fail:   fail,
		match:  make([]int32, len(nodes)),
		suffix: suffix,
		names:  names,
	}
	for i, n := range nodes {
		set.first[i] = int32(len(set.edge))
		set.match[i] = n.match
		taken := make([]byte, 0, len(n.next))
		for b := range n.next {
			taken = append(taken, b)
		}
		slices.Sort(taken)
		for _, b := range taken {
			set.edge = append(set.edge, b)
			set.next = append(set.next, n.next[b])
		}
	}
	set.first[len(nodes)] = int32(len(set.edge))
	return set
}

// Match reports the first pattern the buffer carries, and whether it carries one.
//
// First means first by where it ends: the walk stops on the earliest byte that completes any
// pattern, and where two end together the longer one is reported. Nothing about the position
// is returned, and deliberately so -- see the note on echoing in the caller that reports this.
func (s *Set) Match(buf []byte) (string, bool) {
	if s == nil {
		return "", false
	}
	at := int32(0)
	for _, b := range buf {
		at = s.step(at, b)
		if found := s.match[at]; found >= 0 {
			return s.names[found], true
		}
		// Nothing ends here, but something may end at a shorter tail of what has been read.
		if shorter := s.suffix[at]; shorter >= 0 {
			return s.names[s.match[shorter]], true
		}
	}
	return "", false
}

// Count is how many patterns the set holds.
func (s *Set) Count() int {
	if s == nil {
		return 0
	}
	return len(s.names)
}

// step moves the walk on by one byte, falling back until a node takes it or the root refuses
// it.
func (s *Set) step(at int32, b byte) int32 {
	for {
		if to, ok := s.edgeTo(at, b); ok {
			return to
		}
		if at == 0 {
			return 0
		}
		at = s.fail[at]
	}
}

// edgeTo finds the node one byte takes this one to, by binary search over its sorted edges.
func (s *Set) edgeTo(at int32, b byte) (int32, bool) {
	lo, hi := s.first[at], s.first[at+1]
	found, ok := slices.BinarySearch(s.edge[lo:hi], b)
	if !ok {
		return 0, false
	}
	return s.next[int(lo)+found], true
}
