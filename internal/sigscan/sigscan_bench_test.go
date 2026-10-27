// SPDX-License-Identifier: MIT

package sigscan

// What one walk of a connection's opening bytes costs at the size somebody can actually
// configure. The window is four kilobytes and is walked once per connection, so the number
// that matters is nanoseconds per window rather than per byte -- and it has to hold at the
// ceiling of patterns, because the walk is what makes the ceiling affordable: every pattern is
// matched in the same pass, so the cost is the window's length rather than the list's.

import (
	"fmt"
	"strings"
	"testing"
)

// benchSet is a full list of patterns, which is the state the budget is stated for.
func benchSet(b *testing.B, n int) *Set {
	b.Helper()
	written := make([]Signature, 0, n)
	for i := 0; i < n; i++ {
		written = append(written, Signature{
			Name:    fmt.Sprintf("pattern %d", i),
			Pattern: []byte(fmt.Sprintf("marker-%06d-that-must-not-leave", i)),
		})
	}
	set, err := Compile(written)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	return set
}

// benchWindow is four kilobytes of an ordinary request, which is what nearly every connection
// hands the matcher.
func benchWindow() []byte {
	return []byte("POST /upload HTTP/1.1\r\nHost: files.example\r\n\r\n" +
		strings.Repeat("field=value&", 340))
}

// BenchmarkMatchMiss is every connection on the machine: the whole window is walked and
// nothing is found, which is the walk that has to stay cheap.
func BenchmarkMatchMiss(b *testing.B) {
	set := benchSet(b, MaxPatterns)
	win := benchWindow()
	b.SetBytes(int64(len(win)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := set.Match(win); ok {
			b.Fatal("no pattern is in this window")
		}
	}
}

// BenchmarkMatchHit is a window carrying something the user is watching for, found at the far
// end of it so the whole walk is paid for.
func BenchmarkMatchHit(b *testing.B) {
	set := benchSet(b, MaxPatterns)
	win := append(benchWindow(), fmt.Sprintf("marker-%06d-that-must-not-leave", MaxPatterns/2)...)
	b.SetBytes(int64(len(win)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := set.Match(win); !ok {
			b.Fatal("the window carries a pattern")
		}
	}
}

// BenchmarkCompileFull is what editing the setting costs, and with -benchmem what the matcher
// costs to hold: the flattened tables are the reason a full list is a few hundred kilobytes
// rather than a byte-indexed table per node.
func BenchmarkCompileFull(b *testing.B) {
	written := make([]Signature, 0, MaxPatterns)
	for i := 0; i < MaxPatterns; i++ {
		written = append(written, Signature{
			Name:    fmt.Sprintf("pattern %d", i),
			Pattern: []byte(fmt.Sprintf("marker-%06d-that-must-not-leave", i)),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(written); err != nil {
			b.Fatalf("Compile: %v", err)
		}
	}
}
