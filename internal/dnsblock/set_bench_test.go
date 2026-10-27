// SPDX-License-Identifier: MIT

package dnsblock

// What the matcher costs at the size the shipped catalog reaches: every Hagezi tier plus
// StevenBlack plus OISD Big switched on at once is on the order of a million names, and
// the memory that costs is the reason the set is an arena rather than a map. The compile
// benchmark reports it; -benchmem is where the claim is checked.

import (
	"fmt"
	"testing"
)

// millionNames is a corpus the size of the worst case somebody can actually configure.
func millionNames(n int) []Entry {
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Entry{Name: fmt.Sprintf("n%d.tracker%d.example", i, i%4096), Match: Subtree})
	}
	return out
}

func benchSet(b *testing.B, n int) *Set {
	b.Helper()
	var builder Builder
	if err := builder.Add("bench", "Bench list", millionNames(n), 0); err != nil {
		b.Fatalf("Add: %v", err)
	}
	return builder.Build()
}

// BenchmarkBlocksHit is a name a list carries, which is the query that costs the most: the
// suffix walk stops only once it has found something.
func BenchmarkBlocksHit(b *testing.B) {
	set := benchSet(b, 1_000_000)
	hit := fmt.Sprintf("n%d.tracker%d.example", 500_000, 500_000%4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := set.Blocks(hit); !ok {
			b.Fatalf("the corpus carries %s", hit)
		}
	}
}

// BenchmarkBlocksMiss is every other query on the machine, which is the one that has to
// stay cheap: it probes once per label and finds nothing.
func BenchmarkBlocksMiss(b *testing.B) {
	set := benchSet(b, 1_000_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := set.Blocks("www.some-ordinary-site.example.org"); ok {
			b.Fatal("no rule carries this name")
		}
	}
}

// BenchmarkCompileMillion is what a refresh costs, and with -benchmem what the matcher
// costs to hold: the number the arena exists for.
func BenchmarkCompileMillion(b *testing.B) {
	entries := millionNames(1_000_000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var builder Builder
		if err := builder.Add("bench", "Bench list", entries, 0); err != nil {
			b.Fatalf("Add: %v", err)
		}
		if set := builder.Build(); set.Rules() == 0 {
			b.Fatal("compiled nothing")
		}
	}
}
