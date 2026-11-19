// SPDX-License-Identifier: MIT

package dnsblock

// The two readers of a downloaded list. A list is whatever the address it is fetched from
// answers with, so each is held to what the set built from it relies on for any bytes at all.

import (
	"strings"
	"testing"
)

func seedLists(f *testing.F) {
	f.Add([]byte("# a hosts file\n0.0.0.0 ads.example\n127.0.0.1 localhost\n0.0.0.0 *.tracker.example www.ads.example\n"))
	f.Add([]byte("[Adblock Plus 2.0]\n! a filter list\n||ads.example^\n@@||good.ads.example^\n||zip^\n@@||com^\n"))
	f.Add([]byte("||ads.example^$third-party\nexample.com##.banner\n@@||co.uk^$important\n"))
	f.Add([]byte("0.0.0.0 münchen.example\r\n\r\n||MÜNCHEN.Example.^\r\n"))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte{0xff, 0xfe, 0x00, '|', '|', '.', '^'})
}

// readableName is what the set and the resolver both need of an entry: a name a query could
// carry, in the one spelling a query carries it in.
func readableName(t *testing.T, name string) {
	t.Helper()
	if name == "" || len(name) > 253 {
		t.Fatalf("an entry of %d bytes was kept: %q", len(name), name)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			t.Fatalf("an entry with a %d-byte label was kept: %q", len(label), name)
		}
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			t.Fatalf("an entry carrying the byte %#x was kept: %q", c, name)
		}
	}
}

func FuzzParseHosts(f *testing.F) {
	seedLists(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, skipped := ParseHosts(body)
		// Every name read or skipped is at least a byte of the body with something between
		// it and the next, so neither count can pass the body's own length.
		if len(entries)+skipped > len(body) {
			t.Fatalf("a %d-byte body yielded %d entries and %d skipped", len(body), len(entries), skipped)
		}
		for _, e := range entries {
			readableName(t, e.Name)
			if e.Allow {
				t.Fatalf("a hosts file made an exception of %q, which it has no way to write", e.Name)
			}
		}
	})
}

func FuzzParseABP(f *testing.F) {
	seedLists(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, skipped := ParseABP(body)
		if len(entries)+skipped > len(body) {
			t.Fatalf("a %d-byte body yielded %d entries and %d skipped", len(body), len(entries), skipped)
		}
		for _, e := range entries {
			readableName(t, e.Name)
			if e.Match != Subtree {
				t.Fatalf("the rule for %q was kept as something other than the subtree a filter rule means", e.Name)
			}
			if e.Allow && !strings.Contains(e.Name, ".") {
				t.Fatalf("an exception was kept for everything under %q", e.Name)
			}
		}
	})
}
