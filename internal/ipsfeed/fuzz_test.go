// SPDX-License-Identifier: MIT

package ipsfeed

// The reader of a downloaded feed. A feed is whatever the address it is fetched from answers
// with, and every entry read out of it is a network connections are refused to in prevent
// mode, so what comes out is held to its limits for any bytes at all.

import (
	"bytes"
	"net/netip"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("# a feed\n203.0.113.0/24\n198.51.100.7 # seen 40 times\n2001:db8::/32\n"))
	f.Add([]byte("203.0.113.0/24\r\n198.51.100.7 ; reason\r\n"))
	f.Add([]byte("0.0.0.0/0\n10.0.0.0/8\n100.64.0.0/10\n::/0\n::ffff:203.0.113.0/120\n128.0.0.0/1\n"))
	f.Add([]byte("<html><body>Sign in to use this network</body></html>"))
	f.Add([]byte("\n\n\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, skipped := Parse(body)
		if lines := bytes.Count(body, []byte("\n")) + 1; len(entries)+skipped > lines {
			t.Fatalf("a body of %d lines yielded %d entries and %d skipped", lines, len(entries), skipped)
		}
		for _, entry := range entries {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				t.Fatalf("the entry %q is not a network: %v", entry, err)
			}
			if prefix != prefix.Masked() || prefix.Addr().Is4In6() {
				t.Fatalf("the entry %q is not in the form the matcher looks up in", entry)
			}
			if Reserved(prefix) {
				t.Fatalf("the entry %q reaches a network no feed may put in force", entry)
			}
			if widest := map[bool]int{true: 8, false: 16}[prefix.Addr().Is4()]; prefix.Bits() < widest {
				t.Fatalf("the entry %q is wider than a /%d", entry, widest)
			}
		}
	})
}
