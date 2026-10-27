// SPDX-License-Identifier: MIT

package sigscan

// A signature entry is a line somebody typed and a buffer is bytes an attacker chose. These
// say what neither may ever do: panic, be accepted and then refuse to compile, or report a
// name that was never written.
//
// The seeds run as ordinary tests under test.sh, so the cheap half of this is in every run and
// the expensive half is one command away:
//
//	go test -fuzz=FuzzEntry -fuzztime=5m ./internal/sigscan

import (
	"bytes"
	"testing"
)

// FuzzEntry is the written form, which is the only thing a user hands this package directly.
func FuzzEntry(f *testing.F) {
	for _, seed := range []string{
		`a token = "hunter2-9f3a1c"`,
		`a marker = "MARK\x00\xff\r\n"`,
		`a header = "Authorization: "`,
		`= "abcdefgh"`,
		`a name = abcdefgh`,
		`a name = "ab\qcd"`,
		`a name = "abc"`,
		"",
		"=",
		`""`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, entry string) {
		sig, err := Parse(entry)
		if err != nil {
			return
		}
		// Anything Parse accepted has to compile: the settings field validates with Parse and
		// the agent builds with Compile, so a gap between them is an entry the user was told
		// was good and that quietly matches nothing.
		set, err := Compile([]Signature{sig})
		if err != nil {
			t.Fatalf("%q parsed and then would not compile: %v", entry, err)
		}
		if set == nil {
			t.Fatalf("%q parsed and compiled to no matcher at all", entry)
		}
		// And it has to find its own bytes, wherever they sit in a buffer.
		buf := append([]byte("\x00\x01padding"), sig.Pattern...)
		buf = append(buf, "padding\xff\xfe"...)
		name, ok := set.Match(buf)
		if !ok {
			t.Fatalf("%q did not match the bytes it names", entry)
		}
		if name != sig.Name {
			t.Fatalf("the match named %q, want %q", name, sig.Name)
		}
	})
}

// FuzzMatch is the buffer side: bytes off a connection, walked against a set that is already
// built.
func FuzzMatch(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("GET /?q=hunter2-9f3a1c HTTP/1.1\r\nHost: files.example\r\n\r\n"),
		[]byte("abcabcd"),
		[]byte("xxabcde"),
		[]byte("MARK\x00\xff"),
		{},
		bytes.Repeat([]byte{0xa5}, 4096),
	} {
		f.Add(seed)
	}

	written := []Signature{
		{Name: "a token", Pattern: []byte("hunter2-9f3a1c")},
		{Name: "the long one", Pattern: []byte("abcdefg")},
		{Name: "the short one", Pattern: []byte("bcde")},
		{Name: "a marker", Pattern: []byte("MARK\x00\xff")},
	}
	set, err := Compile(written)
	if err != nil {
		f.Fatalf("Compile: %v", err)
	}

	f.Fuzz(func(t *testing.T, buf []byte) {
		name, ok := set.Match(buf)
		if !ok {
			if name != "" {
				t.Fatalf("nothing matched and a name was handed back anyway: %q", name)
			}
			return
		}
		// A reported name is one of the ones written, and its bytes are really in the buffer:
		// a walk that fell off its tables would report neither.
		for _, sig := range written {
			if sig.Name != name {
				continue
			}
			if !bytes.Contains(buf, sig.Pattern) {
				t.Fatalf("%q was reported for a buffer that does not carry its bytes", name)
			}
			return
		}
		t.Fatalf("the match named %q, which was never written", name)
	})
}
