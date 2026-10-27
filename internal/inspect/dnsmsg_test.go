// SPDX-License-Identifier: MIT

package inspect

// The question inside a DNS message. The hazard here is not a wrong name but a walk that
// never ends, so the pointer cases matter more than the happy one.

import (
	"strings"
	"testing"
)

// dnsQuery builds a query for one name, with the labels written the way a resolver writes
// them.
func dnsQuery(name string) []byte {
	msg := []byte{
		0x12, 0x34, // id
		0x01, 0x00, // a query, recursion desired
		0x00, 0x01, // one question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)        // the root
	msg = append(msg, 0x00, 0x01)  // type A
	return append(msg, 0x00, 0x01) // class IN
}

// The name is what a rule matches on, so reading it back out of a real query is the whole
// contract.
func TestAQuerySaysWhichNameItAsksAbout(t *testing.T) {
	for _, name := range []string{"example.test", "a.b.c.deep.example.test", "single"} {
		got, ok := DNSQuestion(dnsQuery(name))
		if !ok {
			t.Fatalf("a query for %q was not read as a question", name)
		}
		if got != name {
			t.Errorf("the name is %q, want %q", got, name)
		}
	}
}

// An answer carries the same name as the question that asked for it, and counting both would
// count every lookup twice.
func TestAnAnswerIsNotReadAsAQuestion(t *testing.T) {
	msg := dnsQuery("answered.example")
	msg[2] |= dnsFlagResponse
	if name, ok := DNSQuestion(msg); ok {
		t.Errorf("an answer read as a question asking about %q", name)
	}
}

// The corpus. A pointer is the one that matters: following one is how a parser is made to
// walk a message forever, and no bound on the window would stop it because the walk never
// leaves the window.
func TestAMalformedMessageIsNeverReadAsAName(t *testing.T) {
	pointer := append(dnsQuery("looped.example")[:dnsHeaderSize], 0xc0, 0x0c)
	pointer = append(pointer, 0x00, 0x01, 0x00, 0x01)

	selfPointer := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c, // a pointer to itself
		0x00, 0x01, 0x00, 0x01,
	}

	long := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 8; i++ {
		long = append(long, maxDNSLabel)
		long = append(long, strings.Repeat("a", maxDNSLabel)...)
	}
	long = append(long, 0x00, 0x00, 0x01, 0x00, 0x01)

	overLabel := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	overLabel = append(overLabel, maxDNSLabel+1)
	overLabel = append(overLabel, strings.Repeat("b", maxDNSLabel+1)...)
	overLabel = append(overLabel, 0x00, 0x00, 0x01, 0x00, 0x01)

	cases := []struct {
		name string
		msg  []byte
	}{
		{"a compression pointer in the question", pointer},
		{"a pointer to itself", selfPointer},
		{"a name past two hundred and fifty-five bytes", long},
		{"a label past sixty-three bytes", overLabel},
		{"a header and nothing else", dnsQuery("truncated.example")[:dnsHeaderSize]},
		{"a message shorter than a header", []byte{0x12, 0x34, 0x01}},
		{"no question at all", []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"a question with no type or class behind it", dnsQuery("bare.example")[:dnsHeaderSize+14]},
		{"a label claiming more than is there", []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x40, 'a', 'b',
		}},
		{"nothing at all", nil},
	}
	for _, held := range cases {
		t.Run(held.name, func(t *testing.T) {
			if name, ok := DNSQuestion(held.msg); ok {
				t.Fatalf("a message built to be wrong handed back the name %q", name)
			}
		})
	}

	// Every prefix of a real query, for the same reason: an unfinished message must be no
	// answer rather than half a name.
	full := dnsQuery("prefix.example")
	for at := 0; at < len(full); at++ {
		if name, ok := DNSQuestion(full[:at]); ok && name != "prefix.example" {
			t.Fatalf("%d bytes of a query handed back the name %q", at, name)
		}
	}
}

// A name that reaches a log line carrying a control character is the injection the parser is
// the last defence against.
func TestANameCarryingAControlCharacterIsRefused(t *testing.T) {
	for _, name := range []string{"bad\rname.example", "bad\x00name.example", "bad name.example"} {
		if got, ok := DNSQuestion(dnsQuery(name)); ok {
			t.Errorf("a name built to carry a control character read as %q", got)
		}
	}
}

// The root is a legitimate question and not a name any rule could name, so the honest answer
// is that there is no name here.
func TestAQueryForTheRootNamesNothing(t *testing.T) {
	msg := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	if name, ok := DNSQuestion(msg); ok {
		t.Errorf("a query for the root read as the name %q", name)
	}
}
