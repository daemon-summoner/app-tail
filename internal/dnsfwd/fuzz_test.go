// SPDX-License-Identifier: MIT

package dnsfwd

// The parsers that read a message somebody else wrote. A query is whatever a program on this
// machine cared to send, so each is held to what the rest of the package relies on for any
// bytes at all, not only for the messages the other tests thought to build.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// seedQueries is the corpus both targets start from: a plain query, one carrying the option
// that gets stripped beside one that does not, and a few shapes that are not a query.
func seedQueries(f *testing.F) {
	subnet := dnsmessage.Option{Code: ecsOption, Data: []byte{0, 1, 24, 0, 203, 0, 113}}
	cookie := dnsmessage.Option{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	for _, options := range [][]dnsmessage.Option{nil, {subnet}, {cookie, subnet}, {subnet, cookie, subnet}} {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
		b.EnableCompression()
		if err := b.StartQuestions(); err != nil {
			f.Fatal(err)
		}
		question := dnsmessage.Question{
			Name: dnsmessage.MustNewName("seed.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}
		if err := b.Question(question); err != nil {
			f.Fatal(err)
		}
		if options != nil {
			if err := b.StartAdditionals(); err != nil {
				f.Fatal(err)
			}
			var header dnsmessage.ResourceHeader
			if err := header.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
				f.Fatal(err)
			}
			if err := b.OPTResource(header, dnsmessage.OPTResource{Options: options}); err != nil {
				f.Fatal(err)
			}
		}
		msg, err := b.Finish()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(msg)
	}
	// A client-subnet option with a fragment too short to be an option after it.
	f.Add([]byte("0000\x00\x01\x00\x00\x00\x0000\x000000\x00\x00)000000\x00\v\x00\b\x00\x040000000"))
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Add([]byte{0, 7, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1, 1, 'b', 0, 0, 1, 0, 1})
	f.Add([]byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1})
}

// A message read as a query has exactly the one question it is routed by, and a name of a
// length the protocol allows, written the way the rules are.
func FuzzQuestion(f *testing.F) {
	seedQueries(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		q, err := parseQuestion(msg)
		if err != nil {
			return
		}
		if count := binary.BigEndian.Uint16(msg[4:6]); count != 1 {
			t.Fatalf("a message carrying %d questions was read as a query", count)
		}
		if len(q.Name) > 254 {
			t.Fatalf("a name of %d bytes was handed back, past the protocol's own ceiling", len(q.Name))
		}
		if q.Name != strings.ToLower(q.Name) {
			t.Fatalf("the name %q was handed back in a case no rule is written in", q.Name)
		}
	})
}

// subnetOptions counts the client-subnet options in a message's OPT record, and reports
// whether every option in the list could be read.
func subnetOptions(msg []byte) (count int, readable bool) {
	opt, ok := findOPT(msg)
	if !ok {
		return 0, false
	}
	rest := opt.rdata
	// Fewer than four bytes cannot be an option, so a fragment that short at the end is not
	// one that failed to read: the list is readable up to it, and stripping drops it.
	for len(rest) >= 4 {
		length := int(binary.BigEndian.Uint16(rest[2:]))
		if 4+length > len(rest) {
			return count, false
		}
		if binary.BigEndian.Uint16(rest) == ecsOption {
			count++
		}
		rest = rest[4+length:]
	}
	return count, true
}

// What leaves for an upstream never says which network the user is on, whenever the options
// could be read at all; a message with nothing to strip leaves as it came.
func FuzzClientSubnet(f *testing.F) {
	seedQueries(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		before, readable := subnetOptions(msg)
		sent := stripClientSubnet(bytes.Clone(msg))

		if len(sent) > len(msg) {
			t.Fatalf("a %d-byte message left as %d bytes", len(msg), len(sent))
		}
		if !readable || before == 0 {
			if !bytes.Equal(sent, msg) {
				t.Fatalf("a message with nothing to strip was rewritten: %x became %x", msg, sent)
			}
			return
		}
		after, stillReadable := subnetOptions(sent)
		if !stillReadable {
			t.Fatalf("stripping left options that cannot be read: %x became %x", msg, sent)
		}
		if after != 0 {
			t.Fatalf("%d of %d client-subnet options were sent on: %x became %x", after, before, msg, sent)
		}
	})
}
