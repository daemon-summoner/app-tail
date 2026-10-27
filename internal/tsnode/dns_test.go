// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// answer builds a response the way a resolver does, so these tests read real wire bytes
// rather than a restatement of what the parser expects to find.
type answer struct {
	name string
	ttl  uint32
	// body is the record itself; a nil one contributes a question and no answer.
	body dnsmessage.ResourceBody
}

func response(t *testing.T, code dnsmessage.RCode, question string, answers ...answer) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(question)
	if err != nil {
		t.Fatalf("build the question name %q: %v", question, err)
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: code})
	if err := builder.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("add the question: %v", err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatalf("start answers: %v", err)
	}
	for _, a := range answers {
		recordName, err := dnsmessage.NewName(a.name)
		if err != nil {
			t.Fatalf("build the record name %q: %v", a.name, err)
		}
		header := dnsmessage.ResourceHeader{Name: recordName, Class: dnsmessage.ClassINET, TTL: a.ttl}
		var addErr error
		switch body := a.body.(type) {
		case *dnsmessage.AResource:
			addErr = builder.AResource(header, *body)
		case *dnsmessage.AAAAResource:
			addErr = builder.AAAAResource(header, *body)
		case *dnsmessage.CNAMEResource:
			addErr = builder.CNAMEResource(header, *body)
		default:
			t.Fatalf("this helper does not build a %T", a.body)
		}
		if addErr != nil {
			t.Fatalf("add the answer: %v", addErr)
		}
	}
	raw, err := builder.Finish()
	if err != nil {
		t.Fatalf("finish the response: %v", err)
	}
	return raw
}

func aRecord(ip [4]byte) *dnsmessage.AResource { return &dnsmessage.AResource{A: ip} }

func cname(t *testing.T, target string) *dnsmessage.CNAMEResource {
	t.Helper()
	name, err := dnsmessage.NewName(target)
	if err != nil {
		t.Fatalf("build the CNAME target %q: %v", target, err)
	}
	return &dnsmessage.CNAMEResource{CNAME: name}
}

// The addresses are the whole point: a caller dials what came back here, so an answer
// read as empty is a destination that silently becomes unreachable.
func TestAnAnsweredNameComesBackWithItsAddress(t *testing.T) {
	raw := response(t, dnsmessage.RCodeSuccess, "db.corp.example.com.",
		answer{name: "db.corp.example.com.", ttl: 120, body: aRecord([4]byte{10, 1, 2, 3})})

	lookup, err := addressAnswers(raw)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if !lookup.Served() {
		t.Fatal("a name the resolver answered came back unserved")
	}
	if got := lookup.Addrs[0]; got != netip.AddrFrom4([4]byte{10, 1, 2, 3}) {
		t.Errorf("resolved to %v, want the address the resolver answered with", got)
	}
	if lookup.TTL != 2*time.Minute {
		t.Errorf("TTL is %v, want the record's own lifetime", lookup.TTL)
	}
}

// An IPv6-only name is a name: reading only A records would leave it unreachable while
// the resolver was answering all along.
func TestAnIPv6OnlyNameComesBackWithItsAddress(t *testing.T) {
	want := netip.MustParseAddr("fd7a:115c:a1e0::9")
	raw := response(t, dnsmessage.RCodeSuccess, "v6.corp.example.com.", answer{
		name: "v6.corp.example.com.", ttl: 60,
		body: &dnsmessage.AAAAResource{AAAA: want.As16()},
	})

	lookup, err := addressAnswers(raw)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if !lookup.Served() || lookup.Addrs[0] != want {
		t.Errorf("resolved to %v, want %v", lookup.Addrs, want)
	}
}

// A name is normally answered as a CNAME chain ending in an address. Stopping at the
// first record that is not an address would drop the address that follows it.
func TestAnAddressBehindAliasesIsStillFound(t *testing.T) {
	raw := response(t, dnsmessage.RCodeSuccess, "www.corp.example.com.",
		answer{name: "www.corp.example.com.", ttl: 300, body: cname(t, "host.corp.example.com.")},
		answer{name: "host.corp.example.com.", ttl: 300, body: aRecord([4]byte{10, 9, 9, 9})})

	lookup, err := addressAnswers(raw)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if !lookup.Served() || lookup.Addrs[0] != netip.AddrFrom4([4]byte{10, 9, 9, 9}) {
		t.Errorf("resolved to %v, want the address the alias led to", lookup.Addrs)
	}
}

// The shortest lifetime is the one the whole answer is good for. Keeping the longest
// would hold a record past the point its own publisher said to ask again.
func TestTheShortestLifetimeInAnAnswerIsTheOneReported(t *testing.T) {
	raw := response(t, dnsmessage.RCodeSuccess, "pair.corp.example.com.",
		answer{name: "pair.corp.example.com.", ttl: 600, body: aRecord([4]byte{10, 0, 0, 1})},
		answer{name: "pair.corp.example.com.", ttl: 30, body: aRecord([4]byte{10, 0, 0, 2})})

	lookup, err := addressAnswers(raw)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if lookup.TTL != 30*time.Second {
		t.Errorf("TTL is %v, want the shortest in the answer", lookup.TTL)
	}
}

// The backend answers SERVFAIL for a name no configured resolver covers -- which on a
// tailnet with no DNS of its own is every public name. Reading that as a failure would
// turn "the tailnet does not serve this" into a refused connection.
func TestANameTheResolverDoesNotServeIsAnAnswerRatherThanAFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		code dnsmessage.RCode
	}{
		{name: "servfail", code: dnsmessage.RCodeServerFailure},
		{name: "nxdomain", code: dnsmessage.RCodeNameError},
		{name: "success with nothing in it", code: dnsmessage.RCodeSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup, err := addressAnswers(response(t, tc.code, "public.example.com."))
			if err != nil {
				t.Fatalf("read the answer: %v", err)
			}
			if lookup.Served() {
				t.Errorf("a name answered with nothing came back served by %v", lookup.Addrs)
			}
		})
	}
}

// A response that cannot be read is a broken resolver, not an unserved name. Reporting
// it as unserved would send the connection somewhere else without anyone knowing.
func TestAnUnreadableAnswerIsReported(t *testing.T) {
	if _, err := addressAnswers([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("a response that is not a DNS message was read as an answer")
	}
}

// IPv4 first, and only ask for IPv6 when there was no IPv4: the second question is a
// second round trip on every connection to a name that already answered.
func TestIPv6IsAskedForOnlyWhenThereIsNoIPv4(t *testing.T) {
	var asked []string
	query := func(_ context.Context, name, queryType string) ([]byte, error) {
		asked = append(asked, queryType)
		if queryType == "A" {
			return response(t, dnsmessage.RCodeSuccess, name,
				answer{name: name, ttl: 60, body: aRecord([4]byte{10, 0, 0, 5})}), nil
		}
		t.Errorf("AAAA was asked for after A answered")
		return nil, errors.New("should not be reached")
	}

	lookup, err := lookupAddrs(t.Context(), "one.corp.example.com.", query)
	if err != nil {
		t.Fatalf("look up: %v", err)
	}
	if !lookup.Served() {
		t.Fatal("the name came back unserved")
	}
	if len(asked) != 1 || asked[0] != "A" {
		t.Errorf("asked %v, want IPv4 alone", asked)
	}
}

func TestAnIPv6OnlyNameIsFoundBySecondQuestion(t *testing.T) {
	want := netip.MustParseAddr("fd7a:115c:a1e0::11")
	query := func(_ context.Context, name, queryType string) ([]byte, error) {
		if queryType == "A" {
			return response(t, dnsmessage.RCodeSuccess, name), nil
		}
		return response(t, dnsmessage.RCodeSuccess, name, answer{
			name: name, ttl: 60, body: &dnsmessage.AAAAResource{AAAA: want.As16()},
		}), nil
	}

	lookup, err := lookupAddrs(t.Context(), "v6.corp.example.com.", query)
	if err != nil {
		t.Fatalf("look up: %v", err)
	}
	if !lookup.Served() || lookup.Addrs[0] != want {
		t.Errorf("resolved to %v, want %v", lookup.Addrs, want)
	}
}

// Neither question answered anything, which is the ordinary case for every name outside
// the tailnet's DNS. It is an answer, not a failure: the caller resolves such a name the
// ordinary way, and an error here would take every public destination down with it.
func TestANameNeitherQuestionAnswersComesBackUnserved(t *testing.T) {
	var asked []string
	query := func(_ context.Context, name, queryType string) ([]byte, error) {
		asked = append(asked, queryType)
		return response(t, dnsmessage.RCodeServerFailure, name), nil
	}

	lookup, err := lookupAddrs(t.Context(), "public.example.com.", query)
	if err != nil {
		t.Fatalf("a name the tailnet does not serve was reported as a failure: %v", err)
	}
	if lookup.Served() {
		t.Errorf("resolved to %v, want nothing", lookup.Addrs)
	}
	if len(asked) != 2 {
		t.Errorf("asked %v, want both questions before giving up on the name", asked)
	}
}

// A resolver that answers with something that is not a DNS message is broken, and a
// broken resolver is not a name it does not serve. Reading it as unserved would send the
// connection to whatever the other resolver answers, silently.
func TestAnAnswerThatCannotBeReadIsReportedByTheLookup(t *testing.T) {
	query := func(context.Context, string, string) ([]byte, error) {
		return []byte{0x01, 0x02, 0x03}, nil
	}

	_, err := lookupAddrs(t.Context(), "db.corp.example.com.", query)
	if err == nil {
		t.Fatal("a response that is not a DNS message was read as a name the tailnet does not serve")
	}
	if !strings.Contains(err.Error(), "db.corp.example.com") {
		t.Errorf("err = %v, want it to name what was being resolved", err)
	}
}

// A response cut short -- a resolver that died mid-write, a truncated read -- has not
// said anything about the name. Every prefix of a real answer is checked because the
// parser fails at a different place depending on where the bytes stop, and the one that
// came back clean would be read as "not served" and resolve somewhere else.
func TestATruncatedAnswerIsReportedRatherThanReadAsUnserved(t *testing.T) {
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::7")
	raw := response(t, dnsmessage.RCodeSuccess, "www.corp.example.com.",
		answer{name: "www.corp.example.com.", ttl: 300, body: cname(t, "host.corp.example.com.")},
		answer{name: "host.corp.example.com.", ttl: 300, body: aRecord([4]byte{10, 0, 0, 7})},
		answer{name: "host.corp.example.com.", ttl: 300, body: &dnsmessage.AAAAResource{AAAA: v6.As16()}})

	for cut := 1; cut < len(raw); cut++ {
		lookup, err := addressAnswers(raw[:cut])
		if err == nil {
			t.Fatalf("a response cut to %d of %d bytes was read as an answer (%v)",
				cut, len(raw), lookup.Addrs)
		}
	}
}

// A resolver that cannot be reached has to say so. Answering "not served" would send
// every connection down the fallback path for as long as the backend is unwell, which
// is exactly when a split-DNS name silently resolving somewhere else does harm.
func TestAResolverThatCannotAnswerIsReported(t *testing.T) {
	query := func(context.Context, string, string) ([]byte, error) {
		return nil, errors.New("the local backend is not answering")
	}

	_, err := lookupAddrs(t.Context(), "db.corp.example.com.", query)
	if err == nil {
		t.Fatal("a resolver that failed was read as a name it does not serve")
	}
	if !strings.Contains(err.Error(), "db.corp.example.com") {
		t.Errorf("err = %v, want it to name what was being resolved", err)
	}
}
