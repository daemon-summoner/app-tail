// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// recordsFor answers a query with the records the test names, so a lookup can be driven
// through shapes -- a CNAME chain, an unrelated record, an empty answer -- that a single
// address record cannot express.
func recordsFor(label string, records func(q Question) []dnsmessage.Resource) *fakeUpstream {
	return &fakeUpstream{label: label, answer: func(query []byte) ([]byte, error) {
		q, err := parseQuestion(query)
		if err != nil {
			return nil, err
		}
		return answerWith(q, records(q))
	}}
}

// answerWith encodes an answer carrying whatever record types the test needs. The
// package's own builder handles only the addresses it synthesises, and a CNAME chain is
// exactly the shape a lookup has to survive.
func answerWith(q Question, records []dnsmessage.Resource) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: q.ID, Response: true, RecursionDesired: true, RecursionAvailable: true,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	question := dnsmessage.Question{Name: dnsmessage.MustNewName(q.fqdn()), Type: q.Type, Class: q.Class}
	if err := b.Question(question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, r := range records {
		var err error
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(r.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(r.Header, *body)
		case *dnsmessage.CNAMEResource:
			err = b.CNAMEResource(r.Header, *body)
		default:
			err = fmt.Errorf("the test builder cannot encode a %T", r.Body)
		}
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func cname(owner, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(owner + "."),
			Type:  dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target + ".")},
	}
}

func addressFor(owner string, addr netip.Addr) dnsmessage.Resource {
	h := dnsmessage.ResourceHeader{
		Name:  dnsmessage.MustNewName(owner + "."),
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}
	if addr.Is4() {
		h.Type = dnsmessage.TypeA
		return dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: addr.As4()}}
	}
	h.Type = dnsmessage.TypeAAAA
	return dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}}
}

// The reason this function exists: a profile naming its resolver by hostname is pinned to
// an address through the network's own resolvers, once, before the override goes in.
func TestAResolverHostnameIsPinnedThroughTheResolversItWasGiven(t *testing.T) {
	local := recordsFor("local", func(q Question) []dnsmessage.Resource {
		if q.Type == dnsmessage.TypeA {
			return []dnsmessage.Resource{addressFor(q.Name, netip.MustParseAddr("45.90.28.0"))}
		}
		return []dnsmessage.Resource{addressFor(q.Name, netip.MustParseAddr("2a07:a8c0::"))}
	})

	got, err := LookupAddrs(context.Background(), NewPool([]Upstream{local}, nil), "dns.nextdns.io")
	if err != nil {
		t.Fatalf("look up the resolver's name: %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("45.90.28.0"), netip.MustParseAddr("2a07:a8c0::")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d is %v, want %v (IPv4 first, so a machine with no IPv6 still reaches it)", i, got[i], want[i])
		}
	}
	if len(local.questions()) != 2 {
		t.Errorf("asked %v; both address families have to be asked for", local.questions())
	}
}

// A literal address is already pinned. Asking a resolver where 1.1.1.1 is would be a query
// for no reason, and one that fails on a machine whose resolver is exactly what we are
// about to replace.
func TestAnAddressIsNotLookedUpAtAll(t *testing.T) {
	local := failing("local")
	got, err := LookupAddrs(context.Background(), NewPool([]Upstream{local}, nil), "1.1.1.1")
	if err != nil {
		t.Fatalf("pin a literal address: %v", err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("got %v, want [1.1.1.1]", got)
	}
	if len(local.questions()) != 0 {
		t.Errorf("the resolver was asked %v about a literal address", local.questions())
	}
}

// Resolvers are commonly published behind a CNAME. Reading the address off whatever record
// happens to be in the answer would take an address for an unrelated name.
func TestACnameIsFollowedAndAnUnrelatedRecordIsIgnored(t *testing.T) {
	local := recordsFor("local", func(q Question) []dnsmessage.Resource {
		if q.Type != dnsmessage.TypeA {
			return nil
		}
		return []dnsmessage.Resource{
			addressFor("someone.else.example", netip.MustParseAddr("198.51.100.1")),
			cname(q.Name, "edge.example"),
			addressFor("edge.example", netip.MustParseAddr("203.0.113.9")),
		}
	})

	got, err := LookupAddrs(context.Background(), NewPool([]Upstream{local}, nil), "dns.example")
	if err != nil {
		t.Fatalf("follow the CNAME: %v", err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("got %v, want [203.0.113.9] -- the address of the name the CNAME points at", got)
	}
}

// A name that resolves to nothing has to fail loudly here. Carrying on would install an
// override pointing the whole machine at a resolver with no address to dial.
func TestAResolverNameThatResolvesToNothingIsAnError(t *testing.T) {
	local := coding("local", dnsmessage.RCodeNameError)
	_, err := LookupAddrs(context.Background(), NewPool([]Upstream{local}, nil), "nope.example")
	if err == nil {
		t.Fatal("a name with no address resolved without an error")
	}
	if !strings.Contains(err.Error(), "nope.example") {
		t.Errorf("the failure does not name what failed: %v", err)
	}
}

// Every resolver failing reads differently from a name that does not exist, and the
// difference is what tells a user their network is down rather than their profile wrong.
func TestALookupWithNoReachableResolverNamesTheFailure(t *testing.T) {
	_, err := LookupAddrs(context.Background(), NewPool([]Upstream{failing("local")}, nil), "dns.example")
	if err == nil {
		t.Fatal("a lookup with no reachable resolver succeeded")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the failure does not carry what went wrong: %v", err)
	}
}

// The cause of a resolver failure decides what the dashboard tells the user to do, and the
// cause is read with errors.Is by callers several layers up. A failure that is one line in the
// card must still be a chain underneath, or every cause reads as "the network is down".
func TestTheCauseOfAResolverFailureSurvivesTheJoin(t *testing.T) {
	refused := &fakeUpstream{label: "9.9.9.9", answer: func([]byte) ([]byte, error) {
		return nil, fmt.Errorf("dial tcp 9.9.9.9:443: %w", fs.ErrPermission)
	}}
	_, err := LookupAddrs(context.Background(), NewPool([]Upstream{failing("local"), refused}, nil), "dns.example")
	if err == nil {
		t.Fatal("a lookup with no reachable resolver succeeded")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("errors.Is cannot see the refused connection through %v", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("the failure is not one line: %q", err.Error())
	}
	for _, want := range []string{"local: connection refused", "9.9.9.9: dial tcp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not name %q: %v", want, err)
		}
	}
}
