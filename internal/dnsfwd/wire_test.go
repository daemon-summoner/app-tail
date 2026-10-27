// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// buildQuery makes a query the way a stub resolver would, optionally with EDNS options.
func buildQuery(t *testing.T, name string, typ dnsmessage.Type, options ...dnsmessage.Option) []byte {
	t.Helper()
	fqdn := name
	if fqdn == "" {
		fqdn = "."
	} else {
		fqdn += "."
	}
	dn, err := dnsmessage.NewName(fqdn)
	if err != nil {
		t.Fatalf("NewName(%q): %v", fqdn, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{Name: dn, Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("Question: %v", err)
	}
	if len(options) > 0 {
		if err := b.StartAdditionals(); err != nil {
			t.Fatalf("StartAdditionals: %v", err)
		}
		var header dnsmessage.ResourceHeader
		if err := header.SetEDNS0(1232, dnsmessage.RCodeSuccess, true); err != nil {
			t.Fatalf("SetEDNS0: %v", err)
		}
		if err := b.OPTResource(header, dnsmessage.OPTResource{Options: options}); err != nil {
			t.Fatalf("OPTResource: %v", err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}

func clientSubnet() dnsmessage.Option {
	// One IPv4 /24, the shape a stub resolver or a middlebox adds (RFC 7871 §6).
	data := []byte{0, 1, 24, 0, 192, 0, 2}
	return dnsmessage.Option{Code: ecsOption, Data: data}
}

func TestParseQuestionNormalisesTheNameRoutingComparesOn(t *testing.T) {
	msg := buildQuery(t, "WWW.Example.COM", dnsmessage.TypeA)
	q, err := parseQuestion(msg)
	if err != nil {
		t.Fatalf("parseQuestion: %v", err)
	}
	if q.Name != "www.example.com" {
		t.Errorf("Name = %q, want %q -- lowercased with no trailing dot", q.Name, "www.example.com")
	}
	if q.ID != 0x1234 || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
		t.Errorf("question = %+v, want id 0x1234 A IN", q)
	}
	root, err := parseQuestion(buildQuery(t, "", dnsmessage.TypeNS))
	if err != nil {
		t.Fatalf("parseQuestion(root): %v", err)
	}
	if root.Name != "" {
		t.Errorf("root Name = %q, want the empty string", root.Name)
	}
}

func TestParseQuestionRefusesBytesThatAreNotAMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"empty", nil},
		{"short", []byte{1, 2, 3}},
		{"header with no question", make([]byte, 12)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseQuestion(tc.msg); err == nil {
				t.Fatal("parseQuestion = nil error")
			}
		})
	}
}

// The one option that says which network the user is on is removed; everything else the
// client asked for survives, DNSSEC included.
func TestStripClientSubnetRemovesOnlyTheSubnetOption(t *testing.T) {
	cookie := dnsmessage.Option{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	msg := buildQuery(t, "example.com", dnsmessage.TypeA, cookie, clientSubnet())

	out := stripClientSubnet(msg)
	if bytes.Equal(out, msg) {
		t.Fatal("the message came back unchanged with a client-subnet option in it")
	}
	opt, ok := findOPT(out)
	if !ok {
		t.Fatal("the OPT record was lost")
	}
	if opt.class != 1232 {
		t.Errorf("advertised UDP size = %d, want 1232 -- the client's own setting", opt.class)
	}
	codes := optionCodes(t, opt.rdata)
	if len(codes) != 1 || codes[0] != 10 {
		t.Errorf("remaining options = %v, want just the cookie", codes)
	}
	// The DO bit lives in the OPT record's TTL field; a client asking for DNSSEC must
	// still be asking for it afterwards.
	if !dnssecOK(t, out) {
		t.Error("the DNSSEC OK bit was dropped")
	}
	// The question is still the question.
	q, err := parseQuestion(out)
	if err != nil || q.Name != "example.com" {
		t.Errorf("parseQuestion after stripping = %+v, %v", q, err)
	}
}

func TestStripClientSubnetLeavesEverythingElseAlone(t *testing.T) {
	plain := buildQuery(t, "example.com", dnsmessage.TypeA)
	if out := stripClientSubnet(plain); !bytes.Equal(out, plain) {
		t.Error("a query with no OPT record was rewritten")
	}
	cookie := dnsmessage.Option{Code: 10, Data: []byte{1, 2, 3, 4}}
	withOpt := buildQuery(t, "example.com", dnsmessage.TypeA, cookie)
	if out := stripClientSubnet(withOpt); !bytes.Equal(out, withOpt) {
		t.Error("a query with no client-subnet option was rewritten")
	}
	// Bytes that are not a message must come back exactly as they arrived rather than
	// half-rewritten.
	junk := []byte{9, 9, 9}
	if out := stripClientSubnet(junk); !bytes.Equal(out, junk) {
		t.Error("junk was rewritten")
	}
}

func optionCodes(t *testing.T, rdata []byte) []uint16 {
	t.Helper()
	var codes []uint16
	for off := 0; off+4 <= len(rdata); {
		code := binary.BigEndian.Uint16(rdata[off:])
		length := int(binary.BigEndian.Uint16(rdata[off+2:]))
		codes = append(codes, code)
		off += 4 + length
	}
	return codes
}

func dnssecOK(t *testing.T, msg []byte) bool {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	if err := p.SkipAllAnswers(); err != nil {
		t.Fatalf("SkipAllAnswers: %v", err)
	}
	if err := p.SkipAllAuthorities(); err != nil {
		t.Fatalf("SkipAllAuthorities: %v", err)
	}
	for {
		header, err := p.AdditionalHeader()
		if err != nil {
			return false
		}
		if header.Type == dnsmessage.TypeOPT {
			return header.DNSSECAllowed()
		}
		if err := p.SkipAdditional(); err != nil {
			return false
		}
	}
}

func TestUDPPayloadSizeFollowsWhatTheClientAdvertised(t *testing.T) {
	if got := udpPayloadSize(buildQuery(t, "example.com", dnsmessage.TypeA)); got != 512 {
		t.Errorf("payload size with no OPT = %d, want 512", got)
	}
	withOpt := buildQuery(t, "example.com", dnsmessage.TypeA, dnsmessage.Option{Code: 10, Data: []byte{1}})
	if got := udpPayloadSize(withOpt); got != 1232 {
		t.Errorf("payload size = %d, want the advertised 1232", got)
	}
}

func TestLocalhostAnswerIsLoopbackAndNothingElse(t *testing.T) {
	tests := []struct {
		typ  dnsmessage.Type
		want string
	}{
		{dnsmessage.TypeA, "127.0.0.1"},
		{dnsmessage.TypeAAAA, "::1"},
	}
	for _, tc := range tests {
		q := question("app.localhost", tc.typ)
		addrs := addressesIn(t, localhostAnswer(q))
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr(tc.want) {
			t.Errorf("localhostAnswer(%s) = %v, want [%s]", tc.typ, addrs, tc.want)
		}
	}
	// Any other type: the name exists and has nothing of that kind, which is NOERROR
	// with no records rather than NXDOMAIN.
	mx := localhostAnswer(question("app.localhost", dnsmessage.TypeMX))
	if code, _ := rcode(mx); code != dnsmessage.RCodeSuccess {
		t.Errorf("MX rcode = %s, want NOERROR", code)
	}
	if addrs := addressesIn(t, mx); len(addrs) != 0 {
		t.Errorf("MX answer carries %v", addrs)
	}
}

func addressesIn(t *testing.T, msg []byte) []netip.Addr {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	var out []netip.Addr
	for {
		header, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		switch header.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				t.Fatalf("AResource: %v", err)
			}
			out = append(out, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				t.Fatalf("AAAAResource: %v", err)
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				t.Fatalf("SkipAnswer: %v", err)
			}
		}
	}
}

func TestResponseEchoesTheQuestionSoAClientCanMatchIt(t *testing.T) {
	q := question("example.com", dnsmessage.TypeA)
	resp := response(q, dnsmessage.RCodeServerFailure)
	if !isResponse(resp) {
		t.Error("the QR bit is not set")
	}
	if code, _ := rcode(resp); code != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", code)
	}
	if !answersQuestion(resp, q) {
		t.Error("the response does not echo the question")
	}
	tc := truncatedResponse(q)
	if !truncated(tc) {
		t.Error("truncatedResponse does not set the TC bit")
	}
}

// A name too long to encode still gets an answer: a machine waiting on a resolver that
// says nothing behaves far worse than one told the query failed.
func TestAnUnbuildableNameStillGetsAnAnswer(t *testing.T) {
	long := ""
	for i := 0; i < 40; i++ {
		long += "abcdefgh."
	}
	q := Question{ID: 7, Name: long[:len(long)-1], Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	resp := response(q, dnsmessage.RCodeFormatError)
	if len(resp) < 12 {
		t.Fatalf("response is %d bytes", len(resp))
	}
	if id, _ := queryID(resp); id != 7 {
		t.Errorf("id = %d, want 7", id)
	}
	if code, _ := rcode(resp); code != dnsmessage.RCodeFormatError {
		t.Errorf("rcode = %s, want FORMERR", code)
	}
}

// negativeSOAIn returns the SOA a negative answer carries in its authority section, and
// whether it carried one at all.
func negativeSOAIn(t *testing.T, msg []byte) (dnsmessage.ResourceHeader, dnsmessage.SOAResource, bool) {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	if err := p.SkipAllAnswers(); err != nil {
		t.Fatalf("SkipAllAnswers: %v", err)
	}
	for {
		header, err := p.AuthorityHeader()
		if err != nil {
			return dnsmessage.ResourceHeader{}, dnsmessage.SOAResource{}, false
		}
		if header.Type != dnsmessage.TypeSOA {
			if err := p.SkipAuthority(); err != nil {
				t.Fatalf("SkipAuthority: %v", err)
			}
			continue
		}
		soa, err := p.SOAResource()
		if err != nil {
			t.Fatalf("SOAResource: %v", err)
		}
		return header, soa, true
	}
}

// A "no" this package decided itself has to say how long it may be believed. RFC 2308
// takes that lifetime from the SOA in the authority section, and a reply without one is
// cached for however long the client feels like -- so a name blocked by a list stays dead
// after the list is switched off, with nothing on this side able to expire the entry.
func TestALocalNegativeAnswerSaysHowLongItMayBeRemembered(t *testing.T) {
	tests := []struct {
		name   string
		answer BlockAnswer
		typ    dnsmessage.Type
		host   string
	}{
		{"a blocked name answered NXDOMAIN", AnswerNXDomain, dnsmessage.TypeA, "ads.example.com"},
		{"a blocked name with no record of the asked kind", AnswerSinkhole, dnsmessage.TypeMX, "ads.example.com"},
		{"the loopback zone with no record of the asked kind", AnswerNXDomain, dnsmessage.TypeMX, "localhost"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestForwarder(t, Config{
				Rules: Rules{
					HaveLocal:   true,
					Block:       blocking("ads.example.com"),
					BlockAnswer: tc.answer,
				},
				Profile: NewPool([]Upstream{answering("profile", "203.0.113.5")}, nil),
			})

			resp := f.Answer(context.Background(), buildQuery(t, tc.host, tc.typ), false)

			header, soa, ok := negativeSOAIn(t, resp)
			if !ok {
				t.Fatal("the answer carries no SOA, so nothing bounds how long it is cached")
			}
			// RFC 2308 takes the negative lifetime as the lesser of the two, so both bind.
			if header.TTL != localTTL {
				t.Errorf("SOA TTL = %d, want %d", header.TTL, localTTL)
			}
			if soa.MinTTL != localTTL {
				t.Errorf("SOA MinTTL = %d, want %d", soa.MinTTL, localTTL)
			}
			if got := header.Name.String(); got != tc.host+"." {
				t.Errorf("SOA owner = %q, want the queried name %q", got, tc.host+".")
			}
		})
	}
}

// REFUSED says this resolver will not answer, not that the name has nothing. It is not a
// negative answer, nothing caches it, and inventing a zone to bound it would be a lie
// about a name this resolver never looked at.
func TestARefusedAnswerCarriesNoInventedZone(t *testing.T) {
	f := newTestForwarder(t, Config{
		Rules: Rules{
			HaveLocal:   true,
			Block:       blocking("ads.example.com"),
			BlockAnswer: AnswerRefused,
		},
		Profile: NewPool([]Upstream{answering("profile", "203.0.113.5")}, nil),
	})

	resp := f.Answer(context.Background(), buildQuery(t, "ads.example.com", dnsmessage.TypeA), false)

	if _, _, ok := negativeSOAIn(t, resp); ok {
		t.Error("a REFUSED answer carries an SOA; only answers about the name itself may")
	}
}

// The sinkhole address and the SOA that bounds a negative answer drain together: two
// shapes of the same made-up answer, and a client that forgot one while holding the other
// would see the setting take effect twice.
func TestASinkholeAddressAndANegativeAnswerExpireTogether(t *testing.T) {
	f := newTestForwarder(t, Config{
		Rules: Rules{
			HaveLocal:   true,
			Block:       blocking("ads.example.com"),
			BlockAnswer: AnswerSinkhole,
		},
		Profile: NewPool([]Upstream{answering("profile", "203.0.113.5")}, nil),
	})

	resp := f.Answer(context.Background(), buildQuery(t, "ads.example.com", dnsmessage.TypeA), false)

	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	header, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("AnswerHeader: %v", err)
	}
	if header.TTL != localTTL {
		t.Errorf("sinkhole TTL = %d, want %d", header.TTL, localTTL)
	}
}
