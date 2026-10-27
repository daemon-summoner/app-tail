// SPDX-License-Identifier: MIT

package dnsfwd

// What one query costs end to end against a real resolver on the loopback: the routing
// decision, the wire encoding, and the socket the plain-UDP path opens for it.

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sellitus/app-tail/internal/dnsprofiles"
)

// benchAnswer is what the stub resolver answers with. Its value never matters, only that
// it is a well-formed record the forwarder will accept.
var benchAnswer = netip.MustParseAddr("203.0.113.7")

// BenchmarkForwarderAnswerUDP is the whole default path -- a query in, an answer out, over
// UDP to a resolver that answers immediately. A real socket is used rather than a fake
// upstream because the socket is the cost being measured: the plain path opens one per
// query.
func BenchmarkForwarderAnswerUDP(b *testing.B) {
	addr := stubResolver(b)
	up, err := NewUpstream(dnsprofiles.Upstream{
		Protocol: dnsprofiles.Plain,
		Text:     addr.String(),
		Addr:     addr,
	}, nil)
	if err != nil {
		b.Fatalf("build the resolver: %v", err)
	}
	b.Cleanup(func() { up.Close() })

	f := New(Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{up}, nil),
	})
	query := benchQuery(b, "example.com", dnsmessage.TypeA)
	ctx := context.Background()

	// A benchmark that measured a SERVFAIL would be measuring the wrong path entirely.
	if answered := answerCode(b, f.Answer(ctx, query, false)); answered != dnsmessage.RCodeSuccess {
		b.Fatalf("the resolver answered %v, want success", answered)
	}

	b.ReportAllocs()
	for b.Loop() {
		if f.Answer(ctx, query, false) == nil {
			b.Fatal("the query went unanswered")
		}
	}
}

// BenchmarkForwarderAnswerParallel is the same query from several callers at once, which
// is what a browser opening a page produces.
func BenchmarkForwarderAnswerParallel(b *testing.B) {
	addr := stubResolver(b)
	up, err := NewUpstream(dnsprofiles.Upstream{
		Protocol: dnsprofiles.Plain,
		Text:     addr.String(),
		Addr:     addr,
	}, nil)
	if err != nil {
		b.Fatalf("build the resolver: %v", err)
	}
	b.Cleanup(func() { up.Close() })

	f := New(Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{up}, nil),
	})
	query := benchQuery(b, "example.com", dnsmessage.TypeA)
	ctx := context.Background()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if f.Answer(ctx, query, false) == nil {
				b.Error("the query went unanswered")
				return
			}
		}
	})
}

// BenchmarkPlainExchangeUDP is the plain path with the routing above it removed: one
// query, one socket, one answer. It pairs with BenchmarkPlainExchangeReusedSocket -- the
// difference between the two is what opening a socket per query costs.
func BenchmarkPlainExchangeUDP(b *testing.B) {
	addr := stubResolver(b)
	up, err := newPlainUpstream(dnsprofiles.Upstream{
		Protocol: dnsprofiles.Plain,
		Text:     addr.String(),
		Addr:     addr,
	})
	if err != nil {
		b.Fatalf("build the resolver: %v", err)
	}
	b.Cleanup(func() { up.Close() })

	query := benchQuery(b, "example.com", dnsmessage.TypeA)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := up.exchangeUDP(ctx, query); err != nil {
			b.Fatalf("exchange: %v", err)
		}
	}
}

// BenchmarkPlainExchangeReusedSocket is the same round trip over a socket that stays open,
// which is the floor the loopback and the stub resolver impose. Anything above this floor
// in BenchmarkPlainExchangeUDP is the socket, not the network.
func BenchmarkPlainExchangeReusedSocket(b *testing.B) {
	addr := stubResolver(b)
	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		b.Fatalf("dial the resolver: %v", err)
	}
	b.Cleanup(func() { conn.Close() })

	query := benchQuery(b, "example.com", dnsmessage.TypeA)
	buf := make([]byte, maxUDPAnswer)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := conn.Write(query); err != nil {
			b.Fatalf("send: %v", err)
		}
		if _, err := conn.Read(buf); err != nil {
			b.Fatalf("receive: %v", err)
		}
	}
}

// stubResolver answers every query it is sent with one address record, so the benchmark
// measures this package rather than whatever is upstream of it.
//
// It reads from several goroutines and encodes nothing per query -- the answer is built
// once and only its transaction id is rewritten -- because a resolver that serialised the
// queries would put its own cost in the measurement.
func stubResolver(b *testing.B) netip.AddrPort {
	b.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("start a resolver: %v", err)
	}
	b.Cleanup(func() { pc.Close() })

	const readers = 4
	for range readers {
		go func() {
			buf := make([]byte, maxUDPAnswer)
			var prepared []byte
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				id, ok := queryID(buf[:n])
				if !ok {
					continue
				}
				if prepared == nil {
					q, err := parseQuestion(buf[:n])
					if err != nil {
						continue
					}
					prepared = buildResponse(q, dnsmessage.RCodeSuccess, false,
						[]dnsmessage.Resource{addressRecord(q, benchAnswer)}, nil)
				}
				answer := make([]byte, len(prepared))
				copy(answer, prepared)
				setID(answer, id)
				if _, err := pc.WriteTo(answer, from); err != nil {
					return
				}
			}
		}()
	}
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// answerCode reads the response code off an answer, so a benchmark measuring a failure
// path fails instead of reporting a fast number.
func answerCode(b *testing.B, answer []byte) dnsmessage.RCode {
	b.Helper()
	if answer == nil {
		b.Fatal("the query went unanswered")
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(answer)
	if err != nil {
		b.Fatalf("parse the answer: %v", err)
	}
	return header.RCode
}

// benchQuery is buildQuery for a benchmark: the test helper takes a *testing.T.
func benchQuery(b *testing.B, name string, typ dnsmessage.Type) []byte {
	b.Helper()
	dn, err := dnsmessage.NewName(name + ".")
	if err != nil {
		b.Fatalf("NewName(%q): %v", name, err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		b.Fatalf("StartQuestions: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{Name: dn, Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		b.Fatalf("Question: %v", err)
	}
	msg, err := builder.Finish()
	if err != nil {
		b.Fatalf("Finish: %v", err)
	}
	return msg
}
