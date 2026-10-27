// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/testport"
)

// answerFor is what every test resolver in this file replies with: the question echoed and
// one address, so the caller can tell its own answer from anyone else's.
func answerFor(query []byte, addr string) ([]byte, error) {
	q, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	resp := buildResponse(q, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{
		addressRecord(q, netip.MustParseAddr(addr)),
	}, nil)
	id, _ := queryID(query)
	setID(resp, id)
	return resp, nil
}

// servePlain runs a plain-DNS resolver on a loopback port, over both transports. The port
// is one reserved as bindable for both: a ":0" UDP bind can land on a number the machine
// keeps TCP off, as Windows does across the ranges it excludes.
func servePlain(t *testing.T, addr string) (netip.AddrPort, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	port, err := testport.Reserve()
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		t.Fatalf("listen tcp on the same port: %v", err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })

	var udpCalls, tcpCalls atomic.Int32
	go func() {
		buf := make([]byte, maxUDPAnswer)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			udpCalls.Add(1)
			resp, err := answerFor(buf[:n], addr)
			if err != nil {
				continue
			}
			pc.WriteTo(resp, from)
		}
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					query, err := readFramed(conn)
					if err != nil {
						return
					}
					tcpCalls.Add(1)
					resp, err := answerFor(query, addr)
					if err != nil {
						return
					}
					if err := writeFramed(conn, resp); err != nil {
						return
					}
				}
			}()
		}
	}()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), &udpCalls, &tcpCalls
}

func TestThePlainUpstreamUsesUDPAndTCPAsAsked(t *testing.T) {
	addr, udpCalls, tcpCalls := servePlain(t, "203.0.113.20")
	up, err := newPlainUpstream(dnsprofiles.Upstream{Protocol: dnsprofiles.Plain, Text: addr.String(), Addr: addr})
	if err != nil {
		t.Fatalf("newPlainUpstream: %v", err)
	}
	defer up.Close()

	ctx := context.Background()
	query := buildQuery(t, "example.com", dnsmessage.TypeA)
	for _, stream := range []bool{false, true} {
		resp, err := up.Exchange(ctx, query, stream)
		if err != nil {
			t.Fatalf("Exchange(stream=%v): %v", stream, err)
		}
		if addrs := addressesIn(t, resp); len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.20") {
			t.Errorf("stream=%v answer = %v", stream, addrs)
		}
		if id, _ := queryID(resp); id != 0x1234 {
			t.Errorf("stream=%v id = %#x, want the client's own %#x", stream, id, 0x1234)
		}
	}
	if udpCalls.Load() != 1 || tcpCalls.Load() != 1 {
		t.Errorf("udp calls = %d, tcp calls = %d, want one each", udpCalls.Load(), tcpCalls.Load())
	}
}

// The id on the wire is not the client's, so a reply someone guessed the client's id for
// does not match anything we asked.
func TestThePlainUpstreamRandomisesTheIdItSendsOut(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	seen := make(chan uint16, 4)
	go func() {
		buf := make([]byte, maxUDPAnswer)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			id, _ := queryID(buf[:n])
			seen <- id
			resp, err := answerFor(buf[:n], "203.0.113.21")
			if err != nil {
				continue
			}
			pc.WriteTo(resp, from)
		}
	}()

	addr := netip.MustParseAddrPort(pc.LocalAddr().String())
	up, err := newPlainUpstream(dnsprofiles.Upstream{Protocol: dnsprofiles.Plain, Text: addr.String(), Addr: addr})
	if err != nil {
		t.Fatalf("newPlainUpstream: %v", err)
	}
	defer up.Close()

	ids := make(map[uint16]bool)
	for i := 0; i < 3; i++ {
		if _, err := up.Exchange(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		ids[<-seen] = true
	}
	if ids[0x1234] {
		t.Error("the client's own transaction id went out on the wire")
	}
	if len(ids) < 2 {
		t.Errorf("three queries used %d distinct ids; they must not be predictable", len(ids))
	}
}

// A reply to a question we did not ask is not an answer, however well it matches
// otherwise. Accepting one is how a resolver gets poisoned.
func TestThePlainUpstreamIgnoresAnAnswerToADifferentQuestion(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, maxUDPAnswer)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			id, _ := queryID(buf[:n])
			// The right id, the wrong question: the shape of a forged answer.
			wrong := Question{ID: id, Name: "elsewhere.example", Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
			resp := buildResponse(wrong, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{
				addressRecord(wrong, netip.MustParseAddr("198.51.100.1")),
			}, nil)
			pc.WriteTo(resp, from)
		}
	}()

	addr := netip.MustParseAddrPort(pc.LocalAddr().String())
	up, err := newPlainUpstream(dnsprofiles.Upstream{Protocol: dnsprofiles.Plain, Text: addr.String(), Addr: addr})
	if err != nil {
		t.Fatalf("newPlainUpstream: %v", err)
	}
	defer up.Close()

	const wait = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	started := time.Now()
	resp, err := up.Exchange(ctx, buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if err == nil {
		t.Fatalf("Exchange accepted an answer to another question: %v", addressesIn(t, resp))
	}
	// Ignoring means waiting on for the real one, so the forgery ends at the deadline and
	// not before. A read that gave up on the forgery itself would let one forged packet
	// knock out a query a real answer was about to satisfy.
	if elapsed := time.Since(started); elapsed < wait-100*time.Millisecond {
		t.Fatalf("Exchange gave up after %v with %v, want it to keep listening until the deadline", elapsed, err)
	}
	// The socket deadline and the context share an instant, so either may be the one that
	// reports it; anything else is a failure the forgery caused.
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("Exchange = %v, want a deadline", err)
	}
}

// The same rule on a stream, where the id is the only thing routing an answer back to the
// caller waiting for it. Many queries share one connection, and an id is reused once the
// query holding it gives up, so an answer carrying the right id is not yet an answer to
// the question that id currently belongs to.
func TestAnAnswerOnAStreamIsRefusedWhenItAnswersADifferentQuestion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					query, err := readFramed(conn)
					if err != nil {
						return
					}
					id, _ := queryID(query)
					// The id the client is waiting on, carrying somebody else's name.
					wrong := Question{ID: id, Name: "elsewhere.example", Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
					resp := buildResponse(wrong, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{
						addressRecord(wrong, netip.MustParseAddr("198.51.100.2")),
					}, nil)
					if err := writeFramed(conn, resp); err != nil {
						return
					}
				}
			}()
		}
	}()

	addr := netip.MustParseAddrPort(ln.Addr().String())
	up, err := newPlainUpstream(dnsprofiles.Upstream{Protocol: dnsprofiles.Plain, Text: addr.String(), Addr: addr})
	if err != nil {
		t.Fatalf("newPlainUpstream: %v", err)
	}
	defer up.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := up.Exchange(ctx, buildQuery(t, "example.com", dnsmessage.TypeA), true)
	if err == nil {
		t.Fatalf("Exchange accepted an answer to another question: %v", addressesIn(t, resp))
	}
	// Named so the failure is not confused with the connection dying, which is the other
	// way this exchange ends and the one that gets retried instead of refused.
	if !strings.Contains(err.Error(), "answered something other than") {
		t.Errorf("Exchange error = %v, want one saying the answer was to a different question", err)
	}
}

// A resolver that echoes the question it was asked is still answered normally -- the check
// above must not refuse the ordinary case it is wrapped around.
func TestAnAnswerOnAStreamToTheQuestionAskedIsStillAccepted(t *testing.T) {
	addr, _, tcpCalls := servePlain(t, "203.0.113.30")
	up, err := newPlainUpstream(dnsprofiles.Upstream{Protocol: dnsprofiles.Plain, Text: addr.String(), Addr: addr})
	if err != nil {
		t.Fatalf("newPlainUpstream: %v", err)
	}
	defer up.Close()

	resp, err := up.Exchange(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), true)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if addrs := addressesIn(t, resp); len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.30") {
		t.Errorf("answer = %v, want the address the resolver gave", addrs)
	}
	if id, _ := queryID(resp); id != 0x1234 {
		t.Errorf("id = %#x, want the client's own %#x", id, 0x1234)
	}
	if tcpCalls.Load() != 1 {
		t.Errorf("tcp calls = %d, want one", tcpCalls.Load())
	}
}

// testCert makes a certificate a test TLS server can present and a test client can trust,
// so the encrypted transports are exercised with verification on rather than skipped.
func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              names,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create a certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, pool
}

func TestTheDoTUpstreamPipelinesOverOneVerifiedConnection(t *testing.T) {
	cert, pool := testCert(t, "dot.invalid")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var conns atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conn.Close()
				for {
					conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					query, err := readFramed(conn)
					if err != nil {
						return
					}
					resp, err := answerFor(query, "203.0.113.30")
					if err != nil {
						return
					}
					if err := writeFramed(conn, resp); err != nil {
						return
					}
				}
			}()
		}
	}()

	addr := netip.MustParseAddrPort(ln.Addr().String())
	up, err := newDoTUpstream(dnsprofiles.Upstream{
		Protocol:   dnsprofiles.DoT,
		Text:       "tls://dot.invalid",
		Addr:       addr,
		Port:       addr.Port(),
		Host:       "dot.invalid",
		ServerName: "dot.invalid",
	}, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("newDoTUpstream: %v", err)
	}
	defer up.Close()

	for i := 0; i < 4; i++ {
		resp, err := up.Exchange(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
		if err != nil {
			t.Fatalf("Exchange %d: %v", i, err)
		}
		if addrs := addressesIn(t, resp); len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.30") {
			t.Errorf("answer %d = %v", i, addrs)
		}
		if id, _ := queryID(resp); id != 0x1234 {
			t.Errorf("answer %d carries id %#x, want the client's %#x", i, id, 0x1234)
		}
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("the resolver saw %d connections for four queries, want 1 -- a handshake per query is the cost this avoids", got)
	}
}

// A resolver that hangs up mid-query fails that query rather than hanging it, and the next
// query dials a fresh connection.
func TestADoTConnectionDroppedMidQueryFailsThatQueryAndRecovers(t *testing.T) {
	cert, pool := testCert(t, "dot.invalid")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var seen atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					query, err := readFramed(conn)
					if err != nil {
						return
					}
					// The first two queries are dropped on the floor -- one per
					// connection, since hanging up ends the connection.
					if seen.Add(1) <= 2 {
						return
					}
					resp, err := answerFor(query, "203.0.113.31")
					if err != nil {
						return
					}
					writeFramed(conn, resp)
				}
			}()
		}
	}()

	addr := netip.MustParseAddrPort(ln.Addr().String())
	up, err := newDoTUpstream(dnsprofiles.Upstream{
		Protocol: dnsprofiles.DoT, Text: "tls://dot.invalid", Addr: addr, Port: addr.Port(),
		Host: "dot.invalid", ServerName: "dot.invalid",
	}, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("newDoTUpstream: %v", err)
	}
	defer up.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := up.Exchange(ctx, buildQuery(t, "example.com", dnsmessage.TypeA), false); err == nil {
		t.Fatal("Exchange succeeded although the resolver hung up twice")
	}
	resp, err := up.Exchange(ctx, buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatalf("the exchange after a dropped connection: %v", err)
	}
	if addrs := addressesIn(t, resp); len(addrs) != 1 {
		t.Errorf("answer = %v", addrs)
	}
}

// The deadlock this prevents: on a machine whose system resolver is this process, looking
// the resolver's own hostname up through the system resolver is a query waiting on itself.
func TestTheDoHDialerNeverAsksTheSystemResolver(t *testing.T) {
	var lookups atomic.Int32
	restore := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			lookups.Add(1)
			return nil, io.EOF
		},
	}
	t.Cleanup(func() { net.DefaultResolver = restore })

	cert, pool := testCert(t, "doh.invalid")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxStreamAnswer))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if id, _ := queryID(body); id != 0 {
			http.Error(w, "the transaction id was not zero", http.StatusBadRequest)
			return
		}
		resp, err := answerFor(body, "203.0.113.40")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", dohMediaType)
		w.Write(resp)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	addr := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))
	// The URL names a host that resolves nowhere. Only the pinned address makes this
	// reachable, so an answer at all is the proof.
	up, err := newDoHUpstream(dnsprofiles.Upstream{
		Protocol: dnsprofiles.DoH, Text: "https://doh.invalid/dns-query", URL: "https://doh.invalid/dns-query",
		Addr: addr, Port: addr.Port(), Host: "doh.invalid", ServerName: "doh.invalid",
	}, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("newDoHUpstream: %v", err)
	}
	defer up.Close()

	resp, err := up.Exchange(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if addrs := addressesIn(t, resp); len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.40") {
		t.Errorf("answer = %v", addrs)
	}
	if id, _ := queryID(resp); id != 0x1234 {
		t.Errorf("id = %#x, want the client's %#x restored", id, 0x1234)
	}
	if got := lookups.Load(); got != 0 {
		t.Errorf("the system resolver was asked %d times; on this machine that is a query waiting on itself", got)
	}
}

func TestTheDoHUpstreamRefusesAnAnswerThatIsNotADNSMessage(t *testing.T) {
	cert, pool := testCert(t, "doh.invalid")
	var status atomic.Int32
	status.Store(http.StatusOK)
	var body atomic.Value
	body.Store([]byte("<html>sign in to continue</html>"))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(int(status.Load()))
		w.Write(body.Load().([]byte))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	addr := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))
	up, err := newDoHUpstream(dnsprofiles.Upstream{
		Protocol: dnsprofiles.DoH, Text: "https://doh.invalid/dns-query", URL: "https://doh.invalid/dns-query",
		Addr: addr, Port: addr.Port(), Host: "doh.invalid", ServerName: "doh.invalid",
	}, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("newDoHUpstream: %v", err)
	}
	defer up.Close()

	// A captive portal answering the request with its sign-in page is the case this
	// catches, and taking its bytes for an answer would be a resolver returning HTML.
	if _, err := up.Exchange(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false); err == nil {
		t.Fatal("Exchange accepted an HTML body as a DNS answer")
	}

	status.Store(http.StatusForbidden)
	if _, err := up.Exchange(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false); err == nil {
		t.Fatal("Exchange accepted an HTTP 403 as an answer")
	} else if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want it to name the status", err)
	}
}

// A frame claiming more bytes than it carries must not leave the reader waiting forever,
// and a zero-length frame is not a message.
func TestReadFramedRefusesAnEmptyFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], 0)
		server.Write(length[:])
	}()
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFramed(client); err == nil {
		t.Fatal("readFramed accepted a zero-length frame")
	}
}

// The question is read once, before anything is dialled, because every answer coming back on
// the connection is matched against it. A query nothing can be read out of is one no answer
// could be checked against, so it is refused here rather than carried to a resolver.
func TestAQueryThatCarriesNoQuestionIsRefusedBeforeAnythingIsDialled(t *testing.T) {
	var dialled atomic.Int32
	client := newStreamClient("test", func(context.Context) (net.Conn, error) {
		dialled.Add(1)
		return nil, io.EOF
	}, time.Second)

	if _, err := client.Exchange(t.Context(), []byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("a query with no question in it was accepted")
	}
	if got := dialled.Load(); got != 0 {
		t.Errorf("the resolver was dialled %d times for a query that was never readable", got)
	}
}
