// SPDX-License-Identifier: MIT

package tlsmint

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/netpipe"
)

// The real server in these tests is a second Authority: it is a certificate authority nothing
// on this machine trusts, presenting certificates for whatever name it is asked for, which is
// exactly what an ordinary server on the internet looks like from here.
type realServer struct {
	ca    *Authority
	roots *x509.CertPool
	alpn  []string
	// unnamed is the name the server presents to a client that sent no server name, which is
	// the address it was dialled at on a real server and "unnamed.example" when a test does not
	// care.
	unnamed string
	// spoke records what the server received in the clear, so a test can assert the plaintext
	// really crossed rather than that the handshake merely completed.
	mu    sync.Mutex
	spoke []byte
}

func newRealServer(t *testing.T, alpn []string) *realServer {
	t.Helper()
	ca, err := NewAuthority(theTimeIs, broadLimits(t))
	if err != nil {
		t.Fatalf("generating the real server's authority failed: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("the real server's authority is not readable")
	}
	return &realServer{ca: ca, roots: roots, alpn: alpn, unnamed: "unnamed.example"}
}

// serve runs the far end of the connection: it completes a handshake and echoes whatever it is
// sent, which is enough for a test to see plaintext reach it and come back.
func (s *realServer) serve(conn net.Conn) {
	server := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: s.alpn,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = s.unnamed
			}
			return s.ca.Leaf(name, theTimeIs)
		},
	})
	defer server.Close()
	if err := server.Handshake(); err != nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := server.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.spoke = append(s.spoke, buf[:n]...)
			s.mu.Unlock()
			if _, err := server.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *realServer) heard() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.spoke...)
}

// recorder is the inspection side: what a stream watching the carried connection is handed.
type recorder struct {
	mu sync.Mutex
	up []byte
}

func (r *recorder) Up(b []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.up = append(r.up, b...)
	return false
}

func (r *recorder) Down([]byte) bool { return false }
func (r *recorder) Close()           {}

func (r *recorder) saw() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.up...)
}

// carried is one connection taken all the way through: a real client at one end, a real server
// at the other, and Open in between deciding what happens to it.
type carried struct {
	result  Result
	openErr error
	// farEnd is the destination's side of the wire, for a test asserting what actually arrived
	// there. It is the far end of the pipe rather than the connection Open handed back, because
	// that one is being read by the copy.
	farEnd   net.Conn
	watching *recorder
}

// carry wires a client to a server through Open and, when Open handed back a pair, copies
// between them with an inspector watching.
//
// The client's own work runs on another goroutine because Open is what answers its handshake:
// the two have to be in flight together or neither completes.
func carry(t *testing.T, cfg Config, server *realServer, clientCfg *tls.Config, at netip.Addr, client func(net.Conn)) *carried {
	t.Helper()

	clientEnd, interceptClient := net.Pipe()
	interceptUpstream, serverEnd := net.Pipe()
	t.Cleanup(func() {
		_ = clientEnd.Close()
		_ = interceptClient.Close()
		_ = interceptUpstream.Close()
		_ = serverEnd.Close()
	})

	if server != nil {
		go server.serve(serverEnd)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		client(clientEnd)
	}()

	// Cancelled when the test ends rather than when this returns: the copy below runs on this
	// context, and cancelling it here would cut the connection the caller is about to assert on.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	held := &carried{farEnd: serverEnd, watching: &recorder{}}
	held.result, held.openErr = Open(ctx, cfg, interceptClient, interceptUpstream, at)
	if held.openErr == nil {
		copied := make(chan struct{})
		go func() {
			defer close(copied)
			_ = netpipe.CopyWith(ctx, held.result.Client, held.result.Upstream, nil, nil, held.watching)
		}()
		t.Cleanup(func() {
			_ = held.result.Client.Close()
			_ = held.result.Upstream.Close()
			<-copied
		})
	} else {
		_ = interceptClient.Close()
		_ = interceptUpstream.Close()
	}

	<-done
	return held
}

// tlsClient is a client that completes a handshake, sends one line and reads the answer, and
// records what happened for the test to assert on.
type tlsClient struct {
	config *tls.Config
	says   string

	mu         sync.Mutex
	handshake  error
	heard      string
	negotiated string
	presented  []*x509.Certificate
}

func (c *tlsClient) run(conn net.Conn) {
	client := tls.Client(conn, c.config)
	defer client.Close()
	if err := client.Handshake(); err != nil {
		c.mu.Lock()
		c.handshake = err
		c.mu.Unlock()
		return
	}
	state := client.ConnectionState()
	c.mu.Lock()
	c.negotiated = state.NegotiatedProtocol
	c.presented = state.PeerCertificates
	c.mu.Unlock()

	if _, err := io.WriteString(client, c.says); err != nil {
		return
	}
	buf := make([]byte, len(c.says))
	if _, err := io.ReadFull(client, buf); err != nil {
		return
	}
	c.mu.Lock()
	c.heard = string(buf)
	c.mu.Unlock()
}

func (c *tlsClient) result() (err error, heard, negotiated string, presented []*x509.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handshake, c.heard, c.negotiated, c.presented
}

func ourRoots(t *testing.T, a *Authority) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.CertPEM()) {
		t.Fatal("the interception root is not readable")
	}
	return pool
}

// TestAnInterceptedConnectionIsPlaintextOnTheInsideAndWorksOnBothEnds is the whole feature in
// one test: a real client reaches a real server, both handshakes are real, and the bytes
// between them are readable by inspection.
func TestAnInterceptedConnectionIsPlaintextOnTheInsideAndWorksOnBothEnds(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	server := newRealServer(t, nil)

	client := &tlsClient{
		config: &tls.Config{
			ServerName: "opened.example",
			RootCAs:    ourRoots(t, authority),
			Time:       func() time.Time { return theTimeIs },
		},
		says: "the quick brown fox",
	}
	held := carry(t, Config{
		Scope:     compileScope(t, ModeOnly, []string{"opened.example"}),
		Authority: authority,
		Roots:     server.roots,
		Now:       func() time.Time { return theTimeIs },
	}, server, nil, netip.Addr{}, client.run)

	if held.openErr != nil {
		t.Fatalf("opening the connection failed: %v", held.openErr)
	}
	if !held.result.Intercepted {
		t.Fatalf("the connection was not intercepted: %s", held.result.Why)
	}
	if held.result.Name != "opened.example" {
		t.Fatalf("the connection was opened for %q", held.result.Name)
	}

	err, heard, _, presented := client.result()
	if err != nil {
		t.Fatalf("the client's handshake failed: %v", err)
	}
	if heard != client.says {
		t.Fatalf("the client heard %q back, not what it sent", heard)
	}
	if got := string(server.heard()); got != client.says {
		t.Fatalf("the real server received %q", got)
	}
	if len(presented) == 0 || presented[0].Subject.CommonName != "opened.example" {
		t.Fatal("the client was not handed a certificate minted for the name it asked for")
	}

	// The point of all of it: what crossed is readable, so the same inspection that runs on a
	// plaintext connection runs on this one.
	if !bytes.Contains(held.watching.saw(), []byte(client.says)) {
		t.Fatalf("inspection saw %q, not the plaintext that crossed", held.watching.saw())
	}
}

// TestAServerThatDoesNotVerifyStopsTheConnectionRatherThanBeingCarried is the property that
// keeps interception from being a downgrade. The client can no longer check who it is talking
// to, so this side refusing is the only check left, and it has to be a refusal rather than a
// note in a log.
func TestAServerThatDoesNotVerifyStopsTheConnectionRatherThanBeingCarried(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	server := newRealServer(t, nil)

	client := &tlsClient{
		config: &tls.Config{
			ServerName: "opened.example",
			RootCAs:    ourRoots(t, authority),
			Time:       func() time.Time { return theTimeIs },
		},
		says: "never sent",
	}
	held := carry(t, Config{
		Scope:     compileScope(t, ModeOnly, []string{"opened.example"}),
		Authority: authority,
		// Nothing the real server's certificate chains to.
		Roots: x509.NewCertPool(),
		Now:   func() time.Time { return theTimeIs },
	}, server, nil, netip.Addr{}, client.run)

	if held.openErr == nil {
		t.Fatal("a connection to a server that did not verify was carried")
	}
	if !errors.Is(held.openErr, ErrUpstreamRefused) {
		t.Fatalf("the connection was stopped for the wrong reason: %v", held.openErr)
	}
	if !strings.Contains(held.openErr.Error(), "opened.example") {
		t.Fatalf("the failure does not name the destination: %v", held.openErr)
	}

	err, _, _, presented := client.result()
	if err == nil {
		t.Fatal("the client completed a handshake with a server nothing verified")
	}
	if len(presented) != 0 {
		t.Fatal("the client was handed a certificate for a server nothing verified")
	}
}

// TestTheProtocolTheClientEndsUpSpeakingIsTheOneTheServerAgreedTo keeps the two halves from
// speaking different application protocols, which surfaces as software that connects and then
// behaves as if the other end is broken.
func TestTheProtocolTheClientEndsUpSpeakingIsTheOneTheServerAgreedTo(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		name       string
		serverALPN []string
		clientALPN []string
		want       string
	}{
		{"both offer the same two", []string{"h2", "http/1.1"}, []string{"h2", "http/1.1"}, "h2"},
		{"the server speaks only the older one", []string{"http/1.1"}, []string{"h2", "http/1.1"}, "http/1.1"},
		{"neither offers any", nil, nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			authority := newTestAuthority(t)
			server := newRealServer(t, c.serverALPN)

			client := &tlsClient{
				config: &tls.Config{
					ServerName: "opened.example",
					RootCAs:    ourRoots(t, authority),
					NextProtos: c.clientALPN,
					Time:       func() time.Time { return theTimeIs },
				},
				says: "spoken",
			}
			held := carry(t, Config{
				Scope:     compileScope(t, ModeOnly, []string{"opened.example"}),
				Authority: authority,
				Roots:     server.roots,
				Now:       func() time.Time { return theTimeIs },
			}, server, nil, netip.Addr{}, client.run)

			if held.openErr != nil {
				t.Fatalf("opening the connection failed: %v", held.openErr)
			}
			err, heard, negotiated, _ := client.result()
			if err != nil {
				t.Fatalf("the client's handshake failed: %v", err)
			}
			if negotiated != c.want {
				t.Fatalf("the client ended up speaking %q, want %q", negotiated, c.want)
			}
			if heard != client.says {
				t.Fatalf("the client heard %q back", heard)
			}
		})
	}
}

// TestAConnectionOutsideTheScopeReachesItsDestinationByteForByte is the property every
// non-intercepted connection depends on: the opening bytes were read to make the decision, and
// they have to arrive anyway.
func TestAConnectionOutsideTheScopeReachesItsDestinationByteForByte(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	server := newRealServer(t, nil)

	// The client verifies against the real server's own authority, so it completes only if it
	// really reached the real server rather than something in the middle.
	client := &tlsClient{
		config: &tls.Config{
			ServerName: "elsewhere.example",
			RootCAs:    server.roots,
			Time:       func() time.Time { return theTimeIs },
		},
		says: "carried untouched",
	}
	held := carry(t, Config{
		Scope:     compileScope(t, ModeOnly, []string{"opened.example"}),
		Authority: authority,
		Roots:     server.roots,
		Now:       func() time.Time { return theTimeIs },
	}, server, nil, netip.Addr{}, client.run)

	if held.openErr != nil {
		t.Fatalf("carrying the connection failed: %v", held.openErr)
	}
	if held.result.Intercepted {
		t.Fatal("a connection outside the list was intercepted")
	}
	if held.result.Name != "elsewhere.example" {
		t.Fatalf("the connection was read as being for %q", held.result.Name)
	}
	if held.result.Why == "" {
		t.Fatal("nothing says why the connection was carried untouched")
	}

	err, heard, _, presented := client.result()
	if err != nil {
		t.Fatalf("a connection that was only looked at failed: %v", err)
	}
	if heard != client.says {
		t.Fatalf("the client heard %q back", heard)
	}
	if len(presented) == 0 {
		t.Fatal("the client completed a handshake with no certificate")
	}
	// The certificate came from the real server, which is provable only one way: it does not
	// chain to the root this machine signs with. The subjects are no help -- both authorities
	// here are built the same way, which is the point.
	if _, err := presented[0].Verify(x509.VerifyOptions{
		Roots:       ourRoots(t, authority),
		CurrentTime: theTimeIs,
		DNSName:     "elsewhere.example",
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("the client was handed a certificate this machine made for a connection nothing intercepted")
	}
}

// A list grown past what the root was made for opens nothing the root cannot sign for: the
// certificate would be refused by every client that trusts the root, so the connection is
// carried untouched to the real server, and the reason says a new root is needed.
func TestADestinationTheRootWasNotMadeForIsCarriedUntouchedAndSaysANewRootIsNeeded(t *testing.T) {
	t.Parallel()
	authority := authorityFor(t, limitsFor(t, ModeOnly, "opened.example"))
	server := newRealServer(t, nil)
	client := &tlsClient{
		config: &tls.Config{
			ServerName: "elsewhere.example",
			RootCAs:    server.roots,
			Time:       func() time.Time { return theTimeIs },
		},
		says: "carried untouched",
	}
	held := carry(t, Config{
		Scope:     compileScope(t, ModeOnly, []string{"opened.example", "elsewhere.example"}),
		Authority: authority,
		Roots:     server.roots,
		Now:       func() time.Time { return theTimeIs },
	}, server, nil, netip.Addr{}, client.run)

	if held.openErr != nil {
		t.Fatalf("carrying the connection failed: %v", held.openErr)
	}
	if held.result.Intercepted {
		t.Fatal("a connection the root cannot sign for was intercepted")
	}
	if !strings.Contains(held.result.Why, "a new root is needed") {
		t.Fatalf("the reason given is %q, want it to say a new root is needed", held.result.Why)
	}
	if err, heard, _, _ := client.result(); err != nil || heard != client.says {
		t.Fatalf("the carried connection ended with %v, hearing %q", err, heard)
	}
}

// TestAConnectionThatIsNotTLSIsCarriedWithItsOpeningIntact covers the other pass-through path,
// where nothing was even a hello. The bytes read to find that out still have to arrive.
func TestAConnectionThatIsNotTLSIsCarriedWithItsOpeningIntact(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	const request = "GET /index.html HTTP/1.1\r\nHost: plain.example\r\n\r\n"
	held := carry(t, Config{
		Scope:     compileScope(t, ModeExcept, DefaultBypass),
		Authority: authority,
		Now:       func() time.Time { return theTimeIs },
	}, nil, nil, netip.Addr{}, func(conn net.Conn) {
		if _, err := io.WriteString(conn, request); err != nil {
			t.Errorf("writing the request failed: %v", err)
		}
	})

	if held.openErr != nil {
		t.Fatalf("carrying the connection failed: %v", held.openErr)
	}
	if held.result.Intercepted {
		t.Fatal("a connection that is not TLS was intercepted")
	}
	if held.result.Why != "it is not a TLS connection" {
		t.Fatalf("the reason given is %q", held.result.Why)
	}

	// Read what arrived at the destination, which is the only place that answers whether the
	// bytes read to make the decision were put back.
	got := make([]byte, len(request))
	if err := held.farEnd.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("bounding the read failed: %v", err)
	}
	if _, err := io.ReadFull(held.farEnd, got); err != nil {
		t.Fatalf("reading what reached the destination failed: %v", err)
	}
	if string(got) != request {
		t.Fatalf("the destination received %q", got)
	}
}

// TestAConnectionWhoseNameIsEncryptedIsCarriedRatherThanBroken covers the hello whose real name
// is not here to decide on. Terminating one produces a connection that fails, which reads to
// the person using the machine as app-tail having broken the internet.
func TestAConnectionWhoseNameIsEncryptedIsCarriedRatherThanBroken(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	held := carry(t, Config{
		Scope:     compileScope(t, ModeExcept, []string{"nothing.example"}),
		Authority: authority,
		Now:       func() time.Time { return theTimeIs },
	}, nil, nil, netip.Addr{}, func(conn net.Conn) {
		if _, err := conn.Write(helloWithEncryptedName("outer.example")); err != nil {
			t.Errorf("writing the hello failed: %v", err)
		}
	})

	if held.openErr != nil {
		t.Fatalf("carrying the connection failed: %v", held.openErr)
	}
	if held.result.Intercepted {
		t.Fatal("a connection whose real name is encrypted was intercepted")
	}
	if held.result.Name != "outer.example" {
		t.Fatalf("the connection was read as being for %q, want the outer name", held.result.Name)
	}
	if held.result.Why != "the name in the hello is encrypted" {
		t.Fatalf("the reason given is %q", held.result.Why)
	}
}

// TestInterceptionThatIsOffReadsNothingAtAll is the cost claim: a connection carried with
// interception off is the connection that was handed in, not a wrapper around it, so nothing
// on the data path changed.
func TestInterceptionThatIsOffReadsNothingAtAll(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	client, upstream := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = upstream.Close() })

	for _, c := range []struct {
		name string
		cfg  Config
	}{
		{"nothing is switched on", Config{}},
		{"there is a list but nothing to sign with", Config{Scope: compileScope(t, ModeOnly, []string{"a.example"})}},
		{"there is something to sign with but no list", Config{Authority: authority}},
		{"the mode is off", Config{Authority: authority, Scope: compileScope(t, ModeOff, nil)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			held, err := Open(context.Background(), c.cfg, client, upstream, netip.Addr{})
			if err != nil {
				t.Fatalf("carrying the connection failed: %v", err)
			}
			if held.Intercepted {
				t.Fatal("a connection was intercepted with interception off")
			}
			if held.Client != client || held.Upstream != upstream {
				t.Fatal("the connections were wrapped with interception off")
			}
		})
	}
}

// TestAConnectionThatSaysNothingIsNotHeldOpenForever bounds the wait. This runs before the copy
// goroutines start, so a client that connects and stays silent would otherwise hold the
// connection here with nothing carrying it.
func TestAConnectionThatSaysNothingIsNotHeldOpenForever(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	client, silent := net.Pipe()
	upstream, farEnd := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = silent.Close()
		_ = upstream.Close()
		_ = farEnd.Close()
	})

	// The client is left connected and silent, which is the shape that would otherwise hold the
	// connection here. The wait is shortened rather than skipped, so what is proved is that the
	// bound exists and is enforced.
	_ = client

	_, err := Open(context.Background(), Config{
		Scope:       compileScope(t, ModeExcept, DefaultBypass),
		Authority:   authority,
		Now:         func() time.Time { return theTimeIs },
		PeekTimeout: 200 * time.Millisecond,
	}, silent, upstream, netip.Addr{})
	if err == nil {
		t.Fatal("a connection that produced nothing was carried anyway")
	}
	if !strings.Contains(err.Error(), "read the opening of the connection") {
		t.Fatalf("the failure does not say what went wrong: %v", err)
	}
}

// A client that dialled an address sends no server name: the hello carries nothing, and what
// the client checks is the address in the certificate. The connection is opened for the address
// it was dialled at, and the certificate minted names it as an address.
func TestAConnectionDialledByAddressIsOpenedForTheAddress(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	server := newRealServer(t, nil)
	server.unnamed = "10.20.0.7"
	at := addr(t, "10.20.0.7")

	client := &tlsClient{
		config: &tls.Config{
			// Go sends no server name for an address, and verifies the address SAN instead.
			ServerName: "10.20.0.7",
			RootCAs:    ourRoots(t, authority),
			Time:       func() time.Time { return theTimeIs },
		},
		says: "by address",
	}
	held := carry(t, Config{
		Scope:     compileScope(t, ModeOnly, []string{"10.20.0.7"}),
		Authority: authority,
		Roots:     server.roots,
		Now:       func() time.Time { return theTimeIs },
	}, server, nil, at, client.run)

	if held.openErr != nil {
		t.Fatalf("opening the connection failed: %v", held.openErr)
	}
	if !held.result.Intercepted || held.result.Name != "10.20.0.7" {
		t.Fatalf("the connection was opened as intercepted=%t for %q (%s)", held.result.Intercepted, held.result.Name, held.result.Why)
	}
	err, heard, _, presented := client.result()
	if err != nil {
		t.Fatalf("the client's handshake failed: %v", err)
	}
	if heard != client.says {
		t.Fatalf("the client heard %q back", heard)
	}
	if len(presented) == 0 || len(presented[0].IPAddresses) != 1 || presented[0].IPAddresses[0].String() != "10.20.0.7" {
		t.Fatal("the client was not handed a certificate naming the address it dialled")
	}
}

// A client that does not trust the root refuses the minted certificate, and that is the
// client's refusal rather than the server's: the reason must not read as the real server having
// failed to verify, which would point the person at the wrong end of the connection. The real
// connection that was already opened is closed rather than left.
func TestAClientRefusingTheMintedCertificateIsNotReportedAsTheServerFailing(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)
	server := newRealServer(t, nil)

	client := &tlsClient{
		config: &tls.Config{
			ServerName: "refused.example",
			// The client trusts the real server's authority and not the interception root.
			RootCAs: server.roots,
			Time:    func() time.Time { return theTimeIs },
		},
		says: "never sent",
	}
	held := carry(t, Config{
		Scope:     compileScope(t, ModeOnly, []string{"refused.example"}),
		Authority: authority,
		Roots:     server.roots,
		Now:       func() time.Time { return theTimeIs },
	}, server, nil, netip.Addr{}, client.run)

	if held.openErr == nil {
		t.Fatal("a connection whose client refused the certificate was reported as opened")
	}
	if errors.Is(held.openErr, ErrUpstreamRefused) {
		t.Fatalf("the client's refusal was reported as the server failing to verify: %v", held.openErr)
	}
	if !strings.Contains(held.openErr.Error(), "open the connection to refused.example") {
		t.Fatalf("the failure does not say which side failed: %v", held.openErr)
	}
	if err, _, _, _ := client.result(); err == nil {
		t.Fatal("the client completed a handshake against a root it does not hold")
	}
	if got := server.heard(); len(got) != 0 {
		t.Fatalf("the real server received %q over a connection the client refused", got)
	}
}

// A hello that has not finished arriving by the time the opening buffer is full is not one this
// side can decide on, and it is carried as it is: every byte, including the ones past the buffer,
// reaches the destination.
func TestAnOpeningLongerThanTheBufferIsCarriedWholeRatherThanDecidedOn(t *testing.T) {
	t.Parallel()
	authority := newTestAuthority(t)

	// A record header promising far more than the buffer holds, followed by a body that never
	// completes inside it.
	opening := append([]byte{0x16, 0x03, 0x01, 0x20, 0x00}, bytes.Repeat([]byte{0x5a}, peekSize+900)...)
	wrote := make(chan error, 1)
	held := carry(t, Config{
		Scope:     compileScope(t, ModeExcept, DefaultBypass),
		Authority: authority,
		Now:       func() time.Time { return theTimeIs },
	}, nil, nil, netip.Addr{}, func(conn net.Conn) {
		// On its own goroutine: the pipe only takes what the far end reads, and the far end is
		// read below, after the decision.
		go func() {
			_, err := conn.Write(opening)
			wrote <- err
		}()
	})

	if held.openErr != nil {
		t.Fatalf("carrying the connection failed: %v", held.openErr)
	}
	if held.result.Intercepted {
		t.Fatal("a connection whose hello never completed was intercepted")
	}
	if held.result.Why != "it is not a TLS connection" {
		t.Fatalf("the reason given is %q", held.result.Why)
	}

	got := make([]byte, len(opening))
	if err := held.farEnd.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("bounding the read failed: %v", err)
	}
	if _, err := io.ReadFull(held.farEnd, got); err != nil {
		t.Fatalf("reading what reached the destination failed: %v", err)
	}
	if !bytes.Equal(got, opening) {
		t.Fatal("the destination did not receive the opening byte for byte")
	}
	if err := <-wrote; err != nil {
		t.Fatalf("the client's write failed: %v", err)
	}
}

// Replay with nothing to put back is the connection itself, so a caller with nothing unread
// pays for no wrapper; with something to put back, that is read first and the connection after.
func TestReplayHandsBackTheConnectionItselfWhenThereIsNothingToPutBack(t *testing.T) {
	t.Parallel()
	near, far := net.Pipe()
	t.Cleanup(func() { _ = near.Close(); _ = far.Close() })

	if Replay(near, nil) != near {
		t.Fatal("a connection with nothing unread was wrapped")
	}

	replayed := Replay(near, []byte("ab"))
	if replayed == near {
		t.Fatal("a connection with bytes unread was handed back bare")
	}
	go func() { _, _ = far.Write([]byte("cd")) }()
	got := make([]byte, 4)
	if _, err := io.ReadFull(replayed, got); err != nil {
		t.Fatalf("reading through the replay failed: %v", err)
	}
	if string(got) != "abcd" {
		t.Fatalf("read %q, want the unread bytes and then the connection", got)
	}
}

// A half close reaches the connection underneath when it has one, and is refused rather than
// faked when it does not: a pipe cannot be half closed, and reporting success would leave the
// other side waiting for an end that never comes.
func TestAHalfCloseThroughAReplayReachesTheSocketOrIsRefused(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	dialled, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = dialled.Close() })
	other := <-accepted
	if other == nil {
		t.Fatal("nothing was accepted")
	}
	t.Cleanup(func() { _ = other.Close() })

	if err := Replay(dialled, []byte("x")).(*replayConn).CloseWrite(); err != nil {
		t.Fatalf("half closing a socket through the replay: %v", err)
	}
	if err := other.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("bounding the read failed: %v", err)
	}
	if _, err := other.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the other end read %v, want the end of the stream the half close sends", err)
	}

	near, far := net.Pipe()
	t.Cleanup(func() { _ = near.Close(); _ = far.Close() })
	if err := Replay(near, []byte("x")).(*replayConn).CloseWrite(); err == nil {
		t.Fatal("a pipe was reported as half closed, which it cannot be")
	}
}

// helloWithEncryptedName writes the smallest TLS client hello that carries a server name and
// the extension saying the real one is encrypted. It is built by hand because no client this
// side can drive produces one without a published configuration to encrypt against, and the
// branch it reaches is one a connection from the network takes.
func helloWithEncryptedName(name string) []byte {
	var extensions []byte
	extensions = append(extensions, serverNameExtension(name)...)
	// The encrypted client hello extension. Its body is opaque here: this side reads that it
	// is present and nothing else.
	extensions = append(extensions, 0xfe, 0x0d, 0x00, 0x03, 0x00, 0x01, 0x02)

	var body []byte
	body = append(body, 0x03, 0x03)                        // the legacy version every modern hello sends
	body = append(body, bytes.Repeat([]byte{0x11}, 32)...) // random
	body = append(body, 0x00)                              // no session id
	body = append(body, 0x00, 0x02, 0x13, 0x01)            // one cipher suite
	body = append(body, 0x01, 0x00)                        // one compression method, none
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func serverNameExtension(name string) []byte {
	entry := []byte{0x00, byte(len(name) >> 8), byte(len(name))}
	entry = append(entry, name...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	return append([]byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}, list...)
}
