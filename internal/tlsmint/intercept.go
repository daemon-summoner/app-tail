// SPDX-License-Identifier: MIT

package tlsmint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

const (
	// peekSize is how much of a connection's opening is read to find the name in it. It is the
	// same four kilobytes the inspection window uses and for the same reason: a post-quantum
	// hello runs to about two, and a larger buffer here would buy nothing but a longer wait on
	// connections that are not TLS at all.
	peekSize = 4096
	// peekTimeout bounds how long the opening bytes may take to arrive. A connection that
	// opens and then says nothing is carried untouched rather than held: this runs before the
	// two copy goroutines start, so time spent here is time the connection is doing nothing.
	peekTimeout = 10 * time.Second
	// handshakeTimeout bounds each of the two handshakes interception performs.
	handshakeTimeout = 30 * time.Second
)

// ErrUpstreamRefused reports that the real server's certificate did not verify, so the
// connection was stopped instead of being carried.
//
// This is the one failure in this package that must never be recovered from by carrying on.
// Interception replaces the server's identity with a certificate this machine made, and the
// only thing that keeps that from being a downgrade is this side verifying the identity the
// client can no longer see. An interceptor that shrugs at an upstream it could not verify has
// quietly turned every intercepted connection into one nobody is checking.
var ErrUpstreamRefused = errors.New("the real server's certificate did not verify")

// Config is what interception needs to decide and to act, held by the runner and passed to
// each connection.
type Config struct {
	// Scope decides which connections are opened. A nil Scope, or one that is off, means
	// Open reads nothing and hands back what it was given.
	Scope *Scope
	// Authority mints the certificates. A nil Authority is interception off, whatever the
	// scope says: a scope with nothing to sign with cannot open anything.
	Authority *Authority
	// Roots are what the real server's certificate is verified against. Nil is the machine's
	// own trust store, which is the answer in every case but a test.
	//
	// It is a set of trust anchors and never a way to skip verification, because there is no
	// such way here on purpose: the client can no longer see who it is talking to, so this side
	// checking is the only checking left.
	Roots *x509.CertPool
	// Now is the clock, injected so a test pins the validity window. Nil is time.Now.
	Now func() time.Time
	// PeekTimeout bounds how long the opening bytes may take to arrive. Zero is peekTimeout,
	// which is the answer everywhere but a test that would otherwise wait it out.
	PeekTimeout time.Duration
}

// Result is what one connection turned out to be, and the two connections to carry it between.
type Result struct {
	// Client and Upstream are what the caller copies between. On a connection that was not
	// intercepted they are the ones handed in, with the opening bytes put back in front of the
	// client so nothing was consumed. On one that was, they are the two terminated halves and
	// what crosses them is plaintext.
	Client   net.Conn
	Upstream net.Conn
	// Intercepted reports the connection having been opened, which is what the card counts and
	// what the log line says. It is false on every connection that was carried untouched,
	// including the ones interception was switched on for and declined.
	Intercepted bool
	// Name is what the connection asked for, from the hello. Empty on a connection whose
	// opening was not a TLS hello.
	Name string
	// Why names the reason a connection interception was switched on for was still carried
	// untouched, empty when there was none. It is what makes "it is on and nothing is being
	// inspected" answerable without a packet capture.
	Why string
}

// Open decides whether one connection is intercepted, and returns the pair to carry it
// between either way.
//
// The decision happens here, before anything is copied, because it cannot happen later: the
// two copy goroutines each own one direction, and swapping the connections underneath them
// from one of the two is a data race with the other. A connection is either opened before the
// copying starts or it is carried as it is.
//
// Failures are the caller's to act on. Everything this returns an error for has already had
// its opening bytes read, so the connection cannot be carried untouched afterwards: the caller
// closes both ends. That is deliberate for ErrUpstreamRefused and unavoidable for the rest.
func Open(ctx context.Context, cfg Config, client, upstream net.Conn, at netip.Addr) (Result, error) {
	if cfg.Authority == nil || !cfg.Scope.On() {
		return Result{Client: client, Upstream: upstream}, nil
	}

	opening, err := peek(client, cfg.PeekTimeout)
	if err != nil {
		return Result{}, err
	}
	// Whatever happens from here, the bytes read are put back in front of the connection: a
	// connection that is not intercepted has to reach its destination byte for byte, including
	// the ones this read to make the decision.
	client = &replayConn{Conn: client, unread: opening}

	hello, state := inspect.ParseClientHello(opening)
	if state != inspect.Parsed {
		return Result{Client: client, Upstream: upstream, Why: "it is not a TLS connection"}, nil
	}

	name := hello.SNI()
	if name == "" && at.IsValid() {
		// A client that dialled an address and sent no name is asking for that address, and a
		// certificate naming it is what such a client checks. It is also what the scope's list
		// is matched against, so the two agree.
		name = at.Unmap().String()
	}
	if hello.ECH {
		// The name in an encrypted hello is a cover for the real one, so there is nothing here
		// to decide on. Terminating it would fail anyway: a client that sent an encrypted hello
		// and got back a server that ignored it treats that as the attack it is designed to
		// detect, which is a connection broken rather than inspected.
		return Result{Client: client, Upstream: upstream, Name: name, Why: "the name in the hello is encrypted"}, nil
	}
	if !cfg.Scope.Intercepts(name, at) {
		return Result{Client: client, Upstream: upstream, Name: name, Why: "it is not one of the destinations being intercepted"}, nil
	}
	if !cfg.Authority.Covers(name) {
		// The list has grown past what the root was made for. A certificate minted anyway is
		// one every client trusting the root refuses, so the connection is carried as it is
		// until the root is replaced, rather than broken.
		return Result{Client: client, Upstream: upstream, Name: name, Why: "the root app-tail holds was made for a narrower list and cannot sign for it; a new root is needed"}, nil
	}

	openedClient, openedUpstream, err := terminate(ctx, cfg, client, upstream, name)
	if err != nil {
		return Result{}, err
	}
	return Result{Client: openedClient, Upstream: openedUpstream, Intercepted: true, Name: name}, nil
}

// peek reads the opening bytes of a connection until they hold a whole hello, the buffer
// fills, or the connection stops producing.
//
// It parses after every read rather than waiting for a fixed amount, because a hello arrives
// in whatever number of segments the network chose and there is no length to wait for that
// would be right for all of them.
func peek(client net.Conn, within time.Duration) (opening []byte, err error) {
	if within <= 0 {
		within = peekTimeout
	}
	if err := client.SetReadDeadline(time.Now().Add(within)); err != nil {
		return nil, fmt.Errorf("bound how long the opening bytes may take: %w", err)
	}
	// Cleared however this returns: the deadline set here is for this read and the connection
	// is carried afterwards either way, so leaving it on would cut a healthy transfer ten
	// seconds in. A connection that will not take the clearing is one nothing can be carried
	// over, so that failure is the answer rather than a detail.
	defer func() {
		if cleared := client.SetReadDeadline(time.Time{}); cleared != nil && err == nil {
			opening, err = nil, fmt.Errorf("clear the bound on the opening bytes: %w", cleared)
		}
	}()

	held := make([]byte, 0, peekSize)
	buf := make([]byte, peekSize)
	for len(held) < peekSize {
		n, err := client.Read(buf[:peekSize-len(held)])
		if n > 0 {
			held = append(held, buf[:n]...)
			if _, state := inspect.ParseClientHello(held); state != inspect.Incomplete {
				return held, nil
			}
		}
		if err != nil {
			// Bytes already read are the answer, however the read ended: a connection that sent
			// a whole hello and then closed is still one whose hello was read. An error with
			// nothing read is a connection that produced nothing, and there is no decision to
			// make about it.
			if len(held) > 0 {
				return held, nil
			}
			return nil, fmt.Errorf("read the opening of the connection: %w", err)
		}
	}
	return held, nil
}

// terminate performs the two handshakes, upstream first.
//
// Upstream first is the security property, not an ordering preference. The client is handed a
// certificate this machine made only after the real server has proved it is the real server;
// the other order would present a working certificate for a destination nothing had verified,
// which is the failure that makes an interceptor worse than no interception.
func terminate(ctx context.Context, cfg Config, client, upstream net.Conn, name string) (net.Conn, net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	// Set by the callback below, which crypto/tls runs on this goroutine inside Handshake, so
	// there is nothing here to synchronise.
	var opened *tls.Conn
	var upstreamErr error

	server := tls.Server(client, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// The real connection is made from inside the client's handshake because that is
			// where the client's own offer is known: crypto/tls has parsed the hello by now, so
			// the protocols offered upstream are the ones the client actually asked for rather
			// than a list this side guessed at.
			up := tls.Client(upstream, &tls.Config{
				ServerName: name,
				NextProtos: hello.SupportedProtos,
				MinVersion: tls.VersionTLS12,
				RootCAs:    cfg.Roots,
				Time:       now,
			})
			if err := up.HandshakeContext(ctx); err != nil {
				upstreamErr = fmt.Errorf("%w: %s: %w", ErrUpstreamRefused, name, err)
				// The client's handshake fails with an alert rather than a forged certificate,
				// which is the same thing it would have seen had it reached this server itself.
				return nil, upstreamErr
			}
			opened = up

			negotiated := up.ConnectionState().NegotiatedProtocol
			var offer []string
			if negotiated != "" {
				// Exactly what upstream agreed to, so the two halves speak the same protocol.
				// Offering the client anything else would let it choose one the far side is not
				// speaking, and the mismatch would surface as a broken application rather than
				// as a protocol error.
				offer = []string{negotiated}
			}
			return &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: offer,
				GetCertificate: func(from *tls.ClientHelloInfo) (*tls.Certificate, error) {
					want := from.ServerName
					if want == "" {
						want = name
					}
					return cfg.Authority.Leaf(want, now())
				},
			}, nil
		},
	})

	if err := server.HandshakeContext(ctx); err != nil {
		cause := upstreamErr
		if cause == nil {
			cause = fmt.Errorf("open the connection to %s: %w", name, err)
		}
		if opened != nil {
			// The connection to the real server is being abandoned, so what its close reports
			// goes out beside the cause rather than in place of it.
			return nil, nil, errors.Join(cause, opened.Close())
		}
		return nil, nil, cause
	}
	return &openedConn{Conn: server, raw: client}, &openedConn{Conn: opened, raw: upstream}, nil
}

// Replay puts bytes already read off a connection back in front of it, so that whatever reads
// it next reads them first. Nothing unread is the connection itself.
//
// It is exported because the proxy has the same problem from the other direction: a client
// that pipelines its opening bytes behind a CONNECT line leaves them in the server's reader
// rather than in the socket, and they have to be readable from the connection again before
// anything can decide what the connection is.
func Replay(c net.Conn, unread []byte) net.Conn {
	if len(unread) == 0 {
		return c
	}
	return &replayConn{Conn: c, unread: unread}
}

// replayConn is a connection whose opening bytes have already been read, and are handed back
// before anything else is.
type replayConn struct {
	net.Conn
	unread []byte
}

func (c *replayConn) Read(b []byte) (int, error) {
	if len(c.unread) > 0 {
		n := copy(b, c.unread)
		c.unread = c.unread[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// Cut passes the reset through to the connection underneath, which is the one holding the
// socket. Without it a stopped connection would be closed the way a finished one is.
func (c *replayConn) Cut() { netpipe.Reset(c.Conn) }

// CloseWrite passes a half close through, for the connections underneath that have one. A
// connection that does not is left to netpipe's own fallback.
func (c *replayConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.New("this connection cannot be half closed")
}

// openedConn is one half of an intercepted connection: the terminated TLS conn to read and
// write plaintext through, and the raw connection under it.
//
// It exists for one method. netpipe stops a connection with a reset because a graceful close
// is the shape of a request that finished, and a *tls.Conn has no way to be cut -- closing one
// sends a close_notify and then shuts the socket down politely. Passing the cut through to the
// socket underneath keeps a stopped connection reading as a stopped connection.
type openedConn struct {
	net.Conn
	raw net.Conn
}

func (c *openedConn) Cut() { netpipe.Reset(c.raw) }
