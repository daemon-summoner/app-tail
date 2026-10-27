// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/dnsprofiles"
)

// plainUpstream carries DNS over UDP, with TCP for the answers that do not fit.
//
// It is what a resolver on the local network speaks, and what a public resolver speaks
// when the user gave an address rather than a URL. Nothing about it is private: the names
// go over the wire in the clear, which is the tradeoff the user made by writing an
// address instead of tls:// or https://.
type plainUpstream struct {
	addr netip.AddrPort
	// dest is addr in the form a dial takes, worked out once. Dialling by string re-parses
	// the address and walks the resolver machinery on every query -- on this machine, where
	// we are the resolver it would consult.
	dest  *net.UDPAddr
	label string
	tcp   *streamClient
}

// udpAnswers holds the read buffers between queries. One is 4 KB and a query holds it for
// a round trip; a resolver answering a page's worth of names allocates and discards one per
// name otherwise.
var udpAnswers sync.Pool

// udpAnswerBuffer takes a buffer from the pool, or makes one when it is empty.
func udpAnswerBuffer() *[]byte {
	if held, ok := udpAnswers.Get().(*[]byte); ok {
		return held
	}
	buf := make([]byte, maxUDPAnswer)
	return &buf
}

func newPlainUpstream(u dnsprofiles.Upstream) (*plainUpstream, error) {
	addr, ok := u.Endpoint()
	if !ok {
		return nil, fmt.Errorf("%s has no address to dial", u.Text)
	}
	p := plainAt(addr, u.Text)
	p.tcp = newStreamClient(u.Text, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		d.Timeout = dialTimeout
		// The address is a literal, so this never consults a resolver -- which matters,
		// because on this machine we are the resolver it would have consulted.
		return d.DialContext(ctx, "tcp", addr.String())
	}, idleTimeout)
	return p, nil
}

// plainAt is the only way one of these is made, so dest cannot drift from addr: a
// plainUpstream built as a literal somewhere else would dial a nil address.
func plainAt(addr netip.AddrPort, label string) *plainUpstream {
	return &plainUpstream{addr: addr, dest: net.UDPAddrFromAddrPort(addr), label: label}
}

func (p *plainUpstream) Label() string { return p.label }

func (p *plainUpstream) Close() error { return p.tcp.Close() }

func (p *plainUpstream) Exchange(ctx context.Context, query []byte, stream bool) ([]byte, error) {
	if stream {
		return p.tcp.Exchange(ctx, query)
	}
	return p.exchangeUDP(ctx, query)
}

// exchangeUDP sends one query and waits for an answer that is actually the answer to it.
//
// The outbound transaction id is random and the reply's question section is compared
// against the one we asked, because an unauthenticated UDP answer is otherwise something
// anyone on the path -- or anyone who can guess a 16-bit number -- can write.
func (p *plainUpstream) exchangeUDP(ctx context.Context, query []byte) ([]byte, error) {
	question, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A socket of its own per query, which is what makes the source port random per query:
	// that port is half of what an off-path forger has to guess, the transaction id below
	// being the other half. Reusing one across queries would cost less and give that away.
	//
	// Dialled by address rather than by string: there is nothing to resolve, and on this
	// machine we are the resolver that would be consulted.
	var conn net.Conn
	conn, err = net.DialUDP("udp", nil, p.dest)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", p.label, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(queryTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	// A context cancelled while we are blocked in Read has to reach the socket, and closing
	// it is the only thing that unblocks a read. The deferred close above then finds it
	// already closed, which is what it wants.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	out := make([]byte, len(query))
	copy(out, query)
	sentID := randomID()
	setID(out, sentID)
	if _, err := conn.Write(out); err != nil {
		return nil, fmt.Errorf("send to %s: %w", p.label, err)
	}

	held := udpAnswerBuffer()
	defer udpAnswers.Put(held)
	buf := *held
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				return nil, fmt.Errorf("%s did not answer %s", p.label, question)
			}
			return nil, fmt.Errorf("read from %s: %w", p.label, err)
		}
		msg := buf[:n]
		id, ok := queryID(msg)
		if !ok || id != sentID || !isResponse(msg) || !answersQuestion(msg, question) {
			// Not our answer. Keep reading until the deadline rather than returning:
			// giving up here is what makes a single forged packet a denial of service.
			continue
		}
		answer := make([]byte, n)
		copy(answer, msg)
		setID(answer, question.ID)
		return answer, nil
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
