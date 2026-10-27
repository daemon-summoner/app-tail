// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// errConnLost reports that the connection carrying an exchange went away before the
// answer did. It is retried once on a fresh connection, because a resolver closing an
// idle connection is routine rather than a failure.
var errConnLost = errors.New("the connection to the resolver closed")

// streamClient carries DNS over a long-lived, length-prefixed connection: plain TCP or
// TLS, which differ only in how the connection is dialed.
//
// Queries are pipelined. One connection carries many outstanding queries at once, each
// identified by the transaction id this client assigns, and a reader goroutine hands each
// answer to the caller waiting on it. The alternative -- one exchange at a time behind a
// mutex -- turns a browser opening a page into a serial round trip per name, and over TLS
// it would add a handshake to each.
type streamClient struct {
	// label names the resolver as the user wrote it, so a message about a bad answer says
	// which resolver gave it.
	label string
	dial  func(ctx context.Context) (net.Conn, error)
	// idle is how long a connection with nothing outstanding is kept open. Resolvers
	// close idle connections themselves; this keeps us from holding one they have
	// already forgotten.
	idle time.Duration

	mu     sync.Mutex
	conn   *streamConn
	closed bool
}

// streamConn is one connection and the exchanges outstanding on it. The waiters belong to
// the connection rather than to the client, so a connection dying wakes exactly the
// callers it stranded.
type streamConn struct {
	net  net.Conn
	mu   sync.Mutex
	wait map[uint16]chan []byte
	dead bool
}

func newStreamClient(label string, dial func(ctx context.Context) (net.Conn, error), idle time.Duration) *streamClient {
	return &streamClient{label: label, dial: dial, idle: idle}
}

// Exchange sends one query and returns the answer, with the caller's transaction id
// restored.
func (c *streamClient) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	// Parsed once here rather than per attempt: what was asked does not change between
	// the two, and the answer to it is checked against this on the way back.
	question, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	var lost error
	// Two attempts, and only two: the first can land on a connection the resolver closed
	// while it was idle, which is normal. A second failure is the resolver, not the pool.
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := c.exchangeOnce(ctx, query, question)
		if err == nil {
			return resp, nil
		}
		if !errors.Is(err, errConnLost) {
			return nil, err
		}
		lost = err
	}
	return nil, lost
}

func (c *streamClient) exchangeOnce(ctx context.Context, query []byte, question Question) ([]byte, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	id, ch, err := conn.register()
	if err != nil {
		return nil, err
	}
	defer conn.release(id)

	out := make([]byte, len(query))
	copy(out, query)
	setID(out, id)
	if err := writeFramed(conn.net, out); err != nil {
		conn.kill()
		return nil, fmt.Errorf("%w: %w", errConnLost, err)
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errConnLost
		}
		// The id alone says which waiter an answer belongs to, and that is not the same
		// as saying it answers the question that waiter asked. An id is reused once the
		// query holding it gives up, so a late answer to an abandoned query can land on
		// the one that drew the id next; and a resolver willing to answer the wrong
		// question is a resolver that decides what a name resolves to.
		//
		// Failing rather than reading on, which is what the UDP path does with a mismatch:
		// there the sender is unauthenticated and anyone can put a packet on the wire, so
		// a wrong one has to be outlasted. Here the only party that can put bytes on this
		// connection is the resolver itself, and asking it again on the same connection
		// gets the same answer.
		if !isResponse(resp) || !answersQuestion(resp, question) {
			return nil, fmt.Errorf("%s answered something other than %s", c.label, question)
		}
		setID(resp, question.ID)
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// connection returns the live connection, dialing one if there is none.
func (c *streamClient) connection(ctx context.Context) (*streamConn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("the resolver connection is closed")
	}
	if c.conn != nil && !c.conn.isDead() {
		conn := c.conn
		c.mu.Unlock()
		return conn, nil
	}
	c.mu.Unlock()

	// Dialing outside the lock: a slow handshake must not stall every other query, and
	// the loser of a race closes its own connection rather than leaking it.
	netConn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	conn := &streamConn{net: netConn, wait: make(map[uint16]chan []byte)}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		netConn.Close()
		return nil, errors.New("the resolver connection is closed")
	}
	if c.conn != nil && !c.conn.isDead() {
		winner := c.conn
		c.mu.Unlock()
		netConn.Close()
		return winner, nil
	}
	c.conn = conn
	c.mu.Unlock()

	go c.read(conn)
	return conn, nil
}

// read delivers answers until the connection fails or goes idle with nothing outstanding.
func (c *streamClient) read(conn *streamConn) {
	defer c.forget(conn)
	for {
		if err := conn.net.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
			conn.kill()
			return
		}
		msg, err := readFramed(conn.net)
		if err != nil {
			conn.kill()
			return
		}
		id, ok := queryID(msg)
		if !ok {
			continue // not a DNS message; the next one may be
		}
		conn.deliver(id, msg)
	}
}

// forget drops a dead connection so the next exchange dials a new one.
func (c *streamClient) forget(conn *streamConn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
}

// Close ends the connection and wakes everyone waiting on it.
func (c *streamClient) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		conn.kill()
	}
	return nil
}

// register claims a transaction id on this connection.
func (c *streamConn) register() (uint16, chan []byte, error) {
	ch := make(chan []byte, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return 0, nil, errConnLost
	}
	// A random id rather than a counter: an id an off-path attacker can predict is the
	// whole of what makes a forged answer possible.
	for attempt := 0; attempt < 64; attempt++ {
		id := randomID()
		if _, taken := c.wait[id]; taken {
			continue
		}
		c.wait[id] = ch
		return id, ch, nil
	}
	return 0, nil, errors.New("too many queries outstanding on one connection")
}

func (c *streamConn) release(id uint16) {
	c.mu.Lock()
	delete(c.wait, id)
	c.mu.Unlock()
}

func (c *streamConn) deliver(id uint16, msg []byte) {
	c.mu.Lock()
	ch, ok := c.wait[id]
	if ok {
		delete(c.wait, id)
	}
	c.mu.Unlock()
	if ok {
		ch <- msg
	}
}

// kill closes the connection and wakes every caller still waiting on it, so a resolver
// that disappears fails its queries rather than hanging them.
func (c *streamConn) kill() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	waiters := c.wait
	c.wait = make(map[uint16]chan []byte)
	c.mu.Unlock()

	c.net.Close()
	for _, ch := range waiters {
		close(ch)
	}
}

func (c *streamConn) isDead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dead
}

// writeFramed writes one message with the two-byte length prefix RFC 1035 §4.2.2 requires
// on a stream.
func writeFramed(conn net.Conn, msg []byte) error {
	if len(msg) > 65535 {
		return fmt.Errorf("a DNS message of %d bytes does not fit a stream frame", len(msg))
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(msg)))
	copy(framed[2:], msg)
	_, err := conn.Write(framed)
	return err
}

// readFramed reads one length-prefixed message. The caller sets the read deadline.
func readFramed(conn net.Conn) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(length[:])
	if size == 0 {
		return nil, errMalformed
	}
	msg := make([]byte, size)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// randomID draws a transaction id from the system's cryptographic source. rand.Read never
// fails on any platform app-tail supports, and it panics rather than returning an error
// when it does, so an unpredictable id is a guarantee here rather than a best effort.
func randomID() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
