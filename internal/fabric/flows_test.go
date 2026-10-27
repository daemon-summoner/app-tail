// SPDX-License-Identifier: MIT

package fabric

// The datagram relay on its own, where the ways one side can fail are reachable without a
// network. A UDP flow has no close, so how it ends is the whole of its lifetime: a relay that
// kept going past a broken side would hold a socket and a goroutine for as long as the
// interface is up.

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// scriptedConn is one side of a datagram flow: it hands over the datagrams it was given, in
// order, and fails in whatever way the case is about.
type scriptedConn struct {
	net.Conn

	deadlineErr error
	writeErr    error

	mu      sync.Mutex
	pending [][]byte
	written [][]byte
	closed  bool
}

func (c *scriptedConn) SetReadDeadline(time.Time) error { return c.deadlineErr }

func (c *scriptedConn) Read(buf []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(buf, c.pending[0])
	c.pending = c.pending[1:]
	return n, nil
}

func (c *scriptedConn) Write(buf []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	held := make([]byte, len(buf))
	copy(held, buf)
	c.written = append(c.written, held)
	return len(buf), nil
}

func (c *scriptedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *scriptedConn) got() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.written...)
}

// counter is what the relay reports to, which is what the dashboard's per-connection figures
// are built from.
type counter struct {
	mu    sync.Mutex
	total int64
	calls int
}

func (c *counter) add(n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += n
	c.calls++
}

func (c *counter) read() (int64, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total, c.calls
}

// Each datagram crosses whole, and each is counted once. A stream copy would join two
// datagrams into one read and hand the program on the other side a message it never sent.
func TestEachDatagramCrossesWholeAndIsCountedOnce(t *testing.T) {
	src := &scriptedConn{pending: [][]byte{[]byte("one"), []byte("two more")}}
	dst := &scriptedConn{}
	sent := &counter{}

	relayDatagrams(src, dst, sent.add, nil)

	got := dst.got()
	if len(got) != 2 || string(got[0]) != "one" || string(got[1]) != "two more" {
		t.Errorf("the other side received %q, want the two datagrams as they were sent", got)
	}
	total, calls := sent.read()
	if total != int64(len("one")+len("two more")) || calls != 2 {
		t.Errorf("counted %d bytes over %d datagrams, want 11 over 2", total, calls)
	}
}

// A side that will not take a deadline is a side that cannot be given up on: without one the
// read blocks forever and the flow outlives the program that opened it. Stopping is the only
// safe answer.
func TestAFlowThatCannotBeGivenAnIdleTimeIsEndedRatherThanHeldOpen(t *testing.T) {
	src := &scriptedConn{
		pending:     [][]byte{[]byte("one")},
		deadlineErr: errors.New("this side takes no deadline"),
	}
	dst := &scriptedConn{}

	done := make(chan error, 1)
	go func() {
		done <- relayDatagrams(src, dst, nil, nil)
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay is still running on a side that would not take a deadline")
	}
	// The reason travels with the end of the flow: without it the log says a flow stopped
	// and nothing says why, which is the one question anybody asks about a flow that stopped.
	if !errors.Is(err, src.deadlineErr) {
		t.Errorf("the relay ended with %v, want the reason the deadline could not be set", err)
	}

	if got := dst.got(); len(got) != 0 {
		t.Errorf("the other side received %q, want nothing from a flow that could not be timed out", got)
	}
}

// A datagram that could not be delivered ends the flow rather than being counted. Counting it
// would show the dashboard traffic the other side never received, which is a working network
// with nothing reaching it.
func TestADatagramThatCouldNotBeDeliveredEndsTheFlowAndIsNotCounted(t *testing.T) {
	src := &scriptedConn{pending: [][]byte{[]byte("one"), []byte("two")}}
	dst := &scriptedConn{writeErr: errors.New("the other side has gone")}
	sent := &counter{}

	err := relayDatagrams(src, dst, sent.add, nil)

	if !errors.Is(err, dst.writeErr) {
		t.Errorf("the relay ended with %v, want the reason the other side gave", err)
	}
	if total, calls := sent.read(); total != 0 || calls != 0 {
		t.Errorf("counted %d bytes over %d datagrams, want nothing for a side that took none", total, calls)
	}
	// And it stopped at the first refusal rather than reading the rest of the flow into a
	// destination that has already gone.
	src.mu.Lock()
	left := len(src.pending)
	src.mu.Unlock()
	if left != 1 {
		t.Errorf("%d datagrams left unread, want the relay to have stopped at the first refusal", left)
	}
}

// The relay reports only what the other side actually took. A partial write counted in full
// would overstate every connection's figures by exactly what was lost.
func TestOnlyWhatTheOtherSideTookIsCounted(t *testing.T) {
	src := &scriptedConn{pending: [][]byte{[]byte("a datagram")}}
	dst := &shortConn{scriptedConn: scriptedConn{}, takes: 4}
	sent := &counter{}

	relayDatagrams(src, dst, sent.add, nil)

	if total, _ := sent.read(); total != 4 {
		t.Errorf("counted %d bytes, want the 4 the other side took", total)
	}
}

// shortConn is a side that takes only part of a datagram and says so, which is what a socket
// whose buffer is full does.
type shortConn struct {
	scriptedConn
	takes int
}

func (c *shortConn) Write(buf []byte) (int, error) {
	if len(buf) > c.takes {
		return c.takes, io.ErrShortWrite
	}
	return len(buf), nil
}
