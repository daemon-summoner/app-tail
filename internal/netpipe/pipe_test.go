// SPDX-License-Identifier: MIT

package netpipe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// ioDeadline bounds every blocking read in these tests so a regression that would
// hang forever fails in a second instead of timing out the whole package.
const ioDeadline = 5 * time.Second

// dialPair returns the two ends of a connected loopback TCP pair. Real sockets are
// used rather than net.Pipe because CloseWrite -- the behaviour under test -- only
// exists on a real connection.
func dialPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{conn: c, err: err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		dialed.Close()
		t.Fatalf("accept: %v", got.err)
	}
	t.Cleanup(func() {
		dialed.Close()
		got.conn.Close()
	})
	return dialed, got.conn
}

func readFull(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(ioDeadline)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// A forward carries a request in and a response out, and protocols that mark the end
// of a request by shutting down one direction only work if that shutdown crosses the
// proxy. This pins both: the wrong direction on a counter, a dropped half-close (the
// server never sees EOF), and a half-close turned into a full close (the response
// never comes back) each fail it.
func TestCopyCarriesBothDirectionsAndPropagatesTheHalfClose(t *testing.T) {
	callerEnd, client := dialPair(t)
	upstream, serverEnd := dialPair(t)

	// Deliberately different lengths: equal payloads would let onUp and onDown be
	// wired to the same direction without this test noticing.
	request := []byte("request")
	response := []byte("a rather longer response")

	var (
		up, down int64
		copyErr  error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyErr = Copy(context.Background(), client, upstream,
			func(n int64) { up += n },
			func(n int64) { down += n })
	}()

	if _, err := callerEnd.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := callerEnd.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close the caller: %v", err)
	}

	if got := readFull(t, serverEnd, len(request)); string(got) != string(request) {
		t.Fatalf("server read %q, want %q", got, request)
	}

	// The caller's shutdown must reach the server as an EOF, not as a stall.
	if err := serverEnd.SetReadDeadline(time.Now().Add(ioDeadline)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := serverEnd.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server read after the caller half-closed: got %v, want EOF", err)
	}

	// The other direction must still be open, which is the whole point of a half
	// close rather than a close.
	if _, err := serverEnd.Write(response); err != nil {
		t.Fatalf("write response after the half-close: %v", err)
	}
	serverEnd.Close()

	if got := readFull(t, callerEnd, len(response)); string(got) != string(response) {
		t.Fatalf("caller read %q, want %q", got, response)
	}

	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("Copy never returned after both sides finished")
	}

	// Both peers hung up in an orderly way, so nothing failed. Reporting an error here
	// would make every normal connection look like a transport fault to the caller.
	if copyErr != nil {
		t.Errorf("Copy reported %v after a clean shutdown on both sides, want nil", copyErr)
	}
	if up != int64(len(request)) {
		t.Errorf("onUp reported %d bytes, want %d (the caller-to-upstream direction)", up, len(request))
	}
	if down != int64(len(response)) {
		t.Errorf("onDown reported %d bytes, want %d (the upstream-to-caller direction)", down, len(response))
	}
}

// Stopping a forward has to cut connections that are parked in Read with no traffic
// on them; without the cancellation watch those goroutines leak for the life of the
// process.
func TestCopyReturnsWhenTheContextIsCancelledOnAnIdleConnection(t *testing.T) {
	_, client := dialPair(t)
	upstream, _ := dialPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	var copyErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyErr = Copy(ctx, client, upstream, nil, nil)
	}()

	// Nothing is being sent, so both copies are blocked in Read.
	select {
	case <-done:
		t.Fatal("Copy returned before the context was cancelled")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("Copy stayed blocked in Read after its context was cancelled")
	}

	// The cut is surfaced rather than swallowed. Callers that cancelled on purpose
	// tell it apart from a transport fault by checking ctx.Err(), which is only
	// possible if the error reaches them at all.
	if copyErr == nil {
		t.Error("Copy reported success after its connections were cut mid-transfer")
	}
}

// A transfer still running must already have been counted, because the traffic graph is
// sampled once a second against these counters: a long upload reported only at close
// reads as an idle machine for its whole duration and then lands as one spike that
// flattens the scale of every real reading in the window.
//
// The payload is several buffers' worth so that reporting per copy rather than per chunk
// fails this: it would leave the counter at zero until the connection closed.
func TestCopyCountsWhileTheTransferIsStillRunning(t *testing.T) {
	callerEnd, client := dialPair(t)
	upstream, serverEnd := dialPair(t)

	const payload = 8 * chunkSize

	reported := make(chan int64, 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Copy(context.Background(), client, upstream, func(n int64) { reported <- n }, nil)
	}()

	writeErr := make(chan error, 1)
	go func() {
		_, err := callerEnd.Write(make([]byte, payload))
		writeErr <- err
	}()

	// Drain the far end so the copy is never blocked on a full socket buffer, and stop as
	// soon as the whole payload has arrived rather than waiting for a close that this test
	// deliberately never performs.
	if err := serverEnd.SetReadDeadline(time.Now().Add(ioDeadline)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.ReadFull(serverEnd, make([]byte, payload)); err != nil {
		t.Fatalf("read the payload: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write the payload: %v", err)
	}

	// Both connections are still open here. Everything already reported was reported
	// mid-transfer, which is the property under test.
	var total int64
	var instalments int
	deadline := time.Now().Add(ioDeadline)
	for total < payload && time.Now().Before(deadline) {
		select {
		case n := <-reported:
			total += n
			instalments++
		case <-time.After(10 * time.Millisecond):
		}
	}

	if total != payload {
		t.Errorf("counted %d bytes while the transfer was open, want %d", total, payload)
	}
	if instalments < 2 {
		t.Errorf("the transfer was reported in %d instalment(s), want it counted as it crossed", instalments)
	}

	callerEnd.Close()
	serverEnd.Close()
	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("Copy never returned")
	}
}

// Callers that do not meter their traffic pass nil, which must not panic.
func TestCopyAcceptsNilCounters(t *testing.T) {
	callerEnd, client := dialPair(t)
	upstream, serverEnd := dialPair(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		Copy(context.Background(), client, upstream, nil, nil)
	}()

	if _, err := callerEnd.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readFull(t, serverEnd, 5); string(got) != "hello" {
		t.Fatalf("server read %q, want %q", got, "hello")
	}

	callerEnd.Close()
	serverEnd.Close()
	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("Copy never returned")
	}
}

// countingWatch is an inspector that records what crossed and stops the connection when it
// sees a chosen word, which is what a real one does the moment it reads a name it refuses.
type countingWatch struct {
	stopOn     string
	stopDownOn string
	up         [][]byte
	down       [][]byte
	closes     int
}

func (w *countingWatch) Up(b []byte) bool {
	w.up = append(w.up, append([]byte(nil), b...))
	return w.stopOn != "" && bytes.Contains(b, []byte(w.stopOn))
}

func (w *countingWatch) Down(b []byte) bool {
	w.down = append(w.down, append([]byte(nil), b...))
	return w.stopDownOn != "" && bytes.Contains(b, []byte(w.stopDownOn))
}

func (w *countingWatch) Close() { w.closes++ }

// The whole claim of inspecting before the write: a chunk the inspector stops is a chunk the
// far end never receives. An implementation that read the chunk after forwarding it would
// pass every other test in this file and fail this one.
func TestAStoppedConnectionNeverReachesTheFarEnd(t *testing.T) {
	callerEnd, client := dialPair(t)
	upstream, serverEnd := dialPair(t)

	watch := &countingWatch{stopOn: "refused.example"}
	var copyErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyErr = CopyWith(context.Background(), client, upstream, nil, nil, watch)
	}()

	if _, err := callerEnd.Write([]byte("GET / HTTP/1.1\r\nHost: refused.example\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The far end must see the connection end rather than the request. A half-close would
	// read as EOF here, and EOF is the shape of a request that simply finished -- so the
	// error being anything other than EOF is the assertion, not an accident of timing.
	if err := serverEnd.SetReadDeadline(time.Now().Add(ioDeadline)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, err := serverEnd.Read(make([]byte, 64))
	if n != 0 {
		t.Fatalf("the far end received %d bytes of a stopped connection", n)
	}
	if err == nil {
		t.Fatal("the far end read a stopped connection without an error")
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("the far end read a graceful end-of-stream, which is the shape of a finished request rather than a stopped one")
	}

	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("CopyWith never returned after the inspector stopped the connection")
	}

	// A connection stopped on purpose is not a transport fault, and every caller here logs
	// what it is handed.
	if copyErr != nil {
		t.Errorf("CopyWith reported %v after the inspector stopped the connection, want nil", copyErr)
	}
	if len(watch.up) != 1 {
		t.Errorf("the inspector was handed %d chunks, want the one it stopped on", len(watch.up))
	}
	if watch.closes != 1 {
		t.Errorf("the inspector was closed %d times, want once", watch.closes)
	}
}

// The direction coming back is stopped the same way, and it is a separate goroutine with its
// own branch: an implementation that reset the connection only on the way up would carry every
// byte of a refused response to the program that asked for it.
func TestAConnectionStoppedOnTheWayBackNeverReachesTheProgram(t *testing.T) {
	callerEnd, client := dialPair(t)
	upstream, serverEnd := dialPair(t)

	watch := &countingWatch{stopDownOn: "refused.example"}
	var copyErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyErr = CopyWith(context.Background(), client, upstream, nil, nil, watch)
	}()

	if _, err := serverEnd.Write([]byte("HTTP/1.1 302 Found\r\nLocation: refused.example\r\n\r\n")); err != nil {
		t.Fatalf("write the response: %v", err)
	}

	if err := callerEnd.SetReadDeadline(time.Now().Add(ioDeadline)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, err := callerEnd.Read(make([]byte, 64))
	if n != 0 {
		t.Fatalf("the program received %d bytes of a stopped response", n)
	}
	if err == nil {
		t.Fatal("the program read a stopped response without an error")
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("the program read a graceful end-of-stream, which is the shape of a response that simply ended")
	}

	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("CopyWith never returned after the inspector stopped the response")
	}
	if copyErr != nil {
		t.Errorf("CopyWith reported %v after the inspector stopped the response, want nil", copyErr)
	}
	if len(watch.down) != 1 {
		t.Errorf("the inspector was handed %d chunks on the way back, want the one it stopped on", len(watch.down))
	}
}

// An inspector that stops nothing must leave the connection exactly as Copy leaves it: the
// same bytes, both directions, and the same half-close. This is what makes "inspection on"
// and "inspection off" the same code path rather than two.
func TestAnInspectorThatStopsNothingChangesNothing(t *testing.T) {
	callerEnd, client := dialPair(t)
	upstream, serverEnd := dialPair(t)

	request := []byte("request")
	response := []byte("a rather longer response")

	watch := &countingWatch{}
	var copyErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyErr = CopyWith(context.Background(), client, upstream, nil, nil, watch)
	}()

	if _, err := callerEnd.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := callerEnd.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close the caller: %v", err)
	}
	if got := readFull(t, serverEnd, len(request)); string(got) != string(request) {
		t.Fatalf("server read %q, want %q", got, request)
	}

	// The half-close still crosses, which is the behaviour every protocol that ends a
	// request by shutting down one direction depends on.
	if err := serverEnd.SetReadDeadline(time.Now().Add(ioDeadline)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := serverEnd.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server read after the caller half-closed: got %v, want EOF", err)
	}
	if _, err := serverEnd.Write(response); err != nil {
		t.Fatalf("write response after the half-close: %v", err)
	}
	serverEnd.Close()
	if got := readFull(t, callerEnd, len(response)); string(got) != string(response) {
		t.Fatalf("caller read %q, want %q", got, response)
	}

	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("CopyWith never returned after both sides finished")
	}
	if copyErr != nil {
		t.Errorf("CopyWith reported %v after a clean shutdown on both sides, want nil", copyErr)
	}

	// Both directions were offered, which is what makes the inspector able to read a
	// response head as well as a request.
	if joined := bytes.Join(watch.up, nil); string(joined) != string(request) {
		t.Errorf("the inspector was handed %q on the way up, want %q", joined, request)
	}
	if joined := bytes.Join(watch.down, nil); string(joined) != string(response) {
		t.Errorf("the inspector was handed %q on the way down, want %q", joined, response)
	}
}

// A caller with nothing to inspect passes nil, which is the shape every path in the app has
// while the module is off: the parameter is compared against nil and nothing else happens.
func TestCopyPassesNoInspectorAtAll(t *testing.T) {
	callerEnd, client := dialPair(t)
	upstream, serverEnd := dialPair(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		CopyWith(context.Background(), client, upstream, nil, nil, nil)
	}()

	if _, err := callerEnd.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readFull(t, serverEnd, 5); string(got) != "hello" {
		t.Fatalf("server read %q, want %q", got, "hello")
	}

	callerEnd.Close()
	serverEnd.Close()
	select {
	case <-done:
	case <-time.After(ioDeadline):
		t.Fatal("CopyWith never returned")
	}
}

// A connection with no CloseWrite must still be closed, or the peer waits forever
// for an end-of-stream that never arrives.
func TestHalfCloseFallsBackToAFullCloseWhenCloseWriteIsUnavailable(t *testing.T) {
	a, b := net.Pipe() // net.Pipe conns implement no CloseWrite
	defer b.Close()

	// Set before the close: net.Pipe rejects a deadline once either end is closed.
	if err := b.SetReadDeadline(time.Now().Add(ioDeadline)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	HalfClose(a)

	// EOF specifically, not merely an error: leaving the connection open would also
	// fail this read, but as a deadline timeout, which is the bug being excluded.
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("reading the peer of a half-closed pipe: got %v, want EOF", err)
	}
}

// cuttableConn is a connection that carries its own way of being cut, the shape the fabric's
// gvisor endpoints have: the reset belongs to the endpoint rather than to a socket option on
// something else.
type cuttableConn struct {
	net.Conn
	cut    int
	closed int
}

func (c *cuttableConn) Cut()         { c.cut++ }
func (c *cuttableConn) Close() error { c.closed++; return nil }

// A connection that carries its own way of being cut is cut through it. Falling through to the
// linger option would set it on a socket that is not the one being reset, so the peer would see
// a graceful end-of-stream where a filter is what happened.
func TestAConnectionThatCarriesItsOwnResetIsCutThroughIt(t *testing.T) {
	c := &cuttableConn{}

	Reset(c)

	if c.cut != 1 {
		t.Errorf("Cut was called %d times, want once", c.cut)
	}
	if c.closed != 0 {
		t.Errorf("Close was called %d times; cutting is the whole teardown for this shape", c.closed)
	}
}
