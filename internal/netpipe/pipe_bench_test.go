// SPDX-License-Identifier: MIT

package netpipe

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
)

// BenchmarkCopyThroughput moves a fixed payload one way through Copy and reports MB/s.
// Connection setup and teardown sit outside the timer, so the number is the copy loop
// plus the socket rather than the accept.
func BenchmarkCopyThroughput(b *testing.B) {
	const payload = 8 << 20

	b.SetBytes(payload)
	b.ReportAllocs()
	listener := benchUnixListener(b)
	for b.Loop() {
		b.StopTimer()
		clientSide, clientEnd := benchUnixPair(b, listener)
		upstreamSide, upstreamEnd := benchUnixPair(b, listener)

		copied := make(chan struct{})
		go func() {
			defer close(copied)
			Copy(context.Background(), clientEnd, upstreamEnd, nil, nil)
		}()
		// The far end reads and answers nothing, so the measurement is one direction
		// rather than a round trip.
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			io.Copy(io.Discard, upstreamSide)
		}()
		b.StartTimer()

		if _, err := io.CopyN(clientSide, endlessZeros{}, payload); err != nil {
			b.Fatalf("write the payload: %v", err)
		}
		clientSide.Close()
		<-drained

		b.StopTimer()
		// The return direction is still reading from the far end, so it has to be
		// closed before Copy can return.
		upstreamSide.Close()
		<-copied
		b.StartTimer()
	}
}

// BenchmarkCopyFlowSetup is one flow's worth of Copy carrying almost no bytes: two
// goroutines, an AfterFunc registration and the two 32 KB copy buffers. Allocations per
// operation are the figure that matters -- they are paid per concurrent flow, and the
// fabric holds thousands at once.
func BenchmarkCopyFlowSetup(b *testing.B) {
	b.ReportAllocs()
	listener := benchUnixListener(b)
	for b.Loop() {
		clientSide, clientEnd := benchUnixPair(b, listener)
		upstreamSide, upstreamEnd := benchUnixPair(b, listener)

		copied := make(chan struct{})
		go func() {
			defer close(copied)
			Copy(context.Background(), clientEnd, upstreamEnd, nil, nil)
		}()
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			io.Copy(io.Discard, upstreamSide)
		}()

		if _, err := clientSide.Write([]byte("x")); err != nil {
			b.Fatalf("write: %v", err)
		}
		clientSide.Close()
		<-drained
		upstreamSide.Close()
		<-copied
	}
}

// BenchmarkCopyThroughputInspected is BenchmarkCopyThroughput with an inspector attached
// that has already reached its verdict, which is the steady state of every inspected
// transfer: the claim being measured is that a connection past its opening bytes costs one
// comparison and one call per chunk, so this and BenchmarkCopyThroughput must report the
// same MB/s within the noise of the run.
func BenchmarkCopyThroughputInspected(b *testing.B) {
	const payload = 8 << 20

	b.SetBytes(payload)
	b.ReportAllocs()
	listener := benchUnixListener(b)
	for b.Loop() {
		b.StopTimer()
		clientSide, clientEnd := benchUnixPair(b, listener)
		upstreamSide, upstreamEnd := benchUnixPair(b, listener)

		copied := make(chan struct{})
		go func() {
			defer close(copied)
			CopyWith(context.Background(), clientEnd, upstreamEnd, nil, nil, &benchWatch{})
		}()
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			io.Copy(io.Discard, upstreamSide)
		}()
		b.StartTimer()

		if _, err := io.CopyN(clientSide, endlessZeros{}, payload); err != nil {
			b.Fatalf("write the payload: %v", err)
		}
		clientSide.Close()
		<-drained

		b.StopTimer()
		upstreamSide.Close()
		<-copied
		b.StartTimer()
	}
}

// BenchmarkCopyFlowSetupInspected is BenchmarkCopyFlowSetup with an inspector, which is where
// the per-flow cost of inspection lands: this figure minus BenchmarkCopyFlowSetup is what
// switching the module on costs every connection the app carries.
func BenchmarkCopyFlowSetupInspected(b *testing.B) {
	b.ReportAllocs()
	listener := benchUnixListener(b)
	for b.Loop() {
		clientSide, clientEnd := benchUnixPair(b, listener)
		upstreamSide, upstreamEnd := benchUnixPair(b, listener)

		copied := make(chan struct{})
		go func() {
			defer close(copied)
			CopyWith(context.Background(), clientEnd, upstreamEnd, nil, nil, &benchWatch{})
		}()
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			io.Copy(io.Discard, upstreamSide)
		}()

		if _, err := clientSide.Write([]byte("x")); err != nil {
			b.Fatalf("write: %v", err)
		}
		clientSide.Close()
		<-drained
		upstreamSide.Close()
		<-copied
	}
}

// benchWatch is an inspector in its steady state: it counts what it was handed and stops
// nothing, which is what every inspected connection looks like once its verdict is in.
type benchWatch struct{ up, down int64 }

func (w *benchWatch) Up(b []byte) bool   { w.up += int64(len(b)); return false }
func (w *benchWatch) Down(b []byte) bool { w.down += int64(len(b)); return false }
func (w *benchWatch) Close()             {}

// benchUnixListener is one listener for a whole run, accepting for as long as the
// benchmark keeps dialling it. It is a unix socket rather than loopback TCP because a
// benchmark opens a pair per iteration for tens of thousands of iterations: every TCP dial
// takes an ephemeral port that stays in TIME_WAIT for minutes afterwards, and the run dies
// partway through with "can't assign requested address". Both ends still carry a real
// descriptor and a real CloseWrite, which is what the half-close path needs.
func benchUnixListener(b *testing.B) net.Listener {
	b.Helper()
	ln, err := net.Listen("unix", filepath.Join(b.TempDir(), "s"))
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	b.Cleanup(func() { ln.Close() })
	return ln
}

// benchUnixPair is one connected pair from that listener. Both ends are returned, so the
// iteration that opened them closes them and nothing accumulates across the run.
func benchUnixPair(b *testing.B, ln net.Listener) (net.Conn, net.Conn) {
	b.Helper()
	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{conn: c, err: err}
	}()

	dialed, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		dialed.Close()
		b.Fatalf("accept: %v", got.err)
	}
	return dialed, got.conn
}

// endlessZeros is a source that never runs out, so the benchmark measures the copy and
// not the thing feeding it.
type endlessZeros struct{}

func (endlessZeros) Read(p []byte) (int, error) { return len(p), nil }
