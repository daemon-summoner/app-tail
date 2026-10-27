// SPDX-License-Identifier: MIT

// Package netpipe proxies bytes between two connections. It is the one
// implementation every byte-forwarding path in the app shares, so the half-close
// propagation and the cancellation behaviour below cannot drift between callers.
package netpipe

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// Copy proxies bytes between client and upstream until either side finishes or ctx
// is cancelled, then closes both. onUp receives what was read from client and onDown
// what was read from upstream, in instalments as they cross rather than as one total
// at the end; either may be nil. Callers accumulate, so the sum is unchanged, but a
// transfer still running is visible while it runs instead of only once it closes.
//
// It returns what the two copies failed with, joined, and nil when both ends closed
// cleanly. Cancelling ctx closes both connections underneath the copies, so a
// cancelled transfer reports the resulting "use of closed network connection" rather
// than hiding it: callers that stopped on purpose distinguish the two by checking
// ctx.Err(), which keeps a deliberate shutdown from looking like a transport fault
// without discarding real ones.
func Copy(ctx context.Context, client, upstream net.Conn, onUp, onDown func(int64)) error {
	return CopyWith(ctx, client, upstream, onUp, onDown, nil)
}

// Stream is handed the bytes crossing one connection, in the direction they cross, before
// they are written on. Returning true stops the connection.
//
// Before the write is the whole contract: bytes handed over after they had been forwarded
// could be reported on but never prevented, and an inspector that can only report is not
// what any caller here is asking for.
//
// The two directions are driven by two goroutines, one each, so an implementation that keeps
// state shared between Up and Down has to synchronise it. Close is called once, from
// whichever direction finishes last.
type Stream interface {
	Up(b []byte) bool
	Down(b []byte) bool
	Close()
}

// errInspected is what a copy fails with when the inspector stopped the connection. It never
// reaches a caller: CopyWith turns it back into a nil error, because a connection stopped on
// purpose is not a transport fault and every caller here logs what it is handed.
var errInspected = errors.New("stopped by traffic inspection")

// CopyWith is Copy with the bytes offered to an inspector as they cross.
//
// A nil watch is exactly today's loop: the parameter is compared against nil once per chunk
// and nothing else happens, so a build with inspection switched off pays nothing measurable
// for the possibility of it.
//
// A connection the inspector stops is torn down with a reset rather than a graceful
// half-close. The difference is what the far end reads: a half-close is the shape of a
// finished request, and a client reading one where it expected an answer reports a broken
// server rather than a filter.
func CopyWith(ctx context.Context, client, upstream net.Conn, onUp, onDown func(int64), watch Stream) error {
	defer client.Close()
	defer upstream.Close()
	if watch != nil {
		defer watch.Close()
	}

	// A cancelled context must cut connections that are otherwise idle in Read.
	stopWatch := context.AfterFunc(ctx, func() {
		client.Close()
		upstream.Close()
	})
	defer stopWatch()

	// Buffered for both sends, so neither copy goroutine can outlive this call.
	failures := make(chan error, 2)
	go func() {
		err := copyReporting(upstream, client, onUp, upSide(watch))
		if errors.Is(err, errInspected) {
			// No half-close on this path: the connection is being stopped, and the graceful
			// shutdown would tell the far end the request simply ended.
			Reset(client)
			Reset(upstream)
		} else {
			// Propagate the half-close so protocols that signal end-of-request by
			// shutting down one direction still get their response.
			HalfClose(upstream)
		}
		failures <- err
	}()
	go func() {
		err := copyReporting(client, upstream, onDown, downSide(watch))
		if errors.Is(err, errInspected) {
			Reset(client)
			Reset(upstream)
		} else {
			HalfClose(client)
		}
		failures <- err
	}()

	joined := errors.Join(<-failures, <-failures)
	if errors.Is(joined, errInspected) {
		return nil
	}
	return joined
}

// upSide and downSide bind one direction of a watch, or nil when there is none. A nil
// function is what the copy loop compares against, so the inspected and uninspected loops
// are the same loop.
func upSide(watch Stream) func([]byte) bool {
	if watch == nil {
		return nil
	}
	return watch.Up
}

func downSide(watch Stream) func([]byte) bool {
	if watch == nil {
		return nil
	}
	return watch.Down
}

// chunkSize is how much one read moves, and so how often a transfer reports. It is
// io.Copy's own buffer size, and at that granularity a transfer of any interesting
// speed reports many times within one sampling interval.
const chunkSize = 32 * 1024

// chunks holds the copy buffers between flows.
//
// Every flow takes two of these for as long as it is open, and the fabric holds thousands
// at once -- 64 KB per flow allocated at open and thrown away at close is both the
// allocation and the garbage. A pooled buffer is safe here because nothing outside this
// loop ever sees it: it is written into by Read and drained by Write before the next
// iteration.
var chunks sync.Pool

// chunkBuffer takes a buffer from the pool, or makes one when it is empty.
func chunkBuffer() *[]byte {
	if held, ok := chunks.Get().(*[]byte); ok {
		return held
	}
	buf := make([]byte, chunkSize)
	return &buf
}

// copyReporting copies src into dst, handing each chunk to report as it lands.
//
// The loop is what makes reporting incremental: io.Copy returns a total, and a caller
// counting bytes off that total learns nothing until the connection closes -- which is
// how a long transfer reads as idle for its whole duration and then arrives as a single
// spike that flattens the scale of every real reading around it.
func copyReporting(dst io.Writer, src io.Reader, report func(int64), watch func([]byte) bool) error {
	held := chunkBuffer()
	defer chunks.Put(held)
	buf := *held
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			// Offered before the write, so a chunk the inspector stops is a chunk the far
			// end never receives.
			if watch != nil && watch(buf[:nr]) {
				return errInspected
			}
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 && report != nil {
				report(int64(nw))
			}
			if werr != nil {
				return werr
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if rerr != nil {
			// EOF is how a copy ends, not how it fails.
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}

// closeWriter is implemented by connections that support a half close.
type closeWriter interface{ CloseWrite() error }

// lingerSetter is implemented by connections whose close behaviour can be chosen, which on a
// TCP connection is the difference between a FIN and a RST.
type lingerSetter interface{ SetLinger(sec int) error }

// cutter is implemented by connections that are not OS sockets and so have no linger option,
// but can still be cut rather than shut down. The interface app-tail carries is one: its
// connections live in a userspace stack, where the reset is a method rather than an option.
type cutter interface{ Cut() }

// Reset closes c in the way that tells the far end the connection was cut rather than
// finished.
//
// The difference is what the peer's next read returns: a close after a graceful shutdown is
// an end-of-stream, which is exactly the shape of a request that ran to completion, and a
// client reading one where it expected an answer reports a broken server. A reset is the
// shape of a filter, which is the true thing to say when a filter is what happened.
//
// A connection that cannot be told how to close is closed anyway: cutting it with the wrong
// signal is still better than leaving it open.
func Reset(c net.Conn) {
	// Asked first, because a connection that carries its own way of being cut is one whose
	// linger option, if it has one at all, reaches a socket that is not the one being cut.
	if cut, ok := c.(cutter); ok {
		cut.Cut()
		return
	}
	if linger, ok := c.(lingerSetter); ok {
		// Zero seconds is the flag for it: unsent data is discarded and the close sends a
		// reset instead of a shutdown. A connection that refuses the option -- one already
		// closed underneath, which is the only way this fails -- is closed below regardless,
		// so there is nothing this could do with the error that the next line does not.
		linger.SetLinger(0)
	}
	c.Close()
}

// HalfClose shuts down the write side of c, falling back to a full close for
// connections that cannot half-close, which at least unblocks the peer.
func HalfClose(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}
	c.Close()
}
