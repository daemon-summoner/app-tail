// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// runAcceptLoop drives acceptTCP directly over a scripted listener. Going through the
// manager would require a real socket that fails on demand, which no platform offers;
// acceptTCP already takes the listener as a parameter, so no production seam is needed.
func runAcceptLoop(t *testing.T, ln net.Listener) (*Manager, *entry, func()) {
	t.Helper()
	return runAcceptLoopWithLimit(t, ln, maxTCPConns)
}

// runAcceptLoopWithLimit is runAcceptLoop with the connection ceiling set small enough
// for a test to reach it.
func runAcceptLoopWithLimit(t *testing.T, ln net.Listener, limit int) (*Manager, *entry, func()) {
	t.Helper()

	m := NewManager(carry(newFakeTailnet()), testSettings, quietLogger())
	e := &entry{fwd: tcpToLocal(t, "f_accept", 1, "box:80"), counters: newCounters()}
	e.counters.setRunning("127.0.0.1:1")

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	slots := make(chan struct{}, limit)
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.acceptTCP(ctx, e, e.fwd, ln, wg, slots)
	}()

	stop := func() {
		cancel()
		ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the accept loop did not exit after cancellation")
		}
		wg.Wait()
	}
	t.Cleanup(stop)
	return m, e, stop
}

// A listener that keeps reporting a transient error -- a socket deadline, an
// out-of-descriptors moment -- must not be retried in a tight loop. Without the
// throttle the accept loop pins a core for as long as the condition lasts, which on a
// laptop means the fans spin up and the agent looks like the culprit.
func TestATransientAcceptErrorIsRetriedButThrottled(t *testing.T) {
	// Far more failures than the loop can serve within the window below if it honors
	// the delay, and trivially many if it does not.
	script := make([]error, 200)
	for i := range script {
		script[i] = timeoutErr{}
	}
	ln := newScriptedListener(script...)
	_, e, _ := runAcceptLoop(t, ln)

	// Two retries' worth of delay is enough to tell a throttled loop from a spin
	// without making the test slow.
	time.Sleep(4 * acceptRetryDelay)

	got := ln.acceptCount()
	if got < 2 {
		t.Fatalf("the loop made %d accept attempts; a transient error must be retried, not fatal", got)
	}
	// A spinning loop would burn through all 200 in microseconds.
	if got > 20 {
		t.Errorf("the loop made %d accept attempts in %s; acceptRetryDelay of %s is not being honored",
			got, 4*acceptRetryDelay, acceptRetryDelay)
	}
	// Retrying is not a failure: the forward is still listening and must not be
	// painted red in the dashboard for a hiccup it recovered from.
	if st := e.counters.snapshot("f_accept"); st.State != StateRunning {
		t.Errorf("a transient accept error moved the forward to %q; it must stay %q",
			st.State, StateRunning)
	}
}

// Every accepted connection holds a goroutine and two descriptors for as long as it
// lives, and a connection that says nothing lives until its peer gives up. Connecting is
// cheap for whoever does it, so without a ceiling the descriptors this process holds are
// decided by whoever is connecting -- and descriptors run out for the whole process, not
// for one forward.
func TestConnectionsPastTheLimitAreRefusedRatherThanQueued(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Every dial parks, so each accepted connection holds its slot for the whole test --
	// which is what a connection that has said nothing yet does.
	gated := newGatedTailnet(true)
	m := NewManager(carry(gated), testSettings, quietLogger())
	e := &entry{fwd: tcpToLocal(t, "f_limit", 1, "box:80"), counters: newCounters(), net: gated}
	e.counters.setRunning(ln.Addr().String())

	const limit = 4
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	slots := make(chan struct{}, limit)
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		m.acceptTCP(ctx, e, e.fwd, ln, wg, slots)
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		gated.release()
		<-loopDone
		wg.Wait()
	})

	addr := ln.Addr().String()
	for i := range limit {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		t.Cleanup(func() { conn.Close() })
	}
	// Every slot is spoken for only once each connection has reached the dial.
	waitFor(t, 5*time.Second, "every accepted connection to be holding a slot", func() bool {
		return gated.parkedDials() == limit
	})

	over, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial past the limit: %v", err)
	}
	defer over.Close()

	// A refused connection is closed rather than held, so the client reads EOF instead
	// of waiting on a service that will never answer it.
	if err := over.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a read deadline: %v", err)
	}
	if _, err := over.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("reading the refused connection gave %v, want EOF from it being closed", err)
	}
	if got := gated.parkedDials(); got != limit {
		t.Errorf("%d dials are parked, want the refused connection never to have dialled (%d)", got, limit)
	}
	if got := e.counters.snapshot("f_limit").Error; !strings.Contains(got, "limit") {
		t.Errorf("error = %q, want it to say the forward is at its connection limit", got)
	}
}

// A listener that dies for good -- its file descriptor closed out from under the
// process, the interface it bound going away -- must leave the forward showing the
// reason. Silently returning would leave a rule that looks fine and accepts nothing.
func TestAPermanentAcceptFailureStopsTheLoopAndNamesTheReason(t *testing.T) {
	fatal := errors.New("bad file descriptor")
	ln := newScriptedListener(fatal)
	_, e, _ := runAcceptLoop(t, ln)

	deadline := time.Now().Add(5 * time.Second)
	var st Status
	for time.Now().Before(deadline) {
		st = e.counters.snapshot("f_accept")
		if st.State == StateError {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if st.State != StateError {
		t.Fatalf("a dead listener left the forward as %q, want %q", st.State, StateError)
	}
	if !strings.Contains(st.Error, fatal.Error()) {
		t.Errorf("the forward reports %q, want it to name the underlying failure %q", st.Error, fatal)
	}

	// The loop must be gone, not retrying: one more accept after the fatal error
	// would mean the listener is being hammered forever.
	before := ln.acceptCount()
	time.Sleep(4 * acceptRetryDelay)
	if after := ln.acceptCount(); after != before {
		t.Errorf("the loop kept accepting after a permanent failure (%d -> %d)", before, after)
	}
}

// A deliberate stop arriving mid-retry must end the loop rather than sleep out the
// delay and try again. Otherwise every stopped forward holds its goroutine and its
// listener for another retry interval, and StopAll's wait grows with the forward count.
func TestARetryingAcceptLoopStopsImmediatelyOnCancellation(t *testing.T) {
	script := make([]error, 200)
	for i := range script {
		script[i] = timeoutErr{}
	}
	ln := newScriptedListener(script...)
	_, _, stop := runAcceptLoop(t, ln)

	// Let the loop reach its retry sleep, then cancel from underneath it.
	time.Sleep(acceptRetryDelay / 2)

	returned := make(chan struct{})
	go func() {
		stop()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling did not stop a retrying accept loop")
	}
}

// A deliberate stop must not be reported as a fault. The listener's Close makes Accept
// return net.ErrClosed, which is indistinguishable from a real failure except for the
// context -- get that wrong and every shutdown paints every forward red on the way out.
func TestClosingTheListenerDuringAStopIsNotAFault(t *testing.T) {
	ln := newScriptedListener()
	_, e, stop := runAcceptLoop(t, ln)

	stop()

	if st := e.counters.snapshot("f_accept"); st.State == StateError {
		t.Errorf("a deliberate stop was recorded as an error: %q", st.Error)
	}
}

// isTemporary decides between retrying forever and giving up, and it is reached with
// errors that arrive wrapped -- net's own accept path wraps in *net.OpError. A
// non-timeout net.Error must NOT be retried: a permanently broken listener retried at
// 50ms forever is a rule that never works and never says so.
func TestIsTemporaryRetriesOnlyTimeouts(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"socket deadline", timeoutErr{}, true},
		{"wrapped socket deadline", fmt.Errorf("accept tcp: %w", timeoutErr{}), true},
		{"wrapped in an OpError", &net.OpError{Op: "accept", Err: timeoutErr{}}, true},
		{"listener closed", net.ErrClosed, false},
		{"wrapped closed", fmt.Errorf("accept: %w", net.ErrClosed), false},
		{"plain error", errors.New("bad file descriptor"), false},
		{"context cancelled", context.Canceled, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTemporary(tc.err); got != tc.want {
				t.Errorf("isTemporary(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// sleepCtx is what makes every retry and backoff in this package interruptible. A
// version that ignored cancellation would add its full delay to every shutdown.
func TestSleepCtxReportsWhetherItSleptOrWasCancelled(t *testing.T) {
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Error("sleepCtx reported cancellation for an uncancelled context")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if sleepCtx(ctx, 5*time.Second) {
		t.Error("sleepCtx slept through a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleepCtx took %s to notice cancellation", elapsed)
	}
}

// A forward whose protocol or direction the engine does not implement has to fail
// visibly at start. Falling through to a default would leave a rule that is listed as
// running and forwards nothing.
func TestAnUnsupportedProtocolOrDirectionFailsWithItsReason(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Forward)
		want   string
	}{
		{"unknown protocol", func(f *config.Forward) { f.Protocol = "sctp" }, "unsupported protocol"},
		{"unknown direction on tcp", func(f *config.Forward) { f.Direction = "sideways" }, "unsupported direction"},
		{"unknown direction on udp", func(f *config.Forward) {
			f.Direction = "sideways"
			f.Protocol = config.UDP
		}, "unsupported direction"},
		{"unknown direction on both", func(f *config.Forward) {
			f.Direction = "sideways"
			f.Protocol = config.Both
		}, "unsupported direction"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, newFakeTailnet())
			fwd := tcpToLocal(t, "f_bogus", freePort(t), "box:80")
			tc.mutate(&fwd)
			m.Apply([]config.Forward{fwd})

			st := m.Status("f_bogus")
			if st.State != StateError {
				t.Fatalf("state = %q, want %q", st.State, StateError)
			}
			if !strings.Contains(st.Error, tc.want) {
				t.Errorf("error = %q, want it to contain %q", st.Error, tc.want)
			}
		})
	}
}
