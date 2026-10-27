// SPDX-License-Identifier: MIT

package forward

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// errAlwaysFails is the reason a stubbed listener refuses to close.
var errAlwaysFails = errors.New("listener is wedged")

// blockingCloser is a forward listener whose Close can be held open and made to fail,
// which is what lets teardown be observed at a point a real listener races past.
type blockingCloser struct {
	release chan struct{}
	err     error
}

func (c *blockingCloser) Close() error {
	if c.release != nil {
		<-c.release
	}
	return c.err
}

// syncBuffer is a log sink that can be read while the code under test is still
// writing to it, which a bare bytes.Buffer cannot be.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// stalledManager registers one running forward whose teardown blocks until the
// returned release func is called.
func stalledManager(t *testing.T, closeErr error) (*Manager, *syncBuffer, func()) {
	t.Helper()

	logs := new(syncBuffer)
	m := NewManager(carry(newFakeTailnet()), testSettings,
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	closer := &blockingCloser{release: make(chan struct{}), err: closeErr}
	m.entries["f_stalled"] = &entry{
		fwd:      config.Forward{ID: "f_stalled", Name: "stalled"},
		counters: newCounters(),
		cancel:   func() {},
		closer:   closer,
		wg:       &sync.WaitGroup{},
	}

	var once sync.Once
	return m, logs, func() { once.Do(func() { close(closer.release) }) }
}

// The shutdown context bounds only how long StopAll stays quiet, never how long it
// waits. Returning at the deadline would abandon goroutines still holding the
// listeners, and the replacement manager would then fail to rebind every port -- the
// exact failure the deadline looks like it is preventing.
func TestStopAllWaitsPastItsBudgetRatherThanAbandoningListeners(t *testing.T) {
	m, logs, release := stalledManager(t, nil)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	returned := make(chan struct{})
	go func() {
		m.StopAll(ctx)
		close(returned)
	}()

	// The budget is already spent, yet the teardown is still held: StopAll must not
	// return while a listener is outstanding.
	select {
	case <-returned:
		t.Fatal("StopAll returned while a forward still held its listener")
	case <-time.After(100 * time.Millisecond):
	}

	if got := logs.String(); !strings.Contains(got, "longer than the shutdown budget") {
		t.Errorf("logs = %q, want a warning that the budget was exceeded", got)
	}

	release()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll never returned after the forward finished stopping")
	}

	if len(m.entries) != 0 {
		t.Errorf("entries = %d after StopAll, want the registry cleared", len(m.entries))
	}
}

// A listener that will not close keeps its port bound, and the next start then reports
// only "address already in use" with no cause. Teardown has no caller that could act
// on it, so the log is the only place that cause can survive.
func TestStopAllLogsAListenerThatWouldNotClose(t *testing.T) {
	m, logs, release := stalledManager(t, errAlwaysFails)
	release()

	m.StopAll(context.Background())

	got := logs.String()
	if !strings.Contains(got, "forward listener failed to close") {
		t.Errorf("logs = %q, want the failed close reported", got)
	}
	if !strings.Contains(got, "f_stalled") {
		t.Errorf("logs = %q, want the forward id so the port can be identified", got)
	}
	if !strings.Contains(got, errAlwaysFails.Error()) {
		t.Errorf("logs = %q, want the underlying reason", got)
	}
}

// A "both" forward must bind TCP and UDP or neither. When the UDP half cannot bind --
// another process already holds that port on UDP, which is common in the ephemeral
// range -- the TCP listener it already opened has to be rolled back, or the forward
// half-listens: connections are accepted on TCP and answered by nothing, and the port
// stays bound so the next start reports only "address already in use".
func TestABothForwardRollsBackItsTCPHalfWhenUDPCannotBind(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := NewManager(carry(tn), testSettings, quietLogger())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})

	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// Hold the UDP side only, leaving TCP free: the forward's first half succeeds and
	// its second half cannot.
	held, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("hold the udp port: %v", err)
	}
	defer held.Close()

	fwd := tcpToLocal(t, "f_both", port, "box:80")
	fwd.Protocol = config.Both
	m.Apply([]config.Forward{fwd})

	got := waitForStatus(t, m, "f_both", "the both-protocol forward to report its failure", func(s Status) bool {
		return s.State == StateError
	})
	if got.Error == "" {
		t.Error("the forward reports an error state with no reason")
	}

	// The rollback is the point: with the UDP holder gone the TCP port must be free,
	// which it can only be if the TCP listener was closed rather than leaked.
	held.Close()
	probe, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the TCP half was left listening after the UDP half failed: %v", err)
	}
	probe.Close()
}
