// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// scriptedBus replays a fixed sequence of notifications, then blocks until the
// test releases it. It stands in for the real IPN bus.
type scriptedBus struct {
	mu       sync.Mutex
	notifies []ipn.Notify
	idx      int
	closed   chan struct{}
	closeOne sync.Once
	// closeErr is what ending the subscription fails with, which is what a backend
	// connection that has already gone away looks like from the watch loop.
	closeErr error
}

func newScriptedBus(notifies ...ipn.Notify) *scriptedBus {
	return &scriptedBus{notifies: notifies, closed: make(chan struct{})}
}

func (b *scriptedBus) Next() (ipn.Notify, error) {
	b.mu.Lock()
	if b.idx < len(b.notifies) {
		n := b.notifies[b.idx]
		b.idx++
		b.mu.Unlock()
		return n, nil
	}
	b.mu.Unlock()
	// The real bus blocks waiting for the next event; mimic that so the watch loop
	// does not spin, and unblock on Close.
	<-b.closed
	return ipn.Notify{}, io.EOF
}

func (b *scriptedBus) Close() error {
	b.closeOne.Do(func() { close(b.closed) })
	return b.closeErr
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// capturedLogs is a log destination a test can read back while the watch loop is still
// writing to it from its own goroutine.
type capturedLogs struct {
	mu  sync.Mutex
	buf []byte
}

func (c *capturedLogs) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *capturedLogs) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}

// waitForLog polls the captured logs until want appears or the deadline passes.
func waitForLog(t *testing.T, logs *capturedLogs, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in the logs; they read:\n%s", want, logs.String())
}

// newTestNode builds a Node whose backend access points are fakes, so the watch
// loop can be exercised with no tailnet.
func newTestNode(t *testing.T, mode AuthMode, bus busWatcher, status *ipnstate.Status) *Node {
	t.Helper()
	n := &Node{
		params:    ServerParams{Mode: mode, Hostname: "test-node", AdvertiseTags: []string{"tag:app-tail"}},
		logger:    quietLogger(),
		events:    make(chan struct{}, 1),
		watchDone: make(chan struct{}),
		status:    Status{BackendState: StateNoState, AuthMode: mode},
	}
	n.openBus = func(context.Context) (busWatcher, error) { return bus, nil }
	n.fetchStatus = func(context.Context) (*ipnstate.Status, error) {
		if status == nil {
			return nil, errors.New("no status available")
		}
		return status, nil
	}
	return n
}

func statePtr(s ipn.State) *ipn.State { return &s }
func strPtr(s string) *string         { return &s }

// waitForStatus polls the cached status until want reports true or the deadline passes.
func waitForStatus(t *testing.T, n *Node, what string, want func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last Status
	for time.Now().Before(deadline) {
		last = n.Status()
		if want(last) {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; last status: %+v", what, last)
	return last
}

// The bus sends the current state and the current prefs up front only if the watch asks
// for them. Without the prefs bit nothing arrives until something changes, so every
// pref-backed setting reads as its zero value for as long as nobody touches it -- which
// is indistinguishable from a node that never applied any of them.
func TestTheBusWatchAsksForTheStateAndThePrefsItAlreadyHas(t *testing.T) {
	n := New(Options{
		Params: ServerParams{Hostname: "watch-mask-test", Mode: AuthInteractive},
		Logger: quietLogger(),
	})
	var asked string
	n.publish(newStubbedClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/localapi/v0/watch-ipn-bus" {
			t.Errorf("the bus was opened at %s", r.URL.Path)
		}
		asked = r.URL.Query().Get("mask")
		return jsonResponse(""), nil
	}), func() {})

	w, err := n.openBus(t.Context())
	if err != nil {
		t.Fatalf("open the bus: %v", err)
	}
	t.Cleanup(func() { w.Close() })

	raw, err := strconv.ParseUint(asked, 10, 64)
	if err != nil {
		t.Fatalf("the bus was opened with mask %q, which is not a set of flags: %v", asked, err)
	}
	mask := ipn.NotifyWatchOpt(raw)
	if mask&ipn.NotifyInitialState == 0 {
		t.Error("the watch does not ask for the current state, so the node reads as NoState until it changes")
	}
	if mask&ipn.NotifyInitialPrefs == 0 {
		t.Error("the watch does not ask for the current prefs, so every pref-backed setting reads as its zero value")
	}
}

// A subscription that will not close is a fault in the backend connection, and the loop
// cannot act on it: consume has already returned, so resubscribing is the only recovery
// there is. Recording it is what tells a loop quietly leaking subscriptions apart from
// one that is simply reconnecting, and the log is the only place that shows.
func TestASubscriptionThatWouldNotCloseIsRecordedRatherThanSwallowed(t *testing.T) {
	bus := newScriptedBus()
	bus.closeErr = errors.New("the backend connection was already gone")
	n := newTestNode(t, AuthInteractive, bus, nil)
	logs := &capturedLogs{}
	n.logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		<-n.watchDone
	}()
	go n.watch(ctx)

	// Ending the stream from the far side is what makes consume return, which is the
	// only way the loop reaches its own Close.
	bus.Close()

	waitForLog(t, logs, "the backend connection was already gone")
}

func TestWatchCachesLoginURLThenRunningState(t *testing.T) {
	runningStatus := &ipnstate.Status{
		BackendState: StateRunning,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.5"), netip.MustParseAddr("fd7a:115c:a1e0::5")},
		Self: &ipnstate.PeerStatus{
			HostName: "test-node",
			DNSName:  "test-node.tail1234.ts.net.",
			UserID:   tailcfg.UserID(1),
		},
		User: map[tailcfg.UserID]tailcfg.UserProfile{
			1: {LoginName: "user@example.com"},
		},
	}
	bus := newScriptedBus(
		ipn.Notify{State: statePtr(ipn.NeedsLogin)},
		ipn.Notify{BrowseToURL: strPtr("https://login.tailscale.com/a/abc123")},
		ipn.Notify{State: statePtr(ipn.Running)},
	)
	n := newTestNode(t, AuthInteractive, bus, runningStatus)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bus.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	got := waitForStatus(t, n, "the node to reach Running", func(s Status) bool {
		return s.BackendState == StateRunning
	})

	if got.LoginName != "user@example.com" {
		t.Errorf("LoginName = %q, want the logged-in user", got.LoginName)
	}
	if got.DNSName != "test-node.tail1234.ts.net" {
		t.Errorf("DNSName = %q, want the trailing dot stripped", got.DNSName)
	}
	// A stale login URL must not linger once the node is up.
	if got.AuthURL != "" {
		t.Errorf("AuthURL = %q, want it cleared once Running", got.AuthURL)
	}
	// UDP listeners cannot bind without this; it must be cached on the Running transition.
	ip4, ip6 := n.TailnetIPs()
	if ip4.String() != "100.64.0.5" {
		t.Errorf("cached IPv4 = %v, want 100.64.0.5", ip4)
	}
	if ip6.String() != "fd7a:115c:a1e0::5" {
		t.Errorf("cached IPv6 = %v, want fd7a:115c:a1e0::5", ip6)
	}
}

func TestWatchSurfacesLoginURLWhileLoginPending(t *testing.T) {
	bus := newScriptedBus(
		ipn.Notify{State: statePtr(ipn.NeedsLogin)},
		ipn.Notify{BrowseToURL: strPtr("https://login.tailscale.com/a/abc123")},
	)
	n := newTestNode(t, AuthInteractive, bus, &ipnstate.Status{BackendState: StateNeedsLogin})

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bus.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	got := waitForStatus(t, n, "the login URL to be cached", func(s Status) bool {
		return s.AuthURL != ""
	})
	if got.AuthURL != "https://login.tailscale.com/a/abc123" {
		t.Errorf("AuthURL = %q, want the URL from the bus", got.AuthURL)
	}
	if got.BackendState != StateNeedsLogin {
		t.Errorf("BackendState = %q, want NeedsLogin", got.BackendState)
	}
}

func TestWatchReplacesStaleLoginURL(t *testing.T) {
	// Auth URLs expire; the newest one the backend offers must win.
	bus := newScriptedBus(
		ipn.Notify{BrowseToURL: strPtr("https://login.tailscale.com/a/stale")},
		ipn.Notify{BrowseToURL: strPtr("https://login.tailscale.com/a/fresh")},
	)
	n := newTestNode(t, AuthInteractive, bus, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bus.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	waitForStatus(t, n, "the refreshed login URL", func(s Status) bool {
		return s.AuthURL == "https://login.tailscale.com/a/fresh"
	})
}

func TestWatchAppliesInitialStatus(t *testing.T) {
	initial := &ipnstate.Status{
		BackendState: StateRunning,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.9")},
		Self:         &ipnstate.PeerStatus{HostName: "seeded", DNSName: "seeded.ts.net."},
	}
	bus := newScriptedBus(ipn.Notify{InitialStatus: initial})
	n := newTestNode(t, AuthInteractive, bus, initial)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bus.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	got := waitForStatus(t, n, "the initial status to be applied", func(s Status) bool {
		return s.Hostname == "seeded"
	})
	if got.BackendState != StateRunning {
		t.Errorf("BackendState = %q, want it seeded from InitialStatus", got.BackendState)
	}
	if ip4, _ := n.TailnetIPs(); ip4.String() != "100.64.0.9" {
		t.Errorf("cached IPv4 = %v, want it seeded from InitialStatus", ip4)
	}
}

func TestWatchSignalsStateChanges(t *testing.T) {
	bus := newScriptedBus(ipn.Notify{State: statePtr(ipn.NeedsLogin)})
	n := newTestNode(t, AuthInteractive, bus, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bus.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	select {
	case <-n.Events():
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not signal a state change")
	}
}

// The events channel is a one-slot doorbell: a burst of state changes must collapse
// into a single wake-up for a consumer that is slow, and it must never block the bus
// reader. Both halves matter -- blocking would stop the node tracking state whenever
// the dashboard was busy, and dropping every signal would leave the dashboard showing
// a login screen for a node that connected minutes ago.
func TestABurstOfSignalsCollapsesIntoOneWakeUpAndNeverBlocks(t *testing.T) {
	// Nothing consumes Events while the burst runs, so a signal that waited for a
	// reader would deadlock here.
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			n.signal()
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("signal blocked when no consumer was reading events")
	}

	// Exactly one wake-up is readable. Zero would mean signal did nothing at all --
	// which is what the previous shape of this test could not tell apart from
	// success -- and more than one would mean the burst was queued rather than
	// coalesced, waking the consumer 100 times for one change.
	select {
	case <-n.Events():
	default:
		t.Fatal("no wake-up was readable after 100 signals; a consumer would never " +
			"learn the node's state changed")
	}
	select {
	case <-n.Events():
		t.Error("a second wake-up was queued; the burst was not coalesced")
	default:
	}
}

func TestWatchStopsOnContextCancel(t *testing.T) {
	bus := newScriptedBus()
	n := newTestNode(t, AuthInteractive, bus, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go n.watch(ctx)

	cancel()
	bus.Close() // release the blocked Next, as closing the real client would

	select {
	case <-n.watchDone:
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not exit after its context was cancelled")
	}
}

func TestWatchResubscribesWhenTheBusDrops(t *testing.T) {
	var mu sync.Mutex
	opens := 0
	first := newScriptedBus(ipn.Notify{State: statePtr(ipn.Starting)})
	second := newScriptedBus(ipn.Notify{State: statePtr(ipn.Running)})
	first.Close() // this stream ends immediately after its scripted notify

	n := newTestNode(t, AuthInteractive, first, &ipnstate.Status{BackendState: StateRunning})
	n.openBus = func(context.Context) (busWatcher, error) {
		mu.Lock()
		defer mu.Unlock()
		opens++
		if opens == 1 {
			return first, nil
		}
		return second, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		second.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	// The retry delay is deliberate; allow for it.
	deadline := time.Now().Add(watchRetryDelay + 3*time.Second)
	for time.Now().Before(deadline) {
		if n.Status().BackendState == StateRunning {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("watch did not resubscribe after the stream dropped (opens=%d, state=%q)", opens, n.Status().BackendState)
}

func TestStatusSnapshotIsIsolated(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
	n.mu.Lock()
	n.status.TailscaleIPs = []string{"100.64.0.1"}
	n.status.Tags = []string{"tag:app-tail"}
	n.mu.Unlock()

	snap := n.Status()
	snap.TailscaleIPs[0] = "hijacked"
	snap.Tags[0] = "hijacked"

	fresh := n.Status()
	if fresh.TailscaleIPs[0] != "100.64.0.1" || fresh.Tags[0] != "tag:app-tail" {
		t.Error("mutating a status snapshot corrupted the node's cached state")
	}
}

func TestBackendStateNamesMatchTheDocumentedSet(t *testing.T) {
	// The API and UI branch on these strings; a rename upstream must not pass silently.
	tests := []struct {
		state ipn.State
		want  string
	}{
		{ipn.NoState, StateNoState},
		{ipn.NeedsLogin, StateNeedsLogin},
		{ipn.NeedsMachineAuth, StateNeedsMachineAuth},
		{ipn.Stopped, StateStopped},
		{ipn.Starting, StateStarting},
		{ipn.Running, StateRunning},
	}
	for _, tc := range tests {
		if got := backendStateName(tc.state); got != tc.want {
			t.Errorf("backendStateName(%v) = %q, want %q", tc.state, got, tc.want)
		}
	}
}
