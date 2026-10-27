// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

// sameAs is what decides whether the tray redraws, the dashboard's poll sees a change,
// and the forwarding engine reconciles. Comparing only the lengths of the slices -- the
// easy shortcut -- would make a node that swapped tailnet IPs or had a tag revoked look
// unchanged, so UDP forwards would keep binding an address the node no longer owns.
func TestSameAsComparesTailnetIPsAndTagsElementByElement(t *testing.T) {
	base := Status{
		BackendState: StateRunning,
		AuthURL:      "https://login.example/a",
		Hostname:     "box",
		DNSName:      "box.tail1234.ts.net",
		LoginName:    "user@example.com",
		TailscaleIPs: []string{"100.64.0.5", "fd7a::5"},
		Tags:         []string{"tag:app-tail", "tag:fleet"},
	}

	tests := []struct {
		name string
		edit func(*Status)
		same bool
	}{
		{"identical", func(*Status) {}, true},
		{"backend state", func(s *Status) { s.BackendState = StateStopped }, false},
		{"auth url", func(s *Status) { s.AuthURL = "https://login.example/b" }, false},
		{"hostname", func(s *Status) { s.Hostname = "other" }, false},
		{"dns name", func(s *Status) { s.DNSName = "other.tail1234.ts.net" }, false},
		{"login name", func(s *Status) { s.LoginName = "someone@example.com" }, false},
		{"an ip swapped for another", func(s *Status) {
			s.TailscaleIPs = []string{"100.64.0.6", "fd7a::5"}
		}, false},
		{"ips reordered", func(s *Status) {
			s.TailscaleIPs = []string{"fd7a::5", "100.64.0.5"}
		}, false},
		{"an ip dropped", func(s *Status) { s.TailscaleIPs = []string{"100.64.0.5"} }, false},
		{"a tag swapped for another", func(s *Status) {
			s.Tags = []string{"tag:app-tail", "tag:other"}
		}, false},
		{"tags reordered", func(s *Status) {
			s.Tags = []string{"tag:fleet", "tag:app-tail"}
		}, false},
		{"a tag revoked", func(s *Status) { s.Tags = []string{"tag:app-tail"} }, false},
		// Problem is derived locally by diagnose, not delivered by the backend, so
		// folding it into the comparison would make every diagnosis look like a fresh
		// backend change and re-trigger the identity refresh in a loop.
		{"locally derived problem", func(s *Status) { s.Problem = "explained" }, true},
		{"auth mode", func(s *Status) { s.AuthMode = AuthKey }, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			other := base
			other.TailscaleIPs = append([]string(nil), base.TailscaleIPs...)
			other.Tags = append([]string(nil), base.Tags...)
			tc.edit(&other)

			if got := base.sameAs(other); got != tc.same {
				t.Errorf("sameAs = %v, want %v\n base  %+v\n other %+v", got, tc.same, base, other)
			}
			// The comparison has to be symmetric, or which side is "current" changes
			// the answer and events depend on call order.
			if got := other.sameAs(base); got != tc.same {
				t.Errorf("reversed sameAs = %v, want %v", got, tc.same)
			}
		})
	}
}

// The behavioral companion to the table above: a table alone would still pass if
// nothing called sameAs correctly. A repeated InitialStatus carrying no change must not
// wake the agent, or every backend heartbeat reconciles the whole forward set.
func TestARepeatedInitialStatusWithNoChangeDoesNotSignal(t *testing.T) {
	same := &ipnstate.Status{
		BackendState: StateRunning,
		Self:         &ipnstate.PeerStatus{HostName: "steady", DNSName: "steady.ts.net."},
	}
	bus := newScriptedBus(
		ipn.Notify{InitialStatus: same},
		ipn.Notify{InitialStatus: same},
		ipn.Notify{InitialStatus: same},
	)
	n := newTestNode(t, AuthInteractive, bus, same)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bus.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	waitForStatus(t, n, "the first status to be applied", func(s Status) bool {
		return s.Hostname == "steady"
	})

	// Drain the signal the first (genuine) change produced.
	select {
	case <-n.Events():
	case <-time.After(3 * time.Second):
		t.Fatal("the first status change produced no event")
	}

	// The two repeats must produce nothing. Signals coalesce into a buffer of one, so
	// a second event here means at least one repeat was treated as a change.
	select {
	case <-n.Events():
		t.Error("an unchanged status woke the agent; every backend heartbeat would " +
			"reconcile the whole forward set")
	case <-time.After(200 * time.Millisecond):
	}
}

// A control-plane rejection arrives as one ErrMessage on the bus and nowhere else. It
// is the only explanation the user gets for a node that will not enroll -- lose it and
// the dashboard shows "NeedsLogin" forever with no reason and no next step.
func TestABackendErrorBecomesTheDiagnosedProblemTheDashboardShows(t *testing.T) {
	const backendErr = "tag:app-tail is not defined in the tailnet policy file"
	bus := newScriptedBus(
		ipn.Notify{ErrMessage: strPtr(backendErr)},
		ipn.Notify{State: statePtr(ipn.NeedsLogin)},
	)
	n := newTestNode(t, AuthOAuth, bus, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bus.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	// Waiting on the diagnosis rather than on the raw error: the error lands first and
	// the state notify behind it is what wraps it, so waiting on the error alone would
	// read the half-built Problem whenever the two notifies are not drained together.
	got := waitForStatus(t, n, "the backend error to be diagnosed", func(s Status) bool {
		return strings.Contains(s.Problem, "OAuth client")
	})
	// The diagnosis must carry the backend's own words; guidance alone leaves the user
	// with no idea which of their settings the control plane actually objected to.
	if !strings.Contains(got.Problem, backendErr) {
		t.Errorf("Problem = %q, want the backend's own error inside the guidance", got.Problem)
	}
	if !strings.Contains(got.Problem, "tag:app-tail") {
		t.Errorf("Problem = %q, want it to name the tag the node advertises", got.Problem)
	}
}

// Reaching Running clears the diagnosis. A node that connected while still showing why
// it could not connect sends the user chasing a problem that no longer exists.
func TestReachingRunningClearsAPreviousDiagnosis(t *testing.T) {
	n := newTestNode(t, AuthKey, newScriptedBus(), nil)
	n.mu.Lock()
	n.status.Problem = "An auth key is configured but the node could not enroll."
	n.mu.Unlock()

	n.diagnose(StateRunning)

	if got := n.Status().Problem; got != "" {
		t.Errorf("Problem = %q after reaching Running, want it cleared", got)
	}
}

// An interactive login legitimately idles in NeedsLogin until the user clicks the link,
// so an untagged one must stay quiet. Speaking up there would put a scary explanation
// on the dashboard for the normal case of a link not yet clicked.
func TestAnUntaggedInteractiveLoginIsNotDiagnosedAsAProblem(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
	n.params.AdvertiseTags = nil

	n.diagnose(StateNeedsLogin)

	if got := n.Status().Problem; got != "" {
		t.Errorf("Problem = %q for an interactive login still waiting on the user, want none", got)
	}
}

// The bus is unavailable for the whole window between the backend starting and it being
// ready to serve. Giving up on the first failure would leave the node's status frozen at
// whatever it was, with no events ever again -- forwards would never start.
func TestAnUnavailableBusIsRetriedRatherThanAbandoned(t *testing.T) {
	var (
		mu    sync.Mutex
		opens int
	)
	live := newScriptedBus(ipn.Notify{State: statePtr(ipn.Running)})
	n := newTestNode(t, AuthInteractive, live, &ipnstate.Status{BackendState: StateRunning})
	n.openBus = func(context.Context) (busWatcher, error) {
		mu.Lock()
		defer mu.Unlock()
		opens++
		if opens == 1 {
			return nil, errors.New("backend is not listening yet")
		}
		return live, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		live.Close()
		<-n.watchDone
	}()
	go n.watch(ctx)

	deadline := time.Now().Add(watchRetryDelay + 3*time.Second)
	for time.Now().Before(deadline) {
		if n.Status().BackendState == StateRunning {
			mu.Lock()
			got := opens
			mu.Unlock()
			if got < 2 {
				t.Errorf("the bus was opened %d times; the first failure must be retried", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("watch never recovered from a bus that was unavailable at first")
}

// A bus that never becomes available must not keep a cancelled node alive: shutdown
// waits on the watcher, so a retry loop that ignored cancellation would hang every
// restart for the full retry delay, and a stuck one forever.
func TestAWatcherRetryingAnUnavailableBusStopsOnCancellation(t *testing.T) {
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
	n.openBus = func(context.Context) (busWatcher, error) {
		return nil, errors.New("backend is never coming up")
	}

	ctx, cancel := context.WithCancel(context.Background())
	go n.watch(ctx)

	// Let it fail once and enter its retry sleep, then cancel from underneath it.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case <-n.watchDone:
	case <-time.After(watchRetryDelay + 2*time.Second):
		t.Fatal("a watcher retrying an unavailable bus ignored cancellation")
	}
	if elapsed := time.Since(start); elapsed >= watchRetryDelay {
		t.Errorf("cancellation took %s to take effect; the retry sleep of %s is not "+
			"interruptible, so every restart pays it", elapsed, watchRetryDelay)
	}
}

// The context ending while a bus is already open must stop the watcher rather than
// resubscribe. Otherwise Close waits on a watcher that is busy opening a new stream
// against a backend that is shutting down.
func TestAWatcherDoesNotResubscribeAfterCancellation(t *testing.T) {
	var (
		mu    sync.Mutex
		opens int
	)
	ctx, cancel := context.WithCancel(context.Background())
	bus := newCancellableBus(ctx)
	n := newTestNode(t, AuthInteractive, bus, nil)
	n.openBus = func(context.Context) (busWatcher, error) {
		mu.Lock()
		opens++
		mu.Unlock()
		return bus, nil
	}

	go n.watch(ctx)
	waitFor(t, 3*time.Second, "the bus to be opened", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return opens == 1
	})

	cancel()
	select {
	case <-n.watchDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher did not exit after cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	if opens != 1 {
		t.Errorf("the bus was opened %d times; a cancelled watcher must not resubscribe", opens)
	}
}

// waitFor polls until cond holds, so no test here has to guess at a sleep duration.
func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}
