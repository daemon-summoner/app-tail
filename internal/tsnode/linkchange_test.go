// SPDX-License-Identifier: MIT

package tsnode

// What the shared link watcher costs and when it stops costing it.
//
// The signal itself cannot be provoked here -- it comes from this machine's own interfaces
// changing, and a test that unplugged the network to see it would be a test nobody can run.
// What is worth pinning is the part that is this package's own decision: one monitor however
// many watchers, and nothing left running once the last one goes.

import (
	"context"
	"testing"
	"time"
)

// monitorState is the shared monitor and how many watchers it has, read the way another
// goroutine's release would be seen.
func monitorState() (running bool, watchers int) {
	linkWatch.mu.Lock()
	defer linkWatch.mu.Unlock()
	return linkWatch.mon != nil, linkWatch.watchers
}

// waitForMonitor waits for the shared state to settle, since a watcher is released by the
// goroutine watching its context rather than by the caller that cancelled it.
func waitForMonitor(t *testing.T, wantRunning bool, wantWatchers int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		running, watchers := monitorState()
		if running == wantRunning && watchers == wantWatchers {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("the monitor is running=%v with %d watchers, want running=%v with %d",
				running, watchers, wantRunning, wantWatchers)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Each monitor costs a goroutine and, on some platforms, a subscription to the operating
// system's own change notifications. One per connection would multiply both and hand out
// several answers to a question that has one.
func TestEveryWatcherSharesOneMonitor(t *testing.T) {
	first, stopFirst := context.WithCancel(context.Background())
	defer stopFirst()
	if _, err := WatchLinkChanges(first); err != nil {
		t.Fatalf("watch this machine's networking: %v", err)
	}
	running, _ := monitorState()
	if !running {
		t.Fatal("asking to be told about network changes started no monitor")
	}
	linkWatch.mu.Lock()
	mon := linkWatch.mon
	linkWatch.mu.Unlock()

	second, stopSecond := context.WithCancel(context.Background())
	defer stopSecond()
	if _, err := WatchLinkChanges(second); err != nil {
		t.Fatalf("watch this machine's networking a second time: %v", err)
	}

	waitForMonitor(t, true, 2)
	linkWatch.mu.Lock()
	same := linkWatch.mon == mon
	linkWatch.mu.Unlock()
	if !same {
		t.Error("a second watcher started a second monitor")
	}
}

// Three changes in a row are one question with one answer -- rebind and look the server up
// again -- so a watcher that was busy for all three does that work once. Without the
// coalescing a laptop waking up to a burst of interface events would rebuild every
// connection several times over.
func TestSeveralChangesAtOnceAreOneSignal(t *testing.T) {
	w := &linkWatcher{ch: make(chan struct{}, 1)}

	w.notify()
	w.notify()
	w.notify()

	if got := len(w.ch); got != 1 {
		t.Fatalf("%d signals waiting, want one", got)
	}
	<-w.ch
	select {
	case <-w.ch:
		t.Error("a second signal was waiting for a change that had already been reported")
	default:
	}
}

// The monitor's callbacks run on its own goroutine, so one can arrive while the watcher
// that registered it is being torn down. Sending then would panic on a closed channel and
// take the whole process with it.
func TestAChangeArrivingDuringShutdownIsDropped(t *testing.T) {
	w := &linkWatcher{ch: make(chan struct{}, 1)}
	w.stop()

	w.notify()

	if _, open := <-w.ch; open {
		t.Error("a stopped watcher delivered a change")
	}
	// Stopping is what a cancelled context does, and a context may be cancelled while the
	// watcher is already going away.
	w.stop()
}

// A machine with nothing watching must not be paying for a monitor. Without this the cost
// is per connection ever started rather than per connection running.
func TestTheMonitorStopsWhenTheLastWatcherGoes(t *testing.T) {
	first, stopFirst := context.WithCancel(context.Background())
	changes, err := WatchLinkChanges(first)
	if err != nil {
		t.Fatalf("watch this machine's networking: %v", err)
	}
	second, stopSecond := context.WithCancel(context.Background())
	if _, err := WatchLinkChanges(second); err != nil {
		t.Fatalf("watch this machine's networking a second time: %v", err)
	}
	waitForMonitor(t, true, 2)

	stopFirst()
	// The channel closing is how a caller learns its watcher has ended, and it is what a
	// receive on it stops blocking on.
	select {
	case _, open := <-changes:
		if open {
			t.Error("a watcher that was stopped delivered a change instead of ending")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stopped watcher's channel was never closed")
	}
	waitForMonitor(t, true, 1)

	stopSecond()
	waitForMonitor(t, false, 0)
}
