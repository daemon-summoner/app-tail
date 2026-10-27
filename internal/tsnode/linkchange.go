// SPDX-License-Identifier: MIT

package tsnode

// Watching this machine's own networking for movement, for everything in the app that has
// to react to it.
//
// It lives here because the monitor is part of the tailnet stack, and this package is the
// one place allowed to reach that stack. What comes out is a channel: a caller learns that
// the machine's networking moved and decides for itself what that means, without taking on
// the vocabulary of interfaces, deltas and default routes.
//
// One monitor, however many watchers. Each one costs a goroutine and, on some platforms, a
// subscription to the operating system's own change notifications; several would multiply
// both and hand out several answers to a question with one answer. It is started when the
// first watcher asks and shut down when the last one goes away, so a machine with nothing
// watching is not paying for it.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"tailscale.com/net/netmon"
	"tailscale.com/util/eventbus"
)

// linkWatch is the shared monitor and who is currently listening to it.
var linkWatch struct {
	mu       sync.Mutex
	mon      *netmon.Monitor
	bus      *eventbus.Bus
	watchers int
}

// WatchLinkChanges reports when this machine's own networking has moved enough that
// sockets bound to it are likely stale -- a different network, a woken laptop, an
// interface that came or went.
//
// One signal per change, coalesced: a watcher that is busy when three arrive sees one,
// because the answer to all three is the same and doing it three times is wasted work. The
// channel is closed when ctx is done, which is also when this watcher stops costing
// anything.
func WatchLinkChanges(ctx context.Context) (<-chan struct{}, error) {
	mon, err := acquireMonitor()
	if err != nil {
		return nil, err
	}
	w := &linkWatcher{ch: make(chan struct{}, 1)}
	unregister := mon.RegisterChangeCallback(func(delta *netmon.ChangeDelta) {
		// The monitor's own conservative judgement of whether sockets need rebinding.
		// Deciding that again here would be a second, worse copy of it.
		if delta.RebindLikelyRequired {
			w.notify()
		}
	})
	go func() {
		<-ctx.Done()
		unregister()
		w.stop()
		releaseMonitor()
	}()
	return w.ch, nil
}

// linkWatcher is one caller's channel, with the flag that keeps a callback arriving during
// shutdown from sending on a closed channel.
type linkWatcher struct {
	mu     sync.Mutex
	ch     chan struct{}
	closed bool
}

func (w *linkWatcher) notify() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	select {
	case w.ch <- struct{}{}:
	default:
	}
}

func (w *linkWatcher) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	close(w.ch)
}

// acquireMonitor returns the shared monitor, starting it if this is the first watcher.
func acquireMonitor() (*netmon.Monitor, error) {
	linkWatch.mu.Lock()
	defer linkWatch.mu.Unlock()
	if linkWatch.mon != nil {
		linkWatch.watchers++
		return linkWatch.mon, nil
	}
	bus := eventbus.New()
	mon, err := netmon.New(bus, func(string, ...any) {})
	if err != nil {
		bus.Close()
		return nil, fmt.Errorf("watch this machine's network interfaces: %w", err)
	}
	mon.Start()
	linkWatch.mon, linkWatch.bus, linkWatch.watchers = mon, bus, 1
	return mon, nil
}

// releaseMonitor gives up one watcher's share, shutting the monitor down when the last one
// goes.
func releaseMonitor() {
	linkWatch.mu.Lock()
	defer linkWatch.mu.Unlock()
	linkWatch.watchers--
	if linkWatch.watchers > 0 {
		return
	}
	mon, bus := linkWatch.mon, linkWatch.bus
	linkWatch.mon, linkWatch.bus, linkWatch.watchers = nil, nil, 0
	// The caller that opened this watcher has already gone, so there is nobody to return
	// this to. It is still said out loud: a handle on the platform's notifications that
	// would not close is a leak that grows every time a connection is restarted.
	if err := mon.Close(); err != nil {
		slog.Default().Warn("stopping this machine's network monitor failed", "error", err)
	}
	bus.Close()
}
