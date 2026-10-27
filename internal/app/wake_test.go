// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"sync"
	"testing"
	"time"
)

// steppedClock is a clock a test moves by hand, read from another goroutine.
//
// taken is closed by the first reading, because the watcher's baseline is that reading: a jump
// made before it lands is a machine that was asleep before anything was watching, and the test
// would be waiting for a wake nothing can see.
type steppedClock struct {
	mu    sync.Mutex
	at    time.Time
	once  sync.Once
	taken chan struct{}
}

func newSteppedClock(at time.Time) *steppedClock {
	return &steppedClock{at: at, taken: make(chan struct{})}
}

func (c *steppedClock) now() time.Time {
	c.mu.Lock()
	at := c.at
	c.mu.Unlock()
	// Closed with the reading already in hand: released any earlier, the jump it frees can win
	// the lock and become the baseline it was supposed to come after.
	c.once.Do(func() { close(c.taken) })
	return at
}

func (c *steppedClock) jump(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// The whole point: a machine that was asleep gets everything looked at again. Nothing else
// asks -- the lifecycle loop is driven by events and a closing lid produces none -- so without
// this a laptop opens in another building with the interface, the machine's resolver and every
// forward still arranged for the network it left.
func TestTimeThisProcessWasNotRunningForIsNoticed(t *testing.T) {
	clock := newSteppedClock(time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC))
	woke := make(chan time.Duration, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchForWake(ctx, time.Millisecond, clock.now, func(away time.Duration) { woke <- away })

	<-clock.taken
	clock.jump(2 * time.Hour)

	select {
	case away := <-woke:
		if away != 2*time.Hour {
			t.Errorf("the machine was reported away for %s, want the two hours it was", away)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the machine was asleep for two hours and nothing asked for anything to be looked at")
	}
}

// And a machine that is merely running must not be reported as waking. Every sample would be a
// reconcile of every module, which is the periodic churn this app does not have.
func TestAMachineThatWasNotAwayIsLeftAlone(t *testing.T) {
	clock := newSteppedClock(time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC))
	woke := make(chan time.Duration, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchForWake(ctx, time.Millisecond, clock.now, func(away time.Duration) { woke <- away })

	<-clock.taken
	// Time passing the way it does on a machine nobody closed: a little at a time, and never
	// more than a sample plus the slack a loaded machine takes to deliver one.
	for range 50 {
		clock.jump(time.Millisecond)
		time.Sleep(time.Millisecond)
	}

	select {
	case away := <-woke:
		t.Errorf("a running machine was reported away for %s", away)
	default:
	}
}

// The reading has to be the machine's own clock rather than how long this process has been
// running. A monotonic reading does not advance while the machine is asleep, so a subtraction
// that kept it would report the one thing this exists to notice as no time at all.
func TestTheSleepIsMeasuredOnTheMachinesOwnClock(t *testing.T) {
	sampled := time.Now()
	stripped := wallTime(sampled)

	if !stripped.Equal(sampled) {
		t.Fatalf("stripping the monotonic reading moved the time from %s to %s", sampled, stripped)
	}
	// A time carrying a monotonic reading subtracts by it; one without subtracts by the wall
	// clock, which is what a machine that was asleep moved.
	asleep := stripped.Add(2 * time.Hour)
	if got := asleep.Sub(stripped); got != 2*time.Hour {
		t.Errorf("two hours of wall clock measured as %s", got)
	}
}
