// SPDX-License-Identifier: MIT

package app

// Noticing that this machine was away.
//
// A laptop that closes at a desk and opens in a coffee shop has, from this process's point of
// view, done nothing at all: no event arrives, so nothing is reconciled, and every module goes
// on believing what it believed when the lid closed. The connections' own watchers cover their
// sockets; what they do not cover is this app's own state -- the interface carrying the private
// networks, the machine's resolver, the proxies, the forwards -- all of which is settled by a
// pass that nothing is asking for.
//
// Sleep is detected rather than subscribed to: the operating system's own notification is a
// per-platform native callback, and what makes a wake recognisable is visible from here without
// one. A sample that arrives with far more wall-clock time behind it than the interval allows is
// time this process was not running for, which is a machine that was asleep or a clock that was
// moved. Both call for the same thing -- look at everything again -- so neither needs telling
// apart.

import (
	"context"
	"time"
)

const (
	// wakeSample is how often the clock is looked at. It is not a reconcile schedule: nothing
	// happens on a sample unless the gap behind it is wrong, so the cost of this is one wakeup
	// per interval, doing a subtraction.
	wakeSample = 30 * time.Second
	// wakeSlack is how much longer than the interval a gap may be before it counts as time this
	// process was not running for. It is generous because a loaded machine delivers a tick late
	// and that is not a wake, and because the cost of being wrong is one extra reconcile.
	wakeSlack = 20 * time.Second
)

// watchForWake calls back whenever more wall-clock time has passed than the sampling interval
// can account for, with how much.
//
// now is read rather than time.Now so a test drives a whole sleep in an instant. The comparison
// is between wall clocks on purpose: a monotonic reading does not advance while the machine is
// asleep, which is exactly the time being looked for.
func watchForWake(ctx context.Context, every time.Duration, now func() time.Time, woke func(away time.Duration)) {
	tick := time.NewTicker(every)
	defer tick.Stop()

	last := wallTime(now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		sample := wallTime(now())
		away := sample.Sub(last)
		last = sample
		if away < every+wakeSlack {
			continue
		}
		woke(away)
	}
}

// wallTime strips the monotonic reading, so a subtraction between two of these is what the
// machine's clock says rather than how long this process was running.
func wallTime(t time.Time) time.Time { return t.Round(0) }
