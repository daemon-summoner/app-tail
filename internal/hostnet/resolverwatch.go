// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// resolverWatchInterval is how often the helper checks that this machine is not pointed at
// an app-tail that is not there. It is the longest a machine can go resolving nothing after a
// boot-time repair missed, so it is short; a pass with nothing to do is a handful of reads.
const resolverWatchInterval = 30 * time.Second

// resolverWatch puts this machine's resolver back whenever no agent is holding it.
//
// The rule it rests on is the session gate's: an agent that has pointed this machine at
// app-tail holds the resolver session for as long as it is serving, and the teardown that
// releases it puts the machine back first. So a free session with a service still pointed
// at app-tail is a machine pointed at nothing -- a run that crashed or lost power, a restore
// that ran at boot before the network was up and failed, a service the record lost -- and it
// stays that way until somebody opens app-tail, which is the bug this exists for.
type resolverWatch struct {
	gate   *sessionGate
	repair func(ctx context.Context, logf func(format string, args ...any)) (bool, error)
	logf   func(format string, args ...any)

	// lastErr is what the previous pass failed with, so a failure that repeats every pass --
	// an unplugged adapter the record still names -- is reported when it starts and when it
	// changes rather than twice a minute forever.
	lastErr string
}

func newResolverWatch(gate *sessionGate, logf func(format string, args ...any)) *resolverWatch {
	return &resolverWatch{gate: gate, repair: RepairSystemDNS, logf: logf}
}

// run makes a pass at every tick until ctx ends.
func (w *resolverWatch) run(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			w.pass(ctx)
		}
	}
}

// pass repairs this machine's resolver if no agent holds it, reporting whether it ran. An
// app-tail serving this machine outside the helper, one running as root, holds the serving
// lock rather than the session, and the repair stands back for it the same way.
//
// It holds the resolver session for as long as it runs, so an agent arriving mid-repair
// waits for the machine to be put back rather than the two writing the same services at
// once. The wait is the gate's handover, and an agent that outlasts it retries.
func (w *resolverWatch) pass(ctx context.Context) bool {
	if !w.gate.tryTake(gateResolver) {
		return false
	}
	defer w.gate.release(gateResolver)

	ctx, cancel := context.WithTimeout(ctx, systemDNSRestoreTimeout)
	defer cancel()
	// Held back until the pass's outcome is known: a pass that changed nothing and failed
	// the way the last one did has nothing to add to the log.
	var lines []string
	restored, err := w.repair(ctx, func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	if errors.Is(err, ErrResolverServed) {
		return false
	}
	failure := ""
	if err != nil {
		failure = err.Error()
	}
	repeated := failure == w.lastErr
	w.lastErr = failure
	// A failed restore still reports restored, because there was a record; what it failed
	// with is what says whether anything new happened.
	if (err != nil && repeated) || (err == nil && !restored) {
		return true
	}
	for _, line := range lines {
		w.logf("%s", line)
	}
	switch {
	case err != nil:
		w.logf("could not put this machine's resolver back: %v", err)
	case restored:
		w.logf("restored this machine's resolver, which was pointed at app-tail while no app-tail was serving it")
	}
	return true
}
