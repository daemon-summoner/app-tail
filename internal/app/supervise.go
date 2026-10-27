// SPDX-License-Identifier: MIT

package app

// Trying again after something could not be brought up.
//
// Every module is reconciled from applyDesiredState, and a reconcile already re-attempts
// whatever is wanted and not running: a connection that failed to start is simply started
// again on the next pass. What was missing is the next pass. The loop is driven by events --
// a tailnet state change, a config write, a click -- so a connection that failed because the
// machine had no network yet stayed down until something unrelated happened to fire, which on
// a laptop that woke up in a coffee shop can be a long time.
//
// The supervisor starts nothing itself. It counts what the last pass wanted and did not
// reach, and answers how long until the loop should run the pass that would.

import (
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// The retry ladder. The first attempt comes quickly because the usual cause -- a link that
// was not up yet, a route not installed yet -- clears within seconds. It doubles after that
// because a cause that survives a minute is a configuration or an outage, and a laptop asleep
// in a bag should not be woken every five seconds for one.
const (
	retryFirst = 5 * time.Second
	retryMax   = 5 * time.Minute
)

// retryCeiling bounds the consecutive-failure count. It is the point at which the ladder has
// reached retryMax, and counting past it would only overflow the shift below.
const retryCeiling = 8

// supervisor remembers whether the last reconcile left anything it wanted running down.
//
// It is touched only from the lifecycle goroutine -- the pass that records the outcome and
// the arm that reads it are the same one -- so it carries no lock.
type supervisor struct {
	// failures is how many consecutive passes ended with something still down. Zero means the
	// last pass reached everything it wanted, and nothing is waiting on a timer.
	failures int
	// first is the bottom rung of the ladder. It is a field rather than the constant so a test
	// can watch a whole recovery happen instead of waiting one out; zero means retryFirst.
	first time.Duration
}

// settled records one pass. down is how many things that pass wanted running and did not
// reach; zero ends the ladder, because the thing being retried is up.
func (s *supervisor) settled(down int) {
	if down == 0 {
		s.failures = 0
		return
	}
	if s.failures < retryCeiling {
		s.failures++
	}
}

// nextWake is how long until the loop should reconcile again, or zero when nothing is waiting
// on it. A pass that reached everything schedules nothing: an agent whose connections are all
// up costs no timer at all.
func (s *supervisor) nextWake() time.Duration {
	if s.failures == 0 {
		return 0
	}
	first := s.first
	if first <= 0 {
		first = retryFirst
	}
	wait := first << (s.failures - 1)
	if wait > retryMax {
		return retryMax
	}
	return wait
}

// downCount is how much of what this pass wanted is not running.
//
// It is deliberately a count rather than a list: what is down is already recorded against each
// connection and each module, where the user is looking. This answers only "is there anything
// to come back for", which is the question the timer asks.
func (a *Agent) downCount() int {
	down := 0

	running := a.runningTunnels()
	for _, held := range a.runtimeTunnels() {
		if held.ID == config.PrimaryTunnelID || !held.Enabled || !a.startable[held.Type] {
			continue
		}
		if _, up := running[held.ID]; !up {
			down++
		}
	}

	// The interface carrying every private network counts too, and for the sharper reason: the
	// pass that finds it withdrawn tears it down and rebuilds it, so without a timer the
	// machine can sit with its networks taken off it indefinitely.
	if runner := a.currentFabric(); runner != nil && runner.needsAnotherPass() {
		down++
	}

	// This machine's own name resolution counts for the same reason, sharper still: an
	// override standing over a socket nobody is reading resolves no name at all, and the
	// state persists until something arms a timer.
	if runner := a.currentSystemDNS(); runner != nil && runner.needsAnotherPass() {
		down++
	}
	return down
}
