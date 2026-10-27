// SPDX-License-Identifier: MIT

package app

// Watching for this machine losing the route to its own tailnet.
//
// The fault this covers has no other reporter. A tailnet client holds the interface and the
// route for the tailnet's address range as two separate things, and only the second lives
// somewhere anything can remove it. When it goes, the client is still connected, its own probes
// to every device still answer over its own encrypted connection, and every surface it has says
// the tailnet is up -- while every ordinary program on the machine sends tailnet traffic to the
// physical network instead and waits for a timeout. The person at the keyboard sees ssh hang
// against a device the client lists as online.
//
// So this is a loop rather than a reaction to an event: nothing on the machine emits one. It
// reads the settings on each round rather than being started and stopped as the switch moves,
// for the reason the blocklist loop does -- a loop started by a setting is a loop that has to
// be stopped by one, and every path that forgets leaves either a watch that stopped watching or
// two of them running.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// The two machine-facing halves of the watch, as values rather than direct calls.
//
// This is the whole package's default, not one agent's, because every agent an unattended run
// builds gets it: the reader runs the platform's routing tool against whatever machine is
// running, and the repair behind it reaches the privileged side and changes that machine's
// routing table. An Options field alone would leave that the behaviour of every construction
// that did not think to say otherwise.
var (
	readTailnetRoutingOf  = tsnode.ReadTailnetRouting
	repairTailnetRoutesOn = tsnode.RepairTailnetRoutes
)

// tailnetRouteInterval is how often the machine is asked where it sends tailnet traffic.
//
// A round costs one short program run per end of each range the tailnet interface carries, and
// none at all on a machine with no tailnet on it. It is a minute rather than longer because the
// window it sets is how long somebody sits in front of a connection that will not open, and
// rather than shorter because the loss it looks for is not something that happens twice a day.
const tailnetRouteInterval = time.Minute

// tailnetRouteEvery is the interval this agent's watch actually runs on, so a test can shorten
// it and watch the loop come round rather than waiting a minute for it.
func (a *Agent) tailnetRouteEvery() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.tailnetRouteInterval > 0 {
		return a.tailnetRouteInterval
	}
	return tailnetRouteInterval
}

// runTailnetRouteWatch keeps this machine able to reach the tailnet it is carrying, for the life
// of the agent.
//
// It stops for one reason other than the context ending: a platform that cannot be asked the
// question at all. That is a fact about the machine rather than a round that failed, so it is
// reported once and the loop ends instead of asking again every minute for the same answer.
func (a *Agent) runTailnetRouteWatch(ctx context.Context) {
	if !a.checkTailnetRoutes(ctx) {
		return
	}
	tick := time.NewTicker(a.tailnetRouteEvery())
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if !a.checkTailnetRoutes(ctx) {
			return
		}
	}
}

// checkTailnetRoutes runs one round, reporting whether another one is worth doing.
func (a *Agent) checkTailnetRoutes(ctx context.Context) bool {
	if !a.settings().TailnetRouteRepair || a.carryingTailnetItself() {
		return true
	}

	// own is empty because of the check above: the one interface app-tail opens carries a
	// tailnet only in the mode that has just been excluded, and in every other mode a tailnet
	// on this machine belongs to a client that is not this one.
	routing, err := a.readTailnetRouting(ctx, "")
	switch {
	case errors.Is(err, tsnode.ErrTailnetRoutesUnsupported):
		a.logger.Info("this machine cannot be asked where it sends tailnet traffic, "+
			"so the route to the tailnet is not being watched", "reason", err)
		return false
	case err != nil:
		a.noteTailnetRouteTrouble("could not read where this machine sends tailnet traffic: " + err.Error())
		return true
	case !routing.Broken():
		a.clearTailnetRouteTrouble()
		return true
	}

	a.logger.Warn("this machine is carrying a tailnet it cannot reach: nothing routes the "+
		"tailnet's own address range to the interface holding it, so every program here sends "+
		"that traffic to the physical network instead",
		"interface", routing.Interface, "ranges", prefixList(routing.Unrouted))

	repaired, err := a.repairTailnetRoutes(ctx, routing.Interface, a.hostLogf)
	if err != nil {
		a.noteTailnetRouteTrouble("could not put back the route to the tailnet on " +
			routing.Interface + ": " + err.Error())
		return true
	}
	// Empty with no failure is the machine having been put right between the two calls, by the
	// client that owns the route or by a person. Nothing was done and nothing is wrong.
	if len(repaired) > 0 {
		a.logger.Info("put back the route sending tailnet traffic to the interface carrying the tailnet",
			"interface", routing.Interface, "ranges", prefixList(repaired))
	}
	a.clearTailnetRouteTrouble()
	return true
}

// carryingTailnetItself reports whether app-tail is the tailnet client on this machine.
//
// The watch stands down entirely when it is. In that mode the routes for the tailnet's range are
// installed by app-tail's own engine from the netmap it holds, and putting one back from here
// would be a second writer for routes that already have one. It is also the one mode where no
// other client can be running: app-tail refuses to open its interface on a machine already
// carrying a tailnet.
func (a *Agent) carryingTailnetItself() bool {
	node := a.currentNode()
	if node == nil {
		return false
	}
	status := node.Status()
	return status.Running() && status.Network == config.NetworkTUN
}

// noteTailnetRouteTrouble records what went wrong, logging it only when it is not the same thing
// that went wrong last time.
//
// A round runs every minute and the faults it meets are the standing kind -- no helper
// installed, a route the machine will not accept -- so logging each one would bury everything
// else the agent has to say under the same sentence sixty times an hour.
func (a *Agent) noteTailnetRouteTrouble(problem string) {
	a.mu.Lock()
	repeat := a.tailnetRouteProblem == problem
	a.tailnetRouteProblem = problem
	a.mu.Unlock()
	if !repeat {
		a.logger.Warn("the route to the tailnet could not be looked at or put back", "problem", problem)
	}
}

// clearTailnetRouteTrouble forgets the last failure, so one that comes back is reported again
// rather than silenced by the round that recovered.
func (a *Agent) clearTailnetRouteTrouble() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tailnetRouteProblem = ""
}

// prefixList renders ranges for a log line.
func prefixList(prefixes []netip.Prefix) string {
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}
