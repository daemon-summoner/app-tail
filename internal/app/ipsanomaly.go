// SPDX-License-Identifier: MIT

package app

// The runner's half of the second signal. The ledger and the detectors are pure and live in
// internal/inspect; what is here is the clock, the switch, and the sweep that turns what the
// ledger holds into the same findings the card already shows.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/telemetry"
)

// ipsSweepInterval is how often the ledger is read.
//
// It is a third of the ledger's window, so a run of connections is looked at while it is
// still whole rather than after most of it has aged out. Nothing is on the data path here:
// the cost of a round is one pass over a bounded ring, and a round that finds nothing does
// nothing at all.
const ipsSweepInterval = 20 * time.Second

// watchFor turns the flow ledger on or off. Off drops it, which is what makes turning the
// switch off mean the record of where traffic went is gone rather than merely unread.
func (r *ipsRunner) watchFor(on bool) {
	held := r.watch.Load()
	switch {
	case on && held == nil:
		r.watch.Store(inspect.NewWatch(inspect.Limits{}))
	case !on && held != nil:
		// Emptied as well as dropped: the sweep may be holding this same pointer for the
		// round it is in, and a round that finishes after the switch moved must not report
		// what the switch was turned off to stop recording.
		r.watch.Store(nil)
		held.Reset()
	}
}

// question records one name this machine's resolver was asked about. It is the seam the DNS
// forwarder calls, and it is separate from Refuse because a question is not a connection:
// most names asked about are never connected to, and the ones that are arrive here first.
func (r *ipsRunner) question(name string) {
	if r == nil {
		return
	}
	if until := r.pausedUntil.Load(); until != 0 && r.now().UnixNano() < until {
		return
	}
	r.watch.Load().Question(name, r.now())
}

// noteQuestion is the seam the machine-wide resolver hands every name to. It is a method on
// the agent rather than the runner handed over directly because the resolver outlives a node
// rebuild and the runner is looked up per query, so neither has to know the other's lifetime.
func (a *Agent) noteQuestion(name string) { a.currentIPS().question(name) }

// sweep reads the ledger and records what it found. It reports how many findings there were
// so a caller can say whether the round did anything.
//
// A paused inspector sweeps nothing: a pause is asked for because inspection is producing
// something the user does not want, and a sweep that kept reporting through it would be the
// one part of the feature the pause did not reach.
func (r *ipsRunner) sweep(now time.Time) int {
	if until := r.pausedUntil.Load(); until != 0 && now.UnixNano() < until {
		return 0
	}
	watch := r.watch.Load()
	if watch == nil {
		return 0
	}

	found := watch.Sweep(now)
	for _, a := range found {
		r.noteAnomaly(a, now)
	}
	return len(found)
}

// beacons reads the destinations something keeps going back to on a rhythm.
//
// It is read straight off the ledger on the way to the card rather than swept: a rhythm is
// never a finding, so there is nothing to record, nothing to count and nothing to raise. A
// machine with the watch off has no ledger and answers nothing.
func (r *ipsRunner) beacons(now time.Time) []inspect.Beacon {
	if r == nil {
		return nil
	}
	return r.watch.Load().Beacons(now)
}

// noteAnomaly writes one finding to the ring the card reads and to the log.
//
// Refused is false and stays false while nothing acts on these: a finding is about a run of
// connections that has already happened, so there is nothing left to refuse, and reporting
// it as refused would say a connection was stopped that was not.
func (r *ipsRunner) noteAnomaly(a inspect.Anomaly, now time.Time) {
	r.push(Detection{
		At:     now,
		Signal: string(a.Signal),
		Value:  a.Value,
		Source: a.Source(),
		Reason: a.Reason(),
		Where:  ipsAnomalyWhere(a.Signal),
		Peer:   a.Peer,
	})
	r.anomalies.Add(1)

	r.record(telemetry.CodeIPSAnomaly, fmt.Sprintf("%s.", capitalise(a.Reason())), map[string]string{
		"signal": string(a.Signal),
		"value":  a.Value,
		"source": a.Source(),
		"count":  strconv.Itoa(a.Count),
		"over":   a.Until.Sub(a.Since).Round(time.Second).String(),
	})
}

// ipsAnomalyWhere is the column the card shows beside a finding, which for a rule match is
// the path that carried the connection. A run of connections was not carried anywhere in
// particular, so this says where it was seen instead.
func ipsAnomalyWhere(signal inspect.Signal) string {
	if signal == inspect.SignalDNSTunnel {
		return "this machine's resolver"
	}
	return "the traffic app-tail carried"
}

// capitalise starts a sentence, because the reasons are written to be read mid-sentence on
// the card and standing alone in the log.
func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// runIPSAnomaly reads the ledger for the life of the agent.
//
// Like the blocklist loop it runs whether or not the switch is on and reads the switch on
// each round, rather than being started and stopped as the setting moves: a loop a setting
// starts is a loop a setting has to stop, and the paths that forget leave either a detector
// that quietly stopped or two of them reporting everything twice. A round with the switch
// off costs one nil load.
func (a *Agent) runIPSAnomaly(ctx context.Context) { a.sweepEvery(ctx, ipsSweepInterval) }

// sweepEvery is the loop itself, with how often it reads the ledger passed in rather than
// taken from the constant, so a caller can drive a round without waiting one out.
func (a *Agent) sweepEvery(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		a.currentIPS().sweep(a.now())
	}
}
