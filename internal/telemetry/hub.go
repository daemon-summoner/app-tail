// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// queueDepth is how many rows may be waiting for the drain goroutine. Sized for a
	// burst rather than for a backlog: the drain does no I/O in memory-only mode, so a
	// queue this deep is only ever reached by something recording far faster than the
	// scheduler runs the drain, and past that point the honest answer is to drop and
	// say so.
	queueDepth = 4096

	// eventRingSize is how many events memory holds. A thousand at roughly a hundred a
	// day is well over a week of ordinary running, and at forty bytes of pointers plus
	// two short strings apiece it costs a few hundred kilobytes.
	eventRingSize = 1000

	// maintenanceInterval is the tick that applies retention and reports drops. A minute
	// is short enough that a log cut short is admitted while the reader is still looking
	// at it, and long enough to cost nothing.
	maintenanceInterval = time.Minute

	// DefaultEventRetention is how long an event stays in the log with no setting saying
	// otherwise.
	DefaultEventRetention = 30 * 24 * time.Hour
)

// Config is what the hub is allowed to record. It is swapped whole rather than mutated
// field by field, so a reader always sees one coherent set of switches -- the pattern
// the DNS forwarder's own live-reconfigure uses.
type Config struct {
	// Enabled is the module switch. With it false the hub records nothing, holds
	// nothing, and answers every read with a reason rather than an empty list.
	Enabled bool
	// EventRetention is how long an event survives. Zero means DefaultEventRetention.
	EventRetention time.Duration
}

// retention resolves the configured window to the one actually applied.
func (c Config) retention() time.Duration {
	if c.EventRetention <= 0 {
		return DefaultEventRetention
	}
	return c.EventRetention
}

// Options builds a Hub. Every member has a working default, so a caller that wants the
// ordinary thing passes the zero value.
type Options struct {
	// Logger receives the faults the hub cannot report through itself -- a code that is
	// not in the catalog is a bug in the calling code, and recording it as data would
	// hide it in the very list it corrupted. Nil discards.
	Logger *slog.Logger
	// Now is the clock the rows are stamped from. It is a seam so a test can drive a
	// retention window without waiting one out; nil means time.Now.
	Now func() time.Time
	// Config is what the hub starts out allowed to record. The zero value records
	// nothing, which is what a fresh install wants.
	Config Config
}

// Hub is the one telemetry object every other package holds.
//
// The write side is a queue: Record methods hand a row over and return, and a single
// drain goroutine owns every ring. That is what makes the data path's cost a bounded
// channel send instead of a lock shared with whoever is reading the dashboard.
type Hub struct {
	logger *slog.Logger
	now    func() time.Time

	// cfg is swapped whole by SetConfig and read by every Record method. An atomic
	// pointer rather than a mutex because the read is on the data path and the write
	// happens when somebody saves a setting.
	cfg atomic.Pointer[Config]

	queue  chan Event
	events *ring[Event]

	// seq numbers events so two recorded inside one clock tick still have a total
	// order, which is what makes keyset pagination able to resume exactly.
	seq atomic.Uint64

	// dropped counts rows the queue could not take; reported counts the ones already
	// admitted to in an event. Only the drain goroutine touches reported.
	dropped  atomic.Uint64
	reported uint64

	// started guards Run against being entered twice, which would give two goroutines
	// the rings this design says exactly one owns.
	started atomic.Bool

	stopOnce sync.Once
	done     chan struct{}
	// drained closes when the drain goroutine has returned, so Stop can be a real
	// barrier for a test that wants to read what it just recorded.
	drained chan struct{}
}

// New builds a hub. It starts no goroutine: Run does that, and a hub that is never run
// still accepts and drops records rather than blocking a caller.
func New(opts Options) *Hub {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	h := &Hub{
		logger:  logger,
		now:     now,
		queue:   make(chan Event, queueDepth),
		events:  newRing[Event](eventRingSize),
		done:    make(chan struct{}),
		drained: make(chan struct{}),
	}
	cfg := opts.Config
	h.cfg.Store(&cfg)
	return h
}

// Config is what the hub is currently allowed to record.
func (h *Hub) Config() Config {
	if h == nil {
		return Config{}
	}
	return *h.cfg.Load()
}

// SetConfig swaps what the hub may record.
//
// Turning the module off clears what was recorded rather than freezing it. Recording is
// opt-in, so a switch that stopped collection but kept the collection would leave a user
// who opted out with a log they can still be asked for -- and the switch would not mean
// what its label says.
func (h *Hub) SetConfig(cfg Config) {
	if h == nil {
		return
	}
	was := h.cfg.Load().Enabled
	h.cfg.Store(&cfg)
	if was && !cfg.Enabled {
		h.events.keep(func(Event) bool { return false })
	}
}

// RecordEvent records one thing that happened. It is safe on a nil hub and from any
// goroutine, and it never blocks: a full queue drops the row and counts it, which the
// next maintenance tick reports as an event of its own.
//
// The code decides the category and the severity. A code outside the catalog is a bug in
// the caller rather than a fact about the machine, so it is logged and not recorded --
// putting it in the list would corrupt the list it was meant to describe.
func (h *Hub) RecordEvent(code EventCode, message string, fields map[string]string) {
	if h == nil {
		return
	}
	if !h.cfg.Load().Enabled {
		return
	}
	category, severity, ok := Classify(code)
	if !ok {
		h.logger.Error("telemetry: refusing an event whose code is not in the catalog",
			"code", string(code), "message", message)
		return
	}
	h.enqueue(Event{
		Seq:      h.seq.Add(1),
		At:       h.now(),
		Code:     code,
		Category: category,
		Severity: severity,
		Message:  message,
		Fields:   truncateFields(fields),
	})
}

// enqueue is the one non-blocking send. It is separate from RecordEvent so the hub's own
// maintenance can put a row in by the same route as everyone else.
func (h *Hub) enqueue(e Event) {
	select {
	case h.queue <- e:
	default:
		h.dropped.Add(1)
	}
}

// Run owns every ring until the context ends or Stop is called. Exactly one goroutine
// may run it; a second returns at once rather than racing the first for the rings.
func (h *Hub) Run(ctx context.Context) {
	if h == nil {
		return
	}
	if !h.started.CompareAndSwap(false, true) {
		select {
		case <-h.done:
			// Stop already claimed the rings, which it does when it finds nothing
			// running. Starting now would take back ownership of a hub that has
			// finished, so this returns quietly rather than as a fault.
		default:
			h.logger.Error("telemetry: Run called twice; the second call is doing nothing")
		}
		return
	}
	defer close(h.drained)

	tick := time.NewTicker(maintenanceInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			h.drain()
			return
		case <-h.done:
			h.drain()
			return
		case e := <-h.queue:
			h.store(e)
		case <-tick.C:
			h.maintain()
		}
	}
}

// Stop ends Run and waits for the queue to be drained, so a caller that recorded
// something can read it back. It is safe to call more than once and before Run.
//
// The ownership claim is the same compare-and-swap Run makes, and exactly one of them
// wins it. That is what makes Stop a barrier even when it races the goroutine that was
// only just told to start: waiting on a goroutine that has not entered Run yet would
// return at once and leave the queue full, and the caller would read back an empty log.
func (h *Hub) Stop() {
	if h == nil {
		return
	}
	h.stopOnce.Do(func() { close(h.done) })
	if h.started.CompareAndSwap(false, true) {
		// Nothing was running and, with done closed, nothing now will: draining here
		// is this goroutine holding the rings that Run never took.
		h.drain()
		close(h.drained)
		return
	}
	<-h.drained
}

// drain empties whatever is already queued. Anything recorded after this returns is
// dropped, which is the honest outcome for a row handed over after shutdown began.
func (h *Hub) drain() {
	for {
		select {
		case e := <-h.queue:
			h.store(e)
		default:
			return
		}
	}
}

// store puts one row in its ring. Only the drain goroutine calls it.
func (h *Hub) store(e Event) {
	h.events.add(e)
}

// maintain applies retention and admits to anything dropped since the last tick.
func (h *Hub) maintain() {
	cfg := h.cfg.Load()
	if !cfg.Enabled {
		return
	}

	cutoff := h.now().Add(-cfg.retention())
	if trimmed := h.events.keep(func(e Event) bool { return e.At.After(cutoff) }); trimmed > 0 {
		h.store(h.systemEvent(CodeTelemetryTrimmed,
			"Removed events older than the retention window.",
			map[string]string{
				"removed":   strconv.Itoa(trimmed),
				"olderThan": cutoff.Format(time.RFC3339),
			}))
	}

	// Recorded straight into the ring rather than through the queue: the queue being
	// full is the very condition being reported, so a report that queued behind it
	// could itself be the row that is dropped.
	if dropped := h.dropped.Load(); dropped > h.reported {
		missed := dropped - h.reported
		h.reported = dropped
		h.store(h.systemEvent(CodeTelemetryDropped,
			"Telemetry was recorded faster than it could be stored, so some rows were not kept.",
			map[string]string{"dropped": strconv.FormatUint(missed, 10)}))
	}
}

// systemEvent builds one of the hub's reports about itself, already classified.
func (h *Hub) systemEvent(code EventCode, message string, fields map[string]string) Event {
	category, severity, _ := Classify(code)
	return Event{
		Seq:      h.seq.Add(1),
		At:       h.now(),
		Code:     code,
		Category: category,
		Severity: severity,
		Message:  message,
		Fields:   truncateFields(fields),
	}
}

// Dropped is how many rows the queue has refused over this hub's life. It is reported
// alongside the log so a reader can see the gap rather than infer it.
func (h *Hub) Dropped() uint64 {
	if h == nil {
		return 0
	}
	return h.dropped.Load()
}
