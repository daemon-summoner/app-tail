// SPDX-License-Identifier: MIT

// Package traffic keeps a short rolling history of what the agent has carried.
//
// Every counter elsewhere in app-tail is a point-in-time total: the dashboard could say
// four gigabytes had crossed the proxy since it started, and nothing could say whether
// anything was moving right now. This holds a few minutes of those totals so a rate can
// be derived, and holds them here rather than in the browser because the dashboard stops
// polling whenever its tab is hidden -- a history kept there would go blank exactly when
// someone leaves the page open, and start empty again on every reload.
package traffic

import (
	"context"
	"sync"
	"time"
)

// Sample is every counter worth a graph, at one instant.
//
// The figures are cumulative, not rates. Storing what the counters actually said keeps
// the reader free to choose a window, keeps rounding from compounding across a series,
// and leaves a missed tick visible as a gap rather than smoothed into a plausible-looking
// average nobody measured.
type Sample struct {
	At time.Time `json:"at"`

	ProxyUp      int64 `json:"proxyUp"`
	ProxyDown    int64 `json:"proxyDown"`
	ProxyActive  int64 `json:"proxyActive"`
	ProxyOpened  int64 `json:"proxyOpened"`
	ProxyRefused int64 `json:"proxyRefused"`
	ProxyFailed  int64 `json:"proxyFailed"`

	ForwardUp     int64 `json:"forwardUp"`
	ForwardDown   int64 `json:"forwardDown"`
	ForwardActive int64 `json:"forwardActive"`

	RouteIn  int64 `json:"routeIn"`
	RouteOut int64 `json:"routeOut"`

	// TunnelUp and TunnelDown are what the tunnel itself carried, summed across peers.
	//
	// They are the only lane that sees traffic in interface mode, where packets leave
	// through the network interface without passing the proxy, a forward or the subnet
	// router -- the three the lanes above count. They overlap those lanes rather than
	// adding to them, so a reader takes the larger of the two figures and never the sum.
	TunnelUp   int64 `json:"tunnelUp"`
	TunnelDown int64 `json:"tunnelDown"`

	// Keyed is the same instant broken down by whatever a lane names -- a device, a
	// connection, a destination, a port.
	//
	// It is a map per lane because a source builds it once a tick and the sampler folds it
	// straight into columnar storage; nothing holds these maps past the tick that made them.
	// A lane the source cannot answer for is left out, which is what tells the sampler to
	// record its keys as absent rather than as idle.
	Keyed map[Lane]map[string]Row `json:"-"`
}

// Lane names one breakdown of the same history the flat fields above hold.
type Lane string

const (
	// LaneDevices is per tailnet device, counted by the tunnel itself.
	LaneDevices Lane = "devices"
	// LaneConnections is per VPN connection.
	LaneConnections Lane = "connections"
	// LaneDestinations is per host the traffic was addressed to.
	LaneDestinations Lane = "destinations"
	// LanePorts is per port and protocol.
	LanePorts Lane = "ports"
)

// Lanes is every breakdown, in the order the dashboard offers them: each is a finer cut of
// the one before it.
var Lanes = []Lane{LaneDevices, LaneConnections, LaneDestinations, LanePorts}

// maxKeys is how many keys one lane names before it starts folding the rest away.
//
// Ports and destinations are whatever programs on this machine ask for, so both sets are
// unbounded and attacker-adjacent: a browser pointed at the PAC file will name every host it
// visits. This is the same budget the proxy's own destination table keeps, for the same
// reason, and what it leaves out is reported rather than dropped silently.
const maxKeys = 64

// Source is what the sampler reads. It is an interface so this package can be tested
// against a stand-in with no tailnet, no proxy and no network.
//
// The context is the sampler's own, so a backend that has stopped answering cannot hold
// a sample open past the agent's shutdown.
type Source interface {
	Sample(ctx context.Context) Sample
}

// SourceFunc adapts a plain function to Source.
type SourceFunc func(ctx context.Context) Sample

func (f SourceFunc) Sample(ctx context.Context) Sample { return f(ctx) }

// Ring is a fixed-size window of samples, oldest first once it has wrapped.
type Ring struct {
	mu     sync.Mutex
	buf    []Sample
	next   int
	filled bool
}

// NewRing builds a ring holding at most size samples. A size below one is treated as one:
// a zero-length ring would silently record nothing.
func NewRing(size int) *Ring {
	if size < 1 {
		size = 1
	}
	return &Ring{buf: make([]Sample, size)}
}

// Add records one sample, overwriting the oldest once the window is full.
func (r *Ring) Add(s Sample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = s
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.filled = true
	}
}

// Samples is the window in order, oldest first. The slice is freshly built, so a caller
// may hold it while the sampler keeps writing.
func (r *Ring) Samples() []Sample {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.filled {
		out := make([]Sample, r.next)
		copy(out, r.buf[:r.next])
		return out
	}
	out := make([]Sample, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}

// Len is how many samples the window currently holds.
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.filled {
		return len(r.buf)
	}
	return r.next
}

// Sampler reads a Source on a fixed tick into a ring and its keyed lanes.
type Sampler struct {
	src      Source
	ring     *Ring
	lanes    map[Lane]*Table
	interval time.Duration
	done     chan struct{}
	stopOnce sync.Once
}

// NewSampler builds a sampler over its own ring, sized to hold window at interval.
func NewSampler(src Source, interval, window time.Duration) *Sampler {
	if interval <= 0 {
		interval = time.Second
	}
	size := int(window / interval)
	lanes := make(map[Lane]*Table, len(Lanes))
	for _, lane := range Lanes {
		lanes[lane] = NewTable(size, maxKeys)
	}
	return &Sampler{
		src:      src,
		ring:     NewRing(size),
		lanes:    lanes,
		interval: interval,
		done:     make(chan struct{}),
	}
}

// Ring is the window the sampler is filling.
func (s *Sampler) Ring() *Ring { return s.ring }

// Lane is one breakdown's window. Every lane named in Lanes has one, so a caller never has
// to handle a missing table for a lane the source happens not to answer for yet.
func (s *Sampler) Lane(lane Lane) *Table { return s.lanes[lane] }

// Record writes one sample into the ring and every keyed lane. It is what Run does on each
// of its own ticks, separated from the ticker so what a sample becomes can be exercised
// without waiting out an interval of real time.
//
// Every lane is advanced whether or not the sample carried anything for it, so a lane whose
// source has gone away records its keys as absent -- a gap the chart breaks its line at --
// rather than holding the last reading as though it were still being measured.
func (s *Sampler) Record(sample Sample) {
	s.ring.Add(sample)
	for lane, table := range s.lanes {
		table.Advance(sample.At)
		for key, row := range sample.Keyed[lane] {
			table.Set(key, row)
		}
	}
}

// Interval is the tick the samples were taken on.
func (s *Sampler) Interval() time.Duration { return s.interval }

// Run samples until the context ends or Stop is called. It takes one sample immediately,
// so a dashboard opened moments after the agent starts has something to draw rather than
// an empty box for the first tick.
func (s *Sampler) Run(ctx context.Context) {
	s.Record(s.src.Sample(ctx))

	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-tick.C:
			s.Record(s.src.Sample(ctx))
		}
	}
}

// Stop ends Run. It is safe to call more than once and from any goroutine.
func (s *Sampler) Stop() { s.stopOnce.Do(func() { close(s.done) }) }
