// SPDX-License-Identifier: MIT

package traffic

import "time"

// Point is one interval's worth of movement, derived from the pair of samples that
// bracket it.
//
// Rates are bytes per second over that interval rather than raw deltas, so a series
// stays comparable across a tick the sampler missed. Gauges are carried through as the
// later sample read them, because "how many connections are open" has no rate.
type Point struct {
	At time.Time `json:"at"`

	ProxyUp   float64 `json:"proxyUp"`
	ProxyDown float64 `json:"proxyDown"`

	ForwardUp   float64 `json:"forwardUp"`
	ForwardDown float64 `json:"forwardDown"`

	RouteIn  float64 `json:"routeIn"`
	RouteOut float64 `json:"routeOut"`

	TunnelUp   float64 `json:"tunnelUp"`
	TunnelDown float64 `json:"tunnelDown"`

	// Connections is every open connection the agent is carrying, proxy and forwards
	// together: the number someone means when they ask what is going on right now.
	Connections int64 `json:"connections"`

	// Gap marks an interval whose rate could not be measured -- the counters went
	// backwards, or the interval was implausibly long. Its rates are zero, and a chart
	// must break the line rather than draw a floor it did not observe.
	Gap bool `json:"gap,omitempty"`
}

// maxGapFactor is how much longer than the sampling interval a gap may run before the
// interval is treated as unmeasured. A process suspended with the laptop lid closed
// resumes with two samples hours apart; averaging the bytes across that would draw a
// long flat rate nobody experienced.
const maxGapFactor = 4

// Rates turns a window of cumulative samples into per-interval movement.
//
// It returns one fewer point than it was given samples, because a rate is a statement
// about the interval between two readings and a single reading brackets nothing.
func Rates(samples []Sample, interval time.Duration) []Point {
	if len(samples) < 2 {
		return nil
	}
	out := make([]Point, 0, len(samples)-1)
	for i := 1; i < len(samples); i++ {
		out = append(out, rateBetween(samples[i-1], samples[i], interval))
	}
	return out
}

func rateBetween(prev, cur Sample, interval time.Duration) Point {
	p := Point{
		At: cur.At,
		// Gauges, not counters: they are whatever the later reading said, and they are
		// meaningful even across a gap.
		Connections: cur.ProxyActive + cur.ForwardActive,
	}

	elapsed := cur.At.Sub(prev.At)
	if elapsed <= 0 || elapsed > time.Duration(maxGapFactor)*interval {
		p.Gap = true
		return p
	}

	secs := elapsed.Seconds()
	up, upOK := perSecond(prev.ProxyUp, cur.ProxyUp, secs)
	down, downOK := perSecond(prev.ProxyDown, cur.ProxyDown, secs)
	fup, fupOK := perSecond(prev.ForwardUp, cur.ForwardUp, secs)
	fdown, fdownOK := perSecond(prev.ForwardDown, cur.ForwardDown, secs)
	rin, rinOK := perSecond(prev.RouteIn, cur.RouteIn, secs)
	rout, routOK := perSecond(prev.RouteOut, cur.RouteOut, secs)

	// One counter going backwards means something restarted underneath the series, and
	// the whole interval is suspect rather than just that lane.
	if !upOK || !downOK || !fupOK || !fdownOK || !rinOK || !routOK {
		p.Gap = true
		return p
	}

	p.ProxyUp, p.ProxyDown = up, down
	p.ForwardUp, p.ForwardDown = fup, fdown
	p.RouteIn, p.RouteOut = rin, rout

	// The tunnel lane is a sum across peers, so it drops whenever a device leaves the
	// network -- ordinary, and nothing to do with the restart the rule above is about.
	// Its reset costs this one lane one interval instead of blanking every lane in a
	// window that was otherwise measured correctly.
	if tup, ok := perSecond(prev.TunnelUp, cur.TunnelUp, secs); ok {
		p.TunnelUp = tup
	}
	if tdown, ok := perSecond(prev.TunnelDown, cur.TunnelDown, secs); ok {
		p.TunnelDown = tdown
	}
	return p
}

// perSecond is the movement between two readings of one cumulative counter.
//
// A counter that went backwards did not measure negative throughput -- it was reset. A
// forward's counters are rebuilt whenever it is re-registered, so this happens in normal
// use every time someone edits one. Reporting the difference would draw a downward spike
// larger than any traffic the machine has ever carried.
func perSecond(prev, cur int64, secs float64) (float64, bool) {
	if cur < prev {
		return 0, false
	}
	return float64(cur-prev) / secs, true
}

// Latest is the most recent measured point, or the zero value when the window holds
// nothing measurable yet. A gap is skipped rather than reported as an idle machine.
func Latest(points []Point) Point {
	for i := len(points) - 1; i >= 0; i-- {
		if !points[i].Gap {
			return points[i]
		}
	}
	return Point{}
}
