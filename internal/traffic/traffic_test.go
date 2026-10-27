// SPDX-License-Identifier: MIT

package traffic

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// at builds a sample carrying only the two figures most of these tests care about.
func at(t time.Time, proxyUp, proxyDown int64) Sample {
	return Sample{At: t, ProxyUp: proxyUp, ProxyDown: proxyDown}
}

func TestTheRingKeepsWhatItWasGivenUntilItIsFull(t *testing.T) {
	r := NewRing(4)
	base := time.Unix(0, 0)
	for i := range 3 {
		r.Add(at(base.Add(time.Duration(i)*time.Second), int64(i), 0))
	}

	got := r.Samples()
	if len(got) != 3 || r.Len() != 3 {
		t.Fatalf("got %d samples (Len %d), want 3", len(got), r.Len())
	}
	for i, s := range got {
		if s.ProxyUp != int64(i) {
			t.Errorf("sample %d carries %d, want %d -- order was not preserved", i, s.ProxyUp, i)
		}
	}
}

// Once it wraps, the window has to read oldest-first from wherever the write head is.
// A ring that returned its raw backing array would draw a graph that jumps backwards in
// the middle, which reads as a traffic spike that never happened.
func TestTheRingReadsOldestFirstAfterItWraps(t *testing.T) {
	r := NewRing(4)
	base := time.Unix(0, 0)
	for i := range 7 {
		r.Add(at(base.Add(time.Duration(i)*time.Second), int64(i), 0))
	}

	got := r.Samples()
	if len(got) != 4 {
		t.Fatalf("got %d samples, want the window size of 4", len(got))
	}
	for i, want := range []int64{3, 4, 5, 6} {
		if got[i].ProxyUp != want {
			t.Errorf("sample %d carries %d, want %d", i, got[i].ProxyUp, want)
		}
	}
}

// A caller holds the returned slice while the sampler keeps writing on its own goroutine.
// Handing back the backing array would let a graph be redrawn from memory being mutated
// underneath it.
func TestSamplesAreACopy(t *testing.T) {
	r := NewRing(2)
	r.Add(at(time.Unix(0, 0), 1, 0))

	got := r.Samples()
	got[0].ProxyUp = 999
	if again := r.Samples(); again[0].ProxyUp != 1 {
		t.Errorf("the ring now reports %d; a caller mutated its storage", again[0].ProxyUp)
	}
}

// A zero-length ring would accept every sample and hold none, and the dashboard would
// show an empty graph with no error anywhere to explain it.
func TestARingIsNeverZeroLength(t *testing.T) {
	r := NewRing(0)
	r.Add(at(time.Unix(0, 0), 5, 0))

	if got := r.Samples(); len(got) != 1 {
		t.Fatalf("got %d samples, want 1", len(got))
	}
}

func TestRatesAreBytesPerSecondOverTheInterval(t *testing.T) {
	base := time.Unix(0, 0)
	points := Rates([]Sample{
		at(base, 0, 0),
		at(base.Add(time.Second), 1_000, 4_000),
		at(base.Add(2*time.Second), 1_500, 4_000),
	}, time.Second)

	if len(points) != 2 {
		t.Fatalf("got %d points from 3 samples, want 2", len(points))
	}
	if points[0].ProxyUp != 1_000 || points[0].ProxyDown != 4_000 {
		t.Errorf("first point up/down = %v/%v, want 1000/4000", points[0].ProxyUp, points[0].ProxyDown)
	}
	if points[1].ProxyUp != 500 {
		t.Errorf("second point up = %v, want 500", points[1].ProxyUp)
	}
}

// The interval is what the samples say it was, not what the sampler intended. A tick that
// landed late must not read as double the traffic.
func TestARateIsDividedByTheTimeThatActuallyPassed(t *testing.T) {
	base := time.Unix(0, 0)
	points := Rates([]Sample{
		at(base, 0, 0),
		at(base.Add(2*time.Second), 1_000, 0),
	}, time.Second)

	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if points[0].ProxyUp != 500 {
		t.Errorf("up = %v over two seconds, want 500 -- the elapsed time was ignored", points[0].ProxyUp)
	}
}

// A forward's counters are rebuilt whenever it is re-registered, which happens every time
// someone edits one. The series steps backwards, and the difference is not throughput --
// it would draw a downward spike larger than anything the machine has ever carried.
func TestACounterGoingBackwardsIsAResetRatherThanNegativeTraffic(t *testing.T) {
	base := time.Unix(0, 0)
	points := Rates([]Sample{
		{At: base, ForwardUp: 5_000},
		{At: base.Add(time.Second), ForwardUp: 12},
	}, time.Second)

	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if !points[0].Gap {
		t.Error("the reset was not marked as a gap, so a chart would draw straight through it")
	}
	if points[0].ForwardUp < 0 {
		t.Errorf("forwardUp = %v, want no negative rate", points[0].ForwardUp)
	}
}

// In interface mode nothing passes the proxy, a forward or the subnet router, so the
// tunnel counters are the only evidence the machine moved anything at all. A window that
// derives no rate from them reports a saturated uplink as idle.
func TestTheTunnelLaneIsRatedLikeTheOthers(t *testing.T) {
	base := time.Unix(0, 0)
	points := Rates([]Sample{
		{At: base, TunnelUp: 1_000, TunnelDown: 2_000},
		{At: base.Add(2 * time.Second), TunnelUp: 5_000, TunnelDown: 12_000},
	}, time.Second)

	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if points[0].Gap {
		t.Fatal("the interval was marked a gap, so the tunnel's traffic would not be drawn")
	}
	if points[0].TunnelUp != 2_000 || points[0].TunnelDown != 5_000 {
		t.Errorf("tunnel up/down = %v/%v over two seconds, want 2000/5000",
			points[0].TunnelUp, points[0].TunnelDown)
	}
}

// The tunnel lane is a sum across peers, so it steps backwards whenever a device leaves
// the network -- ordinary, and unrelated to the restart that makes the other counters
// reset. Treating it the same way would blank every lane in a window that was otherwise
// measured correctly, which is a worse reading than one quiet second on one lane.
func TestAPeerLeavingCostsOnlyTheTunnelLane(t *testing.T) {
	base := time.Unix(0, 0)
	points := Rates([]Sample{
		{At: base, TunnelUp: 900_000, ProxyUp: 1_000},
		{At: base.Add(time.Second), TunnelUp: 12, ProxyUp: 3_000},
	}, time.Second)

	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if points[0].Gap {
		t.Error("a peer leaving was treated as a reset of the whole series")
	}
	if points[0].ProxyUp != 2_000 {
		t.Errorf("proxyUp = %v, want 2000 -- the measured lanes were discarded", points[0].ProxyUp)
	}
	if points[0].TunnelUp != 0 {
		t.Errorf("tunnelUp = %v, want 0 rather than a spike off the reset", points[0].TunnelUp)
	}
}

// A laptop resumed from sleep produces two samples hours apart. Averaging the bytes
// across that draws a long flat rate that nobody experienced and that buries the real
// traffic either side of it.
func TestAnImplausiblyLongIntervalIsAGapRatherThanAnAverage(t *testing.T) {
	base := time.Unix(0, 0)
	points := Rates([]Sample{
		at(base, 0, 0),
		at(base.Add(time.Hour), 10_000_000, 0),
	}, time.Second)

	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if !points[0].Gap {
		t.Error("an hour-long interval was measured as if it were a sample")
	}
	if points[0].ProxyUp != 0 {
		t.Errorf("up = %v across a gap, want 0", points[0].ProxyUp)
	}
}

// Connections is a gauge, not a counter. It is true of the moment it was read and stays
// meaningful across an interval that could not be measured.
func TestConnectionsSurviveAGap(t *testing.T) {
	base := time.Unix(0, 0)
	points := Rates([]Sample{
		{At: base, ProxyUp: 5_000},
		{At: base.Add(time.Second), ProxyUp: 0, ProxyActive: 3, ForwardActive: 2},
	}, time.Second)

	if !points[0].Gap {
		t.Fatal("expected the reset to be a gap")
	}
	if points[0].Connections != 5 {
		t.Errorf("connections = %d across a gap, want 5", points[0].Connections)
	}
}

// A rate is a statement about the interval between two readings, so one reading brackets
// nothing. Returning a point for it would put a fabricated zero at the start of every
// freshly-started agent's graph.
func TestOneSampleYieldsNoRate(t *testing.T) {
	if got := Rates([]Sample{at(time.Unix(0, 0), 1, 1)}, time.Second); got != nil {
		t.Errorf("got %d points from a single sample, want none", len(got))
	}
}

// The headline figure must not be read off a gap: a machine that just resumed would be
// reported as idle when nothing has actually been measured yet.
func TestLatestSkipsGaps(t *testing.T) {
	points := []Point{
		{ProxyUp: 900},
		{Gap: true},
	}
	if got := Latest(points).ProxyUp; got != 900 {
		t.Errorf("latest up = %v, want the last measured 900", got)
	}
	if got := Latest([]Point{{Gap: true}}).ProxyUp; got != 0 {
		t.Errorf("latest up = %v with nothing measured, want 0", got)
	}
}

func TestTheSamplerRecordsOnItsTickAndStops(t *testing.T) {
	var reads atomic.Int64
	src := SourceFunc(func(context.Context) Sample {
		n := reads.Add(1)
		return Sample{At: time.Unix(n, 0), ProxyUp: n}
	})

	s := NewSampler(src, time.Millisecond, 200*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for s.Ring().Len() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s.Stop()
	wg.Wait()

	if got := s.Ring().Len(); got < 3 {
		t.Fatalf("the ring holds %d samples, want at least 3", got)
	}
	// Stopped means stopped: a sampler still running after Stop keeps a goroutine and a
	// ticker alive for the life of the process.
	after := reads.Load()
	time.Sleep(20 * time.Millisecond)
	if reads.Load() != after {
		t.Error("the source was read after the sampler was stopped")
	}
}

// A dashboard opened moments after the agent starts should have something to draw.
func TestTheSamplerReadsOnceImmediately(t *testing.T) {
	s := NewSampler(SourceFunc(func(context.Context) Sample { return Sample{At: time.Unix(1, 0)} }), time.Hour, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()

	deadline := time.Now().Add(time.Second)
	for s.Ring().Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if got := s.Ring().Len(); got != 1 {
		t.Errorf("the ring holds %d samples before the first tick, want 1", got)
	}
}

// Stop is reachable from any goroutine and from a shutdown path that may already have
// run; a second close would panic and take the agent's exit with it.
func TestStoppingTwiceIsHarmless(t *testing.T) {
	s := NewSampler(SourceFunc(func(context.Context) Sample { return Sample{} }), time.Second, time.Minute)
	s.Stop()
	s.Stop()
}
