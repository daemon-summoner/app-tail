// SPDX-License-Identifier: MIT

package fqcodel

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source, so a test decides how long a packet has waited.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// packet is what the tests queue: a flow name and a sequence number, enough to see which
// flow a dequeued packet came from and whether its order held.
type packet struct {
	flow string
	seq  int
}

const quantum = 1420

// testQueue builds a queue that counts what it drops.
func testQueue(t *testing.T, c *clock, capacity int) (*Queue[packet], *[]packet) {
	t.Helper()
	var dropped []packet
	q, err := New(Options[packet]{
		Capacity: capacity,
		Quantum:  quantum,
		Now:      c.Now,
		Drop:     func(p packet) { dropped = append(dropped, p) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return q, &dropped
}

func flowNamed(name string) Flow {
	var f Flow
	f.Proto = 17
	copy(f.Src[:], name)
	f.SrcPort = 40000
	f.DstPort = 53
	return f
}

func enqueue(t *testing.T, q *Queue[packet], flow string, seq, size int) {
	t.Helper()
	if err := q.Enqueue(flowNamed(flow), size, packet{flow, seq}); err != nil {
		t.Fatalf("enqueue %s/%d: %v", flow, seq, err)
	}
}

func dequeue(t *testing.T, q *Queue[packet]) packet {
	t.Helper()
	p, err := q.Dequeue()
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	return p
}

func TestASparseFlowIsNotStuckBehindABulkOne(t *testing.T) {
	t.Run("bulk flow already had its turn", func(t *testing.T) {
		q, _ := testQueue(t, newClock(), 1024)
		for i := range 500 {
			enqueue(t, q, "bulk", i, quantum)
		}
		for range 3 {
			if p := dequeue(t, q); p.flow != "bulk" {
				t.Fatalf("got %+v before the sparse flow existed", p)
			}
		}
		enqueue(t, q, "sparse", 0, 100)
		if p := dequeue(t, q); p.flow != "sparse" {
			t.Fatalf("the sparse flow's packet waited behind bulk: got %+v", p)
		}
	})
	t.Run("both flows fresh", func(t *testing.T) {
		q, _ := testQueue(t, newClock(), 1024)
		for i := range 500 {
			enqueue(t, q, "bulk", i, quantum)
		}
		enqueue(t, q, "sparse", 0, 100)
		first, second := dequeue(t, q), dequeue(t, q)
		if first.flow != "bulk" || second.flow != "sparse" {
			t.Fatalf("expected one bulk packet then the sparse one, got %+v then %+v", first, second)
		}
	})
}

func TestPacketsOfOneFlowLeaveInTheOrderTheyArrived(t *testing.T) {
	q, _ := testQueue(t, newClock(), 1024)
	for i := range 50 {
		enqueue(t, q, "a", i, 100)
		enqueue(t, q, "b", i, 100)
	}
	last := map[string]int{"a": -1, "b": -1}
	for range 100 {
		p := dequeue(t, q)
		if p.seq != last[p.flow]+1 {
			t.Fatalf("flow %s: packet %d came after %d", p.flow, p.seq, last[p.flow])
		}
		last[p.flow] = p.seq
	}
}

func TestNothingIsDroppedWhileDelayStaysUnderTarget(t *testing.T) {
	c := newClock()
	q, dropped := testQueue(t, c, 1024)
	for i := range 1000 {
		enqueue(t, q, "a", i, quantum)
		// Three packets stay queued and the queue moves one a millisecond, so every packet
		// waits three milliseconds: under Target, for the whole run.
		c.Advance(time.Millisecond)
		if i >= 2 {
			dequeue(t, q)
		}
	}
	if len(*dropped) != 0 || q.Stats().Dropped != 0 {
		t.Fatalf("dropped %d packets while delay was under target", len(*dropped))
	}
}

func TestCoDelDropsOnceDelayExceedsTargetForAnInterval(t *testing.T) {
	c := newClock()
	q, dropped := testQueue(t, c, 1024)
	for i := range 50 {
		enqueue(t, q, "a", i, quantum)
	}
	// The first packet arrived to an empty queue and is not timed; it leaves at once.
	dequeue(t, q)
	c.Advance(200 * time.Millisecond)
	dequeue(t, q)
	if len(*dropped) != 0 {
		t.Fatalf("dropped on the first packet over target; CoDel waits an interval first")
	}
	c.Advance(110 * time.Millisecond)
	dequeue(t, q)
	if len(*dropped) == 0 {
		t.Fatal("no drop after the delay stayed over target for more than an interval")
	}
	if (*dropped)[0].seq != 2 {
		t.Fatalf("the dropped packet was %+v, not the head of the flow", (*dropped)[0])
	}

	// Keeping the clock still, the next drops come at Interval/sqrt(count): each nearer than
	// the last. Advance by the first spacing and expect one, then by less and expect more.
	drops := func() int { return len(*dropped) }
	before := drops()
	c.Advance(100 * time.Millisecond)
	dequeue(t, q)
	afterOne := drops()
	if afterOne <= before {
		t.Fatalf("no drop after another full interval: %d -> %d", before, afterOne)
	}
	c.Advance(100 * time.Millisecond)
	dequeue(t, q)
	afterTwo := drops()
	if afterTwo-afterOne < afterOne-before {
		t.Fatalf("drops did not come more often as the flow stayed over target: %d, %d, %d", before, afterOne, afterTwo)
	}
	if got := q.Stats().Dropped; got != uint64(len(*dropped)) {
		t.Fatalf("Stats.Dropped=%d, Drop was called %d times", got, len(*dropped))
	}
}

// A dropping episode ends when the flow's head is no longer over target, or the flow is down
// to its last packet-size of bytes. A flow that comes straight back over target starts its
// next episode at the drop rate the last one reached, not from one drop per interval.
func TestAFlowThatComesStraightBackIsDroppedAtItsPreviousRate(t *testing.T) {
	c := newClock()
	q, dropped := testQueue(t, c, 1024)
	for i := range 11 {
		enqueue(t, q, "a", i, quantum)
	}
	dequeue(t, q) // untimed
	c.Advance(200 * time.Millisecond)
	dequeue(t, q) // arms CoDel
	c.Advance(110 * time.Millisecond)
	// Over target for an interval: 2 goes, the episode opens at one drop per interval.
	if p := dequeue(t, q); p.seq != 3 {
		t.Fatalf("got %+v, want 3 after the first drop", p)
	}
	dequeue(t, q) // 4, before the next drop is due
	c.Advance(100 * time.Millisecond)
	if p := dequeue(t, q); p.seq != 6 {
		t.Fatalf("got %+v, want 6 after the second drop", p)
	}
	c.Advance(100 * time.Millisecond)
	if p := dequeue(t, q); p.seq != 8 {
		t.Fatalf("got %+v, want 8 after the third drop", p)
	}
	// Two packets left: one packet-size behind the head ends the episode without a drop.
	if p := dequeue(t, q); p.seq != 9 {
		t.Fatalf("got %+v, want 9 spared as the flow ran down", p)
	}
	dequeue(t, q) // 10
	if len(*dropped) != 3 {
		t.Fatalf("dropped %+v, want exactly 2, 5 and 7 in the first episode", *dropped)
	}

	// The flow is back at once with a fresh burst. It earns its next drop after an interval
	// as before, but that episode opens at the rate the last one ended at: the drop after
	// it comes at Interval/sqrt(2), about 71ms, rather than a whole interval later.
	for i := 11; i < 18; i++ {
		enqueue(t, q, "a", i, quantum)
	}
	dequeue(t, q) // 11, untimed
	c.Advance(200 * time.Millisecond)
	dequeue(t, q) // 12, arms CoDel again
	c.Advance(110 * time.Millisecond)
	if p := dequeue(t, q); p.seq != 14 {
		t.Fatalf("got %+v, want 14 after 13 opened the second episode", p)
	}
	c.Advance(80 * time.Millisecond)
	if p := dequeue(t, q); p.seq != 16 {
		t.Fatalf("got %+v, want 16: the carried-over rate is due before a whole interval", p)
	}
	if p := dequeue(t, q); p.seq != 17 {
		t.Fatalf("got %+v, want the last packet", p)
	}
	want := []int{2, 5, 7, 13, 15}
	if len(*dropped) != len(want) {
		t.Fatalf("dropped %+v, want %v", *dropped, want)
	}
	for i, seq := range want {
		if (*dropped)[i].seq != seq {
			t.Fatalf("dropped %+v, want %v", *dropped, want)
		}
	}
}

func TestNewFillsInTheDefaults(t *testing.T) {
	var dropped int
	q, err := New(Options[int]{Quantum: quantum, Drop: func(int) { dropped++ }})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for i := range DefaultCapacity {
		if err := q.Enqueue(flowNamed("a"), quantum, i); err != nil {
			t.Fatal(err)
		}
	}
	if dropped != 0 {
		t.Fatalf("%d dropped before the default capacity was reached", dropped)
	}
	if err := q.Enqueue(flowNamed("b"), quantum, DefaultCapacity); err != nil {
		t.Fatal(err)
	}
	if dropped == 0 {
		t.Fatal("nothing dropped past the default capacity")
	}
	// The default clock is the real one: packets stamped by it are dequeued and judged.
	for range 2 {
		if _, err := q.Dequeue(); err != nil {
			t.Fatal(err)
		}
	}
	if s := q.Stats(); s.Dequeued != 2 || s.Backlog != DefaultCapacity+1-dropped-2 {
		t.Fatalf("stats after two dequeues with %d dropped: %+v", dropped, s)
	}
}

func TestTheLastPacketOfAFlowIsNeverDropped(t *testing.T) {
	c := newClock()
	q, dropped := testQueue(t, c, 1024)
	enqueue(t, q, "a", 0, quantum)
	c.Advance(10 * time.Second)
	if p := dequeue(t, q); p.seq != 0 {
		t.Fatalf("got %+v", p)
	}
	if len(*dropped) != 0 {
		t.Fatal("a flow's only packet was dropped")
	}
	// Two small packets are still within one quantum of bytes: neither is dropped either.
	enqueue(t, q, "b", 0, 100)
	enqueue(t, q, "b", 1, 100)
	c.Advance(10 * time.Second)
	dequeue(t, q)
	dequeue(t, q)
	if len(*dropped) != 0 {
		t.Fatal("a flow holding under one packet-size of bytes was dropped from")
	}

	// A flow that has earned a drop is still spared once only one packet-size of bytes is left
	// behind its head. Four full packets: the first is untimed, the second arms CoDel after
	// 200ms over target, and the third comes up for judgement past the interval with exactly
	// one quantum behind it.
	for i := range 4 {
		enqueue(t, q, "c", i, quantum)
	}
	dequeue(t, q)
	c.Advance(200 * time.Millisecond)
	dequeue(t, q)
	c.Advance(110 * time.Millisecond)
	if p := dequeue(t, q); p.seq != 2 {
		t.Fatalf("got %+v, want the third packet returned rather than dropped", p)
	}
	if p := dequeue(t, q); p.seq != 3 {
		t.Fatalf("got %+v, want the last packet", p)
	}
	if len(*dropped) != 0 {
		t.Fatalf("dropped %+v from a flow down to its last packet-size of bytes", *dropped)
	}
}

func TestEnqueueRefusesAPacketOfImpossibleSize(t *testing.T) {
	q, dropped := testQueue(t, newClock(), 8)
	for _, size := range []int{0, -1, MaxSize + 1} {
		if err := q.Enqueue(flowNamed("a"), size, packet{"a", size}); err == nil {
			t.Fatalf("a packet of %d bytes was queued", size)
		}
	}
	if s := q.Stats(); s.Enqueued != 0 || s.Backlog != 0 || len(*dropped) != 0 {
		t.Fatalf("a refused packet left a trace: %+v, dropped %+v", s, *dropped)
	}
	enqueue(t, q, "a", 0, MaxSize)
	if p := dequeue(t, q); p.seq != 0 {
		t.Fatalf("got %+v", p)
	}
}

func TestAFullQueueDropsHalfTheFattestFlowToAdmitANewcomer(t *testing.T) {
	q, dropped := testQueue(t, newClock(), 8)
	for i := range 7 {
		enqueue(t, q, "fat", i, quantum)
	}
	enqueue(t, q, "thin", 0, 100)
	if s := q.Stats(); s.Backlog != 8 {
		t.Fatalf("backlog %d before the queue was full", s.Backlog)
	}

	returned := make(chan error, 1)
	go func() { returned <- q.Enqueue(flowNamed("new"), 100, packet{"new", 0}) }()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked on a full queue")
	}

	// Seven full packets: half their bytes is three and a half, so four go, from the head.
	want := []packet{{"fat", 0}, {"fat", 1}, {"fat", 2}, {"fat", 3}}
	if len(*dropped) != len(want) {
		t.Fatalf("dropped %+v, wanted the first half of the fat flow %+v", *dropped, want)
	}
	for i, p := range want {
		if (*dropped)[i] != p {
			t.Fatalf("dropped %+v, wanted the first half of the fat flow %+v", *dropped, want)
		}
	}
	s := q.Stats()
	if s.Backlog != 5 || s.Dropped != 4 || s.Enqueued != 9 {
		t.Fatalf("stats after admission: %+v", s)
	}
	seen := map[string]int{}
	for range 5 {
		seen[dequeue(t, q).flow]++
	}
	if seen["new"] != 1 || seen["thin"] != 1 || seen["fat"] != 3 {
		t.Fatalf("queue held %v after admission", seen)
	}
}

// A full queue whose fattest flow is one packet still admits the newcomer: that one packet
// goes, whatever its size.
func TestAFullQueueOfSinglePacketFlowsStillAdmitsANewcomer(t *testing.T) {
	q, dropped := testQueue(t, newClock(), 4)
	for i := range 4 {
		enqueue(t, q, string(rune('a'+i)), 0, 1)
	}
	enqueue(t, q, "new", 0, 1)
	if len(*dropped) != 1 {
		t.Fatalf("dropped %+v, wanted exactly one packet to make room", *dropped)
	}
	if s := q.Stats(); s.Backlog != 4 || s.Dropped != 1 {
		t.Fatalf("stats after admission: %+v", s)
	}
}

func TestCloseUnblocksDequeueAndDropsEveryQueuedItemOnce(t *testing.T) {
	q, dropped := testQueue(t, newClock(), 1024)
	for i := range 10 {
		enqueue(t, q, "a", i, 100)
		enqueue(t, q, "b", i, 100)
	}
	dequeue(t, q)
	q.Close()
	if len(*dropped) != 19 {
		t.Fatalf("Close handed %d items to Drop, 19 were queued", len(*dropped))
	}
	seen := map[packet]int{}
	for _, p := range *dropped {
		seen[p]++
		if seen[p] > 1 {
			t.Fatalf("%+v was dropped twice", p)
		}
	}
	if _, err := q.Dequeue(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Dequeue after Close: %v", err)
	}
	if err := q.Enqueue(flowNamed("a"), 100, packet{"a", 99}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Enqueue after Close: %v", err)
	}
	if len(*dropped) != 19 {
		t.Fatal("an item refused by Enqueue was handed to Drop; the caller still owned it")
	}
	q.Close()
	if len(*dropped) != 19 || q.Stats().Backlog != 0 {
		t.Fatal("a second Close was not a no-op")
	}
}

func TestCloseWakesABlockedDequeue(t *testing.T) {
	q, _ := testQueue(t, newClock(), 1024)
	got := make(chan error, 1)
	go func() {
		_, err := q.Dequeue()
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	q.Close()
	select {
	case err := <-got:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("blocked Dequeue returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake the blocked Dequeue")
	}
}

func TestDequeueOnAnEmptyQueueParksAndWakesOnEnqueue(t *testing.T) {
	q, _ := testQueue(t, newClock(), 1024)
	got := make(chan packet, 1)
	go func() {
		p, err := q.Dequeue()
		if err != nil {
			t.Error(err)
			return
		}
		got <- p
	}()
	select {
	case p := <-got:
		t.Fatalf("Dequeue returned %+v from an empty queue", p)
	case <-time.After(50 * time.Millisecond):
	}
	enqueue(t, q, "a", 7, 100)
	select {
	case p := <-got:
		if p.seq != 7 {
			t.Fatalf("got %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue did not wake the parked Dequeue")
	}
}

func TestStatsReportBacklogActiveFlowsAndPeakSojourn(t *testing.T) {
	c := newClock()
	q, _ := testQueue(t, c, 1024)
	if s := q.Stats(); s != (Stats{}) {
		t.Fatalf("a new queue reports %+v", s)
	}
	enqueue(t, q, "a", 0, 100)
	enqueue(t, q, "a", 1, 100)
	enqueue(t, q, "b", 0, 100)
	s := q.Stats()
	if s.Backlog != 3 || s.ActiveFlows != 2 || s.Enqueued != 3 {
		t.Fatalf("after three enqueues: %+v", s)
	}
	c.Advance(3 * time.Millisecond)
	// The first packet arrived to an empty queue, so its wait is not the queue's to report.
	dequeue(t, q)
	s = q.Stats()
	if s.Backlog != 2 || s.Dequeued != 1 || s.PeakSojourn != 0 {
		t.Fatalf("after dequeuing the untimed first packet: %+v", s)
	}
	dequeue(t, q)
	s = q.Stats()
	if s.Backlog != 1 || s.Dequeued != 2 || s.PeakSojourn != 3*time.Millisecond {
		t.Fatalf("after dequeuing a timed packet: %+v", s)
	}
	dequeue(t, q)
	if s := q.Stats(); s.Backlog != 0 || s.ActiveFlows != 0 {
		t.Fatalf("after draining: %+v", s)
	}
}

func TestNewRefusesAQueueThatCannotWork(t *testing.T) {
	if _, err := New(Options[packet]{Quantum: 0, Drop: func(packet) {}}); err == nil {
		t.Fatal("a zero quantum was accepted")
	}
	if _, err := New(Options[packet]{Quantum: quantum}); err == nil {
		t.Fatal("a nil Drop was accepted")
	}
}

func TestManyProducersAndOneConsumerUnderRace(t *testing.T) {
	q, _ := testQueue(t, newClock(), 64)
	const producers, each = 8, 500
	var wg sync.WaitGroup
	for p := range producers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := string(rune('a' + p))
			for i := range each {
				if err := q.Enqueue(flowNamed(name), 100, packet{name, i}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := q.Dequeue(); err != nil {
				return
			}
		}
	}()
	wg.Wait()
	q.Close()
	<-done
	s := q.Stats()
	if s.Enqueued != producers*each || s.Dequeued+s.Dropped > s.Enqueued {
		t.Fatalf("accounting does not add up: %+v", s)
	}
}
