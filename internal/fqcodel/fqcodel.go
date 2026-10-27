// SPDX-License-Identifier: MIT

// Package fqcodel is a packet queue that shares a slow link fairly and keeps its delay short.
//
// It exists for the one queue in this process that nothing else manages: the packets a
// connection's own network stack has produced and its WireGuard device has not yet
// encrypted. When the device keeps up, that queue is empty and this package is a hand-off.
// When it does not -- encryption is bound by the CPU, or the connection is carried inside
// another one and every packet has to travel that one's stack too -- a plain FIFO lets one
// bulk transfer fill the whole queue, and every other flow through the connection waits
// behind all of it: a thousand packets of a full-size download is a quarter of a second
// added to each keystroke over SSH.
//
// The machine's own kernel runs the same algorithm on its interfaces, but it sees only the
// encrypted outside of this connection, one flow, so it cannot tell the download from the
// keystroke. No mark can be set on the outside to tell it either: the device offers no
// per-packet metadata on its way to the socket. So the queue is here, where the packets are
// still readable.
//
// It is FQ-CoDel as Linux ships it, with the numbers that need no tuning: flows take turns a
// packet-size-worth at a time, a flow that has just started goes first, and a flow whose
// packets have waited over five milliseconds for a tenth of a second starts losing them, one
// at a time and more often the longer it stays over. Nothing here needs to know the link's
// speed; that is the point.
package fqcodel

import (
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"sync"
	"time"
)

// The defaults, from the CoDel RFC and the Linux implementation, which are the values that
// were shown to work on every link between a dial-up modem and a data centre.
const (
	DefaultCapacity = 1024
	DefaultTarget   = 5 * time.Millisecond
	DefaultInterval = 100 * time.Millisecond
)

// buckets is how many flow queues there are. Two flows that hash to the same bucket share a
// queue, which is what Linux does at the same size; the seed is per queue so which flows
// collide cannot be predicted from outside.
const buckets = 1024

// ErrClosed is what both ends get once Close has run.
var ErrClosed = errors.New("the packet queue is closed")

// MaxSize is the largest packet Enqueue takes: one whole IP packet. A size beyond it, or one
// under a byte, would break the byte accounting the turns and the drops are taken by.
const MaxSize = math.MaxUint16

// dropBatch bounds how many packets one full-queue admission discards from the fattest flow,
// so the scan over every bucket to find that flow is paid once per batch, not once per packet
// arriving at a queue that stays full.
const dropBatch = 64

// Options describe one queue. Every zero value but Quantum and Drop has a default.
type Options[T any] struct {
	// Capacity is the most packets the queue holds. At capacity a new packet is admitted
	// by dropping half the bytes of the flow holding the most, from its head.
	Capacity int
	// Quantum is how many bytes one flow may send before the next flow's turn: the link's
	// packet size, so that one full packet is one turn.
	Quantum int
	// Target is the queueing delay a flow may have without losing packets.
	Target time.Duration
	// Interval is how long a flow may stay over Target before its first loss.
	Interval time.Duration
	// Now is the clock; nil is time.Now. It is a seam for tests that drive the delay.
	Now func() time.Time
	// Drop receives every item the queue discards, exactly once: a CoDel drop, an
	// over-capacity drop, and everything still held when Close runs. It is called with the
	// queue's lock held, so it must be cheap and must not call back into the queue.
	Drop func(T)
}

// Stats is a snapshot of what the queue has done and is holding.
type Stats struct {
	Enqueued uint64
	Dequeued uint64
	// Dropped counts discards for delay and for capacity; it does not include what Close
	// drained.
	Dropped uint64
	// Backlog is how many packets are held now.
	Backlog int
	// ActiveFlows is how many flows have a packet held now.
	ActiveFlows int
	// PeakSojourn is the longest any dequeued packet waited. Dropped packets are counted,
	// not timed, and a packet that entered an empty queue is not timed either, so neither
	// raises it.
	PeakSojourn time.Duration
}

// none marks an empty list head or tail, and a slot or bucket that is on no list.
const none int32 = -1

// slot holds one queued packet. Slots are allocated once, at New, and threaded through the
// bucket queues and the free list by index, so a packet in flight costs no allocation.
type slot[T any] struct {
	item T
	size int
	// enqueued is when the packet arrived, or zero for a packet that arrived to an empty
	// queue. Reading the clock is most of what a hand-off costs, and a packet with nothing
	// ahead of it is about to leave: its wait is the consumer's, not the queue's. CoDel
	// treats an untimed packet as one that did not wait, which is what an empty queue means
	// to it anyway.
	enqueued time.Time
	next     int32
}

// lazyClock reads the clock at most once per dequeue, and only if a timed packet asks.
type lazyClock struct {
	read func() time.Time
	t    time.Time
	ok   bool
}

func (c *lazyClock) now() time.Time {
	if !c.ok {
		c.t, c.ok = c.read(), true
	}
	return c.t
}

// bucket is one flow queue with its CoDel state and its place in the round-robin.
type bucket struct {
	head, tail   int32
	backlogBytes int
	backlog      int
	deficit      int

	// CoDel, per RFC 8289: count is how many drops this dropping episode has made,
	// lastCount what the previous episode ended at, dropNext when the next drop is due, and
	// firstAbove when the delay first crossed Target (zero while it is under).
	count      uint32
	lastCount  uint32
	dropping   bool
	dropNext   time.Time
	firstAbove time.Time

	// The round-robin lists are threaded through the buckets by index. A bucket only ever
	// leaves a list from its head, so one link forward is enough.
	next int32
	list uint8
}

const (
	onNoList uint8 = iota
	onNewFlows
	onOldFlows
)

// flowList is one of the two round-robin lists: new flows, which have not yet had a turn,
// and old flows, which have.
type flowList struct {
	head, tail int32
}

// Queue is a flow-fair, delay-bounded packet queue with one consumer and any number of
// producers.
type Queue[T any] struct {
	opts Options[T]
	seed maphash.Seed

	mu       sync.Mutex
	notEmpty sync.Cond
	closed   bool

	slots    []slot[T]
	freeHead int32
	buckets  [buckets]bucket
	newFlows flowList
	oldFlows flowList

	backlog     int
	enqueued    uint64
	dequeued    uint64
	dropped     uint64
	peakSojourn time.Duration
}

// New builds a queue. It refuses one that could not run: a turn of zero bytes never ends,
// and a queue that drops packets with nowhere to put them would leak every one.
func New[T any](opts Options[T]) (*Queue[T], error) {
	if opts.Quantum <= 0 {
		return nil, fmt.Errorf("a packet queue needs a packet size to take turns by, not %d", opts.Quantum)
	}
	if opts.Drop == nil {
		return nil, errors.New("a packet queue needs somewhere to hand the packets it drops")
	}
	if opts.Capacity <= 0 {
		opts.Capacity = DefaultCapacity
	}
	if opts.Target <= 0 {
		opts.Target = DefaultTarget
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	q := &Queue[T]{
		opts:     opts,
		seed:     maphash.MakeSeed(),
		slots:    make([]slot[T], opts.Capacity),
		newFlows: flowList{head: none, tail: none},
		oldFlows: flowList{head: none, tail: none},
	}
	q.notEmpty.L = &q.mu
	for i := range q.slots {
		q.slots[i].next = int32(i + 1)
	}
	q.slots[len(q.slots)-1].next = none
	for i := range q.buckets {
		q.buckets[i] = bucket{head: none, tail: none, next: none}
	}
	return q, nil
}

// Enqueue queues one packet of the given size under its flow. It never blocks: at capacity
// it makes room by dropping from the fattest flow. It returns ErrClosed once the queue is
// closed, and an error for a size outside 1..MaxSize; on any error it has not taken the
// item -- the caller still owns it.
func (q *Queue[T]) Enqueue(flow Flow, size int, item T) error {
	if size <= 0 || size > MaxSize {
		return fmt.Errorf("a packet of %d bytes cannot be queued: sizes run 1 to %d", size, MaxSize)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrClosed
	}
	if q.backlog == len(q.slots) {
		q.dropFattest()
	}
	i := q.freeHead
	q.freeHead = q.slots[i].next
	s := &q.slots[i]
	s.item, s.size, s.next = item, size, none
	if q.backlog > 0 {
		s.enqueued = q.opts.Now()
	} else {
		s.enqueued = time.Time{}
	}

	bi := q.index(flow)
	b := &q.buckets[bi]
	if b.tail == none {
		b.head = i
	} else {
		q.slots[b.tail].next = i
	}
	b.tail = i
	b.backlogBytes += size
	b.backlog++
	if b.list == onNoList {
		b.deficit = q.opts.Quantum
		q.push(&q.newFlows, bi, onNewFlows)
	}

	q.backlog++
	q.enqueued++
	if q.backlog == 1 {
		q.notEmpty.Signal()
	}
	return nil
}

// Dequeue returns the next packet to send, waiting for one when nothing is queued. It
// returns ErrClosed once the queue is closed.
func (q *Queue[T]) Dequeue() (T, error) {
	var zero T
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.closed {
			return zero, ErrClosed
		}
		if q.backlog == 0 {
			q.notEmpty.Wait()
			continue
		}
		clock := lazyClock{read: q.opts.Now}

		var list *flowList
		var membership uint8
		if q.newFlows.head != none {
			list, membership = &q.newFlows, onNewFlows
		} else {
			list, membership = &q.oldFlows, onOldFlows
		}
		bi := list.head
		b := &q.buckets[bi]
		if b.deficit <= 0 {
			b.deficit += q.opts.Quantum
			q.removeHead(list)
			q.push(&q.oldFlows, bi, onOldFlows)
			continue
		}

		i := q.codelDequeue(b, &clock)
		if i == none {
			// This flow has nothing more to send. A new flow that ran dry while old ones wait
			// takes its place at the back of them; otherwise it leaves the round-robin.
			q.removeHead(list)
			if membership == onNewFlows && q.oldFlows.head != none {
				q.push(&q.oldFlows, bi, onOldFlows)
			}
			continue
		}
		s := &q.slots[i]
		b.deficit -= s.size
		item := s.item
		if !s.enqueued.IsZero() {
			if sojourn := clock.now().Sub(s.enqueued); sojourn > q.peakSojourn {
				q.peakSojourn = sojourn
			}
		}
		q.free(i)
		q.backlog--
		q.dequeued++
		return item, nil
	}
}

// Close discards every packet held through Drop and wakes a waiting Dequeue with ErrClosed.
// It is idempotent.
func (q *Queue[T]) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	for bi := range q.buckets {
		b := &q.buckets[bi]
		for b.head != none {
			i := q.pop(b)
			q.opts.Drop(q.slots[i].item)
			q.free(i)
		}
		b.list, b.next = onNoList, none
	}
	q.newFlows = flowList{head: none, tail: none}
	q.oldFlows = flowList{head: none, tail: none}
	q.backlog = 0
	q.notEmpty.Broadcast()
}

// Stats reports what the queue has done and holds.
func (q *Queue[T]) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	active := 0
	for i := range q.buckets {
		if q.buckets[i].backlog > 0 {
			active++
		}
	}
	return Stats{
		Enqueued:    q.enqueued,
		Dequeued:    q.dequeued,
		Dropped:     q.dropped,
		Backlog:     q.backlog,
		ActiveFlows: active,
		PeakSojourn: q.peakSojourn,
	}
}

// index is the bucket a flow lands in.
func (q *Queue[T]) index(flow Flow) int32 {
	return int32(maphash.Comparable(q.seed, flow) & (buckets - 1))
}

// codelDequeue takes the next packet off one flow, dropping ahead of it as CoDel says to.
// It returns the slot index, or none when the flow is empty. This is the dequeue procedure
// of RFC 8289 with one guard beside it: a flow holding no more than one packet-size of bytes
// behind its head is never dropped from, so the last packet of a flow always leaves. That
// guard is also why a pop after a drop always finds a packet: a drop was only allowed with
// more than a packet-size of bytes, so at least one packet, still behind.
func (q *Queue[T]) codelDequeue(b *bucket, clock *lazyClock) int32 {
	i := q.pop(b)
	if i == none {
		b.dropping = false
		return none
	}
	drop := q.shouldDrop(b, i, clock)
	if b.dropping {
		if !drop {
			b.dropping = false
			return i
		}
		now := clock.now()
		for !now.Before(b.dropNext) && b.dropping {
			q.dropSlot(i)
			b.count++
			i = q.pop(b)
			if !q.shouldDrop(b, i, clock) {
				b.dropping = false
			} else {
				b.dropNext = controlLaw(b.dropNext, q.opts.Interval, b.count)
			}
		}
		return i
	}
	if drop {
		now := clock.now()
		q.dropSlot(i)
		i = q.pop(b)
		b.dropping = true
		// A flow that leaves a dropping episode and comes straight back is still misbehaving:
		// its drop rate carries over instead of starting from one.
		delta := b.count - b.lastCount
		if delta > 1 && now.Sub(b.dropNext) < 16*q.opts.Interval {
			b.count = delta
		} else {
			b.count = 1
		}
		b.lastCount = b.count
		b.dropNext = controlLaw(now, q.opts.Interval, b.count)
	}
	return i
}

// shouldDrop is CoDel's judgement of one packet at the head of a flow: its delay has been
// over Target for a whole Interval, and the flow has more than a packet-size queued behind
// it.
func (q *Queue[T]) shouldDrop(b *bucket, i int32, clock *lazyClock) bool {
	enqueued := q.slots[i].enqueued
	if enqueued.IsZero() || b.backlogBytes <= q.opts.Quantum {
		b.firstAbove = time.Time{}
		return false
	}
	now := clock.now()
	if now.Sub(enqueued) < q.opts.Target {
		b.firstAbove = time.Time{}
		return false
	}
	if b.firstAbove.IsZero() {
		b.firstAbove = now.Add(q.opts.Interval)
		return false
	}
	return !now.Before(b.firstAbove)
}

// controlLaw is when the next drop is due: Interval divided by the square root of how many
// drops there have been, so a flow that stays over target loses packets steadily more often.
func controlLaw(t time.Time, interval time.Duration, count uint32) time.Time {
	return t.Add(time.Duration(float64(interval) / math.Sqrt(float64(count))))
}

// dropFattest makes room by discarding from the head of the flow holding the most bytes,
// which is the flow most responsible for the queue being full. It takes half of that flow's
// bytes, up to dropBatch packets, so a queue that stays full is not scanned for every
// arrival. Every packet has at least one byte, so the fattest flow of a full queue is never
// empty.
func (q *Queue[T]) dropFattest() {
	fattest := none
	most := 0
	for i := range q.buckets {
		if q.buckets[i].backlogBytes > most {
			fattest, most = int32(i), q.buckets[i].backlogBytes
		}
	}
	b := &q.buckets[fattest]
	half := most / 2
	freed := 0
	for n := 1; ; n++ {
		i := q.pop(b)
		freed += q.slots[i].size
		q.dropSlot(i)
		if n == dropBatch || freed >= half {
			return
		}
	}
}

// dropSlot hands one already-popped slot's item to Drop and frees the slot.
func (q *Queue[T]) dropSlot(i int32) {
	q.opts.Drop(q.slots[i].item)
	q.free(i)
	q.backlog--
	q.dropped++
}

// pop takes the head slot off a bucket's queue, or none.
func (q *Queue[T]) pop(b *bucket) int32 {
	i := b.head
	if i == none {
		return none
	}
	s := &q.slots[i]
	b.head = s.next
	if b.head == none {
		b.tail = none
	}
	b.backlogBytes -= s.size
	b.backlog--
	return i
}

// free returns a slot to the free list, dropping its reference to the item.
func (q *Queue[T]) free(i int32) {
	var zero T
	q.slots[i].item = zero
	q.slots[i].next = q.freeHead
	q.freeHead = i
}

// push appends a bucket to the tail of a round-robin list.
func (q *Queue[T]) push(l *flowList, i int32, membership uint8) {
	b := &q.buckets[i]
	b.next, b.list = none, membership
	if l.tail == none {
		l.head = i
	} else {
		q.buckets[l.tail].next = i
	}
	l.tail = i
}

// removeHead takes the first bucket off a round-robin list.
func (q *Queue[T]) removeHead(l *flowList) {
	b := &q.buckets[l.head]
	l.head = b.next
	if l.head == none {
		l.tail = none
	}
	b.next, b.list = none, onNoList
}
