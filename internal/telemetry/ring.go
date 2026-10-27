// SPDX-License-Identifier: MIT

package telemetry

import "sync"

// ring is a fixed-size window of rows, oldest first once it has wrapped.
//
// It is the memory floor every log in this package sits on: with persistence off it is
// the whole store, and with persistence on it is still what answers a read while the
// last second of writes is in flight. Bounded by count rather than by age because the
// cost that has to be bounded is memory, and an age bound on a busy machine is not one.
type ring[T any] struct {
	mu     sync.Mutex
	buf    []T
	next   int
	filled bool
	// added counts every row ever written, including the ones overwritten. It is what
	// lets a reader tell "nothing has happened" from "the window has moved past it".
	added uint64
}

// newRing builds a ring holding at most size rows. A size below one is treated as one:
// a zero-length ring would silently record nothing while reporting success.
func newRing[T any](size int) *ring[T] {
	if size < 1 {
		size = 1
	}
	return &ring[T]{buf: make([]T, size)}
}

// add records one row, overwriting the oldest once the window is full.
func (r *ring[T]) add(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.filled = true
	}
	r.added++
}

// all returns the window in order, oldest first. The slice is freshly built, so a caller
// may hold it while writers keep going.
func (r *ring[T]) all() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.filled {
		out := make([]T, r.next)
		copy(out, r.buf[:r.next])
		return out
	}
	out := make([]T, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}

// stats is how many rows the window has ever taken -- including the ones it has since
// overwritten -- and how many it can hold. How many it holds right now comes from all(),
// which the caller needs anyway to report the oldest row.
func (r *ring[T]) stats() (added uint64, capacity int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.added, len(r.buf)
}

// keep drops every row the predicate rejects, preserving order. It is how retention is
// applied: the caller decides what "too old" means, since only it knows the clock the
// rows were stamped from.
func (r *ring[T]) keep(alive func(T) bool) (dropped int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var rows []T
	if r.filled {
		rows = make([]T, 0, len(r.buf))
		rows = append(rows, r.buf[r.next:]...)
		rows = append(rows, r.buf[:r.next]...)
	} else {
		rows = make([]T, r.next)
		copy(rows, r.buf[:r.next])
	}

	kept := rows[:0]
	for _, row := range rows {
		if alive(row) {
			kept = append(kept, row)
		}
	}
	dropped = len(rows) - len(kept)
	if dropped == 0 {
		return 0
	}

	// Rewritten from the start rather than compacted in place: the ring's own zero
	// value is the empty state, and rebuilding it is what keeps a dropped row's memory
	// from being held by a slot nothing will overwrite until the window wraps again.
	var zero T
	for i := range r.buf {
		r.buf[i] = zero
	}
	copy(r.buf, kept)
	r.next = len(kept) % len(r.buf)
	r.filled = len(kept) == len(r.buf)
	return dropped
}
