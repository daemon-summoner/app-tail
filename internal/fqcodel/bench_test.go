// SPDX-License-Identifier: MIT

package fqcodel

import (
	"testing"
)

// The cost of one packet through the queue with nothing waiting, which is the common case,
// beside a plain channel doing the same hand-off: the difference is what fairness costs.

func BenchmarkEnqueueDequeue(b *testing.B) {
	b.Run("1flow", func(b *testing.B) { benchQueue(b, 1) })
	b.Run("64flows", func(b *testing.B) { benchQueue(b, 64) })
}

func benchQueue(b *testing.B, flows int) {
	q, err := New(Options[int]{Quantum: quantum, Drop: func(int) {}})
	if err != nil {
		b.Fatal(err)
	}
	defer q.Close()
	keys := make([]Flow, flows)
	for i := range keys {
		keys[i] = flowNamed("flow")
		keys[i].SrcPort = uint16(40000 + i)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if err := q.Enqueue(keys[i%flows], 1200, i); err != nil {
			b.Fatal(err)
		}
		if _, err := q.Dequeue(); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkChanBaseline(b *testing.B) {
	c := make(chan int, DefaultCapacity)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		c <- i
		<-c
		i++
	}
}
