// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// statusCounter answers every status request and counts how many actually reached the
// backend, which is the only thing the cache is for.
func statusCounter(body string) (roundTripperFunc, *atomic.Int64) {
	var calls atomic.Int64
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/status") {
			calls.Add(1)
			return jsonResponse(body), nil
		}
		return jsonResponse(`{}`), nil
	})
	return rt, &calls
}

// A peer key is 64 hex characters; the value itself is never asserted on, but the JSON
// has to parse as one or the backend reply is rejected before the cache is reached.
const peerKeyHex = "nodekey:" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var oneOnlinePeer = `{"Peer":{"` + peerKeyHex + `":` +
	`{"ID":"n1","HostName":"nas","Online":true,"RxBytes":10}}}`

// One dashboard poll asks for peers through several views at once -- the routes view
// alone asks twice, and DNS asks again. Each of those is a full netmap walk in the
// backend, under the lock that also serves the packet path, so answering them all from
// one fetch is the difference between one such walk per poll and four.
func TestTheFullStatusIsFetchedOncePerWindow(t *testing.T) {
	rt, calls := statusCounter(oneOnlinePeer)
	n := requireStubbedNode(t, rt)

	for range 4 {
		if _, err := n.fullStatus(context.Background()); err != nil {
			t.Fatalf("fullStatus: %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("the backend was asked %d times for one window, want 1", got)
	}
}

// The cache is a window, not a memo: a dashboard that kept showing the first answer it
// ever got would report a peer as online long after it went away.
func TestTheFullStatusIsRefetchedOnceTheWindowPasses(t *testing.T) {
	rt, calls := statusCounter(oneOnlinePeer)
	n := requireStubbedNode(t, rt)

	now := time.Now()
	n.clock = func() time.Time { return now }

	if _, err := n.fullStatus(context.Background()); err != nil {
		t.Fatalf("first fullStatus: %v", err)
	}
	now = now.Add(fullStatusTTL)
	if _, err := n.fullStatus(context.Background()); err != nil {
		t.Fatalf("second fullStatus: %v", err)
	}

	if got := calls.Load(); got != 2 {
		t.Errorf("the backend was asked %d times across two windows, want 2", got)
	}
}

// Serving the last good answer when the backend has stopped answering would report a
// tailnet that is gone as present, and the caller could not tell. A failure is a failure.
func TestAFailedFetchIsReportedRatherThanServedFromTheLastGoodOne(t *testing.T) {
	var fail atomic.Bool
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.URL.Path, "/status") {
			return jsonResponse(`{}`), nil
		}
		if fail.Load() {
			return errorResponse(http.StatusInternalServerError, "the backend is gone"), nil
		}
		return jsonResponse(oneOnlinePeer), nil
	})
	n := requireStubbedNode(t, rt)

	now := time.Now()
	n.clock = func() time.Time { return now }

	if _, err := n.fullStatus(context.Background()); err != nil {
		t.Fatalf("first fullStatus: %v", err)
	}
	fail.Store(true)
	now = now.Add(fullStatusTTL)

	st, err := n.fullStatus(context.Background())
	if err == nil {
		t.Fatalf("fullStatus succeeded with a dead backend, returning %+v", st)
	}
	if st != nil {
		t.Error("a status was returned alongside the error, which a caller would read as live")
	}
}

// Every view that needs peers runs on its own HTTP goroutine, so they arrive together.
// Without the lock the cache would be written by several at once and the counter above
// would be meaningless.
func TestConcurrentCallersShareOneFetch(t *testing.T) {
	rt, calls := statusCounter(oneOnlinePeer)
	n := requireStubbedNode(t, rt)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := n.fullStatus(context.Background()); err != nil {
				t.Errorf("fullStatus: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("the backend was asked %d times by eight concurrent callers, want 1", got)
	}
}

// Peers is the caller that made the fetch worth caching, and it has to keep working
// through it rather than merely not crashing.
func TestPeersReadsThroughTheCache(t *testing.T) {
	rt, calls := statusCounter(oneOnlinePeer)
	n := requireStubbedNode(t, rt)

	first, err := n.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	second, err := n.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers again: %v", err)
	}

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("got %d then %d peers, want 1 each", len(first), len(second))
	}
	if first[0].RxBytes != 10 {
		t.Errorf("rxBytes = %d, want the figure the backend reported", first[0].RxBytes)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("two Peers calls cost %d backend fetches, want 1", got)
	}
}
