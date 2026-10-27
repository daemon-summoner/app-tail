// SPDX-License-Identifier: MIT

package forward

import (
	"sync"
	"sync/atomic"
)

// Forward run states reported to the UI.
const (
	StateRunning = "running"
	StateStopped = "stopped"
	StateError   = "error"
)

// Status is a point-in-time snapshot of one forward's health and counters.
type Status struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	ActiveTCP int    `json:"activeTcp"`
	ActiveUDP int    `json:"activeUdp"`
	BytesUp   int64  `json:"bytesUp"`
	BytesDown int64  `json:"bytesDown"`
	// Listening is the address the forward actually bound, useful when the
	// tailnet IP is only known at runtime.
	Listening string `json:"listening,omitempty"`
}

// counters holds a forward's live metrics. Byte and connection counts are updated
// from proxy goroutines on every transfer, so they are atomic; the string fields
// change rarely and are guarded by a mutex.
type counters struct {
	activeTCP atomic.Int32
	activeUDP atomic.Int32
	bytesUp   atomic.Int64
	bytesDown atomic.Int64

	mu        sync.Mutex
	state     string
	errMsg    string
	listening string
}

func newCounters() *counters {
	return &counters{state: StateStopped}
}

func (c *counters) setRunning(listening string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateRunning
	c.errMsg = ""
	c.listening = listening
}

func (c *counters) setStopped() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateStopped
	c.errMsg = ""
	c.listening = ""
}

// setError records a failure. The forward stays visible in the UI with its reason
// rather than disappearing or failing silently.
func (c *counters) setError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateError
	if err != nil {
		c.errMsg = err.Error()
	}
}

// noteError records a failure that did not stop the forward, such as one datagram
// that could not be delivered. The forward keeps running.
func (c *counters) noteError(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errMsg = err.Error()
}

// noteSuccess clears a transient error once a connection succeeds, so a target that
// recovers stops showing a stale failure. It never disturbs a hard error state,
// which only a stop or restart resolves.
func (c *counters) noteSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == StateRunning {
		c.errMsg = ""
	}
}

func (c *counters) snapshot(id string) Status {
	c.mu.Lock()
	state, errMsg, listening := c.state, c.errMsg, c.listening
	c.mu.Unlock()
	return Status{
		ID:        id,
		State:     state,
		Error:     errMsg,
		ActiveTCP: int(c.activeTCP.Load()),
		ActiveUDP: int(c.activeUDP.Load()),
		BytesUp:   c.bytesUp.Load(),
		BytesDown: c.bytesDown.Load(),
		Listening: listening,
	}
}
