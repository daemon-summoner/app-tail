// SPDX-License-Identifier: MIT

package tsnode

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
)

// roundTripperFunc answers backend requests from the test rather than from a socket.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// newStubbedClient builds a local.Client that answers from rt and never contacts a real
// tailscaled. OmitAuth is set so no platform token is read either: on macOS the client
// otherwise reads the running daemon's auth token, and a test must not be able to reach
// -- let alone log out -- the developer's own node.
func newStubbedClient(rt roundTripperFunc) *local.Client {
	return &local.Client{Transport: rt, OmitAuth: true}
}

// jsonResponse is a successful backend reply carrying body.
func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

// errorResponse is the shape the backend uses to refuse a call: a non-2xx status whose
// body is the plain-text reason. local.Client folds that body into the returned error,
// which is what makes a failure legible in the dashboard rather than just "500".
func errorResponse(status int, reason string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(reason))),
	}
}

// withClient installs lc as the node's backend client, the way Start does once the
// tsnet server is up. Tailnet operations report ErrNotRunning until this happens, so a
// test of the error-wrapping paths has to get past that guard first.
func withClient(n *Node, lc *local.Client) {
	n.mu.Lock()
	n.lc = lc
	n.mu.Unlock()
}

// cancellableBus unblocks Next when the watcher's context ends, the way the real bus
// does. scriptedBus only unblocks on its own Close, so it cannot be used to observe a
// Close that must first wait for its watcher to finish.
//
// Build it from the same context the watcher is given. A bus parked on any other
// context is never released by the cancellation the watcher acts on, and the caller
// waiting for the watcher deadlocks for the package's whole timeout.
type cancellableBus struct {
	ctx      context.Context
	closed   chan struct{}
	closeOne sync.Once
	// entered closes when Next first parks, so a test can be sure the watcher is
	// actually blocked on the bus before it does the thing it means to observe.
	entered   chan struct{}
	enterOnce sync.Once
	hold      chan struct{}
	holdOnce  sync.Once
}

// holdAfterCancel keeps Next inside the bus after the context ends, until the returned
// release is called. It is what makes a caller's wait for the watcher observable: a
// watcher that exits the instant it is cancelled leaves a caller that skipped the wait
// indistinguishable from one that performed it. Call it before starting the watcher.
func (b *cancellableBus) holdAfterCancel() (release func()) {
	b.hold = make(chan struct{})
	return func() { b.holdOnce.Do(func() { close(b.hold) }) }
}

func newCancellableBus(ctx context.Context) *cancellableBus {
	return &cancellableBus{ctx: ctx, closed: make(chan struct{}), entered: make(chan struct{})}
}

func (b *cancellableBus) Next() (ipn.Notify, error) {
	b.enterOnce.Do(func() { close(b.entered) })
	select {
	case <-b.ctx.Done():
		if b.hold != nil {
			<-b.hold
		}
		return ipn.Notify{}, b.ctx.Err()
	case <-b.closed:
		return ipn.Notify{}, io.EOF
	}
}

func (b *cancellableBus) Close() error {
	b.closeOne.Do(func() { close(b.closed) })
	return nil
}

var _ busWatcher = (*cancellableBus)(nil)

// requireStubbedNode returns a node whose backend client answers from rt. It exists so
// the tests below read as assertions about error wrapping rather than as client setup.
func requireStubbedNode(t *testing.T, rt roundTripperFunc) *Node {
	t.Helper()
	n := newTestNode(t, AuthInteractive, newScriptedBus(), nil)
	withClient(n, newStubbedClient(rt))
	return n
}

// noContentResponse is how the backend acknowledges a command it accepted: 204 with no
// body. local.Client treats any other status as a refusal and folds the body into the
// error, so a stub answering 200 would make an accepted command look failed.
func noContentResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}
}
