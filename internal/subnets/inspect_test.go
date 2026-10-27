// SPDX-License-Identifier: MIT

package subnets

// The inspector's seat on the inbound path: the one place in app-tail that knows which
// device asked for the connection it is about to carry.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// fakeInspector refuses every flow when told to, and keeps what it was asked about.
type fakeInspector struct {
	refuse bool
	seen   []inspect.Flow
	// watch answers what reads a carried flow's opening bytes, nil in the tests that only
	// exercise the refusal before anything is dialled.
	watch func(inspect.Flow) netpipe.Stream
	// open answers the pair a flow is carried between, nil in every test that does not
	// exercise opening one.
	open func(inspect.Flow, net.Conn, net.Conn) (net.Conn, net.Conn, error)
}

func (f *fakeInspector) Refuse(flow inspect.Flow) (string, bool) {
	f.seen = append(f.seen, flow)
	if !f.refuse {
		return "", false
	}
	return "the address is in 10.20.0.0/24, which is named by your own entries", true
}

func (f *fakeInspector) Watch(flow inspect.Flow) netpipe.Stream {
	if f.watch == nil {
		return nil
	}
	return f.watch(flow)
}

func (f *fakeInspector) Open(_ context.Context, flow inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error) {
	if f.open == nil {
		return client, upstream, nil
	}
	return f.open(flow, client, upstream)
}

func TestAnInspectedFlowIsRefusedAndCountedWithTheOnesTheRoutesRefuse(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)
	h.router.SetInspector(&fakeInspector{refuse: true})

	if _, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80")); ok {
		t.Fatal("a flow the inspector refused was carried")
	}
	if dialed := h.dials(); len(dialed) != 0 {
		t.Errorf("dialed %v, want nothing dialed for a refused flow", dialed)
	}

	st := h.router.Status()
	if st.Refused != 1 || st.Carried != 0 {
		t.Errorf("carried %d and refused %d, want the flow counted as refused", st.Carried, st.Refused)
	}
}

// The device that asked is what this seam has and no other one does. Without it a match
// here reads as "something reached that address", which is the answer a user already has.
func TestAnInspectedInboundFlowNamesTheDeviceThatAskedForIt(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)
	seen := &fakeInspector{}
	h.router.SetInspector(seen)

	h.carry(t, netip.MustParseAddrPort("10.20.0.7:80"), "hello from the tailnet")

	if len(seen.seen) != 1 {
		t.Fatalf("the inspector saw %d flows, want the one that was delivered", len(seen.seen))
	}
	flow := seen.seen[0]
	if flow.Addr != netip.MustParseAddr("10.20.0.7") {
		t.Errorf("flow address = %s, want the address on the routed network", flow.Addr)
	}
	if flow.Peer != "100.64.0.9" {
		t.Errorf("flow peer = %q, want the device the connection came from", flow.Peer)
	}
	if flow.Where == "" || flow.Protocol != "tcp" {
		t.Errorf("flow = %+v, want it to say what was carried and where", flow)
	}
	// This is the one path that knows both which device asked and which port it reached, so
	// it is the only one that can tell one device walking another's ports from many devices
	// each reaching one. A flow that dropped the port could not.
	if flow.Port != 80 {
		t.Errorf("flow port = %d, want the port the connection was bound for", flow.Port)
	}
}

// A flow that was going to be opened and could not be is stopped rather than carried. This is
// the inbound path, so the device on the other side is another machine on the tailnet: carrying
// the flow unread would tell it the connection succeeded and was inspected, and neither would be
// true.
func TestAnInboundFlowThatCouldNotBeOpenedIsStoppedRatherThanCarried(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)
	watch := &closingStream{}
	h.router.SetInspector(&fakeInspector{
		watch: func(inspect.Flow) netpipe.Stream { return watch },
		open: func(inspect.Flow, net.Conn, net.Conn) (net.Conn, net.Conn, error) {
			return nil, nil, errors.New("the real server's certificate did not verify")
		},
	})

	handle, ok := tn.deliver(t, netip.MustParseAddrPort("10.20.0.7:80"))
	if !ok {
		t.Fatal("the flow was refused before anything could be opened")
	}
	peer, far := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(far)
	}()

	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set the test connection's deadline: %v", err)
	}
	if _, err := peer.Read(make([]byte, 64)); err == nil {
		t.Fatal("the device read a stopped flow without an error")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the router never let go of a flow it could not open")
	}
	// The window goes back on this path too. It is the one path that never reaches the copy that
	// would otherwise return it, which is exactly why it is the one that can leak.
	if closed := watch.closes(); closed != 1 {
		t.Errorf("the window was let go %d times, want once", closed)
	}
}

// closingStream reads nothing and counts being let go, which is all the failed-open path can be
// asked about: it never reaches the copy that would offer it bytes.
type closingStream struct {
	mu     sync.Mutex
	closed int
}

func (s *closingStream) Up([]byte) bool   { return false }
func (s *closingStream) Down([]byte) bool { return false }

func (s *closingStream) Close() {
	s.mu.Lock()
	s.closed++
	s.mu.Unlock()
}

func (s *closingStream) closes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Nothing set is the module switched off, and the inbound path has to carry everything then
// -- a router that read an absent inspector as a refusal would stop every device that routes
// through this one.
func TestARouterWithNoInspectorCarriesEverything(t *testing.T) {
	tn := newFakeTailnet(mustPrefixes(t, "10.20.0.0/24")...)
	h := newHarness(t, tn, newSettings())
	h.apply(t)
	h.router.SetInspector(&fakeInspector{refuse: true})
	h.router.SetInspector(nil)

	got := h.carry(t, netip.MustParseAddrPort("10.20.0.7:80"), "hello from the tailnet")

	if got != "hello from the tailnet" {
		t.Errorf("the carried connection returned %q, want the bytes it sent back", got)
	}
	if st := h.router.Status(); st.Carried != 1 || st.Refused != 0 {
		t.Errorf("carried %d and refused %d, want the flow carried", st.Carried, st.Refused)
	}
}
