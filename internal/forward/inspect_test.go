// SPDX-License-Identifier: MIT

package forward

// The inspector's seat on a port forward. The target is the one the user typed, so there is
// nothing to refuse before the connection is made; what is under test is that the bytes the
// forward carries are offered before they are written, and that a stop tears the connection
// down rather than forwarding it.

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// fakeInspector hands out one reader and keeps every flow it was asked about.
type fakeInspector struct {
	watch func(inspect.Flow) netpipe.Stream
	// open answers the pair a flow is carried between, nil in every test that does not
	// exercise opening one.
	open func(inspect.Flow, net.Conn, net.Conn) (net.Conn, net.Conn, error)

	mu   sync.Mutex
	seen []inspect.Flow
}

func (f *fakeInspector) Open(_ context.Context, flow inspect.Flow, client, upstream net.Conn) (net.Conn, net.Conn, error) {
	if f.open == nil {
		return client, upstream, nil
	}
	return f.open(flow, client, upstream)
}

func (f *fakeInspector) Watch(flow inspect.Flow) netpipe.Stream {
	f.mu.Lock()
	f.seen = append(f.seen, flow)
	f.mu.Unlock()
	if f.watch == nil {
		return nil
	}
	return f.watch(flow)
}

func (f *fakeInspector) flows() []inspect.Flow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]inspect.Flow(nil), f.seen...)
}

// stoppingStream stands in for the window: it stops the connection on the first chunk
// carrying a chosen word. The parsers are tested where they live.
type stoppingStream struct {
	stopOn string

	mu   sync.Mutex
	up   [][]byte
	shut int
}

func (s *stoppingStream) Up(b []byte) bool {
	s.mu.Lock()
	s.up = append(s.up, append([]byte(nil), b...))
	s.mu.Unlock()
	return s.stopOn != "" && strings.Contains(string(b), s.stopOn)
}

func (s *stoppingStream) Down([]byte) bool { return false }

func (s *stoppingStream) Close() {
	s.mu.Lock()
	s.shut++
	s.mu.Unlock()
}

func (s *stoppingStream) offered() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.up...)
}

func (s *stoppingStream) closes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shut
}

// recordingServer keeps every byte it was sent, which is the only place a claim about
// prevention can be checked: what the far side received.
type recordingServer struct {
	addr string

	mu  sync.Mutex
	got []byte
}

func newRecordingServer(t *testing.T) *recordingServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start a server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	server := &recordingServer{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						server.mu.Lock()
						server.got = append(server.got, buf[:n]...)
						server.mu.Unlock()
						if _, err := conn.Write(buf[:n]); err != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return server
}

func (s *recordingServer) received() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.got...)
}

// runningForward starts one forward pointed at target and returns the local address a client
// connects to.
func runningForward(t *testing.T, m *Manager, id, target string) string {
	t.Helper()
	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, id, port, target)})
	waitForStatus(t, m, id, "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// The whole claim on this path: a forward carries connections for names nobody typed here,
// and a connection stopped on what its opening bytes said never reaches the target.
func TestAForwardedConnectionStoppedOnItsOpeningBytesNeverReachesTheTarget(t *testing.T) {
	server := newRecordingServer(t)
	tn := newFakeTailnet()
	tn.route("gateway:443", server.addr)

	m := newTestManager(t, tn)
	stream := &stoppingStream{stopOn: "bad.example"}
	m.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream { return stream }})
	local := runningForward(t, m, "f_gate", "gateway:443")

	conn, err := net.DialTimeout("tcp", local, 3*time.Second)
	if err != nil {
		t.Fatalf("dial the forward: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello for bad.example, please connect")); err != nil {
		t.Fatalf("write the opening bytes: %v", err)
	}

	// The client must stop being able to read. A forward that inspected after the write would
	// echo the bytes straight back here.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	n, err := conn.Read(make([]byte, 64))
	if n != 0 {
		t.Fatalf("the client read %d bytes of a stopped connection", n)
	}
	if err == nil {
		t.Fatal("the client read a stopped connection without an error")
	}

	if got := server.received(); len(got) != 0 {
		t.Errorf("the target received %q of a stopped connection, want nothing", got)
	}
	if offered := stream.offered(); len(offered) != 1 {
		t.Errorf("the inspector was offered %d chunks, want the one it stopped on", len(offered))
	}
	// The window is let go however the connection ended, which is what keeps a stopped
	// connection from being the one shape that leaks one.
	waitForClose(t, stream)
}

// waitForClose waits for the window to be let go. The client learns the connection is gone
// the moment it is reset, and the copy that reset it releases the window as it returns, so
// the two are ordered but not simultaneous.
func waitForClose(t *testing.T, stream *stoppingStream) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		switch closed := stream.closes(); {
		case closed == 1:
			return
		case closed > 1:
			t.Fatalf("the inspector was closed %d times, want once", closed)
		case time.Now().After(deadline):
			t.Fatal("the inspector was never closed on a stopped connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The same path with nothing to stop, which is what every inspected forward that is not a
// match looks like: offered, then carried.
func TestAForwardedConnectionNothingStopsIsStillOfferedAndStillCarried(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("buildbox:22", echo)

	m := newTestManager(t, tn)
	stream := &stoppingStream{}
	m.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream { return stream }})
	local := runningForward(t, m, "f_ssh", "buildbox:22")

	const payload = "hello over the tailnet"
	if got := roundTripTCP(t, local, payload); got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}
	if offered := stream.offered(); len(offered) == 0 {
		t.Error("the inspector was offered nothing on a connection it was reading")
	}
}

// A connection that was going to be opened and could not be is stopped rather than carried. A
// forward that carried it anyway would hand the program the connection it asked for while
// nothing read a byte of it, which is the failure the whole seam exists to prevent.
func TestAForwardedConnectionThatCouldNotBeOpenedNeverReachesTheTarget(t *testing.T) {
	server := newRecordingServer(t)
	tn := newFakeTailnet()
	tn.route("gateway:443", server.addr)

	m := newTestManager(t, tn)
	// The refusal is held until the client's bytes are sent. Refusing straight away resets the
	// client the moment the forward accepts it, and that reset races the client's own dial and
	// write: the test would be reporting the reset it is here to ask for as a broken setup.
	wrote := make(chan struct{})
	m.SetInspector(&fakeInspector{
		open: func(inspect.Flow, net.Conn, net.Conn) (net.Conn, net.Conn, error) {
			<-wrote
			return nil, nil, errors.New("the real server's certificate did not verify")
		},
	})
	local := runningForward(t, m, "f_gate", "gateway:443")

	conn, err := net.DialTimeout("tcp", local, 3*time.Second)
	if err != nil {
		t.Fatalf("dial the forward: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello for the destination that could not be opened")); err != nil {
		t.Fatalf("write the opening bytes: %v", err)
	}
	close(wrote)

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	n, err := conn.Read(make([]byte, 64))
	if n != 0 {
		t.Fatalf("the client read %d bytes of a connection that was never opened", n)
	}
	if err == nil {
		t.Fatal("the client read a stopped connection without an error")
	}
	if got := server.received(); len(got) != 0 {
		t.Errorf("the target received %q of a connection that was never opened, want nothing", got)
	}
}

// Nothing set is the module switched off, and a forward with no inspector has to carry
// everything: reading an absent inspector as a refusal would take every forward down at once.
func TestAForwardWithNoInspectorCarriesEverything(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("buildbox:22", echo)

	m := newTestManager(t, tn)
	m.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream {
		return &stoppingStream{stopOn: "hello"}
	}})
	m.SetInspector(nil)
	local := runningForward(t, m, "f_ssh", "buildbox:22")

	const payload = "hello over the tailnet"
	if got := roundTripTCP(t, local, payload); got != payload {
		t.Fatalf("round trip returned %q with inspection off, want %q", got, payload)
	}
}

// The target a user typed as a name is offered as one. An entry written as a domain is what
// would match a forward pointed at a gateway, and offering only an address leaves every one
// of them unable to.
func TestAForwardOffersTheTargetTheUserTyped(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("buildbox:22", echo)

	m := newTestManager(t, tn)
	seen := &fakeInspector{}
	m.SetInspector(seen)
	local := runningForward(t, m, "f_ssh", "buildbox:22")

	const payload = "hello over the tailnet"
	if got := roundTripTCP(t, local, payload); got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}

	flows := seen.flows()
	if len(flows) != 1 {
		t.Fatalf("the inspector saw %d flows, want the one connection that was made", len(flows))
	}
	got := flows[0]
	if got.Name != "buildbox" {
		t.Errorf("flow name = %q, want the name the target was written as", got.Name)
	}
	if got.Port != 22 {
		t.Errorf("flow port = %d, want the port the forward targets", got.Port)
	}
	if got.Addr.IsValid() {
		t.Errorf("flow address = %s, want none: a target written as a name has no address here", got.Addr)
	}
	if got.Protocol != "tcp" || got.Where == "" {
		t.Errorf("flow = %+v, want it to say what was carried and where", got)
	}
}

// A target written as an address is offered as one, which is the other half of forwardFlow
// and the shape a rule naming a CIDR has to reach.
func TestAForwardTargetWrittenAsAnAddressIsOfferedAsOne(t *testing.T) {
	echo := startEchoTCP(t)
	host, port, err := net.SplitHostPort(echo)
	if err != nil {
		t.Fatalf("split the echo address: %v", err)
	}
	tn := newFakeTailnet()
	tn.route(echo, echo)

	m := newTestManager(t, tn)
	seen := &fakeInspector{}
	m.SetInspector(seen)
	local := runningForward(t, m, "f_addr", echo)

	const payload = "hello over the tailnet"
	if got := roundTripTCP(t, local, payload); got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}

	flows := seen.flows()
	if len(flows) != 1 {
		t.Fatalf("the inspector saw %d flows, want the one connection that was made", len(flows))
	}
	if flows[0].Addr.String() != host {
		t.Errorf("flow address = %s, want %s", flows[0].Addr, host)
	}
	if flows[0].Name != "" {
		t.Errorf("flow name = %q, want none: the target was written as an address", flows[0].Name)
	}
	wantPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatalf("parse the echo port: %v", err)
	}
	if uint64(flows[0].Port) != wantPort {
		t.Errorf("flow port = %d, want %d", flows[0].Port, wantPort)
	}
}

// A target that is not a host and a port is still offered, carrying only where it was: the
// alternative is a flow with a name made of whatever was typed, which would match somebody's
// list against a string that is not a name.
func TestAForwardTargetThatIsNotAHostAndAPortIsStillOffered(t *testing.T) {
	cases := []string{"buildbox", "", "[::1"}
	for _, target := range cases {
		flow := forwardFlow(config.Forward{Target: target})
		if flow.Where != "a port forward" {
			t.Errorf("a target of %q reads as coming from %q, want the port forward", target, flow.Where)
		}
		if flow.Name != "" || flow.Addr.IsValid() || flow.Port != 0 {
			t.Errorf("a target of %q was read as %+v, want nothing read out of it", target, flow)
		}
	}
}

// A port that is not a number leaves the port alone rather than carrying a wrong one, and the
// host beside it is still the thing a list would match.
func TestAForwardTargetWithAPortThatIsNotANumberStillCarriesItsHost(t *testing.T) {
	flow := forwardFlow(config.Forward{Target: "buildbox:ssh"})
	if flow.Name != "buildbox" {
		t.Errorf("flow name = %q, want the host beside the port", flow.Name)
	}
	if flow.Port != 0 {
		t.Errorf("flow port = %d, want none: the port was not a number", flow.Port)
	}
}
