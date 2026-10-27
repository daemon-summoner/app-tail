// SPDX-License-Identifier: MIT

package fabric

// The inspector's seat on the interface: every flow the interface claims, decided before a
// connection is dialled and before the carrier carrying it is even looked up.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// fakeInspector refuses the addresses a test names and keeps every flow it was asked about.
type fakeInspector struct {
	refuse map[string]string
	// watch answers what reads a carried flow's opening bytes, and datagrams what reads a
	// carried datagram flow. Both are nil in the tests that only exercise the refusal before
	// anything is dialled.
	watch     func(inspect.Flow) netpipe.Stream
	datagrams func(inspect.Flow) netpipe.Stream
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
	if f.watch == nil {
		return nil
	}
	return f.watch(flow)
}

func (f *fakeInspector) WatchDatagrams(flow inspect.Flow) netpipe.Stream {
	if f.datagrams == nil {
		return nil
	}
	return f.datagrams(flow)
}

func (f *fakeInspector) Refuse(flow inspect.Flow) (string, bool) {
	f.mu.Lock()
	f.seen = append(f.seen, flow)
	f.mu.Unlock()
	reason, ok := f.refuse[flow.Addr.String()]
	return reason, ok
}

func (f *fakeInspector) flows() []inspect.Flow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]inspect.Flow(nil), f.seen...)
}

// A refusal here is the whole of prevention on this path: the flow is turned away before the
// carrier is dialled, so no byte of it reaches the network it was bound for.
func TestAnInspectedFlowIsRefusedBeforeAnythingIsDialled(t *testing.T) {
	carrier := &recordingCarrier{to: echoServer(t, "first")}
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")})
	f, m := fabricUnder(t, table, carrierSet{"tn_first": carrier}, nil)
	f.SetInspector(&fakeInspector{refuse: map[string]string{
		"93.184.216.34": "the address is in 93.184.216.0/24, which is named by your own entries",
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("93.184.216.34:443")); err == nil {
		conn.Close()
		t.Fatal("a flow the inspector refused was carried")
	}

	if asked := carrier.asks(); len(asked) != 0 {
		t.Errorf("the connection was asked to dial %v, want a refusal before anything is dialled", asked)
	}
	if refused := f.Status("wire").Counters["tn_first"].Refused; refused == 0 {
		t.Error("the refusal was not counted against the connection it was for")
	}
}

// The reason has to survive to the log line and the dashboard: a refusal that reads as an
// address nothing carries sends the reader to the routing table instead of to the entry
// they typed.
func TestARefusedFlowSaysWhichRuleRefusedIt(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")})
	f, _ := fabricUnder(t, table, carrierSet{"tn_first": &recordingCarrier{to: echoServer(t, "first")}}, nil)
	f.SetInspector(&fakeInspector{refuse: map[string]string{
		"93.184.216.34": "the address is in 93.184.216.0/24, which is named by your own entries",
	}})

	dest, carrier, err := f.destinationOf(netip.MustParseAddrPort("93.184.216.34:443"), "tcp")

	if err == nil {
		t.Fatal("an inspected address was given a way out")
	}
	if carrier != nil {
		t.Error("a carrier was returned for a flow that is meant to be refused")
	}
	// The destination comes back with the refusal so the counter lands on the connection the
	// flow was for rather than on none.
	if dest.TunnelID != "tn_first" {
		t.Errorf("the refusal names connection %q, want the one the table chose", dest.TunnelID)
	}
	if !strings.Contains(err.Error(), "your own entries") {
		t.Errorf("the reason is %q, which does not carry what the inspector said", err)
	}
}

// The interface never has a name -- what arrived is packets addressed to an address -- and
// both protocols reach the same seam, so the flow has to say which one it was.
func TestTheInterfaceOffersTheAddressAndTheProtocolItCarried(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("10.0.0.0/8")})
	f, m := fabricUnder(t, table, carrierSet{"tn_first": &recordingCarrier{to: echoServer(t, "first")}}, nil)
	seen := &fakeInspector{}
	f.SetInspector(seen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("10.1.2.3:443"))
	if err != nil {
		t.Fatalf("dial 10.1.2.3:443: %v", err)
	}
	conn.Close()

	flows := seen.flows()
	if len(flows) != 1 {
		t.Fatalf("the inspector saw %d flows, want the one connection that was made", len(flows))
	}
	got := flows[0]
	if got.Addr != netip.MustParseAddr("10.1.2.3") {
		t.Errorf("flow address = %s, want the address the flow was bound for", got.Addr)
	}
	if got.Name != "" {
		t.Errorf("flow name = %q, want none: the interface only ever sees an address", got.Name)
	}
	if got.Protocol != "tcp" || got.Where == "" {
		t.Errorf("flow = %+v, want it to say what was carried and where", got)
	}
	// The interface carries every connection this machine makes, which makes it the path a
	// scan run from here goes over. A flow that dropped the port would leave all of them
	// looking like one.
	if got.Port != 443 {
		t.Errorf("flow port = %d, want the port the connection was bound for", got.Port)
	}
}

// stoppingStream stands in for the window: it stops the flow on the first chunk carrying a
// chosen word, and records everything it was offered. The parsers are tested where they live;
// what is under test here is that the interface offers the bytes at all, and that a stop tears
// the flow down instead of forwarding it.
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

// recordingServer accepts connections and keeps every byte it was sent, which is the only
// place a claim about prevention can be checked: what the far side received.
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

// The whole claim of reading the opening bytes: a connection the interface carried, dialled at
// an address with no name attached to it, is stopped on what it said -- and the bytes it said
// it with never reach the network it was bound for.
func TestAFlowStoppedOnItsOpeningBytesNeverReachesTheNetwork(t *testing.T) {
	server := newRecordingServer(t)
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")})
	f, m := fabricUnder(t, table, carrierSet{"tn_first": &recordingCarrier{to: server.addr}}, nil)

	stream := &stoppingStream{stopOn: "bad.example"}
	f.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream { return stream }})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello for bad.example, please connect")); err != nil {
		t.Fatalf("write the opening bytes: %v", err)
	}

	// The local end must stop being able to read. An implementation that inspected after the
	// write would echo the bytes straight back here.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	n, err := conn.Read(make([]byte, 64))
	if n != 0 {
		t.Fatalf("the local end read %d bytes of a stopped connection", n)
	}
	if err == nil {
		t.Fatal("the local end read a stopped connection without an error")
	}
	// And it must be a cut rather than an end-of-stream. The endpoint lives in a userspace
	// stack with no linger option, so a close here would send a FIN -- and a program reading a
	// FIN where it expected an answer reports the server it asked for as broken, which is the
	// wrong thing to say when a filter is what happened.
	if errors.Is(err, io.EOF) {
		t.Fatal("the local end read a graceful end-of-stream, which is the shape of a request that finished")
	}

	if got := server.received(); len(got) != 0 {
		t.Errorf("the network received %q of a stopped connection, want nothing", got)
	}
	if offered := stream.offered(); len(offered) != 1 {
		t.Errorf("the inspector was offered %d chunks, want the one it stopped on", len(offered))
	}
	// The window is let go however the flow ended, which is what keeps a stopped connection
	// from being the one shape that leaks one.
	//
	// Waited for rather than read once: the local end learns the flow is gone the moment it is
	// reset, and the copy that reset it releases the window as it returns, so the two are
	// ordered but not simultaneous.
	deadline := time.Now().Add(3 * time.Second)
	for {
		switch closed := stream.closes(); {
		case closed == 1:
			return
		case closed > 1:
			t.Fatalf("the inspector was closed %d times, want once", closed)
		case time.Now().After(deadline):
			t.Fatal("the inspector was never closed on a stopped flow")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The same path with nothing to stop: the bytes are offered and then carried, which is what
// every inspected connection that is not a match looks like.
func TestAFlowNothingStopsIsStillOfferedAndStillCarried(t *testing.T) {
	server := newRecordingServer(t)
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")})
	f, m := fabricUnder(t, table, carrierSet{"tn_first": &recordingCarrier{to: server.addr}}, nil)

	stream := &stoppingStream{}
	f.SetInspector(&fakeInspector{watch: func(inspect.Flow) netpipe.Stream { return stream }})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	const said = "hello for fine.example, please connect"
	if _, err := conn.Write([]byte(said)); err != nil {
		t.Fatalf("write the opening bytes: %v", err)
	}
	greeted(t, conn, said)

	if offered := stream.offered(); len(offered) == 0 {
		t.Error("the inspector was offered nothing on a connection it was reading")
	}
}

// The datagram path, where a program that brought its own resolver is the case that reaches
// this and nothing else does.
func TestADatagramFlowIsOfferedWhatItSendsAndStoppedOnIt(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")})
	f, m := fabricUnder(t, table,
		carrierSet{"tn_first": &recordingCarrier{to: udpEchoServer(t, "first")}}, nil)

	stream := &stoppingStream{stopOn: "bad.example"}
	f.SetInspector(&fakeInspector{datagrams: func(inspect.Flow) netpipe.Stream { return stream }})

	conn, err := m.dialUDP(netip.MustParseAddrPort("93.184.216.34:53"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("a question about bad.example")); err != nil {
		t.Fatalf("send a datagram: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	if n, _ := conn.Read(make([]byte, 512)); n != 0 {
		t.Errorf("the local end read %d bytes of a stopped datagram flow", n)
	}
	if offered := stream.offered(); len(offered) != 1 {
		t.Errorf("the inspector was offered %d datagrams, want the one it stopped on", len(offered))
	}
}

// Nothing set is the module switched off. The interface carries every connection this
// machine makes, so reading an absent inspector as a refusal would take the machine off
// every network at once.
func TestAnInterfaceWithNoInspectorCarriesEverything(t *testing.T) {
	carrier := &recordingCarrier{to: echoServer(t, "first")}
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")})
	f, m := fabricUnder(t, table, carrierSet{"tn_first": carrier}, nil)
	f.SetInspector(&fakeInspector{refuse: map[string]string{"93.184.216.34": "stopped"}})
	f.SetInspector(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("dial with inspection off: %v", err)
	}
	defer conn.Close()
	greeted(t, conn, "first")
}

// A connection that was going to be opened and could not be is stopped rather than carried.
// Carrying it would be the failure that matters: the program would get the connection it asked
// for, believe it was inspected, and have it read by nobody.
func TestAFlowThatCouldNotBeOpenedIsStoppedRatherThanCarried(t *testing.T) {
	server := newRecordingServer(t)
	table := tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")})
	f, m := fabricUnder(t, table, carrierSet{"tn_first": &recordingCarrier{to: server.addr}}, nil)

	stream := &stoppingStream{}
	f.SetInspector(&fakeInspector{
		watch: func(inspect.Flow) netpipe.Stream { return stream },
		open: func(inspect.Flow, net.Conn, net.Conn) (net.Conn, net.Conn, error) {
			return nil, nil, errors.New("the real server's certificate did not verify")
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("93.184.216.34:443"))
	// The reset is sent the moment the handshake completes, and can reach the program before
	// its connect has returned: then the connect is what carries it, and there is no
	// connection to write on. Either way the program is told, and told with a reset.
	if err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("dial: %v, want a connection or a reset", err)
	}
	if err == nil {
		defer conn.Close()
		if _, err := conn.Write([]byte("hello for the destination that could not be opened")); err != nil {
			t.Fatalf("write the opening bytes: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("set a deadline: %v", err)
		}
		n, err := conn.Read(make([]byte, 64))
		if n != 0 {
			t.Fatalf("the local end read %d bytes of a connection that was never opened", n)
		}
		if err == nil {
			t.Fatal("the local end read a stopped connection without an error")
		}
		if errors.Is(err, io.EOF) {
			t.Fatal("the local end read a graceful end-of-stream, which is the shape of a request that finished")
		}
	}
	if got := server.received(); len(got) != 0 {
		t.Errorf("the network received %q of a connection that was never opened, want nothing", got)
	}
	// The window goes back on this path too. It is the one path that never reaches the copy that
	// would otherwise return it, which is exactly why it is the one that can leak.
	deadline := time.Now().Add(3 * time.Second)
	for {
		switch closed := stream.closes(); {
		case closed == 1:
			return
		case closed > 1:
			t.Fatalf("the inspector was closed %d times, want once", closed)
		case time.Now().After(deadline):
			t.Fatal("the window was never let go of a connection that was never opened")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
