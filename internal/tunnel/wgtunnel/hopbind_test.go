// SPDX-License-Identifier: MIT

package wgtunnel

// One connection carried inside another: the real thing against a real device, and the
// arithmetic and refusals that keep it from failing silently.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
	"github.com/tailscale/wireguard-go/conn"
)

// carrierOverLoopback stands in for the connection before this one in a chain. It dials the
// ordinary way, which is what a carrier does from the carried connection's point of view: the
// packets go somewhere this connection never has to know about.
type carrierOverLoopback struct {
	mu     sync.Mutex
	dialed []string
	err    error
}

func (c *carrierOverLoopback) Dial(_ context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	c.dialed = append(c.dialed, address)
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return net.Dial(network, address)
}

func (c *carrierOverLoopback) wasDialed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.dialed...)
}

// pipeCarrier hands each conversation one end of a pipe and keeps the other, so a test can be
// the server on the far side of the carrier without a socket anywhere.
type pipeCarrier struct {
	mu   sync.Mutex
	ends []net.Conn
	err  error
}

func (c *pipeCarrier) Dial(context.Context, string, string) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	here, there := net.Pipe()
	c.ends = append(c.ends, there)
	return here, nil
}

// farEnd is the server's side of the conversation opened by the nth Open, counting from zero.
func (c *pipeCarrier) farEnd(t *testing.T, n int) net.Conn {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if n >= len(c.ends) {
		t.Fatalf("the carrier opened %d conversations, so there is no %d one", len(c.ends), n)
	}
	return c.ends[n]
}

// The whole of the chain, end to end: a device whose own packets never touch a socket of its
// own still handshakes and moves traffic. Everything else here is about what that costs.
func TestACarriedConnectionHandshakesThroughTheOneCarryingIt(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)

	carrier := &carrierOverLoopback{}
	client := startClientWith(t, Options{
		ID:         "tn_test",
		Held:       clientConfig(clientPrivate, serverPublic, port),
		Logger:     slog.New(slog.DiscardHandler),
		Through:    carrier,
		ThroughMTU: config.DefaultWireGuardMTU,
	})

	waitForState(t, client, tunnel.StateConnected)

	if dialed := carrier.wasDialed(); len(dialed) != 1 {
		t.Errorf("the carrier was asked for %v, want exactly one conversation with the server -- "+
			"a carried connection opens it once and keeps it for the life of the device", dialed)
	}

	// A service inside the far network, reached across a device that has no way out of this
	// machine except through the carrier.
	listener, err := server.listenTCP(netip.AddrPortFrom(serverAddr, 8080))
	if err != nil {
		t.Fatalf("listen inside the network: %v", err)
	}
	defer listener.Close()
	go echoOnce(listener)

	held, err := client.Dial(t.Context(), "tcp", "10.9.0.1:8080")
	if err != nil {
		t.Fatalf("dial a service inside the network: %v", err)
	}
	defer held.Close()
	const sent = "hello down the chain"
	if got := echoThrough(t, held, sent); got != sent {
		t.Errorf("the service answered %q, want %q", got, sent)
	}
}

// A carried connection's packets never reach this machine's routing table, so it has nothing
// to keep out of the interface's way -- and anchoring its server would take that one address
// off the interface for every other program too, which is a hole in exactly the mode that
// promises there is none.
func TestACarriedConnectionAnchorsNothingAndIsBuiltToFitInsideItsCarrier(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)

	client := startClientWith(t, Options{
		ID:         "tn_test",
		Held:       clientConfig(clientPrivate, serverPublic, port),
		Logger:     slog.New(slog.DiscardHandler),
		Through:    &carrierOverLoopback{},
		ThroughMTU: config.DefaultWireGuardMTU,
	})

	anchored, asks := client.(tunnel.Anchored)
	if !asks {
		t.Fatal("a WireGuard connection stopped saying where its own packets go")
	}
	if got := anchored.Anchors(); len(got) != 0 {
		t.Errorf("a carried connection anchors %v, want nothing -- its packets never reach this "+
			"machine's routing table, and holding one address out of the interface for every "+
			"program on the machine is the hole this mode promises there is none of", got)
	}

	sized, asks := client.(tunnel.Sized)
	if !asks {
		t.Fatal("a WireGuard connection stopped saying how big a packet it takes")
	}
	want := hopMTU(config.DefaultWireGuardMTU, netip.MustParseAddr("127.0.0.1"))
	if got := sized.MTU(); got != want {
		t.Errorf("MTU = %d, want %d -- a carried connection reports the size it was built at, "+
			"and reporting the configured one sends packets its carrier silently drops", got, want)
	}
}

// A carrier that cannot reach the server is a connection that could not start, with the reason
// on it. Left to the device it would be a handshake that never completes, which reads as a
// server that is down.
func TestAConnectionWhoseCarrierCannotReachTheServerFailsToStart(t *testing.T) {
	_, serverPublic := keyPair(t)
	clientPrivate, _ := keyPair(t)

	client := New(Options{
		ID:         "tn_test",
		Held:       clientConfig(clientPrivate, serverPublic, 51820),
		Logger:     slog.New(slog.DiscardHandler),
		Through:    &carrierOverLoopback{err: errors.New("that network is not carrying anything")},
		ThroughMTU: config.DefaultWireGuardMTU,
	})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing the connection failed: %v", err)
		}
	})

	err := client.Start(t.Context())

	if err == nil {
		t.Fatal("a connection whose carrier cannot reach its server started anyway")
	}
	if !strings.Contains(err.Error(), "carrying it") {
		t.Errorf("start failed with %v, want it to say the connection carrying this one could "+
			"not reach the server", err)
	}
}

// Each hop costs the carrier's own headers, so a chain shrinks packets as it lengthens. Below
// what every network has to carry the failure is not visible -- large packets are dropped and
// small ones are not -- so it is refused with the size named.
func TestAConnectionWithNoRoomLeftInsideItsCarrierIsRefused(t *testing.T) {
	held := config.WireGuardTunnel{MTU: config.DefaultWireGuardMTU}
	server := netip.MustParseAddr("192.0.2.10")

	// Room for exactly the floor is built, and one byte less is not: the boundary is the whole
	// of the rule, and a check written the other way round would accept a network nothing is
	// required to carry a full packet over.
	atFloor := &Tunnel{held: held, through: &carrierOverLoopback{},
		throughMTU: minHopMTU + wireGuardOverhead + udp4Overhead}
	if got, err := atFloor.builtMTU(server); err != nil || got != minHopMTU {
		t.Errorf("a carrier with room for exactly %d bytes gives %d, %v, want it built at the floor",
			minHopMTU, got, err)
	}

	tooSmall := &Tunnel{held: held, through: &carrierOverLoopback{},
		throughMTU: minHopMTU + wireGuardOverhead + udp4Overhead - 1}
	_, err := tooSmall.builtMTU(server)
	if err == nil {
		t.Fatal("a connection with less room than every network has to carry was built anyway")
	}
	if !strings.Contains(err.Error(), "1280") {
		t.Errorf("the refusal reads %v, want the size every network has to carry named in it", err)
	}

	// A carrier that says nothing about its packet size is refused rather than assumed: the
	// assumption that would have to be made is the configured size, which is the one size known
	// to be too big.
	_, err = (&Tunnel{held: held, through: &carrierOverLoopback{}}).builtMTU(server)
	if err == nil {
		t.Fatal("a connection was built inside a carrier that never said how big a packet it takes")
	}
	if !strings.Contains(err.Error(), "how big a packet") {
		t.Errorf("the refusal reads %v, want it to say the carrier never gave a packet size -- "+
			"reported as too small it reads as a chain to shorten, which fixes nothing", err)
	}

	// Nothing carrying it is the ordinary connection, built at what it was configured with.
	direct := &Tunnel{held: held}
	if got, err := direct.builtMTU(server); err != nil || got != config.DefaultWireGuardMTU {
		t.Errorf("an uncarried connection gives %d, %v, want the configured size", got, err)
	}
}

// The arithmetic itself. An IPv6 server costs twenty bytes more than an IPv4 one, and reading
// them the same way sets a v6 chain twenty bytes too large -- which is not an error anywhere,
// just packets that stop arriving once they get big enough.
func TestOneHopCostsItsCarriersHeaders(t *testing.T) {
	const carrier = 1420
	if got := hopMTU(carrier, netip.MustParseAddr("192.0.2.10")); got != carrier-32-28 {
		t.Errorf("hopMTU over IPv4 = %d, want %d", got, carrier-32-28)
	}
	if got := hopMTU(carrier, netip.MustParseAddr("2001:db8::1")); got != carrier-32-48 {
		t.Errorf("hopMTU over IPv6 = %d, want %d", got, carrier-32-48)
	}
	// A v4 address written in v6 form still travels in a v4 datagram, so it costs the v4
	// headers. Charging it the v6 ones would shrink every chain reached that way for nothing.
	v4in6 := netip.MustParseAddr("::ffff:192.0.2.10")
	if got := hopMTU(carrier, v4in6); got != carrier-32-28 {
		t.Errorf("hopMTU over a v4-in-v6 address = %d, want the IPv4 cost %d", got, carrier-32-28)
	}
}

// A conversation through a carrier reaches one server and nothing else can write into it, so
// every packet is reported as coming from that server -- and one addressed anywhere else is
// refused rather than sent to the server anyway under a name the device does not think it is
// talking to.
func TestACarriedBindSendsAndReceivesOnlyWithItsServer(t *testing.T) {
	carrier := &pipeCarrier{}
	serverPort := netip.MustParseAddrPort("192.0.2.10:51820")
	bind := newHopBind(t.Context(), carrier, serverPort)

	receives, port, err := bind.Open(41414)
	if err != nil {
		t.Fatalf("opening the bind: %v", err)
	}
	if len(receives) != 1 {
		t.Fatalf("the bind offered %d ways to receive, want exactly one", len(receives))
	}
	if port != 0 {
		t.Errorf("the bind reports port %d, want none -- a carried connection has no port on "+
			"this machine, and a number here is one nothing is listening on", port)
	}
	if _, _, err := bind.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Errorf("opening the bind twice gave %v, want it reported as already open", err)
	}

	server := carrier.farEnd(t, 0)
	t.Cleanup(func() { _ = server.Close() })

	// The offset is room the bind could have encapsulated in, and one that sent it would put
	// that empty space on the wire in front of every packet.
	sent := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, readErr := server.Read(buf)
		if readErr != nil {
			sent <- nil
			return
		}
		sent <- buf[:n]
	}()
	if err := bind.Send([][]byte{[]byte("....payload")}, hopEndpoint(serverPort), 4); err != nil {
		t.Fatalf("sending through the carrier: %v", err)
	}
	if got := string(<-sent); got != "payload" {
		t.Errorf("the carrier was written %q, want %q -- the space before the offset is room "+
			"this bind did not need", got, "payload")
	}

	elsewhere := netip.MustParseAddrPort("198.51.100.7:51820")
	if err := bind.Send([][]byte{[]byte("payload")}, hopEndpoint(elsewhere), 0); err == nil {
		t.Error("a packet addressed to another server was sent through a conversation that " +
			"reaches only one, so the device would be talking to a peer it does not think it is")
	}

	go func() { _, _ = server.Write([]byte("answer")) }()
	packets := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := receives[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("receiving through the carrier: %v", err)
	}
	if n != 1 || string(packets[0][:sizes[0]]) != "answer" {
		t.Errorf("received %d packets, first %q, want the one the server sent",
			n, packets[0][:sizes[0]])
	}
	if eps[0].DstToString() != serverPort.String() {
		t.Errorf("the packet is reported as coming from %q, want the server -- through a "+
			"carrier it can have come from nowhere else", eps[0].DstToString())
	}
}

// The lifecycle the device actually drives: it closes its bind and opens it again whenever it
// is brought up or its port changes. A bind that could not be opened a second time would leave
// a device reporting itself running with nothing carrying its packets, and a read on the
// conversation that ended has to read as a closed socket rather than as a network fault.
func TestACarriedBindOpensAgainAfterTheDeviceClosesIt(t *testing.T) {
	carrier := &pipeCarrier{}
	bind := newHopBind(t.Context(), carrier, netip.MustParseAddrPort("192.0.2.10:51820"))
	receives, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("opening the bind: %v", err)
	}
	t.Cleanup(func() { _ = carrier.farEnd(t, 0).Close() })

	if err := bind.Close(); err != nil {
		t.Fatalf("closing the bind: %v", err)
	}
	if err := bind.Close(); err != nil {
		t.Errorf("closing the bind a second time failed with %v, want it accepted -- a device "+
			"that is brought down and then closed does exactly this", err)
	}

	_, err = receives[0]([][]byte{make([]byte, 16)}, make([]int, 1), make([]conn.Endpoint, 1))
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("a read on the conversation that ended gave %v, want a closed socket", err)
	}
	if err := bind.Send([][]byte{[]byte("packet")}, nil, 0); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a send with no conversation open gave %v, want a closed socket", err)
	}

	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("reopening the bind failed with %v, want a new conversation -- the device does "+
			"exactly this every time it is brought up", err)
	}
	t.Cleanup(func() { _ = carrier.farEnd(t, 1).Close() })

	server := carrier.farEnd(t, 1)
	read := make(chan string, 1)
	go func() {
		buf := make([]byte, 16)
		n, readErr := server.Read(buf)
		if readErr != nil {
			read <- ""
			return
		}
		read <- string(buf[:n])
	}()
	if err := bind.Send([][]byte{[]byte("packet")}, nil, 0); err != nil {
		t.Fatalf("sending through the reopened bind: %v", err)
	}
	if got := <-read; got != "packet" {
		t.Errorf("the reopened conversation carried %q, want the packet -- the bind is still "+
			"writing into the conversation the device closed", got)
	}

	// A carrier that has gone down between one open and the next is a connection that cannot
	// come back, and the reason has to name the connection carrying it or it reads as this
	// connection's own server being unreachable.
	if err := bind.Close(); err != nil {
		t.Fatalf("closing the bind: %v", err)
	}
	carrier.mu.Lock()
	carrier.err = errors.New("that network is not carrying anything")
	carrier.mu.Unlock()
	_, _, err = bind.Open(0)
	if err == nil {
		t.Fatal("the bind opened through a carrier that cannot reach the server")
	}
	if !strings.Contains(err.Error(), "carrying it") {
		t.Errorf("the failure reads %v, want it to name the connection carrying this one", err)
	}
}

// The endpoint the device is handed. It accepts the one server this conversation reaches and
// nothing else, and hands the cookie calculation the address in its own bytes.
func TestACarriedBindAcceptsOnlyItsOwnServersAddress(t *testing.T) {
	serverPort := netip.MustParseAddrPort("192.0.2.10:51820")
	bind := newHopBind(t.Context(), &pipeCarrier{}, serverPort)

	ep, err := bind.ParseEndpoint(serverPort.String())
	if err != nil {
		t.Fatalf("the bind refused its own server's address: %v", err)
	}
	if ep.DstIP() != serverPort.Addr() || ep.SrcToString() != "" {
		t.Errorf("the endpoint reads %s from %q, want the server and no source of its own -- "+
			"the packets leave through the carrier, whose source is the carrier's business",
			ep.DstToString(), ep.SrcToString())
	}
	port := serverPort.Port()
	want := []byte{192, 0, 2, 10, byte(port), byte(port >> 8)}
	if got := ep.DstToBytes(); string(got) != string(want) {
		t.Errorf("DstToBytes = %v, want %v", got, want)
	}

	if _, err := bind.ParseEndpoint("198.51.100.7:51820"); err == nil {
		t.Error("the bind accepted an address it cannot reach, so the device would send packets " +
			"into a conversation with somebody else")
	}
	if _, err := bind.ParseEndpoint("not-an-address"); err == nil {
		t.Error("the bind accepted something that is not an address and a port")
	}
}
