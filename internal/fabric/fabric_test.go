// SPDX-License-Identifier: MIT

package fabric

// The fabric driven the way the machine drives it: real IP packets in one end, a real
// network stack turning them into connections, and a real dial out the other end.
//
// The interface is a pair of in-memory ends rather than one on the machine, and the private
// networks are ordinary loopback servers behind a carrier that records what it was asked
// for. Nothing here needs a privilege, an interface or a network, which is the point: the
// part of this mode that decides where a program's traffic goes is exactly the part that
// must never be tested only by hand.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// testMTU is small enough to be obviously not the platform default and large enough for
// every exchange below to fit in one packet.
const testMTU = 1280

// thisMachine is the address the programs in these tests dial from. It is outside every
// range under test so it can never be mistaken for one of them.
var thisMachine = netip.MustParseAddr("100.100.100.100")

// thisMachine6 is the same machine's address for the networks that are addressed the other
// way. Both families are on the one interface, because a private network reached over IPv6
// is not a different mode.
var thisMachine6 = netip.MustParseAddr("fd00:100::100")

// wireEnd is one end of an in-memory interface: what is written at one end is read at the
// other.
type wireEnd struct {
	rx     <-chan []byte
	tx     chan<- []byte
	events chan tun.Event
	// done and closeOnce are shared by both ends: closing one end of a wire takes the wire
	// down, and the two ends are closed independently by the fabric and by the test.
	done      chan struct{}
	closeOnce *sync.Once

	// broke is closed when the interface stops answering, and broken is what it answers
	// with from then on -- which is how an interface removed from under the process behaves.
	broke    chan struct{}
	broken   error
	breakOne sync.Once
}

var _ tun.Device = (*wireEnd)(nil)

// wirePair is two ends of one interface, already up.
func wirePair() (*wireEnd, *wireEnd) {
	ab := make(chan []byte, 64)
	ba := make(chan []byte, 64)
	done := make(chan struct{})
	once := new(sync.Once)
	a := &wireEnd{rx: ba, tx: ab, events: make(chan tun.Event, 1), done: done, closeOnce: once, broke: make(chan struct{})}
	b := &wireEnd{rx: ab, tx: ba, events: make(chan tun.Event, 1), done: done, closeOnce: once, broke: make(chan struct{})}
	a.events <- tun.EventUp
	b.events <- tun.EventUp
	return a, b
}

// fail makes this end answer every read with an error, standing in for an interface the
// operating system has taken away.
func (w *wireEnd) fail(err error) {
	w.breakOne.Do(func() {
		w.broken = err
		close(w.broke)
	})
}

func (w *wireEnd) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-w.broke:
		return 0, w.broken
	case <-w.done:
		return 0, io.ErrClosedPipe
	case packet, ok := <-w.rx:
		if !ok {
			return 0, io.ErrClosedPipe
		}
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}

func (w *wireEnd) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		// Copied because the caller reuses its buffer for the next packet.
		held := make([]byte, len(packet))
		copy(held, packet)
		select {
		case w.tx <- held:
		case <-w.done:
			return 0, io.ErrClosedPipe
		}
	}
	return len(bufs), nil
}

func (w *wireEnd) MTU() (int, error)        { return testMTU, nil }
func (w *wireEnd) Name() (string, error)    { return "wire", nil }
func (w *wireEnd) File() *os.File           { return nil }
func (w *wireEnd) Events() <-chan tun.Event { return w.events }
func (w *wireEnd) BatchSize() int           { return 1 }
func (w *wireEnd) Close() error {
	w.closeOnce.Do(func() { close(w.done) })
	return nil
}

// machine is the network stack standing in for this computer: it dials, and its packets go
// down the wire to the fabric.
type machine struct {
	ip     *stack.Stack
	ep     *channel.Endpoint
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newMachine(t *testing.T, end *wireEnd) *machine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &machine{
		ep: channel.New(64, testMTU, ""),
		ip: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		}),
		cancel: cancel,
	}
	if err := m.ip.CreateNIC(1, m.ep); err != nil {
		t.Fatalf("create the machine's interface: %v", err)
	}
	for _, own := range []struct {
		protocol tcpip.NetworkProtocolNumber
		addr     netip.Addr
	}{
		{ipv4.ProtocolNumber, thisMachine},
		{ipv6.ProtocolNumber, thisMachine6},
	} {
		held := tcpip.ProtocolAddress{
			Protocol:          own.protocol,
			AddressWithPrefix: tcpip.AddrFromSlice(own.addr.AsSlice()).WithPrefix(),
		}
		if err := m.ip.AddProtocolAddress(1, held, stack.AddressProperties{}); err != nil {
			t.Fatalf("give the machine the address %s: %v", own.addr, err)
		}
	}
	m.ip.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	m.ip.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		bufs := [][]byte{make([]byte, headroom+maxPacket)}
		sizes := make([]int, 1)
		for {
			n, err := end.Read(bufs, sizes, headroom)
			if err != nil || n == 0 {
				return
			}
			frame := bufs[0][headroom : headroom+sizes[0]]
			if len(frame) == 0 {
				continue
			}
			protocol := header.IPv4ProtocolNumber
			if frame[0]>>4 == 6 {
				protocol = header.IPv6ProtocolNumber
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(frame),
			})
			m.ep.InjectInbound(protocol, packet)
			packet.DecRef()
		}
	}()
	go func() {
		defer m.wg.Done()
		buf := make([]byte, headroom+maxPacket)
		for {
			packet := m.ep.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			packet.DecRef()
			n, err := view.Read(buf[headroom:])
			view.Release()
			if err != nil {
				return
			}
			if _, err := end.Write([][]byte{buf[:headroom+n]}, headroom); err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		cancel()
		end.Close()
		m.ep.Close()
		m.wg.Wait()
		m.ip.Close()
		m.ip.Destroy()
	})
	return m
}

// dialTCP opens a connection from this machine to an address the fabric carries.
func (m *machine) dialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	remote := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(to.Addr().AsSlice()),
		Port: to.Port(),
	}
	return gonet.DialContextTCP(ctx, m.ip, remote, familyOf(to.Addr()))
}

// familyOf is the network protocol an address travels in, so one dial helper serves both
// families rather than the tests carrying two.
func familyOf(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

// dialUDP opens a datagram socket from this machine pointed at an address the fabric
// carries.
func (m *machine) dialUDP(to netip.AddrPort) (net.Conn, error) {
	remote := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(to.Addr().AsSlice()),
		Port: to.Port(),
	}
	return gonet.DialUDP(m.ip, nil, &remote, familyOf(to.Addr()))
}

// recordingCarrier stands in for one private network. It dials somewhere real and remembers
// what it was asked to reach, which is the assertion most of these tests are making: the
// address that left this machine is the address the network's own hosts have.
type recordingCarrier struct {
	// to is where a dial actually goes, which is a loopback server the test started.
	to string
	// refuse, when set, is what every dial through this connection fails with.
	refuse error

	mu    sync.Mutex
	asked []string
}

func (c *recordingCarrier) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	c.asked = append(c.asked, network+" "+address)
	c.mu.Unlock()
	if c.refuse != nil {
		return nil, c.refuse
	}
	var d net.Dialer
	return d.DialContext(ctx, network, c.to)
}

func (c *recordingCarrier) asks() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.asked...)
}

// carrierSet is the registry the fabric looks connections up in.
type carrierSet map[string]Carrier

func (s carrierSet) Carrier(id string) (Carrier, bool) {
	c, ok := s[id]
	return c, ok
}

// echoServer answers on loopback with a fixed greeting followed by whatever it was sent, so
// a test can tell which of two identically addressed networks it reached.
func echoServer(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start a server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.WriteString(conn, greeting); err != nil {
					return
				}
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// udpEchoServer answers every datagram with a greeting and the datagram itself.
func udpEchoServer(t *testing.T, greeting string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start a datagram server: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(append([]byte(greeting), buf[:n]...), from); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

// fabricUnder builds a fabric over one end of a wire and a machine over the other.
func fabricUnder(t *testing.T, table *Table, carriers carrierSet, names map[string]string) (*Fabric, *machine) {
	t.Helper()
	hostEnd, machineEnd := wirePair()
	f, err := New(Options{
		Device:   hostEnd,
		Carriers: carriers,
		MTU:      testMTU,
		Table:    table,
		Names:    names,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("build the fabric: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f, newMachine(t, machineEnd)
}

// greeted reads the server's opening line, which says which network answered.
func greeted(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if string(buf) != want {
		t.Errorf("answered by %q, want %q", buf, want)
	}
}

func dialCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The whole mode in one test: a program on this machine dials an address on a private
// network with no setup of its own, and reaches the host that has that address there.
func TestAProgramOnThisMachineReachesAHostOnAConnectedNetwork(t *testing.T) {
	office := &recordingCarrier{to: echoServer(t, "office")}
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	_, m := fabricUnder(t, table, carrierSet{"tn_office": office}, nil)

	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("10.1.2.3:5432"))
	if err != nil {
		t.Fatalf("dial 10.1.2.3:5432: %v", err)
	}
	defer conn.Close()

	greeted(t, conn, "office")
	if asks := office.asks(); len(asks) != 1 || asks[0] != "tcp 10.1.2.3:5432" {
		t.Errorf("the connection was asked for %v, want one dial to tcp 10.1.2.3:5432", asks)
	}
}

// Interface mode is the one mode where nothing else on the machine sees a flow: the proxy,
// the forwards and the subnet router are all bypassed. What the fabric counts here is the only
// account there is of which port carried what, and of which connection it crossed.
func TestTheInterfaceCountsWhatEachPortCarriedAndWhichConnectionCrossedIt(t *testing.T) {
	office := &recordingCarrier{to: echoServer(t, "office")}
	f, m := fabricUnder(t, tableOf(t, at("tn_office", "10.1.0.0/16")),
		carrierSet{"tn_office": office}, nil)

	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("10.1.2.3:5432"))
	if err != nil {
		t.Fatalf("dial 10.1.2.3:5432: %v", err)
	}
	defer conn.Close()
	greeted(t, conn, "office")

	named, _, folded := f.Ports()
	if len(named) != 1 || folded != 0 {
		t.Fatalf("the interface reported %d ports and folded %d, want the one port it carried",
			len(named), folded)
	}
	got := named[0]
	if got.Label != "5432" || got.Detail != "tcp" {
		t.Errorf("the port drew as %q over %q, want 5432 over tcp", got.Label, got.Detail)
	}
	// Which connection carried it: this is the seam that knows it per flow, and it is what the
	// ports graph filters by.
	if got.Via != "tn_office" {
		t.Errorf("the port crossed %q, want the connection carrying that network", got.Via)
	}
	if got.Down == 0 {
		t.Errorf("the port counted %d down, want the greeting the host sent back", got.Down)
	}
}

// The requirement the whole mode exists for: two networks that both use 10.1.2.3, both
// reachable at the same moment, from a program that knows nothing about either.
func TestTwoNetworksWithTheSameAddressesAreBothReachableAtOnce(t *testing.T) {
	prod := &recordingCarrier{to: echoServer(t, "prod")}
	staging := &recordingCarrier{to: echoServer(t, "staging")}
	table := tableOf(t,
		at("tn_prod", "10.1.0.0/16"),
		moved("tn_staging", "10.1.0.0/16", "198.18.0.0/16"),
	)
	_, m := fabricUnder(t, table, carrierSet{"tn_prod": prod, "tn_staging": staging}, nil)

	ctx := dialCtx(t)
	toProd, err := m.dialTCP(ctx, netip.MustParseAddrPort("10.1.2.3:5432"))
	if err != nil {
		t.Fatalf("dial the first network: %v", err)
	}
	defer toProd.Close()
	toStaging, err := m.dialTCP(ctx, netip.MustParseAddrPort("198.18.2.3:5432"))
	if err != nil {
		t.Fatalf("dial the second network: %v", err)
	}
	defer toStaging.Close()

	greeted(t, toProd, "prod")
	greeted(t, toStaging, "staging")

	// Both were dialled at 10.1.2.3 inside their own networks: the second one's address on
	// this machine is this machine's business and means nothing on the network itself.
	if asks := staging.asks(); len(asks) != 1 || asks[0] != "tcp 10.1.2.3:5432" {
		t.Errorf("the moved network was asked for %v, want tcp 10.1.2.3:5432", asks)
	}
	if asks := prod.asks(); len(asks) != 1 || asks[0] != "tcp 10.1.2.3:5432" {
		t.Errorf("the unmoved network was asked for %v, want tcp 10.1.2.3:5432", asks)
	}
}

// Datagrams cross too, with their boundaries intact -- a stream copy would join two of them
// and a program reading one datagram at a time would never see the second.
func TestDatagramsCrossWithTheirBoundariesIntact(t *testing.T) {
	office := &recordingCarrier{to: udpEchoServer(t, "-")}
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	_, m := fabricUnder(t, table, carrierSet{"tn_office": office}, nil)

	conn, err := m.dialUDP(netip.MustParseAddrPort("10.1.2.3:53"))
	if err != nil {
		t.Fatalf("open a datagram socket: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}

	for _, sent := range []string{"one", "two"} {
		if _, err := conn.Write([]byte(sent)); err != nil {
			t.Fatalf("send %q: %v", sent, err)
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read the answer to %q: %v", sent, err)
		}
		if got, want := string(buf[:n]), "-"+sent; got != want {
			t.Errorf("answered %q, want %q", got, want)
		}
	}
	if asks := office.asks(); len(asks) != 1 || asks[0] != "udp 10.1.2.3:53" {
		t.Errorf("the connection was asked for %v, want one dial to udp 10.1.2.3:53", asks)
	}
}

// An address on no connected network is refused rather than carried somewhere. Carrying it
// through whichever connection happened to be first is the wrong-network-right-address
// failure this whole design is arranged to prevent.
func TestAnAddressNoConnectionCarriesIsRefused(t *testing.T) {
	office := &recordingCarrier{to: echoServer(t, "office")}
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	f, m := fabricUnder(t, table, carrierSet{"tn_office": office}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("172.16.0.9:5432"))
	if err == nil {
		conn.Close()
		t.Fatal("a connection to an address no network carries was accepted")
	}
	if len(office.asks()) != 0 {
		t.Errorf("the one connected network was dialled anyway: %v", office.asks())
	}
	if refused := f.Status("wire").Counters[""].Refused; refused == 0 {
		t.Error("nothing recorded the refusal, so the dashboard would show a network working")
	}
}

// The same for a datagram, which fails differently and worse. A TCP dial to nowhere is
// refused at once; a datagram sent nowhere is silence, and a program waits out its own
// timeout on it. Reporting the flow as unhandled is what makes the stack answer "no such
// port" instead, and the refusal still has to be counted or the dashboard shows a working
// network.
func TestADatagramToAnAddressNoConnectionCarriesIsRefused(t *testing.T) {
	office := &recordingCarrier{to: udpEchoServer(t, "-")}
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	f, m := fabricUnder(t, table, carrierSet{"tn_office": office}, nil)

	conn, err := m.dialUDP(netip.MustParseAddrPort("172.16.0.9:53"))
	if err != nil {
		t.Fatalf("open a datagram socket: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("who is there")); err != nil {
		t.Fatalf("send the datagram: %v", err)
	}

	waitFor(t, func() bool { return f.Status("wire").Counters[""].Refused > 0 })
	if len(office.asks()) != 0 {
		t.Errorf("the one connected network was dialled anyway: %v", office.asks())
	}
}

// The budget covers datagram flows too, and it has to: a UDP flow has no close, so a program
// spraying datagrams at a network would otherwise hold a session for every destination it
// touched until each of them went idle.
func TestADatagramFlowPastAConnectionsBudgetIsRefused(t *testing.T) {
	office := &recordingCarrier{to: udpEchoServer(t, "-")}
	hostEnd, machineEnd := wirePair()
	f, err := New(Options{
		Device:        hostEnd,
		Carriers:      carrierSet{"tn_office": office},
		MTU:           testMTU,
		Table:         tableOf(t, at("tn_office", "10.1.0.0/16")),
		SessionBudget: 1,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("build the fabric: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	m := newMachine(t, machineEnd)

	// The first flow claims the whole budget and keeps it while it is being answered.
	holding, err := m.dialUDP(netip.MustParseAddrPort("10.1.0.5:53"))
	if err != nil {
		t.Fatalf("open the first datagram socket: %v", err)
	}
	defer holding.Close()
	if err := holding.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	if _, err := holding.Write([]byte("one")); err != nil {
		t.Fatalf("send the first datagram: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := holding.Read(buf); err != nil {
		t.Fatalf("read the answer to the first datagram: %v", err)
	}
	waitFor(t, func() bool { return f.Status("wire").Counters["tn_office"].Holding == 1 })

	// A second flow to the same connection is refused, and counted against it by name.
	second, err := m.dialUDP(netip.MustParseAddrPort("10.1.0.6:53"))
	if err != nil {
		t.Fatalf("open the second datagram socket: %v", err)
	}
	defer second.Close()
	if _, err := second.Write([]byte("two")); err != nil {
		t.Fatalf("send the second datagram: %v", err)
	}

	waitFor(t, func() bool { return f.Status("wire").Counters["tn_office"].Refused > 0 })
	if asks := office.asks(); len(asks) != 1 {
		t.Errorf("the connection was asked for %v, want only the flow inside its budget", asks)
	}
}

// The fabric refuses what it cannot carry rather than returning something half-built. Every
// caller points the machine's routes at the interface as soon as this returns, so a fabric
// that came back without a stack behind it would take the machine off its networks.
func TestAFabricThatCannotBeBuiltIsRefusedWithItsReason(t *testing.T) {
	dev := newScriptedDevice(1)
	t.Cleanup(func() { dev.Close() })

	cases := []struct {
		name string
		opts Options
		says string
	}{
		{
			"nothing to re-dial through",
			Options{Device: dev, MTU: testMTU},
			"nothing to re-dial connections through",
		},
		{
			// And with no logger given, which is the shape a caller that does not care about
			// logging uses: the refusal still has to arrive rather than fall over on the way.
			"no interface to carry traffic on",
			Options{Carriers: carrierSet{}, MTU: testMTU},
			"no network interface",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := New(c.opts)
			if err == nil {
				f.Close()
				t.Fatalf("a fabric with %s was built anyway", c.name)
			}
			if f != nil {
				t.Error("a refused fabric was still handed back")
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %q, want it to name %q", err, c.says)
			}
		})
	}
}

// An interface that fails on the way down is reported rather than swallowed: it is the one
// signal that this machine may still have routes pointing at something the process no longer
// owns, which the next attempt to switch the mode on has to know about.
func TestAnInterfaceThatFailsOnTheWayDownSaysSo(t *testing.T) {
	hostEnd, _ := wirePair()
	brittle := &brittleDevice{wireEnd: hostEnd, closeErr: errors.New("the interface is busy")}

	f, err := New(Options{
		Device:   brittle,
		Carriers: carrierSet{},
		MTU:      testMTU,
		Table:    tableOf(t, at("tn_office", "10.1.0.0/16")),
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("build the fabric: %v", err)
	}

	closeErr := f.Close()
	if closeErr == nil {
		t.Fatal("an interface that would not close reported a clean shutdown")
	}
	if !strings.Contains(closeErr.Error(), "the interface is busy") {
		t.Errorf("reported %q, want it to carry the interface's own reason", closeErr)
	}
	// And closing again is still quiet, because the second caller has nothing left to do.
	if err := f.Close(); err != nil {
		t.Errorf("closing an already closed fabric reported %v", err)
	}
}

// A datagram destination that will not take the flow is counted against the connection it
// was meant for. Silence is what a datagram to nowhere produces anyway, so this refusal is
// the only thing that distinguishes a network that answered nothing from one that was never
// reached -- and the count is what the dashboard reads.
func TestADatagramToADestinationThatRefusesIsCountedAgainstItsConnection(t *testing.T) {
	office := &recordingCarrier{refuse: errors.New("no route to host")}
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	f, m := fabricUnder(t, table, carrierSet{"tn_office": office}, map[string]string{"tn_office": "Office"})

	conn, err := m.dialUDP(netip.MustParseAddrPort("10.1.0.5:53"))
	if err != nil {
		t.Fatalf("open a datagram socket: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("who is there")); err != nil {
		t.Fatalf("send the datagram: %v", err)
	}

	waitFor(t, func() bool { return f.Status("wire").Counters["tn_office"].Refused > 0 })
	if asks := office.asks(); len(asks) != 1 || asks[0] != "udp 10.1.0.5:53" {
		t.Errorf("the connection was asked for %v, want one dial to udp 10.1.0.5:53", asks)
	}
	// And the flow it could not carry was given back, or the budget leaks one session per
	// destination that is not answering -- which is the shape a network outage has.
	waitFor(t, func() bool { return f.Status("wire").Counters["tn_office"].Holding == 0 })
}

// The budget is a count of what is held right now, so finishing one of several flows has to
// give back exactly one. Clearing the connection instead would hand a busy network its whole
// budget again every time a single flow ended, which is a budget that never refuses anything.
func TestFinishingOneFlowGivesBackOneAndLeavesTheRest(t *testing.T) {
	held := newSessions(3)
	for i := range 3 {
		if !held.take("tn_office") {
			t.Fatalf("flow %d was refused inside the budget", i+1)
		}
	}
	if held.take("tn_office") {
		t.Fatal("a fourth flow was allowed past a budget of three")
	}

	held.release("tn_office")
	if got := held.counts()["tn_office"]; got != 2 {
		t.Errorf("holding %d flows after one ended, want 2", got)
	}
	if !held.take("tn_office") {
		t.Error("the flow that ended did not free room for another")
	}

	for range 3 {
		held.release("tn_office")
	}
	if _, ok := held.counts()["tn_office"]; ok {
		t.Error("a connection holding nothing is still listed as holding flows")
	}
}

// A connection that is configured and not running refuses by name. Falling through to
// another connection would reach a different network at the same address and report success.
func TestAnAddressOnAConnectionThatIsNotRunningIsRefused(t *testing.T) {
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	f, m := fabricUnder(t, table, carrierSet{}, map[string]string{"tn_office": "Office"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("10.1.2.3:5432")); err == nil {
		conn.Close()
		t.Fatal("a connection to a network that is not running was accepted")
	}
	if refused := f.Status("wire").Counters["tn_office"].Refused; refused == 0 {
		t.Error("the refusal was not counted against the connection it was meant for")
	}
}

// A destination that refuses the connection refuses it here too, rather than being accepted
// and then dropped -- which a program reads as a server that hung up on it.
func TestADestinationThatRefusesIsNotAcceptedFirst(t *testing.T) {
	office := &recordingCarrier{refuse: errors.New("connection refused")}
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	_, m := fabricUnder(t, table, carrierSet{"tn_office": office}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("10.1.2.3:5432")); err == nil {
		conn.Close()
		t.Fatal("a connection to a destination that refused it was accepted")
	}
}

// The budget is per connection, and that is the whole of it: one network holding everything
// it may hold must not stop another network being reached at all.
func TestOneConnectionUsingUpItsFlowsLeavesTheOthersReachable(t *testing.T) {
	busy := &recordingCarrier{to: echoServer(t, "busy")}
	quiet := &recordingCarrier{to: echoServer(t, "quiet")}
	table := tableOf(t,
		at("tn_busy", "10.1.0.0/16"),
		at("tn_quiet", "10.2.0.0/16"),
	)
	hostEnd, machineEnd := wirePair()
	f, err := New(Options{
		Device:        hostEnd,
		Carriers:      carrierSet{"tn_busy": busy, "tn_quiet": quiet},
		MTU:           testMTU,
		Table:         table,
		SessionBudget: 1,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("build the fabric: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	m := newMachine(t, machineEnd)

	ctx := dialCtx(t)
	// The first flow claims the busy connection's whole budget and holds it open.
	holding, err := m.dialTCP(ctx, netip.MustParseAddrPort("10.1.0.5:5432"))
	if err != nil {
		t.Fatalf("dial the busy network: %v", err)
	}
	defer holding.Close()
	greeted(t, holding, "busy")
	waitFor(t, func() bool { return f.Status("wire").Counters["tn_busy"].Holding == 1 })

	// A second flow to the same connection is refused...
	refusedCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := m.dialTCP(refusedCtx, netip.MustParseAddrPort("10.1.0.6:5432")); err == nil {
		conn.Close()
		t.Error("a second flow was carried past the connection's budget")
	}

	// ...and the other connection is unaffected, which is the assertion that matters.
	other, err := m.dialTCP(ctx, netip.MustParseAddrPort("10.2.0.5:5432"))
	if err != nil {
		t.Fatalf("the other network became unreachable: %v", err)
	}
	defer other.Close()
	greeted(t, other, "quiet")
}

// Bytes are counted per connection and in both directions, because "which network is this
// traffic on" is the question a hub of several networks has to answer and one machine-wide
// total cannot.
func TestTrafficIsCountedAgainstTheConnectionThatCarriedIt(t *testing.T) {
	office := &recordingCarrier{to: echoServer(t, "office")}
	table := tableOf(t, at("tn_office", "10.1.0.0/16"))
	f, m := fabricUnder(t, table, carrierSet{"tn_office": office}, nil)

	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("10.1.2.3:5432"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	greeted(t, conn, "office")
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatalf("send: %v", err)
	}
	greeted(t, conn, "hello")

	waitFor(t, func() bool {
		counted := f.Status("wire").Counters["tn_office"]
		return counted.Flows == 1 && counted.Sent >= 5 && counted.Received >= uint64(len("office")+len("hello"))
	})
}

// The status is what the dashboard renders, so every part of it a person acts on is asserted
// here: an interface that is up, what it carries, and where each network is reached.
func TestTheStatusSaysWhichNetworkIsReachedWhere(t *testing.T) {
	table := tableOf(t,
		at("tn_prod", "10.1.0.0/16"),
		moved("tn_staging", "10.1.0.0/16", "198.18.0.0/16"),
	)
	f, _ := fabricUnder(t, table, carrierSet{}, nil)

	status := f.Status("apptail0")
	if !status.Running {
		t.Error("the interface reports itself as not carrying traffic")
	}
	if status.Interface != "apptail0" || status.MTU != testMTU {
		t.Errorf("status = %+v, want the interface name and MTU it was built with", status)
	}
	if len(status.Routes) != 2 {
		t.Errorf("routes = %v, want both ranges the machine must send here", status.Routes)
	}
	if len(status.Networks) != 2 {
		t.Fatalf("networks = %+v, want one entry per connected network", status.Networks)
	}
	for _, network := range status.Networks {
		if network.TunnelID == "tn_staging" && !network.Moved() {
			t.Errorf("the moved network is reported as reached at its own addresses: %+v", network)
		}
	}
}

// An interface that goes away underneath the process is a whole-machine failure -- every
// program reaching a private network stops working -- so the reason has to survive as
// something a person can be shown.
func TestAnInterfaceThatGoesAwayIsReportedRatherThanRetriedAround(t *testing.T) {
	hostEnd, _ := wirePair()
	f, err := New(Options{
		Device:   hostEnd,
		Carriers: carrierSet{},
		MTU:      testMTU,
		Table:    tableOf(t, at("tn_office", "10.1.0.0/16")),
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("build the fabric: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	// A read failure that is not a close: the interface is still there and answering with
	// an error, which is what a network interface removed from under the process does.
	hostEnd.fail(errors.New("no such device"))

	select {
	case <-f.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the fabric kept running with an interface that had stopped answering")
	}
	status := f.Status("wire")
	if status.Running {
		t.Error("the status still reports the interface as carrying traffic")
	}
	if !strings.Contains(status.Error, "no such device") {
		t.Errorf("status error = %q, which does not carry the reason the interface stopped", status.Error)
	}
}

// Closing twice is what a shutdown does when something else has already failed, and it must
// not be the thing that brings the process down.
func TestClosingTheFabricTwiceIsSafe(t *testing.T) {
	f, _ := fabricUnder(t, tableOf(t, at("tn_office", "10.1.0.0/16")), carrierSet{}, nil)

	if err := f.Close(); err != nil {
		t.Fatalf("closing the fabric: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the fabric a second time: %v", err)
	}
}

// The switch a person asks for. A flow open through one connection when its address is
// handed to another has to end: leaving it running is traffic still leaving through the
// connection they took away, and a browser holding one socket open sees no switch at all
// until it happens to open a new one.
func TestAFlowIsEndedWhenItsAddressMovesToAnotherConnection(t *testing.T) {
	here := &recordingCarrier{to: echoServer(t, "here")}
	there := &recordingCarrier{to: echoServer(t, "there")}
	carriers := carrierSet{"tn_here": here, "tn_there": there}
	f, m := fabricUnder(t, tableOf(t, at("tn_here", "10.1.0.0/16")), carriers, nil)

	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("10.1.2.3:5432"))
	if err != nil {
		t.Fatalf("dial 10.1.2.3:5432: %v", err)
	}
	defer conn.Close()
	greeted(t, conn, "here")

	f.SetTable(tableOf(t, at("tn_there", "10.1.0.0/16")), nil)

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	// The deadline is the failure this asserts against, not the assertion: a flow left running
	// reads nothing either, and a test satisfied by the deadline expiring would pass over the
	// bug it exists for.
	n, err := conn.Read(make([]byte, 32))
	var timeout net.Error
	switch {
	case err == nil:
		t.Fatalf("the flow was still open after its address moved, and read %d bytes", n)
	case errors.As(err, &timeout) && timeout.Timeout():
		t.Fatalf("the flow was left open after its address moved: %v", err)
	}
	// And the flow it was holding was given back, so the connection it left does not go on
	// counting it against its budget.
	waitFor(t, func() bool { return f.Status("wire").Counters["tn_here"].Holding == 0 })

	// The next flow to the same address is answered by the connection that now carries it,
	// which is the half that already worked and must go on working.
	next, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("10.1.2.3:5432"))
	if err != nil {
		t.Fatalf("dial the address again after the switch: %v", err)
	}
	defer next.Close()
	greeted(t, next, "there")
}

// The addressing is replaced on every pass over the connections, and almost every pass
// changes nothing. A flow the new table answers the same way has to keep running, or the
// interface drops every connection on it every few seconds.
func TestAFlowTheAddressingStillAnswersTheSameWayKeepsRunning(t *testing.T) {
	office := &recordingCarrier{to: echoServer(t, "office")}
	other := &recordingCarrier{to: echoServer(t, "other")}
	carriers := carrierSet{"tn_office": office, "tn_other": other}
	f, m := fabricUnder(t, tableOf(t, at("tn_office", "10.1.0.0/16")), carriers, nil)

	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("10.1.2.3:5432"))
	if err != nil {
		t.Fatalf("dial 10.1.2.3:5432: %v", err)
	}
	defer conn.Close()
	greeted(t, conn, "office")

	// Another network arrives; this flow's own address is answered exactly as before.
	f.SetTable(tableOf(t,
		at("tn_office", "10.1.0.0/16"),
		at("tn_other", "10.2.0.0/16"),
	), nil)

	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatalf("send on the flow after an unrelated change: %v", err)
	}
	greeted(t, conn, "hello")
}

// waitFor polls a condition that a goroutine somewhere else makes true.
func waitFor(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the condition never became true")
}

// The whole of fail-closed. When the connections chosen for internet traffic are all down the
// interface goes on claiming the traffic and refuses it, rather than letting the machine send
// it out over its own network -- which is the one outcome choosing connections for internet
// traffic exists to prevent.
func TestInternetTrafficIsHeldRatherThanSentOutOverThisMachineWhenNoChosenConnectionRuns(t *testing.T) {
	table := tableOf(t, Mapping{TunnelID: Blocked, Prefix: p("0.0.0.0/0")})
	f, m := fabricUnder(t, table, carrierSet{}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := m.dialTCP(ctx, netip.MustParseAddrPort("93.184.216.34:443")); err == nil {
		conn.Close()
		t.Fatal("internet traffic was carried while none of the connections chosen for it was running")
	}
	if refused := f.Status("wire").Counters[Blocked].Refused; refused == 0 {
		t.Error("the refusal was not counted, so nothing anywhere says the traffic was held")
	}
}

// And it says why in a sentence a person can act on, rather than failing as an address nothing
// carries -- which reads as a misconfiguration instead of as the connections being down.
func TestHeldInternetTrafficSaysWhyItWasHeld(t *testing.T) {
	table := tableOf(t, Mapping{TunnelID: Blocked, Prefix: p("0.0.0.0/0")})
	f, _ := fabricUnder(t, table, carrierSet{}, nil)

	_, carrier, err := f.destinationOf(netip.MustParseAddrPort("93.184.216.34:443"), "tcp")
	if err == nil {
		t.Fatal("an address on the blocked route was given a way out")
	}
	if carrier != nil {
		t.Error("a carrier was returned for traffic that is meant to be held")
	}
	for _, want := range []string{"chosen for internet traffic", "none of them is running", "this machine's own network"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the reason is %q, which does not say %q", err, want)
		}
	}
}

// A connection joining the ones carrying internet traffic must not disturb what is already
// running. Re-deciding every flow on every pass would cut live connections every time any
// connection came back, which is the failure spread has to not have.
func TestAConnectionJoiningTheOnesCarryingInternetTrafficLeavesRunningFlowsAlone(t *testing.T) {
	first := &recordingCarrier{to: echoServer(t, "first")}
	second := &recordingCarrier{to: echoServer(t, "second")}
	carriers := carrierSet{"tn_first": first, "tn_second": second}
	f, m := fabricUnder(t, tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")}), carriers, nil)

	// This destination is one the joining connection wins outright, so a flow re-decided
	// against the new set rather than checked for membership would be cut here.
	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("93.184.0.34:443"))
	if err != nil {
		t.Fatalf("dial 93.184.0.34:443: %v", err)
	}
	defer conn.Close()
	greeted(t, conn, "first")

	f.SetTable(tableOf(t, Mapping{Members: []string{"tn_first", "tn_second"}, Prefix: p("0.0.0.0/0")}), nil)

	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatalf("send on the flow after another connection joined: %v", err)
	}
	greeted(t, conn, "hello")
}

// The other half: a connection taken out of the set stops carrying what it held. Traffic still
// leaving through a connection the user removed is the change not having happened.
func TestAFlowEndsWhenItsConnectionStopsCarryingInternetTraffic(t *testing.T) {
	first := &recordingCarrier{to: echoServer(t, "first")}
	second := &recordingCarrier{to: echoServer(t, "second")}
	carriers := carrierSet{"tn_first": first, "tn_second": second}
	f, m := fabricUnder(t, tableOf(t, Mapping{Members: []string{"tn_first"}, Prefix: p("0.0.0.0/0")}), carriers, nil)

	conn, err := m.dialTCP(dialCtx(t), netip.MustParseAddrPort("93.184.216.34:443"))
	if err != nil {
		t.Fatalf("dial 93.184.216.34:443: %v", err)
	}
	defer conn.Close()
	greeted(t, conn, "first")

	f.SetTable(tableOf(t, Mapping{Members: []string{"tn_second"}, Prefix: p("0.0.0.0/0")}), nil)

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	n, err := conn.Read(make([]byte, 32))
	var timeout net.Error
	switch {
	case err == nil:
		t.Fatalf("the flow was still open on a connection that no longer carries internet traffic, and read %d bytes", n)
	case errors.As(err, &timeout) && timeout.Timeout():
		t.Fatalf("the flow was left open on a connection that no longer carries internet traffic: %v", err)
	}
}

// The seed reaches the decision. Without it every machine would spread the same destinations
// the same way across the same providers, which is a pattern worth not having.
func TestTheSeedThisMachineWasBuiltWithDecidesWhereADestinationGoes(t *testing.T) {
	table := tableOf(t, Mapping{Members: []string{"tn_a", "tn_b", "tn_c", "tn_d"}, Prefix: p("0.0.0.0/0")})
	seeded := func(seed uint64) *Fabric {
		hostEnd, _ := wirePair()
		f, err := New(Options{
			Device:   hostEnd,
			Carriers: carrierSet{},
			MTU:      testMTU,
			Table:    table,
			Seed:     seed,
			Logger:   slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatalf("build the fabric: %v", err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	mine, theirs := seeded(1), seeded(2)

	differed := false
	for i := range 64 {
		at := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 7}), 443)
		here, _, _ := mine.destinationOf(at, "tcp")
		there, _, _ := theirs.destinationOf(at, "tcp")
		if here.TunnelID != there.TunnelID {
			differed = true
			break
		}
	}
	if !differed {
		t.Error("64 destinations landed identically on two machines with different seeds, so the seed reaches nothing")
	}
}
