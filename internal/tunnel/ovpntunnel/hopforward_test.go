// SPDX-License-Identifier: MIT

package ovpntunnel

// One OpenVPN connection carried inside another: what openvpn is pointed at, what the stream
// it opens there is carried to, and what happens when the connection carrying it cannot.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// fakeCarrier is a connection this one's packets travel inside. It records what it was asked
// to reach and answers with a connection to wherever the test put its server.
type fakeCarrier struct {
	// to is where a dial actually lands, empty for a carrier that cannot reach anything.
	to  string
	err error

	mu    sync.Mutex
	asked []string
}

func (c *fakeCarrier) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	c.asked = append(c.asked, network+" "+address)
	c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", c.to)
}

func (c *fakeCarrier) reached() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.asked...)
}

// echoServer is a stand-in for this connection's own server: it answers with what it was sent,
// which is enough to prove a stream arrived there whole.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the server this connection reaches: %v", err)
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
				io.Copy(conn, conn) //nolint:errcheck // the test reads what arrives; a failure shows there.
			}()
		}
	}()
	return ln.Addr().String()
}

// The whole of what makes a carried connection carried: openvpn is pointed at a listener on
// this machine rather than at its own server, and at a stream rather than at datagrams.
func TestACarriedConnectionIsPointedAtTheListenerCarryingIt(t *testing.T) {
	runner := &fakeOpenVPN{}
	carrier := &fakeCarrier{to: echoServer(t)}
	live := newTunnelWith(t, heldFixture(), CarryNone, runner, func(o *Options) { o.Through = carrier })
	t.Cleanup(func() { live.Close() })

	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}

	runs := runner.runs()
	if len(runs) != 1 {
		t.Fatalf("the privileged side was asked to start %d programs, want 1", len(runs))
	}
	if runs[0].Remote == heldFixture().Remote {
		t.Fatalf("openvpn was pointed at %q, want the listener this connection is carried through "+
			"-- pointed at its own server it dials over this machine's own network, which is the "+
			"one thing a chain exists to stop", runs[0].Remote)
	}
	addr, err := netip.ParseAddrPort(runs[0].Remote)
	if err != nil {
		t.Fatalf("openvpn was pointed at %q, which is not an address and a port: %v", runs[0].Remote, err)
	}
	if !addr.Addr().IsLoopback() {
		t.Errorf("openvpn was pointed at %s, want an address on this machine's loopback", addr)
	}
	if runs[0].Proto != config.OpenVPNProtoTCP {
		t.Errorf("openvpn was started on the %q transport, want %q -- what is carried is a stream",
			runs[0].Proto, config.OpenVPNProtoTCP)
	}
}

// A connection that is not carried is unchanged: it dials its own server, over the transport
// its settings name.
func TestAConnectionThatIsNotCarriedDialsItsOwnServer(t *testing.T) {
	runner := &fakeOpenVPN{}
	live := newTunnel(t, heldFixture(), CarryNone, runner)
	t.Cleanup(func() { live.Close() })

	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}

	runs := runner.runs()
	if len(runs) != 1 {
		t.Fatalf("the privileged side was asked to start %d programs, want 1", len(runs))
	}
	if runs[0].Remote != heldFixture().Remote {
		t.Errorf("openvpn was pointed at %q, want its own server %q", runs[0].Remote, heldFixture().Remote)
	}
	if runs[0].Proto != config.OpenVPNProtoUDP {
		t.Errorf("openvpn was started on the %q transport, want the stored %q", runs[0].Proto, config.OpenVPNProtoUDP)
	}
}

// The search for a server the settings do not quite describe tries the ports an administrator
// picks when nothing forced another choice. Through a carrier those ports are on this machine,
// so a carried connection searches the key material and nothing else.
func TestACarriedConnectionIsOnlyEverStartedAtTheListenerCarryingIt(t *testing.T) {
	base := Run{Remote: "127.0.0.1:41080", Proto: config.OpenVPNProtoTCP, TLSCrypt: "key"}

	carried := attemptsFor(base, true)
	if len(carried) == 0 {
		t.Fatal("a carried connection has no way at all to be started")
	}
	for _, a := range carried {
		if a.run.Remote != base.Remote {
			t.Errorf("an attempt dials %q, want the listener at %q -- everywhere else is this machine",
				a.run.Remote, base.Remote)
		}
		if a.run.Proto != config.OpenVPNProtoTCP {
			t.Errorf("an attempt uses the %q transport, want %q", a.run.Proto, config.OpenVPNProtoTCP)
		}
	}
	// The key material is still searched: filing a key under the wrong directive is a copying
	// mistake, and being carried neither causes it nor cures it.
	if len(carried) < 2 {
		t.Errorf("a carried connection has %d attempts, want the key material still searched", len(carried))
	}

	// And a connection dialling its own server still searches the addresses, which is what
	// makes the restriction above a restriction rather than the only behaviour there is.
	if direct := attemptsFor(base, false); len(direct) <= len(carried) {
		t.Errorf("a connection dialling its own server has %d attempts and a carried one %d, "+
			"want more for the one whose address can be searched", len(direct), len(carried))
	}
}

// The point of the whole arrangement: what openvpn sends to the listener arrives at its own
// server, and it gets there through the connection carrying this one rather than over this
// machine's own network.
func TestTheStreamAConnectionOpensIsCarriedToItsServer(t *testing.T) {
	carrier := &fakeCarrier{to: echoServer(t)}
	forward, err := startHopForward("tn_test01", "vpn.example.com:1194", carrier, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("open the listener this connection reaches its server through: %v", err)
	}
	t.Cleanup(func() { forward.Close() })

	conn, err := net.Dial("tcp", forward.addr())
	if err != nil {
		t.Fatalf("dial the listener: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("bound the exchange: %v", err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write to the listener: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read what the server answered: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("the server answered %q, want %q", got, "hello")
	}

	reached := carrier.reached()
	if len(reached) != 1 || reached[0] != "tcp vpn.example.com:1194" {
		t.Errorf("the connection carrying this one was asked for %v, want one stream to "+
			"\"tcp vpn.example.com:1194\" -- the server's own name, resolved inside the carrier", reached)
	}
}

// A carrier that cannot reach the server gives the stream back rather than holding it open.
// openvpn treats that as the server refusing and tries again, which is the same thing it does
// when a server is unreachable -- and while this connection is carried, it is.
func TestAStreamIsEndedWhenTheConnectionCarryingItCannotReachTheServer(t *testing.T) {
	carrier := &fakeCarrier{err: errors.New("this connection is not carrying traffic")}
	forward, err := startHopForward("tn_test01", "vpn.example.com:1194", carrier, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("open the listener this connection reaches its server through: %v", err)
	}
	t.Cleanup(func() { forward.Close() })

	conn, err := net.Dial("tcp", forward.addr())
	if err != nil {
		t.Fatalf("dial the listener: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("bound the exchange: %v", err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("the stream was held open rather than ended: %v", err)
	}
}

// The listener exists for exactly as long as the connection does. One left behind would be a
// way into the chain outliving the connection it belonged to.
func TestTheListenerIsClosedWithTheConnectionItCarried(t *testing.T) {
	runner := &fakeOpenVPN{}
	carrier := &fakeCarrier{to: echoServer(t)}
	live := newTunnelWith(t, heldFixture(), CarryNone, runner, func(o *Options) { o.Through = carrier })
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	at := runner.runs()[0].Remote

	if err := live.Close(); err != nil {
		t.Fatalf("close the connection: %v", err)
	}

	conn, err := net.Dial("tcp", at)
	if err == nil {
		conn.Close()
		t.Fatalf("the listener at %s is still accepting after the connection closed", at)
	}
}

// A carried connection's own packets do not leave through this machine's own network, so it
// holds nothing out of the interface app-tail routes everything into. The address openvpn
// reports for a carried connection is the listener, and anchoring that would punch a hole in
// the one-interface mode for an address nothing dials.
func TestACarriedConnectionAnchorsNothingOnThisMachinesOwnNetwork(t *testing.T) {
	server := netip.MustParseAddr("203.0.113.9")

	direct := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	direct.mu.Lock()
	direct.last.Server = server
	direct.mu.Unlock()
	if got := direct.Anchors(); len(got) != 1 || got[0] != server {
		t.Errorf("a connection dialling its own server anchors %v, want %v -- those packets do "+
			"leave over this machine's own network", got, []netip.Addr{server})
	}

	carried := newTunnelWith(t, heldFixture(), CarryNone, &fakeOpenVPN{},
		func(o *Options) { o.Through = &fakeCarrier{} })
	carried.mu.Lock()
	carried.last.Server = server
	carried.mu.Unlock()
	if got := carried.Anchors(); len(got) != 0 {
		t.Errorf("a carried connection anchors %v, want nothing", got)
	}
}

// Everything the listener cannot be opened for, refused where it is asked for rather than
// left to a connection that starts and reaches nothing.
func TestAListenerThisPackageCannotCarryAStreamThroughIsRefused(t *testing.T) {
	if _, err := startHopForward("tn_test01", "vpn.example.com:1194", nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a listener with nothing carrying it was opened")
	}
	if _, err := startHopForward("tn_test01", "vpn.example.com", &fakeCarrier{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a listener for a server with no port was opened")
	}
}
