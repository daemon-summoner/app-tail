// SPDX-License-Identifier: MIT

package wgtunnel

// Two real WireGuard devices in this process, talking to each other over the loopback
// interface.
//
// It is a real handshake with real keys, real encryption and real packets: the only thing
// missing is a network between them. That makes it a far better test than a fake -- a wrong
// key, a wrong address, a configuration line that never reached the device and a stack that
// cannot carry a connection all fail here, and none of them would fail against a mock.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wgconn "github.com/tailscale/wireguard-go/conn"
	wgdevice "github.com/tailscale/wireguard-go/device"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// The addresses the two ends hold inside the test network. They are documentation range, so
// a packet that escaped this process would go nowhere rather than somewhere real.
var (
	serverAddr = netip.MustParseAddr("10.9.0.1")
	clientAddr = netip.MustParseAddr("10.9.0.2")
	testNet    = netip.MustParsePrefix("10.9.0.0/24")
)

// keyPair generates one end's keys, clamped the way WireGuard clamps them.
func keyPair(t *testing.T) (private, public string) {
	t.Helper()
	var raw [config.WireGuardKeyLen]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	private = base64.StdEncoding.EncodeToString(raw[:])
	public = config.WireGuardTunnel{PrivateKey: private}.PublicKey()
	if public == "" {
		t.Fatalf("the generated key %q has no public half", private)
	}
	return private, public
}

func hexKeyOf(t *testing.T, key string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("the test's own key is not base64: %v", err)
	}
	return hex.EncodeToString(raw)
}

// startServer brings up the far end: a WireGuard device on loopback with its own network
// stack, holding serverAddr and expecting the client's key. It answers on an ephemeral port,
// which it reports.
func startServer(t *testing.T, serverPrivate, clientPublic string) (*netStack, uint16) {
	t.Helper()
	ns, err := newNetStack([]netip.Addr{serverAddr}, config.DefaultWireGuardMTU)
	if err != nil {
		t.Fatalf("build the server's network stack: %v", err)
	}
	dev := wgdevice.NewDevice(ns, wgconn.NewStdNetBind(), &wgdevice.Logger{
		Verbosef: wgdevice.DiscardLogf,
		Errorf:   wgdevice.DiscardLogf,
	})
	t.Cleanup(dev.Close)

	uapi := "private_key=" + hexKeyOf(t, serverPrivate) + "\n" +
		"public_key=" + hexKeyOf(t, clientPublic) + "\n" +
		"allowed_ip=" + clientAddr.String() + "/32\n"
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("configure the server: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("start the server: %v", err)
	}

	report, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("ask the server what port it bound: %v", err)
	}
	var port uint16
	for _, line := range strings.Split(report, "\n") {
		value, ok := strings.CutPrefix(line, "listen_port=")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			t.Fatalf("the server reported the port %q: %v", value, err)
		}
		port = uint16(n)
	}
	if port == 0 {
		t.Fatalf("the server bound no port:\n%s", report)
	}
	return ns, port
}

// clientConfig is the connection's stored settings, pointed at a server on this port.
func clientConfig(clientPrivate, serverPublic string, port uint16) config.WireGuardTunnel {
	return config.WireGuardTunnel{
		PrivateKey: clientPrivate,
		Addresses:  []netip.Prefix{netip.PrefixFrom(clientAddr, 24)},
		Peer: config.WireGuardPeer{
			PublicKey:  serverPublic,
			Endpoint:   netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String(),
			AllowedIPs: []netip.Prefix{testNet},
			// One second, so the two ends keep talking without the test waiting on
			// WireGuard's ordinary multi-minute timers.
			KeepaliveSec: 1,
		},
	}
}

// startClient brings up the connection under test and takes it down with the test.
func startClient(t *testing.T, held config.WireGuardTunnel) tunnel.Tunnel {
	t.Helper()
	return startClientWith(t, Options{ID: "tn_test", Held: held, Logger: slog.New(slog.DiscardHandler)})
}

// startClientWith is the same for a test that has to reach past the stored settings -- to
// the clock, the resolver, or what tells the connection this machine has moved.
func startClientWith(t *testing.T, opts Options) tunnel.Tunnel {
	t.Helper()
	client := New(opts)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing the connection failed: %v", err)
		}
	})
	if err := client.Start(t.Context()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	return client
}

// waitLimit bounds every wait in this file. Two real WireGuard devices encrypting real
// packets is heavy work, and the whole suite runs this package alongside every other one,
// so a handshake or a datagram can be many seconds late on a loaded machine with nothing
// wrong with it. It is still a bound: a connection that never comes up fails here rather
// than hanging.
const waitLimit = 90 * time.Second

// waitForState waits for the connection to report a state, driven by its own events rather
// than by sleeping.
func waitForState(t *testing.T, held tunnel.Tunnel, want tunnel.State) {
	t.Helper()
	deadline := time.After(waitLimit)
	for {
		if got := held.Status().State; got == want {
			return
		}
		select {
		case <-held.Events():
		case <-time.After(pollInterval):
		case <-deadline:
			t.Fatalf("the connection reports %q: %s, want %q",
				held.Status().State, held.Status().Detail, want)
		}
	}
}

// retryWhileTimingOut runs a step until it succeeds, fails for a reason other than a
// timeout, or ctx ends.
//
// A lookup inside the network travels over UDP, and Go's resolver gives up after its own
// two attempts: on a loaded machine both can fall in the same busy moment and the answer
// arrives after it stopped listening. That is a dropped datagram rather than a name that
// does not resolve, and only asking again separates the two.
func retryWhileTimingOut(ctx context.Context, step func() error) error {
	for {
		err := step()
		var timeout net.Error
		if err == nil || !errors.As(err, &timeout) || !timeout.Timeout() {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(pollInterval):
		}
	}
}

// The whole point of the phase: a program on this machine reaching a service inside a
// WireGuard network, with no interface, no route and no privilege anywhere in the path.
func TestAConnectionInsideTheNetworkCrossesTwoRealDevices(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))

	// A service inside the network: it lives on the server's stack, so nothing outside this
	// process can reach it and the client can only reach it through the tunnel.
	listener, err := server.listenTCP(netip.AddrPortFrom(serverAddr, 8080))
	if err != nil {
		t.Fatalf("listen inside the network: %v", err)
	}
	defer listener.Close()
	go echoOnce(listener)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, "tcp", "10.9.0.1:8080")
	if err != nil {
		t.Fatalf("dial a service inside the network: %v", err)
	}
	defer conn.Close()

	const sent = "hello across the tunnel"
	if got := echoThrough(t, conn, sent); got != sent {
		t.Errorf("the service answered %q, want %q", got, sent)
	}
}

// A connection that has completed a handshake must say so: the connections screen reports
// exactly this, and a working tunnel stuck on "connecting" is what has someone re-entering
// keys that were right all along.
func TestAConnectionThatHandshakesReportsItselfConnected(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))

	waitForState(t, client, tunnel.StateConnected)
}

// What the connection reports about itself once traffic has actually crossed it. This is the
// only figure on the connections screen that separates a connection that is up and working
// from one that is up and carrying nothing -- the state word says "connected" for both.
func TestAConnectionReportsWhatItHasCarried(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))
	waitForState(t, client, tunnel.StateConnected)

	listener, err := server.listenTCP(netip.AddrPortFrom(serverAddr, 8080))
	if err != nil {
		t.Fatalf("listen inside the network: %v", err)
	}
	defer listener.Close()
	go echoOnce(listener)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, "tcp", "10.9.0.1:8080")
	if err != nil {
		t.Fatalf("dial a service inside the network: %v", err)
	}
	defer conn.Close()
	const sent = "hello across the tunnel"
	if got := echoThrough(t, conn, sent); got != sent {
		t.Fatalf("the service answered %q, want %q", got, sent)
	}

	metered, ok := client.(tunnel.Metered)
	if !ok {
		t.Fatal("a WireGuard connection does not report what it carried, so the screen has " +
			"nothing to tell a working connection from a dead one")
	}
	// The status is republished on the watcher's own schedule, and the totals travel with it.
	var carried tunnel.Carried
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		carried = metered.Carried()
		if carried.Up > 0 && carried.Down > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if carried.Up <= 0 || carried.Down <= 0 {
		t.Fatalf("the connection reports %d up and %d down after an exchange crossed it, want both counted",
			carried.Up, carried.Down)
	}
	if carried.Since.IsZero() {
		t.Error("the connection reports no moment it was built, so nothing can say how long it has been up")
	}
	if carried.LastHandshake.IsZero() {
		t.Error("the connection reports no handshake though it is connected, which is the one " +
			"fact that tells an idle connection from a gone one")
	}
}

// The failure a wrong configuration actually produces: the device starts, sends handshake
// initiations and is never answered. It has to end up reported as failed rather than as
// connecting forever, because nothing else on screen would ever say the key is wrong.
func TestAServerThatNeverAnswersIsReportedFailedRatherThanConnecting(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, _ := keyPair(t)
	// The server is told about a different client, so it drops this one's handshakes.
	_, strangerPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, strangerPublic)

	// The clock is the test's, so the grace period passes without the test waiting for it:
	// the first reading is what the connection started at, every later one is past the
	// grace. Nothing else in this connection reads the clock.
	base := time.Now()
	var reads atomic.Int64
	client := New(Options{
		ID:     "tn_test",
		Held:   clientConfig(clientPrivate, serverPublic, port),
		Logger: slog.New(slog.DiscardHandler),
		Now: func() time.Time {
			if reads.Add(1) == 1 {
				return base
			}
			return base.Add(handshakeGrace + time.Second)
		},
	})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing the connection failed: %v", err)
		}
	})
	if err := client.Start(t.Context()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}

	waitForState(t, client, tunnel.StateFailed)
	if detail := client.Status().Detail; !strings.Contains(detail, "public key") {
		t.Errorf("the reason given is %q, which does not point at the key or the address", detail)
	}
}

// A connection that was never started is off, which is a state and not a fault: it is what a
// configured connection the user has not switched on reads as everywhere.
func TestAConnectionThatWasNeverStartedIsOffRatherThanBroken(t *testing.T) {
	client := New(Options{
		ID:     "tn_test",
		Held:   config.WireGuardTunnel{PrivateKey: testPrivateKey},
		Logger: slog.New(slog.DiscardHandler),
	})

	if got := client.Status().State; got != tunnel.StateOff {
		t.Errorf("an unstarted connection reports %q, want %q", got, tunnel.StateOff)
	}
	if _, err := client.Dial(t.Context(), "tcp", "10.9.0.1:80"); err == nil {
		t.Error("dialling through a connection that is not up succeeded")
	}
}

// A connection nothing could be done with must fail loudly at the point it is started.
// Reporting it as connecting would leave a network that can never work looking like one that
// is merely slow.
func TestAConnectionWithNothingConfiguredRefusesToStart(t *testing.T) {
	client := New(Options{
		ID:     "tn_test",
		Held:   config.WireGuardTunnel{Addresses: []netip.Prefix{netip.PrefixFrom(clientAddr, 24)}},
		Logger: slog.New(slog.DiscardHandler),
	})
	err := client.Start(t.Context())
	if err == nil {
		t.Fatal("a connection with no keys and no server started")
	}
	if got := client.Status().State; got != tunnel.StateFailed {
		t.Errorf("after refusing to start it reports %q, want %q", got, tunnel.StateFailed)
	}
	if !strings.Contains(client.Status().Detail, err.Error()) {
		t.Errorf("the status detail %q does not carry the reason %q", client.Status().Detail, err)
	}
}

// The server's name is resolved on this machine and nowhere else. A name resolved inside a
// tunnel would point at an address only reachable through the tunnel being brought up.
func TestTheServerNameIsResolvedThroughTheMachineResolver(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)

	held := clientConfig(clientPrivate, serverPublic, port)
	held.Peer.Endpoint = "gateway.example:" + strconv.Itoa(int(port))
	asked := make(chan string, 1)
	client := New(Options{
		ID:     "tn_test",
		Held:   held,
		Logger: slog.New(slog.DiscardHandler),
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			asked <- host
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	t.Cleanup(func() { client.Close() })
	if err := client.Start(t.Context()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}

	select {
	case host := <-asked:
		if host != "gateway.example" {
			t.Errorf("the name looked up was %q, want the server's name", host)
		}
	default:
		t.Fatal("the server's name was never looked up on this machine")
	}
	waitForState(t, client, tunnel.StateConnected)
}

// A server whose name does not resolve is a connection that cannot start, and the reason has
// to name the server: it is the one thing the user can go and check.
func TestAServerNameThatDoesNotResolveIsRefusedByName(t *testing.T) {
	held := clientConfig(testPrivateKey, testPublicKey, 51820)
	held.Peer.Endpoint = "gateway.example:51820"
	client := New(Options{
		ID:     "tn_test",
		Held:   held,
		Logger: slog.New(slog.DiscardHandler),
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("no such host")
		},
	})
	err := client.Start(t.Context())
	if err == nil {
		t.Fatal("a connection whose server does not resolve started")
	}
	if !strings.Contains(err.Error(), "gateway.example") {
		t.Errorf("the refusal is %q, which does not name the server", err)
	}
}

// Roaming, which WireGuard does not do for a client on its own: it only learns a new address
// for a server whose packets reach it, and a server the client can no longer send to sends
// nothing. A laptop that changes network while a name-addressed server also moves is stuck
// dialling an address that answers nowhere until the app is restarted.
//
// Both halves are exercised at once, because both are what "the machine moved" means: the
// socket the device sends from is reopened, and the server's name is looked up again.
func TestAServerThatMovedIsFoundAgainWhenTheMachineMoves(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)

	held := clientConfig(clientPrivate, serverPublic, port)
	held.Peer.Endpoint = "gateway.example:" + strconv.Itoa(int(port))

	// Where the name resolves to. It starts at an address on this machine that nothing is
	// listening on, which is a server that cannot be reached rather than one that refuses.
	var answer atomic.Value
	answer.Store(netip.MustParseAddr("127.0.0.2"))
	links := make(chan struct{}, 1)
	// The test's clock, as in the never-answers case above: the grace period passes without
	// the test waiting out twenty seconds of it, and a handshake once the server is found is
	// still recent against it.
	base := time.Now()
	var reads atomic.Int64
	client := startClientWith(t, Options{
		ID:     "tn_test",
		Held:   held,
		Logger: slog.New(slog.DiscardHandler),
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{answer.Load().(netip.Addr)}, nil
		},
		LinkChanges: links,
		Now: func() time.Time {
			if reads.Add(1) == 1 {
				return base
			}
			return base.Add(handshakeGrace + time.Second)
		},
	})
	waitForState(t, client, tunnel.StateFailed)

	answer.Store(netip.MustParseAddr("127.0.0.1"))
	links <- struct{}{}

	waitForState(t, client, tunnel.StateConnected)
}

// Where this connection's own packets go, which the interface mode keeps off the interface.
// A server whose address fell inside a range that interface carries would have its encrypted
// packets routed back into the interface that produced them, and the machine would lose every
// network it has at once.
//
// The address has to be the one being sent to right now rather than the one configured: a
// server addressed by name that moves is followed, and an exclusion left on the old address
// excludes nothing while routing the new one into the loop.
func TestTheAddressThisConnectionSendsToIsTheOneBeingUsedNow(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)

	held := clientConfig(clientPrivate, serverPublic, port)
	held.Peer.Endpoint = "gateway.example:" + strconv.Itoa(int(port))

	var answer atomic.Value
	answer.Store(netip.MustParseAddr("127.0.0.2"))
	links := make(chan struct{}, 1)
	base := time.Now()
	var reads atomic.Int64
	client := New(Options{
		ID:     "tn_test",
		Held:   held,
		Logger: slog.New(slog.DiscardHandler),
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{answer.Load().(netip.Addr)}, nil
		},
		LinkChanges: links,
		Now: func() time.Time {
			if reads.Add(1) == 1 {
				return base
			}
			return base.Add(handshakeGrace + time.Second)
		},
	})
	t.Cleanup(func() { client.Close() })

	anchored, ok := client.(tunnel.Anchored)
	if !ok {
		t.Fatal("this connection does not say where its own packets go, so nothing is kept off the interface")
	}
	// Nothing has been sent anywhere yet, and an address excluded before there is one would
	// be an exclusion for a server this connection is not talking to.
	if got := anchored.Anchors(); len(got) != 0 {
		t.Errorf("a connection that was never started sends to %v, want nowhere", got)
	}

	if err := client.Start(t.Context()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	waitForState(t, client, tunnel.StateFailed)
	if got := anchored.Anchors(); len(got) != 1 || got[0] != netip.MustParseAddr("127.0.0.2") {
		t.Fatalf("the connection sends to %v, want the resolved 127.0.0.2", got)
	}

	answer.Store(netip.MustParseAddr("127.0.0.1"))
	links <- struct{}{}
	waitForState(t, client, tunnel.StateConnected)

	if got := anchored.Anchors(); len(got) != 1 || got[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("after the server moved the connection reports %v, want the 127.0.0.1 it is "+
			"sending to -- the old address excludes nothing and the new one routes into the loop", got)
	}
}

// The packet size the interface mode takes its own from. It is the connection's own setting
// rather than the stack's: a datagram too big for the network it ends up on is dropped with
// nothing reporting why.
func TestTheConnectionReportsThePacketSizeItWasConfiguredWith(t *testing.T) {
	held := clientConfig(testPrivateKey, testPublicKey, 51820)
	held.MTU = 1380

	sized, ok := New(Options{ID: "tn_test", Held: held, Logger: slog.New(slog.DiscardHandler)}).(tunnel.Sized)
	if !ok {
		t.Fatal("this connection states no packet size, so the interface would size itself from nothing")
	}

	if got := sized.MTU(); got != 1380 {
		t.Errorf("MTU() = %d, want the configured 1380", got)
	}
}

// Names inside the network resolve through the resolvers that network publishes, and through
// nothing else. This is what makes a private name reachable at all -- and what keeps a lookup
// for it off this machine's resolver.
func TestNamesResolveThroughTheNetworksOwnResolvers(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	serveNames(t, server, map[string]netip.Addr{"nas.internal.": serverAddr})

	held := clientConfig(clientPrivate, serverPublic, port)
	held.DNS = []netip.Addr{serverAddr}
	client := startClient(t, held)
	waitForState(t, client, tunnel.StateConnected)

	resolving, ok := client.(tunnel.Resolving)
	if !ok {
		t.Fatal("a connection configured with resolvers does not offer name resolution")
	}
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	var lookup tunnel.Lookup
	err := retryWhileTimingOut(ctx, func() error {
		var err error
		lookup, err = resolving.LookupHost(ctx, "nas.internal")
		return err
	})
	if err != nil {
		t.Fatalf("look up a name inside the network: %v", err)
	}
	if len(lookup.Addrs) != 1 || lookup.Addrs[0] != serverAddr {
		t.Errorf("the name resolved to %v, want [%s]", lookup.Addrs, serverAddr)
	}
}

// Dialling a name, which is what everything above this actually does: a forward or a proxy
// is given "nas.internal:8080", and the lookup and the dial have to happen inside the same
// network or the name is answered by whatever this machine resolves with.
func TestAServiceInsideTheNetworkIsReachedByName(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	serveNames(t, server, map[string]netip.Addr{"nas.internal.": serverAddr})

	listener, err := server.listenTCP(netip.AddrPortFrom(serverAddr, 8080))
	if err != nil {
		t.Fatalf("listen inside the network: %v", err)
	}
	defer listener.Close()
	go echoOnce(listener)

	held := clientConfig(clientPrivate, serverPublic, port)
	held.DNS = []netip.Addr{serverAddr}
	client := startClient(t, held)
	waitForState(t, client, tunnel.StateConnected)

	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	var conn net.Conn
	err = retryWhileTimingOut(ctx, func() error {
		var err error
		conn, err = client.Dial(ctx, "tcp", "nas.internal:8080")
		return err
	})
	if err != nil {
		t.Fatalf("dial a name inside the network: %v", err)
	}
	defer conn.Close()
	if got := echoThrough(t, conn, "hello"); got != "hello" {
		t.Errorf("the service answered %q, want what was sent", got)
	}
}

// The other direction, which is what a forward that publishes something to the network
// needs: this device holds an address inside it, and something there can open a connection
// to it.
func TestSomethingInsideTheNetworkCanReachThisDevice(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))
	waitForState(t, client, tunnel.StateConnected)

	listener, err := client.Listen("tcp", 9090)
	if err != nil {
		t.Fatalf("listen on this device inside the network: %v", err)
	}
	defer listener.Close()
	go echoOnce(listener)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, err := server.dial(ctx, "tcp", netip.AddrPortFrom(clientAddr, 9090))
	if err != nil {
		t.Fatalf("reach this device from inside the network: %v", err)
	}
	defer conn.Close()
	if got := echoThrough(t, conn, "inbound"); got != "inbound" {
		t.Errorf("this device answered %q, want what was sent", got)
	}
}

// The same for datagrams, which is what a DNS forward inside the network is.
func TestSomethingInsideTheNetworkCanSendThisDeviceADatagram(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))
	waitForState(t, client, tunnel.StateConnected)

	here, err := client.ListenPacket("udp", 9091)
	if err != nil {
		t.Fatalf("receive datagrams on this device inside the network: %v", err)
	}
	defer here.Close()

	sender, err := server.dial(t.Context(), "udp", netip.AddrPortFrom(clientAddr, 9091))
	if err != nil {
		t.Fatalf("send to this device from inside the network: %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("ping")); err != nil {
		t.Fatalf("send the datagram: %v", err)
	}

	if err := here.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set a deadline on the receiving socket: %v", err)
	}
	buf := make([]byte, 16)
	n, from, err := here.ReadFrom(buf)
	if err != nil {
		t.Fatalf("receive the datagram: %v", err)
	}
	if got := string(buf[:n]); got != "ping" {
		t.Errorf("the datagram carried %q, want what was sent", got)
	}
	if !strings.HasPrefix(from.String(), serverAddr.String()) {
		t.Errorf("the datagram came from %s, want the sender's address inside the network", from)
	}
}

// A connection holds addresses of one family here, so asking it to listen on the other is a
// request it cannot honour. Answering with a socket bound to nothing in particular would be
// a listener whose network nobody can name.
func TestListeningForAFamilyThisConnectionDoesNotHoldIsRefused(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))

	if _, err := client.Listen("tcp6", 9090); err == nil {
		t.Error("a connection holding only IPv4 addresses listened on IPv6")
	}
	if _, err := client.ListenPacket("udp6", 9091); err == nil {
		t.Error("a connection holding only IPv4 addresses received datagrams on IPv6")
	}
}

// Where a destination goes, decided without dialling it -- which is what a permission check
// asks before it lets anything through, and what the registry asks to pick a connection.
func TestAskingWhereADestinationGoesWithoutDiallingIt(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	serveNames(t, server, map[string]netip.Addr{"nas.internal.": serverAddr})

	held := clientConfig(clientPrivate, serverPublic, port)
	held.DNS = []netip.Addr{serverAddr}
	client := startClient(t, held)
	waitForState(t, client, tunnel.StateConnected)

	asker, ok := client.(tunnel.Reaching)
	if !ok {
		t.Fatal("a connection cannot say where a destination goes, so nothing can check a permission against it")
	}
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()

	// An address this connection carries, and a name resolved inside it: both land on the
	// same place, because the name is only a name for it here.
	for _, address := range []string{serverAddr.String() + ":8080", "nas.internal:8080"} {
		var reach tunnel.Reach
		err := retryWhileTimingOut(ctx, func() error {
			var err error
			reach, err = asker.Reach(ctx, "tcp", address)
			return err
		})
		if err != nil {
			t.Fatalf("ask where %s goes: %v", address, err)
		}
		if !reach.Carried {
			t.Errorf("%s is reported as somewhere this connection does not carry", address)
		}
		if want := netip.AddrPortFrom(serverAddr, 8080); reach.Addr != want {
			t.Errorf("%s goes to %s, want %s", address, reach.Addr, want)
		}
	}

	// The family the caller asked for is the family looked up. A tcp4 question answered with
	// an IPv6 address, or the other way round, hands back an address the dial cannot use.
	var reach4 tunnel.Reach
	err := retryWhileTimingOut(ctx, func() error {
		var err error
		reach4, err = asker.Reach(ctx, "tcp4", "nas.internal:8080")
		return err
	})
	if err != nil {
		t.Fatalf("ask where a name goes over IPv4: %v", err)
	}
	if !reach4.Carried || !reach4.Addr.Addr().Is4() {
		t.Errorf("an IPv4 question was answered with %s, carried=%v", reach4.Addr, reach4.Carried)
	}
	if reach6, _ := asker.Reach(ctx, "tcp6", "nas.internal:8080"); reach6.Carried {
		t.Errorf("a network holding no IPv6 addresses answered an IPv6 question with %s", reach6.Addr)
	}

	// An address outside every network this connection carries is not carried, and saying
	// so is not an error: the caller asks each connection in turn.
	reach, err := asker.Reach(ctx, "tcp", "203.0.113.9:443")
	if err != nil {
		t.Fatalf("ask where an address outside the network goes: %v", err)
	}
	if reach.Carried || reach.Addr.IsValid() {
		t.Errorf("an address outside the network is reported carried, at %s", reach.Addr)
	}
}

// This device's own address inside the network is somewhere it carries. Reporting otherwise
// would refuse a forward that publishes a service on this device to the network.
func TestThisDevicesOwnAddressInsideTheNetworkIsCarried(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)

	held := clientConfig(clientPrivate, serverPublic, port)
	// Only the far end is carried, so the answer can come from nowhere but this device's own
	// address: without that arm this is the case that reads as unreachable.
	held.Peer.AllowedIPs = []netip.Prefix{netip.PrefixFrom(serverAddr, 32)}
	client := startClient(t, held)
	waitForState(t, client, tunnel.StateConnected)

	reach, err := client.(tunnel.Reaching).Reach(t.Context(), "tcp", clientAddr.String()+":9090")
	if err != nil {
		t.Fatalf("ask where this device's own address goes: %v", err)
	}
	if !reach.Carried {
		t.Errorf("this device's own address inside the network is reported as somewhere it does not carry")
	}
}

// A name a connection has no way to look up is a destination it does not carry, not a
// fault: with no resolvers there is nothing inside the network to ask, and the caller is
// asking every connection in turn.
func TestANameAConnectionCannotLookUpIsNotCarriedRatherThanAnError(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))
	waitForState(t, client, tunnel.StateConnected)

	reach, err := client.(tunnel.Reaching).Reach(t.Context(), "tcp", "nas.internal:8080")
	if err != nil {
		t.Fatalf("a name a connection with no resolvers cannot look up is an error: %v", err)
	}
	if reach.Carried {
		t.Error("a name that could not be looked up is reported as carried")
	}
}

// A destination that is not a destination is refused by name rather than dialled at some
// address the parse happened to produce.
func TestADestinationThatIsNotAHostAndAPortIsRefused(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)
	client := startClient(t, clientConfig(clientPrivate, serverPublic, port))
	asker := client.(tunnel.Reaching)

	for _, address := range []string{"10.9.0.1", "10.9.0.1:https", "10.9.0.1:70000"} {
		if _, err := asker.Reach(t.Context(), "tcp", address); err == nil {
			t.Errorf("%q was accepted as a destination", address)
		}
		if _, err := client.Dial(t.Context(), "tcp", address); err == nil {
			t.Errorf("%q was dialled", address)
		}
	}
	if _, err := client.Dial(t.Context(), "sctp", serverAddr.String()+":8080"); err == nil {
		t.Error("a connection dialled a protocol it does not carry")
	}
}

// Nothing works before the connection is up, and every way in says so rather than
// dereferencing a stack that was never built.
func TestNothingIsReachableBeforeTheConnectionIsUp(t *testing.T) {
	held := clientConfig(testPrivateKey, testPublicKey, 51820)
	held.DNS = []netip.Addr{serverAddr}
	client := New(Options{ID: "tn_test", Held: held, Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing the connection failed: %v", err)
		}
	})

	if _, err := client.Dial(t.Context(), "tcp", serverAddr.String()+":8080"); err == nil {
		t.Error("a connection that never started dialled")
	}
	if _, err := client.(tunnel.Reaching).Reach(t.Context(), "tcp", serverAddr.String()+":8080"); err == nil {
		t.Error("a connection that never started said where a destination goes")
	}
	if _, err := client.(tunnel.Resolving).LookupHost(t.Context(), "nas.internal"); err == nil {
		t.Error("a connection that never started looked up a name")
	}
	if _, err := client.Listen("tcp", 9090); err == nil {
		t.Error("a connection that never started listened")
	}
	if _, err := client.ListenPacket("udp", 9091); err == nil {
		t.Error("a connection that never started received datagrams")
	}
}

// A name the network's own resolver does not have is not a failure to look it up: the
// caller asks each network in turn, and the name may exist on the next one. An error here
// would stop that walk at the first network that had never heard of the name.
func TestANameTheNetworksResolverDoesNotHaveIsNotAnError(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	server, port := startServer(t, serverPrivate, clientPublic)
	serveNames(t, server, map[string]netip.Addr{"nas.internal.": serverAddr})

	held := clientConfig(clientPrivate, serverPublic, port)
	held.DNS = []netip.Addr{serverAddr}
	client := startClient(t, held)
	waitForState(t, client, tunnel.StateConnected)

	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	var lookup tunnel.Lookup
	err := retryWhileTimingOut(ctx, func() error {
		var err error
		lookup, err = client.(tunnel.Resolving).LookupHost(ctx, "absent.internal")
		return err
	})
	if err != nil {
		t.Fatalf("a name this network has never heard of is an error: %v", err)
	}
	if len(lookup.Addrs) != 0 {
		t.Errorf("a name this network has never heard of resolved to %v", lookup.Addrs)
	}
}

// The registry keys connections by id and reports what kind each is and what it holds. All
// three are read on every dashboard poll, and a connection that answered for the wrong one
// would be one the registry files under the wrong name.
func TestAConnectionSaysWhatItIsAndWhatItHolds(t *testing.T) {
	held := clientConfig(testPrivateKey, testPublicKey, 51820)
	client := New(Options{ID: "tn_office", Held: held, Logger: slog.New(slog.DiscardHandler)})

	if client.ID() != "tn_office" {
		t.Errorf("the connection calls itself %q, want the id it was built with", client.ID())
	}
	if client.Kind() != tunnel.KindWireGuard {
		t.Errorf("the connection reports itself a %q", client.Kind())
	}
	if addrs := client.Addrs(); len(addrs) != 1 || addrs[0] != clientAddr {
		t.Errorf("the connection holds %v inside the network, want [%s]", addrs, clientAddr)
	}
}

// A lookup that fails after the machine moved leaves the connection alone. Taking it down
// would turn a moment of bad networking -- a resolver that is not up yet on the new network
// -- into something the user has to switch back on by hand.
func TestAServerThatCannotBeLookedUpAgainLeavesTheConnectionUp(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)

	held := clientConfig(clientPrivate, serverPublic, port)
	held.Peer.Endpoint = "gateway.example:" + strconv.Itoa(int(port))
	var resolvable atomic.Bool
	resolvable.Store(true)
	links := make(chan struct{}, 1)
	client := startClientWith(t, Options{
		ID:     "tn_test",
		Held:   held,
		Logger: slog.New(slog.DiscardHandler),
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			if !resolvable.Load() {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		LinkChanges: links,
	})
	waitForState(t, client, tunnel.StateConnected)

	resolvable.Store(false)
	links <- struct{}{}

	// Still up, and still carrying traffic: the device keeps the address it already had.
	waitForState(t, client, tunnel.StateConnected)
}

// echoOnce answers one connection with what it was sent, which is the smallest service that
// proves bytes crossed in both directions.
func echoOnce(listener net.Listener) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	io.Copy(conn, conn)
}

// echoThrough sends a line and reads the answer back.
func echoThrough(t *testing.T, conn net.Conn, send string) string {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set a deadline on the connection: %v", err)
	}
	if _, err := conn.Write([]byte(send)); err != nil {
		t.Fatalf("send through the connection: %v", err)
	}
	buf := make([]byte, len(send))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read the answer back: %v", err)
	}
	return string(buf)
}

// What the device tells wireguard-go about itself. The absent descriptor is the whole
// point of running this way: there is no interface on the machine, which is what makes the
// connection need no privilege, and a device that handed one back would be claiming
// otherwise to every caller that asks.
func TestTheDeviceThisConnectionRunsOnHasNoInterfaceOnTheMachine(t *testing.T) {
	ns, err := newNetStack([]netip.Addr{clientAddr}, config.DefaultWireGuardMTU)
	if err != nil {
		t.Fatalf("build a network stack: %v", err)
	}
	defer ns.Close()

	name, err := ns.Name()
	if err != nil {
		t.Fatalf("asking the device its name failed: %v", err)
	}
	if name == "" {
		t.Error("the device has no name, so its log lines name nothing")
	}
	if f := ns.File(); f != nil {
		t.Errorf("the device reported descriptor %v, want none: nothing on this machine holds one", f)
	}
	if got, err := ns.MTU(); err != nil || got != config.DefaultWireGuardMTU {
		t.Errorf("MTU() = %d (%v), want %d", got, err, config.DefaultWireGuardMTU)
	}
}

// The lookup a connection uses when nothing replaced it. Every other test here hands in its
// own, so without this the one path a real connection actually takes is the one nothing
// exercises -- and a named server is how most WireGuard configurations are written.
//
// localhost, because it is answered from this machine's own configuration on every platform
// this app runs on: the test asks whether the machine's resolver was used, not whether a
// network is reachable.
func TestAServerNamedRatherThanNumberedIsLookedUpOnThisMachine(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	addrs, err := resolveWithMachineResolver(ctx, "localhost")

	if err != nil {
		t.Fatalf("looking up localhost on this machine failed: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("localhost resolved to no addresses")
	}
	for _, addr := range addrs {
		if !addr.IsLoopback() {
			t.Errorf("localhost resolved to %s, which is not a loopback address", addr)
		}
	}
}

// A connection whose network publishes no resolvers does not offer name resolution at all.
// Offering it and failing every call is the shape that has every caller classifying an error
// to find out something the configuration already said.
func TestAConnectionWithNoResolversDoesNotOfferNameResolution(t *testing.T) {
	client := New(Options{
		ID:     "tn_test",
		Held:   config.WireGuardTunnel{PrivateKey: testPrivateKey},
		Logger: slog.New(slog.DiscardHandler),
	})
	if _, ok := client.(tunnel.Resolving); ok {
		t.Error("a connection with no resolvers offers name resolution")
	}
}

// Which networks a connection carries is what decides what is routed through it, and a
// default route is not one of them: it is the statement that everything leaves here, which is
// a separate choice. Reporting it as a network would have this connection claim every address
// in existence.
func TestTheCarriedNetworksExcludeTheDefaultRoute(t *testing.T) {
	client := New(Options{
		ID: "tn_test",
		Held: config.WireGuardTunnel{Peer: config.WireGuardPeer{AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			testNet,
			netip.MustParsePrefix("::/0"),
		}}},
		Logger: slog.New(slog.DiscardHandler),
	})

	routes, err := client.Routes(t.Context())
	if err != nil {
		t.Fatalf("reading the carried networks failed: %v", err)
	}
	if len(routes) != 1 || routes[0] != testNet {
		t.Errorf("the carried networks are %v, want only [%s]", routes, testNet)
	}
}

// Whether a connection can carry this machine's internet traffic is the server's decision,
// made at the far end and visible here only as a default route among the allowed addresses.
// A connection without one drops everything it is handed, so offering it as a choice would
// take the machine off the internet with nothing saying why.
func TestOnlyAConnectionWhoseServerRoutesEverythingCanCarryInternetTraffic(t *testing.T) {
	serverPrivate, serverPublic := keyPair(t)
	clientPrivate, clientPublic := keyPair(t)
	_, port := startServer(t, serverPrivate, clientPublic)

	held := clientConfig(clientPrivate, serverPublic, port)
	held.Peer.AllowedIPs = append(held.Peer.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
	client := startClient(t, held)
	waitForState(t, client, tunnel.StateConnected)

	carrier, ok := client.(tunnel.ExitCarrier)
	if !ok {
		t.Fatal("a WireGuard connection does not answer whether it can carry internet traffic")
	}
	if can, why := carrier.CanCarryExit(t.Context()); !can {
		t.Errorf("a connected peer routing everything cannot carry internet traffic: %s", why)
	}
}

// The same connection without the default route. It is the ordinary case -- a peer that
// carries one network -- and the refusal has to name what is missing, because the fix is at
// the server rather than anywhere in this app.
func TestAConnectionCarryingOneNetworkRefusesToCarryInternetTraffic(t *testing.T) {
	client := New(Options{
		ID: "tn_test",
		Held: config.WireGuardTunnel{Peer: config.WireGuardPeer{
			AllowedIPs: []netip.Prefix{testNet},
		}},
		Logger: slog.New(slog.DiscardHandler),
	})

	carrier, ok := client.(tunnel.ExitCarrier)
	if !ok {
		t.Fatal("a WireGuard connection does not answer whether it can carry internet traffic")
	}
	can, why := carrier.CanCarryExit(t.Context())
	if can {
		t.Fatal("a peer that routes one network was offered as a way out to the internet")
	}
	if !strings.Contains(why, "default route") {
		t.Errorf("the reason is %q, want it to name the default route the server is missing", why)
	}
}

// A connection that would carry it and is not up yet. The two refusals are different things
// to do about: one is a wait, the other is a change at the far end.
func TestAConnectionThatIsNotUpCannotCarryInternetTrafficYet(t *testing.T) {
	client := New(Options{
		ID: "tn_test",
		Held: config.WireGuardTunnel{Peer: config.WireGuardPeer{
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
		Logger: slog.New(slog.DiscardHandler),
	})

	can, why := client.(tunnel.ExitCarrier).CanCarryExit(t.Context())

	if can {
		t.Fatal("a connection that was never started reports itself carrying internet traffic")
	}
	if !strings.Contains(why, "not up") {
		t.Errorf("the reason is %q, want it to say the connection is not up", why)
	}
}

// The two states that only arrive after minutes have passed, decided without waiting for
// them. Both are the difference between a screen that reports what is happening and one that
// reports what was happening when the connection started.
func TestWhatAConnectionIsDoingIsDecidedByItsLastHandshake(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		handshake  time.Time
		ever       bool
		since      time.Duration
		keepalive  int
		wantState  tunnel.State
		wantDetail string
	}{
		{
			name:      "a recent handshake is a working connection",
			handshake: now.Add(-30 * time.Second),
			ever:      true,
			since:     time.Hour,
			keepalive: 25,
			wantState: tunnel.StateConnected,
		},
		{
			name: "keepalive is on and the handshake is older than a session key lives, so " +
				"the server has stopped answering",
			handshake:  now.Add(-10 * time.Minute),
			ever:       true,
			since:      time.Hour,
			keepalive:  25,
			wantState:  tunnel.StateDegraded,
			wantDetail: "10m0s ago",
		},
		{
			name:      "no keepalive and nothing being sent is an idle connection, not a broken one",
			handshake: now.Add(-10 * time.Minute),
			ever:      true,
			since:     time.Hour,
			keepalive: 0,
			wantState: tunnel.StateConnected,
		},
		{
			name:      "no handshake yet and only moments since it started is still connecting",
			ever:      false,
			since:     handshakeGrace - time.Second,
			keepalive: 25,
			wantState: tunnel.StateConnecting,
		},
		{
			name:       "no handshake well past the grace period is a connection that will not work",
			ever:       false,
			since:      handshakeGrace + time.Second,
			keepalive:  25,
			wantState:  tunnel.StateFailed,
			wantDetail: "public key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, detail := stateOf(tc.handshake, tc.ever, tc.since, tc.keepalive, now)
			if state != tc.wantState {
				t.Errorf("it reports %q: %s, want %q", state, detail, tc.wantState)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("the reason given is %q, which does not say %q", detail, tc.wantDetail)
			}
		})
	}
}

// The one fact the whole status rests on, read out of the device's own report. A peer that
// has never handshaked reports zero, which is not a time in 1970 and must not be read as one:
// a connection that never came up would otherwise report itself connected decades ago.
func TestTheLastHandshakeIsReadFromTheDevicesReport(t *testing.T) {
	cases := []struct {
		name   string
		report string
		want   time.Time
		wantOK bool
	}{
		{
			name:   "a peer that has handshaked",
			report: "public_key=abc\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=1\n",
			want:   time.Unix(1700000000, 0),
			wantOK: true,
		},
		{
			name:   "a peer that never has",
			report: "public_key=abc\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n",
			wantOK: false,
		},
		{
			name:   "a device with no peer at all",
			report: "private_key=abc\nlisten_port=51820\n",
			wantOK: false,
		},
		{
			name:   "a value that is not a number",
			report: "last_handshake_time_sec=soon\n",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := lastHandshake(tc.report)
			if ok != tc.wantOK {
				t.Fatalf("it reports the handshake known=%v, want %v", ok, tc.wantOK)
			}
			if ok && !got.Equal(tc.want) {
				t.Errorf("the handshake is read as %s, want %s", got, tc.want)
			}
		})
	}
}

// What the connection has carried, out of the same report the state is read from. Direction
// is the half worth pinning: the device reports per peer from its own point of view, so tx is
// what this machine sent, and a connection that showed a download as an upload would be read
// as a machine sending everything it is in fact receiving.
func TestWhatTheConnectionCarriedIsReadFromTheDevicesReport(t *testing.T) {
	cases := []struct {
		name     string
		report   string
		wantUp   int64
		wantDown int64
	}{
		{
			name:     "a peer that has carried traffic",
			report:   "public_key=abc\ntx_bytes=2048\nrx_bytes=4096\n",
			wantUp:   2048,
			wantDown: 4096,
		},
		{
			// Summed rather than taken from the first peer: this connection holds one today,
			// and a report that ever carries more must not report a fraction of the traffic.
			name:     "a report carrying more than one peer",
			report:   "public_key=abc\ntx_bytes=10\nrx_bytes=20\npublic_key=def\ntx_bytes=5\nrx_bytes=7\n",
			wantUp:   15,
			wantDown: 27,
		},
		{
			name:   "a device that has not moved anything",
			report: "private_key=abc\nlisten_port=51820\n",
		},
		{
			name:   "a total that is not a number",
			report: "tx_bytes=lots\nrx_bytes=more\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up, down := transferred(tc.report)
			if up != tc.wantUp || down != tc.wantDown {
				t.Errorf("the report reads as %d up and %d down, want %d up and %d down",
					up, down, tc.wantUp, tc.wantDown)
			}
		})
	}
}

// serveNames answers a fixed set of names on the server's own address inside the network,
// which is what a resolver published by a private network is.
func serveNames(t *testing.T, server *netStack, zone map[string]netip.Addr) {
	t.Helper()
	conn, err := server.listenPacket(netip.AddrPortFrom(serverAddr, 53))
	if err != nil {
		t.Fatalf("listen for name lookups inside the network: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go answerLookups(conn, zone)
}

// answerLookups answers queries until the connection closes. A datagram it could not read,
// parse or send is one lost lookup, which the resolver asking retries; ending the loop over
// one would leave every later lookup in the test unanswered instead, which the test sees as
// a name that does not resolve rather than as the dropped packet it is.
func answerLookups(conn net.PacketConn, zone map[string]netip.Addr) {
	buf := make([]byte, 1500)
	// A read that keeps failing is the endpoint being gone rather than a datagram going
	// missing, and this bounds the loop so it cannot spin on one.
	const readFailureLimit = 8
	failedReads := 0
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			// The netstack reports a closed receive side as EOF.
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			failedReads++
			if failedReads == readFailureLimit {
				return
			}
			continue
		}
		failedReads = 0
		answer, err := dnsAnswer(buf[:n], zone)
		if err != nil {
			continue
		}
		// A send that fails loses one answer. The read that follows reports the close.
		_, _ = conn.WriteTo(answer, from)
	}
}

// One lost datagram must cost one lookup and nothing more. A responder that stops at the
// first read or send it could not complete leaves the rest of a test waiting on names that
// will never be answered, which reads as a hang under load rather than as a dropped packet.
func TestTheNameResponderKeepsAnsweringAfterADatagramIsLost(t *testing.T) {
	conn := &lossyPacketConn{
		queries: make(chan []byte, 2),
		answers: make(chan []byte, 1),
		closed:  make(chan struct{}),
	}
	t.Cleanup(func() { conn.Close() })
	conn.readErrors.Store(1)
	conn.writeErrors.Store(1)
	go answerLookups(conn, map[string]netip.Addr{"nas.internal.": serverAddr})

	conn.queries <- lookupQuery(t, "nas.internal.")
	conn.queries <- lookupQuery(t, "nas.internal.")

	select {
	case answer := <-conn.answers:
		var got dnsmessage.Message
		if err := got.Unpack(answer); err != nil {
			t.Fatalf("the answer is not a DNS message: %v", err)
		}
		if len(got.Answers) != 1 {
			t.Fatalf("the answer carries %d records, want the one address the zone holds", len(got.Answers))
		}
		record, ok := got.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || netip.AddrFrom4(record.A) != serverAddr {
			t.Errorf("the answer carries %v, want %s", got.Answers[0].Body, serverAddr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the responder never answered again after a datagram it could not carry")
	}
}

// lossyPacketConn hands queries to a responder and collects what it sends back, and can
// refuse a read or a send first -- which is what a netstack out of buffer space does.
type lossyPacketConn struct {
	queries     chan []byte
	answers     chan []byte
	closed      chan struct{}
	readErrors  atomic.Int32
	writeErrors atomic.Int32
}

func (c *lossyPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.readErrors.Add(-1) >= 0 {
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: errors.New("no buffer space available")}
	}
	c.readErrors.Store(0)
	select {
	case query := <-c.queries:
		return copy(b, query), &net.UDPAddr{IP: clientAddr.AsSlice(), Port: 51000}, nil
	case <-c.closed:
		return 0, nil, io.EOF
	}
}

func (c *lossyPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.writeErrors.Add(-1) >= 0 {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: errors.New("no buffer space available")}
	}
	c.writeErrors.Store(0)
	answer := make([]byte, len(b))
	copy(answer, b)
	c.answers <- answer
	return len(b), nil
}

func (c *lossyPacketConn) Close() error {
	close(c.closed)
	return nil
}

func (c *lossyPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: serverAddr.AsSlice(), Port: 53}
}

func (c *lossyPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *lossyPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *lossyPacketConn) SetWriteDeadline(time.Time) error { return nil }

// lookupQuery builds the question a resolver asks for a name's IPv4 address.
func lookupQuery(t *testing.T, name string) []byte {
	t.Helper()
	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := query.Pack()
	if err != nil {
		t.Fatalf("build a lookup for %s: %v", name, err)
	}
	return packed
}

// dnsAnswer answers one query from the zone: an address when the name is in it and the query
// asks for the family it is in, and an empty successful answer otherwise -- which is what a
// resolver says when a name exists in one family and not the other.
func dnsAnswer(query []byte, zone map[string]netip.Addr) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	addr, known := zone[question.Name.String()]
	answerHeader := dnsmessage.ResourceHeader{
		Name:  question.Name,
		Class: question.Class,
		TTL:   60,
	}
	switch {
	case known && question.Type == dnsmessage.TypeA && addr.Is4():
		if err := builder.AResource(answerHeader, dnsmessage.AResource{A: addr.As4()}); err != nil {
			return nil, err
		}
	case known && question.Type == dnsmessage.TypeAAAA && addr.Is6():
		if err := builder.AAAAResource(answerHeader, dnsmessage.AAAAResource{AAAA: addr.As16()}); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}
