// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/testport"
)

// fakeTailnet implements Tailnet over loopback. Dial resolves a target name to a
// registered local address; Listen and ListenPacket bind 127.0.0.1 to stand in for
// this node's tailnet identity. That makes every forwarding path exercisable with
// real sockets and no tailnet.
type fakeTailnet struct {
	mu      sync.Mutex
	routes  map[string]string // tailnet target -> loopback address
	dialErr error             // when set, every Dial fails (models an ACL denial)

	dialCount atomic.Int32
}

func newFakeTailnet() *fakeTailnet {
	return &fakeTailnet{routes: make(map[string]string)}
}

// route makes a tailnet target name resolve to a real local address.
func (f *fakeTailnet) route(target, localAddr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[target] = localAddr
}

func (f *fakeTailnet) failDials(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialErr = err
}

func (f *fakeTailnet) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.dialCount.Add(1)
	f.mu.Lock()
	if f.dialErr != nil {
		err := f.dialErr
		f.mu.Unlock()
		return nil, err
	}
	local, ok := f.routes[address]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("fake tailnet: no route to %s", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, local)
}

func (f *fakeTailnet) Listen(network string, port uint16) (net.Listener, error) {
	return net.Listen(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
}

func (f *fakeTailnet) ListenPacket(network string, port uint16) (net.PacketConn, error) {
	return net.ListenPacket(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
}

var _ Tailnet = (*fakeTailnet)(nil)

// carrying is the connection registry a test manager resolves through. The production
// one reads the live tunnels; a test has one network, so every connection id resolves to
// it, and `up` stands in for that connection carrying or not.
type carrying struct {
	mu  sync.Mutex
	net Tailnet
	up  bool
}

// carry wraps one network as the registry a manager resolves through, already carrying.
func carry(tn Tailnet) *carrying { return &carrying{net: tn, up: true} }

func (c *carrying) Tailnet(string) (Tailnet, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.up {
		return nil, false
	}
	return c.net, true
}

// setUp is a connection coming up or going down as a manager sees it: the state changes
// and something reconciles. The agent's own loop reconciles on every pass, so this does
// the same rather than inventing a signal the manager does not have.
func (c *carrying) setUp(m *Manager, up bool) {
	c.mu.Lock()
	c.up = up
	c.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
}

var _ Tailnets = (*carrying)(nil)

// carryingEach is the registry for a test with more than one connection: each id resolves
// to its own network, and an id nothing was registered under is a connection that is not
// carrying. It is what makes "this forward crossed the connection it names" assertable
// rather than assumed.
type carryingEach struct {
	mu   sync.Mutex
	nets map[string]Tailnet
}

func carryEach(nets map[string]Tailnet) *carryingEach {
	held := make(map[string]Tailnet, len(nets))
	for id, tn := range nets {
		held[id] = tn
	}
	return &carryingEach{nets: held}
}

func (c *carryingEach) Tailnet(id string) (Tailnet, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tn, carrying := c.nets[id]
	return tn, carrying
}

// drop takes one connection down and reconciles, the way the agent's loop would.
func (c *carryingEach) drop(m *Manager, id string) {
	c.mu.Lock()
	delete(c.nets, id)
	c.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
}

var _ Tailnets = (*carryingEach)(nil)

// --- test helpers ---

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testSettings() config.Settings {
	s := config.Defaults().Settings
	s.UDPSessionTimeoutSec = 1
	return s
}

// newTestManager builds a manager wired to a fake tailnet, its connection already
// carrying, with a fast janitor so idle eviction can be asserted without waiting.
func newTestManager(t *testing.T, tn Tailnet) *Manager {
	t.Helper()
	return newTestManagerOver(t, carry(tn))
}

// newTestManagerOver is the same for a test that has to reach the registry afterwards,
// to take the connection down or bring it back.
func newTestManagerOver(t *testing.T, nets Tailnets) *Manager {
	t.Helper()
	m := NewManager(nets, testSettings, quietLogger())
	m.janitorInterval = 20 * time.Millisecond
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})
	return m
}

// startEchoTCP runs a TCP echo server on loopback until the test ends.
func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start echo server: %v", err)
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
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// startEchoUDP runs a UDP echo server on loopback until the test ends.
func startEchoUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start udp echo server: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

// freePort returns a loopback port reserved for this test process.
func freePort(t *testing.T) int {
	t.Helper()
	port, err := testport.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// freeUDPPort returns a loopback port reserved for this test process. Reservations
// cover both protocols, so a UDP port never collides with a TCP one.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	port, err := testport.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// waitForStatus polls a forward's status until want reports true.
func waitForStatus(t *testing.T, m *Manager, id, what string, want func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last Status
	for time.Now().Before(deadline) {
		last = m.Status(id)
		if want(last) {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; last status: %+v", what, last)
	return last
}

// roundTripTCP sends a payload through addr and returns what came back.
func roundTripTCP(t *testing.T, addr, payload string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v", err)
	}
	return string(buf)
}
