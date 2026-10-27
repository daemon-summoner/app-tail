// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

func udpToLocal(id string, port int, target string) config.Forward {
	return config.Forward{
		ID:         id,
		Name:       id,
		Direction:  config.ToLocal,
		Protocol:   config.UDP,
		BindAddr:   "127.0.0.1",
		ListenPort: port,
		Target:     target,
		Enabled:    true,
	}
}

// udpExchange sends one datagram from its own socket and returns the reply.
func udpExchange(t *testing.T, conn net.Conn, payload string) string {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read reply for %q: %v", payload, err)
	}
	return string(buf[:n])
}

func dialUDP(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestToLocalUDPRoundTrips(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("dns-server:53", echo)

	m := newTestManager(t, tn)
	port := freeUDPPort(t)
	m.Apply([]config.Forward{udpToLocal("f_dns", port, "dns-server:53")})
	waitForStatus(t, m, "f_dns", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	conn := dialUDP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	const payload = "a dns query"
	if got := udpExchange(t, conn, payload); got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}

	st := waitForStatus(t, m, "f_dns", "byte counters to update", func(s Status) bool {
		return s.BytesUp > 0 && s.BytesDown > 0
	})
	if st.BytesUp != int64(len(payload)) || st.BytesDown != int64(len(payload)) {
		t.Errorf("counters up=%d down=%d, want %d each", st.BytesUp, st.BytesDown, len(payload))
	}
	if st.ActiveUDP != 1 {
		t.Errorf("ActiveUDP = %d, want 1 live session", st.ActiveUDP)
	}
}

func TestToTailnetUDPRoundTrips(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	m := newTestManager(t, tn)

	port := freeUDPPort(t)
	m.Apply([]config.Forward{{
		ID:         "f_pubdns",
		Name:       "Publish DNS",
		Direction:  config.ToTailnet,
		Protocol:   config.UDP,
		ListenPort: port,
		Target:     echo,
		Enabled:    true,
	}})
	waitForStatus(t, m, "f_pubdns", "the published udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	conn := dialUDP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	const payload = "query from a tailnet peer"
	if got := udpExchange(t, conn, payload); got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}
}

func TestUDPRoutesRepliesToTheCorrectClient(t *testing.T) {
	// The core correctness property of the session table: with many clients on one
	// listening socket, each reply must go back to the client that asked.
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)

	m := newTestManager(t, tn)
	port := freeUDPPort(t)
	m.Apply([]config.Forward{udpToLocal("f_multi", port, "echo:9")})
	waitForStatus(t, m, "f_multi", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	const clients = 12
	conns := make([]net.Conn, clients)
	for i := range conns {
		conns[i] = dialUDP(t, addr)
	}

	// Interleave so sessions are created and used out of order.
	for round := 0; round < 3; round++ {
		for i, conn := range conns {
			want := fmt.Sprintf("client-%d-round-%d", i, round)
			if got := udpExchange(t, conn, want); got != want {
				t.Fatalf("client %d received %q, want %q (replies are crossing sessions)", i, got, want)
			}
		}
	}

	st := waitForStatus(t, m, "f_multi", "one session per client", func(s Status) bool {
		return s.ActiveUDP == clients
	})
	if st.ActiveUDP != clients {
		t.Errorf("ActiveUDP = %d, want %d", st.ActiveUDP, clients)
	}
}

func TestUDPSessionsEvictWhenIdle(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)

	m := newTestManager(t, tn) // settings set a 1s idle timeout
	port := freeUDPPort(t)
	m.Apply([]config.Forward{udpToLocal("f_idle", port, "echo:9")})
	waitForStatus(t, m, "f_idle", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for i := 0; i < 4; i++ {
		conn := dialUDP(t, addr)
		udpExchange(t, conn, fmt.Sprintf("hello-%d", i))
	}
	waitForStatus(t, m, "f_idle", "sessions to be established", func(s Status) bool {
		return s.ActiveUDP == 4
	})

	// Without the janitor this count would never come back down: UDP has no close,
	// so an unswept table leaks one socket per client forever.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status("f_idle").ActiveUDP == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("idle sessions were never evicted; ActiveUDP = %d", m.Status("f_idle").ActiveUDP)
}

// UDP has no connection close, so a session table that is not swept grows one upstream
// socket per client forever -- a long-lived forward eventually exhausts the process's
// file descriptors and every forward on the node stops working at once.
//
// The socket accounting is the assertion that can actually fail: every upstream socket
// the manager dialled has to come back closed, exactly, with no slack. The goroutine
// count is a secondary signal only -- the runtime schedules its own workers, so a
// tolerance wide enough to be stable is wide enough to hide a real leak.
func TestUDPDoesNotLeakUnderClientChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("churn test is slow")
	}
	echo := startEchoUDP(t)
	// gatedTailnet with no gate dials straight through, but still counts the sockets
	// it opened and hands back conns that record their own close.
	tn := newGatedTailnet(false)
	tn.route("echo:9", echo)

	m := newTestManager(t, tn)
	port := freeUDPPort(t)
	m.Apply([]config.Forward{udpToLocal("f_churn", port, "echo:9")})
	waitForStatus(t, m, "f_churn", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	runtime.GC()
	baseline := runtime.NumGoroutine()

	// Every client uses a fresh source port, so each one creates a new session.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	const churn = 300
	for i := 0; i < churn; i++ {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte(fmt.Sprintf("one-shot-%d", i))); err != nil {
			t.Fatalf("client %d write: %v", i, err)
		}
		buf := make([]byte, 1024)
		conn.Read(buf) // reply may be dropped under load; the session is what matters
		conn.Close()
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status("f_churn").ActiveUDP == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := m.Status("f_churn").ActiveUDP; got != 0 {
		t.Fatalf("ActiveUDP = %d after churn, want the table drained to 0", got)
	}

	// The datagrams are one-shot, so a burst may be coalesced into fewer sessions than
	// clients; what must hold is that every socket that was opened was also closed.
	opened := int(tn.opened.Load())
	if opened == 0 {
		t.Fatal("no upstream sockets were dialled; the churn never reached the tailnet")
	}
	waitFor(t, 15*time.Second, "every upstream socket to be closed", func() bool {
		return int(tn.closed.Load()) == opened
	})
	if got, want := int(tn.closed.Load()), opened; got != want {
		t.Fatalf("%d of %d upstream sockets were closed; %d file descriptors leaked",
			got, want, want-got)
	}

	// Each session owns a reader goroutine. With the sockets accounted for this only
	// catches a goroutine outliving its own socket, so the tolerance is advisory.
	for range 100 {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline+10 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines = %d after churn, baseline was %d: session readers are leaking",
		runtime.NumGoroutine(), baseline)
}

func TestUDPDialFailureDropsDatagramWithoutCreatingASession(t *testing.T) {
	tn := newFakeTailnet()
	tn.failDials(errors.New("blocked by ACL"))

	m := newTestManager(t, tn)
	port := freeUDPPort(t)
	m.Apply([]config.Forward{udpToLocal("f_denied", port, "locked:53")})
	waitForStatus(t, m, "f_denied", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	conn := dialUDP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if _, err := conn.Write([]byte("query")); err != nil {
		t.Fatalf("write: %v", err)
	}

	st := waitForStatus(t, m, "f_denied", "the dial failure to be recorded", func(s Status) bool {
		return strings.Contains(s.Error, "ACL")
	})
	// A failed dial must not install a broken session that swallows later traffic.
	if st.ActiveUDP != 0 {
		t.Errorf("ActiveUDP = %d, want no session created for a failed dial", st.ActiveUDP)
	}
	if st.State != StateRunning {
		t.Errorf("state = %q, want the forward to keep listening", st.State)
	}
}

func TestStoppingAUDPForwardClosesSessionsAndReleasesThePort(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)

	m := newTestManager(t, tn)
	port := freeUDPPort(t)
	fwd := udpToLocal("f_stop", port, "echo:9")
	m.Apply([]config.Forward{fwd})
	waitForStatus(t, m, "f_stop", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn := dialUDP(t, addr)
	udpExchange(t, conn, "establish a session")
	waitForStatus(t, m, "f_stop", "a live session", func(s Status) bool { return s.ActiveUDP == 1 })

	fwd.Enabled = false
	m.Apply([]config.Forward{fwd})
	st := waitForStatus(t, m, "f_stop", "the forward to stop", func(s Status) bool {
		return s.State == StateStopped
	})
	if st.ActiveUDP != 0 {
		t.Errorf("ActiveUDP = %d after stop, want the table cleared", st.ActiveUDP)
	}

	probe, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("stopped udp forward did not release its port: %v", err)
	}
	probe.Close()
}

func TestUDPTimeoutResolution(t *testing.T) {
	m := NewManager(carry(newFakeTailnet()), func() config.Settings {
		s := config.Defaults().Settings
		s.UDPSessionTimeoutSec = 30
		return s
	}, quietLogger())

	if got := m.udpTimeout(config.Forward{}); got != 30*time.Second {
		t.Errorf("timeout = %v, want the settings default of 30s", got)
	}
	if got := m.udpTimeout(config.Forward{UDPTimeoutSec: 5}); got != 5*time.Second {
		t.Errorf("timeout = %v, want the per-forward override of 5s", got)
	}

	unset := NewManager(carry(newFakeTailnet()), func() config.Settings { return config.Settings{} }, quietLogger())
	want := time.Duration(config.DefaultUDPTimeoutSec) * time.Second
	if got := unset.udpTimeout(config.Forward{}); got != want {
		t.Errorf("timeout = %v, want the built-in default %v", got, want)
	}
}

// The configured buffer is what the read loop actually allocates, and a datagram
// larger than it is silently truncated by the kernel -- the caller gets a short read
// with no error. Asserting the getter alone would pass against a startUDP that ignored
// the setting entirely and read into a hardcoded slice.
func TestTheConfiguredBufferIsTheSizeTheReadLoopAllocates(t *testing.T) {
	const bufBytes = 2048
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)

	m := NewManager(carry(tn), func() config.Settings {
		s := config.Defaults().Settings
		s.UDPBufferBytes = bufBytes
		return s
	}, quietLogger())
	m.janitorInterval = 20 * time.Millisecond
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})

	if got := m.bufferSize(); got != bufBytes {
		t.Fatalf("bufferSize = %d, want the configured %d", got, bufBytes)
	}

	port := freeUDPPort(t)
	m.Apply([]config.Forward{udpToLocal("f_buf", port, "echo:9")})
	waitForStatus(t, m, "f_buf", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	conn := dialUDP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	// Comfortably more than the buffer holds.
	oversized := strings.Repeat("x", 4000)
	if runtime.GOOS == "windows" {
		// Windows answers the read with an error naming no sender instead of handing over
		// the part that fit, so there is nowhere to send this datagram and it is dropped.
		if _, err := conn.Write([]byte(oversized)); err != nil {
			t.Fatalf("write the oversized datagram: %v", err)
		}
	} else {
		// What comes back is what the read loop managed to carry, which is the buffer
		// size and not a byte more.
		got := udpExchange(t, conn, oversized)
		if len(got) != bufBytes {
			t.Errorf("a %d-byte datagram came back as %d bytes, want it truncated to the "+
				"configured buffer of %d", len(oversized), len(got), bufBytes)
		}
	}

	// Whichever of those happened, the forward is still a forward: one client sending
	// more than the buffer holds must not take it away from every other client.
	fits := strings.Repeat("y", bufBytes/2)
	if got := udpExchange(t, conn, fits); got != fits {
		t.Errorf("after the oversized datagram a %d-byte one came back as %d bytes, so the "+
			"forward stopped serving", len(fits), len(got))
	}
}

func TestUDPCarriesLargeDatagrams(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)

	m := newTestManager(t, tn)
	port := freeUDPPort(t)
	m.Apply([]config.Forward{udpToLocal("f_big", port, "echo:9")})
	waitForStatus(t, m, "f_big", "the udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	// Comfortably larger than a typical MTU but within the default buffer, so the
	// read path must not truncate it.
	payload := strings.Repeat("x", 8000)
	conn := dialUDP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if got := udpExchange(t, conn, payload); len(got) != len(payload) {
		t.Fatalf("received %d bytes, want %d: the datagram was truncated", len(got), len(payload))
	}
}

// The dial guard judges the address a datagram's session is actually opened to, so a
// published UDP forward whose target the guard refuses carries nothing there and says why.
func TestAToTailnetUDPForwardRefusedByTheDialGuardCarriesNothing(t *testing.T) {
	echo := startEchoUDP(t)
	m := newTestManager(t, newFakeTailnet())
	var asked []string
	var mu sync.Mutex
	m.SetDialGuard(func(network string, addr netip.AddrPort) error {
		mu.Lock()
		asked = append(asked, network+" "+addr.String())
		mu.Unlock()
		return errors.New("that is app-tail's own resolver")
	})

	port := freeUDPPort(t)
	m.Apply([]config.Forward{{
		ID: "f_guarded", Name: "guarded", Direction: config.ToTailnet, Protocol: config.UDP,
		ListenPort: port, Target: echo, Enabled: true,
	}})
	waitForStatus(t, m, "f_guarded", "the published udp forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	conn := dialUDP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if _, err := conn.Write([]byte("query")); err != nil {
		t.Fatalf("write: %v", err)
	}
	st := waitForStatus(t, m, "f_guarded", "the refusal to be recorded", func(s Status) bool {
		return strings.Contains(s.Error, "own resolver")
	})
	if st.ActiveUDP != 0 {
		t.Errorf("ActiveUDP = %d, want no session opened to a refused address", st.ActiveUDP)
	}
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 64)); err == nil {
		t.Errorf("a reply of %d bytes came back from a target the guard refused", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 || asked[0] != "udp4 "+echo {
		t.Errorf("the guard was asked about %q, want the echo's address %s on udp4", asked, echo)
	}
}
