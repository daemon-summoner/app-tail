// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

func tcpToLocal(t *testing.T, id string, port int, target string) config.Forward {
	t.Helper()
	return config.Forward{
		ID:         id,
		Name:       id,
		Direction:  config.ToLocal,
		Protocol:   config.TCP,
		BindAddr:   "127.0.0.1",
		ListenPort: port,
		Target:     target,
		Enabled:    true,
	}
}

func TestToLocalTCPCarriesTrafficAndCounts(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("buildbox:22", echo)

	m := newTestManager(t, tn)
	port := freePort(t)
	fwd := tcpToLocal(t, "f_ssh", port, "buildbox:22")
	m.Apply([]config.Forward{fwd})

	st := waitForStatus(t, m, "f_ssh", "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})
	if st.Listening == "" {
		t.Error("a running forward did not report the address it bound")
	}

	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	const payload = "hello over the tailnet"
	if got := roundTripTCP(t, local, payload); got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}

	// Counters must reflect real traffic, and connections must not leak.
	final := waitForStatus(t, m, "f_ssh", "the connection to be released", func(s Status) bool {
		return s.ActiveTCP == 0 && s.BytesUp > 0 && s.BytesDown > 0
	})
	if final.BytesUp != int64(len(payload)) {
		t.Errorf("BytesUp = %d, want %d", final.BytesUp, len(payload))
	}
	if final.BytesDown != int64(len(payload)) {
		t.Errorf("BytesDown = %d, want %d", final.BytesDown, len(payload))
	}
}

func TestToTailnetTCPCarriesTraffic(t *testing.T) {
	// The local service being published to the tailnet.
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	m := newTestManager(t, tn)

	port := freePort(t)
	fwd := config.Forward{
		ID:         "f_pub",
		Name:       "Publish web",
		Direction:  config.ToTailnet,
		Protocol:   config.TCP,
		ListenPort: port,
		Target:     echo,
		Enabled:    true,
	}
	m.Apply([]config.Forward{fwd})
	waitForStatus(t, m, "f_pub", "the published forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	// The fake tailnet listens on loopback, so a tailnet peer is modelled by
	// connecting to that port.
	const payload = "from a tailnet peer"
	got := roundTripTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), payload)
	if got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}
}

// A client that vanishes mid-connection is the everyday case behind "the forward keeps
// dropping": the copy fails with ECONNRESET while the forward itself is perfectly
// healthy. Discarding that error leaves nothing at all to look at, so it is reported --
// but only as a per-connection note, because one rude client must not make the forward
// itself look broken.
func TestAConnectionResetByTheClientIsReportedWithoutFailingTheForward(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	logs := new(syncBuffer)
	m := NewManager(carry(tn), testSettings,
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})

	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, "f_rude", port, "box:80")})
	waitForStatus(t, m, "f_rude", "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	// Round-trip first, so the failure lands on a fully established proxied
	// connection rather than racing the dial.
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
		t.Fatalf("read the echo back: %v", err)
	}

	// Linger 0 turns Close into an RST, which is what an abruptly killed client
	// sends. A plain Close would be an orderly shutdown and report no error at all.
	if err := conn.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatalf("set linger: %v", err)
	}
	conn.Close()

	waitFor(t, 5*time.Second, "the reset connection to be reported", func() bool {
		return strings.Contains(logs.String(), "proxied connection ended early")
	})

	st := m.Status("f_rude")
	if st.State != StateRunning {
		t.Errorf("forward state = %q after one client reset, want it to stay %q", st.State, StateRunning)
	}
	if st.Error != "" {
		t.Errorf("forward reports error %q after one client reset; a rude client is not a broken forward", st.Error)
	}
}

func TestActiveTCPTracksOpenConnections(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := newTestManager(t, tn)
	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, "f_web", port, "box:80")})
	waitForStatus(t, m, "f_web", "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp", local, 3*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	waitForStatus(t, m, "f_web", "three connections to be counted", func(s Status) bool {
		return s.ActiveTCP == 3
	})

	for _, c := range conns {
		c.Close()
	}
	waitForStatus(t, m, "f_web", "connections to be released", func(s Status) bool {
		return s.ActiveTCP == 0
	})
}

func TestStoppingOneForwardLeavesOthersRunning(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := newTestManager(t, tn)
	portA, portB := freePort(t), freePort(t)
	a := tcpToLocal(t, "f_a", portA, "box:80")
	b := tcpToLocal(t, "f_b", portB, "box:80")
	m.Apply([]config.Forward{a, b})

	waitForStatus(t, m, "f_a", "forward A to start", func(s Status) bool { return s.State == StateRunning })
	waitForStatus(t, m, "f_b", "forward B to start", func(s Status) bool { return s.State == StateRunning })

	// Hold a live connection through B while A is disabled.
	liveAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(portB))
	live, err := net.DialTimeout("tcp", liveAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()

	a.Enabled = false
	m.Apply([]config.Forward{a, b})
	waitForStatus(t, m, "f_a", "forward A to stop", func(s Status) bool { return s.State == StateStopped })

	// A's port must actually be released.
	probe, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(portA)))
	if err != nil {
		t.Fatalf("disabled forward did not release its port: %v", err)
	}
	probe.Close()

	// B's existing connection must survive, and B must still accept new ones.
	live.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := live.Write([]byte("still here")); err != nil {
		t.Fatalf("connection through the untouched forward was cut: %v", err)
	}
	buf := make([]byte, len("still here"))
	if _, err := live.Read(buf); err != nil {
		t.Fatalf("reply through the untouched forward failed: %v", err)
	}
	if got := roundTripTCP(t, liveAddr, "new conn"); got != "new conn" {
		t.Errorf("untouched forward stopped accepting: got %q", got)
	}
}

func TestPortConflictSurfacesAsForwardError(t *testing.T) {
	// A port taken by something outside this app must show up as a forward error,
	// not a silent no-op.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	tn := newFakeTailnet()
	m := newTestManager(t, tn)
	m.Apply([]config.Forward{tcpToLocal(t, "f_taken", port, "box:80")})

	st := waitForStatus(t, m, "f_taken", "the bind failure to surface", func(s Status) bool {
		return s.State == StateError
	})
	if st.Error == "" {
		t.Error("a forward that failed to bind reported no reason")
	}
}

func TestUnreachableTargetSurfacesOnTheForward(t *testing.T) {
	// ACL denials are the most common "won't connect" cause; the reason must reach
	// the UI rather than being swallowed.
	tn := newFakeTailnet()
	tn.failDials(errors.New("connection refused by ACL"))

	m := newTestManager(t, tn)
	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, "f_denied", port, "locked:22")})
	waitForStatus(t, m, "f_denied", "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("the listener should still accept: %v", err)
	}
	conn.Close()

	st := waitForStatus(t, m, "f_denied", "the dial failure to be recorded", func(s Status) bool {
		return strings.Contains(s.Error, "ACL")
	})
	// The forward keeps listening: one failed connection is not a broken forward.
	if st.State != StateRunning {
		t.Errorf("state = %q, want the forward to keep listening after a failed dial", st.State)
	}
}

func TestForwardsDoNotStartBeforeTheNodeIsRunning(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	// The connection is not carrying yet, which is what a node that has not finished
	// starting looks like to the manager.
	carrier := &carrying{net: tn}
	m := NewManager(carrier, testSettings, quietLogger())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})

	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, "f_early", port, "box:80")})

	// Nothing may bind while the tailnet is down.
	probe, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("a forward bound its port before the node was running: %v", err)
	}
	probe.Close()
	if got := m.Status("f_early").State; got == StateRunning {
		t.Errorf("state = %q, want the forward held back until the node is up", got)
	}

	carrier.setUp(m, true)
	waitForStatus(t, m, "f_early", "the forward to start once the node is up", func(s Status) bool {
		return s.State == StateRunning
	})
	if got := roundTripTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "ping"); got != "ping" {
		t.Errorf("forward did not carry traffic after the node came up: got %q", got)
	}
}

func TestForwardsStopWhenTheNodeGoesDown(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	carrier := carry(tn)
	m := newTestManagerOver(t, carrier)
	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, "f_x", port, "box:80")})
	waitForStatus(t, m, "f_x", "the forward to start", func(s Status) bool { return s.State == StateRunning })

	carrier.setUp(m, false)
	waitForStatus(t, m, "f_x", "the forward to stop", func(s Status) bool { return s.State == StateStopped })

	probe, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("forward kept its port after the node went down: %v", err)
	}
	probe.Close()

	// Coming back up must restore it without re-applying config.
	carrier.setUp(m, true)
	waitForStatus(t, m, "f_x", "the forward to restart", func(s Status) bool { return s.State == StateRunning })
}

func TestEditingATargetRebindsTheForward(t *testing.T) {
	first, second := startEchoTCP(t), startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("first:80", first)
	tn.route("second:80", second)

	m := newTestManager(t, tn)
	port := freePort(t)
	fwd := tcpToLocal(t, "f_edit", port, "first:80")
	m.Apply([]config.Forward{fwd})
	waitForStatus(t, m, "f_edit", "the forward to start", func(s Status) bool { return s.State == StateRunning })

	before := tn.dialCount.Load()
	fwd.Target = "second:80"
	m.Apply([]config.Forward{fwd})
	waitForStatus(t, m, "f_edit", "the forward to restart on its new target", func(s Status) bool {
		return s.State == StateRunning
	})

	local := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if got := roundTripTCP(t, local, "after edit"); got != "after edit" {
		t.Fatalf("edited forward did not carry traffic: got %q", got)
	}
	if tn.dialCount.Load() <= before {
		t.Error("the edited forward did not dial its new target")
	}
}

func TestRenamingAForwardDoesNotDisturbIt(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := newTestManager(t, tn)
	port := freePort(t)
	fwd := tcpToLocal(t, "f_name", port, "box:80")
	m.Apply([]config.Forward{fwd})
	waitForStatus(t, m, "f_name", "the forward to start", func(s Status) bool { return s.State == StateRunning })

	// Hold a connection open across the rename.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fwd.Name = "A nicer name"
	m.Apply([]config.Forward{fwd})

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("survived")); err != nil {
		t.Fatalf("a cosmetic rename cut a live connection: %v", err)
	}
	buf := make([]byte, len("survived"))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("a cosmetic rename broke a live connection: %v", err)
	}
}

func TestDeletedForwardDisappearsAndReleasesItsPort(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := newTestManager(t, tn)
	port := freePort(t)
	m.Apply([]config.Forward{tcpToLocal(t, "f_gone", port, "box:80")})
	waitForStatus(t, m, "f_gone", "the forward to start", func(s Status) bool { return s.State == StateRunning })

	m.Apply(nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.Statuses()) == 0 {
			probe, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatalf("deleted forward did not release its port: %v", err)
			}
			probe.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("deleted forward is still listed: %+v", m.Statuses())
}

func TestAllRunningReflectsEnabledForwards(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := newTestManager(t, tn)
	// A manager that has never reconciled has no readiness claim to make; only an
	// applied-and-empty desired set means "nothing is wanted, so all is well".
	if m.AllRunning() {
		t.Error("AllRunning should be false before the first Apply")
	}
	m.Apply(nil)
	if !m.AllRunning() {
		t.Error("AllRunning should be true once an empty desired set has been applied")
	}

	good := tcpToLocal(t, "f_ok", freePort(t), "box:80")
	m.Apply([]config.Forward{good})
	waitForStatus(t, m, "f_ok", "the forward to start", func(s Status) bool { return s.State == StateRunning })
	if !m.AllRunning() {
		t.Error("AllRunning should be true when every enabled forward is listening")
	}

	// A forward that cannot bind must make the agent unready.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	bad := tcpToLocal(t, "f_bad", blocker.Addr().(*net.TCPAddr).Port, "box:80")
	m.Apply([]config.Forward{good, bad})
	waitForStatus(t, m, "f_bad", "the bind failure", func(s Status) bool { return s.State == StateError })
	if m.AllRunning() {
		t.Error("AllRunning should be false while a forward is in error")
	}

	// Disabled forwards do not count against readiness.
	bad.Enabled = false
	m.Apply([]config.Forward{good, bad})
	waitForStatus(t, m, "f_bad", "the broken forward to be disabled", func(s Status) bool {
		return s.State == StateStopped
	})
	if !m.AllRunning() {
		t.Error("a disabled forward should not hold readiness down")
	}
}

func TestStopAllReleasesEverything(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := NewManager(carry(tn), testSettings, quietLogger())
	portA, portB := freePort(t), freePort(t)
	m.Apply([]config.Forward{
		tcpToLocal(t, "f_a", portA, "box:80"),
		tcpToLocal(t, "f_b", portB, "box:80"),
	})
	waitForStatus(t, m, "f_a", "forward A to start", func(s Status) bool { return s.State == StateRunning })
	waitForStatus(t, m, "f_b", "forward B to start", func(s Status) bool { return s.State == StateRunning })

	// A connection open at shutdown must not prevent a clean stop.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(portA)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.StopAll(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("StopAll did not return; shutdown would hang")
	}

	for _, port := range []int{portA, portB} {
		probe, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("StopAll left port %d bound: %v", port, err)
		}
		probe.Close()
	}
	if len(m.Statuses()) != 0 {
		t.Errorf("StopAll left forwards registered: %+v", m.Statuses())
	}
}

func TestBindHostDefaultsToLoopback(t *testing.T) {
	// The default must never be a wildcard: a to_local forward should not be
	// reachable from the LAN unless the user asks for it.
	if got := bindHost(config.Forward{}); got != config.DefaultBindAddr {
		t.Errorf("bindHost = %q, want %q", got, config.DefaultBindAddr)
	}
	if got := bindHost(config.Forward{BindAddr: "0.0.0.0"}); got != "0.0.0.0" {
		t.Errorf("bindHost = %q, want the explicit address", got)
	}
}

func TestToLocalTCPHonorsAWildcardBindAddress(t *testing.T) {
	// A non-default bind address must reach the real listener, not merely bindHost:
	// 0.0.0.0 binds every interface, so the forward reports the wildcard it bound and
	// stays reachable through loopback (the interface a LAN client would use in tests).
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("nas:5000", echo)

	m := newTestManager(t, tn)
	port := freePort(t)
	fwd := tcpToLocal(t, "f_lan", port, "nas:5000")
	fwd.BindAddr = "0.0.0.0"
	m.Apply([]config.Forward{fwd})

	st := waitForStatus(t, m, "f_lan", "the wildcard forward to start", func(s Status) bool {
		return s.State == StateRunning
	})
	// The kernel may render the wildcard as 0.0.0.0 or the dual-stack [::]; either way
	// it must be unspecified, never loopback, or the LAN could not reach it.
	host, _, err := net.SplitHostPort(st.Listening)
	if err != nil {
		t.Fatalf("Listening %q is not host:port: %v", st.Listening, err)
	}
	bound, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("bound host %q is not an IP: %v", host, err)
	}
	if !bound.IsUnspecified() {
		t.Errorf("bound %s, want an unspecified wildcard (the 0.0.0.0 bind must survive to the listener)", bound)
	}

	const payload = "reachable beyond loopback"
	if got := roundTripTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), payload); got != payload {
		t.Fatalf("round trip returned %q, want %q", got, payload)
	}
}
