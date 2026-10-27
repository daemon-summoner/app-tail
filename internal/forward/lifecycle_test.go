// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// The mirror of the UDP-half rollback: when the TCP half is the one that cannot bind,
// the UDP half must never open at all. A forward that half-listens on UDP would answer
// datagrams from a rule the dashboard reports as failed.
func TestABothForwardThatCannotBindItsTCPHalfNeverOpensTheUDPOne(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)

	m := NewManager(carry(tn), testSettings, quietLogger())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})

	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// Hold the TCP side only, leaving UDP free: the forward's first half fails.
	held, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("hold the tcp port: %v", err)
	}
	defer held.Close()

	fwd := tcpToLocal(t, "f_both", port, "box:80")
	fwd.Protocol = config.Both
	m.Apply([]config.Forward{fwd})

	got := waitForStatus(t, m, "f_both", "the both-protocol forward to report its failure", func(s Status) bool {
		return s.State == StateError
	})
	if got.Error == "" {
		t.Error("the forward reports an error state with no reason")
	}
	if got.Listening != "" {
		t.Errorf("a failed forward claims to be listening on %q", got.Listening)
	}

	// The UDP stack must be untouched: if the second half had opened, this bind fails.
	probe, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the UDP half was opened even though the TCP half never bound: %v", err)
	}
	probe.Close()
}

// The agent reconciles on every backend heartbeat, so the manager is handed the same
// desired set over the same connection again and again. Acting on each would tear down
// and rebuild every listener on a timer, dropping live connections for no reason.
func TestReconcilingWithNothingChangedDoesNothing(t *testing.T) {
	tn := newFakeTailnet()
	echo := startEchoTCP(t)
	tn.route("box:80", echo)

	carrier := carry(tn)
	m := newTestManagerOver(t, carrier)

	fwd := tcpToLocal(t, "f_steady", freePort(t), "box:80")
	m.Apply([]config.Forward{fwd})

	running := waitForStatus(t, m, "f_steady", "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	for range 5 {
		m.Apply([]config.Forward{fwd})
		carrier.setUp(m, true)
	}

	// A restart would move the listening address, because the forward binds a fresh
	// socket each time it starts.
	after := m.Status("f_steady")
	if after.Listening != running.Listening {
		t.Errorf("listening moved from %q to %q; the forward was restarted by a reconcile "+
			"that changed nothing, and every live connection was dropped", running.Listening, after.Listening)
	}
	if after.State != StateRunning {
		t.Errorf("state = %q after repeated reconciles, want the forward still running", after.State)
	}
}

// A connection that stops carrying is announced once, not once per reconcile: the
// forwards on it stay stopped for as long as it is down, and a line per pass would bury
// everything else in the log.
func TestAConnectionGoingDownIsAnnouncedOnce(t *testing.T) {
	tn := newFakeTailnet()
	echo := startEchoTCP(t)
	tn.route("box:80", echo)

	logs := new(syncBuffer)
	carrier := carry(tn)
	m := NewManager(carrier, testSettings,
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})

	m.Apply([]config.Forward{tcpToLocal(t, "f_steady", freePort(t), "box:80")})
	waitForStatus(t, m, "f_steady", "the forward to start", func(s Status) bool {
		return s.State == StateRunning
	})

	carrier.setUp(m, false)
	for range 5 {
		carrier.setUp(m, false)
	}

	if got := strings.Count(logs.String(), "its connection is not carrying"); got != 1 {
		t.Errorf("the manager announced the connection going down %d times, want 1", got)
	}
}

// startNamingTCP runs a TCP server that announces which one it is and hangs up. Two of
// them behind two connections is how a test tells which network a forward crossed, which
// an echo server -- identical on both -- could not.
func startNamingTCP(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start the %s server: %v", name, err)
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
				conn.Write([]byte(name))
			}()
		}
	}()
	return ln.Addr().String()
}

// whoAnswered dials a forward's local address and returns what the server behind it said.
func whoAnswered(t *testing.T, addr string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	said, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read from %s: %v", addr, err)
	}
	return string(said)
}

// The whole point of a forward naming its connection: two networks may use the same
// address, or the same target name, and the forward has to cross the one it names. A
// manager that dialled through whichever network it happened to hold would send a rule
// pointing at the office database to whatever answers on that address at home.
func TestAForwardCrossesTheConnectionItNames(t *testing.T) {
	office, home := newFakeTailnet(), newFakeTailnet()
	office.route("db:5432", startNamingTCP(t, "office"))
	home.route("db:5432", startNamingTCP(t, "home"))

	m := newTestManagerOver(t, carryEach(map[string]Tailnet{"tn_office": office, "tn_home": home}))

	toOffice := tcpToLocal(t, "f_office", freePort(t), "db:5432")
	toOffice.TunnelID = "tn_office"
	toHome := tcpToLocal(t, "f_home", freePort(t), "db:5432")
	toHome.TunnelID = "tn_home"
	m.Apply([]config.Forward{toOffice, toHome})

	for _, want := range []struct{ id, name string }{{"f_office", "office"}, {"f_home", "home"}} {
		running := waitForStatus(t, m, want.id, "the forward to start", func(s Status) bool {
			return s.State == StateRunning
		})
		if got := whoAnswered(t, running.Listening); got != want.name {
			t.Errorf("%s reached the %q network, want %q; the forward crossed the wrong connection",
				want.id, got, want.name)
		}
	}
}

// A forward whose connection stops carrying has nothing to dial through, so it must stop
// listening rather than accept connections it can only fail. Leaving the port bound would
// turn "the network is down" into a connection that hangs and then errors with no reason
// anywhere, and the forwards on every other connection must be untouched.
func TestAForwardStopsWhenItsConnectionStopsCarrying(t *testing.T) {
	office, home := newFakeTailnet(), newFakeTailnet()
	office.route("db:5432", startNamingTCP(t, "office"))
	home.route("db:5432", startNamingTCP(t, "home"))

	nets := carryEach(map[string]Tailnet{"tn_office": office, "tn_home": home})
	m := newTestManagerOver(t, nets)

	toOffice := tcpToLocal(t, "f_office", freePort(t), "db:5432")
	toOffice.TunnelID = "tn_office"
	toHome := tcpToLocal(t, "f_home", freePort(t), "db:5432")
	toHome.TunnelID = "tn_home"
	m.Apply([]config.Forward{toOffice, toHome})

	officeAddr := waitForStatus(t, m, "f_office", "the office forward to start", func(s Status) bool {
		return s.State == StateRunning
	}).Listening
	homeAddr := waitForStatus(t, m, "f_home", "the home forward to start", func(s Status) bool {
		return s.State == StateRunning
	}).Listening

	nets.drop(m, "tn_office")

	if got := m.Status("f_office"); got.State != StateStopped {
		t.Errorf("state = %q with its connection down, want %q", got.State, StateStopped)
	}
	// The port has to be free, or the forward is still accepting connections it cannot
	// carry -- which is the failure this stop exists to prevent.
	probe, err := net.Listen("tcp", officeAddr)
	if err != nil {
		t.Fatalf("the stopped forward is still listening on %s: %v", officeAddr, err)
	}
	probe.Close()

	if got := whoAnswered(t, homeAddr); got != "home" {
		t.Errorf("the home forward answered %q after another connection went down, want %q", got, "home")
	}
}

// A manager built without a logger has to fall back rather than carry a nil one: the
// first forward that fails would otherwise panic inside the goroutine that was trying
// to report the failure, taking the agent down with it.
func TestAManagerBuiltWithoutALoggerStillReportsFailures(t *testing.T) {
	m := NewManager(carry(newFakeTailnet()), testSettings, nil)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.StopAll(ctx)
	})

	if m.logger == nil {
		t.Fatal("the manager kept a nil logger; the first log call panics")
	}

	// Drive a real failure through it: an unsupported protocol takes the path that
	// logs and records the reason.
	fwd := tcpToLocal(t, "f_bogus", freePort(t), "box:80")
	fwd.Protocol = config.Protocol("sctp")
	m.Apply([]config.Forward{fwd})

	got := waitForStatus(t, m, "f_bogus", "the unsupported forward to fail", func(s Status) bool {
		return s.State == StateError
	})
	if !strings.Contains(got.Error, "unsupported protocol") {
		t.Errorf("error = %q, want the unsupported-protocol reason", got.Error)
	}
}

// noteError is called on every datagram that could not be delivered, including the
// successful ones' nil. Recording that nil would clear a real failure the dashboard is
// still showing, or -- worse -- store an empty reason next to an error state.
func TestNotingANilErrorLeavesTheLastRealReasonInPlace(t *testing.T) {
	c := newCounters()
	c.setRunning("127.0.0.1:9000")

	c.noteError(errors.New("no route to the target"))
	c.noteError(nil)

	got := c.snapshot("f_1")
	if got.Error != "no route to the target" {
		t.Errorf("Error = %q, want the last real failure to survive a nil", got.Error)
	}
	if got.State != StateRunning {
		t.Errorf("State = %q, want the forward to stay running through a transient failure", got.State)
	}

	// A success clears it, which is what stops a recovered target showing a stale reason.
	c.noteSuccess()
	if got := c.snapshot("f_1"); got.Error != "" {
		t.Errorf("Error = %q after a success, want it cleared", got.Error)
	}
}

// A transient failure must not overwrite a hard one. The forward is stopped or errored
// for a reason the user has to act on, and a later dropped datagram's message would
// replace it with something that reads as recoverable.
func TestASuccessDoesNotClearAHardFailure(t *testing.T) {
	c := newCounters()
	c.setError(errors.New("bind 127.0.0.1:80: permission denied"))

	c.noteSuccess()

	got := c.snapshot("f_1")
	if got.State != StateError {
		t.Errorf("State = %q, want %q", got.State, StateError)
	}
	if got.Error == "" {
		t.Error("a success cleared the reason the forward is in an error state")
	}
}
