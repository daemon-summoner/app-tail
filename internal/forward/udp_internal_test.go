// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// udpFwd is the forward every test here starts from; the harness supplies the socket,
// so the port is only a label.
func udpFwd(id string) config.Forward { return udpToLocal(id, 1, "echo:9") }

// sendTo delivers one datagram to the forward's listening socket from its own client
// socket, and returns that socket so a test can hold the client identity open.
func sendTo(t *testing.T, addr, payload string) net.Conn {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial the forward at %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("send %q: %v", payload, err)
	}
	return conn
}

// A target that accepts the dial and then refuses the datagram leaves a session whose
// socket is useless. Keeping it would mean every later datagram from that client is
// written into a dead socket and silently lost, with the forward still showing green.
func TestAnUpstreamWriteFailureDropsTheSessionAndSurfacesTheReason(t *testing.T) {
	sendErr := errors.New("no buffer space available")
	m := newTestManager(t, &refusingTailnet{fakeTailnet: newFakeTailnet(), err: sendErr})
	h := newUDPForward(t, m, udpFwd("f_refuse"), nil)

	sendTo(t, h.addr, "first datagram")

	waitFor(t, 5*time.Second, "the write failure to be recorded", func() bool {
		return strings.Contains(h.status().Error, sendErr.Error())
	})
	waitFor(t, 5*time.Second, "the dead session to be dropped", func() bool {
		return h.sessionCount() == 0
	})

	st := h.status()
	if st.State != StateRunning {
		t.Errorf("state = %q; one undeliverable datagram must not stop the forward", st.State)
	}
	if st.BytesUp != 0 {
		t.Errorf("BytesUp = %d after a failed write; bytes that never left must not be counted", st.BytesUp)
	}
	if st.ActiveUDP != 0 {
		t.Errorf("ActiveUDP = %d, want the dropped session to be reflected in the count", st.ActiveUDP)
	}
}

// A reply that cannot be delivered means the client is gone -- it closed its socket, or
// a NAT mapping expired. Holding the session open would keep its upstream socket and
// its reader goroutine alive until the idle sweep, one leak per departed client.
func TestAnUndeliverableReplyClosesTheSessionRatherThanRetrying(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the forward socket: %v", err)
	}
	replyErr := errors.New("host is down")
	h := newUDPForward(t, m, udpFwd("f_noreply"), failingWriteConn{PacketConn: pc, err: replyErr})

	sendTo(t, h.addr, "a datagram whose reply cannot come back")

	waitFor(t, 5*time.Second, "the undeliverable reply to be recorded", func() bool {
		return strings.Contains(h.status().Error, replyErr.Error())
	})
	waitFor(t, 5*time.Second, "the session to be closed", func() bool {
		return h.sessionCount() == 0
	})
	if got := h.status().BytesDown; got != 0 {
		t.Errorf("BytesDown = %d for a reply that was never delivered", got)
	}
}

// The listening socket disappearing under a running forward is a real failure: the rule
// silently stops carrying traffic. Without the error state the dashboard shows a green
// forward that answers nothing.
func TestLosingTheListeningSocketPutsTheForwardIntoError(t *testing.T) {
	m := newTestManager(t, newFakeTailnet())
	h := newUDPForward(t, m, udpFwd("f_lost"), nil)

	// Close the socket without cancelling: the forward was never asked to stop.
	if err := h.uf.local.Close(); err != nil {
		t.Fatalf("close the listening socket: %v", err)
	}

	waitFor(t, 5*time.Second, "the read failure to be recorded", func() bool {
		return h.status().State == StateError
	})
	if got := h.status().Error; !strings.Contains(got, "read:") {
		t.Errorf("error = %q, want it to name the read that failed", got)
	}
}

// Stopping a forward closes its socket, which makes the read loop fail in exactly the
// way a real fault does. Only the cancelled context tells them apart -- get it wrong
// and every shutdown leaves the user's rules painted red.
func TestStoppingMidReadIsNotRecordedAsAFault(t *testing.T) {
	m := newTestManager(t, newFakeTailnet())
	h := newUDPForward(t, m, udpFwd("f_clean"), nil)

	h.stop()

	if st := h.status(); st.State == StateError {
		t.Errorf("a deliberate stop was recorded as an error: %q", st.Error)
	}
}

// Two callers racing to create the session for one client must not both keep their
// socket. The read loop is single-threaded today, so this guard is what keeps that an
// implementation detail rather than a latent leak of one upstream socket -- and one
// reader goroutine -- per duplicated datagram.
func TestTheLoserOfADuplicateDialClosesItsRedundantSocket(t *testing.T) {
	echo := startEchoUDP(t)
	gated := newGatedTailnet(true)
	gated.route("echo:9", echo)
	m := newTestManager(t, gated)
	h := newUDPForward(t, m, udpFwd("f_race"), nil)

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55555}
	ctx := context.Background()

	const racers = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
		got     []*session
	)
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			s, isNew, err := h.uf.sessionFor(ctx, client)
			if err != nil {
				t.Errorf("sessionFor: %v", err)
				return
			}
			mu.Lock()
			if isNew {
				created++
			}
			got = append(got, s)
			mu.Unlock()
		}()
	}

	// Park every dial, then release them together so they finish interleaved. Releasing
	// before they are all parked would let the first finish alone and there would be no
	// race left to observe.
	waitFor(t, 5*time.Second, "every racer to reach the dial", func() bool {
		return gated.parkedDials() == racers
	})
	gated.release()
	wg.Wait()

	if created != 1 {
		t.Errorf("%d racers reported creating the session, want exactly 1", created)
	}
	for i, s := range got {
		if s != got[0] {
			t.Errorf("racer %d got a different session than racer 0; one client must have one session", i)
		}
	}
	if h.sessionCount() != 1 {
		t.Errorf("session table holds %d entries for one client", h.sessionCount())
	}

	// Every socket the losers dialled has to be closed, or each duplicate leaks one.
	opened := int(gated.opened.Load())
	if opened < racers {
		t.Fatalf("only %d sockets were dialled; the racers did not actually race", opened)
	}
	waitFor(t, 5*time.Second, "the redundant sockets to be closed", func() bool {
		return int(gated.closed.Load()) == opened-1
	})
}

// A reply that arrives after the forward was cancelled is discarded without touching
// the session table: shutdown drains that table itself, and an eviction racing the
// drain would mutate the map the drain is walking.
func TestALateReplyAfterCancellationIsDiscardedWithoutEviction(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_late"), nil)

	sendTo(t, h.addr, "establish the session")
	waitFor(t, 5*time.Second, "the session to be established", func() bool {
		return h.sessionCount() == 1
	})
	s := h.anySession(t)
	before := h.status().BytesDown

	// Cancel without closing the listening socket, which leaves the read loop parked in
	// ReadFrom and the session's reply pump still running -- the window this branch
	// exists for.
	h.cancel()

	// Provoke a reply straight from the session's own socket; the read loop is not
	// involved, so this arrives at the pump with the context already cancelled.
	if _, err := s.upstream.Write([]byte("late reply please")); err != nil {
		t.Fatalf("write upstream: %v", err)
	}

	// The pump must exit quietly: no eviction, no counted bytes.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if h.status().BytesDown != before {
			t.Fatalf("BytesDown moved from %d to %d after cancellation; a late reply was "+
				"delivered to a client the forward is no longer serving", before, h.status().BytesDown)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.sessionCount(); got != 1 {
		t.Errorf("session table holds %d entries; the late reply evicted a session that "+
			"shutdown is responsible for draining", got)
	}
}

// Stopping drains the table outright, which is the other half of the same contract: no
// session -- and no upstream socket -- outlives its forward.
func TestStoppingDrainsEverySession(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_drain"), nil)

	for _, payload := range []string{"client one", "client two", "client three"} {
		sendTo(t, h.addr, payload)
	}
	waitFor(t, 5*time.Second, "three sessions to be established", func() bool {
		return h.sessionCount() == 3
	})

	h.stop()

	if got := h.sessionCount(); got != 0 {
		t.Errorf("session table holds %d entries after a stop, want it drained", got)
	}
	if got := h.status().ActiveUDP; got != 0 {
		t.Errorf("ActiveUDP = %d after a stop", got)
	}
}

// UDP has no handshake, so a source address costs nothing to invent and need not be
// reachable. One datagram per made-up source is one dialed socket and one goroutine, and
// the idle sweep cannot help while the flood is still arriving -- it evicts on idleness
// measured from now. Descriptors are a process-wide budget, so the forward that runs out
// takes everything else with it.
func TestAFloodOfClientsCannotGrowTheSessionTablePastItsLimit(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_flood"), nil)
	const limit = 8
	h.uf.maxSessions = limit

	// Far more distinct sources than the ceiling, each seen exactly once -- which is what
	// a spoofed flood looks like from here.
	ctx := context.Background()
	for i := range limit * 4 {
		client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000 + i}
		if _, _, err := h.uf.sessionFor(ctx, client); err != nil {
			t.Fatalf("sessionFor(%s): %v", client, err)
		}
		if got := h.sessionCount(); got > limit {
			t.Fatalf("after %d clients the table holds %d sessions, over the limit of %d",
				i+1, got, limit)
		}
	}

	if got := h.sessionCount(); got != limit {
		t.Errorf("table holds %d sessions, want it filled to its limit of %d", got, limit)
	}
	if got := h.status().ActiveUDP; got != limit {
		t.Errorf("ActiveUDP = %d, want the count to follow the table at %d", got, limit)
	}
	if got := h.status().Error; !strings.Contains(got, "was dropped to make room") {
		t.Errorf("error = %q, want it to say a session was dropped for the limit", got)
	}
}

// Which session goes matters as much as that one goes. A client still sending is touched
// by every datagram, so it must never be the one dropped -- otherwise a flood of made-up
// sources evicts the real clients and the cap becomes the denial of service it exists to
// prevent.
func TestTheClientStillSendingSurvivesAFloodOfNewOnes(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_survive"), nil)
	const limit = 4
	h.uf.maxSessions = limit

	ctx := context.Background()
	regular := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 39000}
	kept, _, err := h.uf.sessionFor(ctx, regular)
	if err != nil {
		t.Fatalf("sessionFor(the regular client): %v", err)
	}

	for i := range limit * 3 {
		// The regular client is active throughout, which is the whole of what marks it
		// out from the flood.
		kept.touch()
		client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41000 + i}
		if _, _, err := h.uf.sessionFor(ctx, client); err != nil {
			t.Fatalf("sessionFor(%s): %v", client, err)
		}
	}

	h.uf.mu.Lock()
	still, ok := h.uf.sessions[regular.String()]
	h.uf.mu.Unlock()
	if !ok {
		t.Fatal("the client that never stopped sending was evicted by clients that sent once")
	}
	if still != kept {
		t.Error("the regular client's session was replaced rather than kept")
	}
}

// The clock is not what ranks the sessions: a coarse one reads the same for a whole flood
// and for the real client touched in the middle of it, and a tie would be settled by
// chance. The order traffic was seen in has no ties, so a session whose clock reading is
// the oldest of all still survives if it was the last to send.
func TestTheOrderOfTrafficRanksSessionsRatherThanTheClocksReading(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_order"), nil)
	const limit = 3
	h.uf.maxSessions = limit

	ctx := context.Background()
	var sessions []*session
	for i := range limit {
		client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42000 + i}
		s, _, err := h.uf.sessionFor(ctx, client)
		if err != nil {
			t.Fatalf("sessionFor(%s): %v", client, err)
		}
		sessions = append(sessions, s)
	}
	// The first session sends last, on a clock that then reads earlier than every other
	// session's: what a clock stepping back, or one too coarse to tell them apart, gives.
	sessions[0].touch()
	sessions[0].lastSeen.Store(0)

	evicted := func() *session {
		h.uf.mu.Lock()
		defer h.uf.mu.Unlock()
		return h.uf.makeRoomLocked()
	}()

	if evicted == sessions[0] {
		t.Fatal("the session that sent last was dropped because its clock reading was oldest")
	}
	if evicted != sessions[1] {
		t.Errorf("dropped %v, want the session that sent earliest (%v)", evicted.client, sessions[1].client)
	}
}

// A client evicted while still sending gets a second session under the same key, and the
// first one's reply pump then wakes on the socket the eviction closed. Cleaning up by key
// alone would close the replacement, and the client's traffic would stop for a reason it
// could neither see nor act on.
func TestCleaningUpAnEvictedSessionDoesNotCloseItsReplacement(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_replace"), nil)

	ctx := context.Background()
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 38000}
	first, _, err := h.uf.sessionFor(ctx, client)
	if err != nil {
		t.Fatalf("sessionFor: %v", err)
	}

	// Evict it the way makeRoomLocked does, then let the client back in.
	h.uf.mu.Lock()
	delete(h.uf.sessions, client.String())
	h.uf.mu.Unlock()
	second, isNew, err := h.uf.sessionFor(ctx, client)
	if err != nil {
		t.Fatalf("sessionFor after eviction: %v", err)
	}
	if !isNew || second == first {
		t.Fatal("the client did not get a new session after being evicted")
	}

	// What the evicted session's pump does on the way out.
	h.uf.removeSession(client.String(), first)

	h.uf.mu.Lock()
	held, ok := h.uf.sessions[client.String()]
	h.uf.mu.Unlock()
	if !ok {
		t.Fatal("cleaning up the evicted session removed the live one that replaced it")
	}
	if held != second {
		t.Error("the table no longer points at the replacement session")
	}
}

// The sweep interval is clamped to the idle timeout, so a deployment that tunes the
// timeout down does not keep sessions -- and their sockets -- alive for a whole default
// sweep afterwards.
func TestTheJanitorSweepsNoSlowerThanTheIdleTimeout(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("echo:9", echo)

	m := NewManager(carry(tn), testSettings, quietLogger()) // testSettings: 1s idle timeout
	// Far longer than the timeout: unclamped, the first sweep would not happen until
	// well after this test's deadline.
	m.janitorInterval = 30 * time.Second

	h := newUDPForward(t, m, udpFwd("f_sweep"), nil)
	sendTo(t, h.addr, "go idle after this")
	waitFor(t, 5*time.Second, "the session to be established", func() bool {
		return h.sessionCount() == 1
	})

	waitFor(t, 6*time.Second, "the idle session to be evicted", func() bool {
		return h.sessionCount() == 0
	})
	if got := h.status().ActiveUDP; got != 0 {
		t.Errorf("ActiveUDP = %d after eviction, want the count to follow the table", got)
	}
}

// A janitor interval of zero is what an unconfigured manager has. Falling through to a
// zero-duration ticker would panic and take the forward's goroutine with it.
func TestAZeroJanitorIntervalFallsBackToTheDefault(t *testing.T) {
	m := NewManager(carry(newFakeTailnet()), testSettings, quietLogger())
	m.janitorInterval = 0

	// Starting the forward is the assertion: time.NewTicker panics on a non-positive
	// interval, and the janitor runs on its own goroutine, so the panic would be fatal
	// for the process rather than recoverable.
	h := newUDPForward(t, m, udpFwd("f_zero"), nil)
	sendTo(t, h.addr, "still served")

	waitFor(t, 5*time.Second, "the forward to keep serving with an unset sweep interval", func() bool {
		return h.status().State == StateRunning
	})
}
