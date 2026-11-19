// SPDX-License-Identifier: MIT

package forward

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
)

// parkingTailnet dials straight through until it is told to park, and then holds every new
// dial until released. It is what a target that takes its time looks like once a forward is
// already carrying somebody: the clients that came first are set up, the next one is not.
type parkingTailnet struct {
	*fakeTailnet
	park   atomic.Bool
	gate   chan struct{}
	parked atomic.Int32
}

func newParkingTailnet() *parkingTailnet {
	return &parkingTailnet{fakeTailnet: newFakeTailnet(), gate: make(chan struct{})}
}

func (p *parkingTailnet) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if p.park.Load() {
		p.parked.Add(1)
		select {
		case <-p.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return p.fakeTailnet.Dial(ctx, network, address)
}

var _ Tailnet = (*parkingTailnet)(nil)

// readReply reads one datagram from a client socket within wait.
func readReply(t *testing.T, conn net.Conn, wait time.Duration) (string, error) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatalf("set a read deadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	return string(buf[:n]), err
}

// One listening socket serves every client, so whatever its read loop waits on, they all
// wait on. A new client whose target is slow to reach must cost the clients already being
// carried nothing, and what it sent while it waited must still arrive, in the order sent.
func TestAClientBeingSetUpDoesNotHoldUpTheOthers(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newParkingTailnet()
	tn.route("echo:9", echo)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_slow"), nil)

	regular := sendTo(t, h.addr, "already here")
	if got, err := readReply(t, regular, 3*time.Second); err != nil || got != "already here" {
		t.Fatalf("the first client's reply = %q, %v", got, err)
	}

	tn.park.Store(true)
	newcomer := sendTo(t, h.addr, "one")
	waitFor(t, 5*time.Second, "the new client's dial to be under way", func() bool {
		return tn.parked.Load() == 1
	})

	if _, err := regular.Write([]byte("still here")); err != nil {
		t.Fatalf("send from the established client: %v", err)
	}
	// Well inside the time a dial is allowed to take.
	if got, err := readReply(t, regular, udpDialTimeout/2); err != nil || got != "still here" {
		t.Fatalf("the established client's reply while another was being set up = %q, %v", got, err)
	}

	for _, payload := range []string{"two", "three"} {
		if _, err := newcomer.Write([]byte(payload)); err != nil {
			t.Fatalf("send %q: %v", payload, err)
		}
	}
	// Both are read off the socket before the dial is let through, so they are what waited.
	if _, err := regular.Write([]byte("and again")); err != nil {
		t.Fatalf("send from the established client: %v", err)
	}
	if got, err := readReply(t, regular, 3*time.Second); err != nil || got != "and again" {
		t.Fatalf("the established client's reply = %q, %v", got, err)
	}
	close(tn.gate)

	for _, want := range []string{"one", "two", "three"} {
		got, err := readReply(t, newcomer, 3*time.Second)
		if err != nil || got != want {
			t.Fatalf("the new client read %q, %v; want %q, in the order it was sent", got, err, want)
		}
	}
	if got := h.status().Error; got != "" {
		t.Errorf("error = %q after every datagram was delivered", got)
	}
}

// A dial costs a socket and a goroutine before anything is known about the client, and a
// source address costs nothing to invent. The dials in flight are bounded like the table
// they fill.
func TestClientsBeingSetUpAtOnceAreBounded(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newParkingTailnet()
	tn.route("echo:9", echo)
	tn.park.Store(true)
	m := newTestManager(t, tn)
	h := newUDPForward(t, m, udpFwd("f_dials"), nil)

	const over = 6
	for i := range maxUDPDials + over {
		sendTo(t, h.addr, fmt.Sprintf("client %d", i))
	}
	waitFor(t, 5*time.Second, "the refusal to be recorded", func() bool {
		return strings.Contains(h.status().Error, "being set up")
	})
	// The refusal is recorded by the read loop and the dials start on goroutines of their
	// own, so the count is waited for; the sessions counted below are what shows it stopped
	// at the limit.
	waitFor(t, 5*time.Second, "every dial that was let in to be under way", func() bool {
		return int(tn.parked.Load()) >= maxUDPDials
	})
	if got := int(tn.parked.Load()); got != maxUDPDials {
		t.Errorf("%d dials are in flight, want the limit of %d", got, maxUDPDials)
	}
	if st := h.status(); st.State != StateRunning {
		t.Errorf("state = %q; turning new clients away must not stop the forward", st.State)
	}

	close(tn.gate)
	waitFor(t, 5*time.Second, "the clients that were let in to be set up", func() bool {
		return h.sessionCount() == maxUDPDials
	})
}

// What a client sends while it is being set up is held for it, and a client that keeps
// sending to a target that is not answering cannot be allowed to fill memory doing it.
func TestWhatIsHeldForAClientBeingSetUpIsBounded(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newParkingTailnet()
	tn.route("echo:9", echo)
	tn.park.Store(true)
	logs := new(syncBuffer)
	m := newTestManagerLogging(t, carry(tn), slog.New(slog.NewTextHandler(logs, nil)))
	h := newUDPForward(t, m, udpFwd("f_held"), nil)

	const size = 1024
	const overflow = 8
	fits := maxHeldBytes / size
	conn := dialUDP(t, h.addr)
	for i := range fits + overflow {
		datagram := []byte(strings.Repeat(string(rune('a'+i%26)), size))
		if _, err := conn.Write(datagram); err != nil {
			t.Fatalf("send datagram %d: %v", i, err)
		}
	}
	// Every datagram past the limit has to be turned away before the session opens: one that is
	// still queued in the socket then reaches a live session and is carried, as it should be.
	waitFor(t, 5*time.Second, "every datagram past the limit to be turned away", func() bool {
		return strings.Count(logs.String(), "dropped a datagram from a client still being set up") == overflow
	})
	if !strings.Contains(h.status().Error, "was dropped") {
		t.Errorf("the overflow was not reported, status error = %q", h.status().Error)
	}
	close(tn.gate)

	for i := range fits {
		got, err := readReply(t, conn, 3*time.Second)
		if err != nil {
			t.Fatalf("reply %d of the %d that were held: %v", i, fits, err)
		}
		if want := string(rune('a' + i%26)); len(got) != size || got[:1] != want {
			t.Fatalf("reply %d is %d bytes of %q, want %d of %q", i, len(got), got[:1], size, want)
		}
	}
	if got, err := readReply(t, conn, 300*time.Millisecond); err == nil {
		t.Errorf("a datagram past what is held was delivered (%d bytes)", len(got))
	}
}

// A forward pointed at a resolver or a gateway carries datagrams for names nobody typed
// here. One that inspection stops never reaches the target, and the client's flow ends with
// it; the ones before it were offered and carried.
func TestAForwardedDatagramInspectionStopsNeverReachesTheTarget(t *testing.T) {
	target := newRecordingUDP(t)
	tn := newFakeTailnet()
	tn.route("resolver:53", target.addr)
	m := newTestManager(t, tn)

	stream := &stoppingStream{stopOn: "bad.example"}
	seen := &fakeInspector{watchDatagrams: func(inspect.Flow) netpipe.Stream { return stream }}
	m.SetInspector(seen)
	h := newUDPForward(t, m, udpToLocal("f_dns", 1, "resolver:53"), nil)

	conn := sendTo(t, h.addr, "a question about good.example")
	if got, err := readReply(t, conn, 3*time.Second); err != nil || got != "a question about good.example" {
		t.Fatalf("the datagram nothing stops came back as %q, %v", got, err)
	}

	if _, err := conn.Write([]byte("a question about bad.example")); err != nil {
		t.Fatalf("send the datagram to be stopped: %v", err)
	}
	waitFor(t, 5*time.Second, "the stopped client's session to be dropped", func() bool {
		return h.sessionCount() == 0
	})
	if got := target.received(); len(got) != 1 || got[0] != "a question about good.example" {
		t.Errorf("the target received %q, want only the datagram nothing stopped", got)
	}
	if offered := stream.offered(); len(offered) != 2 {
		t.Errorf("the inspector was offered %d datagrams, want both", len(offered))
	}
	waitForClose(t, stream)

	flows := seen.datagramFlows()
	if len(flows) != 1 {
		t.Fatalf("the inspector was asked about %d datagram flows, want the one client", len(flows))
	}
	if flows[0].Protocol != "udp" || flows[0].Name != "resolver" || flows[0].Port != 53 || flows[0].Where != "a port forward" {
		t.Errorf("flow = %+v, want the forward's target as a datagram flow", flows[0])
	}
}

// Nothing reading is the module switched off, and a forward has to carry everything then.
func TestAUDPForwardNothingIsReadingCarriesEverything(t *testing.T) {
	echo := startEchoUDP(t)
	tn := newFakeTailnet()
	tn.route("resolver:53", echo)
	m := newTestManager(t, tn)
	// An inspector with no reader for this flow, which is what it answers when its
	// switches are off.
	m.SetInspector(&fakeInspector{})
	h := newUDPForward(t, m, udpToLocal("f_dns", 1, "resolver:53"), nil)

	conn := sendTo(t, h.addr, "a question about bad.example")
	if got, err := readReply(t, conn, 3*time.Second); err != nil || got != "a question about bad.example" {
		t.Fatalf("round trip with nothing reading = %q, %v", got, err)
	}
}
