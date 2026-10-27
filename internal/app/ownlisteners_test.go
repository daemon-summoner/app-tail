// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/forward"
	"github.com/sellitus/app-tail/internal/httpapi"
	"golang.org/x/net/dns/dnsmessage"
)

// A to_tailnet forward to 127.0.0.1 on the dashboard's port would publish app-tail's own
// management API to every device on the tailnet. The write is refused, naming what it
// would have exposed.
func TestAForwardCannotExposeTheAgentsOwnListeners(t *testing.T) {
	h := newHarness(t, nil)
	dashboard := h.agent.UIAddr().String()
	_, port, err := net.SplitHostPort(dashboard)
	if err != nil {
		t.Fatal(err)
	}
	listen, _ := strconv.Atoi(port)

	for _, host := range []string{"127.0.0.1", "localhost", "[::1]", "0.0.0.0"} {
		target := host + ":" + port
		_, err := h.agent.Forwards().Create(context.Background(), httpapi.ForwardSpec{
			Direction:  ptr(config.ToTailnet),
			Protocol:   ptr(config.TCP),
			ListenPort: ptr(listen + 1),
			Target:     ptr(target),
		})
		if err == nil {
			t.Errorf("a forward to %s, app-tail's own dashboard, was stored", target)
			continue
		}
		var ve *config.ValidationError
		if !errors.As(err, &ve) || ve.Field != "target" {
			t.Errorf("target %s: error = %v, want a validation error on target", target, err)
		}
		want := "a forward cannot point at app-tail's own dashboard on"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("target %s: error = %v, want it to say %q", target, err, want)
		}
	}
	if n := len(h.store.Get().Forwards); n != 0 {
		t.Errorf("%d forwards stored, want every one refused", n)
	}

	// Moving an existing forward onto the dashboard is the same write by another route.
	created, err := h.agent.Forwards().Create(context.Background(), httpapi.ForwardSpec{
		Direction:  ptr(config.ToTailnet),
		Protocol:   ptr(config.TCP),
		ListenPort: ptr(listen + 2),
		Target:     ptr("127.0.0.1:" + strconv.Itoa(freePort(t))),
	})
	if err != nil {
		t.Fatalf("a forward to an unrelated loopback port was refused: %v", err)
	}
	if _, err := h.agent.Forwards().Update(context.Background(), created.ID, httpapi.ForwardSpec{
		Target: ptr(dashboard),
	}); err == nil || !strings.Contains(err.Error(), "own dashboard") {
		t.Errorf("updating a forward onto the dashboard: error = %v, want it refused", err)
	}
}

// A forward to some other service on this machine is the ordinary reason to have one.
func TestAForwardToAnUnrelatedLoopbackPortIsAllowed(t *testing.T) {
	h := newHarness(t, nil)
	target := "127.0.0.1:" + strconv.Itoa(freePort(t))
	created, err := h.agent.Forwards().Create(context.Background(), httpapi.ForwardSpec{
		Direction:  ptr(config.ToTailnet),
		Protocol:   ptr(config.TCP),
		ListenPort: ptr(freePort(t)),
		Target:     ptr(target),
	})
	if err != nil {
		t.Fatalf("a forward to %s was refused: %v", target, err)
	}
	if created.Target != target {
		t.Errorf("target = %q, want %q", created.Target, target)
	}
}

// The listeners move -- a proxy whose port was taken lands on another -- so a forward
// stored while harmless is judged again every time the forwards are started.
func TestAForwardThatNowPointsAtTheAgentIsHeldOffAtStart(t *testing.T) {
	h := newHarness(t, nil)
	dashboard := h.agent.UIAddr().String()
	harmless := config.Forward{
		ID: "f_harmls", Name: "harmless", Direction: config.ToTailnet, Protocol: config.TCP,
		ListenPort: 9000, Target: "127.0.0.1:" + strconv.Itoa(freePort(t)), Enabled: true,
	}
	moved := config.Forward{
		ID: "f_moved0", Name: "moved", Direction: config.ToTailnet, Protocol: config.TCP,
		ListenPort: 9001, Target: dashboard, Enabled: true,
	}

	admitted := h.agent.admitForwards([]config.Forward{harmless, moved})

	if len(admitted) != 2 {
		t.Fatalf("admitted %d forwards, want both kept in the set: %+v", len(admitted), admitted)
	}
	if !admitted[0].Enabled {
		t.Error("the harmless forward was held off")
	}
	if admitted[1].Enabled {
		t.Error("the forward pointing at the dashboard was handed on to be started")
	}

	view := h.agent.withSelfTargetRefusal(moved, httpapi.ForwardView{Forward: moved, State: forward.StateRunning})
	if view.State != forward.StateError || !strings.Contains(view.Error, "own dashboard") {
		t.Errorf("view = state %q error %q, want the forward shown failed with the reason", view.State, view.Error)
	}
}

func TestSelfTargetRefusalJudgesTransportAndName(t *testing.T) {
	resolver := ownListener{what: "resolver", addr: netip.MustParseAddrPort("127.0.0.153:53"), tcp: true, udp: true}
	proxy := ownListener{what: "proxy", addr: netip.MustParseAddrPort("127.0.0.1:1080"), tcp: true}
	listeners := []ownListener{resolver, proxy}
	lookup := func(host string) ([]netip.Addr, error) {
		switch host {
		case "me.example":
			return []netip.Addr{netip.MustParseAddr("127.0.1.1")}, nil
		case "nas.example":
			return []netip.Addr{netip.MustParseAddr("192.168.1.5")}, nil
		}
		return nil, errors.New("no such host")
	}
	fwd := func(proto config.Protocol, target string) config.Forward {
		return config.Forward{Direction: config.ToTailnet, Protocol: proto, ListenPort: 9000, Target: target}
	}

	refused := []config.Forward{
		fwd(config.UDP, "127.0.0.1:53"),
		fwd(config.TCP, "[::ffff:127.0.0.1]:1080"),
		fwd(config.Both, "me.example:1080"),
		fwd(config.TCP, "LOCALHOST.:1080"),
	}
	for _, f := range refused {
		if err := selfTargetRefusal(f, listeners, lookup, nil); err == nil {
			t.Errorf("%s %s was allowed", f.Protocol, f.Target)
		}
	}
	allowed := []config.Forward{
		// The proxy listens on TCP alone, so UDP to its port reaches something else.
		fwd(config.UDP, "127.0.0.1:1080"),
		fwd(config.TCP, "nas.example:1080"),
		fwd(config.TCP, "127.0.0.1:8080"),
		fwd(config.TCP, "unresolvable.example:1080"),
	}
	for _, f := range allowed {
		if err := selfTargetRefusal(f, listeners, lookup, nil); err != nil {
			t.Errorf("%s %s was refused: %v", f.Protocol, f.Target, err)
		}
	}
}

// A target that is not host:port cannot be judged, so it cannot be let through as harmless
// either: it is refused with what is wrong with it.
func TestATargetThatCannotBeReadIsRefusedRatherThanWavedThrough(t *testing.T) {
	listeners := []ownListener{{what: "proxy", addr: netip.MustParseAddrPort("127.0.0.1:1080"), tcp: true}}
	for _, target := range []string{"127.0.0.1", "localhost:proxy", "[::1:1080"} {
		f := config.Forward{Direction: config.ToTailnet, Protocol: config.TCP, ListenPort: 9000, Target: target}
		err := selfTargetRefusal(f, listeners, nil, nil)
		var invalid *config.ValidationError
		if !errors.As(err, &invalid) || invalid.Field != "target" {
			t.Errorf("target %q: got %v, want a refusal naming the target", target, err)
		}
	}
}

// A proxy bound to every address answers on this machine's LAN and tailnet addresses as
// well as on loopback, so a forward to either of them on the proxy's port publishes the
// proxy exactly as a forward to 127.0.0.1 would. A listener bound to loopback alone is
// not reached that way, and another machine on the LAN is not this one.
func TestAForwardCannotReachTheAgentThroughThisMachinesOwnNetworkAddresses(t *testing.T) {
	lan := netip.MustParseAddr("192.0.2.10")
	h := newHarnessWith(t, nil, func(o *Options) {
		o.HostAddrs = func() ([]netip.Addr, error) { return []netip.Addr{lan}, nil }
	})
	h.bringUp()

	everywhere := ownListener{what: "proxy", addr: netip.MustParseAddrPort("0.0.0.0:8080"), tcp: true}
	loopbackOnly := ownListener{what: "dashboard", addr: netip.MustParseAddrPort("127.0.0.1:8377"), tcp: true}
	listeners := []ownListener{everywhere, loopbackOnly}
	fwd := func(target string) config.Forward {
		return config.Forward{Direction: config.ToTailnet, Protocol: config.TCP, ListenPort: 9000, Target: target}
	}

	// 100.64.0.9 is the address the fake node takes once it is running.
	for _, target := range []string{"192.0.2.10:8080", "[::ffff:192.0.2.10]:8080", "100.64.0.9:8080"} {
		err := selfTargetRefusal(fwd(target), listeners, nil, h.agent.thisMachineAddrs)
		if err == nil || !strings.Contains(err.Error(), "own proxy") {
			t.Errorf("a forward to %s, this machine's own address on the proxy's port: error = %v, want it refused", target, err)
		}
	}
	for _, target := range []string{"192.0.2.99:8080", "192.0.2.10:8377", "100.64.0.9:8377"} {
		if err := selfTargetRefusal(fwd(target), listeners, nil, h.agent.thisMachineAddrs); err != nil {
			t.Errorf("a forward to %s reaches none of app-tail's listeners but was refused: %v", target, err)
		}
	}
}

// When this machine's addresses cannot be read, a target on one of app-tail's ports cannot
// be shown to be somewhere else, so it is refused with the reason rather than let through.
// A target on no listener's port needs no such answer and is not held up by the failure.
func TestATargetOnAnOwnPortIsRefusedWhenThisMachinesAddressesCannotBeRead(t *testing.T) {
	listeners := []ownListener{{what: "proxy", addr: netip.MustParseAddrPort("0.0.0.0:8080"), tcp: true}}
	unreadable := func() ([]netip.Addr, error) { return nil, errors.New("interface table unavailable") }
	fwd := func(target string) config.Forward {
		return config.Forward{Direction: config.ToTailnet, Protocol: config.TCP, ListenPort: 9000, Target: target}
	}

	err := selfTargetRefusal(fwd("192.0.2.10:8080"), listeners, nil, unreadable)
	if err == nil || !strings.Contains(err.Error(), "interface table unavailable") {
		t.Errorf("error = %v, want a refusal carrying why this machine's addresses could not be read", err)
	}
	if err := selfTargetRefusal(fwd("192.0.2.10:9443"), listeners, nil, unreadable); err != nil {
		t.Errorf("a target on no listener's port was refused: %v", err)
	}
}

// A named target is looked up when the forward is written, but what the name resolves to
// can change afterwards, and a lookup that failed then judged nothing at all. The address
// each connection actually dials is judged again, so a name that comes to resolve onto
// app-tail's own dashboard is refused when a peer connects rather than handed the API.
func TestAForwardWhoseNameLaterResolvesToTheAgentIsRefusedWhenItConnects(t *testing.T) {
	names := serveFakeNames(t)
	h := newHarness(t, nil)
	h.bringUp()
	_, dashPort, err := net.SplitHostPort(h.agent.UIAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	listen := freePort(t)

	// The name does not resolve yet, so the write has nothing to judge and lets it through.
	created, err := h.agent.Forwards().Create(context.Background(), httpapi.ForwardSpec{
		Direction:  ptr(config.ToTailnet),
		Protocol:   ptr(config.TCP),
		ListenPort: ptr(listen),
		Target:     ptr("drifting.example:" + dashPort),
	})
	if err != nil {
		t.Fatalf("a forward to a name that resolves nowhere yet was refused: %v", err)
	}
	waitFor(t, 5*time.Second, "the forward to start", func() bool {
		return h.agent.Forwards().AllRunning()
	})

	names.set("drifting.example", netip.MustParseAddr("127.0.0.1"))

	peer, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listen)), 5*time.Second)
	if err != nil {
		t.Fatalf("connect to the forward: %v", err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(peer, "GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("send through the forward: %v", err)
	}
	reply, _ := io.ReadAll(peer)
	if len(reply) != 0 {
		t.Fatalf("a peer reached app-tail's own dashboard through the forward; it answered %q", reply)
	}

	waitFor(t, 5*time.Second, "the refusal to reach the forward's view", func() bool {
		view, err := h.agent.Forwards().Get(created.ID)
		return err == nil && strings.Contains(view.Error, "own dashboard")
	})
}

// fakeNames is a name server answering A queries from a table a test can change while it
// runs. Every other name does not exist, and every other question has no answer.
type fakeNames struct {
	mu    sync.Mutex
	table map[string]netip.Addr
}

func (n *fakeNames) set(name string, addr netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.table[name] = addr
}

// serveFakeNames points this process's resolver at a fake name server for the length of
// the test. The resolver is process-wide, so a test using it must not run in parallel.
func serveFakeNames(t *testing.T) *fakeNames {
	t.Helper()
	names := &fakeNames{table: make(map[string]netip.Addr)}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for name queries: %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			reply, err := names.answer(buf[:n])
			if err != nil {
				t.Errorf("answer a name query: %v", err)
				continue
			}
			if _, err := pc.WriteTo(reply, from); err != nil {
				t.Errorf("send a name answer: %v", err)
			}
		}
	}()

	restore := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = restore
		pc.Close()
		<-served
	})
	return names
}

func (n *fakeNames) answer(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	addr, known := n.table[strings.TrimSuffix(q.Name.String(), ".")]
	n.mu.Unlock()

	rcode := dnsmessage.RCodeSuccess
	if !known {
		rcode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: header.ID, Response: true, Authoritative: true, RecursionAvailable: true, RCode: rcode,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if known && q.Type == dnsmessage.TypeA && addr.Is4() {
		if err := b.AResource(
			dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			dnsmessage.AResource{A: addr.As4()},
		); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
