// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sellitus/app-tail/internal/testport"
)

// fakeUpstream is a resolver that answers however the test says. It is the seam the
// Upstream interface exists for: everything above it is exercised without a socket.
type fakeUpstream struct {
	label  string
	answer func(query []byte) ([]byte, error)

	mu      sync.Mutex
	asked   []Question
	streams []bool
}

func (f *fakeUpstream) Exchange(ctx context.Context, query []byte, stream bool) ([]byte, error) {
	q, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.asked = append(f.asked, q)
	f.streams = append(f.streams, stream)
	f.mu.Unlock()
	return f.answer(query)
}

func (f *fakeUpstream) Label() string { return f.label }
func (f *fakeUpstream) Close() error  { return nil }

func (f *fakeUpstream) questions() []Question {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Question(nil), f.asked...)
}

// answering builds an upstream that replies with one address and NOERROR.
func answering(label, addr string) *fakeUpstream {
	return &fakeUpstream{label: label, answer: func(query []byte) ([]byte, error) {
		q, err := parseQuestion(query)
		if err != nil {
			return nil, err
		}
		return buildResponse(q, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{
			addressRecord(q, netip.MustParseAddr(addr)),
		}, nil), nil
	}}
}

// refusing builds an upstream that answers with a code and no records.
func coding(label string, code dnsmessage.RCode) *fakeUpstream {
	return &fakeUpstream{label: label, answer: func(query []byte) ([]byte, error) {
		q, err := parseQuestion(query)
		if err != nil {
			return nil, err
		}
		return buildResponse(q, code, false, nil, nil), nil
	}}
}

// failing builds an upstream that cannot be reached at all.
func failing(label string) *fakeUpstream {
	return &fakeUpstream{label: label, answer: func([]byte) ([]byte, error) {
		return nil, errors.New("connection refused")
	}}
}

func newTestForwarder(t *testing.T, cfg Config) *Forwarder {
	t.Helper()
	f := New(cfg)
	t.Cleanup(func() { f.Close() })
	return f
}

// The security property the dashboard's same-origin check depends on: after this feature
// ships, app-tail is the resolver that check reasons about, and an upstream answering
// "evil.localhost is 127.0.0.1" would pass every guard the dashboard has.
func TestALocalhostQueryIsNeverForwarded(t *testing.T) {
	profile := answering("profile", "203.0.113.5")
	local := answering("local", "192.0.2.5")
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{profile}, nil),
		Local:   NewPool([]Upstream{local}, nil),
	})

	for _, name := range []string{"localhost", "evil.localhost", "app.localhost", "DEEP.sub.LOCALHOST"} {
		resp := f.Answer(context.Background(), buildQuery(t, name, dnsmessage.TypeA), false)
		addrs := addressesIn(t, resp)
		if len(addrs) != 1 || !addrs[0].IsLoopback() {
			t.Errorf("%s resolved to %v, want loopback and nothing else", name, addrs)
		}
	}
	if got := profile.questions(); len(got) != 0 {
		t.Errorf("the profile was asked %v -- a localhost name must never leave this machine", got)
	}
	if got := local.questions(); len(got) != 0 {
		t.Errorf("the network's resolver was asked %v -- a localhost name must never leave this machine", got)
	}
}

// A filtering resolver blocks a domain by answering that it does not exist. Asking anyone
// else afterwards is how a blocklist stops working, so the retry is off unless the user
// turns it on.
func TestNXDOMAINIsFinalUnlessTheRetrySwitchIsOn(t *testing.T) {
	newPair := func(retry bool) (*Forwarder, *fakeUpstream) {
		blocked := coding("profile", dnsmessage.RCodeNameError)
		local := answering("local", "192.0.2.5")
		f := newTestForwarder(t, Config{
			Rules:           Rules{HaveLocal: true},
			Profile:         NewPool([]Upstream{blocked}, nil),
			Local:           NewPool([]Upstream{local}, nil),
			RetryOnNXDOMAIN: retry,
		})
		return f, local
	}

	f, local := newPair(false)
	resp := f.Answer(context.Background(), buildQuery(t, "ads.example.com", dnsmessage.TypeA), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN -- the profile's answer is the answer", code)
	}
	if got := local.questions(); len(got) != 0 {
		t.Fatalf("the network's resolver was asked %v with the retry switch off", got)
	}

	f, local = newPair(true)
	resp = f.Answer(context.Background(), buildQuery(t, "ads.example.com", dnsmessage.TypeA), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeSuccess {
		t.Errorf("rcode = %s, want NOERROR once the retry switch is on", code)
	}
	if got := local.questions(); len(got) != 1 {
		t.Errorf("the network's resolver was asked %v, want exactly one query", got)
	}
}

// Not NXDOMAIN, which the machine would cache as "this name does not exist"; not silence,
// which reads as a machine with no resolver at all.
func TestEveryUpstreamFailingIsSERVFAILAndNotNXDOMAIN(t *testing.T) {
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{failing("first"), failing("second")}, nil),
		Local:   NewPool([]Upstream{answering("local", "192.0.2.5")}, nil),
	})
	resp := f.Answer(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if len(resp) == 0 {
		t.Fatal("no answer at all")
	}
	if code, _ := rcode(resp); code != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", code)
	}
	if f.Stats().Failures != 1 {
		t.Errorf("failures = %d, want 1", f.Stats().Failures)
	}
}

// A profile with nothing behind it fails loudly rather than quietly falling back to the
// network: a silent fallback is a blocklist that stopped working with nobody told.
func TestAProfileWithNoResolversFailsRatherThanFallingBack(t *testing.T) {
	local := answering("local", "192.0.2.5")
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool(nil, nil),
		Local:   NewPool([]Upstream{local}, nil),
	})
	resp := f.Answer(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", code)
	}
	if got := local.questions(); len(got) != 0 {
		t.Errorf("the network's resolver was asked %v", got)
	}
}

func TestTheProfileNeverSeesWhichNetworkTheUserIsOn(t *testing.T) {
	var seen []uint16
	probe := &fakeUpstream{label: "profile", answer: func(query []byte) ([]byte, error) {
		if opt, ok := findOPT(query); ok {
			seen = optionCodes(t, opt.rdata)
		}
		q, err := parseQuestion(query)
		if err != nil {
			return nil, err
		}
		return buildResponse(q, dnsmessage.RCodeSuccess, false, nil, nil), nil
	}}
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{probe}, nil),
	})
	cookie := dnsmessage.Option{Code: 10, Data: []byte{1, 2, 3, 4}}
	f.Answer(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA, cookie, clientSubnet()), false)
	for _, code := range seen {
		if code == ecsOption {
			t.Fatal("the client-subnet option reached the profile")
		}
	}
	if len(seen) != 1 || seen[0] != 10 {
		t.Errorf("the profile saw options %v, want the client's cookie kept", seen)
	}
}

func TestAnAnswerTooLargeForTheClientComesBackTruncated(t *testing.T) {
	big := &fakeUpstream{label: "profile", answer: func(query []byte) ([]byte, error) {
		q, err := parseQuestion(query)
		if err != nil {
			return nil, err
		}
		var records []dnsmessage.Resource
		for i := 0; i < 60; i++ {
			records = append(records, addressRecord(q, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})))
		}
		return buildResponse(q, dnsmessage.RCodeSuccess, false, records, nil), nil
	}}
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{big}, nil),
	})

	// Over UDP with no EDNS the client can take 512 bytes, and the answer is larger.
	query := buildQuery(t, "example.com", dnsmessage.TypeA)
	udp := f.Answer(context.Background(), query, false)
	if !truncated(udp) {
		t.Errorf("a %d-byte answer came back untruncated to a 512-byte client", len(udp))
	}
	if len(addressesIn(t, udp)) != 0 {
		t.Error("a truncated answer carries records; it is a signal, not a partial answer")
	}
	// The same query over TCP has no size limit, so the whole answer goes back.
	tcp := f.Answer(context.Background(), query, true)
	if truncated(tcp) {
		t.Error("the answer was truncated over TCP, where there is no size limit")
	}
	if got := len(addressesIn(t, tcp)); got != 60 {
		t.Errorf("addresses over TCP = %d, want 60", got)
	}
}

// An upstream that says "ask me over TCP" is asked over TCP, rather than the signal being
// passed to the client to deal with.
func TestATruncatedUpstreamAnswerIsRetriedOverAStream(t *testing.T) {
	up := &fakeUpstream{label: "profile"}
	up.answer = func(query []byte) ([]byte, error) {
		q, err := parseQuestion(query)
		if err != nil {
			return nil, err
		}
		up.mu.Lock()
		stream := up.streams[len(up.streams)-1]
		up.mu.Unlock()
		if !stream {
			return buildResponse(q, dnsmessage.RCodeSuccess, true, nil, nil), nil
		}
		return buildResponse(q, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{
			addressRecord(q, netip.MustParseAddr("203.0.113.9")),
		}, nil), nil
	}
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{up}, nil),
	})
	resp := f.Answer(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if truncated(resp) {
		t.Fatal("the truncated answer was passed straight through")
	}
	if addrs := addressesIn(t, resp); len(addrs) != 1 {
		t.Fatalf("addresses = %v, want the answer from the stream retry", addrs)
	}
	if got := len(up.questions()); got != 2 {
		t.Errorf("the upstream was asked %d times, want 2 -- once per transport", got)
	}
}

// A resolver that panics takes the machine's name resolution with it. The barrier turns
// that into one failed query.
func TestAPanicWhileAnsweringBecomesOneFailedQuery(t *testing.T) {
	boom := &fakeUpstream{label: "profile", answer: func([]byte) ([]byte, error) {
		panic("the upstream exploded")
	}}
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{boom}, nil),
		Logf:    func(string, ...any) {},
	})
	resp := f.answerSafely(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", code)
	}
	// And the next query still works.
	f.Configure(Config{Rules: Rules{HaveLocal: true}, Profile: NewPool([]Upstream{answering("profile", "203.0.113.1")}, nil)})
	resp = f.answerSafely(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeSuccess {
		t.Errorf("the query after a panic answered %s", code)
	}
}

// fakeTunnels is a connection's own resolver, and the translation from the addresses that
// network uses to the ones this machine reaches them at.
type fakeTunnels struct {
	answer func(tunnelID, host string) ([]netip.Addr, error)

	mu    sync.Mutex
	asked [][2]string
}

func (f *fakeTunnels) LookupTunnel(_ context.Context, tunnelID, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.asked = append(f.asked, [2]string{tunnelID, host})
	f.mu.Unlock()
	return f.answer(tunnelID, host)
}

func (f *fakeTunnels) questions() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]string(nil), f.asked...)
}

func carryingRules() Rules {
	return Rules{
		TunnelSuffixes: []TunnelSuffix{{Suffix: "office.internal", Name: "Office", ID: "tn_office", Carried: true}},
		HaveLocal:      true,
	}
}

// The whole point of the interface mode from a name's side: a host on a connected network
// resolves for every program on this machine, at the address this machine reaches it at --
// which is not the address that network gave when the network had to be moved out of
// another's way.
func TestANameOnACarriedConnectionIsAnsweredWithTheAddressThisMachineReachesItAt(t *testing.T) {
	profile := answering("profile", "203.0.113.5")
	tunnels := &fakeTunnels{answer: func(string, string) ([]netip.Addr, error) {
		// The network's own resolver said 10.0.2.3; the network was moved, so this machine
		// reaches that host at 198.18.2.3 and only that address may be answered with.
		return []netip.Addr{netip.MustParseAddr("198.18.2.3")}, nil
	}}
	f := newTestForwarder(t, Config{
		Rules:   carryingRules(),
		Tunnels: tunnels,
		Profile: NewPool([]Upstream{profile}, nil),
	})

	resp := f.Answer(context.Background(), buildQuery(t, "db.office.internal", dnsmessage.TypeA), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", code)
	}
	addrs := addressesIn(t, resp)
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.18.2.3") {
		t.Errorf("answered %v, want the address this machine reaches the host at", addrs)
	}
	if got := tunnels.questions(); len(got) != 1 || got[0] != [2]string{"tn_office", "db"} {
		t.Errorf("the connection was asked %v, want tn_office for \"db\"", got)
	}
	if got := profile.questions(); len(got) != 0 {
		t.Errorf("the profile was asked %v -- a private name must never leave this machine", got)
	}
}

// The answer is built from the addresses rather than passed through, so the record type has
// to be honoured here: a client asking for AAAA and handed an A record has been answered a
// question it did not ask, and every stub resolver treats that as a broken server.
func TestOnlyTheAddressesTheClientAskedForComeBack(t *testing.T) {
	tunnels := &fakeTunnels{answer: func(string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.18.2.3"), netip.MustParseAddr("fd7a::1")}, nil
	}}
	f := newTestForwarder(t, Config{Rules: carryingRules(), Tunnels: tunnels})

	for _, tc := range []struct {
		typ  dnsmessage.Type
		want string
	}{
		{dnsmessage.TypeA, "198.18.2.3"},
		{dnsmessage.TypeAAAA, "fd7a::1"},
	} {
		resp := f.Answer(context.Background(), buildQuery(t, "db.office.internal", tc.typ), false)
		addrs := addressesIn(t, resp)
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr(tc.want) {
			t.Errorf("%s answered %v, want only %s", tc.typ, addrs, tc.want)
		}
	}

	// A type this cannot answer for is NOERROR with no records: the name exists on that
	// network, and NXDOMAIN would tell the machine to stop asking about it entirely.
	resp := f.Answer(context.Background(), buildQuery(t, "db.office.internal", dnsmessage.TypeMX), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeSuccess {
		t.Errorf("an MX query answered %s, want NOERROR with no records", code)
	}
	if addrs := addressesIn(t, resp); len(addrs) != 0 {
		t.Errorf("an MX query came back with addresses %v", addrs)
	}
}

// The two ways a lookup inside a connection does not produce an address, told apart. They
// must not be the same answer: NXDOMAIN is cached and stops the machine asking again, which
// for a connection that is merely unreachable would outlive the outage.
func TestANameAConnectionDoesNotServeIsNXDOMAINAndAFailureIsNot(t *testing.T) {
	tests := []struct {
		name   string
		answer func(string, string) ([]netip.Addr, error)
		want   dnsmessage.RCode
	}{
		{"the network does not know the name", func(string, string) ([]netip.Addr, error) { return nil, nil }, dnsmessage.RCodeNameError},
		{"the network could not be asked", func(string, string) ([]netip.Addr, error) {
			return nil, errors.New("the connection is not running")
		}, dnsmessage.RCodeServerFailure},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestForwarder(t, Config{
				Rules:   carryingRules(),
				Tunnels: &fakeTunnels{answer: tc.answer},
				Logf:    func(string, ...any) {},
			})
			resp := f.Answer(context.Background(), buildQuery(t, "db.office.internal", dnsmessage.TypeA), false)
			if code, _ := rcode(resp); code != tc.want {
				t.Errorf("rcode = %s, want %s", code, tc.want)
			}
		})
	}
}

// Routing says this machine reaches the connection by address and nothing is wired up to ask
// it -- two halves of one feature disagreeing. It is a failure and not "no such name",
// because the name may well exist and answering NXDOMAIN would have the machine cache that.
func TestANameOnACarriedConnectionWithNothingToAskFailsLoudly(t *testing.T) {
	var logged int
	f := newTestForwarder(t, Config{
		Rules: carryingRules(),
		Logf:  func(string, ...any) { logged++ },
	})
	resp := f.Answer(context.Background(), buildQuery(t, "db.office.internal", dnsmessage.TypeA), false)
	if code, _ := rcode(resp); code != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", code)
	}
	if logged == 0 {
		t.Error("nothing was logged, so the disagreement is invisible")
	}
	if got := f.Stats().Failures; got != 1 {
		t.Errorf("failures = %d, want 1", got)
	}
}

func TestStatsCountWhereQueriesWent(t *testing.T) {
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{answering("profile", "203.0.113.1")}, nil),
		Local:   NewPool([]Upstream{answering("local", "192.0.2.1")}, nil),
	})
	ctx := context.Background()
	f.Answer(ctx, buildQuery(t, "example.com", dnsmessage.TypeA), false)
	f.Answer(ctx, buildQuery(t, "printer", dnsmessage.TypeA), false)
	f.Answer(ctx, buildQuery(t, "app.localhost", dnsmessage.TypeA), false)

	got := f.Stats()
	want := Stats{Queries: 3, ToProfile: 1, ToLocal: 1, AnsweredHere: 1}
	if got != want {
		t.Errorf("stats = %+v, want %+v", got, want)
	}
}

// The pool moves to a backup when the first resolver stops answering, stays there rather
// than stalling every query on the dead one, and goes back when it has had time to recover.
func TestThePoolFailsOverStickilyAndComesBack(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	var primaryFails atomic.Bool
	primaryFails.Store(true)
	primary := &fakeUpstream{label: "primary", answer: func(query []byte) ([]byte, error) {
		if primaryFails.Load() {
			return nil, errors.New("unreachable")
		}
		q, _ := parseQuestion(query)
		return buildResponse(q, dnsmessage.RCodeSuccess, false, nil, nil), nil
	}}
	backup := answering("backup", "203.0.113.2")
	pool := NewPool([]Upstream{primary, backup}, clock)

	ctx := context.Background()
	query := buildQuery(t, "example.com", dnsmessage.TypeA)
	if _, err := pool.Exchange(ctx, query, false); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if got := len(primary.questions()); got != 1 {
		t.Fatalf("the primary was asked %d times, want 1", got)
	}
	// Second query goes straight to the backup: retrying the dead primary first would
	// put its whole timeout in front of every name the user looks up.
	if _, err := pool.Exchange(ctx, query, false); err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if got := len(primary.questions()); got != 1 {
		t.Errorf("the primary was asked again while it was down (%d times)", got)
	}
	if got := len(backup.questions()); got != 2 {
		t.Errorf("the backup was asked %d times, want 2", got)
	}

	// Once it has had a minute, the resolver the user put first gets the query back.
	primaryFails.Store(false)
	now = now.Add(recheckPrimary)
	if _, err := pool.Exchange(ctx, query, false); err != nil {
		t.Fatalf("third exchange: %v", err)
	}
	if got := len(primary.questions()); got != 2 {
		t.Errorf("the primary was asked %d times, want it retried after a minute", got)
	}
}

func TestThePoolNamesEveryResolverThatFailed(t *testing.T) {
	pool := NewPool([]Upstream{failing("one"), failing("two")}, nil)
	_, err := pool.Exchange(context.Background(), buildQuery(t, "example.com", dnsmessage.TypeA), false)
	if err == nil {
		t.Fatal("Exchange = nil error")
	}
	for _, want := range []string{"one", "two", "connection refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err, want)
		}
	}
}

// The captive-portal seam: unreachable-then-reachable is the shape of walking into a hotel
// network, and each change is reported exactly once.
func TestTheProfileGoingUnreachableIsReportedOnceAndSoIsComingBack(t *testing.T) {
	var fails atomic.Bool
	fails.Store(true)
	up := &fakeUpstream{label: "profile", answer: func(query []byte) ([]byte, error) {
		if fails.Load() {
			return nil, errors.New("unreachable")
		}
		q, _ := parseQuestion(query)
		return buildResponse(q, dnsmessage.RCodeSuccess, false, nil, nil), nil
	}}
	var mu sync.Mutex
	var events []bool
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{up}, nil),
		Logf:    func(string, ...any) {},
		OnProfileHealth: func(healthy bool, _ error) {
			mu.Lock()
			events = append(events, healthy)
			mu.Unlock()
		},
	})

	ctx := context.Background()
	query := buildQuery(t, "example.com", dnsmessage.TypeA)
	for i := 0; i < 5; i++ {
		f.Answer(ctx, query, false)
	}
	fails.Store(false)
	for i := 0; i < 2; i++ {
		f.Answer(ctx, query, false)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0] || !events[1] {
		t.Errorf("health events = %v, want one unreachable then one recovered", events)
	}
}

// The whole path over a real loopback socket, which is how the machine will reach it.
func TestServePacketAnswersOnALoopbackSocket(t *testing.T) {
	port, err := testport.Reserve()
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{answering("profile", "203.0.113.7")}, nil),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- f.ServePacket(ctx, pc) }()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(buildQuery(t, "example.com", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, maxUDPAnswer)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	addrs := addressesIn(t, buf[:n])
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("answer = %v, want [203.0.113.7]", addrs)
	}

	cancel()
	if err := <-served; err != nil {
		t.Errorf("ServePacket = %v, want a clean stop on cancellation", err)
	}
}

func TestServeStreamAnswersSeveralQueriesOnOneConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := newTestForwarder(t, Config{
		Rules:   Rules{HaveLocal: true},
		Profile: NewPool([]Upstream{answering("profile", "203.0.113.8")}, nil),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- f.ServeStream(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		if err := writeFramed(conn, buildQuery(t, "example.com", dnsmessage.TypeA)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		resp, err := readFramed(conn)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if addrs := addressesIn(t, resp); len(addrs) != 1 {
			t.Fatalf("answer %d = %v", i, addrs)
		}
	}

	cancel()
	if err := <-served; err != nil {
		t.Errorf("ServeStream = %v, want a clean stop on cancellation", err)
	}
}

// Traffic inspection reads a run of questions rather than any one of them, so the seam has to
// see every query the forwarder answers -- including the ones it answers here. A seam wired
// only to what is forwarded would miss a tunnel run under a name this machine answers for.
func TestEveryNameAskedAboutReachesTheInspectionSeam(t *testing.T) {
	var asked []string
	profile := answering("profile", "203.0.113.5")
	f := newTestForwarder(t, Config{
		Profile:    NewPool([]Upstream{profile}, nil),
		OnQuestion: func(name string) { asked = append(asked, name) },
	})

	for _, name := range []string{"Example.COM", "localhost", "one.tunnel.example"} {
		f.Answer(context.Background(), buildQuery(t, name, dnsmessage.TypeA), false)
	}

	want := []string{"example.com", "localhost", "one.tunnel.example"}
	if !slices.Equal(asked, want) {
		t.Errorf("the seam saw %v, want every name asked about, lowercased: %v", asked, want)
	}
}

// Bytes that are not a query have no name in them, and calling the seam with an empty string
// would put one in the ledger for every malformed packet anything on this machine sends.
func TestBytesThatAreNotAQueryReachNoSeam(t *testing.T) {
	called := 0
	f := newTestForwarder(t, Config{
		Profile:    NewPool([]Upstream{answering("profile", "203.0.113.5")}, nil),
		OnQuestion: func(string) { called++ },
	})

	f.Answer(context.Background(), []byte{0x12, 0x34, 0x01, 0x00}, false)

	if called != 0 {
		t.Errorf("the seam was called %d times for bytes that carry no name", called)
	}
}
