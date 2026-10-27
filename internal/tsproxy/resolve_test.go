// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// testClock is a clock a test moves by hand, so a cached answer is aged rather than
// waited out.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// privateResolving builds an instance that asks the connections' own resolvers, on a clock
// the test drives. The box comes back too, for the tests that change the mode mid-flight.
func privateResolving(t *testing.T, tn *fakeNetwork, clock *testClock) (*Instance, *proxyBox) {
	t.Helper()
	box := newProxyBoxWith(
		Options{Network: tn, Now: clock.Now, DialDirect: tn.dialDirect},
		func(held *config.ProxyInstance) {
			held.ResolveVia = config.ResolveViaTailnet
			// This machine's network is reachable too: half of these tests are about a
			// private resolver answering with an address no connection carries, and the
			// refusal they are looking for has to be the rules', not a missing grant.
			held.Rules = reachThisMachineToo()
		},
	)
	t.Cleanup(box.set.Close)
	box.mustApply(t)
	inst := box.instance()
	if inst == nil {
		t.Fatal("the instance is not running after a successful apply")
	}
	return inst, box
}

// standIn registers a loopback server keyed by its own address -- which is what the proxy
// asks about once a name has been resolved to it, rather than the name itself. carried
// says whether a connection carries it or it sits on this machine's own network.
func standIn(t *testing.T, f *fakeNetwork, carried bool) netip.AddrPort {
	t.Helper()
	addr := echoServer(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	if carried {
		f.carries[addr.String()] = addr
	} else {
		f.public[addr.String()] = addr
	}
	return addr
}

func port(addr netip.AddrPort) string { return strconv.Itoa(int(addr.Port())) }

// The feature in one test: a domain the admin console points at a private nameserver
// resolves only through the tailnet's own resolver. This machine's resolver -- which is
// what the netmap path falls through to -- answers such a name with a public address or
// with nothing, and either way the connection does not reach what the user meant.
func TestASplitDNSNameIsReachedThroughTheTailnetsOwnResolver(t *testing.T) {
	tn := newFakeNetwork(t)
	// Registered by address alone: the name is in no netmap, which is what makes the
	// tailnet's resolver the only way it can be reached.
	private := standIn(t, tn, true)
	tn.resolveAs("db.corp.example.com", private.Addr())

	p, _ := privateResolving(t, tn, newTestClock())

	conn, err := p.dial(context.Background(), "tcp", "db.corp.example.com:"+port(private))
	if err != nil {
		t.Fatalf("a name only the tailnet's resolver knows was not reached: %v", err)
	}
	conn.Close()

	if got := tn.dialledAddresses(); len(got) != 1 || got[0] != private.String() {
		t.Errorf("dialed %v, want the address the tailnet's resolver gave (%s)", got, private)
	}
}

// A name that already says which connection it is on is not a question for the resolvers.
// Asking them would put a name naming one network to every network, and the first to
// answer would win -- which is the ambiguity the suffix exists to remove, reintroduced one
// layer down.
func TestANameThatSaysItsConnectionIsNotPutToEveryResolver(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "db:5432")
	tn.Registry.SetNaming(tunnel.NewNaming(map[string]string{officeTunnel: "office.internal"}))
	p, _ := privateResolving(t, tn, newTestClock())

	conn, err := p.dial(context.Background(), "tcp", "db.office.internal:5432")
	if err != nil {
		t.Fatalf("a host named through its connection's suffix was not reached: %v", err)
	}
	conn.Close()

	if got := tn.lookupCount(); got != 0 {
		t.Errorf("the connections' own resolvers were asked %d times about a name that named one of them", got)
	}
}

// The other mode has to stay exactly what it was: one round trip fewer per connection is
// the whole reason it is the default, and asking anyway would spend it.
func TestTheNetmapModeNeverAsksTheTailnetsResolver(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer.tail1a2b3c.ts.net:22")
	tn.resolveAs("peer.tail1a2b3c.ts.net", netip.MustParseAddr("100.64.0.9"))
	p, _ := startProxy(t, tn)

	conn, err := p.dial(context.Background(), "tcp", "peer.tail1a2b3c.ts.net:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if got := tn.lookupCount(); got != 0 {
		t.Errorf("the tailnet's resolver was asked %d times while the netmap mode was in force", got)
	}
}

// Turning the mode on must not take every ordinary destination away with it. A name the
// tailnet does not serve is reached exactly as before.
func TestANameTheTailnetDoesNotServeStillReachesItsDestination(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer.tail1a2b3c.ts.net:22")
	p, _ := privateResolving(t, tn, newTestClock())

	conn, err := p.dial(context.Background(), "tcp", "peer.tail1a2b3c.ts.net:22")
	if err != nil {
		t.Fatalf("a name the tailnet's resolver does not serve was not reached: %v", err)
	}
	conn.Close()

	if got := tn.lookupCount(); got != 1 {
		t.Errorf("the resolver was asked %d times, want once before falling back", got)
	}
}

// A resolver that cannot answer is not the same as a name it does not serve. Falling
// back would resolve a private name against this machine's resolver -- a public address,
// or the wrong host entirely -- for as long as the backend is unwell, which is exactly
// when nobody is watching for it.
func TestAResolverThatCannotAnswerRefusesTheConnection(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "db.corp.example.com:5432")
	tn.dnsErr = errors.New("the local backend is not answering")
	p, _ := privateResolving(t, tn, newTestClock())

	_, err := p.dial(context.Background(), "tcp", "db.corp.example.com:5432")
	if err == nil {
		t.Fatal("a failing resolver was answered by resolving somewhere else")
	}
	if !strings.Contains(err.Error(), "db.corp.example.com") {
		t.Errorf("err = %v, want it to name what could not be resolved", err)
	}
	if got := tn.dialledAddresses(); len(got) != 0 {
		t.Errorf("dialed %v after the resolver failed, want nothing", got)
	}
}

// An address is not a name. Asking the resolver about one costs a round trip per
// connection and can only answer with what was already there.
func TestAnAddressIsNotAskedAbout(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "100.64.0.9:22")
	p, _ := privateResolving(t, tn, newTestClock())

	conn, err := p.dial(context.Background(), "tcp", "100.64.0.9:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if got := tn.lookupCount(); got != 0 {
		t.Errorf("the resolver was asked %d times about a literal address", got)
	}
}

// A busy destination is one name and many connections. Asking per connection would put a
// round trip through the local backend in front of every one of them.
func TestAnAnswerIsReusedUntilItExpires(t *testing.T) {
	tn := newFakeNetwork(t)
	private := standIn(t, tn, true)
	tn.resolveAs("db.corp.example.com", private.Addr())

	clock := newTestClock()
	p, _ := privateResolving(t, tn, clock)
	address := "db.corp.example.com:" + port(private)

	for range 3 {
		conn, err := p.dial(context.Background(), "tcp", address)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.Close()
	}
	if got := tn.lookupCount(); got != 1 {
		t.Errorf("the resolver was asked %d times for three connections to one name, want once", got)
	}

	// Past the record's own lifetime the name is asked about again, which is what makes
	// a service that moved reachable at its new address.
	clock.advance(2 * time.Minute)
	conn, err := p.dial(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial after the answer expired: %v", err)
	}
	conn.Close()
	if got := tn.lookupCount(); got != 2 {
		t.Errorf("the resolver was asked %d times, want a second question once the answer expired", got)
	}
}

// The remembered answers came from the resolver that is no longer in use, and the whole
// reason to change resolvers is that the two answer differently. Keeping them would send
// connections to the old resolver's address for as long as they had left to live.
func TestChangingTheResolverForgetsWhatTheOldOneSaid(t *testing.T) {
	tn := newFakeNetwork(t)
	private := standIn(t, tn, true)
	tn.resolveAs("db.corp.example.com", private.Addr())

	p, box := privateResolving(t, tn, newTestClock())
	address := "db.corp.example.com:" + port(private)

	conn, err := p.dial(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	for _, via := range []config.ProxyResolveVia{config.ResolveViaNetmap, config.ResolveViaTailnet} {
		box.edit(func(held *config.ProxyInstance) { held.ResolveVia = via })
		if err := box.apply(); err != nil {
			t.Fatalf("Apply with the resolver set to %q: %v", via, err)
		}
	}

	conn, err = p.dial(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial after the resolver changed: %v", err)
	}
	conn.Close()

	if got := tn.lookupCount(); got != 2 {
		t.Errorf("the resolver was asked %d times, want the earlier answer forgotten and asked again", got)
	}
}

// The rules are enforced against the address that will be dialed, whichever resolver
// produced it. A private resolver answering with an address no connection carries is
// exactly the case that would otherwise walk around them.
func TestAResolvedAddressIsStillHeldToTheRules(t *testing.T) {
	tn := newFakeNetwork(t)
	public := standIn(t, tn, false)
	tn.resolveAs("db.corp.example.com", public.Addr())

	clock := newTestClock()
	box := newProxyBoxWith(
		Options{Network: tn, Now: clock.Now, DialDirect: tn.dialDirect},
		func(held *config.ProxyInstance) {
			held.ResolveVia = config.ResolveViaTailnet
			// Only the connection is granted, so an address that resolves onto this
			// machine's own network has no rule carrying it.
			held.Rules = reachTheConnection()
		},
	)
	t.Cleanup(box.set.Close)
	box.mustApply(t)
	p := box.instance()

	_, err := p.dial(context.Background(), "tcp", "db.corp.example.com:"+port(public))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want the destination refused as one no rule allows", err)
	}
	if got := tn.dialledAddresses(); len(got) != 0 {
		t.Errorf("dialed %v, want nothing no rule allows", got)
	}
}

// A destination that cannot be taken apart is reported by the classifier, in the terms
// every other refusal already uses, rather than as a resolver failure.
func TestADestinationWithNoPortIsReportedByTheClassifier(t *testing.T) {
	tn := newFakeNetwork(t)
	p, _ := privateResolving(t, tn, newTestClock())

	_, err := p.dial(context.Background(), "tcp", "db.corp.example.com")
	if err == nil {
		t.Fatal("a destination with no port was accepted")
	}
	if got := tn.lookupCount(); got != 0 {
		t.Errorf("the resolver was asked %d times about a destination with no port", got)
	}
}

// The floor keeps a busy name from costing a query per connection; the ceiling bounds how
// long a record the tailnet republished takes to be noticed, since nothing tells this
// cache that the tailnet's DNS changed.
func TestHowLongAnAnswerIsKept(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{name: "a record with no lifetime at all", ttl: 0, want: minResolveTTL},
		{name: "shorter than the floor", ttl: 5 * time.Second, want: minResolveTTL},
		{name: "its own lifetime", ttl: 90 * time.Second, want: 90 * time.Second},
		{name: "longer than the ceiling", ttl: time.Hour, want: maxResolveTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheFor(tc.ttl); got != tc.want {
				t.Errorf("a %v record is kept for %v, want %v", tc.ttl, got, tc.want)
			}
		})
	}
}
