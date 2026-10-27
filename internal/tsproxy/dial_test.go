// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
)

// The rules are the whole security boundary. A program pointed at this proxy has delegated
// the decision of where its traffic goes, so a destination no rule carries has to be
// refused -- dialing it anyway is the one outcome the program cannot detect for itself.
func TestTheRulesDecideWhatIsCarriedAndNothingFallsThrough(t *testing.T) {
	tests := []struct {
		name        string
		rules       []access.Rule
		destination string
		carried     bool
	}{
		{"the connection alone carries what it routes", reachTheConnection(), "peer:22", true},
		{"the connection alone refuses this machine", reachTheConnection(), "example.com:443", false},
		{"both grants carry what the connection routes", reachThisMachineToo(), "peer:22", true},
		{"both grants carry this machine too", reachThisMachineToo(), "example.com:443", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tn := newFakeNetwork(t)
			tn.route(t, "peer:22")
			tn.expose(t, "example.com:443")
			rules := tt.rules
			p, _ := startProxy(t, tn, func(held *config.ProxyInstance) { held.Rules = rules })

			conn, err := p.dial(context.Background(), "tcp", tt.destination)
			if tt.carried {
				if err != nil {
					t.Fatalf("dial %s: %v", tt.destination, err)
				}
				conn.Close()
				return
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("dial %s = %v, want it refused as a destination no rule allows",
					tt.destination, err)
			}
			if len(tn.dialledAddresses()) != 0 {
				t.Error("a refused destination was dialed anyway")
			}
		})
	}
}

// An instance whose rules cover nothing reaches nothing. Reading an empty list as "carry
// everything" would make the least configured instance the most powerful one, which is the
// opposite of what someone adding a proxy expects.
func TestAnInstanceWithNoRulesReachesNothing(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	tn.expose(t, "example.com:443")
	p, _ := startProxy(t, tn, func(held *config.ProxyInstance) { held.Rules = nil })

	for _, destination := range []string{"peer:22", "example.com:443"} {
		if _, err := p.dial(context.Background(), "tcp", destination); !errors.Is(err, ErrRefused) {
			t.Errorf("dial %s = %v, want an instance with no rules to reach nothing",
				destination, err)
		}
	}
	if len(tn.dialledAddresses()) != 0 {
		t.Error("an instance with no rules dialed something anyway")
	}
}

// The route resolved a name to an address; dialing the name again re-runs DNS, which
// resolves in the permissive direction. The rules would then have passed on one address
// while the connection was made to another.
func TestTheAddressDialedIsTheOneTheRulesWereCheckedAgainst(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer.tail1a2b3c.ts.net:22")
	p, _ := startProxy(t, tn)

	conn, err := p.dial(context.Background(), "tcp", "peer.tail1a2b3c.ts.net:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dialled := tn.dialledAddresses()
	if len(dialled) != 1 {
		t.Fatalf("the backend was dialed %d times, want 1: %v", len(dialled), dialled)
	}
	if _, err := netip.ParseAddrPort(dialled[0]); err != nil {
		t.Errorf("the proxy dialed %q, want the ip:port the classifier resolved: %v", dialled[0], err)
	}
}

// A refusal must say which kind it was. "Nothing could say where that is" clears itself
// when the connection comes up and "no rule allows that" does not, and a user who cannot
// tell them apart cannot act on either.
func TestARefusalNamesWhichKindItIs(t *testing.T) {
	t.Run("no connection could say where it is", func(t *testing.T) {
		tn := newFakeNetwork(t)
		tn.route(t, "peer:22")
		p, _ := startProxy(t, tn)
		tn.mu.Lock()
		tn.reachErr = errors.New("the connection is not running")
		tn.mu.Unlock()

		_, err := p.dial(context.Background(), "tcp", "peer:22")
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("dial error = %v, want ErrUnreachable", err)
		}
	})

	t.Run("no rule allows the destination", func(t *testing.T) {
		tn := newFakeNetwork(t)
		tn.expose(t, "example.com:443")
		p, _ := startProxy(t, tn)

		_, err := p.dial(context.Background(), "tcp", "example.com:443")
		if !errors.Is(err, ErrRefused) {
			t.Errorf("dial error = %v, want ErrRefused", err)
		}
		if len(tn.dialledAddresses()) != 0 {
			t.Error("a refused destination was dialed anyway")
		}
	})

	t.Run("the name does not resolve", func(t *testing.T) {
		tn := newFakeNetwork(t)
		p, _ := startProxy(t, tn)

		_, err := p.dial(context.Background(), "tcp", "nope.invalid:22")
		if err == nil {
			t.Fatal("dial reported no error for a name that does not resolve")
		}
		if errors.Is(err, ErrRefused) {
			t.Errorf("dial error = %v, want the resolver's own failure rather than a rule verdict", err)
		}
		if !strings.Contains(err.Error(), "nope.invalid") {
			t.Errorf("dial error = %v, want it to name the destination", err)
		}
	})
}

// A connection that cannot classify a destination must not be treated as one that said
// "this machine carries it": the proxy would refuse everything with the wrong reason, or --
// with a grant for this machine in the list -- carry a destination nothing vouched for.
func TestADestinationIsRefusedWhenNoConnectionCanClassifyIt(t *testing.T) {
	unclassifiable := errors.New("the connection has no route table yet")
	for _, tc := range []struct {
		name  string
		rules []access.Rule
	}{
		{"the connection alone", reachTheConnection()},
		{"this machine granted too", reachThisMachineToo()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tn := newFakeNetwork(t)
			rules := tc.rules
			p, _ := startProxy(t, tn, func(held *config.ProxyInstance) { held.Rules = rules })
			tn.mu.Lock()
			tn.reachErr = unclassifiable
			tn.mu.Unlock()

			if _, err := p.dial(context.Background(), "tcp", "peer:22"); !errors.Is(err, unclassifiable) {
				t.Errorf("dial error = %v, want the connection's own refusal", err)
			}
			if len(tn.dialledAddresses()) != 0 {
				t.Error("an unclassifiable destination was dialed anyway")
			}
		})
	}
}

// The counters are what the dashboard reports, and a refusal that never showed up there
// would leave a user watching a proxy that looks idle while nothing works.
func TestRefusalsAndTrafficAreBothCounted(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	tn.expose(t, "example.com:443")
	p, _ := startProxy(t, tn)

	if _, err := p.dial(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("a destination no rule allows was carried")
	}
	if got := p.Status().Counters.Refused; got != 1 {
		t.Errorf("refused = %d, want 1", got)
	}

	conn, err := p.dial(context.Background(), "tcp", "peer:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := p.Status().Counters.Active; got != 1 {
		t.Errorf("active = %d, want 1 while a connection is open", got)
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read back through the proxy: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("read %q, want the bytes back from the stand-in peer", buf)
	}

	counters := p.Status().Counters
	if counters.BytesUp != 5 || counters.BytesDown != 5 {
		t.Errorf("bytes up/down = %d/%d, want 5/5", counters.BytesUp, counters.BytesDown)
	}

	conn.Close()
	if got := p.Status().Counters.Active; got != 0 {
		t.Errorf("active = %d after close, want 0", got)
	}
}

// Both ends close a proxied connection -- the SOCKS5 server closes its own, and so does
// whatever wraps it. A count that fell twice would go negative and report an idle proxy
// as busy in reverse.
func TestClosingAConnectionTwiceOnlyDecrementsTheActiveCountOnce(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	p, _ := startProxy(t, tn)

	conn, err := p.dial(context.Background(), "tcp", "peer:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	conn.Close()

	if got := p.Status().Counters.Active; got != 0 {
		t.Errorf("active = %d after two closes, want 0", got)
	}
}

// netpipe.Copy propagates a half close so a protocol that ends its request by shutting
// down one direction still gets its response. The counting wrapper hides the underlying
// conn's own method, so without forwarding it every tunnel would fall back to a full
// close and the response would never arrive.
func TestTheCountingWrapperStillPropagatesAHalfClose(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:80")
	p, _ := startProxy(t, tn)

	conn, err := p.dial(context.Background(), "tcp", "peer:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("a proxied connection cannot half close, so a request-then-response protocol would hang")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The echo peer copies until its read side ends, so the reply arriving after the
	// half close is the proof it was propagated rather than swallowed.
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read after half close: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("read %q, want %q", buf, "ping")
	}
}

// A destination the node classified as reachable and then would not dial is the peer
// being down, not the request being wrong. It counts as a failure rather than a refusal:
// the two answer different questions -- whether the proxy is turning traffic away, and
// whether the tailnet is carrying it -- and one counter for both answers neither.
func TestAPeerThatCannotBeDialedCountsAsAFailureRatherThanARefusal(t *testing.T) {
	tun := &scriptedTunnel{
		stubTunnel: stubTunnel{id: officeTunnel},
		dialErr:    errors.New("no route to host"),
	}
	p, _ := startProxy(t, scriptedNetwork(t, tun))

	_, err := p.dial(context.Background(), "tcp", "peer:443")
	if err == nil {
		t.Fatal("a connection was reported open to a peer that could not be dialed")
	}
	if !strings.Contains(err.Error(), "no route to host") {
		t.Errorf("error is %q, want the connection's own reason carried through", err)
	}
	if !strings.Contains(err.Error(), "peer:443") {
		t.Errorf("error is %q, want it to name the destination that failed", err)
	}

	counters := p.Status().Counters
	if counters.Failed != 1 {
		t.Errorf("failed = %d, want the dial counted as a failure", counters.Failed)
	}
	if counters.Refused != 0 {
		t.Errorf("refused = %d, want a peer being down not counted as the proxy turning it away", counters.Refused)
	}
}

// Switching the module off ends live connections now rather than whenever each happens
// to finish. One that will not close is the interesting case: it must not stop the ones
// behind it in the list from being closed.
func TestOneConnectionRefusingToCloseDoesNotStrandTheRest(t *testing.T) {
	stubborn := &scriptedConn{closeErr: errors.New("the endpoint is wedged")}
	willing := &scriptedConn{}
	tun := &scriptedTunnel{
		stubTunnel: stubTunnel{id: officeTunnel},
		queue:      []*scriptedConn{stubborn, willing},
	}
	p, _ := startProxy(t, scriptedNetwork(t, tun))

	for _, address := range []string{"peer:443", "other:443"} {
		conn, err := p.dial(context.Background(), "tcp", address)
		if err != nil {
			t.Fatalf("dial %s: %v", address, err)
		}
		t.Cleanup(func() { conn.Close() })
	}

	p.Close()

	if !stubborn.closed() {
		t.Error("the connection that refuses to close was never asked to")
	}
	if !willing.closed() {
		t.Error("a connection behind the failing one was left open")
	}
}

// netpipe.Copy signals end-of-request by shutting down one direction, and reaches for
// CloseWrite to do it. A connection with no half close still has to end, or a protocol
// that waits for the shutdown waits forever.
func TestAConnectionWithNoHalfCloseIsEndedRatherThanLeftOpen(t *testing.T) {
	peer := &scriptedConn{}
	tun := &scriptedTunnel{stubTunnel: stubTunnel{id: officeTunnel}, conn: peer}
	p, _ := startProxy(t, scriptedNetwork(t, tun))

	conn, err := p.dial(context.Background(), "tcp", "peer:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("a proxied connection cannot half close at all")
	}

	if err := half.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !peer.closed() {
		t.Error("the connection was neither half closed nor closed, so the peer waits forever")
	}
}

// The proxy's totals say how much crossed; only the destination table says where it went,
// which is the whole question someone opens the traffic view to answer. This exercises the
// real dial path rather than the table on its own, because the attribution happens in
// track() and in the byte hooks -- a table that works in isolation and is never handed a
// destination would pass every test in destinations_test.go and report nothing here.
func TestTrafficIsAttributedThroughARealDial(t *testing.T) {
	tn := newFakeNetwork(t)
	tn.route(t, "peer:22")
	tn.expose(t, "blocked.example:443")
	p, _ := startProxy(t, tn)

	// One refused destination, named.
	if _, err := p.dial(context.Background(), "tcp", "blocked.example:443"); err == nil {
		t.Fatal("a destination no rule allows was carried")
	}

	// One carried destination, with bytes in both directions.
	conn, err := p.dial(context.Background(), "tcp", "peer:22")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	if _, err := conn.Read(make([]byte, 5)); err != nil {
		t.Fatalf("read back through the proxy: %v", err)
	}

	rows := p.Status().Counters.Destinations
	carried := find(t, rows, "peer:22")
	if carried.BytesUp != 5 || carried.BytesDown != 5 {
		t.Errorf("peer:22 up/down = %d/%d, want 5/5", carried.BytesUp, carried.BytesDown)
	}
	if carried.Active != 1 {
		t.Errorf("peer:22 active = %d, want 1 while the connection is open", carried.Active)
	}

	refused := find(t, rows, "blocked.example:443")
	if refused.Refused != 1 {
		t.Errorf("blocked.example:443 refused = %d, want 1", refused.Refused)
	}
	if refused.Opened != 0 {
		t.Errorf("a refused destination reports %d opened, want 0", refused.Opened)
	}

	// Closing has to release the destination's gauge as well as the proxy's, or the
	// table claims a live connection for as long as the process runs.
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := find(t, p.Status().Counters.Destinations, "peer:22"); got.Active != 0 {
		t.Errorf("peer:22 active = %d after close, want 0", got.Active)
	}
}
