// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// socketDir is a short directory to put a management socket in.
//
// It is not t.TempDir: a unix socket address is capped at around a hundred characters by the
// operating system, and on macOS the per-test directory name alone spends most of that.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ovpn") //nolint:usetesting // t.TempDir's names are too long; see above.
	if err != nil {
		t.Fatalf("make a directory for the management socket: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove the directory for the management socket: %v", err)
		}
	})
	return dir
}

func heldFixture() config.OpenVPNTunnel {
	return config.OpenVPNTunnel{
		Remote:       "vpn.example.com:1194",
		Proto:        config.OpenVPNProtoUDP,
		CA:           "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
		AuthUserPass: true,
		Username:     "alice",
		Password:     "s3cret",
		Routes:       []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
	}
}

// fakeOpenVPN stands in for the program the privileged side would run. It listens on the
// management socket the way openvpn does, waits for this connection to dial in, and speaks the
// management protocol down what it accepted -- which is the whole of the conversation this
// package exists to hold, and it needs no privileges, no server and no network to do it.
type fakeOpenVPN struct {
	// speak is what the program says once dialled, nil for one that holds the conversation
	// open and says nothing.
	speak func(t *testing.T, conn net.Conn)
	fail  error
	// mute is a program that starts and never opens its management socket at all.
	mute bool

	// scopeFail is what the privileged side answers when asked to give a connection's
	// interface a default route of its own, nil for the route being installed.
	scopeFail error

	// dir is where this fake's management sockets go. newTunnelWith fills it in; a case that
	// builds its Options by hand sets it itself.
	dir string

	mu       sync.Mutex
	started  []hostnet.OpenVPNRun
	stopped  []string
	scoped   []hostnet.OpenVPNScope
	unscoped []string
	done     chan struct{}
	// ln and conn are the socket the program now running listens on and the conversation it
	// accepted. Stopping the program closes both, because that is what openvpn exiting does --
	// and a fake that kept them would leave the replacement nowhere to listen.
	ln   net.Listener
	conn net.Conn
}

// ManagementSocket is where this fake listens, which is how the connection under test knows
// where to dial: the same question the in-process privileged side answers.
func (f *fakeOpenVPN) ManagementSocket(id string) string {
	return filepath.Join(f.dir, id+".sock")
}

func (f *fakeOpenVPN) StartOpenVPN(_ context.Context, run hostnet.OpenVPNRun) error {
	if f.fail != nil {
		return f.fail
	}
	f.mu.Lock()
	f.started = append(f.started, run)
	f.done = make(chan struct{})
	done := f.done
	speak := f.speak
	f.mu.Unlock()

	if f.mute {
		close(done)
		return nil
	}
	if f.dir == "" {
		close(done)
		return errors.New("this fake openvpn was given no directory to put its management socket in")
	}
	ln, err := net.Listen("unix", f.ManagementSocket(run.ID))
	if err != nil {
		close(done)
		return err
	}
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// A stop that landed between the accept and here found no conversation to close, so
		// this one is closed now rather than held open by a program that has been stopped.
		f.mu.Lock()
		if f.ln != ln {
			f.mu.Unlock()
			return
		}
		f.conn = conn
		f.mu.Unlock()
		if speak == nil {
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		speak(nil, conn)
	}()
	return nil
}

func (f *fakeOpenVPN) StopOpenVPN(_ context.Context, id string) error {
	f.mu.Lock()
	f.stopped = append(f.stopped, id)
	ln, conn, done := f.ln, f.conn, f.done
	f.ln, f.conn = nil, nil
	f.mu.Unlock()
	var errs []error
	if conn != nil {
		errs = append(errs, conn.Close())
	}
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	// Returned only once the program has gone, as the privileged side's stop does.
	if done != nil {
		<-done
	}
	return errors.Join(errs...)
}

// finished is closed once the program last started has ended its conversation.
func (f *fakeOpenVPN) finished() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.done
}

func (f *fakeOpenVPN) ScopeOpenVPN(_ context.Context, scope hostnet.OpenVPNScope) error {
	f.mu.Lock()
	f.scoped = append(f.scoped, scope)
	f.mu.Unlock()
	return f.scopeFail
}

func (f *fakeOpenVPN) UnscopeOpenVPN(_ context.Context, id string) error {
	f.mu.Lock()
	f.unscoped = append(f.unscoped, id)
	f.mu.Unlock()
	return nil
}

func (f *fakeOpenVPN) unscopes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.unscoped...)
}

func (f *fakeOpenVPN) scopes() []hostnet.OpenVPNScope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostnet.OpenVPNScope(nil), f.scoped...)
}

func (f *fakeOpenVPN) runs() []hostnet.OpenVPNRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostnet.OpenVPNRun(nil), f.started...)
}

func (f *fakeOpenVPN) stops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.stopped...)
}

func newTunnel(t *testing.T, held config.OpenVPNTunnel, carry Carry, runner Runner) *Tunnel {
	t.Helper()
	return newTunnelWith(t, held, carry, runner, nil)
}

// newTunnelWith is newTunnel for a case that needs one more of the options set.
func newTunnelWith(t *testing.T, held config.OpenVPNTunnel, carry Carry, runner Runner,
	tune func(*Options)) *Tunnel {
	t.Helper()
	opts := Options{
		ID:     "tn_test01",
		Held:   held,
		Carry:  carry,
		Logger: slog.New(slog.DiscardHandler),
		Runner: runner,
	}
	if fake, ok := runner.(*fakeOpenVPN); ok && fake.dir == "" {
		fake.dir = socketDir(t)
	}
	if tune != nil {
		tune(&opts)
	}
	live := New(opts)
	switch live := live.(type) {
	case *Tunnel:
		return live
	case *resolvingTunnel:
		return live.Tunnel
	default:
		t.Fatalf("New returned a %T", live)
		return nil
	}
}

// waitForState blocks until the connection reports the state, or says what it reported
// instead. It reads the events channel rather than polling, because that channel is what
// every consumer of a connection is woken by and a test that polls would pass with it broken.
// stateDeadline is how long a case waits for a connection to reach the state it asked for.
//
// It has to be longer than attemptWindow. A search normally moves on the moment openvpn names
// the failure, but a machine under load can have the timer fire first, and the connection then
// reaches the same state one window later -- working, not stuck. A deadline of one window is
// racing the fallback the production code exists to have.
const stateDeadline = 3 * attemptWindow

func waitForState(t *testing.T, live *Tunnel, want tunnel.State) tunnel.Status {
	t.Helper()
	deadline := time.After(stateDeadline)
	for {
		if got := live.Status(); got.State == want {
			return got
		}
		select {
		case <-live.Events():
		case <-deadline:
			t.Fatalf("the connection reported %q, want %q", live.Status().State, want)
		}
	}
}

// A connection whose network publishes resolvers can look names up inside it; one that does
// not has no way to, and says so by not having the method at all rather than by answering
// every lookup with an error the caller has to classify.
func TestOnlyAConnectionWithItsOwnResolversCanLookUpNames(t *testing.T) {
	held := heldFixture()
	if _, ok := New(Options{Held: held, Logger: slog.New(slog.DiscardHandler)}).(tunnel.Resolving); ok {
		t.Error("a connection with no resolvers reported that it can look up names")
	}
	held.DNS = []netip.Addr{netip.MustParseAddr("10.8.0.1")}
	if _, ok := New(Options{Held: held, Logger: slog.New(slog.DiscardHandler)}).(tunnel.Resolving); !ok {
		t.Error("a connection with its own resolvers reported that it cannot look up names")
	}
}

// Every state openvpn can report maps onto one this app reports, including the ones that only
// happen against a server that is refusing -- which is exactly where a connection reported
// wrongly costs somebody an afternoon.
func TestEveryStateOpenVPNReportsBecomesOneThisAppReports(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    report
		stopping bool
		want     tunnel.State
		detail   string
	}{
		{name: "carrying traffic", state: report{Name: "CONNECTED"}, want: tunnel.StateConnected},
		{name: "looking the server up", state: report{Name: "RESOLVE"}, want: tunnel.StateConnecting},
		{name: "opening the transport", state: report{Name: "TCP_CONNECT"}, want: tunnel.StateConnecting},
		{name: "reaching the server", state: report{Name: "CONNECTING"}, want: tunnel.StateConnecting},
		{name: "waiting on the server", state: report{Name: "WAIT"}, want: tunnel.StateConnecting},
		{name: "signing in", state: report{Name: "AUTH"}, want: tunnel.StateConnecting},
		{name: "taking the configuration", state: report{Name: "GET_CONFIG"}, want: tunnel.StateConnecting},
		{name: "taking an address", state: report{Name: "ASSIGN_IP"}, want: tunnel.StateConnecting},
		{name: "installing routes", state: report{Name: "ADD_ROUTES"}, want: tunnel.StateConnecting},
		{
			name:   "waiting on a person to approve the login",
			state:  report{Name: "AUTH_PENDING"},
			want:   tunnel.StateNeedsLogin,
			detail: "the server is waiting for this login to be approved somewhere else",
		},
		{
			name:   "dropped and retrying",
			state:  report{Name: "RECONNECTING", Detail: "tls-error"},
			want:   tunnel.StateConnecting,
			detail: "the connection dropped and is being retried: tls-error",
		},
		{
			name:   "ended on its own",
			state:  report{Name: "EXITING", Detail: "auth-failure"},
			want:   tunnel.StateFailed,
			detail: "the connection ended: auth-failure",
		},
		{
			name:     "ended because it was asked to",
			state:    report{Name: "EXITING", Detail: "auth-failure"},
			stopping: true,
			want:     tunnel.StateStopping,
		},
		{
			name:  "a state name a later openvpn invented",
			state: report{Name: "SOMETHING_NEW"},
			want:  tunnel.StateConnecting,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := stateOf(tc.state, tc.stopping)
			if got != tc.want {
				t.Errorf("stateOf(%+v) = %q, want %q", tc.state, got, tc.want)
			}
			if detail != tc.detail {
				t.Errorf("stateOf(%+v) said %q, want %q", tc.state, detail, tc.detail)
			}
		})
	}
}

// openvpn's own EXITING notification carries no reason for the failures that matter most, so
// the last thing it said on its log is folded into the state it went on to report. A
// connection that was told exactly why it failed must not report only that it ended.
func TestTheReasonOpenVPNGaveSurvivesIntoTheStateItProduced(t *testing.T) {
	const reason = "AUTH: Received control message: AUTH_FAILED"
	for _, tc := range []struct {
		name   string
		state  tunnel.State
		detail string
		notice string
		want   string
	}{
		{"a failure openvpn gave no reason for", tunnel.StateFailed, "", reason, reason},
		{
			name:   "a failure with a reason of its own",
			state:  tunnel.StateFailed,
			detail: "the connection ended",
			notice: reason,
			want:   "the connection ended: " + reason,
		},
		{
			name:   "a reason already in the detail",
			state:  tunnel.StateFailed,
			detail: "the connection ended: " + reason,
			notice: reason,
			want:   "the connection ended: " + reason,
		},
		{"a connection that came up", tunnel.StateConnected, "", reason, ""},
		{"a deliberate shutdown", tunnel.StateStopping, "", reason, ""},
		{"nothing was ever said", tunnel.StateFailed, "the connection ended", "", "the connection ended"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := detailWith(tc.state, tc.detail, tc.notice); got != tc.want {
				t.Errorf("detailWith(%q, %q, %q) = %q, want %q", tc.state, tc.detail, tc.notice, got, tc.want)
			}
		})
	}
}

// Both costs of running on a real interface are stated when the connection is built, because
// they are the two things somebody has to know before they connect rather than after
// something stops working.
func TestWhatRunningOnARealInterfaceCostsIsStatedUpFront(t *testing.T) {
	live := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	limits := strings.Join(live.Status().Limits, "\n")
	for _, want := range []string{"administrator rights", "one winner"} {
		if !strings.Contains(limits, want) {
			t.Errorf("the connection does not say %q:\n%s", want, limits)
		}
	}
	if strings.Contains(limits, "IPv6") {
		t.Errorf("a connection that carries nothing to the internet reported an IPv6 gap:\n%s", limits)
	}
}

// A connection chosen to carry this machine's internet traffic with no IPv6 default route
// carries IPv4 only, and the rest still leaves the way it always did. That is a leak somebody
// has to be told about rather than discover.
func TestCarryingOnlyIPv4ToTheInternetIsReportedRatherThanHidden(t *testing.T) {
	held := heldFixture()
	held.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	live := newTunnel(t, held, CarryDefault, &fakeOpenVPN{})
	if limits := strings.Join(live.Status().Limits, "\n"); !strings.Contains(limits, "IPv6") {
		t.Errorf("a connection carrying only IPv4 to the internet did not say so:\n%s", limits)
	}

	held.Routes = append(held.Routes, netip.MustParsePrefix("::/0"))
	live = newTunnel(t, held, CarryDefault, &fakeOpenVPN{})
	if limits := strings.Join(live.Status().Limits, "\n"); strings.Contains(limits, "IPv6") {
		t.Errorf("a connection carrying both families reported an IPv6 gap:\n%s", limits)
	}
}

// The options the server offered and this connection did not apply are reported on the
// connection, because a route the server expected to install is the likeliest reason a
// destination that ought to work does not.
func TestWhatTheServerOfferedAndThisConnectionDroppedIsReported(t *testing.T) {
	held := heldFixture()
	held.DNS = []netip.Addr{netip.MustParseAddr("10.9.0.1")}
	live := newTunnel(t, held, CarryNone, &fakeOpenVPN{})
	live.notePushed([]string{"route 192.168.9.0 255.255.255.0", "dhcp-option DNS 10.8.0.1"})
	limits := strings.Join(live.Status().Limits, "\n")
	if !strings.Contains(limits, "route 192.168.9.0 255.255.255.0") ||
		!strings.Contains(limits, "dhcp-option DNS 10.8.0.1") {
		t.Errorf("the offered settings were not reported:\n%s", limits)
	}
}

// Carrying this machine's internet traffic is refused for two different reasons and they are
// not interchangeable: one is a connection to wait for, the other is a connection openvpn was
// never started to route this machine's traffic through.
func TestCarryingTheInternetIsRefusedForTheReasonThatApplies(t *testing.T) {
	held := heldFixture()
	held.Routes = append(held.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	live := newTunnel(t, held, CarryDefault, &fakeOpenVPN{})
	ok, why := live.CanCarryExit(context.Background())
	if ok || !strings.Contains(why, "not up") {
		t.Errorf("a connection that is down said %v, %q; want a refusal saying it is not up", ok, why)
	}

	live = newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})
	ok, why = live.CanCarryExit(context.Background())
	if ok || !strings.Contains(why, "not chosen") {
		t.Errorf("a connected connection nobody chose said %v, %q; want a refusal saying it was "+
			"not chosen to carry this machine's internet traffic", ok, why)
	}
}

// The other way of carrying it: app-tail owns this machine's default route, so the connection
// is given one belonging to its own interface instead. Until that route is there a dial bound
// to the interface reaches nothing, so the connection reports itself carrying nothing -- and
// once it is there, it reports itself carrying without openvpn having taken anything from this
// machine.
func TestCarryingTheInternetOnItsOwnInterfaceWaitsForTheRoute(t *testing.T) {
	runner := &fakeOpenVPN{}
	live := newTunnel(t, heldFixture(), CarryScoped, runner)
	live.noteDevice("utun9")

	if ok, why := live.CanCarryExit(context.Background()); ok || !strings.Contains(why, "not up") {
		t.Errorf("a connection that is down said %v, %q; want a refusal saying it is not up", ok, why)
	}

	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})
	waitFor(t, func() bool { return len(runner.scopes()) == 1 },
		"the connection never asked for a route on its own interface")

	if scopes := runner.scopes(); scopes[0] != (hostnet.OpenVPNScope{ID: "tn_test01", Interface: "utun9"}) {
		t.Errorf("the route was asked for as %+v, want it on this connection's own interface", scopes[0])
	}
	waitFor(t, func() bool {
		ok, _ := live.CanCarryExit(context.Background())
		return ok
	}, "the connection has the route on its interface and still reports carrying nothing")

	if runs := runner.runs(); len(runs) != 0 {
		t.Fatalf("openvpn was started %d times by a connection that was never started", len(runs))
	}
}

// The route failing is reported on the connection rather than swallowed. Without it every dial
// app-tail sends into this connection fails with "no route to host", and a connection that said
// it was carrying the traffic would be one silently dropping all of it.
func TestAnInterfaceThatCouldNotBeGivenARouteSaysSo(t *testing.T) {
	runner := &fakeOpenVPN{scopeFail: errors.New("route: writing to routing socket: Network is unreachable")}
	live := newTunnel(t, heldFixture(), CarryScoped, runner)
	live.noteDevice("utun9")
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})

	waitFor(t, func() bool {
		ok, why := live.CanCarryExit(context.Background())
		return !ok && strings.Contains(why, "Network is unreachable")
	}, "a connection whose interface could not be given a route did not say why")
}

// The interface openvpn opens is what the route goes on, and nothing else knows its name. A
// connection that reached CONNECTED without one is a disagreement with openvpn rather than a
// connection to report as carrying traffic.
func TestAConnectionWithNoInterfaceYetCarriesNothing(t *testing.T) {
	runner := &fakeOpenVPN{}
	live := newTunnel(t, heldFixture(), CarryScoped, runner)
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})

	waitFor(t, func() bool {
		ok, why := live.CanCarryExit(context.Background())
		return !ok && strings.Contains(why, "which network interface")
	}, "a connection with no interface reported itself carrying this machine's internet traffic")
	if scopes := runner.scopes(); len(scopes) != 0 {
		t.Errorf("a route was asked for on %+v, and openvpn had named no interface", scopes)
	}
}

// openvpn is started without persist-tun, so a connection that dropped and came back tore its
// interface down and opened another -- and an interface that goes away takes its routes with
// it. Asking for the route only once leaves this connection reporting itself as carrying this
// machine's internet traffic over a route the kernel dropped, which is every destination
// failing with nothing on screen saying why. That is the internet dying on a connection the
// dashboard still shows as up.
func TestAReconnectAsksForTheRouteAgain(t *testing.T) {
	runner := &fakeOpenVPN{}
	live := newTunnel(t, heldFixture(), CarryScoped, runner)
	live.noteDevice("utun9")
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})
	waitFor(t, func() bool { return len(runner.scopes()) == 1 },
		"the connection never asked for a route on its own interface")

	// The drop, then the same connection back on the interface the kernel handed it this time.
	live.observe(report{Name: "RECONNECTING"})
	live.noteDevice("utun11")
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})

	waitFor(t, func() bool { return len(runner.scopes()) == 2 },
		"the connection came back on another interface and never asked for a route on it")
	scopes := runner.scopes()
	if scopes[1] != (hostnet.OpenVPNScope{ID: "tn_test01", Interface: "utun11"}) {
		t.Errorf("the second route was asked for as %+v, want it on the interface the connection "+
			"came back on", scopes[1])
	}
	waitFor(t, func() bool {
		ok, _ := live.CanCarryExit(context.Background())
		return ok
	}, "the connection has a route on the interface it came back on and still reports carrying nothing")
}

// The window between openvpn naming its new interface and the route landing on it. A connection
// still reporting the route it had on the interface that went away is one every dial fails
// through while the dashboard says it is carrying the traffic.
func TestAConnectionOnAnInterfaceWithNoRouteYetCarriesNothing(t *testing.T) {
	runner := &fakeOpenVPN{}
	live := newTunnel(t, heldFixture(), CarryScoped, runner)
	live.noteDevice("utun9")
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})
	waitFor(t, func() bool {
		ok, _ := live.CanCarryExit(context.Background())
		return ok
	}, "the connection never reported itself carrying this machine's internet traffic")

	live.noteDevice("utun11")
	if ok, why := live.CanCarryExit(context.Background()); ok {
		t.Errorf("a connection whose route is on an interface it has left said it carries this "+
			"machine's internet traffic: %v, %q", ok, why)
	}
}

// Which connection carries this machine's internet traffic is a route on an interface, not
// something the running openvpn is told -- so moving it is a route change on a connection that
// keeps running. Restarting the program instead drops a working connection and takes the
// machine off the internet for the length of a handshake, which is the switch failing.
func TestMovingTheInternetOntoAndOffThisConnectionLeavesItRunning(t *testing.T) {
	runner := &fakeOpenVPN{}
	live := newTunnel(t, heldFixture(), CarryNone, runner)
	live.noteDevice("utun9")
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})
	if scopes := runner.scopes(); len(scopes) != 0 {
		t.Fatalf("a connection nobody chose asked for a route: %+v", scopes)
	}

	live.SetCarry(CarryScoped)
	waitFor(t, func() bool {
		ok, _ := live.CanCarryExit(context.Background())
		return ok
	}, "the connection was chosen to carry this machine's internet traffic and never got the route")

	live.SetCarry(CarryNone)
	waitFor(t, func() bool { return len(runner.unscopes()) == 1 },
		"another connection took over and the route was never taken back")
	if ok, why := live.CanCarryExit(context.Background()); ok || !strings.Contains(why, "not chosen") {
		t.Errorf("a connection that no longer carries the traffic said %v, %q", ok, why)
	}
	if stops := runner.stops(); len(stops) != 0 {
		t.Errorf("openvpn was stopped %d times to move a route", len(stops))
	}
}

// A laptop that changed networks is sending from an address that no longer exists, and openvpn
// finds that out only when the server's pushed keepalive expires -- a timeout the server chose,
// usually a minute or more, during which the connection looks up and reaches nothing. Being
// told puts that restart at the moment the machine moved instead.
func TestTheConnectionIsMadeAgainWhenTheMachineMoves(t *testing.T) {
	said := make(chan string, 16)
	runner := &fakeOpenVPN{speak: func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			said <- strings.TrimRight(line, "\r\n")
		}
	}}
	links := make(chan struct{}, 1)
	live := newTunnelWith(t, heldFixture(), CarryNone, runner, func(o *Options) { o.LinkChanges = links })

	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})
	// The three notification subscriptions, which is also what proves openvpn is holding the
	// socket: a command sent before that has nothing to reach.
	for range 3 {
		select {
		case <-said:
		case <-time.After(10 * time.Second):
			t.Fatal("the connection never opened its conversation with openvpn")
		}
	}

	links <- struct{}{}

	select {
	case got := <-said:
		if got != "signal SIGUSR1" {
			t.Errorf("the connection said %q when the machine moved, want the restart", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the machine moved and the connection said nothing to the program carrying it")
	}
}

// And a connection that is not running says nothing. The program is not there to be told, and
// the one that follows connects on the machine's networking as it then stands.
func TestAConnectionThatIsNotRunningIsNotToldTheMachineMoved(t *testing.T) {
	runner := &fakeOpenVPN{}
	links := make(chan struct{}, 1)
	live := newTunnelWith(t, heldFixture(), CarryNone, runner, func(o *Options) { o.LinkChanges = links })

	// Never started, so there is no conversation at all. This must not panic and must not
	// reach for a socket that was never created.
	live.reconnect()

	if runs := runner.runs(); len(runs) != 0 {
		t.Errorf("a connection that was never started ran openvpn %d times", len(runs))
	}
}

// waitFor blocks until the condition holds, or fails with what was being waited for. The route
// is asked for on a goroutine of its own -- the connection must not stop being watched while
// this machine's routing is changed -- so what it settles on is waited for rather than read.
func waitFor(t *testing.T, done func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A default route among the stored networks is not a route on the interface: the rendered file
// drops it, because installing it is redirect-gateway's job and openvpn is given that flag only
// when this connection was chosen. Reading it as an ability would report a connection carrying
// nothing as carrying everything, and every dial through it fails with "no route to host".
func TestADeclaredDefaultRouteIsNotAnAbilityToCarryTheInternet(t *testing.T) {
	held := heldFixture()
	held.Routes = append(held.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	live := newTunnel(t, held, CarryNone, &fakeOpenVPN{})
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})

	if ok, why := live.CanCarryExit(context.Background()); ok {
		t.Errorf("a connection nobody chose said it carries internet traffic because 0.0.0.0/0 "+
			"is among its stored networks: %v, %q", ok, why)
	}
}

// Choosing a connection to carry this machine's internet traffic is the whole of the
// instruction. A provider pushes redirect-gateway at connect time rather than writing it into
// the file it hands out, so demanding a default route among the stored networks as well would
// refuse to start the connections this setting exists for.
func TestChoosingAConnectionToCarryEverythingIsInstructionEnough(t *testing.T) {
	runner := &fakeOpenVPN{}
	held := heldFixture()
	if held.CarriesDefault() {
		t.Fatal("the fixture carries a default route, so this proves nothing")
	}
	live := newTunnel(t, held, CarryDefault, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	runs := runner.runs()
	if len(runs) != 1 {
		t.Fatalf("openvpn was started %d times, want once", len(runs))
	}
	if !runs[0].RedirectGateway {
		t.Error("openvpn was not told to take the default route, so nothing would go through it")
	}
	// Its own answer has to agree, or the connection carrying the traffic reports that it
	// cannot -- and what is on screen contradicts what the machine is doing.
	if _, why := live.CanCarryExit(context.Background()); strings.Contains(why, "0.0.0.0/0") {
		t.Errorf("the connection chosen to carry the traffic said %q", why)
	}
}

// Every stored value reaches the privileged side as a typed field, and the one decision that
// is not stored -- whether this connection carries the machine's internet traffic -- is the
// one this app makes.
func TestTheStoredSettingsCrossThePrivilegeBoundaryAsTypedValues(t *testing.T) {
	held := heldFixture()
	held.Routes = append(held.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	held.Cipher = "AES-256-GCM"
	runner := &fakeOpenVPN{}
	live := newTunnel(t, held, CarryDefault, runner)

	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	runs := runner.runs()
	if len(runs) != 1 {
		t.Fatalf("openvpn was started %d times, want once", len(runs))
	}
	run := runs[0]
	if run.ID != "tn_test01" || run.Remote != held.Remote || run.Cipher != held.Cipher {
		t.Errorf("the run does not carry the stored settings: %+v", run)
	}
	if !run.RedirectGateway {
		t.Error("the connection chosen to carry this machine's internet traffic did not say so")
	}
	if len(run.Routes) != len(held.Routes) {
		t.Errorf("the run carries %d routes, want %d", len(run.Routes), len(held.Routes))
	}
}

// The whole conversation, driven by something speaking openvpn's management protocol down the
// socket this connection created: the hold is released, the account is answered, and what the
// server says about the connection becomes what the connection reports.
func TestTheConnectionIsDrivenEntirelyOverItsManagementSocket(t *testing.T) {
	said := make(chan string, 16)
	runner := &fakeOpenVPN{speak: func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		read := func() string {
			line, err := reader.ReadString('\n')
			if err != nil {
				return ""
			}
			return strings.TrimRight(line, "\r\n")
		}
		// The three notification subscriptions this app opens with.
		for range 3 {
			said <- read()
		}
		// Held on purpose, so nothing reaches the server before there is anything here to
		// hear what it says.
		if _, err := io.WriteString(conn, ">HOLD:Waiting for hold release:10\n"); err != nil {
			return
		}
		said <- read()

		if _, err := io.WriteString(conn, ">PASSWORD:Need 'Auth' username/password\n"); err != nil {
			return
		}
		said <- read()
		said <- read()

		if _, err := io.WriteString(conn,
			">LOG:1699999999,I,PUSH: Received control message: 'PUSH_REPLY,route 192.168.9.0 255.255.255.0'\n"+
				">BYTECOUNT:4096,2048\n"+
				">STATE:1699999999,CONNECTED,SUCCESS,10.8.0.6,203.0.113.9,1194,192.168.1.20,54321,\n"); err != nil {
			return
		}
		// Held open: openvpn stops itself when this connection drops, so a fake that hung up
		// here would be testing the teardown instead of the conversation.
		_, _ = io.ReadAll(conn)
	}}

	live := newTunnel(t, heldFixture(), CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}

	for _, want := range []string{
		"state on",
		"log on",
		"bytecount 5",
		"hold release",
		`username "Auth" "alice"`,
		`password "Auth" "s3cret"`,
	} {
		select {
		case got := <-said:
			if got != want {
				t.Errorf("the connection said %q, want %q", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("the connection never said %q", want)
		}
	}

	status := waitForState(t, live, tunnel.StateConnected)
	if len(status.Addrs) != 1 || status.Addrs[0] != "10.8.0.6" {
		t.Errorf("the connection reports the addresses %q, want the one the server assigned", status.Addrs)
	}
	if limits := strings.Join(status.Limits, "\n"); !strings.Contains(limits, "route 192.168.9.0 255.255.255.0") {
		t.Errorf("the route the server offered was not reported:\n%s", limits)
	}
	if anchors := live.Anchors(); len(anchors) != 1 || anchors[0] != netip.MustParseAddr("203.0.113.9") {
		t.Errorf("the connection's own packets are anchored at %v, want the server it is talking to", anchors)
	}
	// Up is what this machine sent and Down what it received, which is the reverse of the
	// order openvpn reports them in: a connection that showed a download as an upload would
	// be read as a machine sending everything it is in fact receiving.
	if carried := live.Carried(); carried.Up != 2048 || carried.Down != 4096 {
		t.Errorf("the connection carried %d up and %d down, want 2048 up and 4096 down",
			carried.Up, carried.Down)
	}
	if carried := live.Carried(); carried.Since.IsZero() {
		t.Error("a running connection reports no moment it was built, so nothing can say how long it has been up")
	}

	if err := live.Close(); err != nil {
		t.Fatalf("close the connection: %v", err)
	}
	if stops := runner.stops(); len(stops) != 1 || stops[0] != "tn_test01" {
		t.Errorf("the privileged side was asked to stop %v, want the connection that was started", stops)
	}
	if status := live.Status(); status.State != tunnel.StateOff {
		t.Errorf("a closed connection reports %q, want %q", status.State, tunnel.StateOff)
	}
	// The conversation ends with the connection: one left open is a program this side still
	// looks like it is supervising.
	select {
	case <-runner.finished():
	case <-time.After(10 * time.Second):
		t.Error("the conversation with openvpn was still open after the connection closed")
	}
}

// A fatal error from openvpn is the connection failing, and it is reported with what openvpn
// said rather than as a connection that is merely not up.
func TestAFatalErrorFromOpenVPNBecomesAFailedConnection(t *testing.T) {
	runner := &fakeOpenVPN{speak: func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		for range 3 {
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}
		}
		if _, err := io.WriteString(conn, ">FATAL:Options error: Unrecognized option\n"); err != nil {
			return
		}
		_, _ = io.ReadAll(conn)
	}}

	live := newTunnel(t, heldFixture(), CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	status := waitForState(t, live, tunnel.StateFailed)
	if !strings.Contains(status.Detail, "Unrecognized option") {
		t.Errorf("the connection failed with %q, want what openvpn said", status.Detail)
	}
}

// openvpn refuses a command over this socket with a plain ERROR line rather than a
// notification, so a reader watching only for the >-prefixed kinds would take a refused
// command as a command that worked.
func TestACommandOpenVPNRefusesIsReportedRatherThanIgnored(t *testing.T) {
	runner := &fakeOpenVPN{speak: func(_ *testing.T, conn net.Conn) {
		reader := bufio.NewReader(conn)
		for range 3 {
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}
		}
		if _, err := io.WriteString(conn, "ERROR: unknown command\n"); err != nil {
			return
		}
		_, _ = io.ReadAll(conn)
	}}

	live := newTunnel(t, heldFixture(), CarryNone, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	status := waitForState(t, live, tunnel.StateFailed)
	if !strings.Contains(status.Detail, "unknown command") {
		t.Errorf("the connection failed with %q, want what openvpn refused", status.Detail)
	}
}

// A connection that never came up carries nothing, so a dial through it is refused rather
// than sent out through this machine's own network -- which is where a destination inside a
// private network would reach somebody else entirely.
func TestNothingIsDialledThroughAConnectionThatIsNotUp(t *testing.T) {
	live := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	if _, err := live.Dial(context.Background(), "tcp", "10.8.0.5:5432"); err == nil {
		t.Error("a dial through a connection that is not up was attempted, want a refusal")
	}
	if _, err := live.Reach(context.Background(), "tcp", "10.8.0.5:5432"); err == nil {
		t.Error("a connection that is not up answered a reach, want a refusal")
	}
	if _, err := live.Listen("tcp", 5432); err == nil {
		t.Error("a listener was opened on a connection with no address, want a refusal")
	}
	if _, err := live.ListenPacket("udp", 5432); err == nil {
		t.Error("a packet listener was opened on a connection with no address, want a refusal")
	}
}

// A destination is reported as carried only when this connection carries it. Reporting one it
// does not would send the caller to an address that belongs to somebody else on whichever
// network the machine happens to be on.
func TestOnlyWhatThisConnectionCarriesIsReportedAsCarried(t *testing.T) {
	live := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})

	carried, err := live.Reach(context.Background(), "tcp", "10.8.0.5:5432")
	if err != nil {
		t.Fatalf("reach a destination inside the network: %v", err)
	}
	if !carried.Carried || carried.Addr != netip.MustParseAddrPort("10.8.0.5:5432") {
		t.Errorf("a destination inside the network was reported as %+v, want it carried", carried)
	}

	outside, err := live.Reach(context.Background(), "tcp", "192.168.1.5:5432")
	if err != nil {
		t.Fatalf("reach a destination outside the network: %v", err)
	}
	if outside.Carried {
		t.Errorf("a destination this connection does not carry was reported as %+v", outside)
	}

	// A default route is where this machine's internet traffic goes, not a claim on every
	// destination there is.
	held := heldFixture()
	held.Routes = append(held.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	live = newTunnel(t, held, CarryNone, &fakeOpenVPN{})
	live.observe(report{Name: "CONNECTED", TunV4: netip.MustParseAddr("10.8.0.6")})
	everything, err := live.Reach(context.Background(), "tcp", "203.0.113.50:443")
	if err != nil {
		t.Fatalf("reach a destination on the internet: %v", err)
	}
	if everything.Carried {
		t.Errorf("a destination on the internet was reported as carried: %+v", everything)
	}
}

// The networks this connection carries are what it was told, so a caller matching a
// destination against them never has to wait for a server to say anything.
func TestTheNetworksCarriedAreWhatTheConnectionWasTold(t *testing.T) {
	held := heldFixture()
	held.Routes = append(held.Routes, netip.MustParsePrefix("0.0.0.0/0"))
	live := newTunnel(t, held, CarryNone, &fakeOpenVPN{})

	routes, err := live.Routes(context.Background())
	if err != nil {
		t.Fatalf("read the networks this connection carries: %v", err)
	}
	if len(routes) != 1 || routes[0] != netip.MustParsePrefix("10.8.0.0/16") {
		t.Errorf("the connection carries %v, want the one network it was told and not the default route", routes)
	}
}

// The packet size is the configured one, openvpn's own default until the interface exists,
// and never zero -- a caller sizing a datagram against zero writes nothing.
func TestThePacketSizeIsAlwaysAnAnswer(t *testing.T) {
	live := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	if got := live.MTU(); got != defaultMTU {
		t.Errorf("a connection with no configured size reports %d, want %d", got, defaultMTU)
	}

	held := heldFixture()
	held.MTU = 1400
	live = newTunnel(t, held, CarryNone, &fakeOpenVPN{})
	if got := live.MTU(); got != 1400 {
		t.Errorf("a connection configured for %d reports %d", held.MTU, got)
	}
}

// The registry keys on the identifier and the kind, so a connection that reported either
// wrongly would be filed under something no caller asks for.
func TestTheConnectionReportsItsOwnIdentifierAndKind(t *testing.T) {
	live := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	if live.ID() != "tn_test01" {
		t.Errorf("id = %q, want the one it was built with", live.ID())
	}
	if live.Kind() != tunnel.KindOpenVPN {
		t.Errorf("kind = %q, want %q", live.Kind(), tunnel.KindOpenVPN)
	}
}

// The interface is empty until the connection has one. The kernel chooses it, so reporting a
// guess before the connection is up would put a name in front of a reader that no tool on
// this machine answers to.
func TestTheInterfaceIsEmptyUntilTheConnectionHasOne(t *testing.T) {
	live := newTunnel(t, heldFixture(), CarryNone, &fakeOpenVPN{})
	if got := live.Interface(); got != "" {
		t.Errorf("interface = %q before the connection started, want none", got)
	}
}

// A lookup on a connection that is not up is refused rather than answered from this machine's
// own resolver, which is what would leak a private name onto the network app-tail is on.
func TestALookupOnAConnectionThatIsNotUpIsRefused(t *testing.T) {
	held := heldFixture()
	held.DNS = []netip.Addr{netip.MustParseAddr("10.8.0.1")}
	live := New(Options{
		ID: "tn_test01", Held: held,
		Logger: slog.New(slog.DiscardHandler), Runner: &fakeOpenVPN{},
	})
	resolving, ok := live.(tunnel.Resolving)
	if !ok {
		t.Fatal("a connection with its own resolvers cannot look names up")
	}
	if _, err := resolving.LookupHost(context.Background(), "db.corp.example"); err == nil {
		t.Fatal("a name was resolved on a connection that is not up")
	}
}

// A dial network names the address family the resolver is asked for. Reading it wrongly would
// answer a tcp4 dial with an IPv6 address, which fails at the dial rather than at the lookup
// and reads as the network being down.
func TestTheAddressFamilyIsReadFromTheDialNetwork(t *testing.T) {
	cases := map[string]string{
		"tcp": "ip", "udp": "ip", "ip": "ip",
		"tcp4": "ip4", "udp4": "ip4", "ip4": "ip4",
		"tcp6": "ip6", "udp6": "ip6", "ip6": "ip6",
	}
	for network, want := range cases {
		if got := lookupNetwork(network); got != want {
			t.Errorf("lookupNetwork(%q) = %q, want %q", network, got, want)
		}
	}
}

// Whether this build can run an OpenVPN connection is answered by the privileged side, and
// this package is what the app asks. The two disagreeing would have the app offer a kind of
// connection that can never start, or withhold one it could.
func TestWhetherThisBuildRunsOpenVPNIsThePrivilegedSidesAnswer(t *testing.T) {
	if Supported() != hostnet.OpenVPNSupported() {
		t.Errorf("this package reports %v and the privileged side reports %v",
			Supported(), hostnet.OpenVPNSupported())
	}
}

// The helper's client does not say where its sockets are, because the helper puts them in one
// place: the connection dials the path the helper computes from the same connection id.
func TestTheConnectionDialsTheSocketTheHelperCreates(t *testing.T) {
	type helperClient struct{ Runner }
	live := newTunnel(t, heldFixture(), CarryNone, helperClient{&fakeOpenVPN{}})
	if got, want := live.managementSocket(), hostnet.OpenVPNManagementSocket("tn_test01"); got != want {
		t.Errorf("the connection would dial %s, want the helper's %s", got, want)
	}
	runner := &fakeOpenVPN{dir: socketDir(t)}
	local := newTunnel(t, heldFixture(), CarryNone, runner)
	if got, want := local.managementSocket(), runner.ManagementSocket("tn_test01"); got != want {
		t.Errorf("the connection would dial %s, want the %s its runner says it listens on", got, want)
	}
}

// A program whose management socket never opens is held, waiting for a client that is not
// coming, and holds root and an interface while it waits. The start fails and the program is
// stopped rather than left there until the session ends.
func TestAProgramThatNeverOpensItsManagementSocketIsStopped(t *testing.T) {
	runner := &fakeOpenVPN{mute: true}
	live := newTunnel(t, heldFixture(), CarryNone, runner)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := live.Start(ctx)

	if err == nil {
		t.Fatal("a connection whose program never opened its management socket was reported as started")
	}
	if !strings.Contains(err.Error(), "management socket") {
		t.Errorf("the failure does not say what was never reached: %v", err)
	}
	if stops := runner.stops(); len(stops) != 1 || stops[0] != "tn_test01" {
		t.Errorf("the privileged side was asked to stop %v, want the program that could not be reached", stops)
	}
	if status := live.Status(); status.State != tunnel.StateFailed {
		t.Errorf("the connection reports %q, want %q", status.State, tunnel.StateFailed)
	}
	if err := live.Close(); err != nil {
		t.Errorf("close a connection that never started: %v", err)
	}
}
