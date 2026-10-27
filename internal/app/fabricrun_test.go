// SPDX-License-Identifier: MIT

package app

// What the agent does with the interface that carries every connection: what it puts on it,
// what it deliberately keeps off it, when it rebuilds it, and what it does when the thing
// behind the interface stops.
//
// The interface itself is covered where it lives. These are about the wiring, which is where
// a machine routing whole networks at something that answers nothing comes from.

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/bytecount"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fabric"
)

// fakeFabric is an interface on this machine that is not on this machine.
//
// It stands in for the one thing the suite must never do: create a network interface and
// point the machine's routing table at it, which needs administrator rights. Everything the
// runner decides -- what to carry, what to keep off it, when to rebuild, when to give up --
// is above that line and is what these tests are about.
type fakeFabric struct {
	name string
	// opened is what the runner asked for, kept because the packet size and the pool are
	// fixed at creation and a change to either has to produce a different interface.
	opened fabric.LiveOptions

	mu        sync.Mutex
	table     *fabric.Table
	names     map[string]string
	tables    int
	routes    []netip.Prefix
	exclude   []netip.Prefix
	mtu       int
	carries   int
	withdrawn int
	closed    bool
	counters  map[string]fabric.Counters
	ports     []bytecount.Row
	trouble   string
	stalled   bool
	inspector fabric.Inspector
	done      chan struct{}

	// The three ways the machine's own side can refuse: the routing table, taking the ranges
	// back off it, and letting go of the interface.
	carryErr    error
	withdrawErr error
	closeErr    error
	// observe, when set, is told when the interface is let go of, so a test can place that
	// among the steps other fakes take.
	observe func(step string)
}

var _ fabricLive = (*fakeFabric)(nil)

func newFakeFabric(opts fabric.LiveOptions) *fakeFabric {
	name := opts.Name
	if name == "" {
		name = "utunfake"
	}
	return &fakeFabric{name: name, opened: opts, mtu: opts.MTU, done: make(chan struct{})}
}

func (f *fakeFabric) Name() string          { return f.name }
func (f *fakeFabric) Addrs() []netip.Prefix { return fabric.InterfaceAddrs(f.opened.Pool) }
func (f *fakeFabric) Done() <-chan struct{} { return f.done }

func (f *fakeFabric) SetTable(t *fabric.Table, names map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.table, f.names = t, names
	f.tables++
}

func (f *fakeFabric) SetInspector(in fabric.Inspector) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspector = in
}

// addressed is how many times the addressing has been replaced. Replacing it walks every
// flow the interface is carrying, so a pass that changes nothing must not.
func (f *fakeFabric) addressed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tables
}

func (f *fakeFabric) Carry(_ context.Context, routes, exclude []netip.Prefix, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.carries++
	if f.carryErr != nil {
		return f.carryErr
	}
	f.routes, f.exclude, f.mtu = slices.Clone(routes), slices.Clone(exclude), mtu
	return nil
}

func (f *fakeFabric) Withdraw(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrawn++
	if f.withdrawErr != nil {
		return f.withdrawErr
	}
	f.routes = nil
	return nil
}

func (f *fakeFabric) MTU() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mtu
}

func (f *fakeFabric) Status() fabric.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fabric.Status{
		Interface: f.name, Running: !f.closed && !f.stalled, MTU: f.mtu, Routes: slices.Clone(f.routes),
		Counters: maps.Clone(f.counters), Error: f.trouble,
	}
}

func (f *fakeFabric) Ports() ([]bytecount.Row, bytecount.Row, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ports), bytecount.Row{}, 0
}

// troubled is the interface itself reporting a problem while it is still up -- a route the
// machine refused, a resolver that would not take the suffixes -- which is a different state
// from the interface never having been created.
func (f *fakeFabric) troubled(why string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trouble = why
}

// stalls is the interface up and carrying nothing, which is the state with no symptom: every
// address on every connection is unreachable while the mode itself looks chosen and fine.
func (f *fakeFabric) stalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stalled = true
}

// carried is what one connection has put across the interface, for the surfaces that report
// it. The real one counts flows as they cross; nothing crosses a fake interface.
func (f *fakeFabric) carried(id string, counted fabric.Counters) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counters == nil {
		f.counters = make(map[string]fabric.Counters)
	}
	f.counters[id] = counted
}

func (f *fakeFabric) Close() error {
	f.mu.Lock()
	f.closed = true
	err, observe := f.closeErr, f.observe
	f.mu.Unlock()
	if observe != nil {
		observe("fabric close")
	}
	return err
}

// refusesTo makes this machine's own side refuse one of the three things it is asked for,
// which is how a test reaches the states a real machine reaches by being in use.
func (f *fakeFabric) refusesTo(what string, why error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch what {
	case "carry":
		f.carryErr = why
	case "withdraw":
		f.withdrawErr = why
	case "close":
		f.closeErr = why
	default:
		panic("no such refusal: " + what)
	}
}

// stops is the stack behind the interface dying while the interface is still up, which is
// the failure the watchdog exists for and the one the privileged side's own dead-man's
// switch cannot see.
func (f *fakeFabric) stops() { close(f.done) }

func (f *fakeFabric) carrying() (routes, exclude []netip.Prefix, calls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.routes), slices.Clone(f.exclude), f.carries
}

func (f *fakeFabric) addressing() *fabric.Table {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.table
}

func (f *fakeFabric) tookNetworksBack() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.withdrawn
}

func (f *fakeFabric) wasClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// fakeFabrics is every interface the runner opened, in order, which is how a test asks
// whether something was rebuilt rather than updated.
type fakeFabrics struct {
	mu      sync.Mutex
	built   []*fakeFabric
	refusal string
	// observe is handed to every interface built here.
	observe func(step string)
}

func (f *fakeFabrics) open(_ context.Context, opts fabric.LiveOptions) (fabricLive, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refusal != "" {
		return nil, errors.New(f.refusal)
	}
	live := newFakeFabric(opts)
	live.observe = f.observe
	f.built = append(f.built, live)
	return live, nil
}

// refuses is a machine that cannot create the interface at all -- no privileged helper, or
// one that will not start. Nothing is carrying anything, which is a different state from an
// interface that is up and having trouble.
func (f *fakeFabrics) refuses(why string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refusal = why
}

func (f *fakeFabrics) all() []*fakeFabric {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeFabric(nil), f.built...)
}

// labTunnelID is the second connection these tests seed, which carries the same addresses as
// the first: the case the whole module exists for.
const labTunnelID = "tn_lab"

// The ranges the seeded connections carry. They are deliberately not ranges a developer's
// own machine is likely to be on: this machine's own networks are read for real, and a
// collision with one of them would move a connection these tests expect to stay put.
var (
	officeRange = netip.MustParsePrefix("172.30.99.0/24")
	labRange    = netip.MustParsePrefix("172.31.88.0/24")
)

// seedFabric puts two WireGuard connections in the document and asks for one interface
// carrying both.
//
// The tailnet this app is built on runs alongside them and carries its own two ranges, so
// what the interface carries is those plus what these two say they reach. Every assertion
// below therefore names the ranges it means rather than counting them.
func seedFabric(c *config.Config, labCarries netip.Prefix) {
	c.Settings.InterfaceEnabled = true
	c.Settings.InterfaceMode = config.NetworkFabric
	c.Settings.InterfaceName = "apptest0"

	office := config.NewTunnel(wgTunnelID, "office", "Office", config.TunnelWireGuard)
	office.WireGuard = &config.WireGuardTunnel{
		PrivateKey: "aBhtG18wo5eIJXAkl7L4L3RyKNwzZuBAK1zSHnRRRXc=",
		Addresses:  []netip.Prefix{netip.MustParsePrefix("172.30.99.4/24")},
		MTU:        config.DefaultWireGuardMTU,
		DNS:        []netip.Addr{netip.MustParseAddr("172.30.99.1")},
		Peer: config.WireGuardPeer{
			PublicKey:  "vGKFmWU/gzcgTHFI9DMBGaGqjRWTKJhCXV/2NAB6dHM=",
			Endpoint:   "gateway.example.com:51820",
			AllowedIPs: []netip.Prefix{officeRange},
		},
	}

	lab := config.NewTunnel(labTunnelID, "lab", "Lab", config.TunnelWireGuard)
	lab.WireGuard = &config.WireGuardTunnel{
		PrivateKey: "majYatxGzfGESWHzcaf6Y+ldZ1CHNgfXsieg+falAgw=",
		Addresses:  []netip.Prefix{netip.MustParsePrefix("172.31.88.4/24")},
		MTU:        config.DefaultWireGuardMTU,
		DNS:        []netip.Addr{netip.MustParseAddr("172.31.88.1")},
		Peer: config.WireGuardPeer{
			PublicKey:  "Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE=",
			Endpoint:   "lab.example.com:51820",
			AllowedIPs: []netip.Prefix{labCarries},
		},
	}

	c.Tunnels = append(c.Tunnels, office, lab)
}

// carryingFabric is a harness whose two connections are up and whose interface is carrying
// them, with the machine's side of it faked.
func carryingFabric(t *testing.T, labCarries netip.Prefix) (*harness, *fakeFabrics) {
	t.Helper()
	return carryingFabricWith(t, labCarries, nil)
}

// carryingFabricWith is the same, with one more change to the document -- for the cases that
// are about a connection arranged differently rather than about the interface.
func carryingFabricWith(t *testing.T, labCarries netip.Prefix, also func(*config.Config)) (*harness, *fakeFabrics) {
	t.Helper()
	fabrics := &fakeFabrics{}
	h := newHarnessWith(t, func(c *config.Config) {
		seedFabric(c, labCarries)
		if also != nil {
			also(c)
		}
	}, func(o *Options) {
		o.OpenFabric = fabrics.open
	})
	waitFor(t, 5*time.Second, "the interface to be carrying both connections", func() bool {
		built := fabrics.all()
		if len(built) == 0 {
			return false
		}
		routes, _, calls := built[len(built)-1].carrying()
		return calls > 0 && slices.Contains(routes, officeRange) && slices.Contains(routes, labCarries)
	})
	return h, fabrics
}

// What the interface is for: every connection's addresses reachable from this machine at
// once. And the hazard that comes with it -- a connection's own server address inside a
// range this machine now sends to the interface would have its encrypted packets routed back
// into the interface that produced them, taking the machine off every network it has.
func TestTheInterfaceCarriesEveryNetworkAndKeepsTheirOwnServersOffIt(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)

	office := h.wireguards.devicesFor(wgTunnelID)[0]
	office.reachesItselfAt(netip.MustParseAddr("172.30.99.254"))
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the connection's own server to be kept off the interface", func() bool {
		_, exclude, _ := fabrics.all()[0].carrying()
		return len(exclude) == 1
	})

	live := fabrics.all()[0]
	routes, exclude, _ := live.carrying()
	for _, want := range []netip.Prefix{officeRange, labRange} {
		if !slices.Contains(routes, want) {
			t.Errorf("routes = %v, want %s among them -- that network is unreachable without it", routes, want)
		}
	}
	if want := netip.MustParsePrefix("172.30.99.254/32"); !slices.Contains(exclude, want) {
		t.Errorf("kept off the interface = %v, want %s -- without it the connection's own packets "+
			"come back to the interface that produced them", exclude, want)
	}
	table := live.addressing()
	if table == nil {
		t.Fatal("the interface was given no addressing at all, so nothing it carries reaches a connection")
	}
	for _, want := range []struct {
		prefix netip.Prefix
		id     string
	}{{officeRange, wgTunnelID}, {labRange, labTunnelID}} {
		if got := carriedBy(table, want.prefix.Addr().Next()); got != want.id {
			t.Errorf("an address in %s is carried by %q, want %q -- that connection has no addressing",
				want.prefix, got, want.id)
		}
	}
}

// The addresses a tailnet hands its devices, and one address on the open internet. The
// tailnet ones are what this machine reaches other devices at; the third is what "everything
// else" means when a connection is asked to carry it.
var (
	aTailnetDevice   = netip.MustParseAddr("100.65.45.58")
	aTailnetDeviceV6 = netip.MustParseAddr("fd7a:115c:a1e0::2836:2d3b")
	somewhereOnline  = netip.MustParseAddr("93.184.216.34")
)

// carriedBy is the connection the interface hands an address to, empty when nothing carries
// it. An address nothing carries is a destination this machine has no way to reach at all.
func carriedBy(table *fabric.Table, addr netip.Addr) string {
	dest, ok := table.Lookup(addr)
	if !ok {
		return ""
	}
	return dest.TunnelID
}

// Every device on the tailnet is reachable over the interface, and stays reachable when the
// connection carrying this machine's internet traffic changes.
//
// The tailnet is the connection no route ever names: its devices live in the tailnet's own
// allocation, and every member reaches every other by being a member rather than by anybody
// advertising a route to it. An interface built from carried routes alone therefore has
// nothing for the tailnet, and every device on it is unreachable from this machine while the
// mode reports itself as carrying every connection.
//
// The second half is the one that moves: sending internet traffic through a connection maps
// every address there is at that connection, which is a wider range than the tailnet's own
// and must not take the tailnet with it.
func TestTheInterfaceCarriesTheTailnetAndKeepsItWhenInternetTrafficMoves(t *testing.T) {
	fabrics := &fakeFabrics{}
	h := newHarnessWith(t, func(c *config.Config) {
		seedFabric(c, labRange)
	}, func(o *Options) {
		o.OpenFabric = fabrics.open
	})

	waitFor(t, 5*time.Second, "the interface to be carrying the tailnet", func() bool {
		built := fabrics.all()
		if len(built) == 0 {
			return false
		}
		return carriedBy(built[len(built)-1].addressing(), aTailnetDevice) == config.PrimaryTunnelID
	})

	live := fabrics.all()[len(fabrics.all())-1]
	if got := carriedBy(live.addressing(), aTailnetDeviceV6); got != config.PrimaryTunnelID {
		t.Errorf("an IPv6 tailnet address is carried by %q, want the tailnet -- a tailnet reachable "+
			"at half its addresses is not half reachable", got)
	}
	routes, _, _ := live.carrying()
	for _, want := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
	} {
		if !slices.Contains(routes, want) {
			t.Errorf("routes = %v, want %s among them -- without it nothing on this machine sends "+
				"a tailnet address to the interface", routes, want)
		}
	}

	resp, raw := h.request(http.MethodPut, "/api/settings", strings.NewReader(
		`{"egress.mode":"tunnel","egress.tunnelId":"`+wgTunnelID+`"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", resp.StatusCode, raw)
	}
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "internet traffic to be on the office connection", func() bool {
		built := fabrics.all()
		return carriedBy(built[len(built)-1].addressing(), somewhereOnline) == wgTunnelID
	})
	built := fabrics.all()
	if got := carriedBy(built[len(built)-1].addressing(), aTailnetDevice); got != config.PrimaryTunnelID {
		t.Errorf("with internet traffic moved onto another connection a tailnet device is carried "+
			"by %q, want the tailnet -- changing where the internet goes took the tailnet with it", got)
	}
}

// The packet size is the smallest of every connected network's, because a datagram is not
// re-segmented on the way through: one too big for the network it ends up on is dropped with
// nothing reporting why. The size is fixed when the interface is created, so a change to it
// is a rebuild rather than an update, and the previous interface has to go with it.
func TestASmallerNetworkResizesTheInterfaceByReplacingIt(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	first := fabrics.all()[0]
	if got := first.MTU(); got != fabricFloorMTU {
		t.Fatalf("the interface carries %d-byte packets, want the floor %d until a network states one", got, fabricFloorMTU)
	}

	h.wireguards.devicesFor(wgTunnelID)[0].carriesPacketsOf(1420)
	h.wireguards.devicesFor(labTunnelID)[0].carriesPacketsOf(1400)
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the interface to be rebuilt at the smaller size", func() bool {
		return len(fabrics.all()) == 2
	})
	second := fabrics.all()[1]
	if got := second.MTU(); got != 1400 {
		t.Errorf("the interface carries %d-byte packets, want 1400 -- the smallest network decides", got)
	}
	if !first.wasClosed() {
		t.Error("the interface at the previous size is still up, so two of them hold the machine at once")
	}
}

// The reconcile runs every few seconds and pointing this machine's routing table at an
// interface is a privileged call. A pass that changes nothing must make none of them.
func TestAPassThatChangesNothingLeavesThisMachinesRoutingTableAlone(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	_, _, before := fabrics.all()[0].carrying()

	for range 3 {
		h.agent.reconcileNow(context.Background())
	}

	if _, _, after := fabrics.all()[0].carrying(); after != before {
		t.Errorf("the routing table was written %d times over three passes that changed nothing", after-before)
	}
	if got := len(fabrics.all()); got != 1 {
		t.Errorf("%d interfaces were created for one unchanged configuration", got)
	}
}

// Replacing the addressing ends every carried flow whose network is now reached differently,
// which means walking all of them. The reconcile runs on every event the tailnet reports, so
// a pass that changes nothing must leave the addressing alone -- and a pass that changes it
// must not be skipped, or the interface goes on answering for a network it no longer carries.
func TestTheAddressingIsReplacedOnlyWhenItChanged(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	live := fabrics.all()[0]
	before := live.addressed()

	for range 3 {
		h.agent.reconcileNow(context.Background())
	}
	if after := live.addressed(); after != before {
		t.Errorf("the addressing was replaced %d times over three passes that changed nothing", after-before)
	}

	// One connection can no longer say what it reaches, so its network leaves the addressing.
	h.wireguards.devicesFor(labTunnelID)[0].failToSayWhatItReaches(errors.New("the connection is not answering"))
	h.agent.reconcileNow(context.Background())

	waitFor(t, 5*time.Second, "the addressing to be replaced once the networks changed", func() bool {
		return live.addressed() > before
	})
}

// The half of the dead-man's switch the privileged side cannot cover. It fires when this
// process is alive and the stack behind the interface is not, which leaves the machine
// sending whole networks at something that answers nothing -- indistinguishable from a slow
// network, for as long as nobody looks. Taking the ranges back off makes every one of those
// destinations fail immediately, the way they fail when app-tail is not running at all.
//
// The runner is driven directly rather than through a running agent: what the withdrawal
// leaves behind is what a reconcile then acts on, so behind a loop it stands only until the
// pass that rebuilds the interface. That recovery is the test below this one.
func TestTheStackStoppingTakesItsNetworksBackOffThisMachine(t *testing.T) {
	live := newFakeFabric(fabric.LiveOptions{Name: "apptest0", MTU: fabricFloorMTU})

	runner := newFabricRunner(quietLogger(), nil, nil, func(context.Context, fabric.LiveOptions) (fabricLive, error) {
		return live, nil
	}, nil)
	runner.apply(context.Background(), fabricTarget{
		on: true, table: &fabric.Table{}, routes: []netip.Prefix{labRange}, mtu: fabricFloorMTU,
	})
	if runner.carriedTable() == nil {
		t.Fatal("the interface came up carrying no addressing at all")
	}

	live.stops()

	waitFor(t, 5*time.Second, "the networks to be taken back off this machine", func() bool {
		return live.tookNetworksBack() == 1
	})
	waitFor(t, 5*time.Second, "the failure to be reported", func() bool {
		return runner.snapshot().failure != ""
	})
	if got := runner.carriedTable(); got != nil {
		t.Error("the addressing is still reported as carried, so a name on a connection would be " +
			"answered with an address this machine no longer routes")
	}
}

// And taking them back off is only half of it. Withdrawing makes the machine honest; it does
// not give the user their networks back, and nothing else is going to ask -- the loop is
// driven by events, and a stack dying is not one. So the switch asks for a pass itself, and
// the pass builds the interface again.
//
// Nothing in this test pokes the agent. That is the whole assertion: a machine left alone
// after the interface behind its connections died has to come back on its own.
func TestTheStackStoppingAsksForTheInterfaceToBeBuiltAgain(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)
	died := fabrics.all()[0]

	died.stops()

	waitFor(t, 10*time.Second, "the interface to be built again", func() bool {
		return len(fabrics.all()) > 1
	})
	rebuilt := fabrics.all()[1]
	waitFor(t, 5*time.Second, "the rebuilt interface to be carrying the networks again", func() bool {
		routes, _, _ := rebuilt.carrying()
		return len(routes) > 0
	})
	if got := h.agent.currentFabric().carriedTable(); got == nil {
		t.Error("the interface was rebuilt and its addressing is not reported as carried, so every " +
			"name on a connection stays unanswered")
	}
	if got := h.agent.currentFabric().snapshot().failure; got != "" {
		t.Errorf("the rebuilt interface still reports %q, so a machine that recovered reads as broken", got)
	}
}

// And when taking them back off fails, that is worse rather than the same: the machine is
// still sending whole networks at an interface that answers nothing, and the reason has to
// say which of the two happened or the fix is a guess.
//
// The runner is driven directly rather than through a running agent: the report a stack death
// leaves behind stands until the next reconcile, and a reconcile that rebuilds the interface
// clears it because the machine is whole again. Going through the agent would test which of
// the two happened first.
func TestNetworksThatCouldNotBeTakenBackOffAreReportedAsStillOnThisMachine(t *testing.T) {
	live := newFakeFabric(fabric.LiveOptions{Name: "apptest0", MTU: fabricFloorMTU})
	live.refusesTo("withdraw", errors.New("the routing table would not give them up"))

	runner := newFabricRunner(quietLogger(), nil, nil, func(context.Context, fabric.LiveOptions) (fabricLive, error) {
		return live, nil
	}, nil)
	runner.apply(context.Background(), fabricTarget{
		on: true, table: &fabric.Table{}, routes: []netip.Prefix{labRange}, mtu: fabricFloorMTU,
	})
	if runner.carriedTable() == nil {
		t.Fatal("the interface came up carrying no addressing at all")
	}

	live.stops()

	waitFor(t, 5*time.Second, "the refusal to be reported", func() bool {
		return runner.snapshot().failure == "the routing table would not give them up"
	})
	if got := runner.carriedTable(); got != nil {
		t.Error("the addressing is still reported as carried")
	}
}

// The interface is up and this machine's routing table will not point at it, which is the
// state that looks exactly like a working mode: the interface exists, the connections are up,
// and nothing reaches them. The reason has to name the routing table, and the mode must not
// come back reported as fine.
func TestARoutingTableThatRefusesTheInterfaceIsReportedRatherThanRetriedSilently(t *testing.T) {
	fabrics := &fakeFabrics{}
	h := newHarnessWith(t, func(c *config.Config) { seedFabric(c, labRange) }, func(o *Options) {
		o.OpenFabric = func(ctx context.Context, opts fabric.LiveOptions) (fabricLive, error) {
			live, err := fabrics.open(ctx, opts)
			if err != nil {
				return nil, err
			}
			live.(*fakeFabric).refusesTo("carry", errors.New("route already exists"))
			return live, nil
		}
	})

	waitFor(t, 5*time.Second, "the refusal to reach the report", func() bool {
		return h.agent.currentFabric().snapshot().failure == "route already exists"
	})
	snapshot := h.agent.currentFabric().snapshot()
	if !strings.Contains(snapshot.reason, "routing table could not be pointed at the interface") {
		t.Errorf("reason = %q, want it to name what refused", snapshot.reason)
	}
	// The interface itself is up, so it is reported as running -- and the addressing is not
	// reported as carried, because nothing on this machine routes to it.
	if !snapshot.running {
		t.Error("the interface was created and is reported as absent")
	}
	if got := h.agent.currentFabric().carriedTable(); got != nil {
		t.Error("the addressing is reported as carried by a machine whose routing table refused it")
	}
}

// An interface that will not let go on the way down is the one failure a clean-looking
// shutdown hides: this machine's routes still point at something this process no longer owns,
// and the next attempt to switch the mode on finds an interface already there.
func TestAnInterfaceThatWillNotLetGoOnShutdownIsReported(t *testing.T) {
	live := newFakeFabric(fabric.LiveOptions{Name: "apptest0", MTU: fabricFloorMTU})
	live.refusesTo("close", errors.New("the interface is still in use"))

	runner := newFabricRunner(quietLogger(), nil, nil, func(context.Context, fabric.LiveOptions) (fabricLive, error) {
		return live, nil
	}, nil)
	runner.apply(context.Background(), fabricTarget{on: true, table: &fabric.Table{}, mtu: fabricFloorMTU})

	err := runner.close()
	if err == nil {
		t.Fatal("an interface that would not let go reported a clean shutdown")
	}
	if !strings.Contains(err.Error(), "the interface is still in use") {
		t.Errorf("reported %v, want the interface's own reason", err)
	}
	// And closing again is quiet, because there is nothing left holding the machine.
	if err := runner.close(); err != nil {
		t.Errorf("closing an already stopped runner reported %v", err)
	}
}

// The runner given no way to make an interface uses this machine's own. Left nil it would
// fail on the first pass with a nil call rather than with anything a reader could act on.
func TestARunnerWithNoInterfaceMakerUsesThisMachinesOwn(t *testing.T) {
	runner := newFabricRunner(quietLogger(), nil, nil, nil, nil)

	if runner.open == nil {
		t.Fatal("the runner has no way to create an interface at all")
	}
}

// A connection that is stored and not running contributes nothing to the interface. It has
// no routes to carry and no server to keep off, and treating it as one would put a range on
// this machine that nothing can answer for.
func TestAConnectionThatIsStoredAndNotRunningPutsNothingOnTheInterface(t *testing.T) {
	spareRange := netip.MustParsePrefix("172.20.0.0/16")
	h, fabrics := carryingFabricWith(t, labRange, func(c *config.Config) {
		off := config.NewTunnel("tn_spare", "spare", "Spare", config.TunnelWireGuard)
		off.Enabled = false
		off.WireGuard = &config.WireGuardTunnel{
			PrivateKey: "majYatxGzfGESWHzcaf6Y+ldZ1CHNgfXsieg+falAgw=",
			Addresses:  []netip.Prefix{netip.MustParsePrefix("172.20.0.4/24")},
			MTU:        config.DefaultWireGuardMTU,
			Peer: config.WireGuardPeer{
				PublicKey:  "Ry0M2rNVGGQrrmJKKIY0F0EySFf9r0mAJvpDCkzQeGE=",
				Endpoint:   "spare.example.com:51820",
				AllowedIPs: []netip.Prefix{spareRange},
			},
		}
		c.Tunnels = append(c.Tunnels, off)
	})

	built := fabrics.all()
	routes, _, _ := built[len(built)-1].carrying()
	if slices.Contains(routes, spareRange) {
		t.Errorf("the interface carries %v, want %s off it -- nothing is running to answer for it",
			routes, spareRange)
	}
	for _, m := range built[len(built)-1].addressing().Mappings() {
		if m.TunnelID == "tn_spare" {
			t.Errorf("a connection that is not running was given the addressing %+v", m)
		}
	}
	if _, registered := h.agent.tunnels.Get("tn_spare"); registered {
		t.Error("a connection switched off is registered, so this test proves nothing")
	}
}

// A connection that is up and cannot say what it reaches leaves its ranges off the
// interface. The rest of the interface still has to come up: dropping every connection
// because one could not answer would take working networks off this machine.
func TestAConnectionThatCannotSayWhatItReachesLeavesTheRestCarried(t *testing.T) {
	h, fabrics := carryingFabric(t, labRange)

	h.wireguards.devicesFor(labTunnelID)[0].failToSayWhatItReaches(
		errors.New("the device is not answering"))
	before := len(fabrics.all())
	h.agent.pokeReconcile()

	waitFor(t, 5*time.Second, "the interface to be rebuilt without the silent connection", func() bool {
		built := fabrics.all()
		routes, _, calls := built[len(built)-1].carrying()
		return calls > 0 && (len(built) > before || !slices.Contains(routes, labRange))
	})

	built := fabrics.all()
	routes, _, _ := built[len(built)-1].carrying()
	if slices.Contains(routes, labRange) {
		t.Errorf("the interface carries %v, want %s off it -- that connection could not say it "+
			"reaches anything", routes, labRange)
	}
	if !slices.Contains(routes, officeRange) {
		t.Errorf("the interface carries %v, want the connection that could answer (%s) still on it",
			routes, officeRange)
	}
}

// The fabric looks a connection up in the registry rather than in a snapshot, so a flow
// arriving a moment after a connection came up finds that connection. A lookup that missed
// it would refuse the flow as belonging to nothing.
func TestTheInterfaceLooksUpConnectionsInTheRegistryItself(t *testing.T) {
	h := runningWireGuard(t)
	carriers := registryCarriers{registry: h.agent.tunnels}

	live, found := carriers.Carrier(wgTunnelID)
	if !found {
		t.Fatal("a running connection was not found, so every flow to it would be refused")
	}
	if live == nil {
		t.Error("the connection was found and handed back as nothing")
	}
	if _, found := carriers.Carrier("tn_absent"); found {
		t.Error("a connection that is not running was handed back as one carrying traffic")
	}
}
