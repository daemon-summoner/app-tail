// SPDX-License-Identifier: MIT

package fabric

// The address the interface itself holds. It is one address out of the same range moved
// networks are presented from, which is what makes it worth pinning: an address the
// machine answers for itself, handed to a connection as well, is a host on that network
// this machine can never reach.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/tailscale/wireguard-go/tun"

	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/inspect"
)

// fakeHost is this machine's privileged side, without the machine or the privilege. Every
// step it stands in for is one that changes the computer's own routing table, so the order
// they run in and what is undone when one of them fails are exactly what cannot be left to a
// manual check on a machine that already holds the rights.
type fakeHost struct {
	dev  tun.Device
	name string

	capsErr   error
	caps      hostnet.Capabilities
	openErr   error
	routerErr error
	routesErr error
	scopeErr  error

	mu       sync.Mutex
	installs []hostnet.Routes
	// steps is every privileged call in the order it arrived, which is what the ordering
	// between keeping the machine's own way out reachable and claiming the address space is
	// asserted against.
	steps  []string
	closes int
}

var _ privileged = (*fakeHost)(nil)

func (h *fakeHost) Capabilities(context.Context) (hostnet.Capabilities, error) {
	return h.caps, h.capsErr
}

func (h *fakeHost) OpenTUN(_ context.Context, name string) (tun.Device, string, error) {
	if h.openErr != nil {
		return nil, "", h.openErr
	}
	if h.name == "" {
		h.name = name
	}
	return h.dev, h.name, nil
}

func (h *fakeHost) RouterUp(context.Context) error { return h.routerErr }

func (h *fakeHost) SetHostRoutes(_ context.Context, r hostnet.Routes) error {
	if h.routesErr != nil {
		return h.routesErr
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.installs = append(h.installs, r)
	h.steps = append(h.steps, "set-host-routes")
	return nil
}

func (h *fakeHost) ScopeHostDefault(context.Context) error {
	if h.scopeErr != nil {
		return h.scopeErr
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.steps = append(h.steps, "scope-host-default")
	return nil
}

func (h *fakeHost) UnscopeHostDefault(context.Context) error {
	if h.scopeErr != nil {
		return h.scopeErr
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.steps = append(h.steps, "unscope-host-default")
	return nil
}

// taken is every privileged call this host was asked for, in order.
func (h *fakeHost) taken() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.steps)
}

func (h *fakeHost) Close() error {
	h.mu.Lock()
	h.closes++
	h.mu.Unlock()
	return nil
}

func (h *fakeHost) installed() []hostnet.Routes {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.installs)
}

func (h *fakeHost) letGoOfTheMachine() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closes
}

// openWith is OpenInterface against a substituted privileged side.
func openWith(t *testing.T, host *fakeHost, opts InterfaceOptions) (*Interface, error) {
	t.Helper()
	opts.open = func(context.Context, hostnet.Options) (privileged, error) { return host, nil }
	return OpenInterface(t.Context(), opts)
}

// Every platform refuses an interface with no address, so there is always one -- and it is
// a single address rather than the range, because holding the whole pool would leave the
// machine answering for every moved network at once.
func TestTheInterfaceTakesOneAddressOutOfThePool(t *testing.T) {
	pool := []netip.Prefix{p("198.18.0.0/15"), p("fd7a:115c:a1e0::/48")}

	addrs := InterfaceAddrs(pool)

	if len(addrs) != 2 {
		t.Fatalf("the interface holds %v, want one address of each family", addrs)
	}
	for _, held := range addrs {
		if held.Addr().Is4() && held.Bits() != 32 {
			t.Errorf("%s is a range, want the single address the interface answers for", held)
		}
		if !held.Addr().Is4() && held.Bits() != 128 {
			t.Errorf("%s is a range, want the single address the interface answers for", held)
		}
		if !pool[0].Contains(held.Addr()) && !pool[1].Contains(held.Addr()) {
			t.Errorf("%s is outside the pool, so nothing keeps a network off it", held)
		}
	}
}

// Handed back to the allocator as one of this machine's own, so no connection is ever
// presented at it. Without that the address would be given to a network and every packet
// for that host would be answered by this machine instead.
func TestNoNetworkIsPresentedAtTheInterfacesOwnAddress(t *testing.T) {
	pool := []netip.Prefix{p("198.18.0.0/24")}
	held := InterfaceAddrs(pool)

	// Two connections on one range, so the second has to be moved into the pool, and a
	// small pool so it is moved next to the interface's own address rather than far from it.
	plan := Allocate([]Network{carries("tn_a", "10.0.0.0/29"), carries("tn_b", "10.0.0.0/29")}, held, pool)

	moved := placementFor(t, plan, "tn_b", "10.0.0.0/29")
	if !moved.Moved() {
		t.Fatal("the second connection was left claiming addresses the first one answers for")
	}
	for _, own := range held {
		if moved.PresentedAs.Contains(own.Addr()) {
			t.Errorf("%s was presented at %s, which holds this machine's own %s",
				moved.TunnelID, moved.PresentedAs, own.Addr())
		}
	}
}

// A pool nobody configured still has to produce an address, because the interface cannot
// come up without one.
func TestAnUnconfiguredPoolStillGivesTheInterfaceAnAddress(t *testing.T) {
	addrs := InterfaceAddrs(nil)

	if len(addrs) == 0 {
		t.Fatal("no address, so the interface would be refused by the machine")
	}
	if !DefaultPool[0].Contains(addrs[0].Addr()) {
		t.Errorf("the interface holds %s, want an address out of %s", addrs[0], DefaultPool[0])
	}
}

// A pool with more than one range of a family: the interface takes one address, not one per
// range. Each extra address is another host this machine answers for instead of a network.
func TestTheInterfaceTakesOneAddressPerFamilyAndNoMore(t *testing.T) {
	addrs := InterfaceAddrs([]netip.Prefix{p("198.18.0.0/16"), p("198.19.0.0/16"), {}})

	if len(addrs) != 1 {
		t.Fatalf("the interface holds %v, want the one address the first range starts at", addrs)
	}
	if addrs[0] != p("198.18.0.0/32") {
		t.Errorf("the interface holds %s, want 198.18.0.0/32", addrs[0])
	}
}

// Every way creating the interface can fail lets go of the machine's privileged side again.
// Holding it keeps the helper session open, and the helper refuses a second one -- so a
// single failed attempt would leave this mode unable to start until the process is restarted,
// with nothing on screen naming the reason.
func TestEveryFailedAttemptLetsGoOfTheMachine(t *testing.T) {
	device, other := wirePair()
	t.Cleanup(func() { other.Close() })

	tests := []struct {
		name string
		host *fakeHost
		want string
	}{
		{
			name: "the machine cannot say what it can do",
			host: &fakeHost{dev: device, capsErr: errors.New("the helper is not answering")},
			want: "the helper is not answering",
		},
		{
			name: "something else already manages this machine's networks",
			host: &fakeHost{dev: device, caps: hostnet.Capabilities{Conflict: "another tailnet client is running"}},
			want: "another tailnet client is running",
		},
		{
			name: "the interface itself cannot be created",
			host: &fakeHost{dev: device, openErr: errors.New("no interface is available")},
			want: "no interface is available",
		},
		{
			name: "the interface is created and cannot be brought up",
			host: &fakeHost{dev: device, routerErr: errors.New("the routing table refused it")},
			want: "the routing table refused it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, err := openWith(t, tt.host, InterfaceOptions{Name: "apptest0"})
			if err == nil {
				t.Fatalf("the interface was created anyway: %+v", iface)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to name %q", err, tt.want)
			}
			if got := tt.host.letGoOfTheMachine(); got != 1 {
				t.Errorf("the machine was let go of %d times, want once -- the next attempt is refused otherwise", got)
			}
		})
	}
}

// The interface's own addresses ride on every routing change, because the privileged side
// installs a whole configuration rather than a difference: leaving them out of one call takes
// them off the interface, and an interface with no address is one the machine will not use.
func TestEveryRoutingChangeCarriesTheInterfacesOwnAddresses(t *testing.T) {
	device, other := wirePair()
	t.Cleanup(func() { other.Close() })
	own := InterfaceAddrs(DefaultPool)
	host := &fakeHost{dev: device, name: "apptest0"}

	iface, err := openWith(t, host, InterfaceOptions{Name: "apptest0", Addrs: own})
	if err != nil {
		t.Fatalf("create the interface: %v", err)
	}
	if iface.Name() != "apptest0" || iface.Device() == nil {
		t.Fatalf("the interface is %q with device %v, want the one the machine handed back", iface.Name(), iface.Device())
	}

	routes := []netip.Prefix{p("10.0.0.0/8"), p("172.16.0.0/12")}
	exclude := []netip.Prefix{p("203.0.113.7/32")}
	if err := iface.Carry(t.Context(), routes, exclude, 1280); err != nil {
		t.Fatalf("point the machine at the interface: %v", err)
	}
	if err := iface.Withdraw(t.Context()); err != nil {
		t.Fatalf("take the networks back off the machine: %v", err)
	}

	installed := host.installed()
	if len(installed) != 2 {
		t.Fatalf("%d routing changes were installed, want the one that carries and the one that withdraws", len(installed))
	}
	carrying := installed[0]
	if !slices.Equal(carrying.Routes, routes) || !slices.Equal(carrying.LocalRoutes, exclude) || carrying.MTU != 1280 {
		t.Errorf("carrying = %+v, want the ranges, the exclusions and the packet size it was given", carrying)
	}
	for i, change := range installed {
		if !slices.Equal(change.LocalAddrs, own) {
			t.Errorf("routing change %d holds %v, want the interface's own %v -- without them the "+
				"machine takes the addresses off the interface", i, change.LocalAddrs, own)
		}
	}
	// Withdrawing leaves the interface up and carrying nothing, which is what makes every
	// destination on it fail at once instead of answering nothing.
	if withdrawn := installed[1]; len(withdrawn.Routes) != 0 || len(withdrawn.LocalRoutes) != 0 {
		t.Errorf("withdrawing installed %+v, want the addresses alone", withdrawn)
	}

	if err := iface.Close(); err != nil {
		t.Fatalf("close the interface: %v", err)
	}
	if got := host.letGoOfTheMachine(); got != 1 {
		t.Errorf("the machine was let go of %d times, want once", got)
	}
}

// The machine's own way out is kept reachable before the ranges that make it necessary are
// installed, and taken back only after they are gone. Either order reversed is a window --
// however short -- in which a program that binds a socket to the interface this machine's
// default route sits on has no route to the internet at all. The tailnet node this app runs is
// one of those programs, and the window is what stops it reaching its control server.
func TestTheMachinesOwnWayOutIsKeptReachableAroundTheRanges(t *testing.T) {
	device, other := wirePair()
	t.Cleanup(func() { other.Close() })
	host := &fakeHost{dev: device, name: "apptest0"}

	iface, err := openWith(t, host, InterfaceOptions{Name: "apptest0", Addrs: InterfaceAddrs(DefaultPool)})
	if err != nil {
		t.Fatalf("create the interface: %v", err)
	}
	if err := iface.Carry(t.Context(), []netip.Prefix{p("10.0.0.0/8")}, nil, 1280); err != nil {
		t.Fatalf("point the machine at the interface: %v", err)
	}
	if err := iface.Withdraw(t.Context()); err != nil {
		t.Fatalf("take the networks back off the machine: %v", err)
	}

	want := []string{"scope-host-default", "set-host-routes", "set-host-routes", "unscope-host-default"}
	if got := host.taken(); !slices.Equal(got, want) {
		t.Errorf("the machine was asked for %v, want %v", got, want)
	}
}

// A machine that cannot give one interface a route of its own is a machine where a bound socket
// is already answered from the whole table, so there is nothing to keep reachable. Treating that
// as a failure would make this whole mode unavailable there -- and saying so on every change to
// what is carried would bury every other line the app writes.
func TestAMachineWithNoScopedRoutesStillCarriesTrafficAndIsSaidOnce(t *testing.T) {
	device, other := wirePair()
	t.Cleanup(func() { other.Close() })
	host := &fakeHost{
		dev:      device,
		name:     "apptest0",
		scopeErr: fmt.Errorf("this machine: %w", hostnet.ErrScopedRoutesUnsupported),
	}
	var said []string

	iface, err := openWith(t, host, InterfaceOptions{
		Name: "apptest0",
		Logf: func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) },
	})
	if err != nil {
		t.Fatalf("create the interface: %v", err)
	}
	for range 3 {
		if err := iface.Carry(t.Context(), []netip.Prefix{p("10.0.0.0/8")}, nil, 1280); err != nil {
			t.Fatalf("a machine with no scoped routes refused to carry traffic: %v", err)
		}
	}
	if err := iface.Withdraw(t.Context()); err != nil {
		t.Fatalf("a machine with no scoped routes refused to withdraw: %v", err)
	}

	if got := len(host.installed()); got != 4 {
		t.Errorf("%d routing changes reached the machine, want all 4 -- the ranges are installed either way", got)
	}
	if len(said) != 1 {
		t.Fatalf("the machine's answer was written %d times, want once: %v", len(said), said)
	}
	if !strings.Contains(said[0], hostnet.ErrScopedRoutesUnsupported.Error()) {
		t.Errorf("the line written was %q, which loses the reason the machine gave", said[0])
	}
}

// Every other failure is the machine refusing to keep its own way out reachable, and carrying
// anyway would install the ranges that cut it off. So Carry fails, and the ranges never reach
// the routing table.
func TestRangesAreNotInstalledWhenTheMachinesOwnWayOutCannotBeKept(t *testing.T) {
	device, other := wirePair()
	t.Cleanup(func() { other.Close() })
	refused := errors.New("the routing table refused the scoped route")
	host := &fakeHost{dev: device, name: "apptest0", scopeErr: refused}

	iface, err := openWith(t, host, InterfaceOptions{Name: "apptest0"})
	if err != nil {
		t.Fatalf("create the interface: %v", err)
	}
	err = iface.Carry(t.Context(), []netip.Prefix{p("10.0.0.0/8")}, nil, 1280)
	if !errors.Is(err, refused) {
		t.Errorf("Carry = %v, want the machine's own refusal", err)
	}
	if got := host.taken(); len(got) != 0 {
		t.Errorf("the machine was asked for %v, want nothing -- those ranges cut off its own way out", got)
	}
}

// Closing an interface that was never created is what a caller does after a failure it did
// not have to classify, so it has to be a no-op rather than a second failure on top of one.
func TestClosingAnInterfaceThatWasNeverCreatedChangesNothing(t *testing.T) {
	if err := (&Interface{}).Close(); err != nil {
		t.Errorf("closing nothing failed: %v", err)
	}
}

// The interface and the stack behind it are handed out as one thing, and this is what that
// buys: the caller gets the name the machine chose, the addresses to keep every network off,
// and one Close that undoes both halves.
func TestAFabricThatIsUpIsTheInterfaceAndTheStackTogether(t *testing.T) {
	device, other := wirePair()
	t.Cleanup(func() { other.Close() })
	host := &fakeHost{dev: device, name: "apptest0"}

	live, err := Open(t.Context(), LiveOptions{
		Name:     "apptest0",
		Pool:     DefaultPool,
		Carriers: carrierSet{},
		MTU:      testMTU,
		Logger:   slog.New(slog.DiscardHandler),
		open:     func(context.Context, hostnet.Options) (privileged, error) { return host, nil },
	})
	if err != nil {
		t.Fatalf("bring the fabric up: %v", err)
	}

	if live.Name() != "apptest0" {
		t.Errorf("the fabric is on %q, want the name the machine gave the interface", live.Name())
	}
	if !slices.Equal(live.Addrs(), InterfaceAddrs(DefaultPool)) {
		t.Errorf("the fabric holds %v, want the addresses taken out of the pool", live.Addrs())
	}
	if live.MTU() != testMTU {
		t.Errorf("the fabric carries %d-byte packets, want %d", live.MTU(), testMTU)
	}
	if status := live.Status(); !status.Running || status.Interface != "apptest0" {
		t.Errorf("status = %+v, want it running and named after the interface", status)
	}
	// The ports are asked for apart from Status, because only the activity graphs want them.
	// An interface that has carried nothing names no port rather than a row of zeroes.
	if named, _, folded := live.Ports(); len(named) != 0 || folded != 0 {
		t.Errorf("a fresh interface reported %d ports and folded %d, want neither", len(named), folded)
	}

	// The addressing arrives after the interface, because it is decided from what the
	// connections carry and that is known only once they are up.
	table, err := NewTable([]Mapping{{TunnelID: "tn_a", Prefix: p("10.1.0.0/16"), PresentedAs: p("198.18.0.0/16")}})
	if err != nil {
		t.Fatalf("build the addressing: %v", err)
	}
	live.SetTable(table, map[string]string{"tn_a": "Office"})
	networks := live.Status().Networks
	if len(networks) != 1 || networks[0].TunnelID != "tn_a" || networks[0].PresentedAs != p("198.18.0.0/16") {
		t.Errorf("the fabric reports %+v, want the one network it was given and where it is reached", networks)
	}
	// Inspection arrives the same way and for the same reason: it is decided from the
	// settings, which are read after the interface is up.
	live.SetInspector(&fakeInspector{refuse: map[string]string{"10.1.0.9": "stopped"}})
	if _, refuse := live.fab.inspects(inspect.Flow{Addr: netip.MustParseAddr("10.1.0.9")}); !refuse {
		t.Error("the inspector handed to the interface never reached the flows it carries")
	}

	if err := live.Carry(t.Context(), []netip.Prefix{p("10.0.0.0/8")}, nil, testMTU); err != nil {
		t.Fatalf("point the machine at the fabric: %v", err)
	}
	if err := live.Withdraw(t.Context()); err != nil {
		t.Fatalf("take the networks back off the machine: %v", err)
	}
	if got := len(host.installed()); got != 2 {
		t.Errorf("%d routing changes reached the machine, want the two that were asked for", got)
	}

	if err := live.Close(); err != nil {
		t.Fatalf("take the fabric down: %v", err)
	}
	select {
	case <-live.Done():
	default:
		t.Error("the fabric reports itself still carrying traffic after it was closed")
	}
	if got := host.letGoOfTheMachine(); got != 1 {
		t.Errorf("the machine was let go of %d times, want once", got)
	}
}

// The machine's privileged side cannot be reached at all: no helper installed, or one this
// build will not talk to. Nothing was created, so there is nothing to undo -- and the reason
// has to survive to the caller, because it is the one a user can act on.
func TestAMachineWithNoPrivilegedSideIsRefusedWithItsReason(t *testing.T) {
	refused := errors.New("the privileged helper is not installed")
	_, err := Open(t.Context(), LiveOptions{
		Pool:     DefaultPool,
		Carriers: carrierSet{},
		MTU:      testMTU,
		Logger:   slog.New(slog.DiscardHandler),
		open:     func(context.Context, hostnet.Options) (privileged, error) { return nil, refused },
	})
	if !errors.Is(err, refused) {
		t.Errorf("error = %v, want the reason the machine gave", err)
	}
}

// A stack that cannot be built after the interface already exists leaves the machine holding
// an interface nothing is reading -- a black hole for every range pointed at it. Both halves
// have to go, in that order, and the device is the half no fabric exists to close.
func TestAStackThatCannotBeBuiltTakesTheInterfaceWithIt(t *testing.T) {
	device, other := wirePair()
	t.Cleanup(func() { other.Close() })
	host := &fakeHost{dev: device, name: "apptest0"}

	// No carriers: a fabric with nothing to re-dial through cannot carry anything, and is
	// refused rather than started and left dropping every flow.
	_, err := Open(t.Context(), LiveOptions{
		Name:   "apptest0",
		Pool:   DefaultPool,
		MTU:    testMTU,
		Logger: slog.New(slog.DiscardHandler),
		open:   func(context.Context, hostnet.Options) (privileged, error) { return host, nil },
	})
	if err == nil {
		t.Fatal("the fabric came up with nothing to re-dial connections through")
	}
	if got := host.letGoOfTheMachine(); got != 1 {
		t.Errorf("the machine was let go of %d times, want once -- the interface is otherwise left up "+
			"with nothing reading it", got)
	}
	if _, readErr := device.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0); readErr == nil {
		t.Error("the interface is still open, so every range pointed at it would answer nothing")
	}
}
