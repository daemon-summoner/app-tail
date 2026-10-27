// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The record is what the next start works through, and part way through a reconciliation both
// sets are on this machine: the copies not yet removed and the ones already installed. A record
// naming only one of them is a route left behind that nothing will ever take back.
func TestTheRecordNamesEveryCopyOnTheMachineDuringAReconciliation(t *testing.T) {
	staying := scopedHostRoute{iface: "utun9990", gateway: "192.0.2.1"}
	going := scopedHostRoute{iface: "utun9991", gateway: "198.51.100.1"}
	arriving := scopedHostRoute{iface: "utun9992", gateway: "203.0.113.1", v6: true}

	both := union([]scopedHostRoute{staying, going}, []scopedHostRoute{staying, arriving})

	want := []scopedHostRoute{staying, going, arriving}
	if !slices.Equal(both, want) {
		t.Errorf("the record would name %+v, want %+v", both, want)
	}
}

// The copy exists to give a socket bound to this machine's own interface a way to the internet.
// A copy made on the interface app-tail itself opened says that traffic bound to that interface
// reaches the internet through that same interface, which is a loop and not a way out -- and the
// machine it would be installed on is one where this app already holds the default route it is
// supposed to be preserving.
func TestNoCopyIsMadeOfADefaultRouteThatIsAlreadyAppTails(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no copy to make: %v", err)
	}
	iface, _, ok, err := hostDefaultRoute(t.Context(), false)
	if err != nil {
		t.Fatalf("read this machine's own default route: %v", err)
	}
	if !ok {
		t.Skip("this machine holds no default route, so there is nothing to copy or refuse")
	}

	wanted, errs := wantedHostDefaults(t.Context(), iface)

	for _, route := range wanted {
		if route.iface == iface {
			t.Errorf("a copy of the default route was made on %s, which app-tail opened itself", iface)
		}
	}
	joined := errors.Join(errs...)
	if joined == nil {
		t.Fatalf("app-tail holding this machine's only default route was passed over in silence")
	}
	if !strings.Contains(joined.Error(), iface) {
		t.Errorf("the reason given was %q, which does not name the interface %q it is about", joined, iface)
	}
}

// The same read, with app-tail on an interface of its own: this is the ordinary case, and what
// it produces is fed straight to the route command. A copy naming no interface would be a route
// command built from an empty string.
func TestThisMachinesOwnWayOutIsCopiedOntoTheInterfaceItSitsOn(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no copy to make: %v", err)
	}
	iface, _, ok, err := hostDefaultRoute(t.Context(), false)
	if err != nil {
		t.Fatalf("read this machine's own default route: %v", err)
	}
	if !ok {
		t.Skip("this machine holds no default route, so there is nothing to copy")
	}

	// A name no interface has, standing in for the one app-tail opened: it cannot collide with
	// the machine's own, so every default route the machine holds is one to copy.
	wanted, errs := wantedHostDefaults(t.Context(), "apptest-absent")
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("reading this machine's own way out failed: %v", err)
	}
	if len(wanted) == 0 {
		t.Fatal("this machine holds a default route and no copy of it was called for")
	}

	seen := map[bool]bool{}
	for _, route := range wanted {
		if route.iface == "" {
			t.Errorf("a copy was called for on no interface at all: %+v", route)
		}
		if seen[route.v6] {
			t.Errorf("two copies were called for on the same address family (v6=%v), which would "+
				"install one over the other and leave the second's removal naming a route that is gone",
				route.v6)
		}
		seen[route.v6] = true
	}
	if wanted[0].iface != iface {
		t.Errorf("the copy is on %q, want %q -- the interface this machine's own default route sits on",
			wanted[0].iface, iface)
	}
}

// The copy is installed for as long as app-tail carries this machine's traffic, so a request
// arriving after the session ended is one whose reason has gone with it. Acting on it would put
// a route on this machine that nothing is left to take back.
func TestNoCopyIsMadeOnceTheSessionHasEnded(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no copy to make: %v", err)
	}
	local := testLocal(t)
	local.mu.Lock()
	local.closed = true
	local.mu.Unlock()

	err := local.ScopeHostDefault(t.Context())
	if err == nil {
		t.Fatal("a route was asked for on a machine whose session had already been torn down")
	}
	if !strings.Contains(err.Error(), "torn down") {
		t.Errorf("err = %q, want it to say the session it was for has ended", err)
	}
	local.mu.Lock()
	held := len(local.hostScoped)
	local.mu.Unlock()
	if held != 0 {
		t.Errorf("%d copies were recorded as installed by a request that was refused", held)
	}
}

// Reading this machine's routing table is a program run per address family, so a caller that
// gave up is answered before the first of them rather than after all of them.
func TestACopyNobodyIsWaitingForIsNotMade(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no copy to make: %v", err)
	}
	local := testLocal(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := local.ScopeHostDefault(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the reason the caller gave for stopping", err)
	}
	local.mu.Lock()
	held := len(local.hostScoped)
	local.mu.Unlock()
	if held != 0 {
		t.Errorf("%d copies were recorded as installed by a request that was never acted on", held)
	}
}

// The interface a copy sits on can go away before the copy is taken back -- unplugging an
// ethernet adapter is enough. The route went with it, so the removal has nothing left to do and
// the record of it has to be dropped, or the teardown goes on trying to remove a route that no
// interface has.
func TestACopyOnAnInterfaceThatIsGoneIsAlreadyTakenBack(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no copy to take back: %v", err)
	}
	local := testLocal(t)
	gone := goneInterface(t)
	local.mu.Lock()
	local.hostScoped = []scopedHostRoute{
		{iface: gone, gateway: "192.0.2.1"},
		{iface: gone, v6: true},
	}
	local.mu.Unlock()

	if err := local.UnscopeHostDefault(t.Context()); err != nil {
		t.Fatalf("take back copies from an interface that is gone: %v", err)
	}
	local.mu.Lock()
	held := local.hostScoped
	local.mu.Unlock()
	if len(held) != 0 {
		t.Errorf("%d copies are still recorded as on this machine after being taken back: %+v", len(held), held)
	}

	// Asked for again, with nothing recorded, it reaches the routing table not at all.
	if err := local.UnscopeHostDefault(t.Context()); err != nil {
		t.Errorf("take back copies that were already taken back: %v", err)
	}
}

// The record is written before the copy goes in, so a record that cannot be written is a copy
// that is not installed. Installing it anyway would put a root route on this machine with
// nothing anywhere that knows to take it back -- which is the state the record exists to
// prevent, reached by the one path that is supposed to prevent it.
func TestNoCopyIsInstalledWhenTheRecordOfItCannotBeWritten(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no copy to make: %v", err)
	}
	local := NewLocal(func(string, ...any) {})
	local.state = closedRootState(t)
	changed := 0
	local.scopeRoute = func(context.Context, string, string, bool) error { changed++; return nil }
	local.unscopeRoute = func(context.Context, string, string, bool) error { changed++; return nil }
	// One copy already held, so the record has something to write whatever this machine's own
	// routing table holds.
	local.hostScoped = []scopedHostRoute{{iface: "utun9993", gateway: "192.0.2.1"}}

	err := local.ScopeHostDefault(t.Context())

	if err == nil {
		t.Fatal("a copy was installed on this machine with nothing recording it")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the reason given is %q, want it to say the record could not be written", err)
	}
	if changed != 0 {
		t.Errorf("%d route changes were made on this machine before the record of them was written", changed)
	}
}

// A copy that could not be taken back is still on this machine, so it stays on the list the
// teardown works through and stays in the record the next start reads. A failure to shrink the
// record is reported for the same reason: the record is the only thing that outlives this run.
func TestACopyThatCouldNotBeTakenBackIsStillOnTheList(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no copy to take back: %v", err)
	}
	state, seal := closableRootState(t)
	local := NewLocal(func(string, ...any) {})
	local.state = state
	stuck := scopedHostRoute{iface: "utun9994", gateway: "198.51.100.1"}
	local.hostScoped = []scopedHostRoute{stuck}
	local.unscopeRoute = func(context.Context, string, string, bool) error {
		// The record goes out of reach at the moment the removal fails, which is the case where
		// this side can neither take the copy back nor write down that it is still there.
		seal()
		return errors.New("the routing table would not have it")
	}
	local.scopeRoute = func(context.Context, string, string, bool) error {
		return errors.New("this case installs nothing on the machine it runs on")
	}

	err := local.ScopeHostDefault(t.Context())

	if err == nil {
		t.Fatal("a copy that is still on this machine was reported as taken back")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the reason given is %q, want it to say the record could not be written", err)
	}
	local.mu.Lock()
	held := local.hostScoped
	local.mu.Unlock()
	if !slices.Contains(held, stuck) {
		t.Errorf("the list the teardown works through holds %+v, and the copy on %s is still on this machine",
			held, stuck.iface)
	}
}

// The record shrinks only once what it named is off the machine. A record emptied on the way
// out would be this side forgetting a route it failed to remove, which leaves it installed with
// nothing left anywhere that knows it is there.
func TestCopiesAreForgottenOnlyOnceTheRecordCanSaySo(t *testing.T) {
	state, seal := closableRootState(t)
	local := NewLocal(func(string, ...any) {})
	local.state = state
	route := scopedHostRoute{iface: "utun9995", gateway: "203.0.113.1"}
	if err := state.setHostRoutes([]scopedHostRoute{route}); err != nil {
		t.Fatalf("record a copy of this machine's own default route: %v", err)
	}
	local.hostScoped = []scopedHostRoute{route}
	seal()
	local.unscopeRoute = func(context.Context, string, string, bool) error { return nil }

	err := local.UnscopeHostDefault(t.Context())

	if err == nil {
		t.Fatal("a record that still names a copy that is gone was reported as written")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the reason given is %q, want it to say the record could not be written", err)
	}
}
