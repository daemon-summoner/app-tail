// SPDX-License-Identifier: MIT

package tunnel

// What the blocklist stops app-tail itself from reaching, and what it deliberately does not.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// namedList blocks the names it was built with and records every question put to it.
type namedList struct{ names map[string]string }

func listing(names ...string) *namedList {
	l := &namedList{names: make(map[string]string, len(names))}
	for _, n := range names {
		l.names[n] = "Hagezi Pro"
	}
	return l
}

func (l *namedList) Blocks(name string) (string, bool) {
	list, ok := l.names[name]
	return list, ok
}

// The same leak the routing rules are answered before a lookup for: a name app-tail will
// not connect to must not be put to any resolver either, because the query alone tells
// that resolver what was wanted.
func TestABlockedNameIsRefusedWithoutBeingLookedUpAnywhere(t *testing.T) {
	r := NewRegistry()
	office := resolvingEgress("tn_office", map[string][]netip.Addr{
		"doubleclick.net": {netip.MustParseAddr("192.0.2.44")},
	})
	mustAdd(t, r, office)
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		return netip.AddrPort{}, errors.New("this machine's resolver was asked")
	})
	r.SetBlocklist(listing("doubleclick.net"))

	_, err := r.Resolve(context.Background(), "tcp", "doubleclick.net:443")

	if !errors.Is(err, ErrNameBlocked) {
		t.Fatalf("Resolve gave %v, want the name refused by the blocklist", err)
	}
	if !strings.Contains(err.Error(), "Hagezi Pro") {
		t.Errorf("the refusal reads %q, which does not say which list to go and switch off", err)
	}
	if len(office.asked) != 0 || len(office.reached) != 0 {
		t.Errorf("a connection was asked about a blocked name: asked=%v reached=%v", office.asked, office.reached)
	}
}

// Nil is the switch being off, and off has to mean the destination behaves exactly as it
// did before the feature existed.
func TestWithNoBlocklistTheSameNameConnectsAsItAlwaysDid(t *testing.T) {
	r, _ := resolvesTo(t, "doubleclick.net:443", "192.0.2.44:443")
	r.SetBlocklist(listing("doubleclick.net"))
	r.SetBlocklist(nil)

	route, err := r.Resolve(context.Background(), "tcp", "doubleclick.net:443")

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Addr != mustAddrPort(t, "192.0.2.44:443") {
		t.Errorf("Addr = %s, want the address the connection answered with", route.Addr)
	}
}

// The scope limit, pinned rather than left to the README: a name one of app-tail's own
// connections answers for is that connection's name, and a list downloaded off the
// internet does not get to decide it. A list carrying "db" or a company domain would
// otherwise take out the hosts the user connected to those networks to reach.
func TestANameOnOneOfAppTailsOwnConnectionsIsNeverBlockedByAList(t *testing.T) {
	r, prod, _ := twoOverlappingNetworks(t)
	r.SetBlocklist(listing("db.prod.internal", "db"))

	route, err := r.Resolve(context.Background(), "tcp", "db.prod.internal:5432")

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.TunnelID != prod.ID() {
		t.Errorf("TunnelID = %q, want the connection the name belongs to", route.TunnelID)
	}
}

// A blocked name is refused before the routing rules choose anything, so an exception
// sending it elsewhere does not smuggle it out.
func TestARuleRoutingABlockedNameElsewhereStillDoesNotReachIt(t *testing.T) {
	r := NewRegistry()
	vpn := resolvingEgress("tn_vpn", map[string][]netip.Addr{
		"doubleclick.net": {netip.MustParseAddr("192.0.2.44")},
	})
	mustAdd(t, r, vpn)
	r.SetEgress("tn_vpn")
	r.SetBlocklist(listing("doubleclick.net"))

	_, err := r.Resolve(context.Background(), "tcp", "doubleclick.net:443")

	if !errors.Is(err, ErrNameBlocked) {
		t.Fatalf("Resolve gave %v, want the name still refused", err)
	}
}

// An address literal carries no name, so there is nothing for a list to match on. Reading
// one as blocked would mean a list could refuse an address nobody listed.
func TestAnAddressLiteralIsNotSomethingAListCanBlock(t *testing.T) {
	r := NewRegistry()
	r.SetHostResolver(func(context.Context, string, string) (netip.AddrPort, error) {
		return mustAddrPort(t, "192.0.2.44:443"), nil
	})
	r.SetBlocklist(listing("192.0.2.44", ""))

	route, err := r.Resolve(context.Background(), "tcp", "192.0.2.44:443")

	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.Addr != mustAddrPort(t, "192.0.2.44:443") {
		t.Errorf("Addr = %s, want the literal that was asked for", route.Addr)
	}
}
