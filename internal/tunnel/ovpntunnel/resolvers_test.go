// SPDX-License-Identifier: MIT

package ovpntunnel

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// The resolvers are picked out of what the server pushed and nothing else is. openvpn sends
// every dhcp-option kind down the same list, so a domain, a WINS server or an address that is
// not one must not end up being asked for names.
func TestOnlyTheNameServersAreTakenOutOfWhatTheServerPushed(t *testing.T) {
	got := servedResolvers([]string{
		"redirect-gateway def1",
		"route 10.8.0.0 255.255.0.0",
		"dhcp-option DNS 103.86.96.100",
		"dhcp-option DNS6 2606:4700:4700::1111",
		"dhcp-option DOMAIN corp.example.com",
		"dhcp-option WINS 10.8.0.9",
		"dhcp-option DNS not-an-address",
		"dhcp-option DNS",
	})
	want := []netip.Addr{
		netip.MustParseAddr("103.86.96.100"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the resolvers taken are %v, want %v", got, want)
	}
}

// A connection with no resolvers of its own could not look a name up inside it at all: the
// dial failed with "no resolvers configured" for every name on the network it had just joined.
// The ones the server hands out are the only thing that knows those names.
func TestANetworkWithNoResolversConfiguredUsesTheOnesItsServerHandedOut(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(hostnet.OpenVPNRun) string {
		return ">LOG:1699999999,I,PUSH: Received control message: 'PUSH_REPLY," +
			"redirect-gateway def1,dhcp-option DNS 103.86.96.100,dhcp-option DNS 103.86.99.100," +
			"route 10.8.0.0 255.255.0.0'\n" + connectedLine
	})

	held := heldFixture()
	if len(held.DNS) != 0 {
		t.Fatal("the fixture configures resolvers, so this proves nothing")
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

	status := waitForState(t, live, tunnel.StateConnected)

	live.mu.Lock()
	served, resolver := live.served, live.resolver
	live.mu.Unlock()
	want := []netip.Addr{netip.MustParseAddr("103.86.96.100"), netip.MustParseAddr("103.86.99.100")}
	if !reflect.DeepEqual(served, want) {
		t.Errorf("the connection took %v as its resolvers, want %v", served, want)
	}
	if resolver == nil {
		t.Error("the connection has no resolver, so every name inside it fails to look up")
	}

	limits := strings.Join(status.Limits, "\n")
	if !strings.Contains(limits, "103.86.96.100, 103.86.99.100") || !strings.Contains(limits, "server sees") {
		t.Errorf("the connection does not say whose resolvers it is using, or what that costs:\n%s", limits)
	}
	// The same option cannot be reported as ignored and used at once.
	if strings.Contains(limits, "not applied: dhcp-option DNS") ||
		strings.Contains(limits, "; dhcp-option DNS 103.86.96.100") {
		t.Errorf("the resolvers being used are also listed as ignored:\n%s", limits)
	}
	// Everything else the server offered is still reported, and still not acted on.
	if !strings.Contains(limits, "redirect-gateway def1") || !strings.Contains(limits, "route 10.8.0.0") {
		t.Errorf("the options this connection did not apply were dropped from the report:\n%s", limits)
	}
	if routes := live.held.Routes; len(routes) != len(held.Routes) {
		t.Errorf("the stored networks were rewritten from what the server pushed: %v", routes)
	}
	if dns := live.held.DNS; len(dns) != 0 {
		t.Errorf("the stored resolvers were rewritten from what the server pushed: %v", dns)
	}
}

// Resolvers configured here are the user's answer to which resolver sees their names. A server
// that pushes its own does not get to replace it.
func TestConfiguredResolversAreNotReplacedByTheOnesAServerPushes(t *testing.T) {
	runner := &fakeOpenVPN{}
	runner.speak = answering(runner, func(hostnet.OpenVPNRun) string {
		return ">LOG:1699999999,I,PUSH: Received control message: 'PUSH_REPLY," +
			"dhcp-option DNS 103.86.96.100'\n" + connectedLine
	})

	held := heldFixture()
	held.DNS = []netip.Addr{netip.MustParseAddr("10.8.0.1")}
	live := newTunnel(t, held, CarryDefault, runner)
	if err := live.Start(context.Background()); err != nil {
		t.Fatalf("start the connection: %v", err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Errorf("close the connection: %v", err)
		}
	})

	status := waitForState(t, live, tunnel.StateConnected)

	live.mu.Lock()
	using := live.resolversLocked()
	live.mu.Unlock()
	if len(using) != 1 || using[0] != netip.MustParseAddr("10.8.0.1") {
		t.Errorf("the connection asks %v for names, want the resolver configured for it", using)
	}
	limits := strings.Join(status.Limits, "\n")
	if strings.Contains(limits, "handed out") {
		t.Errorf("a connection with its own resolvers reported using the server's:\n%s", limits)
	}
	if !strings.Contains(limits, "dhcp-option DNS 103.86.96.100") {
		t.Errorf("the resolver the server offered and this connection ignored was not reported:\n%s", limits)
	}
}
