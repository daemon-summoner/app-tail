// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/wgengine/router"
)

// Validate is the whole of what stands between an unprivileged caller and a privileged
// change to this machine's routing table, so each refusal is stated as the thing that would
// break rather than as a rule number.
func TestAddressingTheMachineCannotGiveAwayIsRefused(t *testing.T) {
	tests := []struct {
		name   string
		routes Routes
		says   string
	}{
		{
			name:   "carrying nothing is how everything is taken back off",
			routes: Routes{},
		},
		{
			name: "an interface address and the ranges it carries are accepted",
			routes: Routes{
				LocalAddrs:  []netip.Prefix{netip.MustParsePrefix("198.18.0.0/32")},
				Routes:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
				LocalRoutes: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
				MTU:         1380,
			},
		},
		{
			name:   "a range that is not one",
			routes: Routes{Routes: []netip.Prefix{{}}},
			says:   "is not an address range",
		},
		{
			name:   "an invalid range among the exclusions is caught too",
			routes: Routes{LocalRoutes: []netip.Prefix{{}}},
			says:   "is not an address range",
		},
		{
			name:   "loopback, which is how every program here reaches itself",
			routes: Routes{Routes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}},
			says:   "reaches itself",
		},
		{
			name:   "loopback as the interface's own address",
			routes: Routes{LocalAddrs: []netip.Prefix{netip.MustParsePrefix("::1/128")}},
			says:   "reaches itself",
		},
		{
			name:   "link-local unicast, which names a different machine on every network",
			routes: Routes{Routes: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}},
			says:   "different machine on every network",
		},
		{
			name:   "link-local multicast",
			routes: Routes{Routes: []netip.Prefix{netip.MustParsePrefix("ff02::/16")}},
			says:   "different machine on every network",
		},
		{
			name:   "multicast, which this interface cannot deliver",
			routes: Routes{Routes: []netip.Prefix{netip.MustParsePrefix("239.0.0.0/8")}},
			says:   "multicast",
		},
		{
			name:   "a packet size below what IPv6 requires a link to carry",
			routes: Routes{MTU: minMTU - 1},
			says:   "outside the",
		},
		{
			name:   "a packet size past any real link",
			routes: Routes{MTU: maxMTU + 1},
			says:   "outside the",
		},
		{
			name:   "a negative packet size",
			routes: Routes{MTU: -1500},
			says:   "outside the",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.routes.Validate()
			if tt.says == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want it accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() accepted addressing the privileged side must not install")
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("Validate() said %q, which does not say %q -- the caller cannot tell what it did wrong", err, tt.says)
			}
		})
	}
}

// An exclusion is the opposite of a route: it names a range that must keep leaving through
// the machine's own network, so the ranges that may not be sent to an interface are exactly
// the ones it is for. Refusing them here would leave a tunnel whose server is on a link-local
// or multicast address with no way to say so.
func TestARangeKeptOffTheInterfaceIsNotJudgedAsOneSentToIt(t *testing.T) {
	kept := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("169.254.1.1/32"),
		netip.MustParsePrefix("224.0.0.251/32"),
	}
	for _, prefix := range kept {
		r := Routes{LocalRoutes: []netip.Prefix{prefix}}
		if err := r.Validate(); err != nil {
			t.Errorf("keeping %s off the interface was refused: %v", prefix, err)
		}
		// The same range sent to the interface is the refusal this one is not.
		if err := (Routes{Routes: []netip.Prefix{prefix}}).Validate(); err == nil {
			t.Errorf("sending %s to the interface was accepted, so the two directions are not being told apart", prefix)
		}
	}
}

// recordingRouter stands in for the platform's routing table, which needs root and a live
// interface. What it records is the configuration the privileged side handed the OS, which
// is the last thing that happens before the machine's routes actually move.
type recordingRouter struct {
	got  *router.Config
	sets int
	err  error
}

func (r *recordingRouter) Up() error { return nil }
func (r *recordingRouter) Set(cfg *router.Config) error {
	r.sets++
	r.got = cfg
	return r.err
}
func (r *recordingRouter) Close() error { return nil }

// The narrow shape crossing the privilege boundary is turned into the engine's own
// configuration here, on the privileged side. The fields an unprivileged caller may not set
// -- the firewall and netfilter ones this app has no business touching -- have to come out
// unset, or the boundary is narrow in name only.
func TestOnlyTheRangesAndPacketSizeCrossIntoTheMachinesRoutingTable(t *testing.T) {
	recorder := &recordingRouter{}
	local := &Local{router: recorder}

	err := local.SetHostRoutes(context.Background(), Routes{
		LocalAddrs:  []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")},
		Routes:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		LocalRoutes: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
		MTU:         1380,
	})
	if err != nil {
		t.Fatalf("SetHostRoutes: %v", err)
	}

	got := recorder.got
	if got == nil {
		t.Fatal("nothing reached the machine's routing table")
	}
	if len(got.Routes) != 1 || got.Routes[0].String() != "10.0.0.0/8" {
		t.Errorf("the machine was told to send %v to the interface, want 10.0.0.0/8", got.Routes)
	}
	if len(got.LocalRoutes) != 1 || got.LocalRoutes[0].String() != "203.0.113.7/32" {
		t.Errorf("the ranges kept off the interface are %v, want the connection's own server",
			got.LocalRoutes)
	}
	if got.NewMTU != 1380 {
		t.Errorf("the interface was sized %d, want 1380", got.NewMTU)
	}
	if got.SubnetRoutes != nil || got.SNATSubnetRoutes || got.StatefulFiltering {
		t.Errorf("the unprivileged caller reached fields it may not set: %+v", got)
	}
}

// Addressing this side refuses must not reach the machine at all. Validating and then
// installing anyway would make the refusal a log line rather than a boundary.
func TestAddressingThePrivilegedSideRefusesNeverReachesTheMachine(t *testing.T) {
	recorder := &recordingRouter{}
	local := &Local{router: recorder}

	err := local.SetHostRoutes(context.Background(), Routes{
		Routes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})

	if err == nil {
		t.Fatal("the machine was told to send its own loopback into the interface")
	}
	if recorder.sets != 0 {
		t.Errorf("the routing table was written %d times despite the refusal", recorder.sets)
	}
}

// Routing with no interface open is a caller asking for addressing on something that is not
// there. It has to say so rather than write into a nil router, which is a crash on the
// privileged side of the boundary.
func TestRoutingWithNoInterfaceOpenSaysSoRatherThanFaulting(t *testing.T) {
	local := &Local{}

	err := local.SetHostRoutes(context.Background(), Routes{
		Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})

	if err == nil {
		t.Fatal("addressing was installed with no interface open")
	}
	if !strings.Contains(err.Error(), "no interface is open") {
		t.Errorf("error = %v, want it to say there is nothing to route", err)
	}
}

// A caller that gave up before the write must not have it land anyway: the shutdown path
// cancels its context, and a routing change arriving after it would leave this machine's
// routes pointing at an interface the process no longer owns.
func TestAddressingAskedForByACallerThatGaveUpIsNotInstalled(t *testing.T) {
	recorder := &recordingRouter{}
	local := &Local{router: recorder}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := local.SetHostRoutes(ctx, Routes{Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})

	if err == nil {
		t.Fatal("addressing from a cancelled caller was installed")
	}
	if recorder.sets != 0 {
		t.Errorf("the routing table was written %d times for a caller that gave up", recorder.sets)
	}
}

// The platform refusing the change is reported rather than swallowed. A machine whose routes
// did not move while this app believes they did is the state nothing on screen can explain.
func TestTheMachineRefusingTheChangeIsReported(t *testing.T) {
	recorder := &recordingRouter{err: errors.New("the interface is not up")}
	local := &Local{router: recorder}

	err := local.SetHostRoutes(context.Background(),
		Routes{Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})

	if err == nil {
		t.Fatal("the machine refused the change and it was reported as installed")
	}
	if !strings.Contains(err.Error(), "the interface is not up") {
		t.Errorf("error = %v, want the reason the machine gave", err)
	}
}

// A machine already has a default route, and a routing table holds one route per
// destination: asking for a second default is refused, on macOS quietly enough that the
// interface ends up carrying nothing while everything above it reports success. The two
// halves are two different destinations, and each is more specific than the default it sits
// beside, so both are accepted and both win.
func TestCarryingEverythingIsInstalledAsTwoHalvesRatherThanASecondDefaultRoute(t *testing.T) {
	got, err := Routes{Routes: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}}.Installed()
	if err != nil {
		t.Fatalf("work out what to install: %v", err)
	}

	want := []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.0.0.0/8"}
	if names := prefixNames(got); !slices.Equal(names, want) {
		t.Errorf("the machine is told to send %v to the interface, want %v", names, want)
	}
	for _, prefix := range got {
		if prefix.Bits() == 0 {
			t.Errorf("%s is a second default route, which the machine will not take", prefix)
		}
	}
}

// The ranges that must keep leaving through the machine's own network are cut out of what
// the interface carries. Without the cut, a connection carrying every address carries its
// own encrypted packets straight back into the interface that produced them, and the machine
// loses every network it has.
func TestTheRangesThatMustKeepLeavingTheOtherWayAreCutOutOfWhatTheInterfaceCarries(t *testing.T) {
	server := netip.MustParsePrefix("203.0.113.7/32")
	got, err := Routes{
		Routes:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		LocalRoutes: []netip.Prefix{server},
	}.Installed()
	if err != nil {
		t.Fatalf("work out what to install: %v", err)
	}

	for _, prefix := range got {
		if prefix.Overlaps(server) {
			t.Fatalf("%s still sends this connection's own server into the interface", prefix)
		}
	}
	// Everything else is still carried: the hole is one address, not a whole half.
	var covered bool
	for _, prefix := range got {
		if prefix.Contains(netip.MustParseAddr("203.0.113.8")) {
			covered = true
		}
	}
	if !covered {
		t.Errorf("cutting one address out took its neighbours with it: %v", prefixNames(got))
	}
}

// An exclusion in the other family is not an exclusion at all. Cutting it out of both would
// leave IPv4 traffic taking a hole punched for an IPv6 server.
func TestAnExclusionOnlyCutsTheFamilyItBelongsTo(t *testing.T) {
	got, err := Routes{
		Routes:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		LocalRoutes: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")},
	}.Installed()
	if err != nil {
		t.Fatalf("work out what to install: %v", err)
	}
	if names := prefixNames(got); !slices.Equal(names, []string{"0.0.0.0/1", "128.0.0.0/1"}) {
		t.Errorf("an IPv6 exclusion changed the IPv4 ranges: %v", names)
	}
}

// The whole point of the split is that it reaches the machine. A caller asking to carry
// everything and finding a default route in the configuration would be back where it started.
func TestCarryingEverythingReachesTheMachineAsHalves(t *testing.T) {
	recorder := &recordingRouter{}
	local := &Local{router: recorder}

	err := local.SetHostRoutes(context.Background(), Routes{
		LocalAddrs:  []netip.Prefix{netip.MustParsePrefix("198.18.0.0/32")},
		Routes:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		LocalRoutes: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
		MTU:         1280,
	})
	if err != nil {
		t.Fatalf("SetHostRoutes: %v", err)
	}
	for _, prefix := range recorder.got.Routes {
		if prefix.Bits() == 0 {
			t.Fatalf("the machine was asked for a second default route: %v", recorder.got.Routes)
		}
		if prefix.Contains(netip.MustParseAddr("203.0.113.7")) {
			t.Fatalf("%s sends this connection's own server into the interface", prefix)
		}
	}
	// The exclusion is still stated outright as well, for the systems that have a way to
	// take it.
	if len(recorder.got.LocalRoutes) != 1 {
		t.Errorf("the ranges kept off the interface are %v, want the connection's own server",
			recorder.got.LocalRoutes)
	}
}

func prefixNames(in []netip.Prefix) []string {
	out := make([]string, 0, len(in))
	for _, prefix := range in {
		out = append(out, prefix.String())
	}
	return out
}

// The engine's own configuration is wider than Routes, and every extra field in it decides
// something a root process then does: which subnets this node advertises, and on Linux which
// firewall binary the privileged side drives. All of it arrives as JSON from an unprivileged
// caller, so all of it is checked here.
func TestTheEngineConfigurationThePrivilegedSideInstallsIsChecked(t *testing.T) {
	tests := []struct {
		name string
		cfg  *router.Config
		says string
	}{
		{
			name: "nothing at all, which is how the engine takes its addressing back off",
			cfg:  nil,
		},
		{
			name: "the shape the engine actually sends",
			cfg: &router.Config{
				LocalAddrs:   []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")},
				Routes:       []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				LocalRoutes:  []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
				SubnetRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.9.0/24")},
				NewMTU:       1280,
			},
		},
		{
			name: "loopback, which is how every program here reaches itself",
			cfg:  &router.Config{Routes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}},
			says: "reaches itself",
		},
		{
			name: "a link-local address as the interface's own",
			cfg:  &router.Config{LocalAddrs: []netip.Prefix{netip.MustParsePrefix("169.254.9.9/32")}},
			says: "different machine on every network",
		},
		{
			name: "a packet size no link carries",
			cfg:  &router.Config{NewMTU: maxMTU + 1},
			says: "outside the",
		},
		{
			name: "an advertised subnet that is not an address range",
			cfg:  &router.Config{SubnetRoutes: []netip.Prefix{{}}},
			says: "is not an address range",
		},
		{
			name: "a firewall mode outside the three the engine defines",
			cfg:  &router.Config{NetfilterMode: 47},
			says: "not a firewall mode",
		},
		{
			name: "a firewall named by the caller, which reaches a root command lookup",
			cfg:  &router.Config{NetfilterKind: "nft; curl example.com"},
			says: "not a firewall this app knows how to drive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouterConfig(tt.cfg)
			if tt.says == "" {
				if err != nil {
					t.Fatalf("validateRouterConfig() = %v, want it accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatal("validateRouterConfig() accepted a configuration the privileged side must not install")
			}
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("validateRouterConfig() said %q, which does not say %q", err, tt.says)
			}
		})
	}
}
