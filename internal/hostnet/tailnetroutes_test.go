// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// routingTable is a machine's answer to "where would you send this", plus a record of every route
// installed on it. Addresses it has no entry for are ones the machine has no route to at all,
// which is the state this whole file exists to notice.
type routingTable struct {
	sendsTo   map[netip.Addr]string
	installed []string
	addErr    error
}

func (t *routingTable) lookup(_ context.Context, addr netip.Addr) (string, bool, error) {
	iface, ok := t.sendsTo[addr]
	return iface, ok, nil
}

func (t *routingTable) add(_ context.Context, iface string, prefix netip.Prefix) error {
	if t.addErr != nil {
		return t.addErr
	}
	t.installed = append(t.installed, iface+" "+prefix.String())
	for _, probe := range rangeEnds(prefix) {
		t.sendsTo[probe] = iface
	}
	return nil
}

// routes builds a table already sending every address in the named ranges to iface.
func routes(iface string, prefixes ...netip.Prefix) *routingTable {
	t := &routingTable{sendsTo: map[netip.Addr]string{}}
	for _, prefix := range prefixes {
		for _, probe := range rangeEnds(prefix) {
			t.sendsTo[probe] = iface
		}
	}
	return t
}

// ops is the machine a test stands up: these interfaces, this routing table, a platform that can
// be asked.
func (t *routingTable) ops(adapters ...adapter) tailnetRouteOps {
	return tailnetRouteOps{
		supported: func() error { return nil },
		adapters:  func() []adapter { return adapters },
		lookup:    t.lookup,
		add:       t.add,
	}
}

var (
	v4Range = netip.MustParsePrefix("100.64.0.0/10")
	v6Range = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// The two addresses each range is checked at. They are the whole reason a client that installs a
// route per peer cannot make a missing range look present: get the second one wrong and the check
// answers from whichever peer happens to sit at the address it does ask about.
func TestWhereTheRangeCheckLooks(t *testing.T) {
	tests := []struct {
		prefix netip.Prefix
		want   [2]string
	}{
		{v4Range, [2]string{"100.64.0.1", "100.127.255.255"}},
		{v6Range, [2]string{"fd7a:115c:a1e0::1", "fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff"}},
		// A prefix given unmasked still names its own range, not the address inside it.
		{netip.MustParsePrefix("100.96.3.7/10"), [2]string{"100.64.0.1", "100.127.255.255"}},
	}
	for _, tt := range tests {
		t.Run(tt.prefix.String(), func(t *testing.T) {
			ends := rangeEnds(tt.prefix)
			got := [2]string{ends[0].String(), ends[1].String()}
			if got != tt.want {
				t.Errorf("rangeEnds(%s) = %v, want %v", tt.prefix, got, tt.want)
			}
			for _, end := range ends {
				if !tt.prefix.Contains(end) {
					t.Errorf("%s is outside %s, so asking about it says nothing about the range",
						end, tt.prefix)
				}
			}
		})
	}
}

// Which interface counts as the one carrying the tailnet, and which of the tailnet's ranges it is
// treated as holding. A family the interface has no address in must not be reported: a route for
// it would point at an interface with nothing to send from.
func TestWhichInterfaceIsCarryingTheTailnet(t *testing.T) {
	down := func(name string, addrs ...string) adapter {
		a := holding(name, addrs...)
		a.up = false
		return a
	}
	tests := []struct {
		name        string
		adapters    []adapter
		own         string
		wantIface   string
		wantCarried []netip.Prefix
	}{
		{
			name:        "one family only",
			adapters:    []adapter{holding("en0", "192.168.1.5"), holding("utun5", "100.111.108.19")},
			wantIface:   "utun5",
			wantCarried: []netip.Prefix{v4Range},
		},
		{
			name:        "both families",
			adapters:    []adapter{holding("utun5", "100.111.108.19", "fd7a:115c:a1e0::1a01")},
			wantIface:   "utun5",
			wantCarried: []netip.Prefix{v4Range, v6Range},
		},
		{
			name:     "an interface that is down carries nothing",
			adapters: []adapter{down("utun5", "100.111.108.19")},
		},
		{
			name:     "app-tail's own interface is not somebody else's tailnet",
			adapters: []adapter{holding("utun5", "100.111.108.19")},
			own:      "utun5",
		},
		{
			name:     "no tailnet on this machine at all",
			adapters: []adapter{holding("en0", "192.168.1.5"), holding("utun6", "10.8.0.2")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, carried, ok := tailnetCarrier(tt.adapters, tt.own)
			if ok != (tt.wantIface != "") {
				t.Fatalf("found = %v, want %v (interface %q)", ok, tt.wantIface != "", tt.wantIface)
			}
			if iface != tt.wantIface {
				t.Errorf("interface = %q, want %q", iface, tt.wantIface)
			}
			if !slices.Equal(carried, tt.wantCarried) {
				t.Errorf("carried = %v, want %v", carried, tt.wantCarried)
			}
		})
	}
}

// Reading the machine: a tailnet it can reach, a tailnet it cannot, and the difference between
// "nothing is wrong" and "there is nothing here". Broken() must be false for the second, since a
// machine with no tailnet is missing nothing.
func TestReadingWhereThisMachineSendsTailnetTraffic(t *testing.T) {
	carrier := holding("utun5", "100.111.108.19", "fd7a:115c:a1e0::1a01")
	tests := []struct {
		name         string
		adapters     []adapter
		table        *routingTable
		wantIface    string
		wantUnrouted []netip.Prefix
		wantBroken   bool
	}{
		{
			name:      "every range routed to the interface holding it",
			adapters:  []adapter{carrier},
			table:     routes("utun5", v4Range, v6Range),
			wantIface: "utun5",
		},
		{
			name:         "both ranges gone, which is what the user hit",
			adapters:     []adapter{carrier},
			table:        routes("utun5"),
			wantIface:    "utun5",
			wantUnrouted: []netip.Prefix{v4Range, v6Range},
			wantBroken:   true,
		},
		{
			name:         "one family gone and the other still there",
			adapters:     []adapter{carrier},
			table:        routes("utun5", v6Range),
			wantIface:    "utun5",
			wantUnrouted: []netip.Prefix{v4Range},
			wantBroken:   true,
		},
		{
			name:     "no tailnet on this machine is not a fault",
			adapters: []adapter{holding("en0", "192.168.1.5")},
			table:    routes("utun5"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routing, err := readTailnetRouting(t.Context(), tt.table.ops(tt.adapters...), "")
			if err != nil {
				t.Fatalf("readTailnetRouting: %v", err)
			}
			if routing.Interface != tt.wantIface {
				t.Errorf("interface = %q, want %q", routing.Interface, tt.wantIface)
			}
			if !slices.Equal(routing.Unrouted, tt.wantUnrouted) {
				t.Errorf("unrouted = %v, want %v", routing.Unrouted, tt.wantUnrouted)
			}
			if routing.Broken() != tt.wantBroken {
				t.Errorf("Broken() = %v, want %v", routing.Broken(), tt.wantBroken)
			}
		})
	}
}

// A range the machine sends to the wrong interface is as unreachable as one it has no route for,
// and a route covering only one end of the range does not cover the range.
func TestARangeCountsAsMissingUnlessTheWholeOfItGoesToTheInterface(t *testing.T) {
	carrier := holding("utun5", "100.111.108.19")
	tests := []struct {
		name  string
		table *routingTable
	}{
		{
			name: "sent to the physical interface instead",
			table: &routingTable{sendsTo: map[netip.Addr]string{
				rangeEnds(v4Range)[0]: "en0",
				rangeEnds(v4Range)[1]: "en0",
			}},
		},
		{
			name: "a route for one peer rather than for the range",
			table: &routingTable{sendsTo: map[netip.Addr]string{
				rangeEnds(v4Range)[0]: "utun5",
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routing, err := readTailnetRouting(t.Context(), tt.table.ops(carrier), "")
			if err != nil {
				t.Fatalf("readTailnetRouting: %v", err)
			}
			if !routing.Broken() {
				t.Fatalf("machine reported reachable with unrouted = %v", routing.Unrouted)
			}
		})
	}
}

// A platform that cannot be asked reports itself, rather than reporting a machine with nothing
// wrong. The difference decides whether the caller stops asking or goes on believing an
// unreachable tailnet is fine.
func TestAPlatformThatCannotBeAskedSaysSo(t *testing.T) {
	ops := tailnetRouteOps{
		supported: func() error { return ErrTailnetRoutesUnsupported },
		adapters:  func() []adapter { t.Fatal("the machine was read on a platform that cannot be asked"); return nil },
	}
	routing, err := readTailnetRouting(t.Context(), ops, "")
	if !errors.Is(err, ErrTailnetRoutesUnsupported) {
		t.Fatalf("err = %v, want %v", err, ErrTailnetRoutesUnsupported)
	}
	if routing.Broken() {
		t.Error("a platform that cannot be asked reported a broken tailnet")
	}
}

// A machine that will not answer where it sends traffic is a failure, not a healthy machine. A
// caller told "nothing is unrouted" would take a routing tool that is refusing for a tailnet that
// is reachable.
func TestAMachineThatWillNotAnswerIsAFailure(t *testing.T) {
	refused := errors.New("route: writing to routing socket: No such process")
	ops := tailnetRouteOps{
		supported: func() error { return nil },
		adapters:  func() []adapter { return []adapter{holding("utun5", "100.111.108.19")} },
		lookup: func(context.Context, netip.Addr) (string, bool, error) {
			return "", false, refused
		},
	}
	if _, err := readTailnetRouting(t.Context(), ops, ""); !errors.Is(err, refused) {
		t.Fatalf("err = %v, want it to carry %v", err, refused)
	}
}

// repairing stands up a privileged side over one machine.
func repairing(table *routingTable, driving string, adapters ...adapter) *Local {
	local := NewLocal(func(string, ...any) {})
	local.tunName = driving
	local.tailnetRoutes = table.ops(adapters...)
	return local
}

// Every reason the privileged side refuses. These are what keep the operation to "send the
// tailnet's traffic to the interface already carrying the tailnet": drop any of them and a caller
// that can reach the helper can put a route on an interface of its choosing.
func TestTheRepairRefusesAnythingButTheInterfaceCarryingTheTailnet(t *testing.T) {
	carrier := holding("utun5", "100.111.108.19")
	tests := []struct {
		name    string
		iface   string
		driving string
		want    string
	}{
		{
			name:  "the physical interface, which is what an attacker would name",
			iface: "en0",
			want:  "not carrying a tailnet",
		},
		{
			name:  "an interface that does not exist",
			iface: "utun9",
			want:  "not carrying a tailnet",
		},
		{
			name:  "a name that is not an interface name",
			iface: "utun5 en0",
			want:  "not a network interface name",
		},
		{
			name:  "no interface at all",
			iface: "",
			want:  "no network interface was given",
		},
		{
			name:  "a name over the length an interface name has",
			iface: strings.Repeat("u", maxInterfaceName+1),
			want:  "over the",
		},
		{
			// app-tail's own engine installs the routes on the interface it opened. A repair here
			// would be a second writer for routes that already have one.
			name:    "the interface app-tail opened itself",
			iface:   "utun5",
			driving: "utun5",
			want:    "the interface app-tail opened",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := routes("utun5")
			local := repairing(table, tt.driving, carrier)
			installed, err := local.RepairTailnetRoutes(t.Context(), tt.iface)
			if err == nil {
				t.Fatalf("the repair went ahead, installing %v", installed)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to mention %q", err, tt.want)
			}
			if len(table.installed) > 0 {
				t.Errorf("a refused repair still changed the machine: %v", table.installed)
			}
		})
	}
}

// The repair installs the ranges the machine is missing and leaves alone the ones it already has.
// Re-adding a route that is already there would make this a second writer for it.
func TestTheRepairInstallsOnlyWhatIsMissing(t *testing.T) {
	carrier := holding("utun5", "100.111.108.19", "fd7a:115c:a1e0::1a01")
	table := routes("utun5", v6Range)
	local := repairing(table, "", carrier)

	installed, err := local.RepairTailnetRoutes(t.Context(), "utun5")
	if err != nil {
		t.Fatalf("RepairTailnetRoutes: %v", err)
	}
	if !slices.Equal(installed, []netip.Prefix{v4Range}) {
		t.Errorf("installed = %v, want %v", installed, []netip.Prefix{v4Range})
	}
	if want := []string{"utun5 " + v4Range.String()}; !slices.Equal(table.installed, want) {
		t.Errorf("the machine was changed as %v, want %v", table.installed, want)
	}

	// A second round over a machine now routing everything must do nothing at all.
	again, err := local.RepairTailnetRoutes(t.Context(), "utun5")
	if err != nil {
		t.Fatalf("second RepairTailnetRoutes: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("a repair of an already-routed machine installed %v", again)
	}
}

// A range the interface holds no address in is not one the machine is missing. Installing it
// would put a route on an interface with nothing to send from.
func TestTheRepairLeavesAloneAFamilyTheInterfaceDoesNotCarry(t *testing.T) {
	table := routes("utun5")
	local := repairing(table, "", holding("utun5", "100.111.108.19"))

	installed, err := local.RepairTailnetRoutes(t.Context(), "utun5")
	if err != nil {
		t.Fatalf("RepairTailnetRoutes: %v", err)
	}
	if !slices.Equal(installed, []netip.Prefix{v4Range}) {
		t.Errorf("installed = %v, want only %v", installed, []netip.Prefix{v4Range})
	}
}

// A routing tool that refuses is reported rather than swallowed, and nothing is claimed as
// installed. A caller told the repair succeeded would stop reporting a tailnet still unreachable.
func TestARoutingToolThatRefusesIsReported(t *testing.T) {
	refused := errors.New("route: not in table")
	table := routes("utun5")
	table.addErr = refused
	local := repairing(table, "", holding("utun5", "100.111.108.19", "fd7a:115c:a1e0::1a01"))

	installed, err := local.RepairTailnetRoutes(t.Context(), "utun5")
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v, want it to carry %v", err, refused)
	}
	if len(installed) != 0 {
		t.Errorf("a repair that installed nothing reported %v", installed)
	}
}

// A machine that will not say where it sends one range is reported, and the other range is still
// put back. Giving up on the first refusal would leave a family unrouted over a fault in the
// other one.
func TestARangeTheMachineWillNotAnswerAboutIsReportedAndTheOthersAreStillDone(t *testing.T) {
	refused := errors.New("route: writing to routing socket: No such process")
	table := routes("utun5")
	local := repairing(table, "", holding("utun5", "100.111.108.19", "fd7a:115c:a1e0::1a01"))
	local.tailnetRoutes.lookup = func(_ context.Context, addr netip.Addr) (string, bool, error) {
		if v6Range.Contains(addr) {
			return "", false, refused
		}
		return table.lookup(context.Background(), addr)
	}

	installed, err := local.RepairTailnetRoutes(t.Context(), "utun5")
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v, want it to carry %v", err, refused)
	}
	if !slices.Equal(installed, []netip.Prefix{v4Range}) {
		t.Errorf("installed = %v, want %v -- the range that could be read was left undone",
			installed, []netip.Prefix{v4Range})
	}
}

// A platform that cannot repair refuses before it reads anything, so a build without a repair
// cannot half-run one.
func TestTheRepairRefusesOnAPlatformThatCannotDoIt(t *testing.T) {
	local := NewLocal(func(string, ...any) {})
	local.tailnetRoutes = tailnetRouteOps{
		supported: func() error { return ErrTailnetRoutesUnsupported },
		adapters:  func() []adapter { t.Fatal("the machine was read on a platform that cannot repair"); return nil },
	}
	if _, err := local.RepairTailnetRoutes(t.Context(), "utun5"); !errors.Is(err, ErrTailnetRoutesUnsupported) {
		t.Fatalf("err = %v, want %v", err, ErrTailnetRoutesUnsupported)
	}
}
