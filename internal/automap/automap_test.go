// SPDX-License-Identifier: MIT

package automap

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// testTunnel is the connection every plan in this file is built for. Assignments are
// keyed by it, so a test naming one connection is what a test on a second connection's
// assignments contrasts with.
const testTunnel = "tn_primary"

// sequential is an allocator that hands out the preferred port and then counts upward,
// never repeating. It stands in for the agent's real one, which additionally checks the
// port is free to bind; what matters here is that a plan asks for distinct ports.
func sequential() Allocator {
	handed := make(map[int]bool)
	return func(preferred int) (int, error) {
		if preferred <= 0 {
			preferred = 1
		}
		for port := preferred; port <= 65535; port++ {
			if !handed[port] {
				handed[port] = true
				return port, nil
			}
		}
		return 0, errors.New("no free port")
	}
}

func peer(id, name string) tsnode.Peer {
	return tsnode.Peer{ID: id, HostName: name, DNSName: name + ".tail1a2b.ts.net", Online: true}
}

func params(peers []tsnode.Peer, ports []int, existing map[string]int) Params {
	return Params{
		TunnelID: testTunnel,
		Peers:    peers,
		Ports:    ports,
		Max:      config.DefaultAutoMapMax,
		PortBase: config.DefaultAutoMapPortBase,
		Existing: existing,
		Allocate: sequential(),
		BindAddr: config.DefaultBindAddr,
	}
}

// portsByTarget indexes a plan by what each forward reaches, so an assertion names the
// device rather than a position in a slice that reordering would invalidate.
func portsByTarget(plan Plan) map[string]int {
	out := make(map[string]int, len(plan.Forwards))
	for _, f := range plan.Forwards {
		out[f.Target] = f.ListenPort
	}
	return out
}

// The promise the whole package exists to keep: a local port assigned once stays put.
// Anything a user saved -- a bookmark, an ssh_config Host block, a shell alias -- names
// that number, and a port that moved would not merely stop working but would point at
// whichever device took it.
func TestAnAssignedPortSurvivesEverythingThatCouldMoveIt(t *testing.T) {
	first, err := Build(params([]tsnode.Peer{peer("nA", "alpha"), peer("nB", "beta")}, []int{22}, nil))
	if err != nil {
		t.Fatalf("first plan: %v", err)
	}
	before := portsByTarget(first)
	if len(before) != 2 {
		t.Fatalf("first plan mapped %d devices, want 2", len(before))
	}

	// The device list arrives in a different order, a device has gone offline and a
	// third has appeared -- none of which is a reason to renumber anything.
	shuffled := []tsnode.Peer{peer("nC", "gamma"), peer("nB", "beta"), peer("nA", "alpha")}
	shuffled[2].Online = false
	second, err := Build(params(shuffled, []int{22}, first.Allocations))
	if err != nil {
		t.Fatalf("second plan: %v", err)
	}

	after := portsByTarget(second)
	for target, port := range before {
		if after[target] != port {
			t.Errorf("%s moved from local port %d to %d", target, port, after[target])
		}
	}
	if len(after) != 3 {
		t.Errorf("second plan mapped %d devices, want the new one included for 3", len(after))
	}
}

// A plan that reused a number would leave one of the two devices with a listener that
// never binds -- and the failure would surface as "that device is unreachable", which
// is the wrong thing to go looking into.
func TestNoTwoMappingsShareALocalPort(t *testing.T) {
	peers := []tsnode.Peer{peer("nA", "alpha"), peer("nB", "beta"), peer("nC", "gamma")}
	plan, err := Build(params(peers, []int{22, 80}, nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Forwards) != 6 {
		t.Fatalf("mapped %d pairs, want 3 devices x 2 ports", len(plan.Forwards))
	}

	seen := make(map[int]string, len(plan.Forwards))
	for _, f := range plan.Forwards {
		if other, dup := seen[f.ListenPort]; dup {
			t.Errorf("local port %d serves both %s and %s", f.ListenPort, other, f.Target)
		}
		seen[f.ListenPort] = f.Target
	}
}

// An allocator that breaks its contract must not produce a plan. Two devices on one
// port is the outcome this package cannot let through quietly.
func TestAnAllocatorThatRepeatsAPortIsRefused(t *testing.T) {
	p := params([]tsnode.Peer{peer("nA", "alpha"), peer("nB", "beta")}, []int{22}, nil)
	p.Allocate = func(int) (int, error) { return 14000, nil }

	_, err := Build(p)
	if err == nil {
		t.Fatal("a plan was produced with both devices on the same local port")
	}
	if !strings.Contains(err.Error(), "already assigned") {
		t.Errorf("error %q does not say the port was already assigned", err)
	}
}

// Allocation reaches the configuration before anything binds, so the failure to write
// it has to stop the plan rather than produce ports that vanish on the next start.
func TestAnAllocationFailureFailsThePlanRatherThanMappingSome(t *testing.T) {
	p := params([]tsnode.Peer{peer("nA", "alpha"), peer("nB", "beta")}, []int{22}, nil)
	calls := 0
	p.Allocate = func(preferred int) (int, error) {
		calls++
		if calls > 1 {
			return 0, errors.New("no free local port")
		}
		return preferred, nil
	}

	plan, err := Build(p)
	if err == nil {
		t.Fatal("Build reported success after an allocation failed")
	}
	if len(plan.Forwards) != 0 || plan.Allocations != nil {
		t.Errorf("a failed plan carried %d forwards and %d allocations, want neither",
			len(plan.Forwards), len(plan.Allocations))
	}
}

// The limit is a resource bound, not a filter: devices past it are counted so the
// dashboard can say so. A device silently missing reads as the feature being broken.
func TestThePairsPastTheLimitAreCountedNotDropped(t *testing.T) {
	peers := make([]tsnode.Peer, 5)
	for i := range peers {
		peers[i] = peer(fmt.Sprintf("n%d", i), fmt.Sprintf("dev%d", i))
	}
	p := params(peers, []int{22, 80}, nil)
	p.Max = 3

	plan, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Forwards) != 3 {
		t.Errorf("mapped %d pairs, want the limit of 3", len(plan.Forwards))
	}
	if plan.Truncated != 7 {
		t.Errorf("Truncated = %d, want the 7 pairs the limit left out", plan.Truncated)
	}
}

// A plan that changed nothing must report no allocations, or the agent writes the
// configuration file on every reconcile -- which is a settings-changed event on every
// node notification, forever.
func TestAPlanThatAssignedNothingAsksForNoWrite(t *testing.T) {
	peers := []tsnode.Peer{peer("nA", "alpha")}
	first, err := Build(params(peers, []int{22}, nil))
	if err != nil {
		t.Fatalf("first plan: %v", err)
	}
	if first.Allocations == nil {
		t.Fatal("the first plan assigned a port but asked for no write")
	}

	second, err := Build(params(peers, []int{22}, first.Allocations))
	if err != nil {
		t.Fatalf("second plan: %v", err)
	}
	if second.Allocations != nil {
		t.Errorf("a plan that assigned nothing asked to write %d allocations", len(second.Allocations))
	}
	if len(second.Forwards) != 1 {
		t.Errorf("the second plan mapped %d devices, want the same 1", len(second.Forwards))
	}
}

// A device with nothing to dial would produce a forward that can only fail, and one
// with no identity could not be given a port that survives a restart. Both are skipped
// rather than mapped into something that looks working.
func TestADeviceThatCannotBeMappedIsSkipped(t *testing.T) {
	peers := []tsnode.Peer{
		{ID: "", HostName: "no-identity", DNSName: "no-identity.tail1a2b.ts.net"},
		{ID: "nB", HostName: "no-address"},
		peer("nC", "gamma"),
	}
	plan, err := Build(params(peers, []int{22}, nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Forwards) != 1 {
		t.Fatalf("mapped %d devices, want only the one that can be reached", len(plan.Forwards))
	}
	if got := plan.Forwards[0].Target; got != "gamma.tail1a2b.ts.net:22" {
		t.Errorf("mapped %q, want the device with both an identity and an address", got)
	}
}

// The MagicDNS name is preferred over the address so the mapping keeps working when the
// device's tailnet address changes; a device with only an address still gets mapped.
func TestAMappingDialsTheNameWhenThereIsOne(t *testing.T) {
	peers := []tsnode.Peer{
		{ID: "nA", HostName: "named", DNSName: "named.tail1a2b.ts.net", IPs: []string{"100.64.0.1"}},
		{ID: "nB", HostName: "unnamed", IPs: []string{"100.64.0.2"}},
	}
	plan, err := Build(params(peers, []int{22}, nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	targets := make([]string, 0, len(plan.Forwards))
	for _, f := range plan.Forwards {
		targets = append(targets, f.Target)
	}
	want := []string{"named.tail1a2b.ts.net:22", "100.64.0.2:22"}
	for i, w := range want {
		if i >= len(targets) || targets[i] != w {
			t.Errorf("targets = %v, want %v", targets, want)
			break
		}
	}
}

// The derived forwards go to the same engine as the configured ones, so they have to be
// shaped like one: loopback, TCP, enabled, and carrying the prefix that makes the API
// refuse edits to them.
func TestADerivedForwardIsShapedLikeOneTheEngineCanRun(t *testing.T) {
	plan, err := Build(params([]tsnode.Peer{peer("nA", "alpha")}, []int{22}, nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	f := plan.Forwards[0]

	if !strings.HasPrefix(f.ID, IDPrefix) {
		t.Errorf("id %q does not carry the prefix that marks it as derived", f.ID)
	}
	if f.Direction != config.ToLocal {
		t.Errorf("direction = %q, want %q", f.Direction, config.ToLocal)
	}
	if f.Protocol != config.TCP {
		t.Errorf("protocol = %q, want %q", f.Protocol, config.TCP)
	}
	if f.BindAddr != config.DefaultBindAddr {
		t.Errorf("bindAddr = %q, want loopback", f.BindAddr)
	}
	if !f.Enabled {
		t.Error("a derived forward arrived disabled, so it would never listen")
	}
	if f.Name == "" {
		t.Error("a derived forward has no name, so the dashboard row is unlabelled")
	}
}

// Turning the module off is expressed as an empty port list or a limit of zero, and
// both have to mean "nothing", not "everything".
func TestNothingIsMappedWithoutPortsOrAllowance(t *testing.T) {
	peers := []tsnode.Peer{peer("nA", "alpha")}
	for _, tc := range []struct {
		name string
		set  func(*Params)
	}{
		{"no ports", func(p *Params) { p.Ports = nil }},
		{"no allowance", func(p *Params) { p.Max = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := params(peers, []int{22}, nil)
			tc.set(&p)

			plan, err := Build(p)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if len(plan.Forwards) != 0 || plan.Allocations != nil {
				t.Errorf("mapped %d devices and assigned %d ports, want neither",
					len(plan.Forwards), len(plan.Allocations))
			}
		})
	}
}

// Forgetting is what stops the assignment map growing forever, but it must only drop
// devices the tailnet no longer reports: dropping a device that is merely offline would
// hand its port away and break whatever names it.
func TestForgettingKeepsEveryDeviceTheTailnetStillReports(t *testing.T) {
	existing := map[string]int{
		allocationKey(testTunnel, "nA", 22):    14000,
		allocationKey(testTunnel, "nA", 80):    14001,
		allocationKey(testTunnel, "nGone", 22): 14002,
	}
	offline := peer("nA", "alpha")
	offline.Online = false

	kept, removed := Prune(testTunnel, existing, []tsnode.Peer{offline})

	if removed != 1 {
		t.Errorf("removed %d assignments, want only the one whose device is gone", removed)
	}
	if len(kept) != 2 {
		t.Errorf("kept %d assignments, want both of the offline device's", len(kept))
	}
	if kept[allocationKey(testTunnel, "nA", 22)] != 14000 || kept[allocationKey(testTunnel, "nA", 80)] != 14001 {
		t.Errorf("an offline device's ports changed: %v", kept)
	}
}

// A device id is only unique within the network that issued it, so a peer list describes
// one connection and says nothing about any other. Pruning one connection against its own
// peers must leave every other connection's assignments exactly where they are -- and a
// device id that happens to be shared between two networks is precisely the case that
// would otherwise move a port on a network nobody asked about.
func TestPruningOneConnectionLeavesAnotherConnectionsPortsAlone(t *testing.T) {
	const other = "tn_office"
	existing := map[string]int{
		allocationKey(testTunnel, "nA", 22):    14000,
		allocationKey(testTunnel, "nGone", 22): 14001,
		allocationKey(other, "nA", 22):         14002,
		allocationKey(other, "nGone", 22):      14003,
	}

	kept, removed := Prune(testTunnel, existing, []tsnode.Peer{peer("nA", "alpha")})

	if removed != 1 {
		t.Errorf("removed %d assignments, want only the pruned connection's departed device", removed)
	}
	if kept[allocationKey(other, "nA", 22)] != 14002 || kept[allocationKey(other, "nGone", 22)] != 14003 {
		t.Errorf("pruning %q moved %q's ports: %v", testTunnel, other, kept)
	}
	if _, still := kept[allocationKey(testTunnel, "nGone", 22)]; still {
		t.Error("the pruned connection kept an assignment for a device it no longer reports")
	}
}

// A key written before assignments named a connection belongs to no connection, so
// pruning must not reach it: migration is what gives it an owner, and dropping it here
// would hand its local port away to whichever device asked next.
func TestPruningLeavesAKeyThatNamesNoConnectionAlone(t *testing.T) {
	existing := map[string]int{
		"nGone/22":                          14000,
		allocationKey(testTunnel, "nA", 22): 14001,
	}

	kept, removed := Prune(testTunnel, existing, []tsnode.Peer{peer("nA", "alpha")})

	if removed != 0 {
		t.Errorf("removed %d assignments, want none", removed)
	}
	if kept["nGone/22"] != 14000 {
		t.Errorf("an unowned assignment was dropped or moved: %v", kept)
	}
}

// The port list is where a typo lands, and a typo that mapped nothing would be
// indistinguishable from the module being off.
func TestPortListRejectsWhatIsNotAPort(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []string
		want  []int
	}{
		{"plain list", []string{"22", "8080"}, []int{22, 8080}},
		{"blanks and spacing", []string{" 22 ", "", "80"}, []int{22, 80}},
		{"duplicates collapse", []string{"22", "22"}, []int{22}},
		{"not a number", []string{"22", "ssh"}, nil},
		{"out of range", []string{"70000"}, nil},
		{"zero", []string{"0"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := config.ParsePortList(tc.input)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("%v was accepted as %v", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%v was rejected: %v", tc.input, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parsed %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parsed %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// The base is where allocation starts looking, not a floor it must land on: with every
// number from the base upwards already handed out, the device is still mapped -- from
// wherever the allocator can find a port -- rather than left out or handed the number
// another device is already listening on.
func TestADeviceIsStillMappedWhenNothingAtOrAboveTheBaseIsFree(t *testing.T) {
	p := params([]tsnode.Peer{peer("nA", "alpha")}, []int{22},
		map[string]int{"nOther/22": 65535})
	p.PortBase = 65535

	plan, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Forwards) != 1 {
		t.Fatalf("mapped %d devices, want the one device mapped anyway", len(plan.Forwards))
	}
	if got := plan.Forwards[0].ListenPort; got == 65535 || got <= 0 {
		t.Errorf("mapped to port %d, want a free port that is not the one already assigned", got)
	}
}

// A device somebody switched off keeps its row and its port, off. Dropping the forward
// instead would take the row off the screen with nothing left to switch back on, and
// releasing the port would hand it to another device -- which is exactly what this
// package's one promise forbids.
func TestAMappingSwitchedOffKeepsItsRowAndItsPort(t *testing.T) {
	on, err := Build(params([]tsnode.Peer{peer("nA", "alpha"), peer("nB", "beta")}, []int{22}, nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var offID string
	var offPort int
	for _, f := range on.Forwards {
		if strings.Contains(f.Target, "alpha") {
			offID, offPort = f.ID, f.ListenPort
		}
	}
	if offID == "" {
		t.Fatal("the plan mapped no device to switch off")
	}

	p := params([]tsnode.Peer{peer("nA", "alpha"), peer("nB", "beta")}, []int{22}, on.Allocations)
	p.Disabled = map[string]bool{offID: true}
	after, err := Build(p)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(after.Forwards) != len(on.Forwards) {
		t.Fatalf("plan holds %d forwards, want the same %d: a switched-off mapping keeps its row",
			len(after.Forwards), len(on.Forwards))
	}
	for _, f := range after.Forwards {
		switch f.ID {
		case offID:
			if f.Enabled {
				t.Error("the mapping switched off came back enabled")
			}
			if f.ListenPort != offPort {
				t.Errorf("listen port = %d, want %d kept: the port is still owed to that device",
					f.ListenPort, offPort)
			}
		default:
			if !f.Enabled {
				t.Errorf("%s was switched off too; only the one named should be", f.ID)
			}
		}
	}
}
