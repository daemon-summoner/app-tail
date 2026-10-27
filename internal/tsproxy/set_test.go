// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"golang.org/x/net/proxy"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
)

// newSet builds a set over the stand-in network with every connection up, which is the state
// a reconcile is normally asked to run in.
func newSet(t *testing.T, hub *fakeNetwork) *Set {
	t.Helper()
	set := NewSet(Options{Network: hub, Logger: quietLogger(), DialDirect: hub.dialDirect})
	t.Cleanup(set.Close)
	set.SetNetworksUp(true)
	return set
}

// heldInstance is one stored instance asking for whichever port is free, because a fixed one
// makes the suite fail when a developer happens to be running something on it.
func heldInstance(id, slug, name string, rules []access.Rule) config.ProxyInstance {
	held := config.NewProxyInstance(id, slug, name, "127.0.0.1:0")
	held.Rules = rules
	return held
}

// mustApplySet reconciles and fails the test if anything refused to bind.
func mustApplySet(t *testing.T, set *Set, want ...config.ProxyInstance) {
	t.Helper()
	if err := set.Apply(want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// boundAddr is where one instance is listening, and a failure when it is not.
func boundAddr(t *testing.T, set *Set, id string) string {
	t.Helper()
	inst, running := set.Get(id)
	if !running {
		t.Fatalf("instance %q is not running after a successful apply", id)
	}
	if addr := inst.Addr(); addr != "" {
		return addr
	}
	t.Fatalf("instance %q is running but bound nothing", id)
	return ""
}

// dialThrough reaches address through one bound instance, returning the refusal rather than
// ending the test: on these paths a refusal is what is being proven.
func dialThrough(t *testing.T, proxyAddr, address string) error {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build a SOCKS5 client: %v", err)
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// onePortOnOneHost is the narrowest useful grant and the one the whole access layer exists
// for: one address, one port, one connection.
func onePortOnOneHost(addr netip.AddrPort) []access.Rule {
	return []access.Rule{{
		ID: "ar_service", Action: access.Allow, Tunnel: officeTunnel,
		CIDR:  netip.PrefixFrom(addr.Addr(), addr.Addr().BitLen()),
		Ports: []string{strconv.Itoa(int(addr.Port()))},
	}}
}

// The claim the access layer is built to make: an instance granted one port on one address
// over one connection reaches that and nothing else.
//
// Both stand-ins sit on the loopback address, so the grant's prefix covers both and the port
// is the only thing separating them -- which is what makes the refusal below a statement
// about the port condition rather than about the address. A port range read one off, or a
// rule matched against the name asked for instead of the address dialled, fails here.
func TestAnInstanceGrantedOnePortReachesNothingOnAnyOther(t *testing.T) {
	hub := newFakeNetwork(t)
	granted := hub.routeLiteral(t)
	neighbour := hub.routeLiteral(t)
	if granted.Addr() != neighbour.Addr() || granted.Port() == neighbour.Port() {
		t.Fatalf("the stand-ins are %s and %s; this proves nothing unless they differ only by port",
			granted, neighbour)
	}
	set := newSet(t, hub)
	held := heldInstance("px_aaaaaa", "db", "psql", onePortOnOneHost(granted))
	mustApplySet(t, set, held)
	at := boundAddr(t, set, held.ID)

	if err := dialThrough(t, at, granted.String()); err != nil {
		t.Fatalf("the granted destination was refused: %v", err)
	}
	if err := dialThrough(t, at, neighbour.String()); err == nil {
		t.Errorf("%s was carried, which is a port the grant does not name", neighbour)
	}
}

// Two instances on two ports with different rule sets, each refusing what the other allows.
// One rule list reaching the wrong listener -- a set that shared configuration between
// instances, or a decision made against the set rather than the instance -- shows up here.
func TestTwoInstancesEachRefuseTheOthersGrant(t *testing.T) {
	hub := newFakeNetwork(t)
	db := hub.routeLiteral(t)
	shell := hub.routeLiteral(t)
	set := newSet(t, hub)
	dbProxy := heldInstance("px_aaaaaa", "db", "psql", onePortOnOneHost(db))
	shellProxy := heldInstance("px_bbbbbb", "shell", "ssh", onePortOnOneHost(shell))
	mustApplySet(t, set, dbProxy, shellProxy)

	dbAt, shellAt := boundAddr(t, set, dbProxy.ID), boundAddr(t, set, shellProxy.ID)
	if dbAt == shellAt {
		t.Fatalf("both instances bound %s, so neither check below proves anything", dbAt)
	}

	if err := dialThrough(t, dbAt, db.String()); err != nil {
		t.Errorf("the database proxy refused its own grant: %v", err)
	}
	if err := dialThrough(t, shellAt, shell.String()); err != nil {
		t.Errorf("the shell proxy refused its own grant: %v", err)
	}
	if err := dialThrough(t, dbAt, shell.String()); err == nil {
		t.Error("the database proxy carried what only the shell proxy was granted")
	}
	if err := dialThrough(t, shellAt, db.String()); err == nil {
		t.Error("the shell proxy carried what only the database proxy was granted")
	}
}

// Adding an instance must not disturb the ones already listening. A reconcile that rebuilt
// the whole set would move every other instance's port, breaking every browser setting and
// ssh_config naming one -- and the only symptom would be programs that stopped connecting.
func TestAddingAnInstanceLeavesTheOthersBoundWhereTheyWere(t *testing.T) {
	hub := newFakeNetwork(t)
	set := newSet(t, hub)
	first := heldInstance("px_aaaaaa", "db", "psql", reachTheConnection())
	mustApplySet(t, set, first)
	inst, _ := set.Get(first.ID)
	before := boundAddr(t, set, first.ID)

	second := heldInstance("px_bbbbbb", "shell", "ssh", reachTheConnection())
	mustApplySet(t, set, first, second)

	if after := boundAddr(t, set, first.ID); after != before {
		t.Errorf("the instance that was already running moved from %s to %s", before, after)
	}
	if now, _ := set.Get(first.ID); now != inst {
		t.Error("the instance that was already running was rebuilt rather than left alone")
	}
	if boundAddr(t, set, second.ID) == before {
		t.Error("the added instance bound the address the first one is on")
	}
}

// Removing one stops it and leaves the rest alone. An instance dropped from the document but
// left bound would go on carrying whatever it was granted with nothing on screen saying it
// exists.
func TestRemovingAnInstanceStopsOnlyThatOne(t *testing.T) {
	hub := newFakeNetwork(t)
	set := newSet(t, hub)
	first := heldInstance("px_aaaaaa", "db", "psql", reachTheConnection())
	second := heldInstance("px_bbbbbb", "shell", "ssh", reachTheConnection())
	mustApplySet(t, set, first, second)
	goneAt, keptAt := boundAddr(t, set, first.ID), boundAddr(t, set, second.ID)

	mustApplySet(t, set, second)

	if _, running := set.Get(first.ID); running {
		t.Error("the removed instance is still running")
	}
	if conn, err := net.Dial("tcp", goneAt); err == nil {
		conn.Close()
		t.Errorf("%s is still accepting connections after the instance was removed", goneAt)
	}
	if after := boundAddr(t, set, second.ID); after != keptAt {
		t.Errorf("the instance that stayed moved from %s to %s", keptAt, after)
	}
}

// Switching one off stops it without touching the others, and it stays in the document: off
// is a state an instance is in, not an instance that is gone.
func TestSwitchingOneInstanceOffLeavesTheOthersRunning(t *testing.T) {
	hub := newFakeNetwork(t)
	set := newSet(t, hub)
	first := heldInstance("px_aaaaaa", "db", "psql", reachTheConnection())
	second := heldInstance("px_bbbbbb", "shell", "ssh", reachTheConnection())
	mustApplySet(t, set, first, second)
	keptAt := boundAddr(t, set, second.ID)

	first.Enabled = false
	mustApplySet(t, set, first, second)

	if _, running := set.Get(first.ID); running {
		t.Error("an instance switched off is still running")
	}
	if after := boundAddr(t, set, second.ID); after != keptAt {
		t.Errorf("the instance that stayed on moved from %s to %s", keptAt, after)
	}
}

// The order the instances are listed in is the order every surface shows them in, so a
// reconcile has to put them back in the document's order rather than in the order they
// happened to be created.
func TestTheRunningInstancesFollowTheOrderTheDocumentListsThemIn(t *testing.T) {
	hub := newFakeNetwork(t)
	set := newSet(t, hub)
	first := heldInstance("px_aaaaaa", "db", "psql", reachTheConnection())
	second := heldInstance("px_bbbbbb", "shell", "ssh", reachTheConnection())
	mustApplySet(t, set, first, second)

	mustApplySet(t, set, second, first)

	running := set.All()
	if len(running) != 2 {
		t.Fatalf("%d instances are running, want both", len(running))
	}
	if running[0].Status().ID != second.ID || running[1].Status().ID != first.ID {
		t.Errorf("the instances run in the order %q, %q; want the order the document lists them in",
			running[0].Status().ID, running[1].Status().ID)
	}
}

// One instance failing to bind must not stop the others: the reason belongs on that
// instance's own status, where the dashboard shows it, and a single unusable address taking
// every other listener down with it is how one bad setting becomes an outage.
func TestOneInstanceThatCannotBindLeavesTheOthersListening(t *testing.T) {
	hub := newFakeNetwork(t)
	set := newSet(t, hub)
	broken := heldInstance("px_aaaaaa", "db", "psql", reachTheConnection())
	broken.ListenAddr = "203.0.113.1:9"
	working := heldInstance("px_bbbbbb", "shell", "ssh", reachTheConnection())

	err := set.Apply([]config.ProxyInstance{broken, working})

	if err == nil {
		t.Fatal("an instance that could not bind was reported as applied")
	}
	if boundAddr(t, set, working.ID) == "" {
		t.Error("the instance that could bind is not listening")
	}
	inst, running := set.Get(broken.ID)
	if !running {
		t.Fatal("the instance that could not bind is gone, so nothing carries its reason")
	}
	if inst.Status().Error == "" {
		t.Error("the instance that could not bind carries no reason, leaving nothing to act on")
	}
}

// The tester has to be decided by the same resolver, rule list and matcher a real connection
// is. A second opinion computed some other way is worse than no tester: it would tell someone
// their rules are right while the proxy refuses them.
func TestWhatAnInstanceWouldDoAgreesWithWhatItDoes(t *testing.T) {
	hub := newFakeNetwork(t)
	granted := hub.routeLiteral(t)
	refused := hub.routeLiteral(t)
	set := newSet(t, hub)
	held := heldInstance("px_aaaaaa", "db", "psql", onePortOnOneHost(granted))
	mustApplySet(t, set, held)
	at := boundAddr(t, set, held.ID)
	inst, _ := set.Get(held.ID)

	for _, tc := range []struct {
		address string
		carried bool
	}{
		{granted.String(), true},
		{refused.String(), false},
	} {
		verdict := inst.Would(context.Background(), "tcp", tc.address)
		if verdict.Allowed != tc.carried {
			t.Errorf("the tester says %s allowed=%v, want %v", tc.address, verdict.Allowed, tc.carried)
		}
		if carried := dialThrough(t, at, tc.address) == nil; carried != tc.carried {
			t.Errorf("dialling %s carried=%v, want %v -- the tester and the proxy disagree",
				tc.address, carried, tc.carried)
		}
	}
}

// A stored instance that is not listening is still one whose permissions somebody is editing,
// so the set has to answer for it. Otherwise the only way to find out what a rule does is to
// switch the listener on, which is the opposite of what a tester is for.
func TestTheSetAnswersForAnInstanceThatIsNotRunning(t *testing.T) {
	hub := newFakeNetwork(t)
	granted := hub.routeLiteral(t)
	set := newSet(t, hub)
	held := heldInstance("px_aaaaaa", "db", "psql", onePortOnOneHost(granted))
	held.Enabled = false
	mustApplySet(t, set, held)

	if _, running := set.Get(held.ID); running {
		t.Fatal("the instance is listening, so this proves nothing about a stored one")
	}

	verdict := set.Would(context.Background(), ConfigOf(held), "tcp", granted.String())

	if !verdict.Allowed {
		t.Errorf("verdict = %+v, want the stored rules decided the way they would when bound", verdict)
	}
	if verdict.Rule != "ar_service" || verdict.Index != 0 {
		t.Errorf("rule = %q at %d, want the rule that decided named", verdict.Rule, verdict.Index)
	}
	if verdict.TunnelID != officeTunnel {
		t.Errorf("tunnel = %q, want the connection that would carry it", verdict.TunnelID)
	}
}

// A destination nothing can place is a third answer, not a refusal: no rule was consulted,
// and reporting it as refused sends somebody to edit rules that had no part in it.
func TestADestinationNothingCanPlaceIsNeitherAllowedNorDecidedByARule(t *testing.T) {
	hub := newFakeNetwork(t)
	set := newSet(t, hub)
	held := heldInstance("px_aaaaaa", "db", "psql", reachTheConnection())
	mustApplySet(t, set, held)
	inst, _ := set.Get(held.ID)

	verdict := inst.Would(context.Background(), "tcp", "nowhere.invalid:443")

	if verdict.Allowed {
		t.Error("a destination nothing could place came back allowed")
	}
	if verdict.Resolved != "" || verdict.TunnelID != "" {
		t.Errorf("verdict = %+v, want no resolved address and no connection", verdict)
	}
	if verdict.Rule != "" || verdict.Index != -1 {
		t.Errorf("rule = %q at %d, want no rule named: none was consulted", verdict.Rule, verdict.Index)
	}
	if verdict.Reason == "" {
		t.Error("the verdict carries no reason, so the page has nothing to explain it with")
	}
}

// Where internet traffic goes, at the point a program actually reaches something. A
// destination no connection carries leaves through the connection chosen to carry it, and
// the rules still decide it as this machine's own network -- so a grant of one connection
// does not silently become a grant of the whole internet.
func TestADestinationNoConnectionCarriesLeavesThroughTheEgressConnection(t *testing.T) {
	hub := newFakeNetwork(t)
	// An address rather than a name, so this is about where the packets go rather than
	// about where the lookup went: the resolver half is decided in the registry and pinned
	// there.
	outside := echoServer(t)
	hub.SetEgress(officeTunnel)
	set := newSet(t, hub)
	held := heldInstance("px_aaaaaa", "web", "browser", reachThisMachineToo())
	mustApplySet(t, set, held)
	at := boundAddr(t, set, held.ID)

	if err := dialThrough(t, at, outside.String()); err != nil {
		t.Fatalf("the destination was refused: %v", err)
	}

	if got := hub.dialsThroughTheConnection(); got != 1 {
		t.Errorf("%d dials left through the connection, want 1 -- the traffic went out of this "+
			"machine while the setting says it goes through a connection", got)
	}
	inst, _ := set.Get(held.ID)
	verdict := inst.Would(context.Background(), "tcp", outside.String())
	if verdict.TunnelID != access.ThisMachine {
		t.Errorf("tunnel = %q, want the destination still decided as this machine's own network",
			verdict.TunnelID)
	}
	if verdict.EgressID != officeTunnel {
		t.Errorf("egress = %q, want the connection the traffic leaves through named", verdict.EgressID)
	}
}

// Without a connection chosen, the same destination leaves this machine directly. Otherwise
// the test above proves only that something dialled it.
func TestTheSameDestinationLeavesThisMachineWithNoEgressConnectionChosen(t *testing.T) {
	hub := newFakeNetwork(t)
	outside := echoServer(t)
	set := newSet(t, hub)
	held := heldInstance("px_aaaaaa", "web", "browser", reachThisMachineToo())
	mustApplySet(t, set, held)
	at := boundAddr(t, set, held.ID)

	if err := dialThrough(t, at, outside.String()); err != nil {
		t.Fatalf("the destination was refused: %v", err)
	}

	if got := hub.dialsThroughTheConnection(); got != 0 {
		t.Errorf("%d dials left through a connection, want none: nothing was chosen to carry "+
			"internet traffic", got)
	}
}
