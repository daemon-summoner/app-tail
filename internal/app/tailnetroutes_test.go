// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// Every agent the suite builds looks at a machine with no tailnet on it, whichever test built
// it and whether or not that test knew this watch exists. The shipped pair reads the routing
// table of the machine running the suite and changes it through the privileged side, which no
// test may do -- least of all the ones whose subject is something else entirely. The tests
// below substitute a machine of their own through the Options fields.
func init() {
	readTailnetRoutingOf = func(context.Context, string) (tsnode.TailnetRouting, error) {
		return tsnode.TailnetRouting{}, nil
	}
	repairTailnetRoutesOn = func(_ context.Context, iface string, _ func(string, ...any)) ([]netip.Prefix, error) {
		return nil, errors.New("this suite does not change the routing table of the machine it runs on, and was asked to on " + iface)
	}
}

// machine stands in for what this one is doing with tailnet traffic, and records every repair
// asked of it. The real pair reads the machine's routing table and changes it as root, so the
// state worth pinning -- a tailnet present and unreachable -- is one no suite can arrange.
type machine struct {
	mu        sync.Mutex
	routing   tsnode.TailnetRouting
	readErr   error
	repaired  []string
	installed []netip.Prefix
	repairErr error
}

func (m *machine) read(context.Context, string) (tsnode.TailnetRouting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routing, m.readErr
}

func (m *machine) repair(_ context.Context, iface string, _ func(string, ...any)) ([]netip.Prefix, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repaired = append(m.repaired, iface)
	if m.repairErr != nil {
		return nil, m.repairErr
	}
	// A repair that worked leaves the machine reachable, so the next round finds nothing to do.
	m.routing.Unrouted = nil
	return m.installed, nil
}

func (m *machine) repairs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.repaired...)
}

// watching builds an agent over one machine, with the log open to the test.
func watching(t *testing.T, m *machine, node *fakeNode) (*Agent, *bytes.Buffer) {
	t.Helper()
	stateDir := t.TempDir()
	store, err := config.Open(filepath.Join(stateDir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	rt, err := config.Resolve(config.Flags{}, emptyEnv, store.Get(), stateDir, store.Path())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	agent, err := New(Options{
		Store: store, Runtime: rt, Getenv: emptyEnv, Logger: quietLogger(),
		Version: "test", Provision: refuseElevation,
		NewNode:             func(tsnode.Options) NodeController { return newFakeNode() },
		ReadTailnetRouting:  m.read,
		RepairTailnetRoutes: m.repair,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var log bytes.Buffer
	agent.logger = slog.New(slog.NewTextHandler(&log, nil))
	if node != nil {
		agent.mu.Lock()
		agent.node = node
		agent.mu.Unlock()
	}
	return agent, &log
}

// carrying puts a node into the state where app-tail is itself the tailnet client.
func carrying(n *fakeNode, mode config.NetworkMode) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.status.BackendState = tsnode.StateRunning
	n.status.Network = mode
}

// A machine carrying a tailnet it cannot reach gets the route put back, and the ranges are
// named in the log: this is the fault nothing else on the machine reports, so the log line is
// the only record that anything was wrong.
func TestAMachineThatCannotReachItsTailnetIsRepaired(t *testing.T) {
	m := &machine{
		routing:   tsnode.TailnetRouting{Interface: "utun5", Unrouted: []netip.Prefix{tailnetV4, tailnetV6}},
		installed: []netip.Prefix{tailnetV4, tailnetV6},
	}
	agent, log := watching(t, m, nil)

	if !agent.checkTailnetRoutes(t.Context()) {
		t.Fatal("the watch gave up on a machine it could read")
	}
	if got := m.repairs(); len(got) != 1 || got[0] != "utun5" {
		t.Fatalf("the repair was asked for on %v, want utun5 once", got)
	}
	line := log.String()
	for _, want := range []string{"utun5", tailnetV4.String(), tailnetV6.String()} {
		if !strings.Contains(line, want) {
			t.Errorf("the log does not mention %q, so nothing records what was mended:\n%s", want, line)
		}
	}
}

// A machine that is routing its tailnet is left alone. A repair sent anyway would be a second
// writer for routes the tailnet client already owns.
func TestAMachineThatCanReachItsTailnetIsLeftAlone(t *testing.T) {
	m := &machine{routing: tsnode.TailnetRouting{Interface: "utun5"}}
	agent, _ := watching(t, m, nil)

	if !agent.checkTailnetRoutes(t.Context()) {
		t.Fatal("the watch gave up on a healthy machine")
	}
	if got := m.repairs(); len(got) != 0 {
		t.Errorf("a healthy machine was repaired on %v", got)
	}
}

// A machine with no tailnet on it at all is not a machine with something wrong.
func TestAMachineWithNoTailnetIsNotRepaired(t *testing.T) {
	m := &machine{}
	agent, _ := watching(t, m, nil)

	if !agent.checkTailnetRoutes(t.Context()) {
		t.Fatal("the watch gave up on a machine with no tailnet")
	}
	if got := m.repairs(); len(got) != 0 {
		t.Errorf("a machine with no tailnet was repaired on %v", got)
	}
}

// The switch is read on every round, so turning it off stops the repair without stopping the
// loop -- which is what lets it be turned back on again without a restart.
func TestTheSwitchStopsTheRepairWithoutStoppingTheWatch(t *testing.T) {
	m := &machine{routing: tsnode.TailnetRouting{Interface: "utun5", Unrouted: []netip.Prefix{tailnetV4}}}
	agent, _ := watching(t, m, nil)
	if _, err := agent.store.Update(func(c *config.Config) error {
		c.Settings.TailnetRouteRepair = false
		return nil
	}); err != nil {
		t.Fatalf("turn the repair off: %v", err)
	}
	if _, err := agent.adoptSettings(); err != nil {
		t.Fatalf("adopt the switched-off document: %v", err)
	}

	if !agent.checkTailnetRoutes(t.Context()) {
		t.Fatal("a switched-off repair ended the watch, so switching it back on would do nothing")
	}
	if got := m.repairs(); len(got) != 0 {
		t.Errorf("a switched-off repair still changed the machine: %v", got)
	}

	if _, err := agent.store.Update(func(c *config.Config) error {
		c.Settings.TailnetRouteRepair = true
		return nil
	}); err != nil {
		t.Fatalf("turn the repair back on: %v", err)
	}
	if _, err := agent.adoptSettings(); err != nil {
		t.Fatalf("adopt the switched-on document: %v", err)
	}
	agent.checkTailnetRoutes(t.Context())
	if got := m.repairs(); len(got) != 1 {
		t.Errorf("the repair was asked for %d times after being switched back on, want once", len(got))
	}
}

// When app-tail is itself the tailnet client on this machine, its own engine installs the
// routes for the tailnet's range from the netmap it holds. Repairing from here would be a
// second writer for routes that already have one.
func TestTheWatchStandsDownWhenAppTailIsTheTailnetClient(t *testing.T) {
	node := newFakeNode()
	carrying(node, config.NetworkTUN)
	m := &machine{routing: tsnode.TailnetRouting{Interface: "utun5", Unrouted: []netip.Prefix{tailnetV4}}}
	agent, _ := watching(t, m, node)

	if !agent.checkTailnetRoutes(t.Context()) {
		t.Fatal("the watch ended rather than standing down, so it would not resume when the node stopped")
	}
	if got := m.repairs(); len(got) != 0 {
		t.Errorf("app-tail repaired routes on its own interface: %v", got)
	}
}

// The contained mode carries no tailnet addresses on this machine, so a tailnet here belongs to
// another client and is the watch's business as usual.
func TestTheWatchKeepsGoingWhileAppTailRunsContained(t *testing.T) {
	node := newFakeNode()
	carrying(node, config.NetworkUserspace)
	m := &machine{routing: tsnode.TailnetRouting{Interface: "utun5", Unrouted: []netip.Prefix{tailnetV4}}}
	agent, _ := watching(t, m, node)

	agent.checkTailnetRoutes(t.Context())
	if got := m.repairs(); len(got) != 1 {
		t.Errorf("the repair ran %d times on a machine app-tail is not the tailnet on, want once", len(got))
	}
}

// A platform that cannot be asked the question ends the watch after saying so once. Asking
// again every minute would fill the log with the same unchanging sentence about the machine.
func TestAPlatformThatCannotBeAskedEndsTheWatch(t *testing.T) {
	m := &machine{readErr: tsnode.ErrTailnetRoutesUnsupported}
	agent, log := watching(t, m, nil)

	if agent.checkTailnetRoutes(t.Context()) {
		t.Fatal("the watch went on asking a platform that has no answer")
	}
	if !strings.Contains(log.String(), "not being watched") {
		t.Errorf("nothing in the log says the route is unwatched:\n%s", log.String())
	}
}

// A machine that cannot be read is a round that failed, not a platform that cannot answer: the
// watch keeps going, because the next round may well succeed.
func TestAMachineThatCannotBeReadIsTriedAgain(t *testing.T) {
	m := &machine{readErr: errors.New("route: writing to routing socket: No such process")}
	agent, log := watching(t, m, nil)

	if !agent.checkTailnetRoutes(t.Context()) {
		t.Fatal("one failed read ended the watch for the life of the agent")
	}
	if !strings.Contains(log.String(), "No such process") {
		t.Errorf("the failure is not in the log, so nothing says why the route is unwatched:\n%s", log.String())
	}
}

// A repair that failed is reported, and the watch keeps going. Reporting it every minute for as
// long as the fault stands would bury everything else the agent has to say, so the same failure
// is logged once -- and reported again once it has cleared and come back.
func TestAStandingFailureIsReportedOnceAndAgainAfterItClears(t *testing.T) {
	m := &machine{
		routing:   tsnode.TailnetRouting{Interface: "utun5", Unrouted: []netip.Prefix{tailnetV4}},
		repairErr: errors.New("route: not in table"),
	}
	agent, log := watching(t, m, nil)

	for range 3 {
		if !agent.checkTailnetRoutes(t.Context()) {
			t.Fatal("a repair that failed ended the watch")
		}
	}
	if got := strings.Count(log.String(), "not in table"); got != 1 {
		t.Errorf("the same failure was logged %d times, want once:\n%s", got, log.String())
	}

	// The machine recovers, then breaks the same way again. The second fault is a new one to
	// report: silenced by the first, it would be a tailnet nobody is told about.
	m.mu.Lock()
	m.routing.Unrouted = nil
	m.mu.Unlock()
	agent.checkTailnetRoutes(t.Context())

	m.mu.Lock()
	m.routing.Unrouted = []netip.Prefix{tailnetV4}
	m.mu.Unlock()
	agent.checkTailnetRoutes(t.Context())

	if got := strings.Count(log.String(), "not in table"); got != 2 {
		t.Errorf("the failure was logged %d times across a recovery, want twice:\n%s", got, log.String())
	}
}

// The loop ends when the platform has no answer, rather than waiting out an interval it will
// never come back from. A watch left running there is a goroutine asking the same unanswerable
// question for the life of the agent.
func TestTheWatchEndsOnAPlatformThatCannotBeAsked(t *testing.T) {
	m := &machine{readErr: tsnode.ErrTailnetRoutesUnsupported}
	agent, _ := watching(t, m, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		agent.runTailnetRouteWatch(t.Context())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch is still running on a platform that has no answer for it")
	}
}

// The loop comes round again, which is the whole reason it is a loop: the loss it watches for is
// a change to this machine that nothing on this machine announces, so a watch that checked once
// would cover only the instant the agent started.
func TestTheWatchComesRoundAgain(t *testing.T) {
	m := &machine{routing: tsnode.TailnetRouting{Interface: "utun5"}}
	agent, _ := watching(t, m, nil)
	agent.tailnetRouteInterval = time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go agent.runTailnetRouteWatch(ctx)

	// The machine loses the route after the first round, so a repair can only come from a later
	// one.
	m.mu.Lock()
	m.routing.Unrouted = []netip.Prefix{tailnetV4}
	m.mu.Unlock()

	waitFor(t, 5*time.Second, "the watch to come round and find the route gone", func() bool {
		return len(m.repairs()) > 0
	})
}

// The loop ends with the agent. One that outlived the context would go on running the platform's
// routing tool against a machine the app has finished with.
func TestTheWatchEndsWithTheAgent(t *testing.T) {
	m := &machine{routing: tsnode.TailnetRouting{Interface: "utun5"}}
	agent, _ := watching(t, m, nil)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		agent.runTailnetRouteWatch(ctx)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch outlived the agent that started it")
	}
}

// A repair that installed nothing is not worth a line: the machine was put right between the
// read and the repair, by the client that owns the route or by a person, and nothing was done.
func TestARepairThatFoundNothingToDoSaysNothing(t *testing.T) {
	m := &machine{routing: tsnode.TailnetRouting{Interface: "utun5", Unrouted: []netip.Prefix{tailnetV4}}}
	agent, log := watching(t, m, nil)

	agent.checkTailnetRoutes(t.Context())

	if strings.Contains(log.String(), "put back the route sending") {
		t.Errorf("a repair that installed nothing reported putting a route back:\n%s", log.String())
	}
}
