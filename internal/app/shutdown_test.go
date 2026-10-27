// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/sysdns"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// teardownTrace is the one list every fake reports into as the agent stops, so the order
// the machine is put back in can be read across components rather than inside each one.
type teardownTrace struct {
	mu    sync.Mutex
	steps []string
}

func (tr *teardownTrace) mark(step string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.steps = append(tr.steps, step)
}

func (tr *teardownTrace) all() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return slices.Clone(tr.steps)
}

// assertBefore fails unless first happened, and happened before second.
func (tr *teardownTrace) assertBefore(t *testing.T, first, second string) {
	t.Helper()
	steps := tr.all()
	i, j := slices.Index(steps, first), slices.Index(steps, second)
	switch {
	case i < 0:
		t.Errorf("%q never happened; the teardown ran %v", first, steps)
	case j < 0:
		t.Errorf("%q never happened; the teardown ran %v", second, steps)
	case i > j:
		t.Errorf("%q came after %q; the teardown ran %v", first, second, steps)
	}
}

// everythingOn is a machine app-tail has changed in every way it can: its resolver
// pointed at app-tail, an interface carrying two networks, its proxy setting written, and
// the node carrying subnet connections for the tailnet.
func everythingOn(c *config.Config) {
	seedFabric(c, labRange)
	systemProxyOn(c)
	c.Settings.SystemDNSEnabled = true
	c.Settings.SystemDNSProfile = "cloudflare"
	c.Settings.RoutesEnabled = true
}

// fullyChangedMachine is a running agent that has changed everything everythingOn asks for,
// with every fake reporting into one trace. rights is the claim on the machine's resolver,
// so a test can make the restore fail before the agent is stopped.
func fullyChangedMachine(t *testing.T, rights *fakeResolverRights) (*harness, *teardownTrace, *fakeFabrics) {
	t.Helper()
	trace := &teardownTrace{}
	rights.observe = trace.mark
	fabrics := &fakeFabrics{observe: trace.mark}
	h := newHarnessWith(t, everythingOn, func(o *Options) {
		o.OpenSystemDNS = func(context.Context, func(string, ...any)) (tsnode.SystemDNSRights, error) {
			return rights, nil
		}
		o.OpenFabric = fabrics.open
	})
	h.node.observe = trace.mark
	h.sysproxy.observe = trace.mark
	h.bringUp()

	waitFor(t, 5*time.Second, "this machine's resolver to be pointed at app-tail", func() bool {
		return h.agent.currentSystemDNS().snapshot().applied
	})
	waitFor(t, 5*time.Second, "the interface to be carrying both connections", func() bool {
		built := fabrics.all()
		if len(built) == 0 {
			return false
		}
		routes, _, calls := built[len(built)-1].carrying()
		return calls > 0 && slices.Contains(routes, officeRange) && slices.Contains(routes, labRange)
	})
	waitForSystemProxy(h, "this machine to be pointed at the proxy", func(url string) bool {
		return url != ""
	})
	patchSettings(h, map[string]any{"routes.serve": true})
	waitForCarrying(h, true, "the router to be installed on the node")
	return h, trace, fabrics
}

// Everything this run changed outside its own process is put back on the way out, and in
// one order: the resolver first, because while app-tail is the resolver every later step
// that looks up a name goes through the socket about to close; the interface next, so the
// networks it carried stop hanging against it; then the proxy setting, then the node's
// subnet hook, and the node itself last of all, since the node is what the rest ran over.
func TestStoppingPutsTheMachineBackResolverFirstAndNodeLast(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")},
	}}
	h, trace, fabrics := fullyChangedMachine(t, rights)

	if err := h.exit(); err != nil {
		t.Fatalf("the agent exited with %v, want a clean exit", err)
	}

	trace.assertBefore(t, "dns restore", "dns close")
	trace.assertBefore(t, "dns close", "fabric close")
	trace.assertBefore(t, "fabric close", "proxy clear")
	trace.assertBefore(t, "proxy clear", "subnet router stop")
	trace.assertBefore(t, "subnet router stop", "node close")
	if got := trace.all(); slices.Index(got, "node close") != len(got)-1 {
		t.Errorf("the node was not the last thing closed; the teardown ran %v", got)
	}

	if pointsAt, _, clears := h.sysproxy.snapshot(); pointsAt != "" || clears != 1 {
		t.Errorf("proxy points at %q after %d clears, want nothing after one", pointsAt, clears)
	}
	if built := fabrics.all(); len(built) != 1 || !built[0].wasClosed() {
		t.Errorf("the interface was not let go of: %d built", len(built))
	}
	if !h.node.wasClosed() {
		t.Error("the node was not closed")
	}
}

// A resolver that could not be put back is the one thing the user cares about after the
// window is gone: the machine resolves through a port nothing answers on, and it survives a
// reboot. The exit says so, and everything else is still put back on the way.
func TestAResolverThatCannotBePutBackFailsTheExitAndTheRestIsStillPutBack(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")},
	}}
	h, trace, fabrics := fullyChangedMachine(t, rights)
	rights.restoreErr = errors.New("networksetup refused to change Wi-Fi")

	err := h.exit()

	if err == nil {
		t.Fatal("the agent exited cleanly having left this machine resolving through a port nothing answers on")
	}
	if !strings.Contains(err.Error(), "restore this machine's name resolution") ||
		!strings.Contains(err.Error(), "networksetup refused") {
		t.Errorf("exit error = %v, want it to name the resolver and what the machine said", err)
	}
	for _, step := range []string{"fabric close", "proxy clear", "subnet router stop", "node close"} {
		if !slices.Contains(trace.all(), step) {
			t.Errorf("%q was skipped after the resolver refused; the teardown ran %v", step, trace.all())
		}
	}
	if pointsAt, _, _ := h.sysproxy.snapshot(); pointsAt != "" {
		t.Errorf("proxy still points at %q", pointsAt)
	}
	if built := fabrics.all(); len(built) != 1 || !built[0].wasClosed() {
		t.Error("the interface was not let go of")
	}
}

// Rebuilding the node is not stopping: the machine's resolver, the interface and the proxy
// setting are not the node's, and each outlives the rebuild untouched. Dropping any of them
// for the length of a rebuild would take this machine's DNS, every connection's network, or
// the browser's proxy away for a settings change that named none of them.
func TestRebuildingTheNodeLeavesTheMachineAsItIs(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")},
	}}
	h, trace, fabrics := fullyChangedMachine(t, rights)

	if err := h.agent.RestartNode(context.Background()); err != nil {
		t.Fatalf("RestartNode: %v", err)
	}
	h.bringUp()

	steps := trace.all()
	for _, step := range []string{"dns restore", "dns close", "fabric close", "proxy clear"} {
		if slices.Contains(steps, step) {
			t.Errorf("%q happened for a node rebuild; the rebuild ran %v", step, steps)
		}
	}
	if opens := strings.Count(strings.Join(steps, ","), "dns open"); opens != 1 {
		t.Errorf("the resolver sockets were opened %d times across the rebuild, want once", opens)
	}
	if !h.agent.currentSystemDNS().snapshot().applied {
		t.Error("this machine's resolver is no longer pointed at app-tail after the rebuild")
	}
	if built := fabrics.all(); len(built) != 1 || built[0].wasClosed() {
		t.Errorf("the interface was rebuilt or let go of: %d built", len(built))
	}
	if pointsAt, applies, clears := h.sysproxy.snapshot(); pointsAt == "" || applies != 1 || clears != 0 {
		t.Errorf("proxy points at %q after %d applies and %d clears, want the one write left standing", pointsAt, applies, clears)
	}
	// The hook belongs to the node, so it is the one thing that is put back, on the new node.
	waitForCarrying(h, true, "the router to be installed on the rebuilt node")

	if err := h.exit(); err != nil {
		t.Fatalf("the agent exited with %v after a rebuild, want a clean exit", err)
	}
	trace.assertBefore(t, "dns restore", "fabric close")
}

// A restore that reached every network service it could is as far back as this machine
// can be put until the ones it could not reach come back, and the next elevated run
// finishes the job from the record it left. That is an ordinary way to quit -- an adapter
// switched off first -- so it is not a failed exit, which would skip a restart the user
// asked for.
func TestARestoreThatReachedEveryServiceItCouldIsACleanExit(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")},
	}}
	h, trace, fabrics := fullyChangedMachine(t, rights)
	rights.restoreErr = &sysdns.PartialRestoreError{Services: []string{"Thunderbolt Bridge"}}

	if err := h.exit(); err != nil {
		t.Fatalf("the agent exited with %v, want a partial restore to be a clean exit", err)
	}

	trace.assertBefore(t, "dns restore", "fabric close")
	trace.assertBefore(t, "fabric close", "proxy clear")
	if pointsAt, _, clears := h.sysproxy.snapshot(); pointsAt != "" || clears != 1 {
		t.Errorf("proxy points at %q after %d clears, want nothing after one", pointsAt, clears)
	}
	if built := fabrics.all(); len(built) != 1 || !built[0].wasClosed() {
		t.Error("the interface was not let go of")
	}
}

// An interface that will not let go is reported, and it is not where the teardown stops:
// the proxy setting and the node are put back regardless, or one stuck interface leaves the
// browser pointed at a proxy that is gone.
func TestAnInterfaceThatWillNotLetGoStillLetsTheRestBePutBack(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")},
	}}
	h, trace, fabrics := fullyChangedMachine(t, rights)
	fabrics.all()[0].refusesTo("close", errors.New("the interface is still in use"))

	err := h.exit()

	if err == nil || !strings.Contains(err.Error(), "the interface is still in use") {
		t.Fatalf("the agent exited with %v, want the interface's own reason", err)
	}
	trace.assertBefore(t, "dns restore", "fabric close")
	for _, step := range []string{"proxy clear", "subnet router stop", "node close"} {
		if !slices.Contains(trace.all(), step) {
			t.Errorf("%q was skipped after the interface refused; the teardown ran %v", step, trace.all())
		}
	}
	if pointsAt, _, clears := h.sysproxy.snapshot(); pointsAt != "" || clears != 1 {
		t.Errorf("proxy points at %q after %d clears, want nothing after one", pointsAt, clears)
	}
	if !h.node.wasClosed() {
		t.Error("the node was not closed")
	}
}

// A second stop after the first finds nothing left to put back and touches nothing: the
// resolver, proxy setting and node were put back once, and doing any of it again would be
// writing to a machine another run may already own.
func TestASecondStopPutsNothingBackTwice(t *testing.T) {
	rights := &fakeResolverRights{base: tsnode.BaseResolvers{
		Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")},
	}}
	h, trace, _ := fullyChangedMachine(t, rights)
	if err := h.exit(); err != nil {
		t.Fatalf("the first stop exited with %v", err)
	}
	before := trace.all()

	if err := h.agent.Shutdown(context.Background()); err != nil {
		t.Fatalf("a second Shutdown returned %v", err)
	}

	if after := trace.all(); !slices.Equal(before, after) {
		t.Errorf("a second stop touched the machine again: %v", after[len(before):])
	}
	if _, _, clears := h.sysproxy.snapshot(); clears != 1 {
		t.Errorf("proxy cleared %d times across two stops, want once", clears)
	}
	if got := strings.Count(strings.Join(before, ","), "dns restore"); got != 1 {
		t.Errorf("the resolver was put back %d times, want once", got)
	}
}
