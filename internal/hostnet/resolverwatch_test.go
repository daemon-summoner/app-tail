// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/sysdns"
)

// recordingRepair is the machine's resolver as the watch sees it: a repair that reports what
// it was told to report, counting the passes that reached it.
type recordingRepair struct {
	passes   int
	restored bool
	err      error
	lines    []string
	during   func()
}

func (r *recordingRepair) repair(_ context.Context, logf func(format string, args ...any)) (bool, error) {
	r.passes++
	for _, line := range r.lines {
		logf("%s", line)
	}
	if r.during != nil {
		r.during()
	}
	return r.restored, r.err
}

func newTestWatch(gate *sessionGate, r *recordingRepair, logged *[]string) *resolverWatch {
	return &resolverWatch{
		gate:   gate,
		repair: r.repair,
		logf: func(format string, args ...any) {
			*logged = append(*logged, format)
		},
	}
}

// A machine left pointed at app-tail by a run that crashed resolves no names until something
// puts it back. The boot-time pass is one chance, and a network that was not up yet, or a
// record that did not name the service, makes it miss. Nothing else would try again until
// the user opened app-tail.
func TestTheWatchRepairsTheResolverWhileNoAgentHoldsIt(t *testing.T) {
	gate := newSessionGate(time.Minute)
	r := &recordingRepair{}
	var logged []string
	w := newTestWatch(gate, r, &logged)

	for range 3 {
		if !w.pass(t.Context()) {
			t.Fatal("a pass with the resolver session free did not run")
		}
	}
	if r.passes != 3 {
		t.Errorf("the repair ran %d times over 3 passes, want every pass to try again", r.passes)
	}
}

// An agent holding the resolver session has this machine pointed at a resolver it is
// serving. Putting that back would switch off a feature the user turned on.
func TestTheWatchLeavesTheResolverAloneWhileAnAgentHoldsIt(t *testing.T) {
	gate := newSessionGate(time.Minute)
	if !gate.take(t.Context(), gateResolver) {
		t.Fatal("could not take the resolver session for the agent")
	}
	r := &recordingRepair{}
	var logged []string
	w := newTestWatch(gate, r, &logged)

	if w.pass(t.Context()) {
		t.Error("the watch ran while an agent held the resolver session")
	}
	if r.passes != 0 {
		t.Errorf("the repair ran %d times under an agent's session, want none", r.passes)
	}

	gate.release(gateResolver)
	if !w.pass(t.Context()) || r.passes != 1 {
		t.Errorf("the watch did not resume once the agent let go (passes = %d)", r.passes)
	}
}

// The watch holds the session for the length of its pass, so an agent arriving mid-repair
// waits for the machine to be put back before it points it anywhere, rather than the two
// writing the same services at once.
func TestAnAgentCannotTakeTheResolverDuringARepair(t *testing.T) {
	gate := newSessionGate(time.Minute)
	takenDuring := true
	r := &recordingRepair{during: func() { takenDuring = gate.tryTake(gateResolver) }}
	var logged []string
	w := newTestWatch(gate, r, &logged)

	w.pass(t.Context())
	if takenDuring {
		t.Error("the resolver session was free in the middle of a repair")
	}
	if !gate.tryTake(gateResolver) {
		t.Error("the watch did not give the resolver session back after its pass")
	}
}

// A pass every half-minute that logs the same unplugged adapter every time is a log nobody
// can read the one useful line out of. A failure is reported when it starts or changes, and a
// repair that changed something always is.
func TestTheWatchReportsAFailureOnceAndARepairEveryTime(t *testing.T) {
	gate := newSessionGate(time.Minute)
	// restored is true alongside the error because that is what a failed restore of a record
	// reports: there was one.
	r := &recordingRepair{restored: true, err: errors.New("Thunderbolt Ethernet could not be read"), lines: []string{"leaving Thunderbolt Ethernet alone"}}
	var logged []string
	w := newTestWatch(gate, r, &logged)

	w.pass(t.Context())
	w.pass(t.Context())
	w.pass(t.Context())
	if got := count(logged, "could not put this machine's resolver back"); got != 1 {
		t.Errorf("the same failure was reported %d times over 3 passes, want once\n%s", got, strings.Join(logged, "\n"))
	}

	r.err = errors.New("Wi-Fi could not be written")
	w.pass(t.Context())
	if got := count(logged, "could not put this machine's resolver back"); got != 2 {
		t.Errorf("a different failure was not reported (%d reports)", got)
	}

	r.err, r.restored = nil, true
	w.pass(t.Context())
	w.pass(t.Context())
	if got := count(logged, "restored this machine's resolver"); got != 2 {
		t.Errorf("%d repairs reported over 2 passes that each changed something, want both", got)
	}
}

// A pass with nothing to do is the normal state of every machine, every half-minute. It
// says nothing at all.
func TestAPassWithNothingToDoSaysNothing(t *testing.T) {
	gate := newSessionGate(time.Minute)
	r := &recordingRepair{lines: []string{"skipping one network service"}}
	var logged []string
	w := newTestWatch(gate, r, &logged)

	w.pass(t.Context())
	if len(logged) != 0 {
		t.Errorf("a pass that changed nothing logged:\n%s", strings.Join(logged, "\n"))
	}
}

func TestTheWatchStopsWithItsContext(t *testing.T) {
	gate := newSessionGate(time.Minute)
	r := &recordingRepair{}
	var logged []string
	w := newTestWatch(gate, r, &logged)

	ctx, cancel := context.WithCancel(t.Context())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		w.run(ctx, ticks)
		close(done)
	}()
	ticks <- time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch kept running after its context was cancelled")
	}
	if r.passes != 1 {
		t.Errorf("the watch ran %d passes for one tick, want 1", r.passes)
	}
}

func count(lines []string, substr string) int {
	n := 0
	for _, line := range lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// fakeRecordedResolver is the resolver manager as a repair sees it.
type fakeRecordedResolver struct {
	installed bool
	clearErr  error
	strays    []string
	strayErr  error
	order     []string
	ours      []netip.Addr
}

func (f *fakeRecordedResolver) Installed() (bool, error) { return f.installed, nil }

func (f *fakeRecordedResolver) Clear(context.Context) error {
	f.order = append(f.order, "clear")
	return f.clearErr
}

func (f *fakeRecordedResolver) ReleaseStrays(_ context.Context, ours []netip.Addr) ([]string, error) {
	f.order = append(f.order, "strays")
	f.ours = ours
	return f.strays, f.strayErr
}

// A record naming an unplugged adapter fails every restore. If that stopped the sweep, the
// services the record does not name would stay pointed at nothing for as long as the
// adapter stays unplugged.
func TestAFailedRestoreStillSweepsAndStillSaysItWasPartial(t *testing.T) {
	m := &fakeRecordedResolver{
		installed: true,
		clearErr:  &sysdns.PartialRestoreError{Services: []string{"Thunderbolt Ethernet"}},
		strays:    []string{"Wi-Fi"},
	}

	changed, err := repairSystemDNS(t.Context(), m)
	if !slices.Equal(m.order, []string{"clear", "strays"}) {
		t.Errorf("ran %v, want the record's restore and then the sweep", m.order)
	}
	if !changed {
		t.Error("a repair that released Wi-Fi reported changing nothing")
	}
	if !PartialSystemDNSRestore(err) {
		t.Errorf("err = %v, want it still recognisable as a partial restore", err)
	}
}

// The sweep is what catches a service the record lost, so it has to run on a machine with
// no record at all -- which is the machine a crash between the change and the write leaves.
func TestTheSweepRunsWithNoRecordAndOnlyForAppTailsOwnAddresses(t *testing.T) {
	m := &fakeRecordedResolver{strays: []string{"Wi-Fi"}}

	changed, err := repairSystemDNS(t.Context(), m)
	if err != nil || !changed {
		t.Fatalf("repairSystemDNS = %v, %v; want the stray released", changed, err)
	}
	if slices.Contains(m.order, "clear") {
		t.Error("restored from a record that is not there")
	}
	want := []netip.Addr{
		netip.MustParseAddr("127.0.0.153"),
		netip.MustParseAddr("127.0.0.154"),
		netip.MustParseAddr("127.0.0.155"),
	}
	if !slices.Equal(m.ours, want) {
		t.Errorf("swept for %v, want only the addresses app-tail listens on (%v)", m.ours, want)
	}
}

func TestARepairWithNothingToDoChangesNothing(t *testing.T) {
	changed, err := repairSystemDNS(t.Context(), &fakeRecordedResolver{})
	if err != nil || changed {
		t.Errorf("repairSystemDNS = %v, %v on a clean machine, want false, nil", changed, err)
	}
}

// holdingLock stands in for the serving lock: held says whether a repair gets it, and the
// log notes when it was taken and given back.
func holdingLock(held bool, order *[]string) func() (func() error, bool, error) {
	return func() (func() error, bool, error) {
		if !held {
			return nil, false, nil
		}
		*order = append(*order, "hold")
		return func() error {
			*order = append(*order, "release")
			return nil
		}, true, nil
	}
}

// A root agent pointed this machine at app-tail without the helper, and holds the lock. A
// repair that went ahead would take its override and the loopback address it serves on away
// from under it.
func TestARepairStandsBackWhileAnAppTailHoldsTheServingLock(t *testing.T) {
	m := &fakeRecordedResolver{installed: true, strays: []string{"Wi-Fi"}}
	var order []string

	changed, err := repairUnlessServed(t.Context(), holdingLock(false, &order), m)
	if !errors.Is(err, ErrResolverServed) || changed {
		t.Fatalf("repairUnlessServed = %v, %v; want ErrResolverServed and nothing changed", changed, err)
	}
	if len(m.order) != 0 {
		t.Errorf("touched the machine (%v) while an app-tail was serving it", m.order)
	}
}

// The repair holds the lock across both halves, so an agent applying its override waits for
// the machine to be put back rather than racing the sweep for the same services.
func TestARepairHoldsTheServingLockWhileItRuns(t *testing.T) {
	var order []string
	m := &fakeRecordedResolver{installed: true}

	if _, err := repairUnlessServed(t.Context(), holdingLock(true, &order), m); err != nil {
		t.Fatalf("repairUnlessServed: %v", err)
	}
	got := append(append([]string{}, order[:1]...), m.order...)
	got = append(got, order[1:]...)
	if want := []string{"hold", "clear", "strays", "release"}; !slices.Equal(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
}

// A machine an app-tail is serving is the normal case for a running helper, every
// half-minute; the watch says nothing about it.
func TestTheWatchSaysNothingWhileAnAppTailServesTheMachine(t *testing.T) {
	gate := newSessionGate(time.Minute)
	r := &recordingRepair{err: ErrResolverServed}
	var logged []string
	w := newTestWatch(gate, r, &logged)

	if w.pass(t.Context()) {
		t.Error("a pass that stood back for a serving app-tail reported that it ran")
	}
	if len(logged) != 0 {
		t.Errorf("logged while an app-tail was serving:\n%s", strings.Join(logged, "\n"))
	}
}
