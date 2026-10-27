// SPDX-License-Identifier: MIT

package sysdns

import (
	"context"
	"errors"
	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// fakeResolver is a machine whose resolver settings live in a map. It is the seam the
// machineResolver interface exists for: the bookkeeping -- which is where the mistakes that
// lose someone's original settings live -- is exercised on every platform through it.
type fakeResolver struct {
	list      []Service
	current   map[string][]netip.Addr
	published map[string]Base
	setErr    map[string]error
	// getErr is a service whose current setting cannot be read at all: an adapter that has
	// been disabled, a dock that was unplugged, a radio switched off.
	getErr    map[string]error
	unsupport string
	flushes   int
	writes    []string

	// held is what this machine's loopback carries because app-tail put it there, in the
	// order it was asked for. holdErr makes the request fail, which is the state of every
	// platform that assigns the whole range.
	held       []netip.Addr
	released   []netip.Addr
	holdErr    error
	releaseErr error
	// writesAfterRelease records the ordering mistake this pair can make: pointing a
	// service back at its own resolver after the address app-tail was listening on has
	// already gone leaves a window where this machine resolves nothing.
	writesAfterRelease bool
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		list: []Service{
			{ID: "wifi-id", Name: "Wi-Fi"},
			{ID: "eth-id", Name: "Ethernet"},
		},
		current: map[string][]netip.Addr{},
		published: map[string]Base{
			"wifi-id": {Nameservers: addrs("192.168.6.1"), SearchDomains: []string{"lan"}},
			"eth-id":  {Nameservers: addrs("10.0.0.1"), SearchDomains: []string{"corp.example.com"}},
		},
		setErr: map[string]error{},
		getErr: map[string]error{},
	}
}

func (f *fakeResolver) supported() (bool, string) {
	if f.unsupport != "" {
		return false, f.unsupport
	}
	return true, ""
}

func (f *fakeResolver) services(context.Context) ([]Service, error) { return f.list, nil }

func (f *fakeResolver) get(_ context.Context, s Service) ([]netip.Addr, error) {
	if err := f.getErr[s.ID]; err != nil {
		return nil, err
	}
	return f.current[s.ID], nil
}

func (f *fakeResolver) set(_ context.Context, s Service, list []netip.Addr) error {
	if err := f.setErr[s.ID]; err != nil {
		return err
	}
	if len(f.released) > 0 {
		f.writesAfterRelease = true
	}
	f.writes = append(f.writes, s.Name+"="+describe(list))
	if len(list) == 0 {
		delete(f.current, s.ID)
		return nil
	}
	f.current[s.ID] = slices.Clone(list)
	return nil
}

func (f *fakeResolver) base(_ context.Context, s Service) (Base, error) {
	return f.published[s.ID], nil
}

func (f *fakeResolver) flush(context.Context) error {
	f.flushes++
	return nil
}

func (f *fakeResolver) holdLoopback(_ context.Context, addr netip.Addr) error {
	if f.holdErr != nil {
		return f.holdErr
	}
	f.held = append(f.held, addr)
	return nil
}

// releaseLoopback mirrors the platform contract: the goal is an address this machine's
// loopback does not carry, so removing one it never carried is that goal, not a failure.
func (f *fakeResolver) releaseLoopback(_ context.Context, addr netip.Addr) error {
	if f.releaseErr != nil {
		return f.releaseErr
	}
	f.released = append(f.released, addr)
	if at := slices.Index(f.held, addr); at >= 0 {
		f.held = slices.Delete(f.held, at, at+1)
	}
	return nil
}

func addrs(in ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func newTestManager(t *testing.T) (*Manager, *fakeResolver) {
	t.Helper()
	// The record is handed to the administrators group as it is written.
	fileowntest.RequireCanHandToAdministrators(t)
	machine := newFakeResolver()
	return &Manager{
		machine:    machine,
		recordPath: filepath.Join(t.TempDir(), RecordFileName),
		logf:       func(string, ...any) {},
	}, machine
}

func TestApplyPointsEveryActiveServiceAtTheForwarder(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")

	want := addrs("127.0.0.153")
	if err := m.Apply(context.Background(), want); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, id := range []string{"wifi-id", "eth-id"} {
		if got := machine.current[id]; !slices.Equal(got, want) {
			t.Errorf("%s resolves through %v, want %v", id, got, want)
		}
	}
	if machine.flushes != 1 {
		t.Errorf("the resolver cache was flushed %d times, want once -- without it the change arrives when the cache expires", machine.flushes)
	}
	if installed, err := m.Installed(); err != nil || !installed {
		t.Errorf("Installed = %v, %v after applying", installed, err)
	}
}

// The first application is the one that saw the user's own setting. A second that recorded
// app-tail's own address as "prior" would make restoring a no-op forever.
func TestApplyingTwiceKeepsWhatTheUserOriginallyHad(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	ctx := context.Background()

	want := addrs("127.0.0.153")
	if err := m.Apply(ctx, want); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if err := m.Apply(ctx, want); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	rec, err := m.readRecord()
	if err != nil {
		t.Fatalf("readRecord: %v", err)
	}
	if got := rec.Services["wifi-id"].Prior; !slices.Equal(got, []string{"192.168.6.1"}) {
		t.Errorf("the recorded prior is %v, want the user's own 192.168.6.1", got)
	}

	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("192.168.6.1")) {
		t.Errorf("Wi-Fi resolves through %v after restoring, want the user's own 192.168.6.1", got)
	}
}

// A service that had nothing set follows its network again rather than being written an
// empty list, which is a different setting.
func TestRestoringAServiceThatHadNothingSetHandsItBackToTheNetwork(t *testing.T) {
	m, machine := newTestManager(t)
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	for _, id := range []string{"wifi-id", "eth-id"} {
		if got, ok := machine.current[id]; ok {
			t.Errorf("%s still carries an override of %v, want none", id, got)
		}
	}
	if installed, err := m.Installed(); err != nil || installed {
		t.Errorf("Installed = %v, %v after clearing", installed, err)
	}
}

// Putting an older value back over a newer one is the same mistake in the other direction,
// so a service somebody else changed since is left exactly as it is.
func TestAServiceChangedSinceIsLeftAlone(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// A VPN client, a profile, or the user.
	machine.current["wifi-id"] = addrs("10.9.9.9")
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("10.9.9.9")) {
		t.Errorf("Wi-Fi resolves through %v, want the newer setting left alone", got)
	}
	// The record is still dropped, so this does not repeat on every start.
	if installed, err := m.Installed(); err != nil || installed {
		t.Errorf("Installed = %v, %v; the record must be dropped either way", installed, err)
	}
}

// A service whose setting cannot be read is the cheapest way to strand a machine: close the
// lid, undock, or switch a radio off before quitting, and the restore skips that service.
// Retiring the record with the rest would throw away the only copy of what that adapter had,
// and it comes back up still pointed at app-tail with nothing left that knows better.
func TestAServiceThatCouldNotBeReadKeepsItsWayBack(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	machine.current["eth-id"] = addrs("10.0.0.1")
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	machine.getErr["wifi-id"] = errors.New("the adapter is not present")
	err := m.Clear(ctx)

	var partial *PartialRestoreError
	if !errors.As(err, &partial) {
		t.Fatalf("Clear = %v, want a partial restore naming the service it could not reach", err)
	}
	if !slices.Equal(partial.Services, []string{"Wi-Fi"}) {
		t.Errorf("the partial restore names %v, want just Wi-Fi", partial.Services)
	}
	// The type does not cross the helper socket and the sentence does, so this is what the
	// far side of the privilege boundary has to recognise it by.
	if !errors.Is(err, ErrPartialRestore) {
		t.Error("the partial restore does not carry its sentinel, so a caller across the helper socket reads it as a teardown that went wrong")
	}
	if got := machine.current["eth-id"]; !slices.Equal(got, addrs("10.0.0.1")) {
		t.Errorf("Ethernet resolves through %v, want it restored despite the other service", got)
	}

	rec, recErr := m.readRecord()
	if recErr != nil {
		t.Fatalf("readRecord: %v", recErr)
	}
	if _, ok := rec.Services["eth-id"]; ok {
		t.Error("the record still carries Ethernet, which was put back; it would be restored a second time over whatever is set by then")
	}
	if got := rec.Services["wifi-id"].Prior; !slices.Equal(got, []string{"192.168.6.1"}) {
		t.Errorf("the record says Wi-Fi's way back is %v, want the 192.168.6.1 it had", got)
	}

	// And the point of keeping it: the adapter comes back, and the next restore finishes.
	delete(machine.getErr, "wifi-id")
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("192.168.6.1")) {
		t.Errorf("Wi-Fi resolves through %v once it is back, want its own 192.168.6.1", got)
	}
	if installed, err := m.Installed(); err != nil || installed {
		t.Errorf("Installed = %v, %v; with everything put back the record must be gone", installed, err)
	}
}

// The record is written before the machine is changed. A crash between the two would
// otherwise leave the machine pointing at app-tail with nothing remembering what it
// replaced, and the next boot with no way back.
func TestTheRecordIsWrittenBeforeTheMachineIsChanged(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	machine.setErr["wifi-id"] = errors.New("networksetup refused")

	err := m.Apply(context.Background(), addrs("127.0.0.153"))
	if err == nil {
		t.Fatal("Apply = nil error although the machine refused the change")
	}
	rec, recErr := m.readRecord()
	if recErr != nil {
		t.Fatalf("readRecord: %v", recErr)
	}
	if got := rec.Services["wifi-id"].Prior; !slices.Equal(got, []string{"192.168.6.1"}) {
		t.Errorf("the record says the prior was %v, want it written before the failed change", got)
	}
}

// Restoring runs every service even after one fails: stopping at the first would leave the
// machine resolving on one interface and not on another.
func TestOneServiceFailingToRestoreDoesNotStopTheRest(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	machine.current["eth-id"] = addrs("10.0.0.1")
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	machine.setErr["wifi-id"] = errors.New("networksetup refused")
	err := m.Clear(ctx)
	if err == nil {
		t.Fatal("Clear = nil error although one service refused")
	}
	if !strings.Contains(err.Error(), "networksetup refused") {
		t.Errorf("Clear = %v, want the machine's own refusal carried", err)
	}
	// A refusal is a failed teardown, which a partial restore -- a service that is merely
	// unreachable -- is not: the caller exits non-zero on the first and cleanly on the second.
	if errors.Is(err, ErrPartialRestore) {
		t.Error("a service that refused the write is reported as one that could not be reached")
	}
	if got := machine.current["eth-id"]; !slices.Equal(got, addrs("10.0.0.1")) {
		t.Errorf("Ethernet resolves through %v, want it restored despite the other failure", got)
	}

	// The record is narrowed to the one service still to put back, so the next restore
	// finishes from it and does not write Ethernet a second time over whatever it has by then.
	rec, recErr := m.readRecord()
	if recErr != nil {
		t.Fatalf("readRecord: %v", recErr)
	}
	if _, ok := rec.Services["eth-id"]; ok {
		t.Error("the record still carries Ethernet, which was put back")
	}
	if got := rec.Services["wifi-id"].Prior; !slices.Equal(got, []string{"192.168.6.1"}) {
		t.Errorf("the record says Wi-Fi's way back is %v, want the 192.168.6.1 it had", got)
	}

	delete(machine.setErr, "wifi-id")
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("192.168.6.1")) {
		t.Errorf("Wi-Fi resolves through %v once the write is accepted, want its own 192.168.6.1", got)
	}
	if installed, err := m.Installed(); err != nil || installed {
		t.Errorf("Installed = %v, %v; with everything put back the record must be gone", installed, err)
	}
}

// app-tail moves this machine between two loopback addresses when its answers change, and
// a move can land on some services and not others: a write refused, or a quit arriving
// partway through. A service left on the old address is still app-tail's, and a restore that
// took it for someone else's setting would leave it pointed at an address nothing listens on
// once app-tail has gone -- past the reboot, with no record left to say so.
func TestAServiceAMoveDidNotReachIsStillPutBack(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	machine.current["eth-id"] = addrs("10.0.0.1")
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	machine.setErr["wifi-id"] = errors.New("networksetup refused")
	if err := m.Apply(ctx, addrs("127.0.0.154")); err == nil {
		t.Fatal("the move reported success although Wi-Fi refused it")
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("127.0.0.153")) {
		t.Fatalf("Wi-Fi resolves through %v, want it still on the old address for this test to mean anything", got)
	}

	// With Ethernet out of reach, Wi-Fi on the old address is the override in force.
	machine.getErr["eth-id"] = errors.New("the adapter is not present")
	if overridden, err := m.Overridden(ctx); err != nil || !overridden {
		t.Errorf("Overridden = %v, %v with Wi-Fi still on app-tail's older address", overridden, err)
	}
	delete(machine.getErr, "eth-id")

	delete(machine.setErr, "wifi-id")
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("192.168.6.1")) {
		t.Errorf("Wi-Fi resolves through %v after the restore, want its own 192.168.6.1", got)
	}
	if got := machine.current["eth-id"]; !slices.Equal(got, addrs("10.0.0.1")) {
		t.Errorf("Ethernet resolves through %v after the restore, want its own 10.0.0.1", got)
	}
}

// A record written before app-tail kept every address it wrote names only the last one. The
// first move after an upgrade has to count that one as app-tail's as well.
func TestARecordFromBeforeEveryAddressWasKeptStillCountsWhatItWrote(t *testing.T) {
	m, machine := newTestManager(t)
	ctx := context.Background()
	if err := m.writeRecord(record{Services: map[string]serviceRecord{
		"wifi-id": {Name: "Wi-Fi", Prior: []string{"192.168.6.1"}, Wrote: []string{"127.0.0.153"}},
	}}); err != nil {
		t.Fatalf("write the old record: %v", err)
	}
	machine.current["wifi-id"] = addrs("127.0.0.153")
	machine.setErr["wifi-id"] = errors.New("networksetup refused")
	if err := m.Apply(ctx, addrs("127.0.0.154")); err == nil {
		t.Fatal("the move reported success although Wi-Fi refused it")
	}

	delete(machine.setErr, "wifi-id")
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("192.168.6.1")) {
		t.Errorf("Wi-Fi resolves through %v after the restore, want its own 192.168.6.1", got)
	}
}

// A restore that could not reach every service keeps the addresses app-tail wrote, so the
// run that finishes it still knows a service on the older one is app-tail's.
func TestARestoreFinishedLaterStillKnowsEveryAddressAppTailWrote(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	machine.current["eth-id"] = addrs("10.0.0.1")
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	machine.setErr["wifi-id"] = errors.New("networksetup refused")
	if err := m.Apply(ctx, addrs("127.0.0.154")); err == nil {
		t.Fatal("the move reported success although Wi-Fi refused it")
	}
	// Wi-Fi still refuses, and Ethernet is unplugged, so the first restore finishes neither.
	machine.getErr["eth-id"] = errors.New("the adapter is not present")
	if err := m.Clear(ctx); err == nil {
		t.Fatal("Clear = nil although Wi-Fi refused and Ethernet was unreachable")
	}

	delete(machine.setErr, "wifi-id")
	delete(machine.getErr, "eth-id")
	if err := m.Clear(ctx); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
	if got := machine.current["wifi-id"]; !slices.Equal(got, addrs("192.168.6.1")) {
		t.Errorf("Wi-Fi resolves through %v after the second restore, want its own 192.168.6.1", got)
	}
}

// A record on a platform that cannot drive its resolver was not written by this platform,
// so nothing here restores it. It is dropped rather than kept: kept, it would ask for a
// restore at every start that no start could perform.
func TestARecordThisPlatformCannotActOnIsDroppedWithoutTouchingTheMachine(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	machine.writes = nil
	machine.unsupport = "no resolver this app can drive"

	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	if len(machine.writes) != 0 {
		t.Errorf("Clear wrote %v on a platform it cannot drive", machine.writes)
	}
	if installed, err := m.Installed(); err != nil || installed {
		t.Errorf("Installed = %v, %v; the record must be dropped so this does not repeat at every start", installed, err)
	}
}

// Overridden asks the machine, not only the record. A record outlives a service that has
// been removed from the machine, and a record alone would keep saying yes about it forever.
func TestOverriddenIsWhatTheMachineSaysNotWhatTheRecordRemembers(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	machine.current["eth-id"] = addrs("10.0.0.1")
	ctx := context.Background()

	if overridden, err := m.Overridden(ctx); err != nil || overridden {
		t.Fatalf("Overridden = %v, %v with nothing applied", overridden, err)
	}
	if err := m.Apply(ctx, addrs("127.0.0.153")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if overridden, err := m.Overridden(ctx); err != nil || !overridden {
		t.Fatalf("Overridden = %v, %v right after applying", overridden, err)
	}

	// Somebody else has since pointed every service elsewhere: the record still says
	// app-tail changed the machine, and the machine says nothing of app-tail's is in force.
	machine.current["wifi-id"] = addrs("10.9.9.9")
	machine.current["eth-id"] = addrs("10.9.9.9")
	if overridden, err := m.Overridden(ctx); err != nil || overridden {
		t.Errorf("Overridden = %v, %v after every service was changed underneath the record", overridden, err)
	}

	// One service still pointed at app-tail is enough: that one resolves nothing.
	machine.current["eth-id"] = addrs("127.0.0.153")
	if overridden, err := m.Overridden(ctx); err != nil || !overridden {
		t.Errorf("Overridden = %v, %v with one service still pointed at app-tail", overridden, err)
	}

	// A service that cannot be read is not what is stopping this machine resolving names.
	machine.getErr["eth-id"] = errors.New("the adapter is not present")
	if overridden, err := m.Overridden(ctx); err != nil || overridden {
		t.Errorf("Overridden = %v, %v when the only service pointed at app-tail is unreachable", overridden, err)
	}

	// And a platform that cannot drive its resolver has nothing of app-tail's in force.
	delete(machine.getErr, "eth-id")
	machine.unsupport = "no resolver this app can drive"
	if overridden, err := m.Overridden(ctx); err != nil || overridden {
		t.Errorf("Overridden = %v, %v on a platform that cannot be changed", overridden, err)
	}
}

// The address app-tail listens on is machine state on macOS: it is added to the loopback
// interface, and a restore that put the resolver back and left the address behind would
// leave this machine carrying an address nobody asked it to have.
func TestTheLoopbackAddressIsGivenBackWhenTheResolverIsPutBack(t *testing.T) {
	m, machine := newTestManager(t)
	ctx := context.Background()
	listen := netip.MustParseAddr("127.0.0.153")
	if err := m.HoldLoopback(ctx, listen); err != nil {
		t.Fatalf("HoldLoopback: %v", err)
	}
	if err := m.Apply(ctx, []netip.Addr{listen}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !slices.Equal(machine.held, []netip.Addr{listen}) {
		t.Fatalf("this machine's loopback carries %v, want %v", machine.held, listen)
	}

	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(machine.held) != 0 {
		t.Errorf("this machine's loopback still carries %v after the restore", machine.held)
	}
	rec, err := m.readRecord()
	if err != nil {
		t.Fatalf("readRecord: %v", err)
	}
	if !rec.empty() {
		t.Errorf("the record still holds %+v after the restore", rec)
	}
}

// The order is the whole point: a machine still pointed at the address whose alias has gone
// resolves no names at all.
func TestTheResolverIsPutBackBeforeTheLoopbackAddressGoes(t *testing.T) {
	m, machine := newTestManager(t)
	ctx := context.Background()
	listen := netip.MustParseAddr("127.0.0.153")
	machine.current["wifi-id"] = addrs("192.168.6.1")
	if err := m.HoldLoopback(ctx, listen); err != nil {
		t.Fatalf("HoldLoopback: %v", err)
	}
	if err := m.Apply(ctx, []netip.Addr{listen}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	machine.writes = nil

	if err := m.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(machine.writes) == 0 {
		t.Fatal("nothing was written back to any service")
	}
	if len(machine.released) == 0 {
		t.Fatal("the loopback address was never given back")
	}
	// The fake records both in call order, and every write happened before the release.
	if machine.writesAfterRelease {
		t.Error("a service was pointed back after the loopback address had already gone")
	}
}

// Recorded before it is added, so a crash between the two still leaves something that knows
// to take the address off this machine.
func TestTheLoopbackAddressIsRecordedBeforeItIsAdded(t *testing.T) {
	m, machine := newTestManager(t)
	machine.holdErr = errors.New("ifconfig refused")

	listen := netip.MustParseAddr("127.0.0.153")
	if err := m.HoldLoopback(context.Background(), listen); err == nil {
		t.Fatal("HoldLoopback = nil error although the machine refused")
	}
	rec, err := m.readRecord()
	if err != nil {
		t.Fatalf("readRecord: %v", err)
	}
	if !slices.Contains(rec.Loopback, listen.String()) {
		t.Errorf("the record holds %v, want it to name the address before it was added", rec.Loopback)
	}
	// An address on the loopback interface changes no name resolution by itself, so a
	// record holding only that must not read as "this machine is pointed at app-tail".
	installed, err := m.Installed()
	if err != nil {
		t.Fatalf("Installed: %v", err)
	}
	if installed {
		t.Error("Installed = true with only a loopback address recorded")
	}
}

func TestHoldLoopbackRefusesAnAddressThatIsNotThisMachinesOwn(t *testing.T) {
	m, machine := newTestManager(t)
	err := m.HoldLoopback(context.Background(), netip.MustParseAddr("192.168.6.1"))
	if err == nil {
		t.Fatal("HoldLoopback = nil error for an address off this machine")
	}
	if len(machine.held) != 0 {
		t.Errorf("this machine's loopback carries %v after a refused request", machine.held)
	}
}

func TestApplyRefusesWhenThisPlatformCannotBeChanged(t *testing.T) {
	m, machine := newTestManager(t)
	machine.unsupport = "no resolver this app can drive"
	err := m.Apply(context.Background(), addrs("127.0.0.153"))
	if err == nil {
		t.Fatal("Apply = nil error on a platform that cannot be changed")
	}
	if !strings.Contains(err.Error(), "no resolver this app can drive") {
		t.Errorf("Apply = %q, want it to carry the platform's own reason", err)
	}
}

// Forwarding to our own address, or to a tailnet client's, is a query that comes back to
// us. Those are not a base to fall back on.
func TestBaseLeavesOutTheAddressesThatWouldLoopBack(t *testing.T) {
	m, machine := newTestManager(t)
	machine.published["wifi-id"] = Base{
		Nameservers:   addrs("127.0.0.153", "100.100.100.100", "192.168.6.1", "::"),
		SearchDomains: []string{"lan", ""},
	}
	machine.published["eth-id"] = Base{
		// The same resolver on a second service is one resolver, not two.
		Nameservers:   addrs("192.168.6.1", "10.0.0.1"),
		SearchDomains: []string{"lan", "corp.example.com"},
	}

	base, err := m.Base(context.Background())
	if err != nil {
		t.Fatalf("Base: %v", err)
	}
	if want := addrs("192.168.6.1", "10.0.0.1"); !slices.Equal(base.Nameservers, want) {
		t.Errorf("base nameservers = %v, want %v", base.Nameservers, want)
	}
	if want := []string{"lan", "corp.example.com"}; !slices.Equal(base.SearchDomains, want) {
		t.Errorf("base search domains = %v, want %v", base.SearchDomains, want)
	}
}

func TestClearWithNothingAppliedChangesNothing(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	if err := m.Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(machine.writes) != 0 {
		t.Errorf("Clear wrote %v with nothing ever applied", machine.writes)
	}
}

func TestPlanSkipsAServiceThatAlreadyResolvesThroughAppTail(t *testing.T) {
	want := addrs("127.0.0.153")
	states := []state{
		{Service: Service{ID: "a", Name: "A"}, Current: want},
		{Service: Service{ID: "b", Name: "B"}, Current: addrs("192.168.6.1")},
	}
	changes := plan(states, want, record{Services: map[string]serviceRecord{
		"a": {Name: "A", Prior: []string{"192.168.6.1"}, Wrote: []string{"127.0.0.153"}},
	}})
	if len(changes) != 2 {
		t.Fatalf("plan produced %d changes, want one per service", len(changes))
	}
	if changes[0].Skip == "" {
		t.Error("a service already resolving through app-tail was written again, which costs a shell-out to change nothing")
	}
	if changes[1].Skip != "" {
		t.Errorf("a service resolving elsewhere was skipped: %s", changes[1].Skip)
	}
	// The skipped service still carries its prior into the record, or switching the module
	// off would leave the override in place with nothing saying it was ours.
	next := merge(record{}, changes)
	if got := next.Services["a"].Prior; !slices.Equal(got, []string{"192.168.6.1"}) {
		t.Errorf("the record for the skipped service says the prior was %v", got)
	}
}

// The record is a list of addresses an elevated process points this machine at later, so a
// record it cannot read is refused rather than read as "nothing was ever applied" -- which
// would abandon whatever is on the machine now and lose the user's own resolvers with it.
func TestARecordThatCannotBeReadIsRefusedRatherThanTreatedAsEmpty(t *testing.T) {
	m, _ := newTestManager(t)
	if err := os.WriteFile(m.recordPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write the record: %v", err)
	}

	_, err := m.readRecord()
	if err == nil {
		t.Fatal("a record that is not readable was read as an empty one")
	}
	// The path is the only thing that says which file to look at, and it differs per platform.
	if !strings.Contains(err.Error(), m.recordPath) {
		t.Errorf("err = %v, want it to name the file at %s", err, m.recordPath)
	}

	// A machine nothing has been applied to has no record at all, and that is the ordinary
	// state rather than a failure.
	if err := os.Remove(m.recordPath); err != nil {
		t.Fatalf("remove the record: %v", err)
	}
	rec, err := m.readRecord()
	if err != nil {
		t.Fatalf("readRecord with no record: %v", err)
	}
	if !rec.empty() {
		t.Errorf("a machine with no record read as %v", rec)
	}
}

// Apply records before it writes, so a record that cannot be written stops the apply: the
// alternative is an override on the machine with nothing remembering what it replaced.
func TestARecordThatCannotBeWrittenStopsTheChange(t *testing.T) {
	m, machine := newTestManager(t)
	// A file where the record's directory has to be: making the directory fails, which is the
	// same refusal a read-only or full disk gives.
	blocker := filepath.Join(t.TempDir(), "in-the-way")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write the blocker: %v", err)
	}
	m.recordPath = filepath.Join(blocker, RecordFileName)

	if err := m.Apply(context.Background(), addrs("127.0.0.153")); err == nil {
		t.Fatal("an apply that could not be recorded reported success")
	}
	if len(machine.writes) != 0 {
		t.Errorf("this machine was pointed at %v with nothing recording what it replaced", machine.writes)
	}
}

// A write that fails partway must leave the previous record intact: it names the resolvers
// this machine is put back to, and a half-written one parses as nothing, which is the same
// as having none at all.
func TestAFailedWriteLeavesThePreviousRecordReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("every write of the record rewrites the access list of its directory, so no directory stays closed to it on Windows")
	}
	m, _ := newTestManager(t)
	if err := m.writeRecord(record{Services: map[string]serviceRecord{
		"Wi-Fi": {Prior: []string{"192.168.1.1"}},
	}}); err != nil {
		t.Fatalf("write the first record: %v", err)
	}

	// A directory where the temporary file has to be created: the replacement cannot be
	// written, which is the refusal a full or read-only disk gives.
	if err := os.Chmod(filepath.Dir(m.recordPath), 0o500); err != nil {
		t.Fatalf("narrow the record directory: %v", err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Dir(m.recordPath), 0o700) })

	if err := m.writeRecord(record{Services: map[string]serviceRecord{
		"Wi-Fi": {Prior: []string{"10.0.0.1"}},
	}}); err == nil {
		t.Fatal("a record that could not be written reported success")
	}
	if err := os.Chmod(filepath.Dir(m.recordPath), 0o700); err != nil {
		t.Fatalf("widen the record directory: %v", err)
	}

	rec, err := m.readRecord()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if got := rec.Services["Wi-Fi"].Prior; !slices.Equal(got, []string{"192.168.1.1"}) {
		t.Fatalf("the failed write destroyed the previous record: prior = %v", got)
	}
}

// Removing a record that is not there is the state removing wants. Reporting it would leave
// Clear failing forever on a machine that is already back to its own resolvers.
func TestRemovingARecordThatIsNotThereIsNotAFailure(t *testing.T) {
	m, _ := newTestManager(t)

	if err := m.removeRecord(); err != nil {
		t.Errorf("removing a record that was never written reported %v", err)
	}
}

// An address app-tail added to this machine's loopback is machine state, and giving it back
// is what a restore is for. A refusal has to reach the caller: the record is only dropped
// when the machine is actually back the way it was.
func TestALoopbackAddressThatCouldNotBeGivenBackIsReported(t *testing.T) {
	m, machine := newTestManager(t)
	machine.releaseErr = errors.New("the interface would not give it up")

	err := m.releaseLoopback(context.Background(), record{Loopback: []string{"127.0.0.153"}})
	if err == nil {
		t.Fatal("an address the machine would not give back was reported as gone")
	}
	if !strings.Contains(err.Error(), "127.0.0.153") {
		t.Errorf("err = %v, want it to name the address still on this machine", err)
	}
}

// A record written by a newer build, or corrupted in place, can carry something that is not
// an address. Every other address in it still has to be given back, or one bad entry keeps
// the rest on the machine forever.
func TestOneUnreadableRecordedAddressDoesNotStopTheRest(t *testing.T) {
	m, machine := newTestManager(t)

	err := m.releaseLoopback(context.Background(), record{Loopback: []string{"not-an-address", "127.0.0.153"}})
	if err == nil {
		t.Fatal("a recorded entry that is not an address was passed over in silence")
	}
	if !slices.Equal(machine.released, addrs("127.0.0.153")) {
		t.Errorf("the machine gave back %v, want the addresses that could be read", machine.released)
	}
}

// New is what every caller outside this package uses, and its two defaults are the ones a
// mistake is silent in: a record written somewhere a user can edit, and a nil log function
// that panics on the first thing worth saying.
func TestAManagerBuiltWithNoPathWritesWhereThePlatformKeepsItsRecord(t *testing.T) {
	m := New("", nil)

	if m.recordPath != DefaultRecordPath() {
		t.Errorf("the record path is %q, want the platform's own %q", m.recordPath, DefaultRecordPath())
	}
	m.logf("a manager built with no log function still logs: %s", "safely")

	chosen := filepath.Join(t.TempDir(), RecordFileName)
	if got := New(chosen, nil); got.recordPath != chosen {
		t.Errorf("the record path is %q, want the chosen %q", got.recordPath, chosen)
	}
}

// Supported is what the card and the CLI read before offering the switch at all, and the
// reason is shown to the user. Answering for the platform rather than asking the machine
// would offer a switch that fails at the moment it is used.
func TestWhetherThisMachinesResolverCanBeChangedComesFromTheMachine(t *testing.T) {
	m, machine := newTestManager(t)

	if ok, reason := m.Supported(); !ok {
		t.Errorf("a machine that can be changed reported %q", reason)
	}
	machine.unsupport = "systemd-resolved is not running here"
	ok, reason := m.Supported()
	if ok {
		t.Fatal("a machine that cannot be changed reported that it can")
	}
	if reason != machine.unsupport {
		t.Errorf("reason = %q, want the machine's own %q", reason, machine.unsupport)
	}
}

// A machine that crashed with the override in place and no record naming one of its services
// -- a run killed between its change and its write, a record lost while the override stood --
// is still pointed at a loopback address nothing listens on after the reboot. Clear has
// nothing to go on there, and that service resolves no names until something notices it.
func TestAServiceLeftPointedAtAppTailWithNoRecordIsHandedBackToTheNetwork(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("127.0.0.154")
	machine.current["eth-id"] = addrs("10.0.0.1")

	released, err := m.ReleaseStrays(context.Background(), addrs("127.0.0.153", "127.0.0.154", "127.0.0.155"))
	if err != nil {
		t.Fatalf("ReleaseStrays: %v", err)
	}
	if !slices.Equal(released, []string{"Wi-Fi"}) {
		t.Errorf("released %v, want only Wi-Fi", released)
	}
	if got, ok := machine.current["wifi-id"]; ok {
		t.Errorf("Wi-Fi still resolves through %v, want it following its network again", got)
	}
	if got := machine.current["eth-id"]; !slices.Equal(got, addrs("10.0.0.1")) {
		t.Errorf("Ethernet resolves through %v, want the user's own 10.0.0.1 left alone", got)
	}
	if machine.flushes != 1 {
		t.Errorf("the resolver cache was flushed %d times, want once", machine.flushes)
	}
}

// A list that mixes one of app-tail's addresses with anything else is a setting somebody
// wrote on purpose, and so is one pointed at a loopback address app-tail never uses: a local
// dnsmasq on 127.0.0.1 is the common case. Neither is a stray.
func TestASettingThatIsNotEntirelyAppTailsIsNeverReleased(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("127.0.0.154", "1.1.1.1")
	machine.current["eth-id"] = addrs("127.0.0.1")

	released, err := m.ReleaseStrays(context.Background(), addrs("127.0.0.153", "127.0.0.154", "127.0.0.155"))
	if err != nil {
		t.Fatalf("ReleaseStrays: %v", err)
	}
	if len(released) != 0 || len(machine.writes) != 0 {
		t.Errorf("released %v and wrote %v, want nothing touched", released, machine.writes)
	}
}

// The record knows what each service had before, which is better than the network's own. A
// sweep that got to a recorded service first would throw that away.
func TestAServiceTheRecordStillNamesIsLeftToTheRestore(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("192.168.6.1")
	ctx := context.Background()
	if err := m.Apply(ctx, addrs("127.0.0.154")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	machine.writes = nil

	released, err := m.ReleaseStrays(ctx, addrs("127.0.0.154"))
	if err != nil {
		t.Fatalf("ReleaseStrays: %v", err)
	}
	if len(released) != 0 || len(machine.writes) != 0 {
		t.Errorf("released %v and wrote %v, want recorded services left for Clear", released, machine.writes)
	}
}

// app-tail moves between addresses when its answers change, and every one it used is in the
// record. A service a crash left on an older one is as much a stray as one on the fallbacks.
func TestAnAddressTheRecordSaysAppTailUsedCountsAsOurs(t *testing.T) {
	m, machine := newTestManager(t)
	if err := m.writeRecord(record{Services: map[string]serviceRecord{}, Ours: []string{"127.0.0.42"}, Loopback: []string{"127.0.0.42"}}); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}
	machine.current["wifi-id"] = addrs("127.0.0.42")

	released, err := m.ReleaseStrays(context.Background(), addrs("127.0.0.153"))
	if err != nil {
		t.Fatalf("ReleaseStrays: %v", err)
	}
	if !slices.Equal(released, []string{"Wi-Fi"}) {
		t.Errorf("released %v, want Wi-Fi, which is on an address the record says app-tail used", released)
	}
}

// One service that cannot be read or written must not stop the others being repaired, and
// the failure has to reach the caller rather than read as a clean pass.
func TestOneServiceThatCannotBeReleasedDoesNotStopTheRest(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("127.0.0.154")
	machine.current["eth-id"] = addrs("127.0.0.154")
	machine.setErr["eth-id"] = errors.New("networksetup could not take the preferences lock")

	released, err := m.ReleaseStrays(context.Background(), addrs("127.0.0.154"))
	if err == nil {
		t.Fatal("ReleaseStrays reported success with a service still pointed at app-tail")
	}
	if !slices.Equal(released, []string{"Wi-Fi"}) {
		t.Errorf("released %v, want Wi-Fi despite Ethernet failing", released)
	}
}

// The lock is the one fact a repair can trust about whether an app-tail is serving this
// machine, so a second holder must be refused while the first lives -- including a second
// holder in the same process, which is what the helper's watch is to its own sessions.
func TestOnlyOneHolderServesTheResolverAtATime(t *testing.T) {
	record := filepath.Join(t.TempDir(), "app-tail", RecordFileName)

	first, held, err := TryHoldServing(record)
	if err != nil || !held {
		t.Fatalf("first hold: held = %v, err = %v", held, err)
	}
	if _, held, err := TryHoldServing(record); err != nil || held {
		t.Fatalf("a second holder got the lock while the first held it (held = %v, err = %v)", held, err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	again, held, err := TryHoldServing(record)
	if err != nil || !held {
		t.Fatalf("the lock was not free after its holder let go (held = %v, err = %v)", held, err)
	}
	if err := again.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
}

func TestNoServingLockWithoutARecordPath(t *testing.T) {
	if _, held, err := TryHoldServing(""); err == nil || held {
		t.Fatalf("TryHoldServing(\"\") = held %v, err %v; want a refusal", held, err)
	}
}

// A service whose setting cannot be read cannot be shown to be app-tail's, so it is not
// app-tail's to change, and it is no failure of the sweep either. Counting it as one would
// make the helper's uninstall refuse over an adapter that has nothing to do with app-tail.
func TestAServiceThatCannotBeReadIsSkippedRatherThanFailingTheSweep(t *testing.T) {
	m, machine := newTestManager(t)
	machine.current["wifi-id"] = addrs("127.0.0.154")
	machine.getErr["eth-id"] = errors.New("scutil: the adapter went away")

	released, err := m.ReleaseStrays(context.Background(), addrs("127.0.0.154"))
	if err != nil {
		t.Fatalf("ReleaseStrays = %v, want an unreadable unrelated service skipped", err)
	}
	if !slices.Equal(released, []string{"Wi-Fi"}) {
		t.Errorf("released %v, want Wi-Fi", released)
	}
}
