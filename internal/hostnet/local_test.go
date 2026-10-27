// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/sysdns"
)

// recordingSystemResolver stands in for this machine's own resolver, which the real one
// changes by shelling out as root. What it records is the order things were asked of it and
// of the other pieces a teardown touches, through the one log they share.
type recordingSystemResolver struct {
	log      *[]string
	applied  [][]netip.Addr
	clears   int
	applyErr error
	clearErr error
}

func (r *recordingSystemResolver) Apply(_ context.Context, addrs []netip.Addr) error {
	*r.log = append(*r.log, "apply")
	r.applied = append(r.applied, slices.Clone(addrs))
	return r.applyErr
}

func (r *recordingSystemResolver) Clear(context.Context) error {
	*r.log = append(*r.log, "clear")
	r.clears++
	return r.clearErr
}

func (r *recordingSystemResolver) Base(context.Context) (sysdns.Base, error) {
	return sysdns.Base{Nameservers: []netip.Addr{netip.MustParseAddr("192.168.6.1")}}, nil
}

func (r *recordingSystemResolver) HoldLoopback(context.Context, netip.Addr) error { return nil }

// loggingConfigurator and loggingRouter are the tailnet's own resolver and routes, noting
// into the same log when they are taken down.
type loggingConfigurator struct {
	recordingConfigurator
	log *[]string
}

func (c *loggingConfigurator) Close() error {
	*c.log = append(*c.log, "tailnet dns close")
	return nil
}

type loggingRouter struct {
	recordingRouter
	log *[]string
}

func (r *loggingRouter) Close() error {
	*r.log = append(*r.log, "routes close")
	return nil
}

// changedMachine is a session that has pointed this machine's resolver at app-tail and holds
// the tailnet's resolver and routes, with everything it will touch on the way out recording
// into log.
func changedMachine(t *testing.T) (*Local, *recordingSystemResolver, *[]string) {
	t.Helper()
	log := &[]string{}
	machine := &recordingSystemResolver{log: log}
	local := &Local{
		logf:   func(string, ...any) {},
		sysdns: machine,
		dns:    &loggingConfigurator{log: log},
		router: &loggingRouter{log: log},
	}
	if err := local.SetSystemDNS(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		t.Fatalf("SetSystemDNS: %v", err)
	}
	return local, machine, log
}

var _ dns.OSConfigurator = (*loggingConfigurator)(nil)
var _ router.Router = (*loggingRouter)(nil)

// Pointing the machine at app-tail and putting it back both go through the machine's own
// resolver, and the session remembers which state it is in: a restore is asked for exactly
// when something was applied, and once put back by hand there is nothing left for the
// teardown to do.
func TestTheSessionPutsBackWhatItAppliedAndOnlyThat(t *testing.T) {
	local, machine, _ := changedMachine(t)
	ctx := context.Background()

	if want := []netip.Addr{netip.MustParseAddr("127.0.0.153")}; len(machine.applied) != 1 || !slices.Equal(machine.applied[0], want) {
		t.Fatalf("the machine was pointed at %v, want %v once", machine.applied, want)
	}
	if !local.systemDNSApplied {
		t.Fatal("the session does not remember having changed this machine's resolver")
	}

	if err := local.SetSystemDNS(ctx, nil); err != nil {
		t.Fatalf("SetSystemDNS(nil): %v", err)
	}
	if machine.clears != 1 {
		t.Errorf("an empty list put the machine back %d times, want once", machine.clears)
	}
	if local.systemDNSApplied {
		t.Error("the session still believes it has changed this machine's resolver after putting it back")
	}

	if err := local.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if machine.clears != 1 {
		t.Errorf("the teardown put back a machine that was already put back: %d clears", machine.clears)
	}
}

// The teardown puts this machine's resolver back before anything else goes, the tailnet's
// own resolver and routes included: a machine pointed at app-tail while app-tail is being
// taken down resolves nothing, and every step after this one may look up a name.
func TestTheTeardownPutsTheResolverBackBeforeAnythingElseGoes(t *testing.T) {
	local, machine, log := changedMachine(t)

	if err := local.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := []string{"apply", "clear", "tailnet dns close", "routes close"}
	if !slices.Equal(*log, want) {
		t.Errorf("the teardown ran %v, want %v", *log, want)
	}
	if machine.clears != 1 || local.systemDNSApplied {
		t.Errorf("clears = %d, applied = %v after the teardown; want one clear and nothing left applied",
			machine.clears, local.systemDNSApplied)
	}
}

// A machine that refuses to be put back is reported, by name, and the rest of the teardown
// still runs: the routes and the tailnet's resolver come back on their own when the process
// dies, so there is no reason to hold them for a failure that has nothing to do with them.
func TestAMachineThatRefusesToBePutBackIsReportedAndTheRestStillGoes(t *testing.T) {
	local, machine, log := changedMachine(t)
	machine.clearErr = errors.New("networksetup refused to change Wi-Fi")

	err := local.Close()

	if err == nil {
		t.Fatal("Close reported a clean teardown over a machine still pointed at app-tail")
	}
	if !strings.Contains(err.Error(), "restore this machine's resolver") || !strings.Contains(err.Error(), "networksetup refused") {
		t.Errorf("Close = %v, want it to name the resolver and what the machine said", err)
	}
	for _, step := range []string{"tailnet dns close", "routes close"} {
		if !slices.Contains(*log, step) {
			t.Errorf("%q was skipped after the resolver refused; the teardown ran %v", step, *log)
		}
	}
}

// A change that failed partway has already changed some of this machine's services, so the
// session counts it as applied: the teardown that believed nothing had landed would leave
// those services pointed at app-tail.
func TestAChangeThatFailedPartwayIsStillPutBackOnTheWayOut(t *testing.T) {
	log := &[]string{}
	machine := &recordingSystemResolver{log: log, applyErr: errors.New("Ethernet refused the write")}
	local := &Local{logf: func(string, ...any) {}, sysdns: machine}

	err := local.SetSystemDNS(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.153")})
	if err == nil || !strings.Contains(err.Error(), "Ethernet refused") {
		t.Fatalf("SetSystemDNS = %v, want the machine's refusal", err)
	}
	if !local.systemDNSApplied {
		t.Fatal("a change that failed partway is recorded as never having happened")
	}

	if err := local.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if machine.clears != 1 {
		t.Errorf("the teardown put the machine back %d times after a change that failed partway, want once", machine.clears)
	}
}

// A restore asked for by hand that fails leaves the session still counting the machine as
// changed, so the teardown tries once more rather than trusting a restore that did not land.
func TestARestoreThatFailedIsTriedAgainByTheTeardown(t *testing.T) {
	local, machine, _ := changedMachine(t)
	machine.clearErr = errors.New("the resolver settings are locked")

	if err := local.SetSystemDNS(context.Background(), nil); err == nil {
		t.Fatal("a restore the machine refused was reported as done")
	}
	if !local.systemDNSApplied {
		t.Fatal("a restore that failed cleared the session's memory of having changed the machine")
	}

	machine.clearErr = nil
	if err := local.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if machine.clears != 2 {
		t.Errorf("clears = %d, want the failed restore and the teardown's retry", machine.clears)
	}
}

// What the machine resolves with on its own is read from the machine, not remembered here.
func TestTheBaseResolversAreReadFromTheMachine(t *testing.T) {
	local := &Local{logf: func(string, ...any) {}, sysdns: &recordingSystemResolver{log: &[]string{}}}

	base, err := local.BaseSystemDNS(context.Background())
	if err != nil {
		t.Fatalf("BaseSystemDNS: %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.168.6.1")}; !slices.Equal(base.Nameservers, want) {
		t.Errorf("base = %v, want %v", base.Nameservers, want)
	}
}

// The warning about a stale override is shown to a user who has not asked for anything, so
// it is exact: a record this process may not read is silence rather than a guess, any other
// failure is named because on Windows it is a real one, and a machine that has been put back
// gets nothing at all.
func TestTheStaleOverrideWarningSaysExactlyWhatIsKnown(t *testing.T) {
	cases := []struct {
		name       string
		overridden bool
		err        error
		want       string
	}{
		{name: "put back", overridden: false, want: ""},
		{name: "still pointed at app-tail", overridden: true, want: "still pointed at app-tail"},
		{name: "record this process may not read", err: fs.ErrPermission, want: ""},
		{name: "record wrapped in a path error", err: &fs.PathError{Op: "open", Path: "record.json", Err: fs.ErrPermission}, want: ""},
		{name: "record that cannot be read", err: errors.New("the record is not valid JSON"), want: "cannot tell"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := staleOverrideMessage(tc.overridden, tc.err)
			if tc.want == "" && got != "" {
				t.Fatalf("staleOverrideMessage = %q, want nothing", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("staleOverrideMessage = %q, want it to say %q", got, tc.want)
			}
			if tc.err != nil && tc.want != "" && !strings.Contains(got, tc.err.Error()) {
				t.Errorf("staleOverrideMessage = %q, want the failure carried", got)
			}
		})
	}
}

// Each platform's rule for a requested interface name, asked of both on every machine: the
// macOS rule is otherwise only ever exercised on a Mac, and the Linux one only on Linux. A
// name one platform's kernel would make is not necessarily one the other's would -- app-tail0
// is Linux's default and is no name macOS gives a tunnel.
func TestEachPlatformAcceptsOnlyTheInterfaceNamesItsKernelGives(t *testing.T) {
	tests := []struct {
		name, goos string
		ok         bool
	}{
		{"", "darwin", true},
		{"utun", "darwin", true},
		{"utun12", "darwin", true},
		{"utun-1", "darwin", false},
		{"app-tail0", "darwin", false},
		{"lo0", "darwin", false},
		{"", "linux", true},
		{"app-tail0", "linux", true},
		{"tun_vpn.1", "linux", true},
		{"tun/0", "linux", false},
		{"tun 0", "linux", false},
		{"tun\t0", "linux", false},
		{"-tun0", "linux", false},
		{strings.Repeat("t", maxInterfaceName), "linux", true},
		{strings.Repeat("t", maxInterfaceName+1), "linux", false},
	}
	for _, tc := range tests {
		err := validTUNName(tc.name, tc.goos)
		if (err == nil) != tc.ok {
			t.Errorf("validTUNName(%q, %s) = %v, want accepted=%v", tc.name, tc.goos, err, tc.ok)
		}
	}
}

// Where no helper runs at boot, a crash with the override in place leaves this machine
// pointed at an address nothing listens on until somebody opens app-tail again. The repair
// that runs at boot is set up before the override, so there is no moment the machine carries
// one without the other.
func TestTheBootRepairIsArmedBeforeTheMachineIsPointedAtAppTail(t *testing.T) {
	log := &[]string{}
	local := &Local{logf: func(string, ...any) {}, sysdns: &recordingSystemResolver{log: log}, bootRepair: func() error {
		*log = append(*log, "arm boot repair")
		return nil
	}}

	if err := local.SetSystemDNS(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		t.Fatalf("SetSystemDNS: %v", err)
	}
	if want := []string{"arm boot repair", "apply"}; !slices.Equal(*log, want) {
		t.Errorf("ran %v, want %v", *log, want)
	}
}

// A machine that could not be given its boot-time repair is a machine a crash strands, so
// the override is refused with the reason rather than put up without its way back.
func TestAMachineThatCouldNotBeGivenItsBootRepairIsNotPointedAtAppTail(t *testing.T) {
	machine := &recordingSystemResolver{log: &[]string{}}
	local := &Local{logf: func(string, ...any) {}, sysdns: machine, bootRepair: func() error {
		return errors.New("the Task Scheduler is not running")
	}}

	err := local.SetSystemDNS(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.153")})
	if err == nil || !strings.Contains(err.Error(), "Task Scheduler is not running") {
		t.Fatalf("SetSystemDNS = %v, want the reason the repair could not be set up", err)
	}
	if len(machine.applied) != 0 || local.systemDNSApplied {
		t.Error("the machine was pointed at app-tail with no repair in place for a crash")
	}
}

// Putting the machine back needs no way back of its own, and refusing a restore because the
// Task Scheduler is down would keep the machine pointed at app-tail for that reason alone.
func TestARestoreDoesNotWaitOnTheBootRepair(t *testing.T) {
	local, machine, _ := changedMachine(t)
	local.bootRepair = func() error { return errors.New("the Task Scheduler is not running") }

	if err := local.SetSystemDNS(t.Context(), nil); err != nil {
		t.Fatalf("SetSystemDNS(nil) = %v, want the restore to go ahead", err)
	}
	if machine.clears != 1 {
		t.Errorf("clears = %d, want 1", machine.clears)
	}
}

// servingLocal is a session whose serving lock notes into the machine's log, so a test reads
// in one list when the lock was taken and let go relative to the machine being changed.
func servingLocal(log *[]string, holdErr error) (*Local, *recordingSystemResolver) {
	machine := &recordingSystemResolver{log: log}
	return &Local{logf: func(string, ...any) {}, sysdns: machine, holdServing: func(context.Context) (func() error, error) {
		if holdErr != nil {
			return nil, holdErr
		}
		*log = append(*log, "hold")
		return func() error {
			*log = append(*log, "release")
			return nil
		}, nil
	}}, machine
}

// A root agent never talks to the helper, so the helper's repair cannot see its session. The
// serving lock is what it sees instead, and it has to be held before the machine is pointed
// at app-tail and for as long as it stays that way -- including across a second apply, which
// must not take it twice.
func TestTheServingLockIsHeldForExactlyAsLongAsTheOverride(t *testing.T) {
	log := &[]string{}
	local, _ := servingLocal(log, nil)
	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.153")}

	if err := local.SetSystemDNS(t.Context(), addrs); err != nil {
		t.Fatalf("SetSystemDNS: %v", err)
	}
	if err := local.SetSystemDNS(t.Context(), addrs); err != nil {
		t.Fatalf("second SetSystemDNS: %v", err)
	}
	if err := local.SetSystemDNS(t.Context(), nil); err != nil {
		t.Fatalf("SetSystemDNS(nil): %v", err)
	}
	if want := []string{"hold", "apply", "apply", "clear", "release"}; !slices.Equal(*log, want) {
		t.Errorf("ran %v, want %v", *log, want)
	}
}

// A restore that failed keeps the override, and with it the lock: a repair stepping in
// while this session still means to retry would race it.
func TestAFailedRestoreKeepsTheServingLock(t *testing.T) {
	log := &[]string{}
	local, machine := servingLocal(log, nil)
	if err := local.SetSystemDNS(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		t.Fatalf("SetSystemDNS: %v", err)
	}
	machine.clearErr = errors.New("networksetup exited 4")

	if err := local.SetSystemDNS(t.Context(), nil); err == nil {
		t.Fatal("a failed restore reported success")
	}
	if slices.Contains(*log, "release") {
		t.Error("the serving lock was given up while the override still stood")
	}
}

// A session going away gives the lock up even when its restore failed, because the repair
// it lets in is now the only thing that will finish the job.
func TestATeardownGivesTheServingLockUpEvenAfterAFailedRestore(t *testing.T) {
	log := &[]string{}
	local, machine := servingLocal(log, nil)
	if err := local.SetSystemDNS(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.153")}); err != nil {
		t.Fatalf("SetSystemDNS: %v", err)
	}
	machine.clearErr = errors.New("networksetup exited 4")

	_ = local.Close()
	if want := []string{"hold", "apply", "clear", "release"}; !slices.Equal(*log, want) {
		t.Errorf("ran %v, want %v", *log, want)
	}
}

// Without the lock a repair would take this override back within half a minute, so a
// session that cannot get it does not put one up.
func TestASessionThatCannotHoldTheServingLockDoesNotPointTheMachineAtAppTail(t *testing.T) {
	log := &[]string{}
	local, machine := servingLocal(log, errors.New("another app-tail is serving this machine's resolver"))

	err := local.SetSystemDNS(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.153")})
	if err == nil || !strings.Contains(err.Error(), "another app-tail is serving") {
		t.Fatalf("SetSystemDNS = %v, want the reason the lock could not be held", err)
	}
	if len(machine.applied) != 0 || local.systemDNSApplied {
		t.Error("the machine was pointed at app-tail without the lock that keeps a repair away")
	}
}
