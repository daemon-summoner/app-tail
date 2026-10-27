// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testLocal is a privileged side whose record of what it installed goes somewhere a test is
// allowed to write. The real one is a root-owned directory, and a suite that wrote there would
// be a suite that has to run as root and that leaves state behind on the machine running it.
func testLocal(t *testing.T) *Local {
	t.Helper()
	local := NewLocal(func(string, ...any) {})
	local.state = testRootState(t)
	return local
}

func testRootState(t *testing.T) *rootState {
	t.Helper()
	requireRecordWriter(t)
	return newRootState(filepath.Join(t.TempDir(), rootStateFileName), nil)
}

// The record is the one thing that survives this process, so what it is written as matters as
// much as what is in it: root reads it back and acts on every line, and a file another account
// can write is a list of things that account has decided root will do.
func TestWhatThisSideInstalledIsWrittenWhereOnlyRootCanChangeIt(t *testing.T) {
	state := testRootState(t)

	if err := state.setProcess("tn_rec0001", "/tmp/app-tail-openvpn-test", 4242); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	assertRecordNarrowed(t, state.path)

	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if got := rec.OpenVPN["tn_rec0001"]; got.PID != 4242 || got.Dir != "/tmp/app-tail-openvpn-test" {
		t.Errorf("the record holds %+v, want the directory and process number that were written", got)
	}
}

// A machine this side has taken everything back from must not be left with a file saying
// otherwise: the next start reads it, and a record naming state that is gone is a start that
// spends its time removing routes nothing has.
func TestTheRecordIsRemovedOnceThereIsNothingLeftInIt(t *testing.T) {
	state := testRootState(t)

	if err := state.setScope("tn_rec0002", "utun9"); err != nil {
		t.Fatalf("record a scoped route: %v", err)
	}
	if _, err := os.Stat(state.path); err != nil {
		t.Fatalf("the record was not written: %v", err)
	}

	if err := state.setScope("tn_rec0002", ""); err != nil {
		t.Fatalf("forget the scoped route: %v", err)
	}
	if _, err := os.Stat(state.path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record is still there with nothing in it (%v)", err)
	}

	// And a machine with no record at all is one with nothing to take back, rather than a
	// failure to read something that was never written.
	reclaimed, err := state.reclaim(t.Context())
	if err != nil {
		t.Errorf("reclaim on a machine with no record: %v", err)
	}
	if reclaimed {
		t.Error("a machine with no record was reported as having had something taken back")
	}
}

// The case the whole record exists for: a run that installed a route and never got to remove
// it. The next start has to take it back and stop carrying it forward, or every start after
// this one repeats the same removal.
func TestARouteAPreviousRunLeftIsTakenBackAndThenForgotten(t *testing.T) {
	if err := ScopedRoutesSupported(); err != nil {
		t.Skipf("this platform has no scoped routing, so there is no route to take back: %v", err)
	}
	state := testRootState(t)
	// An interface no longer on this machine, which is what the interface of an ended
	// connection is. Its routes went with it, so the removal succeeds without a routing table
	// this test has any right to change.
	gone := goneInterface(t)
	if err := state.setScope("tn_rec0003", gone); err != nil {
		t.Fatalf("record a scoped route: %v", err)
	}
	if err := state.setHostRoutes([]scopedHostRoute{{iface: gone, gateway: "192.0.2.1"}}); err != nil {
		t.Fatalf("record a copy of this machine's own default route: %v", err)
	}

	reclaimed, err := state.reclaim(t.Context())
	if err != nil {
		t.Fatalf("take back what a previous run left: %v", err)
	}
	if !reclaimed {
		t.Error("a record with two routes in it was reported as nothing to take back")
	}

	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if !rec.empty() {
		t.Errorf("the record still holds %+v after everything in it was taken back", rec)
	}
}

// The configuration carries a private key, and the run that would have removed it is the run
// that is gone. Nothing else on the machine will ever remove it, so the reclaim does -- whether
// or not there is still a process to stop.
func TestTheConfigurationAPreviousRunLeftBehindIsRemoved(t *testing.T) {
	state := testRootState(t)
	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-left")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}
	if err := os.WriteFile(openvpnConfigPath(dir, "tn_rec0004"), []byte("<key>secret</key>\n"), 0o600); err != nil {
		t.Fatalf("write a configuration standing in for a connection's own: %v", err)
	}
	// No process number: a run that stopped between writing the configuration and starting the
	// program, which is the one window where there is a directory and nothing holding it.
	if err := state.setProcess("tn_rec0004", dir, 0); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	if _, err := state.reclaim(t.Context()); err != nil {
		t.Fatalf("take back what a previous run left: %v", err)
	}

	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory holding a private key is still on the disk (%v)", err)
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if len(rec.OpenVPN) != 0 {
		t.Errorf("the record still holds %+v after the connection was taken back", rec.OpenVPN)
	}
}

// The reason the record cannot be acted on by process number alone. Numbers are reused, and
// this record outlives reboots -- so the number a previous run wrote down names whatever holds
// it now, which on the machine this runs on is somebody else's program. Signalling it would be
// this side killing a stranger on the strength of a file.
func TestAProcessNumberThatNowBelongsToSomethingElseIsLeftAlone(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections, so it records none")
	}
	state := testRootState(t)
	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-reused")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}

	// A process that is running and is not the one that was recorded: nothing in what it was
	// started with names this connection's configuration.
	stranger, exited := startStandInProcess(t)
	if err := state.setProcess("tn_rec0005", dir, stranger.Process.Pid); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	if _, err := state.reclaim(t.Context()); err != nil {
		t.Fatalf("take back what a previous run left: %v", err)
	}

	select {
	case <-exited:
		t.Fatal("a process that was never started by app-tail was killed on the strength of its number")
	case <-time.After(200 * time.Millisecond):
	}
	if !processAlive(stranger.Process.Pid) {
		t.Error("a process that was never started by app-tail is no longer running")
	}
}

// The other half: a process that IS the one recorded has to be stopped. It holds a network
// interface and routes on this machine, and the run that was supervising it is gone -- which
// is exactly the privileged process outliving its supervisor that this side exists to prevent.
func TestTheOpenVPNAPreviousRunLeftRunningIsStopped(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections, so it records none")
	}
	state := testRootState(t)
	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-running")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}

	// Started with this connection's configuration path among its arguments, which is what
	// identifies it as the process that was recorded rather than as the number it holds.
	held, exited := startStandInProcess(t, openvpnConfigPath(dir, "tn_rec0006"))
	if err := state.setProcess("tn_rec0006", dir, held.Process.Pid); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	if _, err := state.reclaim(t.Context()); err != nil {
		t.Fatalf("take back what a previous run left: %v", err)
	}

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the process a previous run left running is still running")
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if len(rec.OpenVPN) != 0 {
		t.Errorf("the record still holds %+v after the connection was stopped", rec.OpenVPN)
	}
}

// A record that cannot be read is reported, never taken as an empty one. Read as empty, every
// route and process a previous run left would stay on this machine with nothing naming it any
// more -- the state the record exists to prevent, reached in silence and reported as success.
func TestARecordThatCannotBeReadIsReportedRatherThanTakenAsEmpty(t *testing.T) {
	state := testRootState(t)
	if err := os.WriteFile(state.path, []byte("{not a record"), 0o600); err != nil {
		t.Fatalf("write a record that cannot be read: %v", err)
	}

	took, err := state.reclaim(t.Context())

	if err == nil {
		t.Fatal("a record that could not be read was taken as an empty one")
	}
	if !strings.Contains(err.Error(), state.path) {
		t.Errorf("the reason given is %q, want it to name the file at %s", err, state.path)
	}
	if took {
		t.Error("a record that could not be read was reported as one that was taken back")
	}
}

// Asking comes first because openvpn answers it by telling its server the client is leaving,
// but the ask is not what this side depends on: a process that ignores it is a root process
// holding an interface and a default route with nothing supervising it, which is the state the
// reclaim exists to end rather than to report.
func TestAnOpenVPNThatWillNotCloseIsKilled(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform runs no OpenVPN connections, so it records none")
	}
	state := testRootState(t)
	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-stubborn")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}

	held, exited := startStandInProcessWith(t, []string{standInIgnoresTermVar + "=1"},
		openvpnConfigPath(dir, "tn_rec0008"))
	if err := state.setProcess("tn_rec0008", dir, held.Process.Pid); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	if _, err := state.reclaim(t.Context()); err != nil {
		t.Fatalf("take back what a previous run left: %v", err)
	}

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("a process that ignored being asked to close is still running")
	}
}

// startStandInProcess runs a process that stays up until it is stopped, with args among what it
// was started with. It stands in for an openvpn a previous run left behind.
//
// The returned channel closes when it exits. It is closed by a goroutine waiting on the
// process, because this test is its parent: a process whose parent has not waited on it is
// still listed on the machine after it dies, and the reclaim asking whether it is gone would be
// told it is not. In the case this stands for, the parent is the run that ended and the machine
// has already cleared it away.
func startStandInProcess(t *testing.T, args ...string) (*exec.Cmd, <-chan struct{}) {
	t.Helper()
	return startStandInProcessWith(t, nil, args...)
}

// startStandInProcessWith is startStandInProcess with more of the environment set, which is how
// the program it runs is told to ignore being asked to close.
func startStandInProcessWith(t *testing.T, env []string, args ...string) (*exec.Cmd, <-chan struct{}) {
	t.Helper()

	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(testBinary(t), append([]string{"-test.run=^TestStandInProcess$"}, args...)...) //nolint:gosec // the test binary itself
	cmd.Env = append(append(os.Environ(), standInProcessVar+"=1", standInReadyVar+"="+ready), env...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start a process to stand in for one a previous run left: %v", err)
	}

	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})

	// Started is not yet running, and the difference decides cases: the reclaim reads what the
	// process was started with, and one of these processes is meant to be ignoring the ask to
	// close by the time it is asked. The file is written once it is doing both.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("the process standing in for one a previous run left never started")
		}
		time.Sleep(time.Millisecond)
	}
	return cmd, exited
}

const (
	standInProcessVar     = "APPTAIL_STAND_IN_PROCESS"
	standInIgnoresTermVar = "APPTAIL_STAND_IN_IGNORES_TERM"
	standInReadyVar       = "APPTAIL_STAND_IN_READY"
)

// TestStandInProcess is not a test. It is the program startStandInProcess runs, which needs to
// be a real process on this machine that outlives the call that started it; go test builds one
// binary and this is how a test gets a second process out of it.
func TestStandInProcess(t *testing.T) {
	if os.Getenv(standInProcessVar) != "1" {
		t.Skip("this is the program the reclaim tests start, not a test")
	}
	if os.Getenv(standInIgnoresTermVar) == "1" {
		// Watching the signal is what stops it killing this process, which is what a program
		// that will not answer the ask to close looks like from the outside.
		signal.Notify(make(chan os.Signal, 1), syscall.SIGTERM)
	}
	if err := os.WriteFile(os.Getenv(standInReadyVar), nil, 0o600); err != nil {
		t.Fatalf("say that the process standing in for one a previous run left is ready: %v", err)
	}
	// Longer than any test that starts it, which stops it rather than waiting for this.
	time.Sleep(time.Minute)
}

// The identification has to work on whatever this platform gives back, so it is read from a
// process this test started rather than assumed: a reader that returned nothing, or that cut
// the line short of the configuration path, would make every recorded process look like a
// stranger and nothing would ever be stopped.
func TestWhatAProcessWasStartedWithCanBeReadBack(t *testing.T) {
	if !OpenVPNSupported() {
		t.Skip("this platform reads no process arguments, since it records no processes")
	}
	// Long enough to sit past the width a terminal-shaped reader would cut a line at, which is
	// where a real connection's configuration path sits.
	marker := filepath.Join(t.TempDir(), strings.Repeat("d", 90), "tn_rec0007.conf")
	cmd, _ := startStandInProcess(t, marker)

	args, err := processArgs(t.Context(), cmd.Process.Pid)
	if err != nil {
		t.Fatalf("read what a running process was started with: %v", err)
	}
	if !strings.Contains(args, marker) {
		t.Errorf("what the process was started with reads %q, want it to carry %q", args, marker)
	}
}

// closedRootState is a record in a place this process cannot write. That is what a full disk,
// a read-only filesystem or a directory somebody else re-made looks like from in here.
//
// An empty record is put there first: what is sealed is the record and the directory it
// sits in, and how each platform seals them is in sealRecord.
func closedRootState(t *testing.T) *rootState {
	t.Helper()
	requireRecordWriter(t)
	dir := filepath.Join(t.TempDir(), "closed")
	if err := os.Mkdir(dir, stateDirMode); err != nil {
		t.Fatalf("make a directory for the record: %v", err)
	}
	state := newRootState(filepath.Join(dir, rootStateFileName), nil)
	if err := os.WriteFile(state.path, []byte("{}\n"), stateFileMode); err != nil {
		t.Fatalf("write an empty record: %v", err)
	}
	sealRecord(t, state.path)
	return state
}

// A record that could not be written is the case the whole file exists to cover, arriving at
// the worst moment. Reported as success it would be this side installing something on the
// machine believing the note that says how to take it back is on the disk, when it is not.
func TestARecordThatCannotBeWrittenIsReported(t *testing.T) {
	state := closedRootState(t)

	err := state.setProcess("tn_rec0009", "/tmp/app-tail-openvpn-closed", 4242)

	if err == nil {
		t.Fatal("a record that was never written was reported as written")
	}
	if !strings.Contains(err.Error(), "write the record") {
		t.Errorf("the reason given is %q, want it to say the record could not be written", err)
	}
}

// The same, one step earlier: the directory the record lives in is made on first use, and a
// machine where it cannot be made is one where nothing will ever be written down.
func TestARecordWhoseDirectoryCannotBeMadeIsReported(t *testing.T) {
	state := unmakeableRootState(t)

	err := state.setScope("tn_rec0010", "utun9990")

	if err == nil {
		t.Fatal("a record with nowhere to live was reported as written")
	}
	if !strings.Contains(err.Error(), "make the directory") {
		t.Errorf("the reason given is %q, want it to say the directory could not be made", err)
	}
}

// Emptying the record removes the file, and a removal that failed leaves a file naming state
// that is gone. Passed over in silence, the next start reads it and works through routes and
// processes that no longer exist -- for as long as the file stays there, which is forever.
func TestARecordThatCannotBeRemovedIsReported(t *testing.T) {
	state := testRootState(t)
	if err := state.setProcess("tn_rec0011", "/tmp/app-tail-openvpn-stuck", 4242); err != nil {
		t.Fatalf("record a connection: %v", err)
	}
	sealRecord(t, state.path)

	err := state.dropProcess("tn_rec0011")

	if err == nil {
		t.Fatal("a record that is still on the disk was reported as removed")
	}
	if !strings.Contains(err.Error(), "remove the record") {
		t.Errorf("the reason given is %q, want it to say the record could not be removed", err)
	}
}

// Everything a reclaim could not take back is still on this machine, so the record has to go on
// naming it. Dropped from the record on the way out, a route or a private key that survived one
// start would survive every start after it with nothing left that knows it is there.
func TestWhatCouldNotBeTakenBackStaysOnTheListForTheNextStart(t *testing.T) {
	state := testRootState(t)
	state.unscopeDefault = func(context.Context, string, string, bool) error {
		return errors.New("the routing table would not have it")
	}
	// The recorded process is this test itself: it is certainly running, and reading its
	// arguments is what fails, so nothing is ever signalled.
	state.processAlive = func(int) bool { return true }
	state.processArgs = func(context.Context, int) (string, error) {
		return "", errors.New("the process table would not answer")
	}

	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-held")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}
	if err := state.setProcess("tn_rec0012", dir, os.Getpid()); err != nil {
		t.Fatalf("record a connection: %v", err)
	}
	if err := state.setScope("tn_rec0013", "utun9991"); err != nil {
		t.Fatalf("record a scoped route: %v", err)
	}
	if err := state.setHostRoutes([]scopedHostRoute{{iface: "utun9992", gateway: "192.0.2.1"}}); err != nil {
		t.Fatalf("record a copy of this machine's own default route: %v", err)
	}

	took, err := state.reclaim(t.Context())

	if !took {
		t.Error("a record with three things in it was reported as nothing to take back")
	}
	if err == nil {
		t.Fatal("a reclaim that took nothing back at all reported success")
	}
	for _, want := range []string{"tn_rec0012", "tn_rec0013", "utun9992"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the reason given is %q, want it to name %s, which is still on this machine", err, want)
		}
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if _, ok := rec.OpenVPN["tn_rec0012"]; !ok {
		t.Error("a connection that was not stopped was dropped from the record, so nothing will ever stop it")
	}
	if rec.Scoped["tn_rec0013"] != "utun9991" {
		t.Errorf("the record holds %q for a route that is still on this machine, want utun9991", rec.Scoped["tn_rec0013"])
	}
	if len(rec.HostRoutes) != 1 || rec.HostRoutes[0].Interface != "utun9992" {
		t.Errorf("the record holds %+v for a copy that is still on this machine, want the one on utun9992", rec.HostRoutes)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("the configuration of a connection that is still running was removed: %v", err)
	}
}

// A process that cannot be signalled at all is reported rather than treated as stopped. It is
// still holding a network interface and routes on this machine, and the record has to go on
// naming it -- reported as stopped, it becomes a root process nothing is left to stop.
func TestAnOpenVPNThatWillNotTakeASignalIsReported(t *testing.T) {
	state := testRootState(t)
	var said []string
	state.logf = func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }
	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-deaf")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}
	// The recorded process is this test itself, so it is running, and stays running whatever
	// is sent to it: neither signal here reaches a real process.
	state.processAlive = func(int) bool { return true }
	state.processArgs = func(context.Context, int) (string, error) {
		return "openvpn --config " + openvpnConfigPath(dir, "tn_rec0014"), nil
	}
	state.askToClose = func(int) error { return errors.New("not permitted") }
	state.killProcess = func(int) error { return errors.New("still not permitted") }
	if err := state.setProcess("tn_rec0014", dir, os.Getpid()); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	_, err := state.reclaim(t.Context())

	if err == nil {
		t.Fatal("a process that took neither signal was reported as stopped")
	}
	if !strings.Contains(err.Error(), "stop the openvpn") {
		t.Errorf("the reason given is %q, want it to say the process could not be stopped", err)
	}
	if !strings.Contains(strings.Join(said, "\n"), "killing it") {
		t.Errorf("this side reported %q, want it to say the ask failed and it went on to kill", said)
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if _, ok := rec.OpenVPN["tn_rec0014"]; !ok {
		t.Error("a process that is still running was dropped from the record")
	}
}

// The other end of the same case: both signals were accepted and the process is still there.
// Silence here is the same failure -- a root openvpn left running with nothing naming it.
func TestAnOpenVPNStillRunningAfterTheKillIsReported(t *testing.T) {
	state := testRootState(t)
	dir := filepath.Join(t.TempDir(), "app-tail-openvpn-stubborn")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}
	// Nothing is signalled and the process is this test, so it is still running after both
	// asks -- which is what a process that ignores them looks like from here.
	state.processAlive = func(int) bool { return true }
	state.processArgs = func(context.Context, int) (string, error) {
		return "openvpn --config " + openvpnConfigPath(dir, "tn_rec0015"), nil
	}
	state.askToClose = func(int) error { return nil }
	state.killProcess = func(int) error { return nil }
	state.stopGrace = 20 * time.Millisecond
	if err := state.setProcess("tn_rec0015", dir, os.Getpid()); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	_, err := state.reclaim(t.Context())

	if err == nil {
		t.Fatal("a process that outlived the kill was reported as stopped")
	}
	if !strings.Contains(err.Error(), "did not stop when killed") {
		t.Errorf("the reason given is %q, want it to say the process outlived the kill", err)
	}
}

// The window between the configuration being written and the program being started: a record
// with a directory and no process. There is nothing to stop, and the directory still holds a
// private key that nothing else will ever remove.
func TestAConnectionRecordedWithNoDirectoryIsSimplyForgotten(t *testing.T) {
	state := testRootState(t)
	if err := state.setProcess("tn_rec0016", "", 0); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	if _, err := state.reclaim(t.Context()); err != nil {
		t.Fatalf("take back a connection with nothing recorded against it: %v", err)
	}

	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if len(rec.OpenVPN) != 0 {
		t.Errorf("the record still holds %+v, and there was nothing there to take back", rec.OpenVPN)
	}
}

// A private key that could not be removed is reported and kept on the list. Passed over, it is
// a key left in the temporary area with the one thing that knew about it thrown away.
func TestAConfigurationDirectoryThatCannotBeRemovedIsReported(t *testing.T) {
	state := testRootState(t)
	parent := filepath.Join(t.TempDir(), "parent")
	dir := filepath.Join(parent, "app-tail-openvpn-kept")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make a directory standing in for a connection's own: %v", err)
	}
	if err := os.WriteFile(openvpnConfigPath(dir, "tn_rec0017"), []byte("<key>secret</key>\n"), 0o600); err != nil {
		t.Fatalf("write a configuration standing in for a connection's own: %v", err)
	}
	pinConfiguration(t, dir, openvpnConfigPath(dir, "tn_rec0017"))
	if err := state.setProcess("tn_rec0017", dir, 0); err != nil {
		t.Fatalf("record a connection: %v", err)
	}

	_, err := state.reclaim(t.Context())

	if err == nil {
		t.Fatal("a configuration that is still on the disk was reported as removed")
	}
	if !strings.Contains(err.Error(), "tn_rec0017") {
		t.Errorf("the reason given is %q, want it to name the connection whose key is still on the disk", err)
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if _, ok := rec.OpenVPN["tn_rec0017"]; !ok {
		t.Error("a connection whose configuration is still on the disk was dropped from the record")
	}
}

// closableRootState is a record a test can close to writing part way through, which is how the
// failure that arrives between two writes of the same operation is reached.
func closableRootState(t *testing.T) (*rootState, func()) {
	t.Helper()
	requireRecordWriter(t)
	dir := filepath.Join(t.TempDir(), "record")
	if err := os.Mkdir(dir, stateDirMode); err != nil {
		t.Fatalf("make a directory for the record: %v", err)
	}
	state := newRootState(filepath.Join(dir, rootStateFileName), nil)
	return state, func() { sealRecord(t, state.path) }
}

// The record is written back whatever happened above it, and a write-back that failed is
// reported with everything else. Passed over, a machine this side took nothing back from would
// be one whose record still says otherwise, with the reclaim reporting success.
func TestARecordThatCouldNotBeWrittenBackIsReportedWithTheRest(t *testing.T) {
	state, seal := closableRootState(t)
	if err := state.setHostRoutes([]scopedHostRoute{{iface: "utun9998", gateway: "192.0.2.1"}}); err != nil {
		t.Fatalf("record a copy of this machine's own default route: %v", err)
	}
	seal()
	state.unscopeDefault = func(context.Context, string, string, bool) error { return nil }

	took, err := state.reclaim(t.Context())

	if !took {
		t.Error("a record with a route in it was reported as nothing to take back")
	}
	if err == nil {
		t.Fatal("a record that is still on the disk naming a route that is gone was reported as written")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the reason given is %q, want it to say the record could not be written", err)
	}
}

// The reclaim runs before the helper's socket is open, and a machine it could not finish on is
// exactly the machine that needs the helper most. Refusing to start would leave that machine in
// the state the refusal is about, with nothing left running that will ever repair it.
func TestAReclaimThatCouldNotFinishDoesNotStopTheHelperFromStarting(t *testing.T) {
	state := testRootState(t)
	if err := os.WriteFile(state.path, []byte("{not a record"), 0o600); err != nil {
		t.Fatalf("write a record that cannot be read: %v", err)
	}
	var said []string
	logf := func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }

	reclaimPreviousRun(t.Context(), state, logf)

	if !strings.Contains(strings.Join(said, "\n"), "could not take back") {
		t.Errorf("this side reported %q, want it to say what it could not take back", said)
	}
}

// And the ordinary case: what was taken back is reported, so a machine that came up holding
// leftovers says so in the one log anybody reads afterwards.
func TestWhatAStartTookBackIsReported(t *testing.T) {
	state := testRootState(t)
	state.unscopeDefault = func(context.Context, string, string, bool) error { return nil }
	if err := state.setHostRoutes([]scopedHostRoute{{iface: "utun9999", gateway: "192.0.2.1"}}); err != nil {
		t.Fatalf("record a copy of this machine's own default route: %v", err)
	}
	var said []string
	logf := func(format string, args ...any) { said = append(said, fmt.Sprintf(format, args...)) }

	reclaimPreviousRun(t.Context(), state, logf)

	if !strings.Contains(strings.Join(said, "\n"), "took back") {
		t.Errorf("this side reported %q, want it to say what a previous run had left", said)
	}
	rec, err := state.read()
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if !rec.empty() {
		t.Errorf("the record still holds %+v after everything in it was taken back", rec)
	}
}

// The repair is the privileged side undoing what a killed run left on the machine, so a
// process that holds no rights must not attempt any of it. Without the guard every ordinary
// start would try to rewrite this machine's resolver and remove its routes, and report the
// refusals it collected as a problem with the machine.
func TestTheRepairOfAPreviousRunDoesNothingWithoutTheRightsItNeeds(t *testing.T) {
	if Privileged() && !HasHelper() {
		t.Skip("this process is the privileged side, which is the branch that does the work")
	}
	var said []string

	RepairPreviousRun(t.Context(), func(format string, args ...any) {
		said = append(said, fmt.Sprintf(format, args...))
	})

	if len(said) != 0 {
		t.Errorf("an unprivileged start reported %q, want it to have attempted nothing", said)
	}
}

// The startup repair has to run wherever nothing else will. Asking whether the platform has
// the split-process design answers a different question: Linux has it with no install step, so
// nothing runs at boot there, and a `sudo app-tail` on a Mac that never installed a helper is
// the same shape. Both were left with no startup repair at all, which means an agent that was
// killed leaves this machine pointed at app-tail until somebody undoes it by hand.
func TestTheStartupRepairRunsWhereverNothingElseWill(t *testing.T) {
	tests := []struct {
		name            string
		privileged      bool
		helperInstalled bool
		want            bool
	}{
		{
			name:       "a privileged process with no helper installed does it",
			privileged: true,
			want:       true,
		},
		{
			name:            "a machine whose installed helper already did it at boot leaves it alone",
			privileged:      true,
			helperInstalled: true,
		},
		{
			name: "an unprivileged process cannot, and says so elsewhere",
		},
		{
			name:            "an unprivileged process beside an installed helper leaves it alone",
			helperInstalled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ran := false
			repairPreviousRun(tt.privileged, tt.helperInstalled, func() { ran = true })
			if ran != tt.want {
				t.Errorf("the repair ran = %t, want %t", ran, tt.want)
			}
		})
	}
}

// testBinary is the path of this test binary, resolved by the OS rather than read from the
// command line: on Windows a test started through a launcher can see a bare file name as
// its first argument, and exec refuses to resolve that against the working directory.
func testBinary(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatalf("find this test binary: %v", err)
	}
	return path
}
