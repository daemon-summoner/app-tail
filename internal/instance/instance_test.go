// SPDX-License-Identifier: MIT

package instance

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fileown"
)

const (
	holderVar     = "APP_TAIL_INSTANCE_HOLDER"
	holderCfgVar  = "APP_TAIL_INSTANCE_HOLDER_CONFIG"
	holderUpVar   = "APP_TAIL_INSTANCE_HOLDER_READY"
	holderMute    = "APP_TAIL_INSTANCE_HOLDER_SILENT"
	holderDeafVar = "APP_TAIL_INSTANCE_HOLDER_DEAF"

	// holderLifetime is longer than any test that starts one; every test ends its holder.
	holderLifetime = 2 * time.Minute

	// testGrace keeps a takeover that is meant to fail from taking the real wait.
	testGrace = 300 * time.Millisecond
)

// TestClaimHolder is not a test of anything. It is the app-tail already running, in the only
// form a test can produce one: this binary, started again, holding the claim until something
// stops it. It skips unless it is being used that way.
func TestClaimHolder(t *testing.T) {
	if os.Getenv(holderVar) != "1" {
		t.Skip("this runs only as the process a takeover test takes over from")
	}
	configPath := os.Getenv(holderCfgVar)

	if os.Getenv(holderDeafVar) == "1" {
		// An agent that no longer acts on the ask: wedged, or holding a shutdown that never
		// finishes. The signal arrives and nothing happens.
		signal.Ignore(syscall.SIGTERM)
	}

	if os.Getenv(holderMute) == "1" {
		// A claim held by a process that never said which one it is: taken, then dead or
		// stalled before writing. Nothing here writes the process id.
		file, err := openClaim(PathFor(configPath))
		if err != nil {
			t.Fatalf("open the claim: %v", err)
		}
		taken, err := fileown.TryLock(file)
		if err != nil || !taken {
			t.Fatalf("hold the claim: taken = %v, err = %v", taken, err)
		}
	} else {
		lock, err := Acquire(context.Background(), Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("hold the claim: %v", err)
		}
		defer func() { _ = lock.Release() }()
	}

	if err := os.WriteFile(os.Getenv(holderUpVar), []byte("held\n"), config.FileMode); err != nil {
		t.Fatalf("say the claim is held: %v", err)
	}
	time.Sleep(holderLifetime)
}

// holder is the running app-tail a takeover test takes over from.
type holder struct {
	cmd    *exec.Cmd
	exited <-chan struct{}
}

// pid is the process the claim names, which is what a takeover asks to stop.
func (h *holder) pid() int { return h.cmd.Process.Pid }

// gone reports whether the holder has ended, waiting up to d for it.
func (h *holder) gone(d time.Duration) bool {
	select {
	case <-h.exited:
		return true
	case <-time.After(d):
		return false
	}
}

// startHolder starts a second copy of this binary holding the claim on configPath and
// returns once it has it. mute makes it hold the claim without writing which process it is,
// and extra carries any further environment that shapes how it behaves.
func startHolder(t *testing.T, configPath string, mute bool, extra ...string) *holder {
	t.Helper()

	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(testBinary(t), "-test.run=^TestClaimHolder$") //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(),
		holderVar+"=1", holderCfgVar+"="+configPath, holderUpVar+"="+ready)
	cmd.Env = append(cmd.Env, extra...)
	if mute {
		cmd.Env = append(cmd.Env, holderMute+"=1")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the app-tail to be taken over from: %v", err)
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

	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return &holder{cmd: cmd, exited: exited}
		}
		if !time.Now().Before(deadline) {
			t.Fatal("the app-tail to be taken over from never took the claim")
		}
		select {
		case <-exited:
			t.Fatal("the app-tail to be taken over from exited before it held the claim")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// calls records what a takeover asked of the holder, in place of signalling a real machine.
type calls struct {
	mu   sync.Mutex
	pids []int
	act  func(pid int) error
}

func (c *calls) record(_ context.Context, pid int) error {
	c.mu.Lock()
	c.pids = append(c.pids, pid)
	act := c.act
	c.mu.Unlock()
	if act == nil {
		return nil
	}
	return act(pid)
}

func (c *calls) seen() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.pids...)
}

// endProcess stands in for a real agent's shutdown, which is the part of a takeover that
// happens inside the other process and cannot be exercised from here.
func endProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

// configIn is a config document in a directory of its own, which is where its claim lives.
func configIn(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), config.ConfigFileName)
}

// The claim lives beside the config document, because that is what identifies an agent: two
// runs pointed at different config files are two agents and must not displace each other.
func TestTheClaimSitsBesideTheConfigDocument(t *testing.T) {
	dir := t.TempDir()

	got := PathFor(filepath.Join(dir, config.ConfigFileName))

	if want := filepath.Join(dir, FileName); got != want {
		t.Errorf("PathFor = %q, want %q", got, want)
	}
}

// The ordinary start: nothing is running, so nothing is asked to stop and nothing waits.
// The process id has to be recorded, because it is the only thing the next run can ask.
func TestAnAgentThatIsAloneStartsWithoutStoppingAnything(t *testing.T) {
	configPath := configIn(t)
	stop, kill := &calls{}, &calls{}

	lock, err := Acquire(t.Context(), Options{
		ConfigPath: configPath, Stop: stop.record, Kill: kill.record, Grace: testGrace,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if len(stop.seen()) != 0 || len(kill.seen()) != 0 {
		t.Errorf("a first agent asked %v to stop and ended %v", stop.seen(), kill.seen())
	}
	if got := readHolder(lock.file); got != os.Getpid() {
		t.Errorf("the claim names process %d, want this one (%d): the next run has nothing to ask",
			got, os.Getpid())
	}
}

// The case this exists for. A second run does not refuse and does not start beside the first:
// it asks the one already running to stop, and continues only once the claim is its own.
func TestASecondAgentTakesOverFromTheOneAlreadyRunning(t *testing.T) {
	configPath := configIn(t)
	running := startHolder(t, configPath, false)

	// Stands in for the shutdown the ask produces; what is under test is that the takeover
	// asks the process the claim names, and waits for it.
	stop := &calls{act: func(pid int) error { return endProcess(pid) }}
	kill := &calls{}

	lock, err := Acquire(t.Context(), Options{
		ConfigPath: configPath, Stop: stop.record, Kill: kill.record, Grace: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if got := stop.seen(); len(got) != 1 || got[0] != running.pid() {
		t.Errorf("asked %v to stop, want exactly the running agent (%d)", got, running.pid())
	}
	if got := kill.seen(); len(got) != 0 {
		t.Errorf("an agent that stopped when asked was ended anyway: %v", got)
	}
	if !running.gone(10 * time.Second) {
		t.Error("the takeover finished while the agent it took over from was still running")
	}
}

// An agent that will not shut down cannot be left holding the machine: the takeover ends it.
// Waiting forever instead would leave the user with an app that never opens.
func TestAnAgentThatIgnoresTheAskIsEnded(t *testing.T) {
	configPath := configIn(t)
	running := startHolder(t, configPath, false)

	stop := &calls{}
	kill := &calls{act: func(pid int) error { return endProcess(pid) }}

	lock, err := Acquire(t.Context(), Options{
		ConfigPath: configPath, Stop: stop.record, Kill: kill.record, Grace: testGrace,
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if got := kill.seen(); len(got) != 1 || got[0] != running.pid() {
		t.Errorf("ended %v, want exactly the agent that ignored the ask (%d)", got, running.pid())
	}
	if !running.gone(10 * time.Second) {
		t.Error("the takeover finished while the agent it took over from was still running")
	}
}

// Neither asking nor ending worked, so there are two agents' worth of the machine at stake
// and this one must not start. The failure has to name the process still holding it, since
// that is the only thing the user can act on.
func TestAnAgentThatCannotBeStoppedIsReportedRatherThanStartedBeside(t *testing.T) {
	configPath := configIn(t)
	running := startHolder(t, configPath, false)
	stop, kill := &calls{}, &calls{}

	lock, err := Acquire(t.Context(), Options{
		ConfigPath: configPath, Stop: stop.record, Kill: kill.record, Grace: testGrace,
	})

	if err == nil {
		_ = lock.Release()
		t.Fatal("a second agent started while the first still held the claim")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(running.pid())) {
		t.Errorf("the failure does not name the process holding the claim (%d): %v", running.pid(), err)
	}
	if running.gone(100 * time.Millisecond) {
		t.Error("the agent that could not be stopped went anyway, so the failure was wrong")
	}
}

// A claim held by something that never wrote which process it is must not be turned into a
// signal: the process id would be made up out of half a file, and ending the wrong process is
// not a recoverable mistake. The only thing left is to wait, and then to say so.
func TestAClaimThatNamesNoProcessIsWaitedOutRatherThanSignalled(t *testing.T) {
	configPath := configIn(t)
	startHolder(t, configPath, true)
	stop, kill := &calls{}, &calls{}

	lock, err := Acquire(t.Context(), Options{
		ConfigPath: configPath, Stop: stop.record, Kill: kill.record, Grace: testGrace,
	})

	if err == nil {
		_ = lock.Release()
		t.Fatal("a second agent started while something else held the claim")
	}
	if got := append(stop.seen(), kill.seen()...); len(got) != 0 {
		t.Errorf("a claim naming no process led to signalling %v", got)
	}
	if !strings.Contains(err.Error(), PathFor(configPath)) {
		t.Errorf("the failure does not name the claim that is held: %v", err)
	}
}

// The claim this process already holds is its own: asking the holder to stop would be this
// process signalling itself, which is a shutdown nobody requested.
func TestTheClaimIsNeverTakenFromThisProcessBySignallingIt(t *testing.T) {
	configPath := configIn(t)
	stop, kill := &calls{}, &calls{}

	first, err := Acquire(t.Context(), Options{ConfigPath: configPath, Grace: testGrace})
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer func() { _ = first.Release() }()

	second, err := Acquire(t.Context(), Options{
		ConfigPath: configPath, Stop: stop.record, Kill: kill.record, Grace: testGrace,
	})

	if err == nil {
		_ = second.Release()
		t.Fatal("the claim was handed out twice inside one process")
	}
	if got := append(stop.seen(), kill.seen()...); len(got) != 0 {
		t.Fatalf("this process signalled %v to take a claim it already held", got)
	}
	// Still held: a failed second attempt that released the first would leave the running
	// agent with no claim at all, and the next start would find the machine unowned.
	if got := readHolder(first.file); got != os.Getpid() {
		t.Errorf("the claim names process %d after a failed second attempt, want %d", got, os.Getpid())
	}
}

// Releasing is what makes a restart work: the replacement takes the claim without having to
// stop anything, because the process it replaces gave it up first.
func TestReleasingHandsTheClaimToTheNextRun(t *testing.T) {
	configPath := configIn(t)
	stop, kill := &calls{}, &calls{}

	first, err := Acquire(t.Context(), Options{ConfigPath: configPath, Grace: testGrace})
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	second, err := Acquire(t.Context(), Options{
		ConfigPath: configPath, Stop: stop.record, Kill: kill.record, Grace: testGrace,
	})
	if err != nil {
		t.Fatalf("second Acquire after a release: %v", err)
	}
	defer func() { _ = second.Release() }()

	if got := append(stop.seen(), kill.seen()...); len(got) != 0 {
		t.Errorf("a claim that had been released still led to signalling %v", got)
	}
}

// Release is deferred by every caller and called outright on the restart path, so the second
// call has to be a no-op rather than an unlock of a file the process no longer owns.
func TestReleasingTwiceIsHarmless(t *testing.T) {
	lock, err := Acquire(t.Context(), Options{ConfigPath: configIn(t), Grace: testGrace})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	if err := lock.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Errorf("second Release: %v", err)
	}
	if err := (*Lock)(nil).Release(); err != nil {
		t.Errorf("releasing a claim that was never taken: %v", err)
	}
}

// A start that is waiting on another process is a start the user can still abandon. Ctrl-C
// has to end it there rather than after the full wait.
func TestWaitingForTheClaimEndsWhenTheStartIsAbandoned(t *testing.T) {
	configPath := configIn(t)
	startHolder(t, configPath, false)

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := Acquire(ctx, Options{
		ConfigPath: configPath,
		Stop:       func(context.Context, int) error { return nil },
		Kill:       func(context.Context, int) error { return nil },
		Grace:      30 * time.Second,
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire returned %v, want the cancellation that ended the wait", err)
	}
}

// A run pointed at no config has no claim to take. Guessing one would put the claim somewhere
// arbitrary, where the agent that is actually running would never look for it.
func TestAClaimWithNoConfigDocumentIsRefused(t *testing.T) {
	_, err := Acquire(t.Context(), Options{ConfigPath: "  "})

	if err == nil {
		t.Fatal("a claim was taken for a run with no config file")
	}
}

// The loopback API is how a takeover reaches an agent no signal can: a Windows process, or
// one another account started. It has to reach the address that agent recorded, since the
// configured port is not necessarily the one it got.
func TestTheRunningAgentIsAskedToQuitThroughTheAddressItRecorded(t *testing.T) {
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	configPath := configIn(t)
	if err := config.WriteDashboardAddr(configPath, strings.TrimPrefix(server.URL, "http://")); err != nil {
		t.Fatalf("record the dashboard address: %v", err)
	}

	if err := askAgentToQuit(t.Context(), configPath); err != nil {
		t.Fatalf("ask the running agent to quit: %v", err)
	}

	if len(asked) != 1 || asked[0] != "POST /api/quit" {
		t.Errorf("the running agent was asked %v, want a single POST /api/quit", asked)
	}
}

// An agent that refuses -- one already shutting down, or a build without the route -- must not
// read as a successful handover, or the takeover would end its wait and start beside it.
func TestAnAgentThatRefusesToQuitIsNotTreatedAsStopped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	configPath := configIn(t)
	if err := config.WriteDashboardAddr(configPath, strings.TrimPrefix(server.URL, "http://")); err != nil {
		t.Fatalf("record the dashboard address: %v", err)
	}

	err := askAgentToQuit(t.Context(), configPath)

	if err == nil {
		t.Fatal("an agent that refused to stop was reported as stopped")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("the failure does not say what the agent answered: %v", err)
	}
}

// An address that no longer answers is the ordinary case for a record left by an agent that
// died: the ask has to fail then and there so the takeover moves on to ending the process,
// rather than reading a dead address as a handover that succeeded.
func TestAnAgentThatIsNoLongerListeningIsReportedRatherThanTreatedAsStopped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(server.URL, "http://")
	server.Close()

	configPath := configIn(t)
	if err := config.WriteDashboardAddr(configPath, addr); err != nil {
		t.Fatalf("record the dashboard address: %v", err)
	}

	err := askAgentToQuit(t.Context(), configPath)

	if err == nil {
		t.Fatal("an address nothing is listening on was reported as a successful handover")
	}
	if !strings.Contains(err.Error(), addr) {
		t.Errorf("the failure does not name the address that was tried (%s): %v", addr, err)
	}
}

// A claim whose process id cannot be read names no process at all. Every one of these is a
// half-written or overwritten file, and turning any of them into a number to signal would end
// whatever process happens to have that id.
func TestAClaimWithAnUnreadableProcessIdNamesNoProcess(t *testing.T) {
	for _, record := range []string{"not-a-process", "-5", "0", "   ", ""} {
		t.Run(strconv.Quote(record), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			if err := os.WriteFile(path, []byte(record), config.FileMode); err != nil {
				t.Fatalf("write the claim: %v", err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatalf("open the claim: %v", err)
			}
			defer func() { _ = file.Close() }()

			if got := readHolder(file); got != 0 {
				t.Errorf("a claim reading %q names process %d, want none: it would be signalled", record, got)
			}
		})
	}
}

// The claim says which file it is held on, which is the one thing a user whose start failed
// can act on -- and the nil case, because a run that never took one still reports.
func TestTheClaimNamesTheFileItIsHeldOn(t *testing.T) {
	configPath := configIn(t)

	lock, err := Acquire(t.Context(), Options{ConfigPath: configPath, Grace: testGrace})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if got, want := lock.Path(), PathFor(configPath); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
	if got := (*Lock)(nil).Path(); got != "" {
		t.Errorf("a claim that was never taken reports %q, want no file", got)
	}
}

// An agent that recorded no address cannot be asked, and saying so is what makes the takeover
// fall back rather than wait out a request nobody is listening for.
func TestAnAgentWithNoRecordedAddressCannotBeAsked(t *testing.T) {
	err := askAgentToQuit(t.Context(), configIn(t))

	if err == nil {
		t.Fatal("an agent that recorded no address was asked to quit anyway")
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
