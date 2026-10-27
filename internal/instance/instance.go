// SPDX-License-Identifier: MIT

// Package instance keeps one agent per config document.
//
// Two agents pointed at the same config do not divide the machine between them: both bind
// the dashboard, both write the same file, and with the network-interface mode on both take
// this machine's resolver, its proxy settings and its routes. Whichever starts second wins
// some of that and loses the rest, and neither one's shutdown puts back what the other
// installed.
//
// So a second run is not refused -- refusing it leaves a user who double-clicked the icon
// with no window and no way to tell which copy is live. It takes over instead: the agent
// already running is asked to shut down, and this one continues only once it has. That
// order is what makes the takeover safe, because everything the first agent installed on
// this machine is undone by its own shutdown.
package instance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fileown"
)

// FileName is the claim file. It sits beside the config document rather than in the state
// directory for the same reason the dashboard address record does: an agent is identified
// by the config it was pointed at, and the two are not always in the same place.
const FileName = "agent.lock"

const (
	// defaultGrace bounds how long the agent already running has to stop after it is asked.
	// Its shutdown is what puts this machine's resolver, proxy settings and routes back, and
	// a tunnel it has to tear down first makes that take seconds rather than milliseconds --
	// so the wait is generous, and cutting it short is the expensive mistake.
	defaultGrace = 15 * time.Second

	// endGrace bounds the wait after the process was ended outright. Nothing is being waited
	// for by then except the operating system dropping the locks it held.
	endGrace = 5 * time.Second

	// pollInterval is how often the claim is retried while waiting for it.
	pollInterval = 25 * time.Millisecond

	// quitRequestTimeout bounds the loopback request that asks the running agent to stop. It
	// answers before it begins shutting down, so anything slower than this is an agent that
	// is not going to answer at all.
	quitRequestTimeout = 5 * time.Second

	// holderRecord is the fixed width the holder's process id is written in, so a shorter id
	// never leaves the tail of a longer one behind it and the file never has to be truncated
	// while it is locked.
	holderRecord = 32
)

// Options shapes one takeover.
type Options struct {
	// ConfigPath is the config document this run was pointed at. The claim lives beside it.
	ConfigPath string

	// Logf reports what the takeover did. It is where a user learns that the agent they had
	// running was stopped, so it goes to the same place the rest of the startup diagnostics
	// do. A nil Logf discards them.
	Logf func(format string, args ...any)

	// Grace is how long the agent already running has to stop after it is asked. Zero takes
	// the default.
	Grace time.Duration

	// Stop asks the agent holding the claim to shut down, and Kill ends one that would not.
	// Both are the platform's own when nil. They are separate fields so a test can drive a
	// whole takeover without signalling anything on the machine running it.
	Stop func(ctx context.Context, pid int) error
	Kill func(ctx context.Context, pid int) error
}

func (o Options) withDefaults() Options {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Grace <= 0 {
		o.Grace = defaultGrace
	}
	configPath := o.ConfigPath
	if o.Stop == nil {
		o.Stop = func(ctx context.Context, pid int) error { return stopHolder(ctx, configPath, pid) }
	}
	if o.Kill == nil {
		o.Kill = killHolder
	}
	return o
}

// Lock is this process's claim on a config document.
//
// Release it once the agent has finished shutting down -- and before starting a replacement,
// so the replacement does not have to take the claim from a process that is already on its
// way out.
type Lock struct {
	file *os.File
	path string
}

// Acquire claims sole ownership of o.ConfigPath for this process, stopping whatever agent
// already holds it.
//
// The claim is an operating-system lock on a file, so the kernel drops it however this
// process ends: a crash or a kill leaves nothing stale behind, which a process-id file on
// its own cannot promise. The id written into that file is only ever read while the lock is
// held, so it names a process that is running rather than one that used to be.
func Acquire(ctx context.Context, o Options) (*Lock, error) {
	if strings.TrimSpace(o.ConfigPath) == "" {
		return nil, errors.New("take the single-instance claim: no config file was named")
	}
	o = o.withDefaults()

	path := PathFor(o.ConfigPath)
	file, err := openClaim(path)
	if err != nil {
		return nil, err
	}
	lock := &Lock{file: file, path: path}

	taken, err := lock.take()
	if err != nil {
		return nil, errors.Join(err, lock.Release())
	}
	if !taken {
		if err := lock.takeOver(ctx, o); err != nil {
			return nil, errors.Join(err, lock.Release())
		}
	}
	if err := writeHolder(file, os.Getpid()); err != nil {
		return nil, errors.Join(err, lock.Release())
	}
	return lock, nil
}

// PathFor is where the claim for a config document lives.
func PathFor(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), FileName)
}

// Path is the file this claim is held on.
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Release gives up the claim. It is safe on a nil Lock and safe to call twice, so a caller
// can defer it and still release early on the path that starts a replacement.
//
// The file is left in place. Unlinking it would let a process that opened it a moment
// earlier go on holding a lock on a file nothing else can see, and both agents would then
// believe they were the only one. It is a claim rather than a record: what it holds matters
// only while the lock does.
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	return errors.Join(fileown.Unlock(file), file.Close())
}

// take attempts the lock without blocking and reports whether it got it.
func (l *Lock) take() (bool, error) {
	taken, err := fileown.TryLock(l.file)
	if err != nil {
		return false, fmt.Errorf("claim %s: %w", l.path, err)
	}
	return taken, nil
}

// takeOver stops the agent holding the claim and waits for the operating system to hand it
// over.
func (l *Lock) takeOver(ctx context.Context, o Options) error {
	holder := readHolder(l.file)
	switch {
	case holder == os.Getpid():
		return fmt.Errorf("take the claim on %s: this process already holds it", l.path)
	case holder <= 0:
		// Held, but by something that has not said which process it is: it took the lock and
		// died before writing, or it is between those two steps right now. There is nobody to
		// ask, so waiting for the kernel to drop the lock is the whole of what can be done.
		o.Logf("something already holds %s without saying which process it is; waiting %s for it to let go",
			l.path, o.Grace)
		return l.waitOrFail(ctx, o.Grace, fmt.Errorf("app-tail cannot start: %s is held by another process", l.path))
	}

	o.Logf("another app-tail is already running as process %d; asking it to stop", holder)
	if err := o.Stop(ctx, holder); err != nil {
		// Not fatal on its own. A process already on its way out refuses the ask and releases
		// the claim regardless, so the wait below is what actually decides.
		o.Logf("could not ask process %d to stop: %v", holder, err)
	}

	taken, err := l.waitForClaim(ctx, o.Grace)
	if err != nil {
		return err
	}
	if taken {
		o.Logf("process %d stopped; taking over", holder)
		return nil
	}

	o.Logf("process %d did not stop within %s; ending it. What it installed on this machine is "+
		"put back by the repair that runs before this agent starts.", holder, o.Grace)
	if err := o.Kill(ctx, holder); err != nil {
		return fmt.Errorf("app-tail is already running as process %d and would not stop: %w", holder, err)
	}
	return l.waitOrFail(ctx, endGrace,
		fmt.Errorf("app-tail is already running as process %d, which was ended and still holds %s", holder, l.path))
}

// waitOrFail waits out the claim and reports failed as the reason it never came free.
func (l *Lock) waitOrFail(ctx context.Context, d time.Duration, failed error) error {
	taken, err := l.waitForClaim(ctx, d)
	if err != nil {
		return err
	}
	if !taken {
		return failed
	}
	return nil
}

// waitForClaim retries the claim until it comes free, the wait runs out, or ctx ends --
// which is a user pressing Ctrl-C at a startup that is waiting on another process.
func (l *Lock) waitForClaim(ctx context.Context, d time.Duration) (bool, error) {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline.C:
			// One last attempt, so a release that lands exactly on the deadline is taken
			// rather than reported as a holder that never let go.
			return l.take()
		case <-ticker.C:
			taken, err := l.take()
			if taken || err != nil {
				return taken, err
			}
		}
	}
}

// openClaim opens the claim file, creating it and the directory holding it.
func openClaim(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, config.DirMode); err != nil {
		return nil, fmt.Errorf("take the single-instance claim: create %s: %w", dir, err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, config.FileMode)
	if err != nil {
		return nil, fmt.Errorf("take the single-instance claim: %w", err)
	}
	return file, nil
}

// writeHolder records which process holds the claim, for the next run to ask.
func writeHolder(file *os.File, pid int) error {
	record := make([]byte, holderRecord)
	for i := range record {
		record[i] = ' '
	}
	copy(record, strconv.Itoa(pid))
	record[len(record)-1] = '\n'
	if _, err := file.WriteAt(record, 0); err != nil {
		return fmt.Errorf("record this process in the claim: %w", err)
	}
	return nil
}

// readHolder reads which process holds the claim. Anything unreadable is reported as no
// holder at all, which the caller treats as "wait rather than ask": a claim that names
// nothing usable is not grounds for signalling a process id made up out of half a file.
func readHolder(file *os.File) int {
	record := make([]byte, holderRecord)
	n, err := file.ReadAt(record, 0)
	if n == 0 && err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(record[:n])))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// askAgentToQuit asks the agent that recorded its dashboard address beside configPath to
// shut down, over the same loopback API the CLI and the dashboard use.
//
// It is the one way across a boundary a signal cannot cross: Windows has no signal that
// means "shut down cleanly", and an agent another account started -- one running as root,
// typically -- refuses a signal from this one.
func askAgentToQuit(ctx context.Context, configPath string) error {
	addr := config.ReadDashboardAddr(configPath)
	if addr == "" {
		return fmt.Errorf("the agent holding %s recorded no dashboard address to ask", configPath)
	}
	ctx, cancel := context.WithTimeout(ctx, quitRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/api/quit", nil)
	if err != nil {
		return fmt.Errorf("ask the running agent to stop: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: quitRequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ask the running agent at %s to stop: %w", addr, err)
	}
	// The reply is closed unread: the agent answers before it begins shutting down, so the
	// status is the whole answer and this connection has nothing else to carry.
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("the running agent at %s refused to stop: HTTP %d", addr, resp.StatusCode)
	}
	return nil
}
