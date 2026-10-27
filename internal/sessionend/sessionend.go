// SPDX-License-Identifier: MIT

// Package sessionend runs app-tail's teardown while the machine is ending the session.
//
// It exists for one platform and one hole. The shipped Windows binary is linked as a GUI
// application, so it has no console, and Go can only deliver os.Interrupt to a console
// process: a reboot or a logoff ends app-tail with none of its shutdown code run. What that
// leaves behind is not a lost log line -- the machine-wide resolver override is written into
// the registry, so the machine comes back up pointed at an address nothing answers on, and
// stays there.
//
// Windows does tell a process the session is ending, but only through a window message. So
// this owns a window: hidden, top-level, on a thread of its own, doing nothing but waiting to
// be told. Everywhere else it is a no-op -- macOS and Linux put the machine back through the
// privileged helper's dead-man's switch, which fires on the connection closing and needs no
// cooperation from a dying process.
package sessionend

import (
	"context"
	"sync"
	"time"
)

// Ending is how the session is going away, as the machine describes it.
type Ending struct {
	// Logoff is a user logging off rather than the machine shutting down.
	Logoff bool
	// Critical is a shutdown that will not be argued with -- `shutdown /f`, an update
	// deadline, a battery about to run out. The budget for it is much shorter.
	Critical bool
}

// Options configures a watch. The zero value is usable: every field has a default.
type Options struct {
	// Reason is what the machine's blocking screen says app-tail is still doing.
	Reason string
	// Budget is how long the teardown is waited for before the session is let go.
	Budget time.Duration
	// CriticalBudget is the same for a shutdown that cannot be delayed.
	CriticalBudget time.Duration
	// Logf is where this reports; a run with no window to watch through says so here.
	Logf func(format string, args ...any)
}

const (
	defaultBudget         = 20 * time.Second
	defaultCriticalBudget = 2 * time.Second
	// maxReason is the machine's own limit on the blocking screen's text.
	maxReason = 256

	// The flags Windows describes the ending with. Here rather than beside the rest of the
	// Win32 half so that endingFrom, which is where the whole meaning of a session-end
	// message is decided, can be tested on any machine.
	endSessionLogoff   = 0x80000000
	endSessionCritical = 0x40000000
)

// platform is the per-machine half: the thing holding whatever the machine tells us through.
type platform interface {
	stop()
}

// Watch is a live session-end watch. Its zero value is not usable; build one with Notify.
type Watch struct {
	opts     Options
	cancel   context.CancelFunc
	finished chan struct{}
	once     sync.Once
	plat     platform
}

// Notify returns a context cancelled when the session starts ending, and the watch to report
// the teardown's completion to.
//
// It never fails. A machine that will not give app-tail a window logs it and hands back a
// watch that watches nothing: refusing to start the agent because a shutdown watch could not
// be registered would be a worse outcome than the one this package exists to prevent.
func Notify(parent context.Context, opts Options) (context.Context, *Watch) {
	opts = normalize(opts)
	ctx, cancel := context.WithCancel(parent)
	w := &Watch{opts: opts, cancel: cancel, finished: make(chan struct{})}
	w.plat = watch(w)
	return ctx, w
}

// Finished reports the ordered teardown done, releasing a session end that is waiting on it.
//
// Safe to call more than once, and safe to call on a run that is ending for any other reason:
// with nothing waiting, it does nothing.
func (w *Watch) Finished() {
	w.once.Do(func() { close(w.finished) })
}

// Stop takes the watch down. It does not cancel the context Notify returned: a caller that
// stops watching for the end of the session has not ended anything.
func (w *Watch) Stop() {
	if w.plat != nil {
		w.plat.stop()
	}
}

// Watching reports whether this machine will tell app-tail the session is ending.
func (w *Watch) Watching() bool {
	return w.plat != nil
}

// begin runs the session end: cancel, then wait for the teardown or for the budget.
//
// Cancelling rather than calling the agent's shutdown directly is deliberate. It is what
// stops the reconcile loop before its own shutdown runs, so the restore cannot race a pass
// that is re-pointing this machine's adapters at app-tail.
func (w *Watch) begin(ending Ending) {
	budget := budgetFor(ending, w.opts)
	w.opts.Logf("this session is ending; app-tail has %s to put this machine back", budget)
	w.cancel()

	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-w.finished:
		w.opts.Logf("this machine was put back before the session ended")
	case <-timer.C:
		w.opts.Logf("the session ended before app-tail finished putting this machine back within %s; "+
			"the next start with administrator rights finishes it", budget)
	}
}

// endingFrom reads how the session is going away out of the message's lParam.
func endingFrom(lparam uintptr) Ending {
	return Ending{
		Logoff:   lparam&endSessionLogoff != 0,
		Critical: lparam&endSessionCritical != 0,
	}
}

// budgetFor is how long a teardown is waited for. A critical shutdown is not waiting for
// anybody, so asking for the full budget there only means being killed partway through it.
func budgetFor(ending Ending, opts Options) time.Duration {
	if ending.Critical {
		return opts.CriticalBudget
	}
	return opts.Budget
}

// normalize fills in the defaults, so nothing downstream has to check.
func normalize(opts Options) Options {
	if opts.Budget <= 0 {
		opts.Budget = defaultBudget
	}
	if opts.CriticalBudget <= 0 {
		opts.CriticalBudget = defaultCriticalBudget
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	opts.Reason = trimReason(opts.Reason)
	return opts
}

// trimReason cuts the blocking screen's text to what the machine will accept, on a rune
// boundary: half a character there is a mojibake glyph on a screen nobody can dismiss.
func trimReason(reason string) string {
	runes := []rune(reason)
	if len(runes) <= maxReason {
		return reason
	}
	return string(runes[:maxReason])
}
