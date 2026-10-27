// SPDX-License-Identifier: MIT

package sessionend

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The whole handshake, and it needs no Windows: returning from the session-end handler is how
// a process tells the machine it is finished, so the two things that must be true are that the
// teardown is started before the wait, and that the wait really ends when the teardown reports
// itself done.
func TestTheSessionEndStartsTheTeardownAndWaitsForIt(t *testing.T) {
	ctx, w := Notify(context.Background(), Options{Budget: 10 * time.Second})

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		w.begin(Ending{Logoff: true})
	}()

	// Cancelled first, before anything is waited on: a handler that waited for a teardown it
	// never asked for would hold the session up for its whole budget and tear nothing down.
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session end never told app-tail to stop, so it waits for a teardown that was never started")
	}

	select {
	case <-returned:
		t.Fatal("the handler returned before the teardown finished, which tells the machine it is free to end this process")
	case <-time.After(50 * time.Millisecond):
	}

	w.Finished()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still holding the session up after the teardown reported itself done")
	}
}

// The other half: a teardown that hangs must not hold the session open forever. Windows ends
// the process anyway, and a machine that has decided to shut down is not waiting for an app
// to decide otherwise.
func TestATeardownThatNeverFinishesStillLetsTheSessionEnd(t *testing.T) {
	_, w := Notify(context.Background(), Options{Budget: 20 * time.Millisecond})

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.begin(Ending{Logoff: true})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never gave up on a teardown that never finished")
	}
}

// A critical shutdown -- `shutdown /f`, an update deadline, a battery about to go -- is not
// waiting twenty seconds. Asking for the full budget there only means being killed partway
// through the restore rather than finishing the part that fits.
func TestAShutdownThatWillNotWaitIsGivenTheShorterBudget(t *testing.T) {
	opts := normalize(Options{})
	ordinary := budgetFor(Ending{Logoff: true}, opts)
	critical := budgetFor(Ending{Critical: true}, opts)

	if critical >= ordinary {
		t.Errorf("a critical shutdown is given %s and an ordinary one %s, want the forced one shorter", critical, ordinary)
	}
	if ordinary != defaultBudget || critical != defaultCriticalBudget {
		t.Errorf("the budgets are %s and %s, want the defaults %s and %s", ordinary, critical, defaultBudget, defaultCriticalBudget)
	}

	chosen := normalize(Options{Budget: time.Second, CriticalBudget: 100 * time.Millisecond})
	if got := budgetFor(Ending{}, chosen); got != time.Second {
		t.Errorf("a chosen budget of 1s was read as %s", got)
	}
}

// What the machine says about the ending decides the budget, so reading it wrongly is reading
// every forced shutdown as one that will wait.
func TestHowTheSessionIsEndingIsReadFromWhatTheMachineSays(t *testing.T) {
	tests := []struct {
		name  string
		param uintptr
		want  Ending
	}{
		{name: "a shutdown", want: Ending{}},
		{name: "a logoff", param: endSessionLogoff, want: Ending{Logoff: true}},
		{name: "a forced shutdown", param: endSessionCritical, want: Ending{Critical: true}},
		{
			name:  "a forced logoff",
			param: endSessionLogoff | endSessionCritical,
			want:  Ending{Logoff: true, Critical: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := endingFrom(tt.param); got != tt.want {
				t.Errorf("endingFrom(%#x) = %+v, want %+v", tt.param, got, tt.want)
			}
		})
	}
}

// The defaults exist so that nothing downstream has to check, and Logf in particular: the
// Win32 half calls it from inside a window procedure, where a nil would be a crash on the
// thread the machine is waiting on.
func TestAWatchBuiltWithNothingSetStillWorks(t *testing.T) {
	opts := normalize(Options{})
	if opts.Logf == nil {
		t.Fatal("a watch with no log function would crash on the thread the shutdown is waiting on")
	}
	opts.Logf("this must not panic: %d", 1)

	long := strings.Repeat("é", maxReason*2)
	trimmed := trimReason(long)
	if got := len([]rune(trimmed)); got != maxReason {
		t.Errorf("the blocking screen's text is %d characters, want it cut to %d", got, maxReason)
	}
	if !strings.HasPrefix(long, trimmed) {
		t.Error("the text was cut somewhere other than the front, or through a character")
	}
	if short := trimReason("putting this machine back"); short != "putting this machine back" {
		t.Errorf("a short reason was changed to %q", short)
	}
}

// Reporting the teardown done is on the ordinary exit path, where no session is ending at all,
// and the relaunch path runs it before starting a replacement. Neither can be allowed to
// block or to panic on a second call.
func TestReportingTheTeardownDoneIsSafeOnARunThatIsSimplyStopping(t *testing.T) {
	_, w := Notify(context.Background(), Options{})
	w.Finished()
	w.Finished()
	w.Stop()

	if w.Watching() {
		t.Skip("this machine watches for the end of the session, so there is nothing to assert about one that does not")
	}
}

// A machine that will not give app-tail a window is not a reason to refuse to start: the state
// that follows from refusing is the one this package exists to prevent.
func TestAMachineThatCannotBeWatchedStillStarts(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, w := Notify(parent, Options{})
	if ctx == nil || w == nil {
		t.Fatal("Notify refused to hand back a context, so the agent has nothing to run under")
	}
	if ctx.Err() != nil {
		t.Fatalf("the context came back already cancelled: %v", ctx.Err())
	}

	// And the parent still governs it, watch or no watch.
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the parent no longer stops the agent")
	}
}
