// SPDX-License-Identifier: MIT

package fileown

import (
	"errors"
	"testing"
	"time"
)

var errHeldOpen = errors.New("the file is held open by a scanner")

// A scanner holds a freshly written file for milliseconds. Giving up on the first refusal
// turns that into a record never written, which is a machine changed with nothing saying
// how to put it back.
func TestATransientRefusalIsRetriedUntilTheRenameGoesThrough(t *testing.T) {
	refusals := 3
	calls := 0
	var slept []time.Duration
	err := retryReplace(func() error {
		calls++
		if calls <= refusals {
			return errHeldOpen
		}
		return nil
	}, func(err error) bool { return errors.Is(err, errHeldOpen) },
		func(d time.Duration) { slept = append(slept, d) })

	if err != nil {
		t.Fatalf("retryReplace = %v, want the fourth attempt to succeed", err)
	}
	if calls != refusals+1 {
		t.Errorf("rename ran %d times, want %d", calls, refusals+1)
	}
	// Doubling from a millisecond: a fixed sleep either hammers the file or waits far
	// longer than a scan takes.
	want := []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	if len(slept) != len(want) {
		t.Fatalf("slept %v, want %v", slept, want)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Errorf("sleep %d = %v, want %v", i, slept[i], want[i])
		}
	}
}

// Only a refusal the classifier recognises is worth waiting on. Anything else -- a
// missing directory, a full disk -- is the same answer a second later, and the caller has
// to see it now.
func TestARefusalThatIsNotTransientIsReportedAtOnce(t *testing.T) {
	permanent := errors.New("the directory is gone")
	calls := 0
	err := retryReplace(func() error {
		calls++
		return permanent
	}, func(error) bool { return false },
		func(time.Duration) { t.Error("slept before a refusal that will not change") })

	if !errors.Is(err, permanent) {
		t.Errorf("retryReplace = %v, want %v", err, permanent)
	}
	if calls != 1 {
		t.Errorf("rename ran %d times, want once", calls)
	}
}

// A file held open for good -- a scanner that quarantined it, a handle something else
// keeps -- must not hold the write open forever. The budget ends it, and what comes back
// is the refusal itself rather than a timeout that hides what the platform said.
func TestAnEndlessRefusalGivesUpWithinTheBudgetAndReportsIt(t *testing.T) {
	calls := 0
	var total time.Duration
	err := retryReplace(func() error {
		calls++
		return errHeldOpen
	}, func(err error) bool { return errors.Is(err, errHeldOpen) },
		func(d time.Duration) { total += d })

	if !errors.Is(err, errHeldOpen) {
		t.Errorf("retryReplace = %v, want the refusal itself", err)
	}
	if total > replaceRetryBudget {
		t.Errorf("slept %v in total, past the %v budget", total, replaceRetryBudget)
	}
	if calls < 2 {
		t.Errorf("rename ran %d times; a budget that allows no retry is no budget", calls)
	}
	// Doubling from 1ms, the sleeps sum to 2^n-1 ms; the budget is spent before the sleep
	// that would cross it, so the loop stops after eleven waits of a possible twelve.
	if calls > 12 {
		t.Errorf("rename ran %d times, which is more than the budget allows with doubling backoff", calls)
	}
}

// A source that is not there is a real refusal on every platform, and has to come back
// without the two-second wait a held-open file earns.
func TestTheRealReplaceReportsAMissingSourceAtOnce(t *testing.T) {
	start := time.Now()
	dir := t.TempDir()
	err := replace(dir+"/absent", dir+"/target")
	if err == nil {
		t.Fatal("replace of a file that does not exist succeeded")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("a missing source took %v to report, so it was retried as though transient", waited)
	}
}
