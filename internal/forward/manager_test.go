// SPDX-License-Identifier: MIT

package forward

import (
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// unsupportedProtocol makes a forward register an entry and immediately fail to start,
// with no socket involved. It is the manager's own "visible with its reason" path, and
// it lets a status test carry many forwards without binding many ports.
const unsupportedProtocol = config.Protocol("sctp")

func idsOf(statuses []Status) []string {
	out := make([]string, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, s.ID)
	}
	return out
}

// The registry behind Statuses is a Go map, whose iteration order is deliberately
// randomized per range. Without the comparator the dashboard's forward table would
// reshuffle on every poll -- rows jumping under the cursor mid-click -- and no
// existing test would notice, because they all only check the length.
func TestStatusesAreOrderedByIDSoTheDashboardDoesNotReshuffleBetweenPolls(t *testing.T) {
	tn := newFakeTailnet()
	m := newTestManager(t, tn)

	// Applied out of order, and alternating between forwards that start and forwards
	// that fail, so a Statuses that returned insertion order or grouped by state would
	// both be caught alongside plain map randomness.
	echo := startEchoTCP(t)
	tn.route("box:80", echo)
	desired := []config.Forward{
		mixedForward(t, "f_e"),
		mixedForward(t, "f_b"),
		mixedForward(t, "f_g"),
		mixedForward(t, "f_a"),
		mixedForward(t, "f_f"),
		mixedForward(t, "f_c"),
		mixedForward(t, "f_d"),
	}
	m.Apply(desired)

	want := []string{"f_a", "f_b", "f_c", "f_d", "f_e", "f_f", "f_g"}
	got := idsOf(m.Statuses())
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Statuses returned %v, want them sorted by id: %v", got, want)
	}

	// One sorted result could still be luck; the contract is that consecutive polls
	// agree, which is what the dashboard actually depends on.
	for poll := range 5 {
		again := idsOf(m.Statuses())
		if strings.Join(again, ",") != strings.Join(want, ",") {
			t.Fatalf("poll %d returned %v, want %v; consecutive polls must agree", poll+2, again, want)
		}
	}
}

// A forward that cannot start must stay in the list carrying its reason. Dropping it
// would leave the dashboard showing nothing where the user's broken rule should be,
// and the only signal that anything is wrong would be a log line nobody reads.
func TestStatusesReportsEveryRegisteredForwardIncludingTheOnesThatFailed(t *testing.T) {
	echo := startEchoTCP(t)
	tn := newFakeTailnet()
	tn.route("box:80", echo)
	m := newTestManager(t, tn)

	good := tcpToLocal(t, "f_good", freePort(t), "box:80")
	bad := tcpToLocal(t, "f_bad", freePort(t), "box:80")
	bad.Protocol = unsupportedProtocol
	m.Apply([]config.Forward{good, bad})

	statuses := m.Statuses()
	if len(statuses) != 2 {
		t.Fatalf("Statuses returned %d entries (%v), want both the working and the broken forward",
			len(statuses), idsOf(statuses))
	}

	byID := make(map[string]Status, len(statuses))
	for _, s := range statuses {
		byID[s.ID] = s
	}
	if got := byID["f_bad"].State; got != StateError {
		t.Errorf("broken forward reports state %q, want %q", got, StateError)
	}
	if got := byID["f_bad"].Error; !strings.Contains(got, string(unsupportedProtocol)) {
		t.Errorf("broken forward reports error %q, want it to name the unsupported protocol %q",
			got, unsupportedProtocol)
	}

	waitForStatus(t, m, "f_good", "the working forward to start", func(s Status) bool {
		return s.State == StateRunning
	})
	if got := m.Status("f_good").Error; got != "" {
		t.Errorf("working forward carries error %q, want none", got)
	}
}

// Statuses covers forwards the manager never knew about only by omission, so a lookup
// for one has to answer rather than leaving the caller with a zero value it cannot
// distinguish from a forward that is genuinely idle.
func TestStatusOfAnUnknownForwardReportsStoppedRatherThanEmpty(t *testing.T) {
	m := newTestManager(t, newFakeTailnet())

	st := m.Status("f_never_existed")
	if st.ID != "f_never_existed" {
		t.Errorf("Status returned id %q, want the id that was asked for", st.ID)
	}
	if st.State != StateStopped {
		t.Errorf("Status returned state %q, want %q", st.State, StateStopped)
	}
}

// mixedForward alternates between a forward that starts and one that cannot, keyed off
// the last letter of the id so the mapping is stable however the ids are ordered.
func mixedForward(t *testing.T, id string) config.Forward {
	t.Helper()
	f := tcpToLocal(t, id, freePort(t), "box:80")
	if (id[len(id)-1]-'a')%2 == 1 {
		f.Protocol = unsupportedProtocol
	}
	return f
}
