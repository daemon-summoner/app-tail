// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// A machine whose connections are all up is owed nothing. If a pass that reached everything
// left the ladder standing, the agent would go on waking a sleeping laptop forever over a
// problem that is already fixed.
func TestAPassThatReachedEverythingSchedulesNothing(t *testing.T) {
	var s supervisor
	s.settled(2)
	s.settled(1)
	if s.nextWake() == 0 {
		t.Fatal("a pass that left something down asked for no further pass")
	}

	s.settled(0)

	if got := s.nextWake(); got != 0 {
		t.Errorf("a pass that reached everything asks to come back in %s, want no timer at all", got)
	}
}

// Retries back off. A fixed interval would be the same request every few seconds against a
// provider that is down or a configuration that is wrong -- a machine in a bag hammering a
// server it will not reach until somebody changes something.
func TestConsecutiveFailuresBackOff(t *testing.T) {
	s := supervisor{first: time.Second}

	var waits []time.Duration
	for range 4 {
		s.settled(1)
		waits = append(waits, s.nextWake())
	}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, got := range waits {
		if got != want[i] {
			t.Errorf("failure %d asks to come back in %s, want %s", i+1, got, want[i])
		}
	}
}

// The ladder stops climbing. Counting past the top would shift the base duration off the end
// of an int64 -- a wait that comes back negative, which arms no timer at all and turns the
// longest outage into one that is never retried again.
func TestTheLadderStopsClimbingAtItsCeiling(t *testing.T) {
	s := supervisor{first: retryFirst}

	for range 200 {
		s.settled(1)
	}

	got := s.nextWake()
	if got <= 0 {
		t.Fatalf("after a long outage the next pass is scheduled in %s, so nothing is ever tried again", got)
	}
	if got != retryMax {
		t.Errorf("the ladder settled at %s, want the ceiling %s", got, retryMax)
	}
}

// The whole point of the ladder, end to end: a connection that could not start comes up by
// itself once the reason clears.
//
// The reason is usually the machine -- no network yet at boot, a link that arrived a moment
// later -- and the app is never told when it goes away. Nothing in this test tells it: no
// click, no settings write, no tailnet event. Before this, the connection stayed down until
// something unrelated happened to fire, and the user's workaround was switching it off and on.
func TestAConnectionThatCouldNotStartComesUpOnItsOwn(t *testing.T) {
	h := newHarnessWith(t, nil, func(o *Options) { o.RetryDelay = 20 * time.Millisecond })
	view := mustCreateTunnel(t, h, httpapi.TunnelSpec{Type: config.TunnelWireGuard, Name: "Office"})
	h.wireguards.refuseToStart(view.ID, errors.New("the machine has no network yet"))

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), view.ID,
		patchOf(t, wgSettings())); err != nil {
		t.Fatalf("configuring the connection: %v", err)
	}
	waitFor(t, 5*time.Second, "the connection to report that it could not start", func() bool {
		return viewOfTunnel(t, h, view.ID).State == string(tunnel.StateFailed)
	})

	// The machine gets its network. Nothing announces that.
	h.wireguards.refuseToStart(view.ID, nil)

	waitFor(t, 10*time.Second, "the connection to come up on its own", func() bool {
		_, registered := h.agent.tunnels.Get(view.ID)
		return registered
	})
	if got := viewOfTunnel(t, h, view.ID); got.State != string(tunnel.StateConnected) {
		t.Errorf("the connection is registered and reports %q, want %q", got.State, tunnel.StateConnected)
	}
}

// A connection that is switched off is not a connection that is down. Counting it would leave
// the ladder running forever on a machine where nothing is wrong, which is the same wasted
// wake-up the first test here refuses.
func TestAConnectionSwitchedOffIsNotCountedAsDown(t *testing.T) {
	h := newHarnessWith(t, func(c *config.Config) {
		seedWireGuard(c)
		c.Tunnels[len(c.Tunnels)-1].Enabled = false
	}, nil)

	if got := h.agent.downCount(); got != 0 {
		t.Errorf("%d things are counted as down on a machine whose only connection is switched off", got)
	}
}
