// SPDX-License-Identifier: MIT

package app

// Asking for one connection to be built again now.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tunnel"
)

// The whole of what a retry is for: a connection that is up and carrying nothing is rebuilt.
//
// Every other pass keeps a connection whose plan still matches what is stored, which is what
// makes an ordinary reconcile cheap -- and it is also why a peer that stopped answering, or an
// openvpn program that is running and signed out, stays exactly as it is forever. The user's
// workaround today is switching the connection off and on again.
func TestRetryingAConnectionBuildsItAgainThoughNothingAboutItChanged(t *testing.T) {
	h := runningWireGuard(t)
	first := h.wireguards.devicesFor(wgTunnelID)
	if len(first) != 1 {
		t.Fatalf("%d devices were built before the retry, want exactly one", len(first))
	}

	if _, err := h.agent.TunnelsAPI().Retry(context.Background(), wgTunnelID); err != nil {
		t.Fatalf("retrying the connection: %v", err)
	}

	built := h.wireguards.devicesFor(wgTunnelID)
	if len(built) != 2 {
		t.Fatalf("%d devices were built for one retried connection, want the first one and a "+
			"fresh one -- a retry that kept the device leaves the connection exactly as broken "+
			"as it was", len(built))
	}
	if !built[1].wasStarted() {
		t.Error("the connection was built again and never started")
	}
	if !first[0].wasClosed() {
		t.Error("the device that was replaced is still running, so the connection was rebuilt " +
			"on top of itself")
	}
	if got := viewOfTunnel(t, h, wgTunnelID).State; got != string(tunnel.StateConnected) {
		t.Errorf("the retried connection reports %q, want %q", got, tunnel.StateConnected)
	}
}

// A retry is asked for once and acted on once. Nothing carries it over: a second pass rebuilding
// a connection nobody asked about would cut every flow on it for no reason.
func TestAConnectionIsBuiltAgainOnceForOneRetry(t *testing.T) {
	h := runningWireGuard(t)

	if _, err := h.agent.TunnelsAPI().Retry(context.Background(), wgTunnelID); err != nil {
		t.Fatalf("retrying the connection: %v", err)
	}
	after := len(h.wireguards.devicesFor(wgTunnelID))

	// An ordinary pass, asked for by something unrelated.
	h.agent.reconcileNow(context.Background())

	if got := len(h.wireguards.devicesFor(wgTunnelID)); got != after {
		t.Errorf("%d devices exist after a pass that followed the retry, want %d -- the retry "+
			"was acted on again", got, after)
	}
}

// A retry clears the reason the last attempt failed before the new one runs. Left on screen, it
// reads as the retry having failed the instant it was pressed.
func TestRetryingAConnectionClearsWhatTheLastAttemptFailedWith(t *testing.T) {
	h := newHarnessWith(t, seedWireGuard, func(o *Options) { o.RetryDelay = time.Hour })
	// Broken while it is up, which is the state this whole control exists for. The retry is
	// what rebuilds it, and that rebuild is the attempt that fails.
	h.wireguards.refuseToStart(wgTunnelID, errors.New("the machine has no network yet"))
	if _, err := h.agent.TunnelsAPI().Retry(context.Background(), wgTunnelID); err != nil {
		t.Fatalf("retrying the connection: %v", err)
	}
	waitFor(t, 5*time.Second, "the connection to report that it could not start", func() bool {
		return viewOfTunnel(t, h, wgTunnelID).Detail != ""
	})

	h.wireguards.refuseToStart(wgTunnelID, nil)
	view, err := h.agent.TunnelsAPI().Retry(context.Background(), wgTunnelID)
	if err != nil {
		t.Fatalf("retrying the connection: %v", err)
	}

	if view.Detail != "" {
		t.Errorf("the retried connection still reports %q, want the previous failure cleared", view.Detail)
	}
	if view.State != string(tunnel.StateConnected) {
		t.Errorf("the retried connection reports %q, want %q", view.State, tunnel.StateConnected)
	}
}

// Everything a retry cannot act on is refused where it is asked for. A retry that reported
// success and started nothing would leave somebody pressing a button that does nothing.
func TestRetryingAConnectionNothingWouldBuildIsRefused(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		seedWireGuard(c)
		c.Tunnels[len(c.Tunnels)-1].Enabled = false
	})

	if _, err := h.agent.TunnelsAPI().Retry(context.Background(), "tn_absent"); !errors.Is(err, config.ErrNotFound) {
		t.Errorf("retrying a connection that does not exist failed with %v, want %v", err, config.ErrNotFound)
	}

	_, err := h.agent.TunnelsAPI().Retry(context.Background(), wgTunnelID)
	var refusal *config.ValidationError
	if !errors.As(err, &refusal) {
		t.Fatalf("retrying a connection that is switched off failed with %v, want a refusal "+
			"naming what to do instead", err)
	}
	if !strings.Contains(refusal.Message, "switched off") {
		t.Errorf("the refusal reads %q, want it to say the connection is switched off", refusal.Message)
	}

	_, err = h.agent.TunnelsAPI().Retry(context.Background(), config.PrimaryTunnelID)
	if !errors.As(err, &refusal) {
		t.Fatalf("retrying the primary connection failed with %v, want a refusal naming what to "+
			"do instead", err)
	}
}

// A retry puts the automatic ladder back on its bottom rung.
//
// Without this the button is worse than useless on the connection that needs it most: an outage
// that lasted a while has the ladder up at minutes, so the one attempt the retry makes is
// followed by that same long silence -- and the person watching has no way to see the wait they
// are being held to.
func TestARetryPutsTheAutomaticLadderBackOnItsBottomRung(t *testing.T) {
	const rung = 50 * time.Millisecond
	h := newHarnessWith(t, seedWireGuard, func(o *Options) { o.RetryDelay = rung })
	h.wireguards.refuseToStart(wgTunnelID, errors.New("the machine has no network yet"))
	if _, err := h.agent.TunnelsAPI().Retry(context.Background(), wgTunnelID); err != nil {
		t.Fatalf("breaking the connection: %v", err)
	}

	// Six failed attempts puts the ladder at 32 rungs, which is what makes the wait below
	// decisive: the next automatic attempt is over a second and a half away.
	waitFor(t, 30*time.Second, "the ladder to climb", func() bool {
		return len(h.wireguards.devicesFor(wgTunnelID)) >= 7
	})

	if _, err := h.agent.TunnelsAPI().Retry(context.Background(), wgTunnelID); err != nil {
		t.Fatalf("retrying the connection: %v", err)
	}
	// The retry's own attempt fails too -- the machine still has no network -- so what is
	// measured is the ladder the failure after a retry lands on.
	after := len(h.wireguards.devicesFor(wgTunnelID))

	waitFor(t, 700*time.Millisecond, "two more attempts at the bottom of the ladder", func() bool {
		return len(h.wireguards.devicesFor(wgTunnelID)) >= after+2
	})
}

// Whether a connection can be built again is served rather than worked out by each client.
// A dashboard, a tray and a CLI each deciding for themselves would eventually offer a button
// on a connection the agent refuses, which reads as the app being broken rather than as the
// action not applying.
func TestWhetherAConnectionCanBeBuiltAgainIsServedWithIt(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		seedWireGuard(c)
		c.Tunnels[len(c.Tunnels)-1].Enabled = false
	})

	if got := viewOfTunnel(t, h, wgTunnelID); got.Retryable {
		t.Error("a connection that is switched off is offered as one that can be built again")
	}
	if got := viewOfTunnel(t, h, config.PrimaryTunnelID); got.Retryable {
		t.Error("the primary connection is offered as one that can be built again")
	}

	if _, err := h.agent.TunnelsAPI().Update(context.Background(), wgTunnelID,
		patchOf(t, map[string]any{"enabled": true})); err != nil {
		t.Fatalf("switching the connection on: %v", err)
	}
	if got := viewOfTunnel(t, h, wgTunnelID); !got.Retryable {
		t.Error("a connection that is switched on is not offered as one that can be built again")
	}
}
