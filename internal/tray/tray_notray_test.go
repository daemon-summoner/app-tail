// SPDX-License-Identifier: MIT

//go:build notray

package tray

import (
	"context"
	"strings"
	"testing"
	"time"
)

// This is the build that ships in every container and every cross-compiled target
// (release.sh builds them with -tags notray), so it is the one most users actually
// run. CI has only ever compiled it.
//
// TestRunRefusesToStartWithoutAController passes here for the wrong reason -- Run
// refuses everything -- so it proves nothing about this build. These do.

// Run must fail even when it is handed a perfectly good controller. A Run that
// blocked, or returned nil, would leave main believing a tray came up: it would stop
// short of the headless fallback and the agent would never serve the dashboard.
func TestTheTraylessBuildRefusesToRunEvenWithAController(t *testing.T) {
	err := Run(context.Background(), Options{Controller: &fakeController{}})

	if err == nil {
		t.Fatal("the trayless build reported a tray had started")
	}
	// The message is the user's only clue why the icon they expect is missing, so it
	// has to name both the build tag and the flag that makes the behaviour explicit.
	if !strings.Contains(err.Error(), "notray") {
		t.Errorf("err = %v, want it to name the build tag", err)
	}
	if !strings.Contains(err.Error(), "--headless") {
		t.Errorf("err = %v, want it to point at the headless flag", err)
	}
}

// Run has to return rather than block. main calls it on the main goroutine and only
// falls back to headless once it comes back; a Run that waited would hang the process
// with no icon and no dashboard.
func TestTheTraylessRunReturnsRatherThanBlocking(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), Options{Controller: &fakeController{}}) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run blocked; main would hang before ever reaching the headless fallback")
	}
}

// Supported is what main reads before it decides to try a tray at all. Reporting true
// here would send it down a path that always fails.
func TestTheTraylessBuildNeverClaimsToSupportATray(t *testing.T) {
	if Supported() {
		t.Error("the trayless build claims a tray icon can be shown")
	}
}

// Options must keep the same shape as the tray build, because main constructs it
// unconditionally. A field renamed on one side only fails the notray compile, which
// is the failure this assignment exists to produce.
func TestOptionsCarriesTheSameFieldsAsTheTrayBuild(t *testing.T) {
	opts := Options{
		Controller: &fakeController{},
		OnError:    func(error) {},
	}
	if opts.Controller == nil || opts.OnError == nil {
		t.Fatal("Options dropped a field main sets")
	}
}
