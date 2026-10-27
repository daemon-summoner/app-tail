// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// View reports what this machine can do about the network-interface mode and what it is
// doing now.
//
// The machine is read on every call rather than remembered from the node's start: a helper
// installed in a terminal, or an official Tailscale client started since, changes the
// answer without anything in this process changing at all. That read is the same one
// `app-tail tun doctor` performs, so the two surfaces cannot report different machines.
func (sa interfaceSetupAPI) View(ctx context.Context) httpapi.InterfaceView {
	a := sa.a
	s := a.settings()
	report := a.inspect(ctx, a.hostLogf)
	ready, blocker := report.Ready()

	view := httpapi.InterfaceView{
		Enabled:    s.InterfaceEnabled,
		Configured: string(s.InterfaceModeChosen()),
		Mode:       string(config.NetworkUserspace),
		// Retired against the machine just read: the report below carries the live
		// answer for anything about this machine, so a recorded one would only be an
		// older second copy of it. What is left is a start that failed, which the
		// machine read cannot speak to.
		Fallback:  a.retireMachineFallback(),
		Ready:     ready,
		Blocker:   blocker,
		Interface: report.Interface,
		Helper: httpapi.Helper{
			Design:      report.Helper.Design,
			Installable: report.Helper.Installable,
			Installed:   report.Helper.Installed,
			Running:     report.Helper.Running,
			Version:     report.Helper.Version,
			Problem:     report.Helper.Problem,
			Socket:      report.Helper.Socket,
		},
		Conflict:  report.Conflict,
		Missing:   report.Missing,
		Leftovers: report.Leftovers,
		Undo:      report.Undo,
	}
	if node := a.currentNode(); node != nil {
		status := node.Status()
		if status.Network != "" {
			view.Mode = string(status.Network)
		}
		view.InForce = status.Running() && status.Network == config.NetworkTUN
	}
	view.Capability = interfaceCapability(s, view, report)
	return view
}

// interfaceLimits are what the mode does not do, stated before somebody meets one. They
// never clear and are not errors: each is a property of running a tailnet through the
// operating system rather than inside one process.
//
// What the rights are for is the one line that differs by platform: where a helper holds
// them, they are given once and to the helper; where the process holds them itself, they
// are asked for every time app-tail starts. Saying "once, to install the helper" on a
// platform that installs no helper contradicts the same card's own answer for whether
// there is a helper.
func interfaceLimits(report tsnode.InterfaceReport) []string {
	rights := "It needs administrator rights once, to install the privileged helper that " +
		"creates the interface."
	if !report.Helper.Design {
		rights = "It needs administrator rights: this platform installs no helper, so " +
			"app-tail asks for them as it starts and holds them for as long as it runs."
	}
	return []string{
		"It changes the machine, not just app-tail: a network interface, routes for your " +
			"tailnet's addresses, and a resolver file for your tailnet's names.",
		rights,
		"It cannot run beside the official Tailscale client. Only one of them can own the " +
			"tailnet's addresses on a machine.",
	}
}

// interfaceCapability turns the machine's answer into the one sentence the card leads
// with. The order is the order the questions get asked in: is the mode available here,
// was it asked for, and is it actually doing anything.
func interfaceCapability(s config.Settings, view httpapi.InterfaceView, report tsnode.InterfaceReport) httpapi.Capability {
	ready, why := view.Ready, view.Blocker
	limits := interfaceLimits(report)
	switch {
	case !report.Supported:
		return httpapi.Capability{Reason: why, Limits: limits}
	case !s.InterfaceEnabled:
		return httpapi.Capability{
			Available: true,
			Reason: "The network-interface module is off, so app-tail reaches your tailnet " +
				"through its own forwards and proxy and changes nothing on this machine.",
			Limits: limits,
		}
	case !ready:
		return httpapi.Capability{Available: true, Degraded: true, Reason: why, Limits: limits}
	case view.Fallback != "":
		return httpapi.Capability{Available: true, Degraded: true, Reason: view.Fallback, Limits: limits}
	case s.FabricSelected():
		// Ahead of the arm below, which would otherwise say the tailnet is kept inside
		// app-tail. It is not: it is on an interface, the one every other connection is on
		// too, and this card is about the interface that carries the tailnet alone.
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "This machine is ready for the network-interface mode, and is set to reach " +
				"every connection over one interface instead. Your tailnet is reached there " +
				"along with the rest of them.",
			Limits: limits,
		}
	case !s.TunSelected():
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "This machine is ready for the network-interface mode, but the mode is " +
				"set to keep the tailnet inside app-tail.",
			Limits: limits,
		}
	case !view.InForce:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The network-interface mode is set but not in force yet. Restart the " +
				"tailnet node to move onto it.",
			Limits: limits,
		}
	default:
		return httpapi.Capability{Available: true, Limits: limits}
	}
}

// The ladder for reading this machine again after a node had to come up in the contained
// mode. What it is waiting for happens outside app-tail entirely -- an official Tailscale
// client being quit, the privileged helper being installed from a terminal -- and produces
// no event here, so looking again is the only way to find out. The first rung is short
// because somebody who just quit the other client is watching; it doubles from there
// because a blocker that survives a few minutes is one nobody is standing over, and
// reading the privileged side every minute for the rest of the day buys nothing.
const (
	interfaceRecheckFirst   = time.Minute
	interfaceRecheckMax     = 15 * time.Minute
	interfaceRecheckCeiling = 4
)

// interfaceRetry paces those reads. Like the exit-node schedule and the supervisor it is
// written and read only by the lifecycle goroutine, so it carries no lock.
type interfaceRetry struct {
	// checks is how many times the machine has been read since the fallback began.
	checks int
	// first is the bottom rung, a field rather than the constant so a test can watch a
	// whole recovery happen instead of waiting one out; zero means interfaceRecheckFirst.
	first time.Duration
}

// checked records one read of the machine that did not end the fallback.
func (r *interfaceRetry) checked() {
	if r.checks < interfaceRecheckCeiling {
		r.checks++
	}
}

// settled ends the ladder, because there is nothing left to come back for.
func (r *interfaceRetry) settled() { r.checks = 0 }

// nextWake is how long until the machine should be read again.
func (r *interfaceRetry) nextWake() time.Duration {
	first := r.first
	if first <= 0 {
		first = interfaceRecheckFirst
	}
	if wait := first << r.checks; wait < interfaceRecheckMax {
		return wait
	}
	return interfaceRecheckMax
}

// awaitingInterfaceRecovery reports that the node is running inside app-tail only because
// this machine could not carry the network interface the settings ask for.
//
// A fallback recorded because the start itself failed is deliberately not this, for the
// same reason retireMachineFallback keeps that one: reading the machine again cannot speak
// to a node that did not come up on a machine that looked able. Retrying on it would
// rebuild the node on a schedule against a reason no re-read can ever retire.
func (a *Agent) awaitingInterfaceRecovery() bool {
	if !a.settings().TunSelected() {
		return false
	}
	a.mu.RLock()
	fromMachine := a.networkFallbackFromMachine
	a.mu.RUnlock()
	if !fromMachine {
		return false
	}
	node := a.currentNode()
	if node == nil {
		return false
	}
	status := node.Status()
	return status.Running() && status.Network != config.NetworkTUN
}

// interfaceRecoveryWake is how long until the machine is read again for a node stuck in
// the contained mode, and zero when none is. Nothing waiting also ends the ladder, so a
// fallback that begins later starts at the bottom rung rather than the one the last one
// left behind.
func (a *Agent) interfaceRecoveryWake() time.Duration {
	if !a.awaitingInterfaceRecovery() {
		a.interfaceRecovery.settled()
		return 0
	}
	return a.interfaceRecovery.nextWake()
}

// recoverInterfaceMode rebuilds the node onto the network interface once this machine can
// carry it again.
//
// The mode is chosen when a node is built and never revisited, so without this a machine
// that was busy at start -- the official client still running, the helper not installed
// yet -- keeps the tailnet inside app-tail for as long as the process lives, and the card
// asks the user to restart the node for a blocker they have already cleared.
//
// It asks the same question the build itself asks, so a rebuild only happens when the
// build that follows it will land on the interface.
func (a *Agent) recoverInterfaceMode(ctx context.Context) {
	if !a.awaitingInterfaceRecovery() {
		return
	}
	a.interfaceRecovery.checked()

	s := a.settings()
	// Preflight reads the machine and nothing else, so the rest of the parameters a node
	// is built from are not needed to ask whether it could be built on the interface.
	blocker := a.preflight(ctx, tsnode.ServerParams{
		Network:       config.NetworkTUN,
		InterfaceName: s.InterfaceName,
	}, a.hostLogf)
	if blocker != nil {
		// Not an error here: it is the state the node is already reporting, and the card
		// is where the user is being told about it.
		a.logger.Debug("this machine still cannot carry the network-interface mode",
			"reason", blocker)
		return
	}

	a.logger.Info("this machine can carry the network-interface mode again; " +
		"rebuilding the tailnet node onto it")
	if err := a.restartNode(ctx); err != nil {
		a.logger.Warn("could not move the tailnet node onto the network interface", "error", err)
	}
}
