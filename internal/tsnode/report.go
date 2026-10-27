// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"runtime"

	"github.com/sellitus/app-tail/internal/elevate"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// InterfaceReport is what this machine says about the network-interface mode. It is a
// value rather than something printed as it is gathered so the same findings render as
// terminal text, as JSON and as a dashboard card, and so the rendering is testable
// without a machine in any particular state.
type InterfaceReport struct {
	// Platform is the operating system this ran on, because a report pasted into an
	// issue is worth much less without it.
	Platform string `json:"platform"`
	// Supported reports whether the interface mode exists on this platform at all.
	Supported bool `json:"supported"`
	// Privileged reports whether this process could do the privileged work itself.
	Privileged bool `json:"privileged"`
	// Helper describes the privileged helper, on the platforms that have one.
	Helper InterfaceHelperReport `json:"helper"`
	// Interface is the name a new interface would get, empty where the platform chooses.
	Interface string `json:"interface,omitempty"`
	// Conflict names another tailnet client on this machine, empty when there is none.
	Conflict string `json:"conflict,omitempty"`
	// Missing names a component the mode needs that is not installed here.
	Missing string `json:"missing,omitempty"`
	// ResolverBusy names what already holds every address app-tail would answer DNS on,
	// empty when one of them is free. It belongs to the machine-wide resolver rather than
	// to the interface: the two features are refused for different reasons, and reporting
	// either one's blocker against the other is how a working feature reads as broken.
	ResolverBusy string `json:"resolverBusy,omitempty"`
	// StaleOverride is set when a previous run left this machine's name resolution pointed
	// at app-tail and nothing has put it back. It is not a Leftover: those are paths a user
	// can delete, and this is a setting on every network service.
	StaleOverride string `json:"staleOverride,omitempty"`
	// Leftovers are files or interfaces a previous run did not clean up.
	Leftovers []string `json:"leftovers,omitempty"`
	// Undo are the commands that remove the leftovers by hand. They are in the report
	// because the case this is for is the one where app-tail is not the thing that will
	// do the cleaning.
	Undo []string `json:"undo,omitempty"`
}

// InterfaceHelperReport is the state of the privileged helper.
type InterfaceHelperReport struct {
	// Design reports whether this platform runs the privileged side out of process.
	Design bool `json:"design"`
	// Installable reports whether app-tail can install it for you here.
	Installable bool `json:"installable"`
	// Installed reports whether its launch configuration is on the machine.
	Installed bool `json:"installed"`
	// Running reports whether it answered.
	Running bool `json:"running"`
	// Version is the version it reported, empty when it did not answer.
	Version string `json:"version,omitempty"`
	// Problem is why it did not answer, or why its answer is not usable.
	Problem string `json:"problem,omitempty"`
	// Socket is where it listens, so a report says where to look.
	Socket string `json:"socket,omitempty"`
}

// Ready reports whether the mode could be turned on right now, and why not when it could
// not. It is the one sentence both surfaces lead with, so they cannot disagree about what
// counts as ready.
func (r InterfaceReport) Ready() (bool, string) {
	switch {
	case !r.Supported:
		return false, "this platform cannot run app-tail on a network interface"
	case r.Missing != "":
		return false, r.Missing
	case r.Conflict != "":
		return false, r.Conflict
	case r.Privileged:
		return true, ""
	case !r.Helper.Design:
		// There is nothing to install on a platform whose privileged work is done by the
		// process itself: what is missing is the rights, and they are asked for as app-tail
		// starts. Reporting ready without them is what makes the switch report success and
		// leave the machine where it was.
		return false, needsRights("run app-tail on a network interface")
	case r.Helper.Running:
		return true, ""
	case r.Helper.Problem != "":
		return false, r.Helper.Problem
	default:
		return false, "the privileged helper is not installed"
	}
}

// needsRights is the refusal a platform with no helper gives, naming what the rights are
// for and what to do about it. The two readiness answers word the first half differently
// because somebody who asked for a resolver is not told about a network interface.
func needsRights(what string) string {
	return "app-tail needs administrator rights to " + what + ". " + elevateHint(elevate.Supported())
}

// ResolverReady reports whether the machine-wide resolver could be turned on right now,
// and why not when it could not.
//
// It shares the privileged side with the interface mode and almost nothing else: another
// tailnet client on this machine and a missing wintun are both reasons the interface cannot
// run and neither is a reason a resolver cannot, while something already holding port 53 is
// the reverse.
func (r InterfaceReport) ResolverReady() (bool, string) {
	switch {
	case !r.Supported:
		return false, "this platform cannot let app-tail change how it resolves names"
	case r.ResolverBusy != "":
		return false, r.ResolverBusy
	case r.Privileged:
		return true, ""
	case !r.Helper.Design:
		return false, needsRights("let app-tail choose how this machine resolves names")
	case r.Helper.Running:
		return true, ""
	case r.Helper.Problem != "":
		return false, r.Helper.Problem
	default:
		return false, "the privileged helper is not installed"
	}
}

// BlockerDespiteRights reports what would still stop the interface mode after administrator
// rights were granted, empty when nothing would.
//
// It exists because Ready answers a different question. On a platform with no privileged
// helper the rights are what is missing, so Ready's answer is "app-tail needs administrator
// rights" -- correct on a card, and circular at the one call site that is deciding whether to
// ask for them. A gate that reads it there refuses to prompt because the process lacks the
// rights the prompt would grant, and the machine keeps whatever the last run left on it.
//
// Every refusal the rights cannot lift -- an unsupported platform, a missing wintun, a second
// tailnet client -- is decided before the Privileged arm in both switches, so answering with
// Privileged forced true clears exactly the one arm that the rights would clear and nothing
// else.
func (r InterfaceReport) BlockerDespiteRights() string {
	_, blocker := r.withRights().Ready()
	return blocker
}

// ResolverBlockerDespiteRights is BlockerDespiteRights for the machine-wide resolver.
func (r InterfaceReport) ResolverBlockerDespiteRights() string {
	_, blocker := r.withRights().ResolverReady()
	return blocker
}

// withRights is this report as it would read from a process that held administrator rights.
func (r InterfaceReport) withRights() InterfaceReport {
	r.Privileged = true
	return r
}

// InspectInterface reads what this machine says about the interface mode. Nothing here
// changes anything: the one command people run when they suspect app-tail left something
// behind must not be a command that leaves something behind.
func InspectInterface(ctx context.Context, logf func(format string, args ...any)) InterfaceReport {
	report := InterfaceReport{
		Platform:   runtime.GOOS,
		Supported:  hostnet.Supported(),
		Privileged: hostnet.Privileged(),
		Helper: InterfaceHelperReport{
			Design:      hostnet.HasHelper(),
			Installable: hostnet.SupportsHelperInstall(),
			Installed:   hostnet.HelperInstalled(),
			Socket:      hostnet.SocketPath(),
		},
		Interface: hostnet.DefaultInterfaceName(),
		// No interface of app-tail's own is named: this process holds none -- the helper is the
		// one that opens it -- and where app-tail is holding one, the helper's own scan replaces
		// every answer here. See applyHelperProbe.
		Conflict:  hostnet.DetectConflict(ctx, ""),
		Missing:   hostnet.DetectMissing(),
		Leftovers: hostnet.DetectLeftovers(),
	}
	switch {
	case report.Supported && report.Helper.Design && !report.Privileged:
		caps, err := probeHelper(ctx, report.Helper.Socket, logf)
		applyHelperProbe(&report, caps, err)
	case report.Supported && !report.Helper.Design:
		// No helper to ask, so this process is the one that answers -- and both of these are
		// read rather than left empty because nothing else on such a platform reads them. A
		// machine a killed run left resolving through an address nothing answers on would
		// otherwise be reported as clean by every surface, with no prompt to put it back.
		report.ResolverBusy = hostnet.DetectResolverBusy(ctx)
		report.StaleOverride = hostnet.DetectStaleOverride(ctx)
	}
	// Derived last, from whichever scan won, so the commands reported always remove
	// exactly what was reported.
	report.Undo = hostnet.UndoFor(report.Leftovers)
	return report
}

// applyHelperProbe folds the helper's own answer into the report.
//
// Where the two overlap the helper's view replaces this process's: it is the one that will
// create the interface, and it runs as root, so it can read resolver files and sockets this
// process cannot -- an unprivileged scan that finds nothing is not the same answer as a
// privileged one that finds nothing.
func applyHelperProbe(report *InterfaceReport, caps hostnet.Capabilities, err error) {
	if err != nil {
		// Carrying the next step, because this line is the whole reason somebody reads
		// the report: the reasons a helper does not answer have different answers, and
		// the raw one names a socket rather than any of them.
		report.Helper.Problem = WithNextStep(err).Error()
		return
	}
	report.Helper.Running = true
	report.Helper.Version = caps.Version
	report.Conflict = caps.Conflict
	report.Missing = caps.Missing
	report.ResolverBusy = caps.ResolverBusy
	report.StaleOverride = caps.StaleOverride
	report.Leftovers = caps.Leftovers
	// Kept only when the helper named one, so a helper too old to report it leaves this
	// process's own answer standing rather than blanking the line.
	if caps.Interface != "" {
		report.Interface = caps.Interface
	}
}

// probeHelper asks the helper what it sees, which is the one question that proves the
// whole path works: the socket exists, its permissions let this user through, the helper
// is the build this app expects, and it is answering rather than wedged.
//
// The socket is passed in rather than resolved again, so the path the report names is the
// path that was actually tried.
func probeHelper(ctx context.Context, socket string, logf func(format string, args ...any)) (hostnet.Capabilities, error) {
	client, err := hostnet.Dial(ctx, hostnet.Options{SocketPath: socket, Logf: func(string, ...any) {}})
	if err != nil {
		return hostnet.Capabilities{}, err
	}
	defer func() {
		if err := client.Close(); err != nil {
			logf("could not close the connection to the helper: %v", err)
		}
	}()
	return client.Capabilities(ctx)
}
