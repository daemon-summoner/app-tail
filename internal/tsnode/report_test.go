// SPDX-License-Identifier: MIT

package tsnode

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/hostnet"
)

// The line saying why the helper did not answer is the whole reason somebody reads the
// report, and each reason has a different answer -- install one, set it up for this account,
// replace it. Without the next step the report names a socket and stops there, which is the
// state a person is already in when they read it.
func TestTheReportSaysWhatToDoAboutAHelperThatDidNotAnswer(t *testing.T) {
	for _, refusal := range []error{
		hostnet.ErrNoHelper,
		hostnet.ErrHelperNotOpenToThisAccount,
		hostnet.ErrHelperFromAnotherBuild,
	} {
		var report InterfaceReport
		applyHelperProbe(&report, hostnet.Capabilities{}, fmt.Errorf("%w: /var/run/app-tail/helper.sock", refusal))
		if report.Helper.Running {
			t.Errorf("a helper that refused %v was reported as answering", refusal)
		}
		if !strings.Contains(report.Helper.Problem, "app-tail tun ") {
			t.Errorf("the report said %q about %v, which names nothing to run", report.Helper.Problem, refusal)
		}
	}
}

// The helper is root and this process is not, so where the two disagree the helper wins --
// and a helper too old to name its interface must not blank the line this process filled in.
func TestTheHelpersOwnViewReplacesTheUnprivilegedScan(t *testing.T) {
	report := InterfaceReport{
		Interface: "utun",
		Conflict:  "",
		Leftovers: nil,
	}
	applyHelperProbe(&report, hostnet.Capabilities{
		Version:   "1.2.3",
		Conflict:  "the official Tailscale client is running on this machine",
		Missing:   "wintun.dll is not next to app-tail.exe",
		Leftovers: []string{"/etc/resolver/example.ts.net"},
	}, nil)
	if !report.Helper.Running || report.Helper.Version != "1.2.3" {
		t.Errorf("a helper that answered was reported as %+v", report.Helper)
	}
	if report.Conflict == "" || report.Missing == "" || len(report.Leftovers) != 1 {
		t.Errorf("what only the helper could see was dropped: %+v", report)
	}
	if report.Interface != "utun" {
		t.Errorf("a helper that named no interface blanked the one this process found: %q", report.Interface)
	}

	// A helper that does name one is answering for the machine that will create it, so
	// its name is the one the report has to carry.
	named := InterfaceReport{Interface: "utun"}
	applyHelperProbe(&named, hostnet.Capabilities{Interface: "utun7"}, nil)
	if named.Interface != "utun7" {
		t.Errorf("the report kept %q over the name the helper gave", named.Interface)
	}
}

// Ready is what both the terminal and the dashboard lead with, and a reason is the whole
// difference between an offer to fix the machine and a switch that silently does nothing.
// Each of these states reaches a different remedy.
func TestTheReportSaysWhetherTheModeCouldBeTurnedOnAndWhyNot(t *testing.T) {
	tests := []struct {
		name   string
		report InterfaceReport
		ready  bool
		says   string
	}{
		{
			name:   "a platform without the mode",
			report: InterfaceReport{Supported: false},
			says:   "cannot run app-tail on a network interface",
		},
		{
			name:   "a machine missing a component",
			report: InterfaceReport{Supported: true, Privileged: true, Missing: "wintun.dll is not next to app-tail.exe"},
			says:   "wintun.dll",
		},
		{
			name:   "another client already running",
			report: InterfaceReport{Supported: true, Privileged: true, Conflict: "the official Tailscale client is running"},
			says:   "official Tailscale client",
		},
		{
			name:   "a process that already has the rights",
			report: InterfaceReport{Supported: true, Privileged: true},
			ready:  true,
		},
		{
			// Nothing to install here: this process is the privileged side, so what is
			// missing is the rights themselves. Reported ready, the switch would report
			// success and leave the machine exactly where it was.
			name:   "a platform with no helper, in a process without the rights",
			report: InterfaceReport{Supported: true},
			says:   "administrator rights",
		},
		{
			name:   "a helper that is answering",
			report: InterfaceReport{Supported: true, Helper: InterfaceHelperReport{Design: true, Running: true}},
			ready:  true,
		},
		{
			name: "a helper that did not answer",
			report: InterfaceReport{Supported: true, Helper: InterfaceHelperReport{
				Design: true, Installed: true, Problem: "the privileged helper is not running",
			}},
			says: "not running",
		},
		{
			name:   "a helper that was never installed",
			report: InterfaceReport{Supported: true, Helper: InterfaceHelperReport{Design: true}},
			says:   "not installed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ready, why := tt.report.Ready()
			if ready != tt.ready {
				t.Errorf("the mode was reported as ready = %t, want %t (reason %q)", ready, tt.ready, why)
			}
			if tt.ready && why != "" {
				t.Errorf("a machine that is ready carried the reason %q", why)
			}
			if !strings.Contains(why, tt.says) {
				t.Errorf("the reason %q does not mention %q, so it names no remedy", why, tt.says)
			}
		})
	}
}

// The resolver shares the privileged side with the interface mode and almost nothing else,
// so it answers for itself. A resolver switch that reported the interface's blockers would
// refuse on a machine that can resolve perfectly well, and one that reported ready without
// the rights would say it changed a machine it never touched.
func TestTheResolverAnswersForItselfRatherThanForTheInterface(t *testing.T) {
	tests := []struct {
		name   string
		report InterfaceReport
		ready  bool
		says   string
	}{
		{
			name:   "a platform that cannot be repointed",
			report: InterfaceReport{Supported: false},
			says:   "resolves names",
		},
		{
			name:   "something else already holding the resolver",
			report: InterfaceReport{Supported: true, Privileged: true, ResolverBusy: "port 53 is held by dnsmasq"},
			says:   "dnsmasq",
		},
		{
			name:   "a process that already has the rights",
			report: InterfaceReport{Supported: true, Privileged: true},
			ready:  true,
		},
		{
			name:   "a platform with no helper, in a process without the rights",
			report: InterfaceReport{Supported: true},
			says:   "administrator rights",
		},
		{
			name:   "a helper that is answering",
			report: InterfaceReport{Supported: true, Helper: InterfaceHelperReport{Design: true, Running: true}},
			ready:  true,
		},
		{
			name: "a helper that did not answer",
			report: InterfaceReport{Supported: true, Helper: InterfaceHelperReport{
				Design: true, Installed: true, Problem: "the privileged helper is not running",
			}},
			says: "not running",
		},
		{
			name:   "a helper that was never installed",
			report: InterfaceReport{Supported: true, Helper: InterfaceHelperReport{Design: true}},
			says:   "not installed",
		},
		{
			// Both are reasons the interface cannot run and neither is a reason a resolver
			// cannot: a machine with no wintun and another client running still resolves.
			name: "the interface's own blockers",
			report: InterfaceReport{
				Supported: true, Privileged: true,
				Missing:  "wintun.dll is not next to app-tail.exe",
				Conflict: "the official Tailscale client is running",
			},
			ready: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ready, why := tt.report.ResolverReady()
			if ready != tt.ready {
				t.Errorf("the resolver was reported as ready = %t, want %t (reason %q)", ready, tt.ready, why)
			}
			if tt.ready && why != "" {
				t.Errorf("a machine that is ready carried the reason %q", why)
			}
			if !strings.Contains(why, tt.says) {
				t.Errorf("the reason %q does not mention %q, so it names no remedy", why, tt.says)
			}
			if strings.Contains(why, "network interface") {
				t.Errorf("the resolver refused with %q, which tells somebody who asked for a "+
					"resolver about a network interface they did not ask for", why)
			}
		})
	}
}

// Inspecting the machine must not change it: this is what somebody reads when they suspect
// app-tail already left something behind. It is also the one call the dashboard makes on
// every poll, so it has to answer on a machine in any state at all.
func TestInspectingTheMachineReportsItWithoutChangingIt(t *testing.T) {
	before := hostnet.DetectLeftovers()

	report := InspectInterface(t.Context(), func(string, ...any) {})

	if report.Platform != runtime.GOOS {
		t.Errorf("the report names platform %q, want %q", report.Platform, runtime.GOOS)
	}
	if report.Supported != hostnet.Supported() {
		t.Errorf("the report says the mode is available = %t, want %t", report.Supported, hostnet.Supported())
	}
	// Each platform decides how many commands its leftovers take -- one per file plus a
	// cache flush, or a single command covering all of them. What has to hold everywhere is
	// that a clean machine is never handed a sudo command, and a dirty one is never left
	// without a remedy.
	switch {
	case len(report.Leftovers) == 0 && len(report.Undo) != 0:
		t.Errorf("nothing was left on this machine, yet it was told to run %v", report.Undo)
	case len(report.Leftovers) > 0 && len(report.Undo) == 0:
		t.Errorf("%v was left on this machine with no command to remove it", report.Leftovers)
	}
	if got := hostnet.DetectLeftovers(); len(got) != len(before) {
		t.Errorf("reading the machine changed what is on it: %v became %v", before, got)
	}
}

// The rights must never be reported as the reason not to ask for them. On a platform with no
// privileged helper, Ready's answer for an unprivileged process IS "app-tail needs
// administrator rights" -- right on a card, and circular at the one call site deciding
// whether to raise the prompt. What that gate needs is what would still be in the way after
// the prompt was accepted.
func TestRightsAreOnlyTheAnswerWhenNothingElseIsInTheWay(t *testing.T) {
	tests := []struct {
		name string
		// unprivileged, as every process is at the moment this question is asked.
		report    InterfaceReport
		blocks    string
		dnsBlocks string
	}{
		{
			name:   "a machine the rights are all that is missing on",
			report: InterfaceReport{Supported: true},
		},
		{
			name:      "a platform without the mode at all",
			report:    InterfaceReport{Supported: false},
			blocks:    "cannot run app-tail on a network interface",
			dnsBlocks: "cannot let app-tail change how it resolves names",
		},
		{
			name:   "a machine missing a component",
			report: InterfaceReport{Supported: true, Missing: "wintun.dll is not next to app-tail.exe"},
			blocks: "wintun.dll",
		},
		{
			// Decided before the Privileged arm, so forcing the rights on cannot clear it --
			// and it says nothing about resolving names, which needs no interface.
			name:   "another tailnet client already connected",
			report: InterfaceReport{Supported: true, Conflict: "the official Tailscale client is running"},
			blocks: "official Tailscale client",
		},
		{
			name:      "something else already answering DNS",
			report:    InterfaceReport{Supported: true, ResolverBusy: "another program is already answering DNS"},
			dnsBlocks: "already answering DNS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.report.Privileged {
				t.Fatal("this table is about the unprivileged process that asks the question; a privileged one never reaches it")
			}
			blocker := tt.report.BlockerDespiteRights()
			switch {
			case tt.blocks == "" && blocker != "":
				t.Errorf("the interface mode was refused for %q, which the rights would have cleared", blocker)
			case tt.blocks != "" && !strings.Contains(blocker, tt.blocks):
				t.Errorf("the interface mode reported %q as the blocker, want it to mention %q", blocker, tt.blocks)
			}

			dnsBlocker := tt.report.ResolverBlockerDespiteRights()
			switch {
			case tt.dnsBlocks == "" && dnsBlocker != "":
				t.Errorf("the machine-wide resolver was refused for %q, which the rights would have cleared", dnsBlocker)
			case tt.dnsBlocks != "" && !strings.Contains(dnsBlocker, tt.dnsBlocks):
				t.Errorf("the machine-wide resolver reported %q as the blocker, want it to mention %q", dnsBlocker, tt.dnsBlocks)
			}
		})
	}
}

// The report a card reads is unchanged: the rights are still what it names, because on that
// surface they are the honest answer.
func TestTheCardStillSaysTheRightsAreWhatIsMissing(t *testing.T) {
	report := InterfaceReport{Supported: true}
	if ready, why := report.Ready(); ready || !strings.Contains(why, "administrator rights") {
		t.Errorf("Ready = %t, %q; want it to still name the rights", ready, why)
	}
	if ready, why := report.ResolverReady(); ready || !strings.Contains(why, "administrator rights") {
		t.Errorf("ResolverReady = %t, %q; want it to still name the rights", ready, why)
	}
}
