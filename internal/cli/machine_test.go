// SPDX-License-Identifier: MIT

package cli

// The commands that change this machine rather than talk to the agent: putting the resolver
// back, installing and removing the helper, and deciding whether a save needs administrator
// rights. Each is driven with the machine stood in for, so what the command prints, refuses
// and passes on is pinned on every platform rather than only where the real change happens.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/elevate"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/sysdns"
)

// machineRestores stands in for the machine-level resolver repair and records whether the
// command reached it.
func machineRestores(t *testing.T, restored bool, err error) *int {
	t.Helper()
	calls := 0
	before := restoreSystemDNS
	restoreSystemDNS = func(context.Context, func(string, ...any)) (bool, error) {
		calls++
		return restored, err
	}
	t.Cleanup(func() { restoreSystemDNS = before })
	return &calls
}

// `dns restore` is run by somebody whose machine cannot resolve names, so each answer the
// machine can give has to be told apart in the output: put back, nothing to put back, partly
// put back, and could not.
func TestDNSRestoreSaysWhichOfTheMachinesAnswersItGot(t *testing.T) {
	t.Run("put back", func(t *testing.T) {
		calls := machineRestores(t, true, nil)
		env, out := captureTunEnv()

		if err := runDNS(t.Context(), []string{"restore"}, env); err != nil {
			t.Fatalf("dns restore: %v", err)
		}

		if *calls != 1 {
			t.Errorf("the machine was asked %d times, want once", *calls)
		}
		if !strings.Contains(out.String(), "back to what it was") {
			t.Errorf("output %q does not say the resolver was put back", out.String())
		}
	})

	t.Run("nothing recorded", func(t *testing.T) {
		machineRestores(t, false, nil)
		env, out := captureTunEnv()

		if err := runDNS(t.Context(), []string{"restore"}, env); err != nil {
			t.Fatalf("dns restore: %v", err)
		}

		if !strings.Contains(out.String(), "Nothing to put back") {
			t.Errorf("output %q does not say there was nothing to put back", out.String())
		}
		if strings.Contains(out.String(), "back to what it was") {
			t.Errorf("output %q claims a repair on a machine nothing was recorded for", out.String())
		}
	})

	t.Run("partly back", func(t *testing.T) {
		partial := &sysdns.PartialRestoreError{Services: []string{"Wi-Fi", "Thunderbolt Ethernet"}}
		machineRestores(t, true, partial)
		env, out := captureTunEnv()

		err := runDNS(t.Context(), []string{"restore"}, env)

		if err != nil {
			t.Fatalf("a partial restore was reported as a failure: %v", err)
		}
		for _, want := range []string{"Most of this machine's resolver", "  Wi-Fi\n", "  Thunderbolt Ethernet\n", "run this again"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("output does not carry %q:\n%s", want, out.String())
			}
		}
	})

	// The repair also hands back services the record lost, and a failure there is a service
	// still pointed at nothing. Saying only that the listed ones were left would send the user
	// away from the one that matters.
	t.Run("partly back, and another service failed", func(t *testing.T) {
		partial := &sysdns.PartialRestoreError{Services: []string{"Thunderbolt Ethernet"}}
		stray := errors.New("release Wi-Fi: networksetup exited 4")
		machineRestores(t, true, errors.Join(partial, stray))
		env, out := captureTunEnv()

		err := runDNS(t.Context(), []string{"restore"}, env)

		if !errors.Is(err, stray) {
			t.Fatalf("dns restore = %v, want the failure beside the partial restore carried", err)
		}
		if !strings.Contains(out.String(), "  Thunderbolt Ethernet\n") {
			t.Errorf("output does not list the service the partial restore left:\n%s", out.String())
		}
	})

	// The Windows boot task runs this at every boot, so meeting a running app-tail is
	// ordinary, and it is not a failure: that app-tail puts its own override back.
	t.Run("an app-tail is serving", func(t *testing.T) {
		machineRestores(t, false, hostnet.ErrResolverServed)
		env, out := captureTunEnv()

		if err := runDNS(t.Context(), []string{"restore"}, env); err != nil {
			t.Fatalf("dns restore with an app-tail serving = %v, want no error", err)
		}
		if !strings.Contains(out.String(), "app-tail is running") {
			t.Errorf("output %q does not say a running app-tail is serving the resolver", out.String())
		}
		if strings.Contains(out.String(), "Nothing to put back") {
			t.Errorf("output %q says nothing was redirected on a machine pointed at a running app-tail", out.String())
		}
	})

	t.Run("could not", func(t *testing.T) {
		refused := errors.New("networksetup: permission denied")
		machineRestores(t, false, refused)
		env, out := captureTunEnv()

		err := runDNS(t.Context(), []string{"restore"}, env)

		if !errors.Is(err, refused) {
			t.Fatalf("dns restore = %v, want the machine's own refusal carried", err)
		}
		if !strings.Contains(err.Error(), "administrator rights") {
			t.Errorf("error %q does not say the command needs administrator rights", err)
		}
		if out.Len() != 0 {
			t.Errorf("a failed restore printed %q as though something was done", out.String())
		}
	})
}

// An argument the command does not take is a usage mistake, and a usage mistake never
// touches the machine: `dns restore wifi` is somebody who expected a narrower repair than
// exists, not permission to run the whole one.
func TestDNSRestoreWithAnArgumentIsAUsageErrorThatTouchesNothing(t *testing.T) {
	calls := machineRestores(t, true, nil)
	env, _ := captureTunEnv()

	err := runDNS(t.Context(), []string{"restore", "Wi-Fi"}, env)

	if !errors.Is(err, ErrUsage) {
		t.Fatalf("dns restore Wi-Fi = %v, want a usage error", err)
	}
	if *calls != 0 {
		t.Error("a usage error still ran the repair")
	}
}

// helperInstaller stands in for the platform's install step, recording what the command
// handed it.
type helperInstaller struct {
	supported bool
	installs  []installCall
	removals  int
	refuse    error
}

type installCall struct {
	exe   string
	owner int
}

func standInInstaller(t *testing.T, supported bool, refuse error) *helperInstaller {
	t.Helper()
	in := &helperInstaller{supported: supported, refuse: refuse}
	before := [3]any{supportsHelperInstall, installHelper, uninstallHelper}
	supportsHelperInstall = func() bool { return in.supported }
	installHelper = func(_ context.Context, _ func(string, ...any), exe string, owner int) error {
		in.installs = append(in.installs, installCall{exe, owner})
		return in.refuse
	}
	uninstallHelper = func(context.Context, func(string, ...any)) error {
		in.removals++
		return in.refuse
	}
	t.Cleanup(func() {
		supportsHelperInstall = before[0].(func() bool)
		installHelper = before[1].(func(context.Context, func(string, ...any), string, int) error)
		uninstallHelper = before[2].(func(context.Context, func(string, ...any)) error)
	})
	return in
}

// The helper is installed to serve the account that ran sudo, from the binary that is
// running: the recorded owner is the whole access control on a root socket, and a path other
// than this program's own is a helper that starts something else as root.
func TestInstallHelperInstallsThisProgramForTheAccountThatRanSudo(t *testing.T) {
	in := standInInstaller(t, true, nil)
	env, out := captureTunEnv()
	env.Getenv = func(name string) string {
		if name == "SUDO_UID" {
			return "501"
		}
		return ""
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("find this program: %v", err)
	}

	if err := runTun(t.Context(), []string{"install-helper"}, env); err != nil {
		t.Fatalf("tun install-helper: %v", err)
	}

	if len(in.installs) != 1 || in.installs[0] != (installCall{self, 501}) {
		t.Errorf("installed %+v, want this program %s serving user 501", in.installs, self)
	}
	if !strings.Contains(out.String(), "serving user 501") || !strings.Contains(out.String(), tunEnableCommand) {
		t.Errorf("output does not name the owner and the command that turns the mode on:\n%s", out.String())
	}
}

// --owner overrides SUDO_UID, and an owner that cannot be resolved stops the install before
// anything is written: a helper serving root, or nobody, is one no agent can use and one
// anybody can talk to.
func TestInstallHelperRefusesAnOwnerItCannotServeBeforeInstalling(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  func(string) string
		want string
	}{
		{"root by flag", []string{"install-helper", "--owner", "0"}, func(string) string { return "501" }, "root is not one"},
		{"nobody", []string{"install-helper"}, func(string) string { return "" }, "could not tell which account"},
		{"not a number", []string{"install-helper", "--owner", "sellitus"}, func(string) string { return "" }, `"sellitus"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := standInInstaller(t, true, nil)
			env, _ := captureTunEnv()
			env.Getenv = tc.env

			err := runTun(t.Context(), tc.args, env)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("tun %v = %v, want a refusal saying %q", tc.args, err, tc.want)
			}
			if len(in.installs) != 0 {
				t.Errorf("a refused owner still installed %+v", in.installs)
			}
		})
	}
}

// A platform with no install step says what to do there instead, and never reaches the
// installer -- which on those platforms is the stub that would refuse anyway, with a message
// about what the platform lacks rather than what the person should run.
func TestInstallAndUninstallOnAPlatformWithNoInstallerSayWhatToDoInstead(t *testing.T) {
	in := standInInstaller(t, false, nil)
	env, _ := captureTunEnv()
	env.Getenv = func(string) string { return "501" }

	for _, args := range [][]string{{"install-helper"}, {"uninstall-helper"}, {"setup"}} {
		err := runTun(t.Context(), args, env)
		if err == nil || err.Error() != noInstallerHere {
			t.Errorf("tun %v = %v, want %q", args, err, noInstallerHere)
		}
	}
	if len(in.installs) != 0 || in.removals != 0 {
		t.Errorf("a platform with no installer still ran it: %d installs, %d removals", len(in.installs), in.removals)
	}
}

// What the platform's install step says goes to the person unchanged: it is the one place
// that knows which launchd step failed, and wrapping it here would say less.
func TestAnInstallOrRemovalThatFailsCarriesThePlatformsOwnReason(t *testing.T) {
	refused := errors.New("launchctl bootstrap: Input/output error")
	in := standInInstaller(t, true, refused)
	env, out := captureTunEnv()
	env.Getenv = func(string) string { return "501" }

	if err := runTun(t.Context(), []string{"install-helper"}, env); !errors.Is(err, refused) {
		t.Errorf("tun install-helper = %v, want the platform's refusal", err)
	}
	if err := runTun(t.Context(), []string{"uninstall-helper"}, env); !errors.Is(err, refused) {
		t.Errorf("tun uninstall-helper = %v, want the platform's refusal", err)
	}
	if len(in.installs) != 1 || in.removals != 1 {
		t.Errorf("%d installs and %d removals reached the platform, want one each", len(in.installs), in.removals)
	}
	if strings.Contains(out.String(), "Installed") || strings.Contains(out.String(), "Removed") {
		t.Errorf("a failed step was reported as done:\n%s", out.String())
	}
}

// Removal takes the helper and everything it installed, and says so along with what still
// works: somebody removing the helper is choosing the contained mode, and needs to hear that
// it needs nothing.
func TestUninstallHelperRemovesTheHelperAndSaysWhatStillWorks(t *testing.T) {
	in := standInInstaller(t, true, nil)
	env, out := captureTunEnv()

	if err := runTun(t.Context(), []string{"uninstall-helper"}, env); err != nil {
		t.Fatalf("tun uninstall-helper: %v", err)
	}

	if in.removals != 1 {
		t.Errorf("the platform removal ran %d times, want once", in.removals)
	}
	if !strings.Contains(out.String(), "Removed the app-tail helper") || !strings.Contains(out.String(), "contained mode still works") {
		t.Errorf("output does not say what was removed and what still works:\n%s", out.String())
	}
}

// machineOverridden stands in for the machine's record of whether an earlier run left its
// resolver pointed at app-tail, counting the reads so a cached answer would show.
func machineOverridden(t *testing.T, overridden bool, err error) *int {
	t.Helper()
	reads := 0
	before := systemDNSOverridden
	systemDNSOverridden = func(context.Context) (bool, error) {
		reads++
		return overridden, err
	}
	t.Cleanup(func() { systemDNSOverridden = before })
	return &reads
}

// A record that cannot be read answers no. That is what every unprivileged process on macOS
// and Linux gets, and treating it as yes would offer every one of them a restart to repair a
// machine that is fine.
func TestAStaleOverrideIsOnlyReportedWhenTheRecordCanBeReadAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		overridden bool
		err        error
		want       bool
	}{
		{"recorded and still in force", true, nil, true},
		{"recorded and already put back", false, nil, false},
		{"record unreadable", true, errors.New("open: permission denied"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			machineOverridden(t, tc.overridden, tc.err)
			if got := staleOverrideOnThisMachine(context.Background()); got != tc.want {
				t.Errorf("staleOverrideOnThisMachine = %t, want %t", got, tc.want)
			}
		})
	}
}

// The facts a save is judged by come from that save and from the machine as it is now. The
// machine is read on every call: the way out of a stale override is `dns restore` from another
// process, and a cached yes would keep offering a restart to a machine already put back.
func TestAdminRestartFactsFollowTheSaveAndReadTheMachineEveryTime(t *testing.T) {
	reads := machineOverridden(t, true, nil)
	facts := adminRestartFacts(config.Flags{})

	tun := config.Settings{InterfaceEnabled: true, InterfaceMode: config.NetworkTUN}
	got := facts(tun)
	if !got.WantsInterface || got.WantsSystemDNS || !got.StaleOverride || got.AlreadyAsked {
		t.Errorf("facts for the interface mode = %+v, want the interface and the stale override and nothing else asked for", got)
	}

	dns := config.Settings{SystemDNSEnabled: true, SystemDNSProfile: "cloudflare"}
	got = facts(dns)
	if got.WantsInterface || !got.WantsSystemDNS {
		t.Errorf("facts for the machine-wide resolver = %+v, want the resolver and not the interface", got)
	}

	if *reads != 2 {
		t.Errorf("the machine was read %d times over two saves, want once per save", *reads)
	}

	// The same record, put back between two saves, stops being reported.
	machineOverridden(t, false, nil)
	if facts(tun).StaleOverride {
		t.Error("a stale override that was put back is still reported")
	}
}

// --no-elevate is carried into every later save. A copy told not to ask cannot prompt, and a
// restart banner it cannot honour is worse than none: AlreadyAsked is what stops the predicate
// there, on every platform, whatever the save asks for.
func TestNoElevateIsCarriedIntoEverySaveAndStopsTheRestart(t *testing.T) {
	machineOverridden(t, true, nil)
	noElevate := true
	wants := config.Settings{InterfaceEnabled: true, InterfaceMode: config.NetworkTUN, SystemDNSEnabled: true, SystemDNSProfile: "cloudflare"}

	facts := adminRestartFacts(config.Flags{NoElevate: &noElevate})(wants)
	if !facts.AlreadyAsked {
		t.Fatalf("facts = %+v, want --no-elevate carried as AlreadyAsked", facts)
	}
	if AdminRestartNeeded(config.Flags{NoElevate: &noElevate})(wants) {
		t.Error("a copy told not to ask still offers a restart that would ask")
	}

	// Without the flag the decision is the platform's: the facts say everything is wanted,
	// and only a platform that elevates turns that into a restart.
	asked := adminRestartFacts(config.Flags{})(wants)
	if asked.AlreadyAsked {
		t.Errorf("facts = %+v, want a copy never told not to ask still able to", asked)
	}
	if got, want := AdminRestartNeeded(config.Flags{})(wants), elevate.Needed(asked); got != want {
		t.Errorf("AdminRestartNeeded = %t, want the elevation decision %t for the same facts", got, want)
	}
	if AdminRestartNeeded(config.Flags{})(config.Settings{}) && !elevate.Needed(adminRestartFacts(config.Flags{})(config.Settings{})) {
		t.Error("a save asking for nothing offers a restart")
	}
}

// The agent asks this at the moment a feature is turned on, and it has to be the start-up's
// own answer: a yes where the start-up would not prompt restarts app-tail for nothing, and a
// copy told not to ask must never restart into a copy that will not ask either.
func TestRightsByRestartIsTheStartUpDecision(t *testing.T) {
	if RightsByRestart(config.Flags{NoElevate: ptr(true)})() {
		t.Error("a copy told not to ask restarts to obtain rights")
	}
	want := elevate.Needed(rightsFacts(rightsWants{systemDNS: true}, false))
	if got := RightsByRestart(config.Flags{})(); got != want {
		t.Errorf("RightsByRestart = %t, want the start-up decision %t for a feature that needs rights", got, want)
	}
}

// The alert is the only way a refusal reaches somebody on a build with no terminal, so the
// warning has to reach it -- and only when there is one: a declined prompt on a machine that
// is fine raises nothing.
func TestTheStaleOverrideWarningReachesTheAlertOnlyWhenThereIsOne(t *testing.T) {
	var shown []string
	before := showAlert
	showAlert = func(message string) { shown = append(shown, message) }
	t.Cleanup(func() { showAlert = before })

	warnStaleOverride(rightsWants{interfaceMode: true}, errors.New("the prompt was declined"))
	if len(shown) != 0 {
		t.Fatalf("a declined prompt on a machine that is fine raised %q", shown)
	}

	warnStaleOverride(rightsWants{staleOverride: true}, errors.New("the prompt was declined"))
	if len(shown) != 1 {
		t.Fatalf("a stale override raised %d alerts, want one", len(shown))
	}
	for _, want := range []string{"still pointed at app-tail", "the prompt was declined", "dns restore"} {
		if !strings.Contains(shown[0], want) {
			t.Errorf("the alert does not carry %q:\n%s", want, shown[0])
		}
	}

	warnStaleOverride(rightsWants{staleOverride: true}, nil)
	if len(shown) != 2 || strings.Contains(shown[1], "declined") {
		t.Errorf("a stale override with no refusal to report raised %q, want the warning without a reason", shown[1:])
	}
}
