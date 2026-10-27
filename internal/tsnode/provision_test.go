// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/hostnet"
)

// answerSequence stands in for the machine's own answer to "can this carry an interface
// yet?", which changes underneath the caller: it is no before the helper is installed and
// yes once the daemon launchd accepted has actually started.
type answerSequence struct {
	answers []error
	asked   int
}

func (s *answerSequence) next(context.Context) error {
	if s.asked >= len(s.answers) {
		s.asked++
		return errors.New("the privileged helper is not running")
	}
	err := s.answers[s.asked]
	s.asked++
	return err
}

// testSteps are steps that touch nothing, so a test drives the sequence rather than the
// machine. The delay is zero because what is being pinned is the number of attempts, and a
// real one would spend three seconds proving it.
func testSteps(usable func(context.Context) error, install func(context.Context, string, int) error) provisionSteps {
	return provisionSteps{
		usable:  usable,
		exePath: func() (string, error) { return "/usr/local/bin/app-tail", nil },
		install: install,
		owner:   501,
		checks:  provisionChecks,
	}
}

// The dialog is the cost of this whole path, and a machine that is already set up must not
// pay it: turning the mode off and on again, or running the setup twice, would otherwise
// ask for a password that changes nothing -- which is how an app teaches people to click
// through its prompts.
func TestAMachineThatIsAlreadySetUpIsNotAskedForAPassword(t *testing.T) {
	installs := 0
	steps := testSteps(
		func(context.Context) error { return nil },
		func(context.Context, string, int) error {
			installs++
			return nil
		},
	)

	if err := provision(t.Context(), func(string, ...any) {}, steps, RightsInterface, true); err != nil {
		t.Fatalf("provisionInterface on a machine that is already able = %v, want nothing to be done", err)
	}
	if installs != 0 {
		t.Errorf("a machine that is already set up was provisioned %d times, want none", installs)
	}
}

// The flag's help text promises no dialog, and the install is the one step that raises
// one. A machine that still needs it is told so and told what it would have been for --
// otherwise the refusal names a flag and leaves no way to get the mode by hand.
func TestAProcessForbiddenToElevateStopsAtTheDialogAndSaysWhy(t *testing.T) {
	installs := 0
	steps := testSteps(
		func(context.Context) error { return errors.New("the privileged helper is not running") },
		func(context.Context, string, int) error {
			installs++
			return nil
		},
	)

	err := provision(t.Context(), func(string, ...any) {}, steps, RightsInterface, false)

	if err == nil {
		t.Fatal("a machine that needed the rights was reported as set up by a process that never asked for them")
	}
	if installs != 0 {
		t.Errorf("administrator rights were asked for %d times despite --no-elevate", installs)
	}
	if !strings.Contains(err.Error(), "--no-elevate") {
		t.Errorf("the refusal said %q, which does not say why nothing was asked", err)
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("the refusal said %q, which does not carry what the machine is missing", err)
	}
}

// --no-elevate withholds the step that raises a dialog, not the answer to whether one was
// needed. The process that carries the flag is the one that already elevated -- the
// relaunched copy appends it to stop a second prompt -- so refusing outright would tell
// the one process holding the rights to go and get them.
func TestAMachineThatIsAlreadyAbleIsReadyEvenWhenNothingMayBeAsked(t *testing.T) {
	installs := 0
	steps := testSteps(
		func(context.Context) error { return nil },
		func(context.Context, string, int) error {
			installs++
			return nil
		},
	)

	if err := provision(t.Context(), func(string, ...any) {}, steps, RightsInterface, false); err != nil {
		t.Fatalf("provisionInterface on an able machine that may not elevate = %v, want it reported as ready", err)
	}
	if installs != 0 {
		t.Errorf("an able machine was provisioned %d times, want none", installs)
	}
}

// launchd returns as soon as it has accepted the job, not when the process is listening.
// Reporting success there would tell the user the machine is set up and then hand them the
// contained mode anyway, which is the one failure this path exists to prevent.
func TestSuccessIsReportedOnlyOnceTheHelperAnswers(t *testing.T) {
	answers := &answerSequence{answers: []error{
		errors.New("the privileged helper is not running"), // the check before installing
		errors.New("the privileged helper is not running"), // launchd has the job, the daemon is not up
		errors.New("the privileged helper is not running"),
		nil,
	}}
	var installedExe string
	var installedOwner int
	steps := testSteps(answers.next, func(_ context.Context, exe string, owner int) error {
		installedExe, installedOwner = exe, owner
		return nil
	})

	if err := provision(t.Context(), func(string, ...any) {}, steps, RightsInterface, true); err != nil {
		t.Fatalf("provisionInterface = %v, want the wait to have found the helper", err)
	}
	if answers.asked != 4 {
		t.Errorf("the machine was asked %d times, want it asked until it answered", answers.asked)
	}
	// The binary launchd will run and the account the helper serves are the two values the
	// install decides everything from, and neither is recoverable afterwards.
	if installedExe != "/usr/local/bin/app-tail" || installedOwner != 501 {
		t.Errorf("the helper was installed as %q for account %d, want this binary and this account",
			installedExe, installedOwner)
	}
}

// A daemon launchd accepted but never started is the shape of failure this cannot report as
// success, and the wait has to end somewhere: an unbounded one turns a broken install into
// a command that never returns.
func TestAHelperThatNeverStartsIsReportedRatherThanWaitedForForever(t *testing.T) {
	answers := &answerSequence{}
	steps := testSteps(answers.next, func(context.Context, string, int) error { return nil })

	err := provision(t.Context(), func(string, ...any) {}, steps, RightsInterface, true)

	if err == nil {
		t.Fatal("a helper that never started was reported as a machine that is set up")
	}
	if !strings.Contains(err.Error(), "not answering") {
		t.Errorf("the failure said %q, which does not say the helper was installed and did not come up", err)
	}
	// One before the install and provisionChecks after it. A wait that gave up on the
	// first attempt would fail every real install, where the daemon takes a moment.
	if want := 1 + provisionChecks; answers.asked != want {
		t.Errorf("the machine was asked %d times, want %d", answers.asked, want)
	}
}

// The dialog blocks until it is answered, and the caller that is bounded by a timeout --
// the dashboard's -- needs the wait to end when its context does rather than after its own
// full run of attempts.
func TestAWaitEndsWhenTheCallerGivesUp(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	answers := &answerSequence{}
	steps := testSteps(func(c context.Context) error {
		cancel()
		return answers.next(c)
	}, func(context.Context, string, int) error { return nil })
	// A real delay, so a wait that ignored the context would be caught by taking one
	// rather than by returning the wrong sentence instantly.
	steps.delay = provisionCheckDelay

	err := provision(ctx, func(string, ...any) {}, steps, RightsInterface, true)

	if err == nil {
		t.Fatal("an abandoned wait was reported as a machine that is set up")
	}
	if !strings.Contains(err.Error(), "wait for the privileged helper") {
		t.Errorf("the failure said %q, which does not say what was being waited for", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the failure %v does not carry the cancellation, so a caller cannot tell it from a broken install", err)
	}
}

// A dismissed dialog is an answer, and the caller acts on it: the CLI says the machine was
// left alone and the dashboard records it beside the mode. Wrapping it would make every
// caller match on text instead.
func TestADeclinedPromptReachesTheCallerAsItself(t *testing.T) {
	steps := testSteps(
		func(context.Context) error { return errors.New("the privileged helper is not running") },
		func(context.Context, string, int) error { return hostnet.ErrDeclined },
	)

	err := provision(t.Context(), func(string, ...any) {}, steps, RightsInterface, true)

	if !errors.Is(err, hostnet.ErrDeclined) {
		t.Errorf("provisionInterface = %v, want the declined prompt to survive to the caller", err)
	}
}

// The install copies this binary somewhere root-owned, so not knowing where it is has to
// stop the install rather than produce one pointed at nothing.
func TestAnUnfindableBinaryStopsTheInstallWithItsOwnReason(t *testing.T) {
	installs := 0
	steps := testSteps(
		func(context.Context) error { return errors.New("the privileged helper is not running") },
		func(context.Context, string, int) error {
			installs++
			return nil
		},
	)
	steps.exePath = func() (string, error) { return "", errors.New("readlink /proc/self/exe: no such file") }

	err := provision(t.Context(), func(string, ...any) {}, steps, RightsInterface, true)

	if err == nil {
		t.Fatal("an install went ahead without knowing which binary to install")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("the failure said %q, which does not carry what the machine said", err)
	}
	if installs != 0 {
		t.Errorf("the helper was installed %d times without a binary to install", installs)
	}
}

// The install reports what it half-did through the log rather than its return value, so
// provisioning without one would discard it. Asked of the exported entry point, because
// that is the argument a caller can leave out.
func TestProvisioningTheInterfaceRefusesToRunWithNowhereToReport(t *testing.T) {
	err := ProvisionInterface(t.Context(), nil, true, "")
	if err == nil {
		t.Fatal("provisioning with no log function was accepted")
	}
	if !strings.Contains(err.Error(), "log function") {
		t.Errorf("the refusal said %q, which does not say what was missing", err)
	}
}

// The steps this machine actually gets, as opposed to the ones the tests above make up.
// Each one is what makes the real path do anything at all, and a nil or wrong value here
// would leave every test above passing against a path that installs nothing.
func TestTheStepsThisMachineGetsReachTheRealPrivilegedSide(t *testing.T) {
	steps := machineProvisionSteps(func(string, ...any) {}, RightsInterface, "")

	if steps.owner != os.Getuid() {
		t.Errorf("the helper would be installed for account %d, want this process's own %d",
			steps.owner, os.Getuid())
	}
	if steps.checks != provisionChecks || steps.delay != provisionCheckDelay {
		t.Errorf("the wait is %d checks of %v, want %d of %v",
			steps.checks, steps.delay, provisionChecks, provisionCheckDelay)
	}

	// The real check, asked of this machine. Either answer is correct -- it depends on
	// whether a helper happens to be installed here -- and what is being pinned is that
	// the step reaches the privileged side rather than reporting a fixed answer.
	//
	// Bounded, because that privileged side is a separately installed binary a suite has no
	// way to put into a known state.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := steps.usable(ctx); err != nil && strings.TrimSpace(err.Error()) == "" {
		t.Error("the check reported a failure with nothing in it")
	}

	// The real install, asked for the one account it must refuse. Any other account would
	// raise a password dialog, which a suite must never do.
	err := steps.install(t.Context(), "/bin/ls", 0)
	if err == nil {
		t.Fatal("the install step accepted root as the account to serve, so it is not the real one")
	}
	if !strings.Contains(err.Error(), "own account") {
		t.Errorf("the install step refused with %q, which is not the privileged side's own refusal", err)
	}

	exe, err := steps.exePath()
	if err != nil {
		t.Fatalf("find this binary: %v", err)
	}
	if exe == "" {
		t.Error("the install would copy a binary at no path at all")
	}
}
