// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/elevate"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// Rights names what a caller needs from this machine's privileged side.
//
// The two are independent, which is the whole reason this is a parameter: a machine
// already running another tailnet client cannot take a network interface and can still
// switch its own resolver, and a machine whose port 53 is taken by something else can take
// the interface and cannot answer DNS. Asking one question for both would refuse each
// feature for the other's reasons.
type Rights int

const (
	// RightsInterface is the network-interface mode: a real interface, routes and
	// per-domain resolver files.
	RightsInterface Rights = iota
	// RightsResolver is the machine-wide resolver: a loopback DNS socket and this
	// machine's own resolver setting.
	RightsResolver
)

// String is what a refusal calls the feature it is refusing, in the user's words.
func (r Rights) String() string {
	if r == RightsResolver {
		return "the machine-wide resolver"
	}
	return "the network-interface mode"
}

// Preflight reports whether a node built from these parameters could start, without
// starting one and without changing anything on the machine.
//
// It exists for one moment: switching modes tears the running node down before the
// replacement binds the same state directory, and past that point a failure leaves the
// machine with no tailnet at all. Everything that can be found out first is found out
// here, while the old node is still up, so a machine with no helper or a conflicting
// client gets a refusal instead of an outage.
//
// A node that does not want an interface has nothing to check and reports so.
func Preflight(ctx context.Context, p ServerParams, logf func(format string, args ...any)) error {
	if !p.TUN() {
		return nil
	}
	if logf == nil {
		return errors.New("preflight: no log function was provided")
	}
	return rightsUsable(ctx, logf, RightsInterface)
}

// rightsUsable reports whether this machine could carry what the caller wants right now,
// leaving out whether any particular node wants it. It takes the Rights rather than
// reading them off a node, so a check made before anything is built asks the same
// question the running path does.
func rightsUsable(ctx context.Context, logf func(format string, args ...any), want Rights) error {
	host, err := hostnet.Open(ctx, hostnet.Options{Logf: logf})
	if err != nil {
		return WithNextStep(err)
	}
	// Nothing was opened, so this releases a connection and nothing else.
	defer func() {
		if err := host.Close(); err != nil {
			logf("could not close the connection to the privileged side: %v", err)
		}
	}()
	return checkHost(ctx, host, want, logf)
}

// provisionChecks and provisionCheckDelay bound the wait for the daemon that was just
// registered. launchd returns as soon as it has accepted the job, not when the process is
// listening, so an install followed immediately by a connection finds nothing there.
const (
	provisionChecks     = 10
	provisionCheckDelay = 300 * time.Millisecond
)

// provisionSteps are what provisioning does to the machine: reading whether it is already
// able, finding this binary, and obtaining the rights. They are values rather than direct
// calls because the last of them raises the system's password dialog, which a suite must
// never raise -- and which is exactly the step whose surrounding decisions are worth
// pinning.
type provisionSteps struct {
	usable  func(ctx context.Context) error
	exePath func() (string, error)
	install func(ctx context.Context, exe string, owner int) error
	owner   int
	checks  int
	delay   time.Duration
}

// machineProvisionSteps are the real steps, performed on the machine this is running on.
// configPath is the config file whose network changes the install also approves, or "": it
// is read here, as this account, and the dialog lists what it asks for.
func machineProvisionSteps(logf func(format string, args ...any), want Rights, configPath string) provisionSteps {
	return provisionSteps{
		usable:  func(ctx context.Context) error { return rightsUsable(ctx, logf, want) },
		exePath: os.Executable,
		install: func(ctx context.Context, exe string, owner int) error {
			needs, err := installNeeds(configPath, hostnet.AttachedNetworks)
			if err != nil {
				return err
			}
			return hostnet.ProvisionHelper(ctx, logf, exe, owner, needs)
		},
		// The account this process runs as is the one whose agent will connect, and the
		// recorded owner is the whole access control on the helper's socket.
		owner:  os.Getuid(),
		checks: provisionChecks,
		delay:  provisionCheckDelay,
	}
}

// ProvisionInterface makes this machine able to carry the interface mode, asking for the
// administrator rights it needs rather than telling the caller to go and get them.
//
// It is for a user action -- turning the mode on, or asking for the setup directly --
// and never for a start: obtaining the rights raises a dialog, and a dialog on every
// login is how an app trains people to dismiss it. A machine that is already able is left
// alone, so running this twice costs nothing and prompts for nothing.
//
// mayElevate is false for a process started with --no-elevate, which withholds the one
// step that raises a dialog rather than the answer to whether one was needed. configPath is
// the config file whose network changes the same password also approves, or "" for none.
func ProvisionInterface(ctx context.Context, logf func(format string, args ...any), mayElevate bool, configPath string) error {
	return Provision(ctx, logf, RightsInterface, mayElevate, configPath)
}

// Provision makes this machine able to carry what the caller wants, asking for the
// administrator rights that needs. The rights are the same rights either way -- one helper,
// one installation -- and what differs is which machine state counts as already able and
// what a refusal names. configPath is as for ProvisionInterface.
func Provision(ctx context.Context, logf func(format string, args ...any), want Rights, mayElevate bool, configPath string) error {
	return provision(ctx, logf, machineProvisionSteps(logf, want, configPath), want, mayElevate)
}

// provision is the sequence Provision follows, separated from the machine it follows it on.
func provision(ctx context.Context, logf func(format string, args ...any), steps provisionSteps, want Rights, mayElevate bool) error {
	if logf == nil {
		return errors.New("provision: no log function was provided")
	}
	usable := steps.usable(ctx)
	if usable == nil {
		return nil
	}
	// A machine that is already able has been reported as such above, so this is reached
	// only where a dialog is the next thing that would happen. The reason it would have
	// been raised for is carried, because it is what says how to get the mode by hand.
	if !mayElevate {
		return fmt.Errorf("app-tail was started with --no-elevate, so it did not ask for the "+
			"administrator rights %s needs: %w", want, usable)
	}
	exe, err := steps.exePath()
	if err != nil {
		return fmt.Errorf("find this program's own path to install the privileged helper: %w", err)
	}
	if err := steps.install(ctx, exe, steps.owner); err != nil {
		return err
	}
	return waitForInterface(ctx, steps)
}

// waitForInterface reports whether the helper that was just installed is answering.
//
// Returning as soon as launchd accepts the job would report success for a daemon that
// never came up, which is the one failure this whole path exists to prevent: the user
// would be told the machine is set up and get the contained mode anyway.
func waitForInterface(ctx context.Context, steps provisionSteps) error {
	err := steps.usable(ctx)
	for attempt := 1; err != nil && attempt < steps.checks; attempt++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for the privileged helper to start: %w", ctx.Err())
		case <-time.After(steps.delay):
		}
		err = steps.usable(ctx)
	}
	if err != nil {
		return fmt.Errorf("the privileged helper was installed but is not answering: %w", err)
	}
	return nil
}

// ErrHelperFromAnotherBuild is the machine state SetupWouldFix answers yes to: a
// privileged helper installed for a different build of app-tail, which takes commands
// only from the binary it was installed for.
//
// Named here rather than reached for through the package holding the rights, because
// which packages may reach that one is part of the design. Everything above this boundary
// asks tsnode what a machine can do, and this is what one of the answers is called.
var ErrHelperFromAnotherBuild = hostnet.ErrHelperFromAnotherBuild

// ErrDeclined is an administrator dialog that was dismissed: an answer, not a failure.
var ErrDeclined = hostnet.ErrDeclined

// ErrApproveByHand is a machine where app-tail cannot ask for an administrator's approval
// itself; the error carrying it names the command to run instead.
var ErrApproveByHand = hostnet.ErrApproveByHand

// ApproveGrants asks an administrator to approve needs, which is what makes the privileged
// side stop refusing them. See hostnet.ApproveGrants.
func ApproveGrants(ctx context.Context, logf func(format string, args ...any), needs []grants.Need) error {
	return hostnet.ApproveGrants(ctx, logf, needs)
}

// SetupWouldFix reports whether running the setup would put this refusal right, rather
// than only describing it again.
//
// One refusal qualifies, which is what makes it safe to act on without being asked. A
// helper from another build is a machine that was set up and then had app-tail replaced
// underneath it: the helper authenticates the agent by which binary it is, so an upgrade
// leaves the two out of step, and nothing on the machine will ever put them back. This
// build's helper installed over it is the whole fix, and the state cannot return until
// the next upgrade.
//
// None of the others is one to act on unasked. A machine with no helper never had one,
// and offering to install it wherever this is consulted is a dialog at every login. A
// helper held by another account, or busy with another app, is somebody else's
// arrangement and taking it over is a decision. A platform that cannot carry the mode has
// nothing to install.
func SetupWouldFix(err error) bool {
	return errors.Is(err, hostnet.ErrHelperFromAnotherBuild)
}

// checkHost is the decision Preflight makes, separated from the act of reaching the
// privileged side so it can be exercised against every answer that side can give -- which
// on a real machine would each need the machine to be in that state.
func checkHost(ctx context.Context, host hostnet.Host, want Rights, logf func(format string, args ...any)) error {
	caps, err := host.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("ask this machine what it can carry: %w", err)
	}
	if want == RightsResolver {
		// A running tailnet client is not in the way of a resolver, and a missing wintun
		// is a component only the interface needs. What is in the way is something already
		// holding every address app-tail would answer DNS on.
		if caps.ResolverBusy != "" {
			return errors.New(caps.ResolverBusy)
		}
		return nil
	}
	if ok, why := caps.Usable(); !ok {
		return errors.New(why)
	}
	if len(caps.Leftovers) > 0 {
		// Reported and not refused: they are removed as part of opening the interface,
		// and they are also what an unclean exit looks like from outside. Refusing here
		// would make a crash require manual repair before the app would start again.
		logf("a previous run left this behind, and it will be cleared on start: %s",
			strings.Join(caps.Leftovers, ", "))
	}
	return nil
}

// installHint says how to get the helper onto this machine, which is not the same
// sentence everywhere: a platform that can install it asks for the rights itself and needs
// no terminal at all, while one that cannot has to be told the command to run as root.
// Naming the wrong one sends somebody to a command that does not exist here.
//
// The platform's answer is passed in rather than read here so both sentences are reachable
// from any machine -- otherwise each one is only ever exercised on the platform it belongs
// to, and the other is whatever it was last edited to say.
func installHint(canInstall bool) string {
	if canInstall {
		return "Turn the network-interface mode on again, or run `app-tail tun setup`, " +
			"and app-tail will ask for your password and set it up."
	}
	return "Start it with `sudo app-tail tun helper`."
}

// reinstallHint says how to hand an installed helper to the account that is asking. It is
// separate from installHint because the machine already has one: pointing at a first
// install would describe work that has been done, which is how somebody concludes the app
// is telling them to do something they just did.
func reinstallHint(canInstall bool) string {
	if canInstall {
		return "Turn the network-interface mode on again, or run `app-tail tun setup`, " +
			"and app-tail will set it up for this account."
	}
	return "Start it again with `sudo app-tail tun helper`, recording this account as the one it serves."
}

// elevateHint says how to obtain rights on a platform that has no helper to hold them. One
// of them relaunches itself under a prompt as it starts, so it needs only to be started
// again -- telling somebody there to restart it as an administrator sends them to a context
// menu for something the app does on its own.
//
// The platform's answer is passed in rather than read here so both sentences are reachable
// from any machine, and not only from the one each belongs to.
func elevateHint(relaunches bool) string {
	if relaunches {
		return "Quit app-tail and start it again, and it will ask for them."
	}
	return "Restart app-tail as an administrator, or leave the network mode set to the contained one."
}

// replaceHint says how to put the matching helper on the machine, over the one already
// there. The two sentences split for the same reason installHint's do: one machine is
// asked for a password, and the other has to be given a command it can run as root.
//
// The first leads with the restart because that is what actually happens: this is the one
// refusal app-tail repairs unasked (SetupWouldFix), so a machine reading this sentence is
// a start away from being fixed. Leading with a command would send somebody to a terminal
// to do by hand the thing the next start does for them.
func replaceHint(canInstall bool) string {
	if canInstall {
		return "Restart app-tail and it will ask for your password and replace it. " +
			"The dashboard's network-interface card and `app-tail tun setup` do the same."
	}
	return "Start it again with `sudo app-tail tun helper`, from the same app-tail this one runs from."
}

// WithNextStep returns the refusal carrying the sentence that says what to do about it.
// Each of these otherwise surfaces as a phrase about a socket or a version -- true, and not
// the part anyone can act on. Anything unrecognised is returned as it stands: a description
// of a failure nobody anticipated is worth more than advice invented for it.
//
// Exported because the refusals reach a user from two places, the mode switch and the
// doctor, and a second copy of these sentences is a second place for them to go stale.
func WithNextStep(err error) error {
	switch {
	case errors.Is(err, hostnet.ErrUnsupported):
		return errors.New("this platform cannot run app-tail on a network interface. Leave the network mode set to the contained one.")
	case errors.Is(err, hostnet.ErrHelperNotOpenToThisAccount):
		return fmt.Errorf("%w. %s", err, reinstallHint(hostnet.SupportsHelperInstall()))
	case errors.Is(err, hostnet.ErrHelperFromAnotherBuild):
		return fmt.Errorf("%w. %s", err, replaceHint(hostnet.SupportsHelperInstall()))
	case errors.Is(err, hostnet.ErrHelperBusy):
		return fmt.Errorf("%w. Quit the other one, or turn its network-interface mode off, and try again.", err)
	case errors.Is(err, hostnet.ErrNoHelper):
		return fmt.Errorf("%w. %s", err, installHint(hostnet.SupportsHelperInstall()))
	case errors.Is(err, hostnet.ErrNeedsElevation):
		return fmt.Errorf("%w. %s", err, elevateHint(elevate.Supported()))
	}
	return err
}
