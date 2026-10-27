// SPDX-License-Identifier: MIT

package tsnode

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/hostnet"
)

// answeringHost stands in for the privileged side, which is a separate process holding
// root. Substituting it is how every answer that side can give gets exercised: on a real
// machine each one would need the machine itself to be in that state, and one of them --
// another tailnet client running -- cannot be arranged at all without breaking the machine
// the test runs on.
type answeringHost struct {
	caps hostnet.Capabilities
	err  error
}

var _ hostnet.Host = (*answeringHost)(nil)

func (h *answeringHost) Capabilities(context.Context) (hostnet.Capabilities, error) {
	return h.caps, h.err
}
func (h *answeringHost) OpenTUN(context.Context, string) (tun.Device, string, error) {
	return nil, "", errors.New("this host opens no interface")
}
func (h *answeringHost) RouterUp(context.Context) error                  { return nil }
func (h *answeringHost) SetRoutes(context.Context, *router.Config) error { return nil }
func (h *answeringHost) SetHostRoutes(context.Context, hostnet.Routes) error {
	return errors.New("this host routes nothing of its own")
}
func (h *answeringHost) ScopeHostDefault(context.Context) error {
	return errors.New("this host holds no route of this machine's own")
}
func (h *answeringHost) UnscopeHostDefault(context.Context) error      { return nil }
func (h *answeringHost) SetDNS(context.Context, dns.OSConfig) error    { return nil }
func (h *answeringHost) BaseDNS(context.Context) (dns.OSConfig, error) { return dns.OSConfig{}, nil }
func (h *answeringHost) SplitDNS(context.Context) (bool, error)        { return false, nil }
func (h *answeringHost) Close() error                                  { return nil }

// The preflight runs in one specific moment: the old node is still up, and past this point
// the switch tears it down before the replacement binds the same state directory. So a
// machine that cannot carry an interface has to be refused here, and a machine that merely
// has stale files behind it must not be -- refusing that would make a crash require manual
// repair before the app would run again.
func TestThePreflightRefusesOnlyWhatWouldLeaveNoTailnet(t *testing.T) {
	tests := []struct {
		name       string
		host       *answeringHost
		wantErr    bool
		wantPhrase string
		wantLogged string
	}{
		{
			name: "a clean machine goes ahead",
			host: &answeringHost{caps: hostnet.Capabilities{Version: "1"}},
		},
		{
			name: "another tailnet client is a refusal, because the two delete each other's resolver files",
			host: &answeringHost{caps: hostnet.Capabilities{
				Version:  "1",
				Conflict: "the official Tailscale client is running on this machine",
			}},
			wantErr:    true,
			wantPhrase: "official Tailscale client",
		},
		{
			name: "stale files from a crash are reported and not refused",
			host: &answeringHost{caps: hostnet.Capabilities{
				Version:   "1",
				Leftovers: []string{"/etc/resolver/example.ts.net"},
			}},
			wantLogged: "/etc/resolver/example.ts.net",
		},
		{
			name:       "a privileged side that will not answer is a refusal",
			host:       &answeringHost{err: errors.New("the helper stopped responding")},
			wantErr:    true,
			wantPhrase: "the helper stopped responding",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logged strings.Builder
			logf := func(format string, args ...any) {
				fmt.Fprintf(&logged, format+"\n", args...)
			}

			err := checkHost(context.Background(), tt.host, RightsInterface, logf)
			if tt.wantErr {
				if err == nil {
					t.Fatal("the preflight went ahead, so the switch would tear down a working node and then fail")
				}
				if !strings.Contains(err.Error(), tt.wantPhrase) {
					t.Errorf("the refusal said %q, which does not mention %q", err, tt.wantPhrase)
				}
				return
			}
			if err != nil {
				t.Fatalf("the preflight refused a machine that can carry an interface: %v", err)
			}
			if tt.wantLogged != "" && !strings.Contains(logged.String(), tt.wantLogged) {
				t.Errorf("the log said %q, which does not mention the leftover %q", logged.String(), tt.wantLogged)
			}
		})
	}
}

// A node that wants no interface has nothing to check, and must not reach for a helper it
// does not need -- which on a machine with none would turn a working contained start into
// a refusal.
func TestThePreflightIsASilentNoOpForAContainedNode(t *testing.T) {
	err := Preflight(context.Background(), ServerParams{Network: config.NetworkUserspace}, nil)
	if err != nil {
		t.Errorf("Preflight on a contained node = %v, want it to do nothing at all", err)
	}
}

// The privileged side reports through a log rather than a return value for anything it
// half-did, so a preflight without one would hide it. This is the one argument the caller
// cannot omit.
func TestThePreflightRefusesToRunWithNowhereToReport(t *testing.T) {
	err := Preflight(context.Background(), ServerParams{Network: config.NetworkTUN}, nil)
	if err == nil {
		t.Fatal("a preflight with no log function was accepted")
	}
	if !strings.Contains(err.Error(), "log function") {
		t.Errorf("the refusal said %q, which does not say what was missing", err)
	}
}

// The whole point of running this before the old node is torn down is that a machine which
// cannot carry the mode says so instead of ending up with no tailnet. A machine with no
// privileged side reachable is the ordinary case of that -- it is every machine before
// anyone has run the install -- and it must come back as a sentence naming the next step.
func TestAMachineWithNoPrivilegedSideIsRefusedRatherThanStarted(t *testing.T) {
	logf := func(string, ...any) {}
	// Bounded because the privileged side serves one session at a time: on a machine
	// running the app, this asks for the one it is holding, and an unbounded wait would
	// hang the suite instead of failing it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := Preflight(ctx, ServerParams{Network: config.NetworkTUN}, logf)

	if err == nil {
		// It reported this machine ready, so the privileged side has to be there. A check
		// that returned without asking anything lands here on a machine that has none.
		host, openErr := hostnet.Open(ctx, hostnet.Options{Logf: logf})
		if openErr != nil {
			t.Fatalf("this machine was reported ready to run on an interface, and its privileged side is not there: %v", openErr)
		}
		if closeErr := host.Close(); closeErr != nil {
			t.Errorf("release the connection to the privileged side: %v", closeErr)
		}
		return
	}
	// Anything at all: the refusal is read by whoever changed the setting, and a phrase
	// about a socket is true without being actionable.
	if strings.TrimSpace(err.Error()) == "" {
		t.Error("the refusal is empty")
	}
}

// Each of these is a different thing for the user to do, and each otherwise surfaces as a
// phrase about a socket -- true, and not the part anyone can act on.
func TestEveryReasonTheInterfaceModeIsUnavailableSaysWhatToDo(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantPhrase string
	}{
		{
			name:       "a platform with no interface mode says to leave the mode alone",
			err:        hostnet.ErrUnsupported,
			wantPhrase: "contained one",
		},
		{
			// The command differs by platform, so the row asserts the part that
			// does not: whichever machine this is, the sentence names one.
			name:       "a missing helper says how to get one",
			err:        hostnet.ErrNoHelper,
			wantPhrase: "app-tail tun ",
		},
		{
			// The machine has a helper, so the sentence has to be about this account
			// rather than about installing one: a user who is told to install what they
			// already installed stops there.
			name:       "a helper this account cannot reach says to set it up for this account",
			err:        hostnet.ErrHelperNotOpenToThisAccount,
			wantPhrase: "app-tail tun ",
		},
		{
			// A helper from another build has to be replaced, so neither of the other
			// two sentences applies: there is one installed, and it is this account's.
			name:       "a helper from another build says to replace it",
			err:        hostnet.ErrHelperFromAnotherBuild,
			wantPhrase: "app-tail tun ",
		},
		{
			// Nothing about the machine is wrong here, so every sentence about
			// installing or replacing something would send someone to repair a machine
			// that is already set up. What there is to do is elsewhere.
			name:       "a helper somebody else is using says to deal with them",
			err:        hostnet.ErrHelperBusy,
			wantPhrase: "Quit the other one",
		},
		{
			// Both sentences this arm can produce say to start app-tail some way, and
			// which one it is depends on the platform running the suite. The two are
			// checked against each other elsewhere; what is pinned here is that the arm
			// says anything at all, since the sentinel alone names no next step.
			name:       "and a platform with no helper says to start app-tail again",
			err:        hostnet.ErrNeedsElevation,
			wantPhrase: "start",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithNextStep(tt.err)
			if got == nil {
				t.Fatal("WithNextStep turned a refusal into a success")
			}
			if !strings.Contains(got.Error(), tt.wantPhrase) {
				t.Errorf("WithNextStep(%v) said %q, which does not tell the user to %q",
					tt.err, got, tt.wantPhrase)
			}
		})
	}
}

// Anything that is not one of the sentinels is passed through as it stands. Replacing it
// would throw away the only description of a failure nobody anticipated.
func TestAnUnrecognisedFailurePassesThroughUntouched(t *testing.T) {
	original := errors.New("the socket directory has the wrong owner")
	got := WithNextStep(original)
	// Both halves: the same error, and nothing added to what it says. A wrapper that
	// prepended advice for a failure nobody anticipated would satisfy the first alone.
	if !errors.Is(got, original) || got.Error() != original.Error() {
		t.Errorf("WithNextStep replaced %v with %v", original, got)
	}
}

// The two sentences are what somebody does next, and each is only ever produced on the
// platform it belongs to -- so on any given machine one of them is never exercised at all,
// and an edit that broke it would ship. Both are checked here on every machine.
func TestEachPlatformIsToldHowToGetAHelperInTermsThatExistThere(t *testing.T) {
	// A machine that can install it must not be sent to a terminal: doing it for you is
	// the whole difference, and naming the root command instead hides that it is there.
	canInstall := installHint(true)
	if !strings.Contains(canInstall, "app-tail tun setup") {
		t.Errorf("a machine that can install a helper is told %q, which does not name the command that does it", canInstall)
	}
	if strings.Contains(canInstall, "sudo") {
		t.Errorf("a machine that can install a helper is told to use sudo anyway: %q", canInstall)
	}

	// A machine that cannot has to be told the command to run as root, because nothing
	// is going to ask on its behalf.
	cannot := installHint(false)
	if !strings.Contains(cannot, "sudo app-tail tun helper") {
		t.Errorf("a machine with no installer is told %q, which does not name a command it has", cannot)
	}
	if strings.Contains(cannot, "tun setup") {
		t.Errorf("a machine with no installer is sent to a command that does nothing there: %q", cannot)
	}
}

// A helper that is installed and out of this account's reach needs the other sentence: the
// install has been done, and repeating a description of it is how somebody decides the app
// is stuck telling them to do what they just did.
func TestAnUnreachableHelperIsDescribedAsOneToSetUpAgainForThisAccount(t *testing.T) {
	for _, canInstall := range []bool{true, false} {
		hint := reinstallHint(canInstall)
		if !strings.Contains(hint, "this account") {
			t.Errorf("reinstallHint(%v) said %q, which does not say who the helper has to be set up for", canInstall, hint)
		}
		if !strings.Contains(hint, "app-tail tun ") {
			t.Errorf("reinstallHint(%v) said %q, which names no command to run", canInstall, hint)
		}
	}
	// The same split installHint makes, for the same reason: one machine is asked for a
	// password and the other is given a root command, and swapping them sends somebody to
	// a command that does not exist there.
	if strings.Contains(reinstallHint(true), "sudo") {
		t.Errorf("a machine that can install a helper is told to use sudo anyway: %q", reinstallHint(true))
	}
	if strings.Contains(reinstallHint(false), "tun setup") {
		t.Errorf("a machine with no installer is sent to a command that does nothing there: %q", reinstallHint(false))
	}
}

// A helper from another build is the third sentence, and it is neither of the other two: the
// machine has one, this account can reach it, and it still has to go. Both halves are checked
// here because each is only ever produced on the platform it belongs to.
func TestAHelperFromAnotherBuildIsDescribedAsOneToReplace(t *testing.T) {
	for _, canInstall := range []bool{true, false} {
		hint := replaceHint(canInstall)
		if !strings.Contains(hint, "app-tail tun ") {
			t.Errorf("replaceHint(%v) said %q, which names no command to run", canInstall, hint)
		}
	}
	// The split installHint makes, for the same reason: one machine is asked for a password
	// and the other is given a root command, and swapping them sends somebody to a command
	// that does not exist there.
	if strings.Contains(replaceHint(true), "sudo") {
		t.Errorf("a machine that can install a helper is told to use sudo anyway: %q", replaceHint(true))
	}
	if strings.Contains(replaceHint(false), "tun setup") {
		t.Errorf("a machine with no installer is sent to a command that does nothing there: %q", replaceHint(false))
	}
	// install-helper is the macOS installer, and the machine reading this sentence is the
	// one where it reports that there is nothing to install. Naming it there describes work
	// that cannot be done.
	if strings.Contains(replaceHint(false), "install-helper") {
		t.Errorf("a machine with no installer is sent to install one anyway: %q", replaceHint(false))
	}
	// This is the refusal app-tail repairs on its own, so the machine that can be repaired
	// is a start away from being fixed. Leading with a command sends somebody to a terminal
	// to do by hand what the next start does for them -- and then app-tail asks for a
	// password anyway, for work already done.
	if !strings.Contains(replaceHint(true), "Restart app-tail") {
		t.Errorf("a machine app-tail repairs itself is told %q, which does not say the restart is the fix", replaceHint(true))
	}
}

// A platform with no helper to hold the rights gets them one of two ways, and each sentence
// is only ever produced on the platform it belongs to -- so on any given machine one of them
// is never exercised and an edit that broke it would ship. Both are checked here everywhere.
func TestAPlatformWithNoHelperIsToldHowItsRightsAreObtained(t *testing.T) {
	// The app raises the prompt itself as it starts, so there is nothing to do but start
	// it. Sending somebody to a right-click menu hides that the app already does this.
	relaunches := elevateHint(true)
	if !strings.Contains(relaunches, "start it again") {
		t.Errorf("a platform that asks as it starts says %q, which does not say to start it again", relaunches)
	}
	if strings.Contains(relaunches, "as an administrator") {
		t.Errorf("a platform that asks for itself sends somebody to do it by hand anyway: %q", relaunches)
	}

	// Nothing here will ask, so the rights have to be brought to the process.
	manual := elevateHint(false)
	if !strings.Contains(manual, "as an administrator") {
		t.Errorf("a platform that never asks says %q, which does not say how to get the rights", manual)
	}
}

// The whole safety of repairing a machine unasked is that exactly one refusal qualifies.
// Widening this quietly turns a start into a password prompt for machines that were never
// set up -- the dialog-at-every-login habit -- and narrowing it to nothing puts the one
// fault an upgrade causes back behind a terminal command.
func TestOnlyTheRefusalAnInstallWouldActuallyFixIsOneToActOnUnasked(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "a helper from another build is what replacing it fixes",
			err:  hostnet.ErrHelperFromAnotherBuild,
			want: true,
		},
		{
			// The refusal reaches the agent through this, never bare, so a predicate that
			// only recognised the sentinel itself would never fire in the running app.
			name: "still recognised through the sentence added for the user",
			err:  WithNextStep(hostnet.ErrHelperFromAnotherBuild),
			want: true,
		},
		{
			name: "a machine that never had a helper is not prompted unasked",
			err:  WithNextStep(hostnet.ErrNoHelper),
			want: false,
		},
		{
			name: "a helper belonging to another account is that account's to give up",
			err:  WithNextStep(hostnet.ErrHelperNotOpenToThisAccount),
			want: false,
		},
		{
			name: "a helper another app is using is not one to take over",
			err:  WithNextStep(hostnet.ErrHelperBusy),
			want: false,
		},
		{
			name: "a platform that cannot carry the mode has nothing to install",
			err:  WithNextStep(hostnet.ErrUnsupported),
			want: false,
		},
		{
			name: "a platform with no helper at all is restarted, not installed to",
			err:  WithNextStep(hostnet.ErrNeedsElevation),
			want: false,
		},
		{
			name: "a failure nobody anticipated is not one to guess a fix for",
			err:  errors.New("open the helper socket: connection reset by peer"),
			want: false,
		},
		{
			// A machine that is able reports no refusal at all, and reading that as a
			// reason to install would prompt every start on a working machine.
			name: "a machine with nothing wrong with it",
			err:  nil,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SetupWouldFix(tc.err); got != tc.want {
				t.Errorf("SetupWouldFix(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
