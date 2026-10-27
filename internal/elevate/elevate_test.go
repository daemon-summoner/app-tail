// SPDX-License-Identifier: MIT

package elevate

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// The decision is what stops an elevation prompt appearing for something that does not
// need one. Every arm below is a machine state that is expensive or impossible to
// reproduce, and each wrong answer is a different visible failure: a prompt on a Mac, a
// prompt on every launch, or a prompt that never comes and a mode that silently does not
// start.
func TestOnlyAMachineThatNeedsRightsIsAskedForThem(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  bool
	}{
		{
			name:  "the contained mode never asks",
			facts: Facts{},
			want:  false,
		},
		{
			name:  "the interface mode without rights asks",
			facts: Facts{WantsInterface: true},
			want:  true,
		},
		{
			name:  "a process that already has them does not",
			facts: Facts{WantsInterface: true, Privileged: true},
			want:  false,
		},
		{
			name:  "and neither does a platform whose helper holds them",
			facts: Facts{WantsInterface: true, HasHelper: true},
			want:  false,
		},
		{
			name:  "one relaunch that did not produce rights is not followed by another",
			facts: Facts{WantsInterface: true, AlreadyAsked: true},
			want:  false,
		},
		{
			// The machine-wide resolver is a machine-level feature of its own, so a user
			// who wants only that must not have to turn on a network interface to get it.
			name:  "the machine-wide resolver alone asks",
			facts: Facts{WantsSystemDNS: true},
			want:  true,
		},
		{
			name:  "and it asks no more than once either",
			facts: Facts{WantsSystemDNS: true, AlreadyAsked: true},
			want:  false,
		},
		{
			// The case nothing else repairs: the feature is off now, which is exactly why
			// nothing will put this machine's resolver back unless the rights are asked for.
			name:  "a resolver left redirected by an earlier run asks with everything off",
			facts: Facts{StaleOverride: true},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wantsRights(tt.facts); got != tt.want {
				t.Errorf("wantsRights(%+v) = %v, want %v", tt.facts, got, tt.want)
			}
			// The platform is the other half of the answer, and it is the half that keeps
			// a Mac from ever seeing a prompt whatever its settings say.
			if got := Needed(tt.facts); got != (tt.want && Supported()) {
				t.Errorf("Needed(%+v) = %v on %s, want %v", tt.facts, got, runtime.GOOS, tt.want && Supported())
			}
		})
	}
}

// The prompt-loop guard is the one property that cannot be recovered from at run time:
// a process that asks, gets started without the rights, and asks again puts a UAC dialog
// on screen forever. So the flag is appended by the relaunch itself rather than by the
// caller, and appended exactly once however the caller assembled its arguments.
func TestTheRelaunchedProcessIsToldNotToAskAgain(t *testing.T) {
	verbatim := func(s string) string { return s }

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "a caller that forgot it still gets it",
			args: []string{"run", "--headless"},
			want: "run --headless " + NoElevateFlag,
		},
		{
			name: "a caller that passed it does not get it twice",
			args: []string{"run", NoElevateFlag, "--headless"},
			want: "run --headless " + NoElevateFlag,
		},
		{
			name: "and neither does a bare relaunch",
			args: nil,
			want: NoElevateFlag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commandLine(tt.args, verbatim)
			if got != tt.want {
				t.Errorf("commandLine(%q) = %q, want %q", tt.args, got, tt.want)
			}
			if strings.Count(got, NoElevateFlag) != 1 {
				t.Errorf("%q carries the guard flag %d times; anything but once is a prompt loop or a lost guard",
					got, strings.Count(got, NoElevateFlag))
			}
		})
	}
}

// Every argument goes through the platform's own quoter. A path with a space that
// reached the new process as two arguments would start it against a state directory
// that does not exist, which looks like a fresh install rather than a broken relaunch.
func TestEveryArgumentIsQuotedForThePlatformParser(t *testing.T) {
	seen := []string{}
	marking := func(s string) string {
		seen = append(seen, s)
		return "<" + s + ">"
	}
	args := []string{"run", "--state-dir", `C:\Users\a b\AppData\app-tail`}

	got := commandLine(args, marking)

	if len(seen) != len(args) {
		t.Fatalf("the quoter saw %d of %d arguments: %q", len(seen), len(args), seen)
	}
	for _, arg := range args {
		if !strings.Contains(got, "<"+arg+">") {
			t.Errorf("%q reached the command line unquoted: %s", arg, got)
		}
	}
	// The guard flag is app-tail's own literal and is not a path, so quoting it would
	// only make it harder to recognise in a process list.
	if !strings.HasSuffix(got, " "+NoElevateFlag) {
		t.Errorf("the command line %q does not end with the guard flag unquoted", got)
	}
}

// A caller on a platform with no elevation must get a refusal it can act on rather than
// a silent success: reporting that a relaunch happened when nothing started would leave
// the agent exiting and no replacement running.
func TestAPlatformWithNoElevationRefusesRatherThanPretends(t *testing.T) {
	if Supported() {
		t.Skip("this platform elevates, so there is no refusal to check")
	}
	err := Relaunch(Request{Exe: "/nonexistent/app-tail"})
	if err == nil {
		t.Fatal("Relaunch reported success on a platform that cannot elevate")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Relaunch failed with %v, which callers cannot tell from a real failure", err)
	}
}

// Supported is read by the caller before it opens any file, so a wrong answer costs a
// config read on every start of every platform. It is also what the doctor's wording
// keys off, and a Mac being told app-tail will ask for administrator rights is the
// opposite of what that platform does.
func TestOnlyWindowsElevates(t *testing.T) {
	if got, want := Supported(), runtime.GOOS == "windows"; got != want {
		t.Errorf("Supported() = %v on %s, want %v", got, runtime.GOOS, want)
	}
}
