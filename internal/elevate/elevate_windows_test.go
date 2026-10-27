// SPDX-License-Identifier: MIT

package elevate

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// shellCall is what one Relaunch handed the shell, decoded back into strings.
type shellCall struct {
	verb string
	exe  string
	args string
	dir  string
	show int32
}

// stubShell stands in for the call that puts the elevation prompt on screen and starts a
// second app-tail. It records what was asked for and answers with err.
func stubShell(t *testing.T, err error) *shellCall {
	t.Helper()
	// Every test using this one is about what reaches the shell, which is only reached by an
	// account elevation would keep. The machine running the tests decides the real answer.
	stubAccount(t, true, nil)
	call := &shellCall{}
	original := shellExecute
	shellExecute = func(_ windows.Handle, verb, exe, args, dir *uint16, show int32) error {
		call.verb = windows.UTF16PtrToString(verb)
		call.exe = windows.UTF16PtrToString(exe)
		call.args = windows.UTF16PtrToString(args)
		call.dir = windows.UTF16PtrToString(dir)
		call.show = show
		return err
	}
	t.Cleanup(func() { shellExecute = original })
	return call
}

// stubAccount stands in for the question of whether the prompt raises this account in place.
func stubAccount(t *testing.T, inPlace bool, err error) {
	t.Helper()
	original := elevatesInPlace
	elevatesInPlace = func() (bool, error) { return inPlace, err }
	t.Cleanup(func() { elevatesInPlace = original })
}

// A standard account has no filtered token to restore, so "runas" asks for another account's
// credentials and starts app-tail as that account -- reading its %APPDATA% rather than the
// one holding the settings on screen. There is no prompt worth putting up for that.
func TestAnAccountThatElevatingWouldChangeIsRefusedBeforeAnyPromptAppears(t *testing.T) {
	original := shellExecute
	shellExecute = func(windows.Handle, *uint16, *uint16, *uint16, *uint16, int32) error {
		t.Error("a prompt went up for an account that consenting would change")
		return nil
	}
	t.Cleanup(func() { shellExecute = original })
	stubAccount(t, false, nil)

	err := Relaunch(Request{Exe: `C:\Program Files\app-tail\app-tail.exe`})

	if !errors.Is(err, ErrDifferentAccount) {
		t.Fatalf("elevating an account without administrator rights = %v, want ErrDifferentAccount", err)
	}
}

// Dismissing the prompt is an answer, not a failure: the caller carries on unelevated and
// says what was given up. Reported as an ordinary error it would read as a broken machine,
// and the one thing that must never follow is a second prompt for what was just refused.
func TestDismissingThePromptIsReportedAsADeclineRatherThanAFailure(t *testing.T) {
	stubShell(t, windows.ERROR_CANCELLED)

	err := Relaunch(Request{Exe: `C:\Program Files\app-tail\app-tail.exe`})

	if !errors.Is(err, ErrDeclined) {
		t.Fatalf("a dismissed prompt = %v, want ErrDeclined", err)
	}
}

// Everything else is a real failure and has to keep its cause: a policy that blocks the
// verb and a missing binary are different problems, and a caller shown only "declined"
// would tell the user to try again forever.
func TestAShellFailureThatIsNotADeclineKeepsItsCause(t *testing.T) {
	stubShell(t, windows.ERROR_ACCESS_DENIED)

	err := Relaunch(Request{Exe: `C:\Program Files\app-tail\app-tail.exe`})

	if errors.Is(err, ErrDeclined) {
		t.Fatal("a shell failure was reported as the user declining, so nothing says what went wrong")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("the cause was dropped: %v", err)
	}
}

// The elevated copy is the one that will hold administrator rights, so what it is started
// with is the whole security-relevant surface of this package.
func TestTheElevatedCopyIsStartedWithTheRequestAndTheFlagThatStopsALoop(t *testing.T) {
	call := stubShell(t, nil)
	req := Request{
		Exe: `C:\Program Files\app-tail\app-tail.exe`,
		// A --state-dir ending in a backslash is the case a hand-written quoter gets
		// wrong: the trailing backslash escapes the closing quote and swallows the rest.
		Args: []string{"run", `--state-dir=C:\Users\a b\state\`},
		Dir:  `C:\Program Files\app-tail`,
	}

	if err := Relaunch(req); err != nil {
		t.Fatalf("relaunch with administrator rights: %v", err)
	}

	if call.verb != "runas" {
		t.Errorf("the shell was asked for %q, want %q -- anything else starts an unelevated copy", call.verb, "runas")
	}
	if call.exe != req.Exe {
		t.Errorf("the shell was asked to start %q, want %q", call.exe, req.Exe)
	}
	if call.dir != req.Dir {
		t.Errorf("the elevated copy starts in %q, want %q; a relative --state-dir resolves against it", call.dir, req.Dir)
	}
	if !strings.HasSuffix(call.args, NoElevateFlag) {
		t.Errorf("the elevated copy is not given %s, so it asks to be elevated again: %q", NoElevateFlag, call.args)
	}
	if !strings.Contains(call.args, `"--state-dir=C:\Users\a b\state\\"`) {
		t.Errorf("the backslash-terminated argument was not escaped, so the rest of the line is lost: %q", call.args)
	}
	// SW_HIDE would take the console build's own output with it, leaving a user who
	// started app-tail from a prompt with no sign of what the new copy is doing.
	if call.show != windows.SW_SHOWNORMAL {
		t.Errorf("the elevated copy is started with show=%d, want SW_SHOWNORMAL (%d)", call.show, windows.SW_SHOWNORMAL)
	}
}

// An empty working directory means the shell's default, which is a null pointer rather
// than an empty string -- passing a pointer to "" starts the process in a directory that
// does not exist.
func TestNoWorkingDirectoryLeavesTheShellsDefaultInPlace(t *testing.T) {
	stubAccount(t, true, nil)
	original := shellExecute
	var gotNil bool
	shellExecute = func(_ windows.Handle, _, _, _, dir *uint16, _ int32) error {
		gotNil = dir == nil
		return nil
	}
	t.Cleanup(func() { shellExecute = original })

	if err := Relaunch(Request{Exe: `C:\Program Files\app-tail\app-tail.exe`}); err != nil {
		t.Fatalf("relaunch with administrator rights: %v", err)
	}
	if !gotNil {
		t.Error("an empty Dir was passed as a string, so the elevated copy starts in a directory that does not exist")
	}
}

// CoInitializeEx answers three ways and only one of them is a failure. Reading S_FALSE as
// one leaves the apartment's reference count raised for the life of the thread, and this
// thread is pinned; reading RPC_E_CHANGED_MODE as a success releases a reference this call
// never took, which tears down an apartment something else is using.
func TestOnlyAThreadThatTookAReferenceReleasesOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		from error
		want bool
	}{
		{name: "the apartment was entered", from: nil, want: true},
		{name: "this thread was already in it", from: syscall.Errno(windows.S_FALSE), want: true},
		{name: "this thread is in the other kind", from: syscall.Errno(windows.RPC_E_CHANGED_MODE), want: false},
		{name: "the call failed outright", from: windows.ERROR_ACCESS_DENIED, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinedApartment(tc.from); got != tc.want {
				t.Errorf("joinedApartment(%v) = %v, want %v", tc.from, got, tc.want)
			}
		})
	}
}

// Nothing is asked of the shell when there is no program to start: a prompt appearing for
// an empty path is a prompt with nothing behind it.
func TestARequestWithNoProgramNeverReachesTheShell(t *testing.T) {
	original := shellExecute
	shellExecute = func(windows.Handle, *uint16, *uint16, *uint16, *uint16, int32) error {
		t.Error("the shell was asked to elevate a request naming no program")
		return nil
	}
	t.Cleanup(func() { shellExecute = original })

	if err := Relaunch(Request{}); err == nil {
		t.Error("a request naming no program was accepted")
	}
}
