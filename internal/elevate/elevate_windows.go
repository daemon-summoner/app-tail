// SPDX-License-Identifier: MIT

package elevate

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

// shellExecute is the call that puts the elevation prompt on screen. It is a variable so
// a test can stand in for it: the real one shows a prompt and starts a second app-tail.
var shellExecute = windows.ShellExecute

// Relaunch starts the same program again under an elevation prompt and returns as soon
// as the shell has accepted the request.
//
// It does not wait for the new process and cannot: ShellExecuteW hands back no process
// handle, and the elevated copy is started by the AppInfo service rather than as a child
// of this one. The caller's contract is therefore to return without starting anything --
// there are briefly two app-tail processes, and only one of them ever binds a port.
func Relaunch(req Request) error {
	if req.Exe == "" {
		return errors.New("relaunch: no program path was given")
	}

	same, err := elevatesInPlace()
	if err != nil {
		return fmt.Errorf("relaunch: %w", err)
	}
	if !same {
		return ErrDifferentAccount
	}

	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("relaunch: encode the elevation verb: %w", err)
	}
	exe, err := windows.UTF16PtrFromString(req.Exe)
	if err != nil {
		return fmt.Errorf("relaunch: encode %q: %w", req.Exe, err)
	}
	args, err := windows.UTF16PtrFromString(commandLine(req.Args, syscall.EscapeArg))
	if err != nil {
		return fmt.Errorf("relaunch: encode the arguments: %w", err)
	}
	// A null working directory is the shell's default, which is what an empty Dir means.
	var dir *uint16
	if req.Dir != "" {
		dir, err = windows.UTF16PtrFromString(req.Dir)
		if err != nil {
			return fmt.Errorf("relaunch: encode the working directory %q: %w", req.Dir, err)
		}
	}

	// The elevation prompt is put up by the shell, which reaches it through COM. A
	// thread that has not joined an apartment gets one implicitly on the first call and
	// keeps it for its lifetime, so this pins the thread and joins deliberately -- the
	// goroutine could otherwise be scheduled onto a thread already in the wrong one.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if joinedApartment(windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED)) {
		defer windows.CoUninitialize()
	}

	return shellExecuteElevated(verb, exe, args, dir)
}

// elevatesInPlace is the account question Relaunch asks. It is a variable for the same
// reason shellExecute is: the real one answers from the account the tests happen to run
// under, so both answers have to be reachable on any machine.
var elevatesInPlace = tokenElevatesInPlace

// tokenElevatesInPlace reports whether the account this process runs as is one the elevation
// prompt raises without changing who app-tail runs as.
//
// A member of the administrators group is handed a filtered token at logon, with the group
// present and marked deny-only; consenting to the prompt restores the full token and the user
// is unchanged. An account that is not a member has no such token to restore, so "runas" asks
// for another account's credentials and starts app-tail as that account -- a different
// %APPDATA%, a different HKCU, and therefore a second copy reading a configuration nobody
// edited, with the settings on screen left running in the unelevated one.
//
// Group membership is read rather than tested with CheckTokenMembership, which answers for
// the filtered token and reports the deny-only entry as absent: that entry is exactly the
// account this admits.
func tokenElevatesInPlace() (bool, error) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("look up the administrators group: %w", err)
	}
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return false, fmt.Errorf("read the groups this account belongs to: %w", err)
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.Equals(admins) {
			return true, nil
		}
	}
	return false, nil
}

// joinedApartment reports whether a CoInitializeEx result left this thread holding a
// reference to release.
//
// Success and S_FALSE both raise the apartment's reference count, and S_FALSE -- the
// thread was already in this apartment -- arrives as an error from the Go wrapper because
// it is a non-zero HRESULT. Reading it as a failure leaks the reference for the life of
// the thread. RPC_E_CHANGED_MODE is the genuine refusal: the thread is in the other kind
// of apartment, nothing was counted, and calling CoUninitialize would release somebody
// else's reference.
func joinedApartment(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.Errno(windows.S_FALSE))
}

// shellExecuteElevated puts the prompt on screen and maps the one refusal that is not a
// failure: a user who says no.
func shellExecuteElevated(verb, exe, args, dir *uint16) error {
	// SW_SHOWNORMAL rather than SW_HIDE: the console build writes to a console, and a
	// hidden window would take its output with it. The GUI build has no console to show,
	// so the flag costs it nothing.
	if err := shellExecute(0, verb, exe, args, dir, windows.SW_SHOWNORMAL); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return ErrDeclined
		}
		return fmt.Errorf("ask Windows to restart app-tail with administrator rights: %w", err)
	}
	return nil
}
