// SPDX-License-Identifier: MIT

// Package elevate restarts app-tail with the administrator rights the
// network-interface mode needs, on the one platform where that is how the rights are
// obtained.
//
// macOS and Linux get their rights from a small root helper, so the agent itself stays
// the user's own process. Windows cannot: the wintun adapter's handle is not exposed by
// the Go binding in a form another process could take over, so the process that drives
// the interface has to be the process that created it. Elevation there is cheap by
// comparison -- it keeps the same user and the same %APPDATA% -- which is why this
// exists on Windows and nowhere else.
package elevate

import (
	"errors"
	"runtime"
)

// ErrDeclined reports that the user dismissed the elevation prompt. It is a sentinel
// because the answer is to carry on unelevated and say what was given up, not to retry:
// a second prompt for a request that was just refused is how an app becomes one people
// click through without reading.
var ErrDeclined = errors.New("the request for administrator rights was declined")

// ErrUnsupported reports that this platform does not obtain rights by relaunching.
var ErrUnsupported = errors.New("this platform does not relaunch itself with administrator rights")

// ErrDifferentAccount reports that elevating would start app-tail as somebody else.
//
// It is a sentinel for the same reason ErrDeclined is: there is no retry that changes the
// answer. The account signed in has to be one that holds administrator rights, or the
// feature stays off.
var ErrDifferentAccount = errors.New("this account cannot be given administrator rights without signing in as a " +
	"different one, and app-tail started as a different account would read that account's settings rather than " +
	"the ones on screen. Sign in as an account that holds administrator rights, or leave the network-interface " +
	"mode off")

// Supported reports whether this platform obtains administrator rights by relaunching
// with a prompt.
func Supported() bool { return runtime.GOOS == "windows" }

// NoElevateFlag is the flag the relaunched process carries.
//
// It is what stops a prompt loop: a machine where elevation succeeds but the rights
// still do not arrive -- a policy that strips them, an administrator account with UAC
// configured to auto-deny -- would otherwise start a process that immediately asks to be
// started again. The child never asks, so the worst case is one prompt and a mode that
// falls back with a reason.
const NoElevateFlag = "--no-elevate"

// Request is what one relaunch needs to know. It is a value rather than four arguments
// because every field is a decision made elsewhere, and a caller assembling it can be
// read against what it means to elevate.
type Request struct {
	// Exe is the absolute path of the binary to start. The running binary's own path is
	// what the caller passes; it is a field so a test can point at something harmless.
	Exe string
	// Args are the arguments the elevated process gets, excluding the program name.
	// NoElevateFlag is appended by Relaunch, so a caller cannot forget it.
	Args []string
	// Dir is the working directory for the new process, empty for the system default.
	// An elevated process does not inherit the caller's, and a relative --state-dir
	// would otherwise resolve somewhere else.
	Dir string
}

// Needed reports whether a process in this situation should relaunch itself with
// administrator rights before it starts anything.
func Needed(f Facts) bool { return Supported() && wantsRights(f) }

// wantsRights reports whether this machine's own state calls for a relaunch, leaving out
// whether the platform has a way to perform one.
//
// The two halves are separate so every combination below is exercised anywhere rather
// than only on the platform that elevates -- otherwise each arm reads as correct on a
// machine where the answer was already no for a different reason. The arm that matters is
// a platform with a helper: relaunching there would ask for rights the helper already
// holds and that the agent is deliberately without.
func wantsRights(f Facts) bool {
	switch {
	case !f.WantsInterface && !f.WantsSystemDNS && !f.StaleOverride:
		// Nothing about the contained mode needs rights, which is the default and the
		// state this app is in for almost everyone.
		return false
	case f.AlreadyAsked:
		return false
	case f.Privileged:
		return false
	case f.HasHelper:
		// The rights live in the helper by design. Elevating the agent here would put
		// the tray, the dashboard and the config directory in a root process to obtain
		// something a helper already has.
		return false
	default:
		return true
	}
}

// commandLine renders one process's arguments as the single string the next one parses,
// with escape applied to each, and appends the flag that stops the new process asking for
// rights in its turn.
//
// The escaping is passed in rather than done here because the rules belong to the
// platform's own parser -- on Windows that is syscall.EscapeArg, which handles the
// backslash-run cases a hand-written quoter gets wrong, and those cases arrive here for
// real: a --state-dir ending in a backslash is what turns a closing quote into a literal
// one and swallows the rest of the line.
func commandLine(args []string, escape func(string) string) string {
	line := make([]byte, 0, 64)
	for _, arg := range args {
		if arg == NoElevateFlag {
			// Already there, so appending it below would pass it twice.
			continue
		}
		line = appendArg(line, escape(arg))
	}
	return string(appendArg(line, NoElevateFlag))
}

func appendArg(line []byte, arg string) []byte {
	if len(line) > 0 {
		line = append(line, ' ')
	}
	return append(line, arg...)
}

// Facts are what the decision is made from, each one a question answered elsewhere.
type Facts struct {
	// WantsInterface reports whether the stored settings select the network-interface
	// mode. It is read from the stored settings rather than from the running node,
	// because the decision is made before a node exists.
	WantsInterface bool
	// WantsSystemDNS reports whether the stored settings ask for this machine's own
	// resolver to be changed. It is a second reason for the same rights: the machine-wide
	// resolver is a machine-level feature that stands on its own, so a user who wants only
	// that must not be told to turn on a network interface they do not want.
	WantsSystemDNS bool
	// StaleOverride reports a previous run that left this machine's name resolution pointed
	// at app-tail with nothing having put it back. Putting it back needs the same rights,
	// and this is the one case where the feature being switched off now is exactly why
	// nothing else would repair it.
	StaleOverride bool
	// Privileged reports whether this process already holds administrator rights.
	Privileged bool
	// HasHelper reports whether this platform puts the privileged work in a separate
	// process instead.
	HasHelper bool
	// AlreadyAsked reports whether this process is itself the result of an elevation
	// attempt, which is what stops a prompt loop.
	AlreadyAsked bool
}
