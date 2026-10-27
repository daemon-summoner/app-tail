// SPDX-License-Identifier: MIT

package hostnet

// Telling app-tail apart from another program running under the same account.
//
// The owner check says which account a connection came from. Every program that account runs
// passes it, and the helper holds root, so on its own it hands root-level network control to
// anything the user happens to run. What is checked on top of it is that the connecting
// process is running this very program: the helper is a copy of the agent's binary, so the
// two have the same code.
//
// The answer has to come from the kernel and be tied to the process that connected rather
// than to a pid looked up afterwards, because a pid can be reused, and a process can connect
// and then replace its own program with app-tail's before anybody looks.

// CallerCheck is how the helper on this platform tells app-tail from another program running
// under the same account.
type CallerCheck string

const (
	// CallerCheckCodeHash compares the hash of the connecting process's code signature, which
	// the kernel recorded for that exact process when it started, with the helper's own. A
	// process that replaces its program after connecting is no longer the process that
	// connected, and is refused.
	CallerCheckCodeHash CallerCheck = "code-hash"
	// CallerCheckExecutable compares the file the connecting process is running with the
	// helper's own, and refuses a process being traced. The kernel keeps no count of how many
	// times a process has replaced its program, so one that connects and then becomes
	// app-tail passes, and it keeps no record of a debugger that changed app-tail as it
	// started and then let go. Either way the caller gets only what the helper would do for
	// app-tail: the changes it makes unasked and the ones you approved.
	CallerCheckExecutable CallerCheck = "executable"
	// CallerCheckUnavailable is a helper that cannot tell programs apart, and so takes
	// commands from root alone.
	CallerCheckUnavailable CallerCheck = "unavailable"
)

// Describe is the check as a sentence a person reads.
func (c CallerCheck) Describe() string {
	switch c {
	case CallerCheckCodeHash:
		return "only app-tail itself: the connecting process's code signature must match the helper's, as the kernel recorded it when that process started"
	case CallerCheckExecutable:
		return "only app-tail itself, by its executable file, and never while traced; a program that connects first and then starts app-tail, or that starts app-tail under a debugger and changes it before letting go, is not caught, and gets only the changes app-tail may make unasked and the ones you approved"
	}
	return "nothing can be told apart here, so the helper takes commands from root alone"
}
