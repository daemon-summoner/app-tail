// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/sellitus/app-tail/internal/grants"
)

// Approving a change the helper refused writes the approvals file, which only root may do. On
// macOS this asks for an administrator's password for the length of one command, and that
// command is the installed helper's own `tun grant`: a root-owned binary in a directory only
// root can write, so what runs as root is the reviewed program already holding root rather
// than whatever sits where the app was unpacked. Nothing else is ever run this way.
//
// Like provision.go this is not behind a build tag, so the property the safety rests on --
// every value travels as an argument and is quoted by the shell's own rules -- is checked by
// every run of the suite.

// ErrApproveByHand is a machine where app-tail cannot ask for an administrator's approval
// itself: someone has to run the approving command from an administrator's shell.
var ErrApproveByHand = errors.New("app-tail cannot ask for an administrator's approval on this machine")

// approveScript asks for the rights and runs the helper's `tun grant`. Item 1 is the helper,
// item 2 the prompt, and every item after that one argument to the helper. Each argument is
// passed through `quoted form of`, so a value carrying a quote or a semicolon reaches the
// helper as the one argument it was and is never read as script or as a second command.
const approveScript = `on run argv
	do shell script (my commandLine(argv)) with prompt (item 2 of argv) with administrator privileges
end run
` + approveCommandLine

// approveCommandLine is the shell command approveScript runs, built from its arguments. It is
// separate so a test can ask macOS for the command without raising the password dialog.
const approveCommandLine = `on commandLine(argv)
	set cmd to quoted form of (item 1 of argv)
	repeat with i from 3 to count of argv
		set cmd to cmd & " " & quoted form of (item i of argv)
	end repeat
	return cmd
end commandLine
`

// approveCommand is the command that asks for the rights and approves args. Built apart from
// being run, so that every value being its own argument is something a test asserts.
func approveCommand(helper, prompt string, args []string) []string {
	return append([]string{osascriptPath, "-e", approveScript, helper, prompt}, args...)
}

// maxPromptReasons caps how many reasons the dialog lists. The dialog has no scroll bar, and
// the full list is on the dashboard beside the button that raised it.
const maxPromptReasons = 8

// approvePrompt is what the administrator dialog says: each change in the words the dashboard
// shows.
func approvePrompt(needs []grants.Need) string {
	return "app-tail wants an administrator to approve these changes to this machine's network: " +
		reasonList(needs) + ". Enter your password only if you asked app-tail for them."
}

// reasonList is the needs' reasons as one line for a dialog. A reason can carry a name from
// the configuration, so anything unprintable is replaced rather than allowed to draw a line of
// its own under the real ones.
func reasonList(needs []grants.Need) string {
	var b strings.Builder
	for i, need := range needs {
		if i == maxPromptReasons {
			fmt.Fprintf(&b, "; and %d more", len(needs)-i)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(printable(need.Reason))
	}
	return b.String()
}

func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, s)
}

// approveSteps are the machine facts approveGrants decides on and the act it performs. They
// are values so a suite can run every platform's branch and never raise a dialog.
type approveSteps struct {
	// goos is the platform, which decides whether app-tail can ask at all.
	goos string
	// helper is the installed, root-owned helper binary, or "" when none is installed.
	helper string
	// elevate runs a command and returns everything it wrote.
	elevate func(ctx context.Context, args []string) ([]byte, error)
}

// ApproveGrants asks an administrator to approve needs and records the approval. It returns
// ErrDeclined when the dialog is dismissed and an error matching ErrApproveByHand on a machine
// where app-tail cannot ask itself.
func ApproveGrants(ctx context.Context, logf func(format string, args ...any), needs []grants.Need) error {
	return approveGrants(ctx, logf, needs, machineApproveSteps())
}

func approveGrants(ctx context.Context, logf func(format string, args ...any), needs []grants.Need, steps approveSteps) error {
	if logf == nil {
		return errors.New("hostnet: no log function was provided")
	}
	if len(needs) == 0 {
		return nil
	}
	switch {
	case steps.goos == "windows":
		return fmt.Errorf("%w: run `%s` from PowerShell started as administrator", ErrApproveByHand,
			grants.CommandLine(steps.goos, needs))
	case steps.goos != "darwin":
		return fmt.Errorf("%w: run `%s` in a terminal", ErrApproveByHand, grants.CommandLine(steps.goos, needs))
	case steps.helper == "":
		// Without the installed helper there is no root-owned program to run, and running the
		// app's own binary as root is what the helper exists to avoid.
		return fmt.Errorf("%w: the network helper is not installed, so run `%s` in a terminal", ErrApproveByHand,
			grants.CommandLine(steps.goos, needs))
	}
	out, err := steps.elevate(ctx, approveCommand(steps.helper, approvePrompt(needs), grants.GrantArgs(needs)))
	if err != nil {
		if declined(string(out)) {
			return ErrDeclined
		}
		return fmt.Errorf("ask macOS for the rights to approve the change: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
		logf("approving network changes reported: %s", trimmed)
	}
	return nil
}
