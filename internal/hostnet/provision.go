// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sellitus/app-tail/internal/grants"
)

// Installing the helper needs root, and the agent deliberately does not have it. This asks
// the platform for the rights for the length of one command instead, and the command it
// runs is this same binary's own installer -- so the privileged work stays the reviewed
// path in install_darwin.go and nothing new runs as root.
//
// That command, `app-tail tun install-helper` followed by `tun grant` when the dialog listed
// changes to approve, is the only program from outside a root-owned directory app-tail ever
// asks macOS to run with administrator rights. Everything root does
// after it is done by the installed helper, which takes requests over its socket from the one
// account recorded at install time. The one other dialog, in approve.go, runs that installed
// helper's own `tun grant` and nothing else.
//
// macOS is the only platform that reports SupportsHelperInstall, so the escalation below is
// only ever run there. It is not behind a build tag, because the property everything here
// rests on -- that the binary path travels as an argument and never as script -- is then
// checked by every run of the suite rather than only by the machines that could run it.

// noInstallerReason says how a platform with no install step gets its rights, which is not
// the same sentence in the two places there is no install step. A platform with a helper
// has one to start by hand; a platform without one restarts the whole app under a prompt,
// and telling somebody there to start a helper names a thing that does not exist.
//
// The platform's answer is passed in rather than read here so both sentences are reachable
// from any machine -- otherwise each is only ever exercised where it belongs, and the other
// is whatever it was last edited to say.
func noInstallerReason(hasHelper bool) string {
	if hasHelper {
		return "this platform installs no helper: start one by hand with `sudo app-tail tun helper`"
	}
	return "this platform installs no helper: app-tail asks for the administrator rights it " +
		"needs as it starts. Quit app-tail and start it again, and it will ask"
}

// osascriptPath is the system's AppleScript runner, which is what raises the
// authorization dialog. It is absolute because this ends in a root command: resolving it
// through PATH would let anything earlier on the path decide what gets elevated.
const osascriptPath = "/usr/bin/osascript"

// provisionScript asks for the rights and runs the installer.
//
// Every value arrives as an argument to the run handler rather than inside this text, and
// each one bound for the shell is passed through `quoted form of`, which applies the shell's
// own quoting rules. Nothing a caller controls is ever parsed as script or as a second
// command: a path containing a quote or a semicolon travels as one argument and comes out
// the other side as one argument. The shell it runs is installShell, itself an argument.
const provisionScript = `on run argv
	do shell script (my installCommandLine(argv)) with prompt (item 3 of argv) with administrator privileges
end run
` + installCommandLine

// installCommandLine is the shell command provisionScript runs, built from its arguments:
// item 1 the binary, 2 the account, 4 installShell, 5 the fingerprint, and every item from 6
// on one `tun grant` flag. It is separate so a test can ask macOS for the command without
// raising the password dialog.
const installCommandLine = `on installCommandLine(argv)
	set cmd to "/bin/sh -c " & (quoted form of (item 4 of argv)) & " app-tail-install " & (quoted form of (item 1 of argv)) & " " & (quoted form of (item 5 of argv)) & " " & (quoted form of (item 2 of argv))
	repeat with i from 6 to count of argv
		set cmd to cmd & " " & (quoted form of (item i of argv))
	end repeat
	return cmd
end installCommandLine
`

// installShell is what root runs once the password is entered: $1 is the binary the
// prompt named, $2 the SHA-256 the prompt showed, $3 the account the helper will serve, and
// every argument after those one `tun grant` flag for a change the prompt listed. The approval
// is in the same command because the prompt said so: one password covers both. Root is handed
// the approvals themselves and never the config they came from, which is the user's to write
// and could say something else by the time root read it.
//
// The binary sits wherever the app was unpacked, usually somewhere the user can write, so
// running it in place would run whatever is there at that moment rather than the file the
// prompt vouched for. Root copies it once into a directory only root can open, checks the
// copy against the fingerprint the prompt showed, and runs the copy; a swap at any point
// after the prompt either lands before the copy and fails the check, or lands after it and
// changes nothing. Every tool is named by absolute path, since PATH is the caller's.
const installShell = `set -eu
umask 077
dir=$(/usr/bin/mktemp -d /var/tmp/app-tail-install.XXXXXX)
trap '/bin/rm -rf "$dir"' EXIT
/bin/cp "$1" "$dir/app-tail"
got=$(/usr/bin/shasum -a 256 "$dir/app-tail" | /usr/bin/cut -d' ' -f1)
if [ "$got" != "$2" ]; then
	echo "the app-tail binary changed after the password prompt showed its fingerprint, so nothing was installed" >&2
	exit 1
fi
"$dir/app-tail" tun install-helper --owner "$3"
shift 3
if [ "$#" -gt 0 ]; then
	"$dir/app-tail" tun grant "$@"
fi
`

// provisionCommand is the command that asks for the rights and installs the helper.
//
// It is built separately from being run so that the one property the safety rests on --
// that the binary path is its own argument and never part of the script -- is something a
// test can assert rather than something a reader has to take on trust.
func provisionCommand(exe string, owner int, prompt, digest string, grantFlags []string) []string {
	return append([]string{osascriptPath, "-e", provisionScript, exe, strconv.Itoa(owner), prompt, installShell, digest}, grantFlags...)
}

// provisionPrompt is what the administrator dialog says.
//
// Without it macOS says only that a program wants to make changes, which reads the same for
// this request and for any other, so it names the file that will be copied and run as root and
// the first 16 hex digits of its SHA-256. The path is shown quoted with anything unprintable
// escaped: a name with a line break in it would otherwise draw a second sentence of its own
// choosing under the real one. It reaches the dialog as an argument, never as script, so no
// AppleScript quoting is needed for it to stay text. When the install also approves changes,
// the dialog lists each one: a password given for one thing must not quietly do two.
func provisionPrompt(path, digest string, needs []grants.Need) string {
	prompt := "app-tail wants to install its network helper, which runs as root, from " +
		strconv.QuoteToGraphic(path) + " (SHA-256 " + digest[:16] + "). "
	if len(needs) > 0 {
		prompt += "The same password approves these changes to this machine's network: " + reasonList(needs) + ". "
	}
	return prompt + "Enter your password only if you asked app-tail to turn on the network-interface mode."
}

// fileDigest is the hex SHA-256 of the file at path.
func fileDigest(path string) (_ string, reterr error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read the app-tail binary to show its fingerprint: %w", err)
	}
	defer func() { reterr = errors.Join(reterr, f.Close()) }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read the app-tail binary to show its fingerprint: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// provisionSteps are the two machine facts ProvisionHelper decides on and the two acts it
// performs. They are values rather than direct calls because obtaining administrator rights
// raises a system dialog, which a suite must never raise -- and because a decision between
// platforms is otherwise only ever exercised on the platform it was written on.
type provisionSteps struct {
	privileged bool
	canElevate bool
	// install is the unprompted install, for a process that already holds the rights or a
	// platform with nothing to ask. It never approves: approving is offered only where a
	// dialog says it will happen.
	install func(ctx context.Context, logf func(format string, args ...any), exe string, owner int) error
	elevate func(ctx context.Context, args []string) ([]byte, error)
}

// machineProvisionSteps reads this machine and pairs what it found with the real acts.
func machineProvisionSteps() provisionSteps {
	return provisionSteps{
		privileged: Privileged(),
		canElevate: SupportsHelperInstall(),
		install:    InstallHelper,
		elevate:    runCombined,
	}
}

// runCombined runs a command and returns everything it wrote. Both streams are kept
// together because the two things worth reading arrive on different ones: the installer's
// own account of what it did, and the dialog's answer when it was dismissed.
func runCombined(ctx context.Context, args []string) ([]byte, error) {
	return exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
}

// ProvisionHelper installs the helper, obtaining the administrator rights rather than
// requiring the caller to already hold them.
//
// exe is the running program's path and owner is the account the helper will take
// commands from. needs are the changes the same password also approves, listed in the dialog,
// so a machine that has just been set up does not refuse the first thing its settings ask for.
func ProvisionHelper(ctx context.Context, logf func(format string, args ...any), exe string, owner int, needs []grants.Need) error {
	return provisionHelper(ctx, logf, exe, owner, needs, machineProvisionSteps())
}

// provisionHelper is the decision ProvisionHelper makes, separated from the machine it
// makes it about.
func provisionHelper(ctx context.Context, logf func(format string, args ...any), exe string, owner int, needs []grants.Need, steps provisionSteps) error {
	if logf == nil {
		return errors.New("hostnet: no log function was provided")
	}
	if owner == 0 {
		return errors.New("the helper serves an ordinary account, and root is not one. " +
			"Turn the network-interface mode on from your own account rather than from a root shell")
	}
	// Neither case has anything to ask for: a process that already holds the rights
	// installs directly, and a platform with no escalation gets the install's own account
	// of why there is nothing here to install.
	if steps.privileged || !steps.canElevate {
		return steps.install(ctx, logf, exe, owner)
	}

	// The file the dialog vouches for is the file that gets installed: the link is
	// resolved once, here, and the resolved path is both what the prompt shows and what
	// the elevated command runs.
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("find the app-tail binary to install: %w", err)
	}
	digest, err := fileDigest(resolved)
	if err != nil {
		return err
	}
	out, err := steps.elevate(ctx, provisionCommand(resolved, owner, provisionPrompt(resolved, digest, needs), digest, grants.GrantFlags(needs)))
	if err != nil {
		return provisionErr(err, string(out))
	}
	// The installer's own account of the steps whose failure does not stop it, which
	// otherwise ends inside a dialog nobody sees again.
	if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
		logf("installing the privileged helper reported: %s", trimmed)
	}
	return nil
}

// provisionErr says which kind of failure this was. The distinction is the whole point:
// a dismissed dialog is an answer and is reported as one, while anything else is a
// machine that could not do it and carries what it said.
func provisionErr(err error, output string) error {
	if declined(output) {
		return ErrDeclined
	}
	return fmt.Errorf("ask macOS for the rights to install the privileged helper: %w: %s",
		err, strings.TrimSpace(output))
}

// declined recognises a dismissed authorization dialog.
//
// Both forms are matched because the number is what AppleScript documents and the
// sentence is what it prints, and which one reaches here depends on the macOS release.
func declined(output string) bool {
	return strings.Contains(output, "(-128)") || strings.Contains(output, "User canceled")
}
