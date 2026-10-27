// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/grants"
)

// This path ends in a command run as root, so the one property everything else rests on is
// that nothing a caller controls is ever parsed as script. The binary path travels as its
// own argument to the run handler; if it were concatenated into the script text instead, a
// path containing a quote would close the string and the rest would run as root.
func TestTheBinaryPathTravelsAsAnArgumentRatherThanAsScript(t *testing.T) {
	const nasty = `/Users/someone/My "App"/app-tail; touch /tmp/pwned`
	digest := strings.Repeat("ab", 32)
	flags := []string{`--dns-domain=x"; touch /tmp/pwned; "y`, "--full-tunnel"}
	prompt := provisionPrompt(nasty, digest, nil)
	args := provisionCommand(nasty, 501, prompt, digest, flags)

	script, rest := scriptAndArgs(t, args)
	if strings.Contains(script, nasty) || strings.Contains(script, "My ") {
		t.Errorf("the binary path was built into the script, so a path can become a command:\n%s", script)
	}
	if len(rest) != 5+len(flags) || rest[0] != nasty {
		t.Fatalf("the binary path is not passed as its own argument: %q", rest)
	}
	if !slices.Equal(rest[5:], flags) || strings.Contains(script, "dns-domain") {
		t.Errorf("the approval flags are not passed as their own arguments: %q", rest)
	}
	if rest[1] != "501" {
		t.Errorf("the account is passed as %q, want the number it was given", rest[1])
	}
	// The prompt names the path too, so it is data for the same reason the path is: it
	// reaches the dialog as an argument and is never spliced into the script text.
	if rest[2] != prompt || strings.Contains(script, "SHA-256") {
		t.Errorf("the prompt is not passed as its own argument: %q\n%s", rest, script)
	}
	if !strings.Contains(script, "with prompt (item 3 of argv)") {
		t.Errorf("the dialog is not given the prompt, so it says only that something wants rights:\n%s", script)
	}
	// The root shell's own text and the fingerprint it checks are arguments too, so the
	// script never carries a value that could differ between two installs.
	if rest[3] != installShell || rest[4] != digest {
		t.Errorf("the install shell and fingerprint are not passed as their own arguments: %q", rest[3:])
	}
	// Every value that reaches a shell has to be quoted for one: the four fixed ones, and each
	// approval flag in the loop that appends them. The prompt reaches only the dialog.
	if got := strings.Count(script, "quoted form of"); got != 5 {
		t.Errorf("the script quotes %d of its 5 kinds of shell argument for the shell:\n%s", got, script)
	}
	if !strings.Contains(script, "repeat with i from 6 to count of argv") {
		t.Errorf("the script does not pass on every approval flag after the fixed arguments:\n%s", script)
	}
	if !strings.Contains(script, "with administrator privileges") {
		t.Errorf("the script does not ask for the rights, so the install would fail as the user:\n%s", script)
	}
}

// scriptAndArgs splits the command into the script it runs and the arguments it passes,
// so a test asserts against each rather than against one flat list where a value in the
// wrong half would still be found.
func scriptAndArgs(t *testing.T, args []string) (string, []string) {
	t.Helper()
	if len(args) < 3 || args[1] != "-e" {
		t.Fatalf("the command is not `osascript -e <script> <args...>`: %q", args)
	}
	if args[0] != osascriptPath {
		t.Errorf("the command runs %q rather than the absolute %s, so PATH decides what gets elevated",
			args[0], osascriptPath)
	}
	return args[2], args[3:]
}

// A dismissed dialog is an answer and every other failure is a machine that could not do
// it. Reporting the first as the second sends someone to debug a decision they made.
func TestADismissedPromptIsAnAnswerRatherThanAFailure(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantDecline bool
	}{
		{
			name:        "the number AppleScript documents",
			output:      "0:17: execution error: User canceled. (-128)",
			wantDecline: true,
		},
		{
			name:        "the sentence it prints",
			output:      "execution error: User canceled.",
			wantDecline: true,
		},
		{
			name:   "a machine that could not run the installer",
			output: "write the helper's launch configuration: read-only file system",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := provisionErr(errors.New("exit status 1"), tc.output)
			if got := errors.Is(err, ErrDeclined); got != tc.wantDecline {
				t.Errorf("errors.Is(%v, ErrDeclined) = %v, want %v", err, got, tc.wantDecline)
			}
			if tc.wantDecline {
				return
			}
			// The machine's own words are what the person acts on, so losing them
			// leaves a failure nobody can do anything about.
			if !strings.Contains(err.Error(), "read-only file system") {
				t.Errorf("the failure %q does not carry what the machine said", err)
			}
		})
	}
}

// The helper takes commands only from the account recorded at install time, and that
// record is the entire access control on a root socket. Recording root would mean a helper
// that serves the one account no agent runs as.
//
// Asked of the exported entry point, so the refusal is proven to hold on this machine as it
// is rather than only against a set of steps a test made up.
func TestTheHelperIsNeverInstalledForRoot(t *testing.T) {
	err := ProvisionHelper(t.Context(), func(string, ...any) {}, "/bin/ls", 0, nil)
	if err == nil {
		t.Fatal("the helper was provisioned for root, which no agent runs as")
	}
	if !strings.Contains(err.Error(), "own account") {
		t.Errorf("the refusal said %q, which does not say what to do differently", err)
	}
}

// The account reaches a file root acts on, so it is checked here as it is in the plist:
// an int on the way in is what makes it impossible for it to become anything else.
func TestTheAccountIsCarriedAsTheNumberItWasGiven(t *testing.T) {
	for _, uid := range []int{1, 501, 4294967294} {
		_, rest := scriptAndArgs(t, provisionCommand("/bin/ls", uid, "a prompt", strings.Repeat("ab", 32), nil))
		if want := strconv.Itoa(uid); rest[1] != want {
			t.Errorf("provisionCommand(_, %d) passes the account as %q, want %q", uid, rest[1], want)
		}
	}
}

// Which of the three routes a machine takes is the whole of this decision, and on any one
// machine only one of them would ever run. Getting it wrong is not a visible failure: a
// process that already holds the rights would raise a dialog asking for them, and a
// platform with no escalation would run a command it does not have.
func TestEachKindOfMachineTakesTheRouteThatWorksThere(t *testing.T) {
	tests := []struct {
		name        string
		privileged  bool
		canElevate  bool
		wantInstall bool
		wantElevate bool
	}{
		{
			name:        "an unprivileged macOS agent asks for the rights",
			canElevate:  true,
			wantElevate: true,
		},
		{
			name:        "a process already holding the rights installs directly",
			privileged:  true,
			canElevate:  true,
			wantInstall: true,
		},
		{
			name:        "a platform with no escalation gets the install's own refusal",
			wantInstall: true,
		},
		{
			name:        "and so does a root process there",
			privileged:  true,
			wantInstall: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var installed, elevated bool
			steps := provisionSteps{
				privileged: tc.privileged,
				canElevate: tc.canElevate,
				install: func(context.Context, func(string, ...any), string, int) error {
					installed = true
					return nil
				},
				elevate: func(context.Context, []string) ([]byte, error) {
					elevated = true
					return nil, nil
				},
			}

			if err := provisionHelper(t.Context(), func(string, ...any) {}, "/bin/ls", 501, nil, steps); err != nil {
				t.Fatalf("provisionHelper = %v, want the route to be taken", err)
			}
			if installed != tc.wantInstall {
				t.Errorf("installed directly = %v, want %v", installed, tc.wantInstall)
			}
			if elevated != tc.wantElevate {
				t.Errorf("asked for administrator rights = %v, want %v", elevated, tc.wantElevate)
			}
		})
	}
}

// The installer runs inside a dialog, so what it printed is the only trace it leaves. A
// half-done install that reported nothing looks exactly like one that worked.
func TestWhatTheInstallerPrintedInsideTheDialogIsCarriedOut(t *testing.T) {
	var logged []string
	steps := provisionSteps{
		canElevate: true,
		install:    func(context.Context, func(string, ...any), string, int) error { return nil },
		elevate: func(context.Context, []string) ([]byte, error) {
			return []byte("  no previous helper was unloaded\n"), nil
		},
	}

	err := provisionHelper(t.Context(), func(format string, args ...any) {
		logged = append(logged, format)
	}, "/bin/ls", 501, nil, steps)

	if err != nil {
		t.Fatalf("provisionHelper = %v, want a success that carries what it said", err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "%s") {
		t.Fatalf("the installer's output was not reported: %q", logged)
	}
}

// Silence is not something to report: an install that printed nothing would otherwise log
// an empty line, which reads as a message that got lost.
func TestAnInstallerThatSaidNothingLogsNothing(t *testing.T) {
	var logged int
	steps := provisionSteps{
		canElevate: true,
		install:    func(context.Context, func(string, ...any), string, int) error { return nil },
		elevate:    func(context.Context, []string) ([]byte, error) { return []byte("  \n"), nil },
	}

	if err := provisionHelper(t.Context(), func(string, ...any) { logged++ }, "/bin/ls", 501, nil, steps); err != nil {
		t.Fatalf("provisionHelper = %v, want a success", err)
	}
	if logged != 0 {
		t.Errorf("a silent install produced %d log lines, want none", logged)
	}
}

// A failed escalation carries the dialog's answer, and the answer is what tells a dismissed
// prompt apart from a machine that could not do it.
func TestAFailedEscalationIsClassifiedByWhatTheDialogSaid(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantDecline bool
		wantPhrase  string
	}{
		{
			name:        "a dismissed dialog",
			output:      "execution error: User canceled. (-128)",
			wantDecline: true,
		},
		{
			name:       "a machine that could not do it",
			output:     "install the helper: read-only file system",
			wantPhrase: "read-only file system",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			steps := provisionSteps{
				canElevate: true,
				install:    func(context.Context, func(string, ...any), string, int) error { return nil },
				elevate: func(context.Context, []string) ([]byte, error) {
					return []byte(tc.output), errors.New("exit status 1")
				},
			}

			err := provisionHelper(t.Context(), func(string, ...any) {}, "/bin/ls", 501, nil, steps)
			if err == nil {
				t.Fatal("a failed escalation was reported as a completed install")
			}
			if got := errors.Is(err, ErrDeclined); got != tc.wantDecline {
				t.Errorf("errors.Is(%v, ErrDeclined) = %v, want %v", err, got, tc.wantDecline)
			}
			if tc.wantPhrase != "" && !strings.Contains(err.Error(), tc.wantPhrase) {
				t.Errorf("the failure %q does not carry what the machine said", err)
			}
		})
	}
}

// The installer reports what it half-did through the log and not through its return value,
// so provisioning without one would discard it. This is the one argument the caller cannot
// omit.
func TestProvisioningRefusesToRunWithNowhereToReport(t *testing.T) {
	err := ProvisionHelper(t.Context(), nil, "/bin/ls", 501, nil)
	if err == nil {
		t.Fatal("an install with no log function was accepted")
	}
	if !strings.Contains(err.Error(), "log function") {
		t.Errorf("the refusal said %q, which does not say what was missing", err)
	}
}

// The steps this machine actually gets, as opposed to the ones a test makes up. Both facts
// have to be the machine's own: a hardcoded answer here would send every machine down the
// same route regardless of what it can do.
func TestTheStepsThisMachineGetsAreTheOnesItCanPerform(t *testing.T) {
	steps := machineProvisionSteps()

	if steps.privileged != Privileged() {
		t.Errorf("the steps report privileged=%v on a machine where it is %v", steps.privileged, Privileged())
	}
	if steps.canElevate != SupportsHelperInstall() {
		t.Errorf("the steps report canElevate=%v on a machine where it is %v",
			steps.canElevate, SupportsHelperInstall())
	}
	if steps.install == nil || steps.elevate == nil {
		t.Fatal("the steps carry no act to perform, so provisioning would panic rather than install")
	}
}

// The escalation reads the command's output to tell a dismissed dialog from a failure, so
// output that never arrives would make every refusal look like a machine error. Asked of a
// command with nothing to do with the helper, because the dangerous one is provisionCommand
// and that is checked as data above.
func TestTheCommandRunnerReturnsWhatTheCommandWroteOnEitherStream(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate this test binary: %v", err)
	}
	child := []string{self, "-test.run=^" + helperTestName + "$"}

	t.Setenv(helperExitVar, "0")
	out, err := runCombined(t.Context(), child)
	if err != nil {
		t.Fatalf("runCombined = %v, want the command to have run: %s", err, out)
	}
	for _, want := range []string{helperOnStdout, helperOnStderr} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the output %q is missing %q, so half of what the installer said is lost", out, want)
		}
	}

	t.Setenv(helperExitVar, "1")
	out, err = runCombined(t.Context(), child)
	if err == nil {
		t.Fatal("a command that failed was reported as a success")
	}
	if !strings.Contains(string(out), helperOnStderr) {
		t.Errorf("a failed command's output %q was discarded, leaving nothing to classify it by", out)
	}
}

// runCombined has to be asked about a real child process, and re-running this test binary
// is the one command every platform is certain to have. The variable both selects the
// child's exit status and marks it as the child at all.
const (
	helperTestName = "TestTheCommandRunnerHelperWritesToBothStreams"
	helperExitVar  = "APPTAIL_COMMAND_RUNNER_HELPER_EXIT"
	helperOnStdout = "what the installer said it did"
	helperOnStderr = "what the dialog answered"
)

func TestTheCommandRunnerHelperWritesToBothStreams(t *testing.T) {
	code, asked := os.LookupEnv(helperExitVar)
	if !asked {
		t.Skip("this is the child process the command-runner test launches")
	}
	status, err := strconv.Atoi(code)
	if err != nil {
		t.Fatalf("%s = %q, which is not an exit status", helperExitVar, code)
	}
	fmt.Fprintln(os.Stdout, helperOnStdout)
	fmt.Fprintln(os.Stderr, helperOnStderr)
	os.Exit(status)
}

// macOS's administrator dialog says only that something wants to make changes unless it is
// told more, and a person can only refuse a request they can tell apart from the one they
// meant to approve. So the dialog names the exact file that will be installed as root and the
// start of its SHA-256: the path that runs is the one shown, a link is shown as what it
// leads to, and two builds at the same path are told apart by the fingerprint.
func TestTheAdministratorPromptNamesTheBinaryAndItsFingerprint(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve the test's directory: %v", err)
	}
	build := filepath.Join(root, "app-tail")
	body := []byte("this exact build")
	if err := os.WriteFile(build, body, 0o755); err != nil {
		t.Fatalf("write the build: %v", err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(build, link); err != nil {
		t.Fatalf("link the build: %v", err)
	}
	sum := sha256.Sum256(body)
	fingerprint := hex.EncodeToString(sum[:])[:16]

	var asked []string
	steps := provisionSteps{
		canElevate: true,
		install:    func(context.Context, func(string, ...any), string, int) error { return nil },
		elevate: func(_ context.Context, args []string) ([]byte, error) {
			asked = args
			return nil, nil
		},
	}
	if err := provisionHelper(t.Context(), func(string, ...any) {}, link, 501, nil, steps); err != nil {
		t.Fatalf("provisionHelper = %v", err)
	}
	_, rest := scriptAndArgs(t, asked)
	if len(rest) != 5 {
		t.Fatalf("the command passes %q, want the binary, the account, the prompt, the install shell and the fingerprint", rest)
	}
	if strings.Contains(rest[2], "approve") {
		t.Errorf("an install that approves nothing says it does: %q", rest[2])
	}
	// The fingerprint root checks the copy against is the whole one the prompt abbreviates.
	if rest[4] != hex.EncodeToString(sum[:]) {
		t.Errorf("root checks the copy against %q, want the build's full SHA-256", rest[4])
	}
	if rest[0] != build {
		t.Errorf("the command installs %s, want %s, the file the prompt names", rest[0], build)
	}
	if !strings.Contains(rest[2], build) {
		t.Errorf("the prompt %q does not name %s", rest[2], build)
	}
	if !strings.Contains(rest[2], fingerprint) {
		t.Errorf("the prompt %q does not carry the build's fingerprint %s", rest[2], fingerprint)
	}

	// A path made to look like more than one line in the dialog is shown as the single
	// value it is, so it cannot draw a second, reassuring sentence under the real one.
	shown := provisionPrompt("/tmp/x\nThis request is from Apple", strings.Repeat("0", 64), nil)
	if strings.Contains(shown, "\n") {
		t.Errorf("a line break in the path reached the dialog: %q", shown)
	}

	// Nothing there is nothing to vouch for, and the dialog is never raised for it.
	asked = nil
	if err := provisionHelper(t.Context(), func(string, ...any) {}, filepath.Join(root, "missing"), 501, nil, steps); err == nil {
		t.Error("a binary that does not exist was offered to the dialog")
	}
	if asked != nil {
		t.Errorf("the dialog was raised for a binary that does not exist: %q", asked)
	}
}

// When the install also approves what the settings use, the dialog lists each change before
// anyone types the password, and root is handed exactly those approvals as flags. Root is never
// given the config file: it is the user's to write, so reading it after the password would
// approve whatever it said by then rather than what the dialog showed.
func TestAnInstallThatAlsoApprovesListsEachChangeAndPassesExactlyThose(t *testing.T) {
	var asked []string
	steps := provisionSteps{
		canElevate: true,
		install: func(context.Context, func(string, ...any), string, int) error {
			t.Error("the unprompted install ran on a machine that asks")
			return nil
		},
		elevate: func(_ context.Context, args []string) ([]byte, error) {
			asked = args
			return nil, nil
		},
	}
	needs := []grants.Need{
		{Kind: grants.KindFullTunnel, Reason: "carry all of this machine's internet traffic"},
		{Kind: grants.KindRoute, Value: "203.0.113.0/24", Reason: "send 203.0.113.0/24 through app-tail\nThis request is from Apple"},
	}
	if err := provisionHelper(t.Context(), func(string, ...any) {}, "/bin/ls", 501, needs, steps); err != nil {
		t.Fatalf("provisionHelper = %v", err)
	}
	_, rest := scriptAndArgs(t, asked)
	if want := []string{"--full-tunnel", "--route=203.0.113.0/24"}; len(rest) < 5 || !slices.Equal(rest[5:], want) {
		t.Fatalf("the command passes %q, want the approvals %q after the fixed arguments", rest, want)
	}
	for _, arg := range rest {
		if strings.Contains(arg, "--config") || strings.HasSuffix(arg, ".json") {
			t.Errorf("root was handed a config to read: %q", arg)
		}
	}
	for _, reason := range []string{"carry all of this machine's internet traffic", "send 203.0.113.0/24 through app-tail"} {
		if !strings.Contains(rest[2], reason) {
			t.Errorf("the prompt %q does not list %q", rest[2], reason)
		}
	}
	if strings.Contains(rest[2], "\n") {
		t.Errorf("a line break in a reason reached the dialog: %q", rest[2])
	}
}
