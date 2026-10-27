// SPDX-License-Identifier: MIT

package hostnet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Asserting the shape of the command proves how it is built; this proves the system agrees.
// AppleScript's own engine is what decides whether an argument is data, and the answer is
// a fact about macOS rather than about this code -- so it is asked rather than assumed.
func TestMacOSTreatsTheArgumentAsDataAndQuotesItForAShell(t *testing.T) {
	const nasty = `/tmp/a"; touch /tmp/app-tail-test-pwned; "b`

	// The same argv shape the real command uses, with a handler that returns the value
	// instead of running it: `do shell script ... with administrator privileges` would
	// raise a password dialog, which a test must never do.
	out, err := exec.Command(osascriptPath, "-e",
		"on run argv\nreturn quoted form of (item 1 of argv)\nend run", nasty).CombinedOutput()
	if err != nil {
		t.Fatalf("ask AppleScript to quote an argument: %v: %s", err, out)
	}

	got := strings.TrimSpace(string(out))
	if strings.Contains(got, `"; touch`) && !strings.HasPrefix(got, "'") {
		t.Errorf("the argument came back able to end a shell word: %s", got)
	}
	// A shell is the thing that has to agree, so it is the thing that is asked: echoing
	// the quoted form must produce the original path and nothing else.
	echoed, err := exec.Command("/bin/sh", "-c", "printf %s "+got).CombinedOutput()
	if err != nil {
		t.Fatalf("run the quoted form through a shell: %v: %s", err, echoed)
	}
	if string(echoed) != nasty {
		t.Errorf("a shell read the quoted path as %q, want %q", echoed, nasty)
	}
}

// The prompt is the one argument the dialog shows rather than hands to a shell, so what has
// to hold for it is that AppleScript takes it as text whatever it contains, and that the real
// script -- prompt clause and all -- is one macOS accepts. Both are asked of macOS itself:
// the script is compiled without being run, since running it would raise the dialog, and a
// handler of the same shape returns the prompt it was given for comparison.
func TestMacOSShowsAHostilePromptAsTheTextItIs(t *testing.T) {
	compiled := filepath.Join(t.TempDir(), "provision.scpt")
	if out, err := exec.Command("/usr/bin/osacompile", "-e", provisionScript, "-o", compiled).CombinedOutput(); err != nil {
		t.Fatalf("macOS does not accept the provisioning script: %v: %s", err, out)
	}

	const nasty = `/tmp/a"; do shell script "touch /tmp/app-tail-test-pwned" --\ b`
	prompt := provisionPrompt(nasty, strings.Repeat("ab", 32), nil)
	out, err := exec.Command(osascriptPath, "-e",
		"on run argv\nreturn item 3 of argv\nend run", nasty, "501", prompt, installShell, strings.Repeat("ab", 32)).CombinedOutput()
	if err != nil {
		t.Fatalf("ask AppleScript for the prompt argument: %v: %s", err, out)
	}
	if got := strings.TrimSuffix(string(out), "\n"); got != prompt {
		t.Errorf("AppleScript read the prompt as %q, want %q", got, prompt)
	}
}

// fakeInstaller writes an executable that reports the arguments it was run with and the
// directory it was run from, standing in for the app-tail binary the root shell copies.
func fakeInstaller(t *testing.T) (path, digest string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "app-tail")
	body := []byte("#!/bin/sh\necho \"ran from $(/usr/bin/dirname \"$0\") with $*\"\n")
	if err := os.WriteFile(path, body, 0o755); err != nil {
		t.Fatalf("write the stand-in binary: %v", err)
	}
	sum := sha256.Sum256(body)
	return path, hex.EncodeToString(sum[:])
}

// runInstallShell runs installShell the way the elevated command does, as the current
// account: nothing in it needs root except what the installer it starts goes on to do.
func runInstallShell(t *testing.T, src, digest string, flags ...string) (string, error) {
	t.Helper()
	args := append([]string{"-c", installShell, "app-tail-install", src, digest, "501"}, flags...)
	out, err := exec.Command("/bin/sh", args...).CombinedOutput()
	return string(out), err
}

// The prompt vouches for one file, and root has to run that file and not whatever sits at
// its path a moment later. What runs is a copy, outside the folder anyone else can write,
// and the copy is gone afterwards.
func TestRootRunsACheckedCopyOfTheBinaryThePromptNamed(t *testing.T) {
	src, digest := fakeInstaller(t)

	out, err := runInstallShell(t, src, digest)
	if err != nil {
		t.Fatalf("the install shell failed on the binary the prompt named: %v: %s", err, out)
	}
	line := strings.TrimSpace(out)
	if !strings.HasSuffix(line, " with tun install-helper --owner 501") {
		t.Fatalf("the copy was not run as the installer for the account: %q", line)
	}
	ranFrom := strings.TrimSuffix(strings.TrimPrefix(line, "ran from "), " with tun install-helper --owner 501")
	if ranFrom == filepath.Dir(src) {
		t.Errorf("root ran the binary in place, from %s, where it can be swapped after the prompt", ranFrom)
	}
	if _, err := os.Stat(ranFrom); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the private copy in %s was left behind: %v", ranFrom, err)
	}
}

// A binary swapped after the prompt showed its fingerprint is not run at all, and the
// refusal says why.
func TestABinarySwappedAfterThePromptIsNotRun(t *testing.T) {
	src, digest := fakeInstaller(t)
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho swapped\n"), 0o755); err != nil {
		t.Fatalf("swap the binary: %v", err)
	}

	out, err := runInstallShell(t, src, digest)
	if err == nil {
		t.Fatalf("the install shell ran a binary that no longer matches the fingerprint: %s", out)
	}
	if strings.Contains(out, "swapped") {
		t.Errorf("the swapped binary ran: %s", out)
	}
	if !strings.Contains(out, "changed after the password prompt showed its fingerprint") {
		t.Errorf("the refusal %q does not say why nothing was installed", out)
	}
}

// Given approvals, root's copy installs and then approves exactly those, each flag reaching it
// as the single argument it was; given none, it approves nothing.
func TestRootApprovesExactlyTheChangesThePromptListed(t *testing.T) {
	src, digest := fakeInstaller(t)

	out, err := runInstallShell(t, src, digest, "--full-tunnel", "--dns-domain=corp example")
	if err != nil {
		t.Fatalf("the install shell failed: %v: %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], " with tun install-helper --owner 501") ||
		!strings.HasSuffix(lines[1], " with tun grant --full-tunnel --dns-domain=corp example") {
		t.Errorf("root ran %q, want the install and then `tun grant` with the two approvals", lines)
	}

	out, err = runInstallShell(t, src, digest)
	if err != nil {
		t.Fatalf("the install shell failed: %v: %s", err, out)
	}
	if strings.Contains(out, "grant") {
		t.Errorf("root approved something when nothing was listed: %q", out)
	}
}

// The command root runs is built by AppleScript from the arguments, so macOS is asked for it
// on hostile approval flags and a shell runs what it returned: the stand-in must receive each
// flag as the one argument it was, and nothing may run as a command.
func TestMacOSHandsEachInstallArgumentToRootAsTheOneArgumentItWas(t *testing.T) {
	compiled := filepath.Join(t.TempDir(), "provision.scpt")
	if out, err := exec.Command("/usr/bin/osacompile", "-e", provisionScript, "-o", compiled).CombinedOutput(); err != nil {
		t.Fatalf("macOS does not accept the provisioning script: %v: %s", err, out)
	}
	src := filepath.Join(t.TempDir(), "app tail")
	body := []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n")
	if err := os.WriteFile(src, body, 0o755); err != nil {
		t.Fatalf("write the stand-in binary: %v", err)
	}
	sum := sha256.Sum256(body)
	flags := []string{`--openvpn=a'; touch /tmp/app-tail-test-pwned; '$(reboot):1194=aa`, "--dns-domain=x\" y"}
	argv := append([]string{"-e", "on run argv\nreturn my installCommandLine(argv)\nend run\n" + installCommandLine,
		src, "501", "prompt", installShell, hex.EncodeToString(sum[:])}, flags...)
	out, err := exec.Command(osascriptPath, argv...).CombinedOutput()
	if err != nil {
		t.Fatalf("ask AppleScript for the command line: %v: %s", err, out)
	}
	ran, err := exec.Command("/bin/sh", "-c", strings.TrimSuffix(string(out), "\n")).CombinedOutput()
	if err != nil {
		t.Fatalf("run the command line through a shell: %v: %s", err, ran)
	}
	want := append([]string{"tun", "install-helper", "--owner", "501", "tun", "grant"}, flags...)
	if got := strings.Split(strings.TrimSuffix(string(ran), "\n"), "\n"); !slices.Equal(got, want) {
		t.Errorf("root's copy received %q, want %q", got, want)
	}
	if _, err := os.Stat("/tmp/app-tail-test-pwned"); err == nil {
		t.Error("an argument ran as a command")
	}
}

// The approval script is asked of macOS the same way: compiled without running, and its
// command-line handler run on hostile arguments, whose output a shell must read back as those
// same arguments, one each.
func TestMacOSHandsEachApprovalArgumentToTheHelperAsTheOneArgumentItWas(t *testing.T) {
	compiled := filepath.Join(t.TempDir(), "approve.scpt")
	if out, err := exec.Command("/usr/bin/osacompile", "-e", approveScript, "-o", compiled).CombinedOutput(); err != nil {
		t.Fatalf("macOS does not accept the approval script: %v: %s", err, out)
	}

	echo := filepath.Join(t.TempDir(), "helper with space")
	if err := os.WriteFile(echo, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"), 0o755); err != nil {
		t.Fatalf("write the stand-in helper: %v", err)
	}
	args := []string{"tun", "grant", `--openvpn=a'; touch /tmp/app-tail-test-pwned; '$(reboot):1194=aa`, "--dns-domain=x\" y"}
	out, err := exec.Command(osascriptPath, append([]string{"-e", "on run argv\nreturn my commandLine(argv)\nend run\n" + approveCommandLine, echo, "prompt"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ask AppleScript for the command line: %v: %s", err, out)
	}
	ran, err := exec.Command("/bin/sh", "-c", strings.TrimSuffix(string(out), "\n")).CombinedOutput()
	if err != nil {
		t.Fatalf("run the command line through a shell: %v: %s", err, ran)
	}
	if got := strings.Split(strings.TrimSuffix(string(ran), "\n"), "\n"); !slices.Equal(got, args) {
		t.Errorf("the helper received %q, want %q", got, args)
	}
	if _, err := os.Stat("/tmp/app-tail-test-pwned"); err == nil {
		t.Error("an argument ran as a command")
	}
}
