// SPDX-License-Identifier: MIT

package clipboard

import (
	"path/filepath"
	"strings"
	"testing"
)

// The guard is what stands between a malformed value and a clipboard the user then
// pastes somewhere. An empty copy is the one worth naming on its own: it leaves whatever
// was there before, so the click reads as having done nothing at all.
func TestCopyRefusesWhatAClipboardCannotUsefullyHold(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		wantErr string
	}{
		{"address", "100.101.102.103", ""},
		{"dns name", "htpc.tail1a2b3c.ts.net", ""},
		{"multi-line", "one\ntwo", ""},
		{"tab", "one\ttwo", ""},
		{"empty", "", "nothing to copy"},
		{"null byte", "100.64.0.1\x00", "control character"},
		{"escape", "\x1b]0;title\x07", "control character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkText(tc.text)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkText(%q) = %v, want nil", tc.text, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkText(%q) = nil, want an error mentioning %q", tc.text, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("checkText(%q) = %q, want it to mention %q", tc.text, err, tc.wantErr)
			}
		})
	}
}

// The text travels on stdin, so the one way it could ever reach a program as an argument
// is if somebody reached for a shell to build the command. A candidate is a program
// executed directly with fixed arguments -- some of which are a flag's value, like
// xclip's "-selection clipboard" -- and nothing in it may be interpreted by anything.
func TestNoClipboardCommandGoesThroughAShell(t *testing.T) {
	// Metacharacters are what a shell acts on. None of them can appear in a command that
	// is handed straight to exec, so their presence means a shell is in the picture.
	// The path separators are left out: one platform names its program by full path, on
	// purpose, and the rule for that is the one below rather than this one.
	const metacharacters = " \t|&;<>$`\"'*?()[]{}!#~\n"

	candidates, err := commands()
	if err != nil {
		t.Fatalf("commands: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatal("this platform has no clipboard command at all")
	}
	for _, argv := range candidates {
		if len(argv) == 0 {
			t.Fatal("a candidate has no program name")
		}
		switch argv[0] {
		case "sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh":
			t.Errorf("%q is a shell, so its arguments are a script rather than a program's flags", argv[0])
		}
		// A bare name or a full path, and nothing in between: a relative path with a
		// separator in it would be resolved against whatever directory the process happens
		// to be in.
		if strings.ContainsAny(argv[0], metacharacters) {
			t.Errorf("program %q is not a program name", argv[0])
		}
		if strings.ContainsAny(argv[0], `/\`) && !filepath.IsAbs(argv[0]) {
			t.Errorf("program %q is a relative path, so which program runs depends on the working directory", argv[0])
		}
		for _, arg := range argv[1:] {
			if strings.ContainsAny(arg, metacharacters) {
				t.Errorf("%s carries argument %q, which a shell would act on", argv[0], arg)
			}
		}
	}
}

// A value that fails the guard must never reach exec, so Copy returns the guard's error
// rather than launching anything.
func TestCopyReturnsTheGuardsErrorWithoutLaunchingAnything(t *testing.T) {
	if err := Copy(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "nothing to copy") {
		t.Fatalf("Copy(\"\") = %v, want the refusal", err)
	}
}

// A clipboard program that is not installed has to say so. Reporting nothing would leave
// the user pasting whatever was on the clipboard before and believing it was the address
// they just clicked.
func TestACopyThatCouldNotRunSaysWhichProgramFailed(t *testing.T) {
	err := run(t.Context(), []string{"app-tail-no-such-clipboard-program"}, "100.64.0.1")
	if err == nil {
		t.Fatal("running a program that does not exist reported success")
	}
	if !strings.Contains(err.Error(), "app-tail-no-such-clipboard-program") {
		t.Errorf("the failure is %q, which does not name the program that could not run", err)
	}
}
