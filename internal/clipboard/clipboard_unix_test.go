// SPDX-License-Identifier: MIT

//go:build unix

package clipboard

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The value travels on stdin, which is what makes the argument checks sufficient: nothing
// in the text can change how the program is invoked. grep stands in for a clipboard
// program here because it reads stdin and reports through its exit status whether what
// arrived is what was sent -- which is the one thing this needs to observe.
func TestTheValueReachesTheProgramOnStdin(t *testing.T) {
	if _, err := exec.LookPath("grep"); err != nil {
		t.Fatalf("grep is needed to observe what the program receives on stdin: %v", err)
	}
	// The shapes that break argument passing: a leading dash, a space, and a shell
	// metacharacter. On stdin none of them mean anything.
	const value = "-100.64.0.1 && echo pwned"

	if err := run(t.Context(), []string{"grep", "-qF", "-e", value}, value); err != nil {
		t.Errorf("the program did not receive %q on stdin: %v", value, err)
	}
}

// A clipboard program that ran and failed is not a copy. Treating a non-zero exit as
// success would leave the user pasting what was on the clipboard before.
func TestAProgramThatExitsNonZeroIsAFailedCopy(t *testing.T) {
	if _, err := exec.LookPath("grep"); err != nil {
		t.Fatalf("grep is needed to produce a non-zero exit: %v", err)
	}

	err := run(t.Context(), []string{"grep", "-qF", "-e", "a-string-that-is-not-there"}, "100.64.0.1")
	if err == nil {
		t.Fatal("a program that exited non-zero was reported as a successful copy")
	}
	if !strings.Contains(err.Error(), "grep") {
		t.Errorf("the failure is %q, which does not name the program that failed", err)
	}
}

// A machine can have a clipboard program installed and no session for it to talk to, so
// one that fails is not the end of the attempt. This is the whole reason the candidates
// are a list: the copy has to reach the program that works on this machine.
func TestTheProgramsAreTriedInOrderUntilOneOfThemWorks(t *testing.T) {
	for _, name := range []string{"false", "grep"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("%s is needed to stand in for a clipboard program: %v", name, err)
		}
	}
	const value = "100.64.0.1"

	t.Run("a program that fails hands over to the next one", func(t *testing.T) {
		err := copyWith(t.Context(), [][]string{
			{"app-tail-no-such-clipboard-program"},
			{"false"},
			{"grep", "-qF", "-e", value},
		}, value)
		if err != nil {
			t.Errorf("the copy stopped at a failing program instead of reaching the one that works: %v", err)
		}
	})

	t.Run("nothing that works names every program that did not", func(t *testing.T) {
		err := copyWith(t.Context(), [][]string{
			{"app-tail-no-such-clipboard-program"},
			{"false"},
		}, value)
		if err == nil {
			t.Fatal("a copy no program accepted was reported as a success")
		}
		for _, want := range []string{"app-tail-no-such-clipboard-program", "false"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the failure %q does not mention %q, so one attempt went unreported", err, want)
			}
		}
	})

	t.Run("a platform with no clipboard program says so", func(t *testing.T) {
		err := copyWith(t.Context(), nil, value)
		if err == nil || !strings.Contains(err.Error(), "no clipboard program") {
			t.Errorf("copyWith(nil) = %v, want it to say the platform has no clipboard program", err)
		}
	})
}

// What the program itself said is the difference between "not installed" and "no Wayland
// session"; an exit status alone leaves the user with nothing to act on.
func TestWhatTheProgramComplainedAboutIsCarriedIntoTheFailure(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatalf("sh is needed to produce a program that complains: %v", err)
	}

	err := run(t.Context(), []string{"sh", "-c", "echo no clipboard session here >&2; exit 1"}, "100.64.0.1")
	if err == nil {
		t.Fatal("a program that exited non-zero was reported as a successful copy")
	}
	if !strings.Contains(err.Error(), "no clipboard session here") {
		t.Errorf("the failure %q drops what the program said, leaving no remedy", err)
	}
}

// wl-copy forks and goes on serving the selection after the command exits, holding the
// pipes it inherited. Waiting on those pipes would hang the menu click on a copy that has
// already happened, so the shell here reproduces exactly that shape: read the text, exit,
// leave a child behind.
func TestACopyIsDoneWhenTheProgramExitsEvenIfAChildOutlivesIt(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatalf("sh is needed to leave a child holding the pipes: %v", err)
	}

	started := time.Now()
	err := run(t.Context(), []string{"sh", "-c", "cat >/dev/null; sleep 30 &"}, "100.64.0.1")
	elapsed := time.Since(started)

	if err != nil {
		t.Errorf("a program that exited cleanly was reported as a failed copy: %v", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("the copy took %s, so it waited on the child rather than the program", elapsed)
	}
}
