// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// presentIn answers the plan's question from a list of file names.
func presentIn(names ...string) func(string) (bool, error) {
	return func(name string) (bool, error) { return slices.Contains(names, name), nil }
}

// targetsOf maps each install-folder name in a plan to the file it is copied from.
func targetsOf(plan []installFile) map[string]string {
	out := map[string]string{}
	for _, file := range plan {
		out[file.target] = file.source
	}
	return out
}

// Nothing but Windows starts app-tail itself with administrator rights, so the command says
// so rather than pretending to install anything, and points at the guide that does apply.
func TestInstallingOutsideWindowsSaysItIsWindowsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this is the platform the install is for")
	}
	env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}

	err := runInstall(context.Background(), nil, env)
	if err == nil {
		t.Fatal("install reported success on a platform it does nothing on")
	}
	for _, want := range []string{"Windows only", "docs/install.md"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q", err, want)
		}
	}
}

func TestInstallTakesNoPositionalArguments(t *testing.T) {
	env := Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if err := runInstall(context.Background(), []string{`C:\somewhere`}, env); !errors.Is(err, ErrUsage) {
		t.Errorf("install with a stray argument returned %v, want a usage error", err)
	}
}

// The release names both builds after the version, and the install gives them the fixed
// names a login item and the build scripts look for.
func TestTheInstallCopiesTheGUITwinOfTheConsoleBuildUnderFixedNames(t *testing.T) {
	console, gui := "app-tail-1.4.0-windows-amd64.exe", "app-tail-1.4.0-windows-amd64-gui.exe"
	plan, err := installPlan(console, presentIn(console, gui, "wintun.dll", "WINTUN-LICENSE.txt", "THIRD_PARTY_LICENSES.txt"))
	if err != nil {
		t.Fatalf("plan an install from a whole release: %v", err)
	}
	want := map[string]string{
		"app-tail.exe":             console,
		"app-tail-gui.exe":         gui,
		"wintun.dll":               "wintun.dll",
		"WINTUN-LICENSE.txt":       "WINTUN-LICENSE.txt",
		"THIRD_PARTY_LICENSES.txt": "THIRD_PARTY_LICENSES.txt",
	}
	if got := targetsOf(plan); !mapsEqual(got, want) {
		t.Errorf("install plan = %v, want %v", got, want)
	}
	if skipped := skippedTargets(plan); len(skipped) != 0 {
		t.Errorf("a whole release skipped %v", skipped)
	}
}

// Started from Explorer it is the GUI build that runs the install, and the console build
// beside it is the twin.
func TestTheInstallFindsTheConsoleTwinWhenTheGUIBuildRunsIt(t *testing.T) {
	plan, err := installPlan("app-tail-gui.exe", presentIn("app-tail.exe", "app-tail-gui.exe", "wintun.dll"))
	if err != nil {
		t.Fatalf("plan an install from the GUI build: %v", err)
	}
	got := targetsOf(plan)
	if got["app-tail.exe"] != "app-tail.exe" || got["app-tail-gui.exe"] != "app-tail-gui.exe" {
		t.Errorf("install plan = %v, want both builds under their own names", got)
	}
}

// A build with no GUI twin installs without one, and the name it would have had is listed
// so a GUI agent from an earlier install is not left beside a newer CLI.
func TestABuildWithoutAGUITwinInstallsWithoutOne(t *testing.T) {
	plan, err := installPlan("app-tail.exe", presentIn("app-tail.exe", "wintun.dll"))
	if err != nil {
		t.Fatalf("plan an install from a lone console build: %v", err)
	}
	if _, there := targetsOf(plan)["app-tail-gui.exe"]; there {
		t.Error("a GUI build that is not there was planned for copying")
	}
	if !slices.Contains(skippedTargets(plan), "app-tail-gui.exe") {
		t.Errorf("skipped %v, want app-tail-gui.exe among them so an older one is removed", skippedTargets(plan))
	}
}

// Elevating is for the features that load wintun.dll, so an install without it would put a
// copy where only administrators can add the missing file -- and still not start them.
func TestTheInstallRefusesAFolderWithoutWintun(t *testing.T) {
	_, err := installPlan("app-tail.exe", presentIn("app-tail.exe", "app-tail-gui.exe"))
	if err == nil {
		t.Fatal("an install without wintun.dll was planned")
	}
	if !strings.Contains(err.Error(), "wintun.dll") {
		t.Errorf("the refusal %q does not name the missing file", err)
	}
}

func TestTheInstallStopsWhenTheSourceFolderCannotBeRead(t *testing.T) {
	failing := func(string) (bool, error) { return false, errors.New("access denied") }
	if _, err := installPlan("app-tail.exe", failing); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("a folder that could not be checked returned %v, want its failure", err)
	}
}

func TestACopyThatDoesNotMatchItsSourceIsRefused(t *testing.T) {
	read := strings.Repeat("a", 64)
	if err := verifyCopied("app-tail.exe", read, strings.Repeat("b", 64)); err == nil {
		t.Error("an installed file with a different hash from its source was accepted")
	}
	if err := verifyCopied("app-tail.exe", read, strings.ToUpper(read)); err != nil {
		t.Errorf("an installed file matching its source was refused: %v", err)
	}
}

// The elevated copy runs in a window of its own, so with the flag the result is printed
// there and the window waits for Enter instead of closing over it.
func TestAPausedInstallPrintsItsResultAndWaitsForEnter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the install would run for real here")
	}
	var stdout, stderr bytes.Buffer
	stdin := &countingReader{r: strings.NewReader("\n")}
	env := Env{Stdout: &stdout, Stderr: &stderr, Stdin: stdin}

	err := runInstall(context.Background(), []string{"--" + pauseWhenDoneFlag}, env)
	if err == nil {
		t.Fatal("the paused install reported success on a platform it does nothing on")
	}
	if !strings.Contains(stderr.String(), "app-tail was not installed") {
		t.Errorf("the window would close over a failure it never printed; stderr: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Press Enter") {
		t.Errorf("the window did not say how to close it; stdout: %q", stdout.String())
	}
	if stdin.reads == 0 {
		t.Error("the window closed without waiting for Enter")
	}
}

// countingReader records whether anything waited on it.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
