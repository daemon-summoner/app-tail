// SPDX-License-Identifier: MIT

package sysdns

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// resolvectl repoints the whole machine's name resolution, so which program answers to that
// name is not something the environment this process was started in may decide. A PATH entry
// is exactly that decision: anything earlier on the list than the real program takes its
// place, and it runs with whatever rights this process holds.
func TestResolvectlIsNeverTakenFromPATH(t *testing.T) {
	dir := t.TempDir()
	imposter := filepath.Join(dir, "resolvectl")
	if err := os.WriteFile(imposter, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write the program under test: %v", err)
	}
	t.Setenv("PATH", dir)

	got := resolvectl()
	if got == imposter {
		t.Fatalf("resolvectl() = %q, want a program named by this build rather than one found on PATH", got)
	}
	if got != "" && !slices.Contains(resolvectlPaths, got) {
		t.Errorf("resolvectl() = %q, want one of %v", got, resolvectlPaths)
	}
}

// Every candidate is absolute, which is what makes the list a list of programs rather than of
// names resolved against whatever directory this process happens to be running in.
func TestEveryPlaceResolvectlIsLookedForIsAnAbsolutePath(t *testing.T) {
	for _, path := range resolvectlPaths {
		if !filepath.IsAbs(path) {
			t.Errorf("resolvectl is looked for at %q, which is not an absolute path", path)
		}
	}
}

// A machine with no resolvectl is refused, and the refusal has to say where app-tail looked:
// on a distribution that keeps it somewhere else that sentence is the whole difference
// between installing something and having no idea what is missing.
func TestARefusalNamesEveryPlaceItLookedForResolvectl(t *testing.T) {
	if path := resolvectl(); path != "" {
		t.Skipf("this machine keeps resolvectl at %s, so there is no refusal to read", path)
	}

	ok, reason := linuxResolver{}.supported()
	if ok {
		t.Fatal("a machine with no resolvectl was reported as one app-tail can change the resolver on")
	}
	for _, path := range resolvectlPaths {
		if !strings.Contains(reason, path) {
			t.Errorf("the refusal %q does not say that app-tail looked at %s", reason, path)
		}
	}
}
