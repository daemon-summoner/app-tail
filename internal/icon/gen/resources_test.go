// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

// The four-part number is what Windows compares two builds by, and what an installer
// or a scanner reads without parsing the string. A bare commit starts with digits, so a
// parser that took the leading digits would stamp 4233.0.0.0 on a build off 4233a6b98901
// and every later release would sort below it.
func TestOnlyATagBecomesTheFourPartVersionNumber(t *testing.T) {
	cases := []struct {
		in      string
		want    [4]uint16
		release bool
	}{
		{"v1.2.3", [4]uint16{1, 2, 3, 0}, true},
		{"v1.2", [4]uint16{1, 2, 0, 0}, true},
		{"1.2.3", [4]uint16{1, 2, 3, 0}, true},
		{"v0.0", [4]uint16{}, true},
		{"v1.2.3-4-g4233a6b98901", [4]uint16{1, 2, 3, 0}, false},
		{"v1.2.3+dirty", [4]uint16{1, 2, 3, 0}, false},
		{"v1.2.3-4-g4233a6b98901+dirty", [4]uint16{1, 2, 3, 0}, false},
		{"4233a6b98901", [4]uint16{}, false},
		{"2777559", [4]uint16{}, false},
		{"dev", [4]uint16{}, false},
		{"v1", [4]uint16{}, false},
		{"v1.2.3.4", [4]uint16{}, false},
		{"v70000.1", [4]uint16{}, false},
		{"v1.x", [4]uint16{}, false},
	}
	for _, tc := range cases {
		if got := numericVersion(tc.in); got != tc.want {
			t.Errorf("numericVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
		if got := isReleaseTag(tc.in); got != tc.release {
			t.Errorf("isReleaseTag(%q) = %v, want %v", tc.in, got, tc.release)
		}
	}
}

// The Details tab and every heuristic that reads a version block see the fields below.
// A block missing the company or the product is the shape an unsigned dropper has, so
// each is pinned by name, and the full version string has to survive untouched: it is
// how a build off an untagged commit says which commit.
func TestTheVersionBlockNamesThePublisherTheProductAndTheBuild(t *testing.T) {
	const ver = "v1.2.3-4-g4233a6b98901+dirty"
	rs, err := windowsResources(ver)
	if err != nil {
		t.Fatalf("windowsResources: %v", err)
	}
	raw := rs.Get(winres.RT_VERSION, winres.ID(1), version.LangDefault)
	if raw == nil {
		t.Fatal("no en-US version resource in the set")
	}
	vi, err := version.FromBytes(raw)
	if err != nil {
		t.Fatalf("the version resource does not parse: %v", err)
	}
	if want := [4]uint16{1, 2, 3, 0}; vi.FileVersion != want || vi.ProductVersion != want {
		t.Errorf("numbers = file %v product %v, want both %v", vi.FileVersion, vi.ProductVersion, want)
	}
	if !vi.Flags.Prerelease {
		t.Error("a build between two tags is not flagged as a prerelease")
	}

	strs := versionStrings(t, vi)
	for key, want := range map[string]string{
		version.CompanyName:      "sellitus",
		version.ProductName:      "app-tail",
		version.OriginalFilename: "app-tail.exe",
		version.FileVersion:      ver,
		version.ProductVersion:   ver,
	} {
		if got := strs[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{version.FileDescription, version.InternalName, version.LegalCopyright} {
		if strs[key] == "" {
			t.Errorf("%s is empty", key)
		}
	}
}

func TestAnExactTagIsNotFlaggedAsAPrerelease(t *testing.T) {
	vi, err := versionInfo("v2.0.0")
	if err != nil {
		t.Fatalf("versionInfo: %v", err)
	}
	if vi.Flags.Prerelease {
		t.Error("a release tag is flagged as a prerelease")
	}
}

// The manifest's job is to exist with asInvoker in it: without one, Windows guesses
// from the file name whether a program is an installer that needs elevation, and
// app-tail decides that for itself through internal/elevate. requireAdministrator
// would make every start a UAC prompt, including the contained mode that needs none.
func TestTheManifestLeavesElevationToTheProgram(t *testing.T) {
	rs, err := windowsResources("v1.2.3")
	if err != nil {
		t.Fatalf("windowsResources: %v", err)
	}
	raw := rs.Get(winres.RT_MANIFEST, winres.ID(1), winres.LCIDDefault)
	if raw == nil {
		t.Fatal("no manifest resource in the set")
	}
	m, err := winres.AppManifestFromXML(raw)
	if err != nil {
		t.Fatalf("the manifest does not parse: %v", err)
	}
	if m.ExecutionLevel != winres.AsInvoker {
		t.Errorf("execution level = %v, want asInvoker", m.ExecutionLevel)
	}
	if m.Identity.Name != assemblyName {
		t.Errorf("identity = %q, want %q", m.Identity.Name, assemblyName)
	}
	if want := [4]uint16{1, 2, 3, 0}; m.Identity.Version != want {
		t.Errorf("identity version = %v, want %v", m.Identity.Version, want)
	}
	if m.Compatibility != winres.Win10AndAbove {
		t.Errorf("minimum OS = %v, want Windows 10, which is what Go itself requires", m.Compatibility)
	}
}

// The icon still has to be in the set: the version block and the manifest joined it,
// they did not replace it.
func TestTheResourceSetStillCarriesTheIcon(t *testing.T) {
	rs, err := windowsResources("v1.2.3")
	if err != nil {
		t.Fatalf("windowsResources: %v", err)
	}
	if rs.Get(winres.RT_GROUP_ICON, winres.ID(1), winres.LCIDNeutral) == nil {
		t.Error("no icon group with ID 1; Explorer draws the lowest-numbered one")
	}
}

// The copyright line in the .exe is read by people who never open the repository, so
// it has to say what LICENSE says.
func TestTheCopyrightLineMirrorsTheLicense(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test's own source path")
	}
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	if !strings.Contains(string(raw), legalCopyright) {
		t.Errorf("LICENSE does not carry the line the .exe claims: %q", legalCopyright)
	}
}

// versionStrings reads the en-US string table back out through the one export the
// package offers for it.
func versionStrings(t *testing.T, vi *version.Info) map[string]string {
	t.Helper()
	raw, err := json.Marshal(vi)
	if err != nil {
		t.Fatalf("marshal the version resource: %v", err)
	}
	var decoded struct {
		Info map[string]map[string]string `json:"info"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode the version resource: %v", err)
	}
	strs, ok := decoded.Info["0409"]
	if !ok {
		t.Fatalf("no en-US string table; tables present: %v", decoded.Info)
	}
	return strs
}
