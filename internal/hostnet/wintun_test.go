// SPDX-License-Identifier: MIT

package hostnet

import (
	"strings"
	"testing"
)

// A wintun.dll that is not byte-for-byte the release this build ships is refused before it
// is loaded: the process loading it holds administrator rights, and whatever is in that file
// runs with them the moment it is mapped.
func TestAWintunDLLThatDoesNotMatchThePinIsNotLoaded(t *testing.T) {
	planted := strings.Repeat("0", 64)
	err := CheckWintunPin("amd64", planted)
	if err == nil {
		t.Fatal("a wintun.dll with a hash nobody pinned was accepted, so it would be loaded with administrator rights")
	}
	for _, want := range []string{wintunSHA256["amd64"], planted, "app-tail install"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not name %q; it has to say what was expected, what was found and what fixes it", err, want)
		}
	}
}

func TestTheWintunDLLFromThePinnedReleaseIsLoaded(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "386"} {
		sum, pinned := wintunSHA256[arch]
		if !pinned {
			t.Errorf("there is no pin for %s, so a Windows build for it could never load wintun", arch)
			continue
		}
		if err := CheckWintunPin(arch, sum); err != nil {
			t.Errorf("the pinned DLL for %s was refused: %v", arch, err)
		}
		// Hash tools differ in case, and refusing the right file over that would turn the
		// interface mode off on a machine with nothing wrong with it.
		if err := CheckWintunPin(arch, strings.ToUpper(sum)); err != nil {
			t.Errorf("the pinned DLL for %s was refused when its hash arrived in upper case: %v", arch, err)
		}
	}
}

// Another architecture's DLL is a different file, and loading it would fail anyway; what
// matters is that the pin for one architecture never vouches for a file meant for another.
func TestAWintunDLLPinnedForAnotherArchitectureIsRefused(t *testing.T) {
	if err := CheckWintunPin("amd64", wintunSHA256["arm64"]); err == nil {
		t.Error("the arm64 DLL was accepted as the amd64 one")
	}
}

func TestAnArchitectureWithNoPinLoadsNothing(t *testing.T) {
	err := CheckWintunPin("mips", wintunSHA256["amd64"])
	if err == nil {
		t.Fatal("an architecture with no pinned wintun.dll accepted one, so the pin vouched for a file it never saw")
	}
	if !strings.Contains(err.Error(), "mips") {
		t.Errorf("the refusal %q does not name the architecture it has no pin for", err)
	}
}

// Every pin is a SHA-256 written out in full, so a value cut short by an edit cannot match
// some other file by being a prefix of its hash.
func TestEveryWintunPinIsAWholeSHA256(t *testing.T) {
	for arch, sum := range wintunSHA256 {
		if len(sum) != 64 || strings.Trim(sum, "0123456789abcdef") != "" {
			t.Errorf("the %s pin %q is not 64 lower-case hex digits", arch, sum)
		}
	}
}
