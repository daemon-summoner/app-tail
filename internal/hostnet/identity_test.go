// SPDX-License-Identifier: MIT

package hostnet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole reason this exists: two builds of one commit report the same version, so the
// version alone cannot tell a helper a rebuild left behind from the one this app speaks to.
// It holds root while reading a protocol that carries no compatibility rules.
func TestAHelperOfTheSameVersionRunningAnotherBinaryIsRefused(t *testing.T) {
	mine, err := BuildID()
	if err != nil {
		t.Fatalf("BuildID: %v", err)
	}

	err = expectedBuild(Capabilities{Version: Version, Build: "0000000000000000"})

	if !errors.Is(err, ErrHelperFromAnotherBuild) {
		t.Fatalf("a same-version helper running another binary = %v, want it refused as another build", err)
	}
	if strings.Contains(err.Error(), mine) {
		t.Error("the refusal carries this binary's hash, which says nothing a user can act on")
	}
}

// The field is the answer to the only question here, and a helper old enough to omit it is
// exactly the one this exists to catch: it predates the check, so it is not this build.
func TestAHelperThatSaysNothingAboutItsBinaryIsRefused(t *testing.T) {
	err := expectedBuild(Capabilities{Version: Version})

	if !errors.Is(err, ErrHelperFromAnotherBuild) {
		t.Fatalf("a helper that named no binary = %v, want it refused as another build", err)
	}
	if !strings.Contains(err.Error(), "did not say") {
		t.Errorf("the refusal said %q, which does not say what was missing", err)
	}
}

// The helper is a copy of this same binary, so the ordinary case is an exact match. A check
// that refused that would make every correctly installed machine unusable.
func TestTheHelperThisAppInstalledIsAccepted(t *testing.T) {
	mine, err := BuildID()
	if err != nil {
		t.Fatalf("BuildID: %v", err)
	}

	if err := expectedBuild(Capabilities{Version: Version, Build: mine}); err != nil {
		t.Errorf("a helper running this same binary = %v, want it accepted", err)
	}
}

// The version is checked first because it is the half a person can act on: it names both
// releases, where the hashes name neither.
func TestAHelperFromAnotherReleaseIsNamedByItsVersion(t *testing.T) {
	err := expectedBuild(Capabilities{Version: "v0.0.1-from-another-release", Build: "whatever"})

	if !errors.Is(err, ErrHelperFromAnotherBuild) {
		t.Fatalf("a helper from another release = %v, want it refused as another build", err)
	}
	if !strings.Contains(err.Error(), "v0.0.1-from-another-release") {
		t.Errorf("the refusal said %q, which does not name the version that is installed", err)
	}
}

// The identity is the contents of the file, so a byte that differs has to change it --
// otherwise a rebuilt helper of the same size would pass as the same program.
func TestTheIdentityFollowsTheBytes(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "one")
	second := filepath.Join(dir, "two")
	if err := os.WriteFile(first, []byte("the helper binary"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(second, []byte("the helper binarY"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	one, err := hashExecutable(func() (string, error) { return first, nil })
	if err != nil {
		t.Fatalf("hash the first: %v", err)
	}
	two, err := hashExecutable(func() (string, error) { return second, nil })
	if err != nil {
		t.Fatalf("hash the second: %v", err)
	}

	if one == two {
		t.Error("two binaries differing by one byte have the same identity")
	}
	// Against the hash of the contents, so the identity is what it claims to be rather
	// than a name, a size or a modification time that a copy would carry along.
	sum := sha256.Sum256([]byte("the helper binary"))
	if want := hex.EncodeToString(sum[:]); one != want {
		t.Errorf("the identity is %q, want the hash of the contents %q", one, want)
	}
}

// A binary that cannot be read is a helper that cannot be checked, and an unchecked helper
// is the one holding root. Both failures carry what the machine said.
func TestAnUnreadableBinaryIsReportedRatherThanPassedOver(t *testing.T) {
	tests := []struct {
		name   string
		locate func() (string, error)
		want   string
	}{
		{
			name:   "nowhere to look",
			locate: func() (string, error) { return "", errors.New("readlink /proc/self/exe: no such file") },
			want:   "no such file",
		},
		{
			name:   "nothing there to read",
			locate: func() (string, error) { return filepath.Join(t.TempDir(), "gone"), nil },
			want:   "read this program's own binary",
		},
		{
			// Opening it succeeds and reading it does not, which is the shape of every
			// failure that arrives partway through rather than at the door.
			name:   "something there that will not be read",
			locate: func() (string, error) { return t.TempDir(), nil },
			want:   "hash this program's own binary",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := hashExecutable(tc.locate)

			if err == nil {
				t.Fatalf("a binary that could not be read was identified as %q", id)
			}
			if id != "" {
				t.Errorf("a failed identification produced %q, which a caller could compare against", id)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the failure said %q, which does not carry %q", err, tc.want)
			}
		})
	}
}

// A side that cannot identify itself cannot check the other, and the one it would be
// checking holds root. Reporting the machine's own reason beats comparing against nothing.
func TestAnAppThatCannotIdentifyItselfRefusesRatherThanCompareNothing(t *testing.T) {
	err := checkAgainst(
		Capabilities{Version: Version, Build: "whatever the helper is running"},
		func() (string, error) { return "", errors.New("readlink /proc/self/exe: no such file") },
	)

	if err == nil {
		t.Fatal("a helper was accepted by an app that could not say which binary it is itself")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("the refusal said %q, which does not carry what the machine said", err)
	}
}

// The privileged side is what the helper answers from, so one that cannot say which binary
// it runs must refuse rather than answer with an empty field the client has to interpret.
func TestThePrivilegedSideNamesItsOwnBinary(t *testing.T) {
	caps, err := NewLocal(func(string, ...any) {}).Capabilities(t.Context())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}

	mine, err := BuildID()
	if err != nil {
		t.Fatalf("BuildID: %v", err)
	}
	if caps.Build != mine {
		t.Errorf("the privileged side reports binary %q, want this process's own %q", caps.Build, mine)
	}

	// A side that cannot identify itself answers with nothing rather than with a report
	// carrying an empty field, which the other side would have to interpret.
	broken, err := capabilities(t.Context(), func() (string, error) {
		return "", errors.New("readlink /proc/self/exe: no such file")
	}, "")
	if err == nil {
		t.Fatalf("a side that could not identify itself answered anyway with %+v", broken)
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("the failure said %q, which does not carry what the machine said", err)
	}
}

// A machine that installs no helper still has to say how its rights are obtained, and the
// two platforms with no install step obtain them in opposite ways. Naming the wrong one
// sends somebody to start a helper that does not exist there, or to restart an app that
// was never going to ask.
func TestAPlatformWithNoInstallStepSaysHowItsRightsAreObtained(t *testing.T) {
	withHelper := noInstallerReason(true)
	if !strings.Contains(withHelper, "tun helper") {
		t.Errorf("a platform whose helper is started by hand says %q, which does not name the command", withHelper)
	}

	withoutHelper := noInstallerReason(false)
	if strings.Contains(withoutHelper, "tun helper") {
		t.Errorf("a platform with no helper says %q, which sends somebody to start one", withoutHelper)
	}
	if !strings.Contains(withoutHelper, "start it again") {
		t.Errorf("a platform that elevates as it starts says %q, which does not say to start it again", withoutHelper)
	}
}
