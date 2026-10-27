// SPDX-License-Identifier: MIT

package buildinfo

import (
	"runtime/debug"
	"strings"
	"testing"
)

// stubBuildInfo returns a reader that reports the given VCS settings, standing in
// for the module stamps the toolchain records. It is an external boundary: nothing
// in a test binary can make the real debug.ReadBuildInfo report a tagged release.
func stubBuildInfo(mainVersion string, settings map[string]string) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		bi := &debug.BuildInfo{}
		bi.Main.Version = mainVersion
		for k, v := range settings {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
		}
		return bi, true
	}
}

// withLinkerStamps sets the -ldflags variables for one test and restores them, so a
// case that exercises the linked path cannot leak into the fallback cases.
func withLinkerStamps(t *testing.T, v, c, d string) {
	t.Helper()
	oldV, oldC, oldD := version, commit, date
	version, commit, date = v, c, d
	t.Cleanup(func() { version, commit, date = oldV, oldC, oldD })
}

// The whole point of the chain is that release builds report the tag the release
// was cut from, never a commit hash or "dev".
func TestLinkerStampsWinOverEverythingElse(t *testing.T) {
	withLinkerStamps(t, "v0.1.0", "abcdef1234567890", "2026-07-24T12:00:00Z")

	got := resolve(stubBuildInfo("v9.9.9", map[string]string{
		"vcs.revision": "0000000000000000",
		"vcs.time":     "1999-01-01T00:00:00Z",
	}))

	if got.Version != "v0.1.0" {
		t.Errorf("Version = %q, want the linked v0.1.0", got.Version)
	}
	if got.Commit != "abcdef1234567890" {
		t.Errorf("Commit = %q, want the linked commit", got.Commit)
	}
	if got.Date != "2026-07-24T12:00:00Z" {
		t.Errorf("Date = %q, want the linked date", got.Date)
	}
}

// `go install github.com/sellitus/app-tail@v0.1.0` links no stamps, so without this
// fallback the cheapest distribution channel would ship a binary reporting "dev".
func TestAGoInstalledBuildReportsItsModuleVersion(t *testing.T) {
	withLinkerStamps(t, "", "", "")

	got := resolve(stubBuildInfo("v0.1.0", nil))

	if got.Version != "v0.1.0" {
		t.Fatalf("Version = %q, want v0.1.0 from the module stamp", got.Version)
	}
}

// A plain `go build` in a git checkout records VCS stamps but no module version.
func TestAPlainBuildFallsBackToTheCommit(t *testing.T) {
	withLinkerStamps(t, "", "", "")

	got := resolve(stubBuildInfo("(devel)", map[string]string{
		"vcs.revision": "fedcba9876543210deadbeef",
		"vcs.time":     "2026-07-24T09:30:00Z",
		"vcs.modified": "false",
	}))

	if got.Version != "fedcba987654" {
		t.Errorf("Version = %q, want the short commit", got.Version)
	}
	if got.Date != "2026-07-24T09:30:00Z" {
		t.Errorf("Date = %q, want the commit time", got.Date)
	}
	if got.Dirty {
		t.Error("a clean tree was reported dirty")
	}
}

// A binary built from uncommitted changes must say so: a bug report citing a
// version that does not match that source wastes everyone's time.
func TestAnUncommittedTreeIsReportedDirty(t *testing.T) {
	withLinkerStamps(t, "", "", "")

	got := resolve(stubBuildInfo("(devel)", map[string]string{
		"vcs.revision": "fedcba9876543210",
		"vcs.modified": "true",
	}))

	if !got.Dirty {
		t.Fatal("a modified tree was not reported dirty")
	}
	if !strings.Contains(got.String(), "dirty") {
		t.Errorf("the rendered version hides the dirty tree: %q", got.String())
	}
}

// The linker path carries dirtiness in the version string, since -ldflags has no
// boolean to set. It must land in the same field a plain build uses.
func TestALinkedDirtySuffixSetsTheDirtyFlag(t *testing.T) {
	withLinkerStamps(t, "v0.1.0+dirty", "abcdef1234567890", "2026-07-24T12:00:00Z")

	got := resolve(stubBuildInfo("", nil))

	if !got.Dirty {
		t.Fatal("the +dirty suffix did not set Dirty")
	}
	if got.Version != "v0.1.0" {
		t.Errorf("Version = %q, want the suffix stripped", got.Version)
	}
}

// Every field must render something. A blank version in the dashboard header or a
// bug report is indistinguishable from a broken build.
func TestNothingResolvableStillReportsSomething(t *testing.T) {
	withLinkerStamps(t, "", "", "")

	got := resolve(func() (*debug.BuildInfo, bool) { return nil, false })

	if got.Version != Unknown || got.Commit != Unknown || got.Date != Unknown {
		t.Fatalf("unresolved build left a blank field: %+v", got)
	}
	if got.String() != Unknown {
		t.Errorf("String() = %q, want a bare %q with nothing to add", got.String(), Unknown)
	}
}

// The rendered string is what a user pastes into a bug report, so it has to carry
// the commit without repeating it when the version already is one.
func TestStringDoesNotRepeatTheCommit(t *testing.T) {
	withLinkerStamps(t, "", "", "")

	got := resolve(stubBuildInfo("(devel)", map[string]string{
		"vcs.revision": "fedcba9876543210",
		"vcs.time":     "2026-07-24T09:30:00Z",
	}))

	if n := strings.Count(got.String(), "fedcba987654"); n != 1 {
		t.Fatalf("commit appears %d times in %q, want 1", n, got.String())
	}
}

// The de-duplication above must not cost a tagged release its commit: "v0.1.0"
// names the tag but not which build of it, and that is the whole reason a bug
// report carries this string.
func TestStringCarriesTheCommitAlongsideATag(t *testing.T) {
	withLinkerStamps(t, "", "", "")

	got := resolve(stubBuildInfo("v0.1.0", map[string]string{
		"vcs.revision": "fedcba9876543210",
		"vcs.time":     "2026-07-24T09:30:00Z",
	}))

	rendered := got.String()
	if !strings.Contains(rendered, "v0.1.0") {
		t.Errorf("String() = %q, want the tag", rendered)
	}
	if !strings.Contains(rendered, "fedcba987654") {
		t.Errorf("String() = %q, want the short commit next to the tag", rendered)
	}
	if !strings.Contains(rendered, "2026-07-24T09:30:00Z") {
		t.Errorf("String() = %q, want the commit date", rendered)
	}
}

// Every other case here drives resolve with a stub. This one runs the real
// ReadBuildInfo the shipped binary uses, which is the only check that the wiring
// in Get -- and resolve's handling of a genuine BuildInfo -- produces a usable
// identity rather than three blanks.
func TestGetResolvesAnIdentityFromTheRealBuildInfo(t *testing.T) {
	got := Get()

	if got.Version == "" || got.Commit == "" || got.Date == "" {
		t.Fatalf("Get() left a field blank: %+v", got)
	}
	if got.String() == "" {
		t.Error("Get().String() is empty; the version command would print nothing")
	}
}

// The 12-character cut is what keeps `app-tail version` on one line and what the
// de-duplication in String compares against. Both boundaries matter: cutting a
// shorter commit would produce a prefix that matches the wrong revision in a bug
// report, and failing to cut a full 40-character hash would wrap the version line.
func TestTheCommitIsShortenedAtExactlyTwelveCharacters(t *testing.T) {
	tests := []struct {
		name   string
		commit string
		want   string
	}{
		{"a full git hash", "fedcba9876543210fedcba9876543210fedcba98", "fedcba987654"},
		{"exactly twelve is already short enough", "fedcba987654", "fedcba987654"},
		{"eleven is left whole", "fedcba98765", "fedcba98765"},
		{"thirteen loses its last character", "fedcba9876543", "fedcba987654"},
		{"the unknown sentinel is not a hash and must survive whole", Unknown, Unknown},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shortCommit(tt.commit); got != tt.want {
				t.Errorf("shortCommit(%q) = %q, want %q", tt.commit, got, tt.want)
			}
		})
	}
}

// An untagged build's version already is the short commit, and the de-duplication
// that stops it printing twice compares against exactly twelve characters. A commit
// one character either side of the cut has to render once, not twice and not zero
// times -- the string is what a user pastes into a bug report.
func TestAVersionThatIsTheShortCommitRendersItOnce(t *testing.T) {
	tests := []struct {
		name   string
		commit string
	}{
		{"a full hash", "fedcba9876543210fedcba9876543210fedcba98"},
		{"exactly twelve characters", "fedcba987654"},
		{"shorter than the cut", "fedcba98765"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withLinkerStamps(t, "", "", "")

			got := resolve(stubBuildInfo("(devel)", map[string]string{
				"vcs.revision": tt.commit,
				"vcs.time":     "2026-07-24T09:30:00Z",
			}))

			short := shortCommit(tt.commit)
			if got.Version != short {
				t.Fatalf("Version = %q, want the short commit %q", got.Version, short)
			}
			if n := strings.Count(got.String(), short); n != 1 {
				t.Errorf("the short commit appears %d times in %q, want 1", n, got.String())
			}
		})
	}
}
