// SPDX-License-Identifier: MIT

package licenses

import (
	"strings"
	"testing"
)

// A //go:embed of a file that exists but is empty compiles fine and ships a binary
// whose `licenses` command prints nothing. That is the failure this catches: the
// notices are a distribution obligation, so an empty one is worse than a build error.
func TestTheEmbeddedNoticesAreNotEmpty(t *testing.T) {
	got := ThirdParty()
	if len(got) < 1000 {
		t.Fatalf("ThirdParty() is %d bytes; the embedded notices did not survive the build", len(got))
	}
}

// scripts/licenses.sh writes a header per module and the license text under it. If
// its output format changes, every consumer that greps this file breaks silently.
func TestTheNoticesNameModulesAndCarryLicenseText(t *testing.T) {
	got := ThirdParty()

	// tailscale.com is the reason this project exists; it can never drop out of the
	// dependency graph, so its absence means the file was generated wrong.
	if !strings.Contains(got, "tailscale.com") {
		t.Error("the notices name no tailscale.com module")
	}
	// A list of module names without the license bodies would satisfy nobody's
	// license terms, and is exactly what a truncated generator run produces.
	if !strings.Contains(got, "--- LICENSE ---") {
		t.Error("the notices carry module names but no license text")
	}
	if !strings.Contains(got, "Regenerate with scripts/licenses.sh") {
		t.Error("the notices are missing the header that says how to regenerate them")
	}
}

// The dashboard bundle is embedded in the same binary, and its typefaces are under a
// licence that requires its text to travel with every copy of the fonts. The Go module
// walk cannot see them, so the bundle's own notices have to be appended, in full.
func TestTheNoticesCarryTheDashboardBundlesLicences(t *testing.T) {
	got := ThirdParty()

	if !strings.Contains(got, "dashboard bundle (ui/dist)") {
		t.Fatal("the notices carry no section for the dashboard bundle")
	}
	for _, want := range []string{
		"SIL OPEN FONT LICENSE Version 1.1",
		"The Inter Project Authors",
		"The JetBrains Mono Project Authors",
		"qrcode.react",
		"lucide-react",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the notices do not carry %q, which the embedded dashboard ships", want)
		}
	}
}

// Callers print this straight to a terminal. Without the trailing newline the shell
// prompt lands on the last line of a license.
func TestTheNoticesEndWithExactlyOneNewline(t *testing.T) {
	got := ThirdParty()
	if !strings.HasSuffix(got, "\n") {
		t.Fatal("ThirdParty() is not newline-terminated")
	}
	if strings.HasSuffix(got, "\n\n") {
		t.Error("ThirdParty() ends with a blank line; it appends a newline to text that already had one")
	}
}

// Filename is what release.sh and the .app bundle name the copied-out file. A
// mismatch would ship notices under a name nothing looks for.
func TestFilenameMatchesTheGeneratedFile(t *testing.T) {
	if Filename != "THIRD_PARTY_LICENSES.txt" {
		t.Errorf("Filename = %q, but scripts/licenses.sh writes THIRD_PARTY_LICENSES.txt", Filename)
	}
}

// The Wintun notice is the one file here that may not be reformatted: its own terms
// forbid altering it, and release.sh compares this copy byte for byte against the
// archive the shipped DLL came out of. A stray editor normalizing the line endings
// would break the release with a diff nobody could explain from the Go source.
func TestTheWintunNoticeIsStoredExactlyAsItsVendorShipsIt(t *testing.T) {
	got := Wintun()

	if !strings.Contains(got, "Prebuilt Binaries License") {
		t.Error("the stored file is not the Wintun prebuilt-binaries licence")
	}
	if !strings.Contains(got, "\r\n") {
		t.Error("the stored notice has had its carriage returns stripped; it no longer matches the vendor archive")
	}
	if strings.Contains(strings.ReplaceAll(got, "\r\n", ""), "\n") {
		t.Error("the stored notice mixes line endings; it no longer matches the vendor archive byte for byte")
	}
}

// The notice ships beside a file the reader can see, so it has to say what that file is
// and why it is not like everything else in the notices -- it is not open source and is
// not linked into this binary.
func TestTheWintunNoticeSaysWhatItCovers(t *testing.T) {
	got := WintunNotice()

	if !strings.Contains(got, WintunVersion) {
		t.Errorf("the notice does not name the version it was taken from (%s); the terms cover one download", WintunVersion)
	}
	if !strings.Contains(got, "wintun.dll") {
		t.Error("the notice does not name the file it covers")
	}
	if !strings.Contains(got, "Prebuilt Binaries License") {
		t.Error("the notice carries a preamble but not the licence text under it")
	}
	// Printed straight to a terminal, where a carriage return per line is visible in
	// some pagers and in every scrollback that does not fold it.
	if strings.Contains(got, "\r") {
		t.Error("the printed notice carries the vendor's carriage returns into the terminal")
	}
	if !strings.HasSuffix(got, "\n") || strings.HasSuffix(got, "\n\n") {
		t.Error("the printed notice does not end with exactly one newline")
	}
}

// WintunFilename is what release.sh writes beside the Windows binaries. The notice has
// to travel with the file it covers, so a name nothing writes is a licence breach rather
// than a cosmetic mismatch.
func TestTheWintunNoticeIsNamedWhatTheReleaseWrites(t *testing.T) {
	if WintunFilename != "WINTUN-LICENSE.txt" {
		t.Errorf("WintunFilename = %q, but release.sh writes WINTUN-LICENSE.txt beside app-tail.exe", WintunFilename)
	}
}
