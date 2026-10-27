// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"debug/pe"
	"errors"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/icon"
)

// iconutil refuses a directory that is missing any entry, so a generator that skips
// one fails the release rather than shipping a partial icon -- but it fails inside
// release.sh, after the binaries are built. Catching it here keeps that cheap.
func TestEveryFileIconutilRequiresIsWrittenAtItsDeclaredSize(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"iconset", dir}); err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, want := range icon.IconsetFiles() {
		path := filepath.Join(dir, IconsetName, want.Name)
		f, err := os.Open(path)
		if err != nil {
			t.Errorf("%s: %v", want.Name, err)
			continue
		}
		img, err := png.Decode(f)
		f.Close()
		if err != nil {
			t.Errorf("%s is not decodable PNG: %v", want.Name, err)
			continue
		}
		if b := img.Bounds(); b.Dx() != want.Px || b.Dy() != want.Px {
			t.Errorf("%s is %dx%d, want %dx%d", want.Name, b.Dx(), b.Dy(), want.Px, want.Px)
		}
	}
}

// The favicon is committed, so an edit to the pixel map that is not regenerated leaves
// the browser tab showing the previous mark indefinitely. Comparing the renderer to the
// checked-in file catches that here, without writing anything.
func TestTheCommittedFaviconMatchesThePixelMap(t *testing.T) {
	committed, err := os.ReadFile(committedFavicon(t))
	if err != nil {
		t.Fatalf("read the committed favicon: %v", err)
	}
	// CI runs windows-latest and the repo carries no .gitattributes, so git checks the
	// file out with CRLF there while the renderer always emits LF.
	got := normalizeEOL(icon.SVG())
	if want := normalizeEOL(committed); !bytes.Equal(got, want) {
		t.Errorf("ui/public/favicon.svg is stale; regenerate it with: go generate ./internal/icon")
	}
}

func normalizeEOL(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

// committedFavicon locates the checked-in file from this source file's own path, so the
// comparison holds whatever working directory the test is run from. It deliberately
// lives here rather than in the command: nothing in a test writes to it, which is what
// keeps the drift check honest -- a generator run from a test would repair the staleness
// it exists to report.
func committedFavicon(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test's own source path")
	}
	// self = <root>/internal/icon/gen/main_test.go
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	return filepath.Join(root, "ui", "public", "favicon.svg")
}

// The //go:generate directive names the favicon by a path relative to internal/icon,
// which is the directory go generate runs it from. A directive pointing anywhere else
// writes a file nobody serves while the drift check keeps passing.
func TestTheGenerateDirectiveNamesTheFileTheDriftCheckReads(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test's own source path")
	}
	pkgDir := filepath.Join(filepath.Dir(self), "..")

	src, err := os.ReadFile(filepath.Join(pkgDir, "icon.go"))
	if err != nil {
		t.Fatalf("read the package carrying the directive: %v", err)
	}
	const marker = "//go:generate go run ./gen favicon "
	i := bytes.Index(src, []byte(marker))
	if i < 0 {
		t.Fatalf("internal/icon/icon.go carries no %q directive", marker)
	}
	rest := src[i+len(marker):]
	arg := string(bytes.TrimSpace(rest[:bytes.IndexByte(rest, '\n')]))

	got, err := filepath.Abs(filepath.Join(pkgDir, arg))
	if err != nil {
		t.Fatalf("resolve %q against the package dir: %v", arg, err)
	}
	want, err := filepath.Abs(committedFavicon(t))
	if err != nil {
		t.Fatalf("resolve the committed favicon: %v", err)
	}
	if got != want {
		t.Errorf("go generate writes %s, but the drift check reads %s", got, want)
	}
}

// Regenerating has to actually replace the file. A writer that appended, or that wrote
// somewhere other than the path it was given, would leave the drift check above passing
// against a file the browser never loads.
func TestRegeneratingTheFaviconReplacesTheFileWithTheCurrentRender(t *testing.T) {
	path := filepath.Join(t.TempDir(), "favicon.svg")
	if err := os.WriteFile(path, []byte("<svg>stale</svg>"), 0o644); err != nil {
		t.Fatalf("seed a stale favicon: %v", err)
	}
	if err := run([]string{"favicon", path}); err != nil {
		t.Fatalf("run favicon: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, icon.SVG()) {
		t.Error("the regenerated favicon is not the current render")
	}
}

func TestAFaviconThatCannotBeWrittenIsReported(t *testing.T) {
	// A directory at the target path: creating a file cannot replace one.
	path := filepath.Join(t.TempDir(), "favicon.svg")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("seed the blocker: %v", err)
	}
	if err := writeFavicon(path); err == nil {
		t.Error("writeFavicon reported success despite writing nothing")
	}
}

// The directory name becomes the .icns stem, which Info.plist names. A rename here
// with no matching plist change leaves the bundle showing the generic app icon.
func TestTheIconsetDirectoryIsNamedForTheBundleIcon(t *testing.T) {
	if !strings.HasSuffix(IconsetName, ".iconset") {
		t.Errorf("IconsetName = %q, which iconutil will not accept", IconsetName)
	}
	if got := strings.TrimSuffix(IconsetName, ".iconset"); got != "App-Tail" {
		t.Errorf("icns stem = %q, want App-Tail to match CFBundleIconFile in release.sh", got)
	}
}

// go build links a .syso only when its machine type matches the target it is building.
// An object written for the wrong architecture is skipped in silence, so the .exe would
// ship with the generic Windows icon and no failed step anywhere to point at.
func TestTheWindowsResourceObjectTargetsTheArchitectureTheReleaseBuilds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rsrc_windows_amd64.syso")
	if err := run([]string{"syso", path, "v1.2.3"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	obj, err := pe.Open(path)
	if err != nil {
		t.Fatalf("the object is not a readable COFF file: %v", err)
	}
	defer obj.Close()

	if obj.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("machine = %#x, want %#x (amd64), which is the only arch release.sh builds",
			obj.Machine, pe.IMAGE_FILE_MACHINE_AMD64)
	}
	// Windows loads icons from .rsrc; an object carrying the bytes in any other section
	// links cleanly and shows nothing.
	if obj.Section(".rsrc") == nil {
		var names []string
		for _, s := range obj.Sections {
			names = append(names, s.Name)
		}
		t.Errorf("no .rsrc section; the object carries %v", names)
	}
}

// Without the argument check, a bare invocation indexes an empty slice and panics.
// release.sh reads the exit status, and a panic is indistinguishable from a real
// failure only until someone has to debug it.
func TestAMissingOutputDirectoryIsAnErrorRatherThanAPanic(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"iconset"}, {"iconset", "a", "b"}, {"favicon"}, {"favicon", "a", "b"}, {"syso"}, {"syso", "a"}, {"syso", "a", "b", "c"}, {"syso", "a", ""}, {"nonsense"}} {
		if err := run(args); err == nil {
			t.Errorf("run(%v) accepted arguments it cannot act on", args)
		}
	}
}

// Every size the release embeds has to fit the ICO format. A size past 256 is rejected
// by the encoder, and swallowing that would ship an .exe whose icon Explorer has to
// scale from a neighbouring size -- the blurring that picking whole-number sizes avoids.
func TestASizeTheICOFormatCannotCarryIsReported(t *testing.T) {
	for _, sizes := range [][]int{{512}, {2048}, {16, 512}} {
		if _, err := buildIcon(sizes); err == nil {
			t.Errorf("buildIcon(%v) accepted a size the ICO format cannot hold", sizes)
		}
	}
	if _, err := buildIcon(icon.WindowsIconSizes()); err != nil {
		t.Errorf("the sizes the release ships are rejected: %v", err)
	}
}

// A write that fails partway leaves a truncated file behind. Reporting success would
// have release.sh link that object into the .exe, or serve that SVG as the favicon --
// both of which fail silently, visible only to whoever looks at the shipped artifact.
func TestAFailedWriteIsReportedRatherThanLeavingATruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rsrc_windows_amd64.syso")
	sentinel := errors.New("the volume went away mid-write")

	err := writeFile(path, func(w io.Writer) error {
		if _, err := w.Write([]byte("the first half")); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("writeFile error = %v, want it to wrap %v", err, sentinel)
	}
	// The generator writes several files per release run; an error naming none of them
	// leaves whoever reads the failure guessing which one it was.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file that failed: %v", err)
	}
}

// A PNG that cannot be written has to reach the caller. iconutil refuses an incomplete
// directory, so a swallowed write failure turns into a confusing release failure one
// step later, pointing at iconutil rather than at the file that never landed.
func TestAnIconsetEntryThatCannotBeWrittenIsReported(t *testing.T) {
	parent := t.TempDir()
	// A directory where the first PNG must go: WriteFile cannot replace one, and
	// MkdirAll is happy to find the iconset directory already present.
	blocked := filepath.Join(parent, IconsetName, icon.IconsetFiles()[0].Name)
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatalf("seed the blocker: %v", err)
	}
	if err := run([]string{"iconset", parent}); err == nil {
		t.Error("run reported success despite being unable to write an iconset entry")
	}
}

// An unwritable target has to reach the caller: a release that silently produced no
// iconset would ship a bundle with no icon and no failed step to point at.
func TestAnUnwritableTargetFailsLoudly(t *testing.T) {
	// A regular file where the iconset directory must go: MkdirAll cannot replace it.
	dir := t.TempDir()
	blocker := filepath.Join(dir, IconsetName)
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("seed the blocker: %v", err)
	}
	if err := run([]string{"iconset", dir}); err == nil {
		t.Error("run reported success despite being unable to create the iconset directory")
	}
}
