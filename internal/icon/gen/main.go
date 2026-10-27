// SPDX-License-Identifier: MIT

// Command gen emits the rendered projections of the pixel map in internal/icon, so the
// bundle icon, the dashboard favicon and the tray icon cannot drift from each other.
//
// Usage:
//
//	go run ./internal/icon/gen iconset <dir>    writes <dir>/App-Tail.iconset for iconutil
//	go run ./internal/icon/gen syso <file> <version>   writes the Windows PE resource object
//	go run ./internal/icon/gen favicon <file>          writes the dashboard favicon
//
// The syso form carries the version block and the application manifest along with the
// icon; the version string is the one scripts/version.sh resolved.
//
// release.sh runs the iconset and syso forms. The favicon form is the //go:generate
// directive in internal/icon; main_test.go compares SVG() against the checked-in file
// on every test run, so a stale favicon fails the suite rather than waiting to be
// noticed in a browser tab.
package main

import (
	"errors"
	"fmt"
	"image"
	"io"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"

	"github.com/sellitus/app-tail/internal/icon"
)

// IconsetName is the directory iconutil is pointed at. Its stem becomes the .icns
// filename, which Info.plist names in CFBundleIconFile.
const IconsetName = "App-Tail.iconset"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 2 && args[0] == "iconset":
		return writeIconset(args[1])
	case len(args) == 3 && args[0] == "syso":
		return writeSyso(args[1], args[2])
	case len(args) == 2 && args[0] == "favicon":
		return writeFavicon(args[1])
	default:
		return fmt.Errorf("usage: gen iconset <dir> | gen syso <file> <version> | gen favicon <file>")
	}
}

// buildIcon renders each size into the multi-resolution icon Windows picks from.
// A size the ICO format cannot carry -- anything past 256 -- has to reach the caller:
// a resource silently short of a size makes Explorer scale a neighbouring one, which
// on pixel art is the blurred result the whole-number sizes exist to avoid.
func buildIcon(sizes []int) (*winres.Icon, error) {
	images := make([]image.Image, 0, len(sizes))
	for _, px := range sizes {
		images = append(images, icon.AppIcon(px))
	}
	ico, err := winres.NewIconFromImages(images)
	if err != nil {
		return nil, fmt.Errorf("build the windows icon: %w", err)
	}
	return ico, nil
}

// writeFile creates path and hands it to write. A failed close joins the result:
// close is where a buffered flush fails, and the half-written file it leaves behind
// is one the tools downstream accept and then draw nothing from.
func writeFile(path string, write func(io.Writer) error) (err error) {
	// The mode is explicit rather than os.Create's 0666-minus-umask: the favicon is
	// committed, so its permissions should not depend on the shell that generated it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	if err := write(f); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeSyso emits the COFF object holding the application icon, the version block and
// the manifest. `go build` links any .syso in the main package's directory into the
// executable's resource section, which is the only way to give a Windows .exe any of
// them -- there is no linker flag for resources.
func writeSyso(path, ver string) error {
	if ver == "" {
		return errors.New("the version string is empty; the build scripts pass APPTAIL_VERSION")
	}
	rs, err := windowsResources(ver)
	if err != nil {
		return err
	}
	return writeFile(path, func(w io.Writer) error {
		return rs.WriteObject(w, winres.ArchAMD64)
	})
}

// writeIconset renders every size iconutil needs and prints the directory, which is
// what release.sh captures to pass on to iconutil.
func writeIconset(parent string) error {
	dir := filepath.Join(parent, IconsetName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create iconset dir: %w", err)
	}
	for _, f := range icon.IconsetFiles() {
		path := filepath.Join(dir, f.Name)
		if err := os.WriteFile(path, icon.AppIconPNG(f.Px), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	fmt.Println(dir)
	return nil
}

func writeFavicon(path string) error {
	return writeFile(path, func(w io.Writer) error {
		_, err := w.Write(icon.SVG())
		return err
	})
}
