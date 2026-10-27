// SPDX-License-Identifier: MIT

package clipboard

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// app-tail runs elevated on this platform whenever the network-interface mode is on, and a
// bare program name is resolved through a PATH the user's own environment contributes to.
// A clip.exe planted ahead of the system directory would then be started with
// administrator rights, so the program has to be named by its full path.
func TestTheClipboardProgramIsNamedByItsPathUnderTheSystemDirectory(t *testing.T) {
	candidates, err := commands()
	if err != nil {
		t.Fatalf("commands: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("commands() = %q, want the one program that ships with Windows", candidates)
	}
	program := candidates[0][0]

	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory: %v", err)
	}
	if !filepath.IsAbs(program) {
		t.Fatalf("clipboard program = %q, want an absolute path", program)
	}
	if !strings.EqualFold(filepath.Dir(program), filepath.Clean(system)) {
		t.Errorf("clipboard program = %q, want it under the system directory %q", program, system)
	}
	if !strings.EqualFold(filepath.Base(program), "clip.exe") {
		t.Errorf("clipboard program = %q, want clip.exe", program)
	}
}
