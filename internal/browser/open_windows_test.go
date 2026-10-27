// SPDX-License-Identifier: MIT

package browser

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The launcher is started from a process that may hold administrator rights, so which
// program it is may not depend on PATH -- which the user's own environment contributes to.
func TestTheLauncherIsNamedByItsPathUnderTheSystemDirectory(t *testing.T) {
	name, args, err := platformCommand("https://login.tailscale.com/a/abc")
	if err != nil {
		t.Fatalf("platformCommand: %v", err)
	}

	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory: %v", err)
	}
	if !filepath.IsAbs(name) {
		t.Fatalf("launcher = %q, want an absolute path", name)
	}
	if !strings.EqualFold(filepath.Dir(name), filepath.Clean(system)) {
		t.Errorf("launcher = %q, want it under the system directory %q", name, system)
	}
	if !strings.EqualFold(filepath.Base(name), "rundll32.exe") {
		t.Errorf("launcher = %q, want rundll32.exe", name)
	}
	// The handler is what makes rundll32 open a URL at all; naming the program alone
	// would start it with no arguments and open nothing.
	if len(args) == 0 || args[0] != "url.dll,FileProtocolHandler" {
		t.Errorf("launcher args = %q, want the URL protocol handler first", args)
	}
}
