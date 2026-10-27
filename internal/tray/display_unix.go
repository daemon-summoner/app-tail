// SPDX-License-Identifier: MIT

//go:build !darwin && !windows && !notray

package tray

import "os"

// hasDisplay reports whether this session can show a tray icon. On Linux and the
// other Unixes a tray needs a running X or Wayland session; a server or an SSH shell
// has neither, which is exactly the case that must fall back to headless.
func hasDisplay() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
