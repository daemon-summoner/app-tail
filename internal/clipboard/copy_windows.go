// SPDX-License-Identifier: MIT

package clipboard

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// commands returns the clipboard writer for Windows. clip ships with the system, so there
// is nothing to fall back to and nothing that can be missing.
//
// Windows is asked for its own system directory rather than the program being resolved
// through PATH: app-tail runs elevated here whenever the network-interface mode is on, and
// PATH is partly the user's own to set, so a clip.exe planted ahead of the system
// directory would be started with administrator rights.
func commands() ([][]string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, fmt.Errorf("find this machine's system directory: %w", err)
	}
	return [][]string{{filepath.Join(dir, "clip.exe")}}, nil
}
