// SPDX-License-Identifier: MIT

package grants

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Path is where this machine keeps its approvals: under ProgramData, asked of Windows rather
// than read from %ProgramData%, which a standard account can set for itself.
func Path() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT_PATH)
	if err != nil {
		return "", fmt.Errorf("find the ProgramData folder: %w", err)
	}
	return filepath.Join(dir, "app-tail", "grants.json"), nil
}
