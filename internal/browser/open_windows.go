// SPDX-License-Identifier: MIT

package browser

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// platformCommand returns the launcher for Windows. rundll32 takes the URL as a single
// argument, which sidesteps the `cmd /c start` quoting rules that mangle URLs
// containing an ampersand -- exactly what a Tailscale login URL contains.
//
// It is named by its full path under the system directory, because a bare name is
// resolved through PATH and through the working directory. app-tail runs elevated on
// this platform whenever the network-interface mode is on, and PATH is partly what the
// user's own environment says it is, so a program planted ahead of the system directory
// would be started with administrator rights.
func platformCommand(rawURL string) (string, []string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", nil, fmt.Errorf("find this machine's system directory: %w", err)
	}
	return filepath.Join(dir, "rundll32.exe"), []string{"url.dll,FileProtocolHandler", rawURL}, nil
}
