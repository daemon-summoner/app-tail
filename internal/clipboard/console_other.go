// SPDX-License-Identifier: MIT

//go:build !windows

package clipboard

import "os/exec"

// hideConsole has nothing to do outside Windows: no clipboard program here owns a
// console window to begin with.
func hideConsole(*exec.Cmd) {}
