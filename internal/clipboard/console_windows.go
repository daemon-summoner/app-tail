// SPDX-License-Identifier: MIT

package clipboard

import (
	"os/exec"
	"syscall"
)

// hideConsole keeps clip from flashing a console window. app-tail runs as a menu-bar
// application, and a window appearing for the length of a copy is the whole visible
// effect of one.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
