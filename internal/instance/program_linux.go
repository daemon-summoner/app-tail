// SPDX-License-Identifier: MIT

package instance

import (
	"fmt"
	"os"
)

// runningProgram reports the program process pid is running, as the kernel names it.
func runningProgram(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
