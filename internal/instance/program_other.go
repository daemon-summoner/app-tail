// SPDX-License-Identifier: MIT

//go:build !windows && !linux && !darwin

package instance

import "errors"

// runningProgram cannot be answered here, so nothing is ended on the strength of a process id
// alone.
func runningProgram(int) (string, error) {
	return "", errors.New("this platform does not say which program a process is running")
}
