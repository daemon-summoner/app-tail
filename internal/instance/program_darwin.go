// SPDX-License-Identifier: MIT

package instance

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

// runningProgram reports the program process pid is running, as the kernel recorded it when
// the process started. The kernel answers only for this account's processes, which are the
// only ones this account could end.
func runningProgram(pid int) (string, error) {
	// The record is the argument count, then the program's path, then the arguments.
	const countBytes = 4
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(raw) <= countBytes {
		return "", errors.New("the kernel reported no program path")
	}
	path, _, _ := bytes.Cut(raw[countBytes:], []byte{0})
	return string(path), nil
}
