// SPDX-License-Identifier: MIT

//go:build !windows

package fileown

import (
	"errors"
	"os"
	"syscall"
)

// TryLock takes an exclusive lock on the whole file without blocking, reporting whether it
// got it. The lock goes when the process does, however it ends.
//
// flock rather than a POSIX record lock: a POSIX lock is dropped when any descriptor on the
// same file is closed anywhere in the process, which would make the lock depend on what
// unrelated code does with the same path.
func TryLock(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EWOULDBLOCK):
		return false, nil
	default:
		return false, err
	}
}

// Unlock drops the lock. Closing the file would do it too; doing it explicitly keeps the
// release from depending on the order two cleanups run in.
func Unlock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
