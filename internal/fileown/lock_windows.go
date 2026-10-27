// SPDX-License-Identifier: MIT

package fileown

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const (
	// lockRegionOffsetHigh puts the locked byte 4 GiB into the file, which no lock file ever
	// reaches. A Windows lock stops other processes reading the bytes it covers, and what a
	// lock file says about its holder lives at the start of the file.
	lockRegionOffsetHigh = 1
	// lockRegionBytes is how much of the file the lock covers: one byte is a lock, and
	// locking a range beyond the end of a file is allowed.
	lockRegionBytes = 1
)

// TryLock takes an exclusive lock on the file without blocking, reporting whether it got it.
// The lock goes when the process does, however it ends.
func TryLock(file *os.File) (bool, error) {
	overlapped := &windows.Overlapped{OffsetHigh: lockRegionOffsetHigh}
	err := windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, lockRegionBytes, 0, overlapped)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION), errors.Is(err, windows.ERROR_IO_PENDING):
		return false, nil
	default:
		return false, err
	}
}

// Unlock drops the lock.
func Unlock(file *os.File) error {
	overlapped := &windows.Overlapped{OffsetHigh: lockRegionOffsetHigh}
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, lockRegionBytes, 0, overlapped)
}
