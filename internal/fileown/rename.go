// SPDX-License-Identifier: MIT

package fileown

import (
	"os"
	"time"
)

// replaceRetryBudget bounds how long a replace keeps trying past a transient refusal. Two
// seconds is what Go's own toolchain allows its build cache for the same reason.
const replaceRetryBudget = 2 * time.Second

// replace moves the temporary file over the record, trying again for a while when the
// platform refuses in a way that passes.
//
// On Windows an antivirus on-access scanner opens a file the moment it is written and
// holds it for the length of the scan, and a rename over a file somebody holds open is
// refused with ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION. The refusal lasts
// milliseconds; the write it stops is the record of what an elevated app-tail changed
// about this machine, without which nothing puts the machine back. Everywhere else a
// rename that fails stays failed, and the loop runs once.
func replace(oldpath, newpath string) error {
	return retryReplace(func() error { return os.Rename(oldpath, newpath) }, transientRenameError, time.Sleep)
}

// retryReplace is the loop itself, with the rename, the classifier and the clock passed in
// so a test can drive every branch on any platform: backoff doubles from a millisecond
// until the budget is spent, and the last refusal is what the caller gets.
func retryReplace(rename func() error, transient func(error) bool, sleep func(time.Duration)) error {
	var (
		spent time.Duration
		next  = time.Millisecond
	)
	for {
		err := rename()
		if err == nil || !transient(err) {
			return err
		}
		if spent+next > replaceRetryBudget {
			return err
		}
		sleep(next)
		spent += next
		next *= 2
	}
}
