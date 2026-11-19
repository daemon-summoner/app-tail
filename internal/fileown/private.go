// SPDX-License-Identifier: MIT

//go:build unix || windows

package fileown

import (
	"errors"
	"fmt"
	"os"
)

// NotPrivateError reports a file holding a secret that another account could have written
// or can read. Reason is the clause that follows the path, and Fix is the command that puts
// the file right when there is one.
type NotPrivateError struct {
	Path   string
	Reason string
	Fix    string
}

func (e *NotPrivateError) Error() string {
	if e.Fix == "" {
		return e.Path + " " + e.Reason
	}
	return fmt.Sprintf("%s %s; if the file is yours, run `%s` and try again", e.Path, e.Reason, e.Fix)
}

// OpenPrivate opens a file that holds a secret, for reading, and refuses one that is not
// private to this account with a *NotPrivateError.
//
// The link is refused at the open and everything else is read from the opened file -- not
// from the path, which could be swapped between a check and an open. A file that is not
// there comes back as the error os.Open gives, matching fs.ErrNotExist.
func OpenPrivate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		if isSymlinkRefusal(err) {
			return nil, &NotPrivateError{Path: path, Reason: "is a symbolic link"}
		}
		return nil, err
	}
	refuse := func(cause error) (*os.File, error) {
		return nil, errors.Join(cause, f.Close())
	}

	info, err := f.Stat()
	if err != nil {
		return refuse(err)
	}
	if !info.Mode().IsRegular() {
		return refuse(&NotPrivateError{Path: path, Reason: "is not a regular file"})
	}
	fault, err := privateFault(f, info, path)
	if err != nil {
		return refuse(fmt.Errorf("read who can reach %s: %w", path, err))
	}
	if fault != nil {
		return refuse(fault)
	}
	return f, nil
}
