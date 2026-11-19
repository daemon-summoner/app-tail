// SPDX-License-Identifier: MIT

//go:build unix

package fileown

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

const openNoFollow = syscall.O_NOFOLLOW

// isSymlinkRefusal reports the error O_NOFOLLOW gives for a symlink: ELOOP on Linux and
// macOS, EMLINK on the BSDs.
func isSymlinkRefusal(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}

// privateFault says why an opened file is not private, or nil when it is: it must belong
// to this account and grant nothing to the group or to anyone else.
func privateFault(_ *os.File, info fs.FileInfo, path string) (*NotPrivateError, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return &NotPrivateError{Path: path, Reason: "could not be checked for its owner"}, nil
	}
	if int(st.Uid) != os.Geteuid() {
		return &NotPrivateError{
			Path:   path,
			Reason: fmt.Sprintf("belongs to another account (uid %d)", st.Uid),
			Fix:    fmt.Sprintf("sudo chown %d %s", os.Geteuid(), shellQuote(path)),
		}, nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return &NotPrivateError{
			Path:   path,
			Reason: fmt.Sprintf("can be read by other accounts (mode %#o)", perm),
			Fix:    "chmod 600 " + shellQuote(path),
		}, nil
	}
	return nil, nil
}

// shellQuote writes path as one shell word, so a command naming it can be pasted as it is.
func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}
