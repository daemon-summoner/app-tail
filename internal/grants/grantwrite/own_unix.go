// SPDX-License-Identifier: MIT

//go:build unix

package grantwrite

import "os"

// restrictDir hands the folder to root and closes it to everyone else's writes. A folder that
// already existed may have been made by another account, which could then replace the file.
func restrictDir(dir string) error {
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}
