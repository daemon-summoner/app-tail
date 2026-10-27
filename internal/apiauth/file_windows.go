// SPDX-License-Identifier: MIT

//go:build windows

package apiauth

import (
	"fmt"
	"io/fs"
	"os"
)

// Windows has no O_NOFOLLOW. The token directory sits under the account's own profile,
// which other accounts cannot write, and the file carries an access list naming this
// account alone, written by fileown before the token is.
const openNoFollow = 0

func isSymlinkRefusal(error) bool { return false }

// untrustedFile has nothing to read from mode bits here: access is the access list
// fileown writes when the token is created.
func untrustedFile(fs.FileInfo) string { return "" }

func checkDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("inspect the directory for the API token: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("the API token belongs in %s, which is not a directory", dir)
	}
	return nil
}
