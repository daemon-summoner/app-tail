// SPDX-License-Identifier: MIT

//go:build windows

package apiauth

import (
	"fmt"
	"os"

	"github.com/sellitus/app-tail/internal/fileown"
)

// checkDir refuses a token directory another account owns or can put a file into, since
// whoever can write it can put a file of their own at the token's path. The mode bits say
// nothing here, so the answer is the directory's owner and its access list.
func checkDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("inspect the directory for the API token: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("the API token belongs in %s, which is not a directory", dir)
	}
	if err := fileown.PrivateDir(dir); err != nil {
		return fmt.Errorf("refusing to keep the API token there: %w", err)
	}
	return nil
}
