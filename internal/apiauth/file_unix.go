// SPDX-License-Identifier: MIT

//go:build unix

package apiauth

import (
	"fmt"
	"os"
	"syscall"
)

// checkDir refuses a token directory another account owns or can write, since whoever can
// write it can put a file of their own at the token's path.
func checkDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("inspect the directory for the API token: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("the API token belongs in %s, which is not a directory", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not read the owner of %s", dir)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing to keep the API token in %s: it belongs to uid %d, not to this account (uid %d)",
			dir, st.Uid, os.Geteuid())
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("refusing to keep the API token in %s: other accounts can write to it (mode %#o); "+
			"run `chmod go-w %s` and start again", dir, perm, dir)
	}
	return nil
}
