// SPDX-License-Identifier: MIT

//go:build !windows

package fileowntest

import (
	"io/fs"
	"os"
	"testing"
)

// AssertOwnerOnly fails unless nobody but the file's owner can reach path. The permission
// bits are that answer here, and want is what they should read.
func AssertOwnerOnly(t testing.TB, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("read the permissions of %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want.Perm() {
		t.Errorf("%s is %04o, want %04o", path, got, want.Perm())
	}
}

// CloseDirectory stops this process from creating anything in dir, and opens it again when
// the test ends so its temporary directory can still be cleared. Root creates files
// regardless, so under root the case proves nothing and is skipped.
func CloseDirectory(t testing.TB, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("this case is about a place this process cannot write, and root can write everywhere")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("read the permissions of %s: %v", dir, err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("close %s to writing: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, info.Mode().Perm()); err != nil {
			t.Errorf("open %s to writing again: %v", dir, err)
		}
	})
}

// RequireCanHandToAdministrators skips a case that writes a file through
// fileown.RestrictToAdministrators. Ownership is not handed over here, so any account can.
func RequireCanHandToAdministrators(testing.TB) {}
