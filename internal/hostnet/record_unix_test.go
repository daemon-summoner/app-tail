// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

// requireRecordWriter skips a case that writes the record of what app-tail installed. Any
// account can write one into a temporary directory here, so there is nothing to skip for.
func requireRecordWriter(*testing.T) {}

// closeDirectory stops this process from writing in dir until the test ends.
func closeDirectory(t *testing.T, dir string) {
	t.Helper()
	fileowntest.CloseDirectory(t, dir)
}

// sealRecord stops the record at path from being replaced or removed: the directory is closed,
// which is what both need, and a record already there is closed as well so that writing over
// it needs nothing the directory could still give.
func sealRecord(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatalf("close the record to writing: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, stateFileMode) })
	}
	closeDirectory(t, filepath.Dir(path))
}

// pinConfiguration stops a connection's configuration directory from being removed. Removing
// a directory is a write to the one above it, so that is the one closed.
func pinConfiguration(t *testing.T, dir, _ string) {
	t.Helper()
	closeDirectory(t, filepath.Dir(dir))
}

// unmakeableRootState is a record whose directory cannot be made: the one above it is closed.
func unmakeableRootState(t *testing.T) *rootState {
	t.Helper()
	closed := filepath.Join(t.TempDir(), "closed")
	if err := os.Mkdir(closed, stateDirMode); err != nil {
		t.Fatalf("make the directory to close: %v", err)
	}
	closeDirectory(t, closed)
	return newRootState(filepath.Join(closed, "deeper", rootStateFileName), nil)
}

// assertRecordNarrowed fails unless the record and the directory holding it are writable by
// root alone, which the mode bits say here.
func assertRecordNarrowed(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("read the record that was just written: %v", err)
	}
	if mode := info.Mode().Perm(); mode != stateFileMode {
		t.Errorf("the record is mode %#o, want %#o -- readable and writable by root alone", mode, stateFileMode)
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read the directory holding the record: %v", err)
	}
	if mode := dir.Mode().Perm(); mode&0o022 != 0 {
		t.Errorf("the directory holding the record is mode %#o, which another account can write to", mode)
	}
}
