// SPDX-License-Identifier: MIT

package hostnet

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown"
	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

// requireRecordWriter skips a case that writes the record of what app-tail installed: the
// record is handed to the administrators group as it is written.
func requireRecordWriter(t *testing.T) {
	t.Helper()
	fileowntest.RequireCanHandToAdministrators(t)
}

// holdOpen keeps path open until the test ends. A file another handle holds without sharing
// its deletion can be read but neither replaced nor removed, which is the refusal a
// read-only directory gives elsewhere. Go opens files sharing reads and writes only.
func holdOpen(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("hold %s open: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
}

// sealRecord stops the record at path from being replaced or removed. The directory's own
// access list is rewritten by every write of the record, so it is the record that is held,
// and one that is not there yet is put there empty so there is something to hold.
func sealRecord(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, []byte("{}\r\n"), stateFileMode); err != nil {
			t.Fatalf("write an empty record: %v", err)
		}
	}
	holdOpen(t, path)
}

// pinConfiguration stops a connection's configuration directory from being removed by
// holding the configuration inside it open: a directory whose contents cannot go cannot go.
func pinConfiguration(t *testing.T, _, config string) {
	t.Helper()
	holdOpen(t, config)
}

// unmakeableRootState is a record whose directory cannot be made: a file stands where it
// would go. Reading under a file reports no record here, so the first thing that fails is
// making the directory.
func unmakeableRootState(t *testing.T) *rootState {
	t.Helper()
	blocked := filepath.Join(t.TempDir(), "in-the-way")
	if err := os.WriteFile(blocked, []byte("not a directory\r\n"), stateFileMode); err != nil {
		t.Fatalf("write the file standing where the directory would go: %v", err)
	}
	return newRootState(filepath.Join(blocked, rootStateFileName), nil)
}

// assertRecordNarrowed fails unless the record belongs to the administrators group, which is
// what the next elevated run checks before acting on it, and what an account that could
// have written its own record in the same place cannot arrange.
func assertRecordNarrowed(t *testing.T, path string) {
	t.Helper()
	owned, owner, err := fileown.OwnedByAdministrators(path)
	if err != nil {
		t.Fatalf("read who owns the record that was just written: %v", err)
	}
	if !owned {
		t.Errorf("the record belongs to %s, want the administrators group so that the next elevated run acts on it", owner)
	}
}
