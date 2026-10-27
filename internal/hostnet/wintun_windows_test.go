// SPDX-License-Identifier: MIT

package hostnet

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A file at the DLL's path that is not the pinned release never reaches LoadLibraryEx: the
// refusal names both hashes, and no module comes back for the binding to use.
func TestAReplacedWintunDLLIsRefusedBeforeItIsLoaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), wintunDLL)
	if err := os.WriteFile(path, []byte("not the pinned release"), 0o644); err != nil {
		t.Fatalf("stage a replaced %s: %v", wintunDLL, err)
	}

	module, err := loadVerifiedWintun(path, runtime.GOARCH)
	if err == nil {
		t.Fatal("a wintun.dll that does not match the pin was loaded")
	}
	if module != 0 {
		t.Errorf("a refused wintun.dll still returned module %#x", module)
	}
	if !strings.Contains(err.Error(), wintunSHA256[runtime.GOARCH]) {
		t.Errorf("the refusal %q does not name the hash it expected", err)
	}
}

// The check and the load are about the same bytes only if nothing can change the file in
// between, so the handle the hash is read through has to keep every writer out.
func TestTheWintunDLLCannotBeRewrittenWhileItIsBeingChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), wintunDLL)
	if err := os.WriteFile(path, []byte("contents"), 0o644); err != nil {
		t.Fatalf("stage %s: %v", wintunDLL, err)
	}
	held, err := openWintunForPinning(path)
	if err != nil {
		t.Fatalf("open %s for the check: %v", path, err)
	}
	defer func() {
		if err := held.Close(); err != nil {
			t.Errorf("close the held %s: %v", path, err)
		}
	}()

	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		writer.Close()
		t.Error("the file could be opened for writing while it was being checked, so it could change before the load")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Error("the file could be renamed away while it was being checked, so another could take its place")
	}
}
