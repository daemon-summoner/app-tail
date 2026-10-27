// SPDX-License-Identifier: MIT

package secretstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On Windows the access list can be taken over by any administrator, so the contents are
// sealed as well: the bytes on disk must not carry a credential in the clear.
func TestTheFileOnWindowsHoldsNoCredentialInTheClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Save(path, sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), sampleKey) || strings.Contains(string(raw), "secrets") {
		t.Error("the file holds its contents in the clear")
	}
}

// A sealed blob that was altered must be refused, not unsealed to something else.
func TestAnAlteredSealedFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Save(path, sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(path, raw, FileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("Load of an altered file = %v, want an error naming it", err)
	}
}
