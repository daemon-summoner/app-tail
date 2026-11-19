// SPDX-License-Identifier: MIT

//go:build unix

package secretstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A credentials file other accounts can read is what a backup restored without its mode
// leaves behind. It is refused where it stands, with the command that puts it right: read
// as it is, every credential in it would be in use while anyone on the machine could copy it.
func TestCredentialsOtherAccountsCanReadAreRefusedWithTheRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Save(path, sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("loosen the file: %v", err)
	}

	got, err := Load(path)
	if err == nil {
		t.Fatalf("Load of a world-readable credentials file returned %d kinds, want a refusal", len(got))
	}
	for _, want := range []string{path, "other accounts", "chmod 600"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Load = %q, want it to mention %q", err, want)
		}
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("stat the file: %v", statErr)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("the file is now mode %#o; a refusal must leave it as it was found", info.Mode().Perm())
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("run the repair: %v", err)
	}
	if got, err := Load(path); err != nil || !Equal(got, sample()) {
		t.Errorf("Load after the repair = %v, want the saved credentials back", err)
	}
}

// A link at the file's path reads whatever another account pointed it at.
func TestALinkWhereTheCredentialsBelongIsRefused(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere.json")
	if err := Save(elsewhere, sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path := filepath.Join(dir, FileName)
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatalf("link the file: %v", err)
	}

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("Load through a link = %v, want a refusal naming the link", err)
	}
}
