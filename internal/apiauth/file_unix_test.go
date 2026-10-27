// SPDX-License-Identifier: MIT

//go:build unix

package apiauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestATokenFileOthersCanReadIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, TokenFileName)
	leaked := "atk1_" + strings.Repeat("A", 43)
	if err := os.WriteFile(path, []byte(leaked+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Set after the write so the umask cannot narrow it back.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	k, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if k.CheckBearer(leaked) {
		t.Error("a token other accounts could read is still accepted")
	}
	if !strings.Contains(k.Replaced(), "other accounts") {
		t.Errorf("Replaced() = %q, want it to say other accounts could read the file", k.Replaced())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the replacement token file has mode %#o, want 0600", perm)
	}
}

func TestReadRefusesATokenFileOthersCanRead(t *testing.T) {
	_, _, dir := newTestKeys(t)
	if err := os.Chmod(filepath.Join(dir, TokenFileName), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), "other accounts") {
		t.Errorf("Read of a group-readable token = %v, want a refusal naming other accounts", err)
	}
}

func TestASymlinkedTokenFileIsNeitherReadNorTrusted(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "planted")
	planted := "atk1_" + strings.Repeat("B", 43)
	if err := os.WriteFile(elsewhere, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, TokenFileName)); err != nil {
		t.Fatal(err)
	}

	if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("Read through a symlink = %v, want a refusal naming the link", err)
	}
	k, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if k.CheckBearer(planted) {
		t.Error("the token behind a planted symlink was accepted")
	}
	if got, err := os.ReadFile(elsewhere); err != nil || string(got) != planted {
		t.Errorf("replacing the link wrote through it to its target: %q, %v", got, err)
	}
}

func TestADirectoryOthersCanWriteRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil || !strings.Contains(err.Error(), "other accounts can write") {
		t.Errorf("LoadOrCreate in a world-writable directory = %v, want a refusal", err)
	}
	if _, err := Read(dir); err == nil {
		t.Error("Read trusted a token in a world-writable directory")
	}
}
