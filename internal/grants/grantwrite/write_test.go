// SPDX-License-Identifier: MIT

package grantwrite

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sellitus/app-tail/internal/grants"
)

func withOwnDir(t *testing.T, seam func(string) error) {
	t.Helper()
	saved := ownDir
	ownDir = seam
	t.Cleanup(func() { ownDir = saved })
}

func TestWrittenApprovalsReadBackAndEveryoneCanReadThem(t *testing.T) {
	var owned []string
	withOwnDir(t, func(dir string) error { owned = append(owned, dir); return nil })
	path := filepath.Join(t.TempDir(), "app-tail", "grants.json")
	doc := grants.Document{FullTunnel: true, Routes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	if err := Write(path, doc); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(owned) != 1 || owned[0] != filepath.Dir(path) {
		t.Fatalf("the folder handed to root was %v", owned)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := grants.Parse(data)
	if err != nil {
		t.Fatalf("parse what was written: %v", err)
	}
	if !got.FullTunnel || len(got.Routes) != 1 {
		t.Fatalf("read back %+v", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("mode %#o, want 0644", info.Mode().Perm())
		}
	}
}

func TestApprovalsAreNotWrittenWhenTheFolderCannotBeMadeRootsAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	withOwnDir(t, func(string) error { return nil })
	if err := Write(path, grants.Document{SystemDNS: true}); err != nil {
		t.Fatal(err)
	}
	withOwnDir(t, func(string) error { return fs.ErrPermission })
	err := Write(path, grants.Document{FullTunnel: true})
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("got %v, want the folder's refusal", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := grants.Parse(data)
	if err != nil || got.FullTunnel || !got.SystemDNS {
		t.Fatalf("the earlier approvals changed to %+v (%v)", got, err)
	}
}

func TestAnInvalidDocumentIsNotWritten(t *testing.T) {
	withOwnDir(t, func(string) error { return nil })
	path := filepath.Join(t.TempDir(), "grants.json")
	err := Write(path, grants.Document{DNSDomains: []string{"not a domain"}})
	if err == nil {
		t.Fatal("an invalid domain was written")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("a file was left behind: %v", statErr)
	}
}
