// SPDX-License-Identifier: MIT

package fileown

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

// The files these writers produce are the record of what an elevated app-tail changed about
// a machine, so the bytes and the permissions have to be what the caller asked for: a record
// another account may write is one this side must not act on afterwards.
func TestARecordIsWrittenWithThePermissionsItWasAskedFor(t *testing.T) {
	fileowntest.RequireCanHandToAdministrators(t)
	path := filepath.Join(t.TempDir(), "record.json")

	if err := WriteRestricted(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write the record: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if string(body) != "{}\n" {
		t.Errorf("the record holds %q, want what was written", body)
	}
	if runtime.GOOS == "windows" {
		// Mode bits are inert there; RestrictToAdministrators is what carries this, and it
		// answers against a real machine's accounts rather than a temporary directory.
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("read the record's permissions: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the record is %v, want it readable only by the account that wrote it", info.Mode().Perm())
	}
}

// The write goes through a temporary file in the same directory, and a run that leaves those
// behind fills the state directory with copies of the record -- each one holding what app-tail
// changed about the machine, none of them the one anything reads.
func TestReplacingARecordLeavesNothingBesideIt(t *testing.T) {
	fileowntest.RequireCanHandToAdministrators(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")

	for _, body := range []string{"first", "second", "third"} {
		if err := WriteRestricted(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %q: %v", body, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("list the directory holding the record: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "record.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("the directory holds %v, want only the record itself", names)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if string(body) != "third" {
		t.Errorf("the record holds %q, want the last thing written", body)
	}
}

// A write that could not happen has to say so and name the file. Reported as success it would
// leave this side believing the note saying how to undo a machine change is on the disk.
func TestAWriteWithNowhereToPutItIsReportedAndNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-made-yet", "record.json")

	err := WriteRestricted(path, []byte("{}\n"), 0o600)

	if err == nil {
		t.Fatal("a write into a directory that does not exist was reported as having happened")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the reason given is %q, want it to name the file that was not written", err)
	}
}

// The directory is made on first use and narrowed every time, so the first record written on a
// machine lands somewhere only an administrator may write rather than wherever the account that
// happened to start app-tail could reach.
func TestTheDirectoryForARecordIsMadeWholeAndCanBeAskedForTwice(t *testing.T) {
	fileowntest.RequireCanHandToAdministrators(t)
	dir := filepath.Join(t.TempDir(), "app-tail", "state")

	if err := MakeRestrictedDir(dir, 0o700); err != nil {
		t.Fatalf("make the directory for the record: %v", err)
	}
	if err := MakeRestrictedDir(dir, 0o700); err != nil {
		t.Fatalf("make the directory a second time: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("read the directory back: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("the directory is %v, want it reachable only by the account that made it", info.Mode().Perm())
	}
}

// A directory that cannot be made is reported rather than written around: everything the
// caller does next assumes the record it is about to write has somewhere to go.
func TestADirectoryThatCannotBeMadeIsReported(t *testing.T) {
	blocking := filepath.Join(t.TempDir(), "in-the-way")
	if err := os.WriteFile(blocking, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("put a file where the directory would go: %v", err)
	}

	err := MakeRestrictedDir(filepath.Join(blocking, "state"), 0o700)

	if err == nil {
		t.Fatal("a directory that could not be made was reported as made")
	}
	if !strings.Contains(err.Error(), blocking) {
		t.Errorf("the reason given is %q, want it to name the path that is in the way", err)
	}
}
