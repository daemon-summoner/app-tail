// SPDX-License-Identifier: MIT

package fileowntest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown"
)

// A closed directory refuses a new file for as long as the test that closed it runs, and
// takes one again afterwards: the temporary directory it sits in has to be clearable.
func TestAClosedDirectoryRefusesANewFileUntilTheTestEnds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "closed")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("make the directory to close: %v", err)
	}
	inside := filepath.Join(dir, "new")

	t.Run("while closed", func(t *testing.T) {
		CloseDirectory(t, dir)
		if err := os.WriteFile(inside, []byte("x"), 0o600); err == nil {
			t.Fatal("a file was written into a directory that was closed")
		}
	})

	if err := os.WriteFile(inside, []byte("x"), 0o600); err != nil {
		t.Fatalf("the directory is still closed after the test that closed it ended: %v", err)
	}
}

// recorder stands in for the test an assertion reports to, so what it reports can be read.
// A fatal report ends the assertion the way it would end a test: by leaving.
type recorder struct {
	testing.TB
	failed []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.failed = append(r.failed, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}

// check runs the assertion against path on a recorder and returns what it reported.
func check(t *testing.T, path string) []string {
	t.Helper()
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		AssertOwnerOnly(r, path, 0o600)
	}()
	<-done
	return r.failed
}

// The assertion passes a file narrowed the way the code under test narrows its own, and
// fails one left as the directory hands it out. A check that passed both would be no check.
func TestTheOwnerOnlyAssertionTellsANarrowedFileFromAnOpenOne(t *testing.T) {
	dir := t.TempDir()
	narrowed := filepath.Join(dir, "narrowed")
	if err := os.WriteFile(narrowed, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fileown.RestrictToOwner(narrowed); err != nil {
		t.Fatalf("narrow the file: %v", err)
	}
	if reported := check(t, narrowed); len(reported) != 0 {
		t.Errorf("a file narrowed to this account was reported: %s", strings.Join(reported, "; "))
	}

	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if reported := check(t, open); len(reported) == 0 {
		t.Error("a file every account can read passed as one only this account can")
	}
}
