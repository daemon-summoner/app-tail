// SPDX-License-Identifier: MIT

package secretstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

const sampleKey = "tskey-auth-kSAMPLE-not-a-real-key"

func sample() Secrets {
	return Secrets{
		"tunnels": {"tn_primary": {"authKey": sampleKey}},
		"proxies": {"px_default": {"proxy.token": "hunter2-proxy"}},
	}
}

func TestWhatIsSavedIsWhatLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Save(path, sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !Equal(got, sample()) {
		t.Error("the loaded credentials differ from the saved ones")
	}
	if got["tunnels"]["tn_primary"]["authKey"] != sampleKey {
		t.Error("the tunnel's auth key did not come back under its id and key")
	}
}

// Anyone else who can read this file has every credential the app holds.
func TestTheCredentialsFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Save(path, sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fileowntest.AssertOwnerOnly(t, path, FileMode)
}

// A first run has no file, and that is not a fault: the caller needs to tell it apart from
// a file it could not read.
func TestAMissingFileIsReportedAsNotExisting(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), FileName))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load of a missing file = %v, want fs.ErrNotExist", err)
	}
}

// A file that is present but unreadable must stop the caller, naming the file, rather than
// read as "no credentials": the next write would then make that true.
func TestACorruptFileIsALoudErrorNamingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("{not json at all"), FileMode); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err == nil {
		t.Fatal("a corrupt credentials file loaded without an error")
	}
	if got != nil {
		t.Error("a corrupt credentials file returned a set alongside its error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the file", err)
	}
}

// A newer build may store credentials differently. Reading its file as this format would
// misplace or drop them.
func TestAFileInAnotherFormatIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	plain := []byte(`{"version":2,"secrets":{}}`)
	sealed, err := seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := os.WriteFile(path, sealed, FileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "format 2") {
		t.Fatalf("Load of a format-2 file = %v, want a refusal naming the format", err)
	}
}

// Saving replaces the file whole; a cleared credential is gone from it rather than kept.
func TestSavingASmallerSetRemovesWhatWasCleared(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Save(path, sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := Save(path, Secrets{"tunnels": {"tn_primary": {"authKey": sampleKey}}}); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hunter2-proxy") {
		t.Error("a credential cleared by the second save is still in the file")
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	} else if len(entries) != 1 {
		t.Errorf("the directory holds %d entries after two saves, want only the file itself", len(entries))
	}
}

func TestEqualIgnoresEmptyValuesButNotDifferentOnes(t *testing.T) {
	withEmpty := sample()
	withEmpty["tunnels"]["tn_other"] = map[string]string{"authKey": ""}
	if !Equal(sample(), withEmpty) {
		t.Error("an empty value made two otherwise equal sets differ")
	}
	changed := sample()
	changed["tunnels"]["tn_primary"]["authKey"] = "tskey-auth-kOTHER"
	if Equal(sample(), changed) {
		t.Error("a changed credential compared equal")
	}
	if Equal(sample(), Secrets{}) {
		t.Error("a set compared equal to an empty one")
	}
}

func TestPathIsBesideTheConfig(t *testing.T) {
	configPath := filepath.Join("state", "dir", "config.json")
	if got, want := Path(configPath), filepath.Join("state", "dir", FileName); got != want {
		t.Errorf("Path(%q) = %q, want %q", configPath, got, want)
	}
}
