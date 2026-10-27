// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

// writeConfigAt puts a usable document at path and returns what it wrote.
func writeConfigAt(t *testing.T, path, machineID string) []byte {
	t.Helper()
	cfg := Defaults()
	cfg.Settings.MachineID = machineID
	cfg.Settings.StateDir = filepath.Dir(path)
	data, err := encodeConfig(cfg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(path, data, FileMode); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestInspectSaysThereIsNoConfigYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	report, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if report.Exists {
		t.Error("Inspect reported a config file in an empty directory")
	}
	// A machine that has never run the app is not broken, and a report that said
	// "unusable" about a file nobody has written yet would send someone repairing
	// nothing.
	if report.Usable {
		t.Error("a config that does not exist was reported as usable")
	}
	if !strings.Contains(report.Reason, "no config file") {
		t.Errorf("reason = %q, want it to say there is no file yet", report.Reason)
	}
}

func TestInspectPassesAUsableConfigAndTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	before := writeConfigAt(t, path, "abcd1234")

	report, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !report.Exists || !report.Usable {
		t.Fatalf("a good config was reported exists=%v usable=%v (%s)", report.Exists, report.Usable, report.Reason)
	}
	if report.Version != ConfigVersion || report.Current != ConfigVersion {
		t.Errorf("version = %d, current = %d, want both %d", report.Version, report.Current, ConfigVersion)
	}
	// Checking is a read. A command someone runs because they suspect the file is damaged
	// must not be the thing that changes it.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("Inspect rewrote the document it was asked to look at")
	}
}

func TestInspectNamesWhatIsWrongAndListsWhatIsBeside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte("{not json"), FileMode); err != nil {
		t.Fatal(err)
	}
	writeConfigAt(t, path+backupSuffix(6), "abcd1234")
	if err := os.WriteFile(path+quarantineSuffix+"20240101-000000", []byte("{also broken"), FileMode); err != nil {
		t.Fatal(err)
	}

	report, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if report.Usable {
		t.Fatal("a document that is not JSON was reported as usable")
	}
	if !strings.Contains(report.Reason, "JSON") {
		t.Errorf("reason = %q, want it to say the document could not be read as JSON", report.Reason)
	}
	if len(report.Saved) != 2 {
		t.Fatalf("saved copies = %d, want the backup and the quarantined one: %+v", len(report.Saved), report.Saved)
	}

	var backup, quarantined *SavedDocument
	for i := range report.Saved {
		switch report.Saved[i].Kind {
		case "backup":
			backup = &report.Saved[i]
		case "quarantine":
			quarantined = &report.Saved[i]
		}
	}
	if backup == nil || quarantined == nil {
		t.Fatalf("saved copies were not classified: %+v", report.Saved)
	}
	// Whether a copy can actually be gone back to is the whole reason to list it: a
	// restore offering a document this build cannot load only moves the fault.
	if !backup.Usable {
		t.Errorf("the pre-migration backup was reported unusable: %s", backup.Reason)
	}
	if quarantined.Usable {
		t.Error("a quarantined document that is not JSON was offered as usable")
	}
}

func TestRestorePutsBackTheNewestUsableCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte("{not json"), FileMode); err != nil {
		t.Fatal(err)
	}
	saved := path + quarantineSuffix + "20240101-000000"
	writeConfigAt(t, saved, "abcd1234")

	installed, moved, err := Restore(path, "")
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if installed != saved {
		t.Errorf("restored %q, want %q", installed, saved)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open the restored config: %v", err)
	}
	if got := store.Settings().MachineID; got != "abcd1234" {
		t.Errorf("machine id = %q, want the restored document's", got)
	}
	if store.Quarantined() != nil {
		t.Error("the restored document did not load cleanly")
	}
	// The document being replaced is kept: a restore of the wrong copy has to be
	// undoable, or the command is one keystroke from destroying the evidence.
	if moved == nil {
		t.Fatal("the replaced document was discarded rather than kept")
	}
	kept, err := os.ReadFile(moved.Path)
	if err != nil {
		t.Fatalf("read the replaced document: %v", err)
	}
	if string(kept) != "{not json" {
		t.Errorf("the replaced document was changed on the way aside: %q", kept)
	}
}

func TestRestoreRefusesACopyThisBuildCannotLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	before := writeConfigAt(t, path, "abcd1234")
	bad := path + quarantineSuffix + "20240101-000000"
	if err := os.WriteFile(bad, []byte(`{"settings":{"uiListenAddr":"0.0.0.0:8377"}}`), FileMode); err != nil {
		t.Fatal(err)
	}

	_, _, err := Restore(path, bad)
	if err == nil {
		t.Fatal("Restore installed a document this build cannot load")
	}
	if !strings.Contains(err.Error(), "uiListenAddr") {
		t.Errorf("error = %q, want it to name what is wrong with the copy", err)
	}
	// Refusing has to leave everything where it was; a half-done restore would take the
	// working config away in exchange for one that cannot be loaded.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("a refused restore changed the config anyway")
	}
}

func TestRestoreSaysSoWhenThereIsNothingToGoBackTo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	writeConfigAt(t, path, "abcd1234")

	if _, _, err := Restore(path, ""); err == nil {
		t.Fatal("Restore reported success with no saved copy beside the config")
	}
}

func TestResetKeepsTheMachineIdAndTheOldDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	cfg.Settings.UDPSessionTimeoutSec = 99
	data, err := encodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, FileMode); err != nil {
		t.Fatal(err)
	}

	moved, err := Reset(path)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open the reset config: %v", err)
	}
	if got := store.Settings().UDPSessionTimeoutSec; got != Defaults().Settings.UDPSessionTimeoutSec {
		t.Errorf("udpSessionTimeoutSec = %d, want the default a reset installs", got)
	}
	// A reset is someone clearing their settings, not a new machine: a fresh id renames
	// this device on every tailnet it is on.
	if got := store.Settings().MachineID; got != "abcd1234" {
		t.Errorf("machine id = %q, want the install's own id carried over", got)
	}
	if moved == nil {
		t.Fatal("the old document was discarded rather than kept")
	}
	var kept Config
	raw, err := os.ReadFile(moved.Path)
	if err != nil {
		t.Fatalf("read the kept document: %v", err)
	}
	if err := json.Unmarshal(raw, &kept); err != nil {
		t.Fatalf("the kept document is not the one that was replaced: %v", err)
	}
	if kept.Settings.UDPSessionTimeoutSec != 99 {
		t.Errorf("the kept document holds %d, want the settings that were reset away",
			kept.Settings.UDPSessionTimeoutSec)
	}
}

// A document a reset set aside was working when it was moved, so the listing has to say
// it was replaced. Filing it under "unusable" tells whoever reads the directory the
// opposite of what happened, and it is the copy they are most likely to want back.
func TestADocumentAResetSetAsideIsListedAsReplacedNotUnusable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	writeConfigAt(t, path, "abcd1234")

	if _, err := Reset(path); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	saved, err := savedBeside(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 {
		t.Fatalf("saved copies = %d, want the document the reset replaced: %+v", len(saved), saved)
	}
	if saved[0].Kind != "replaced" {
		t.Errorf("kind = %q, want %q", saved[0].Kind, "replaced")
	}
	if !saved[0].Usable {
		t.Errorf("the document the reset replaced was reported unusable: %s", saved[0].Reason)
	}
}

func TestResetWritesDefaultsWhereThereIsNoConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)
	moved, err := Reset(path)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if moved != nil {
		t.Errorf("Reset claimed to move %s aside when there was no config", moved.Path)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open the written config: %v", err)
	}
	if store.Settings().MachineID == "" {
		t.Error("a reset with no document to salvage from wrote no machine id")
	}
}

func TestResetWritesOwnerOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	writeConfigAt(t, path, "abcd1234")
	moved, err := Reset(path)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	// Both files hold auth keys and OAuth secrets: the new one because it is the config,
	// and the one moved aside because it is the config someone was using a moment ago.
	fileowntest.AssertOwnerOnly(t, path, FileMode)
	if moved != nil {
		fileowntest.AssertOwnerOnly(t, moved.Path, FileMode)
	}
}

// Two bad loads in the same second must not destroy the first document, which is the one
// thing this whole path exists to prevent.
func TestASecondQuarantineDoesNotOverwriteTheFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)

	for i, body := range []string{"{first broken", "{second broken"} {
		if err := os.WriteFile(path, []byte(body), FileMode); err != nil {
			t.Fatal(err)
		}
		store, err := Open(path)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		note := store.Quarantined()
		if note == nil {
			t.Fatalf("Open %d replaced a broken document with no record of it", i)
		}
		kept, err := os.ReadFile(note.Path)
		if err != nil {
			t.Fatal(err)
		}
		if string(kept) != body {
			t.Errorf("quarantined document %d holds %q, want %q", i, kept, body)
		}
	}

	saved, err := savedBeside(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 2 {
		t.Fatalf("saved copies = %d, want both broken documents kept: %+v", len(saved), saved)
	}
}

// A document from a newer build is not invalid, it is unreadable here. Saying "invalid"
// sends someone looking for a mistake in a file that is perfectly correct.
func TestAConfigFromANewerBuildSaysSoRatherThanCallingItInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	doc := map[string]any{
		"version":  ConfigVersion + 1,
		"settings": map[string]any{"uiListenAddr": "0.0.0.0:8377"},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, FileMode); err != nil {
		t.Fatal(err)
	}

	report, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if report.Usable {
		t.Fatal("a document this build cannot read was reported usable")
	}
	if !strings.Contains(report.Reason, "newer app-tail") {
		t.Errorf("reason = %q, want it to say the document is from a newer build", report.Reason)
	}
	if report.Version != ConfigVersion+1 {
		t.Errorf("version = %d, want the version the document declares", report.Version)
	}
}
