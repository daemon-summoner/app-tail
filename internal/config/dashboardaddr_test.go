// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

// The record is how a second process finds a running agent, so it has to survive the round
// trip exactly and be gone once the agent stops.
func TestTheRecordedDashboardAddressComesBackAndThenGoesAway(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)

	if got := ReadDashboardAddr(path); got != "" {
		t.Errorf("a state directory with no record answers %q, want nothing", got)
	}
	if err := WriteDashboardAddr(path, "127.0.0.1:64641"); err != nil {
		t.Fatalf("WriteDashboardAddr: %v", err)
	}
	if got := ReadDashboardAddr(path); got != "127.0.0.1:64641" {
		t.Errorf("the record reads back as %q, want the address that was written", got)
	}
	if err := RemoveDashboardAddr(path); err != nil {
		t.Fatalf("RemoveDashboardAddr: %v", err)
	}
	if got := ReadDashboardAddr(path); got != "" {
		t.Errorf("the record still answers %q after being removed", got)
	}
	// Removing what is not there is the ordinary case on a machine that crashed, and
	// reporting it would turn every clean start into a failure.
	if err := RemoveDashboardAddr(path); err != nil {
		t.Errorf("removing an absent record reported %v", err)
	}
}

// A record nothing can dial is worth no more than no record: the caller has the configured
// address to fall back to, and an unusable one would send it nowhere instead.
func TestARecordThatIsNotAnAddressIsTheSameAnswerAsNoRecord(t *testing.T) {
	for _, content := range []string{"", "   \n", "not-an-address", "127.0.0.1"} {
		path := filepath.Join(t.TempDir(), ConfigFileName)
		if err := os.WriteFile(DashboardAddrPath(path), []byte(content), FileMode); err != nil {
			t.Fatalf("write the record: %v", err)
		}

		if got := ReadDashboardAddr(path); got != "" {
			t.Errorf("a record holding %q answers %q, want nothing", content, got)
		}
	}
}

// Recording no address at all would leave a record naming nowhere, which every reader
// would then prefer over the configured address.
func TestRecordingAnEmptyDashboardAddressIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFileName)

	err := WriteDashboardAddr(path, "  ")

	if err == nil {
		t.Fatal("WriteDashboardAddr accepted an empty address")
	}
	if !strings.Contains(err.Error(), "no address was bound") {
		t.Errorf("err = %v, want it to say what was missing", err)
	}
	if _, statErr := os.Stat(DashboardAddrPath(path)); statErr == nil {
		t.Error("a record was written for an address that was never bound")
	}
}

// Every way the record can fail to be written is a state the agent has to hear about: it
// binds the port either way, and a caller that is never told the record is missing looks
// for the agent on the address it asked for and finds nothing there.
func TestARecordThatCannotBeWrittenIsReportedRatherThanPassedOver(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bits this test depends on")
	}

	t.Run("the state directory cannot be created", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "in-the-way")
		if err := os.WriteFile(blocked, []byte("not a directory"), FileMode); err != nil {
			t.Fatalf("write the file standing where the directory would go: %v", err)
		}

		err := WriteDashboardAddr(filepath.Join(blocked, ConfigFileName), "127.0.0.1:64641")

		requireRecordError(t, err, "create state dir")
	})

	t.Run("the state directory cannot be written to", func(t *testing.T) {
		dir := t.TempDir()
		fileowntest.CloseDirectory(t, dir)

		err := WriteDashboardAddr(filepath.Join(dir, ConfigFileName), "127.0.0.1:64641")

		requireRecordError(t, err, "create temp file")
	})

	t.Run("the record cannot be moved into place", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ConfigFileName)
		// A directory holding something is what a rename cannot replace, and it leaves the
		// temp file the write has already created to be cleaned up.
		if err := os.Mkdir(DashboardAddrPath(path), DirMode); err != nil {
			t.Fatalf("put a directory where the record goes: %v", err)
		}
		if err := os.WriteFile(filepath.Join(DashboardAddrPath(path), "occupied"), nil, FileMode); err != nil {
			t.Fatalf("fill that directory: %v", err)
		}

		err := WriteDashboardAddr(path, "127.0.0.1:64641")

		requireRecordError(t, err, "record the dashboard address")
		leftBehind, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatalf("read the state dir: %v", readErr)
		}
		if len(leftBehind) != 1 {
			t.Errorf("the state dir holds %d entries, want only the directory in the way", len(leftBehind))
		}
	})
}

// The agent reports what it could not clean up on the way out. A record it failed to
// remove is the one that sends the next `app-tail status` at a port nothing answers on.
func TestARecordThatCannotBeRemovedIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes what this test depends on being undeletable")
	}
	path := filepath.Join(t.TempDir(), ConfigFileName)
	if err := os.Mkdir(DashboardAddrPath(path), DirMode); err != nil {
		t.Fatalf("put a directory where the record goes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(DashboardAddrPath(path), "occupied"), nil, FileMode); err != nil {
		t.Fatalf("fill that directory: %v", err)
	}

	err := RemoveDashboardAddr(path)

	if err == nil {
		t.Fatal("removing a record that is still there reported success")
	}
	if !strings.Contains(err.Error(), "remove the dashboard address record") {
		t.Errorf("err = %v, want it to name what could not be removed", err)
	}
}

// requireRecordError checks a write refusal names the record and the step that failed.
func requireRecordError(t *testing.T, err error, step string) {
	t.Helper()
	if err == nil {
		t.Fatal("WriteDashboardAddr reported success over a state directory it could not use")
	}
	if !strings.Contains(err.Error(), "record the dashboard address") {
		t.Errorf("err = %v, want it to say the record is what failed", err)
	}
	if !strings.Contains(err.Error(), step) {
		t.Errorf("err = %v, want it to name the step %q that failed", err, step)
	}
}

// The repair commands read the address without opening the document, and a running agent
// on a port it had to fall back to is exactly the case they are used in.
func TestDashboardAddrPrefersTheRunningAgentOverTheStoredSetting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.Update(func(c *Config) error {
		c.Settings.UIListen = "127.0.0.1:18377"
		return nil
	}); err != nil {
		t.Fatalf("seed the configured address: %v", err)
	}

	if got := DashboardAddr(path); got != "127.0.0.1:18377" {
		t.Errorf("with no agent running, DashboardAddr = %q, want the configured address", got)
	}

	if err := WriteDashboardAddr(path, "127.0.0.1:19999"); err != nil {
		t.Fatalf("record where the agent bound: %v", err)
	}
	if got := DashboardAddr(path); got != "127.0.0.1:19999" {
		t.Errorf("DashboardAddr = %q, want the port the running agent is on", got)
	}
}
