// SPDX-License-Identifier: MIT

package autostart

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

// The menu reads the login item on every refresh, and on Windows reading it means running
// schtasks. app-tail's windowed build owns no console, so a console program started from
// it without this flag is handed a new window: the visible effect is one flashing on the
// desktop every couple of seconds, for as long as the app runs.
func TestAskingTheTaskSchedulerOpensNoConsoleWindow(t *testing.T) {
	cmd := schtasksCommand(context.Background(), "/Query", "/TN", TaskName)

	if cmd.SysProcAttr == nil {
		t.Fatal("the schtasks command carries no process attributes, so it opens a console window")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Error("the schtasks command does not hide its window")
	}
	if cmd.Path != schtasks {
		t.Errorf("the command runs %q, want the absolute path %q", cmd.Path, schtasks)
	}
}

// schtasks registers what runs with administrator rights at every login, so which program
// answers to that name may not be decided by the environment this process happened to
// start in.
func TestTheTaskSchedulerIsFoundWithoutReadingTheEnvironment(t *testing.T) {
	if !filepath.IsAbs(schtasks) {
		t.Fatalf("schtasks resolved to %q, which PATH decides", schtasks)
	}
	t.Setenv("SystemRoot", `Z:\nowhere`)
	if got := systemProgram("schtasks.exe"); got != schtasks {
		t.Errorf("an environment variable moved schtasks from %q to %q", schtasks, got)
	}
}

// scratchRunKey points the module at a startup key of this test's own, deleted with it.
// The real one is this user's live startup list, so a test that used it would install and
// remove a login item on the machine running the suite.
func scratchRunKey(t *testing.T) {
	t.Helper()
	path := `Software\app-tail\test\` + strings.ReplaceAll(t.Name(), "/", "_")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("create the scratch key HKCU\\%s: %v", path, err)
	}
	if err := key.Close(); err != nil {
		t.Fatalf("close the scratch key: %v", err)
	}
	original := runKeyPath
	runKeyPath = path
	t.Cleanup(func() {
		runKeyPath = original
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Errorf("delete the scratch key HKCU\\%s: %v", path, err)
		}
	})
}

func winManager(t *testing.T) *Manager {
	t.Helper()
	return &Manager{ExecPath: `C:\Program Files\app-tail\app-tail.exe`, Home: t.TempDir(), Args: []string{"run"}}
}

// The round trip is the whole registry half of the module: what SetEnabled writes has to
// be what Enabled reads back, and switching off has to remove the value rather than blank
// it -- an empty Run value is a login item Windows still tries to start.
func TestTheRunValueIsWrittenReadBackAndRemoved(t *testing.T) {
	scratchRunKey(t)
	m := winManager(t)

	installed, err := m.runValueInstalled()
	if err != nil {
		t.Fatalf("read a startup key with no login item: %v", err)
	}
	if installed {
		t.Fatal("a fresh key already reports a login item")
	}

	if err := m.setRunValue(true); err != nil {
		t.Fatalf("install the login item: %v", err)
	}
	installed, err = m.runValueInstalled()
	if err != nil {
		t.Fatalf("read the login item back: %v", err)
	}
	if !installed {
		t.Error("the login item was written and does not read back, so nothing starts at login")
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("open the scratch key: %v", err)
	}
	value, _, err := key.GetStringValue(ServiceName)
	if err := key.Close(); err != nil {
		t.Fatalf("close the scratch key: %v", err)
	}
	if err != nil {
		t.Fatalf("read the written value: %v", err)
	}
	if !strings.Contains(value, m.ExecPath) {
		t.Errorf("the login item runs %q, which does not name %q", value, m.ExecPath)
	}

	if err := m.setRunValue(false); err != nil {
		t.Fatalf("remove the login item: %v", err)
	}
	installed, err = m.runValueInstalled()
	if err != nil {
		t.Fatalf("read the startup key after removal: %v", err)
	}
	if installed {
		t.Error("the login item is still there after being removed")
	}
}

// Removing a login item that was never installed is what happens whenever autostart is
// switched off twice, or off on a machine that never had it. Reporting it as a failure
// leaves the off path stuck.
func TestRemovingALoginItemThatWasNeverThereIsNotAFailure(t *testing.T) {
	scratchRunKey(t)
	if err := winManager(t).setRunValue(false); err != nil {
		t.Errorf("removing a login item that was never installed = %v, want it accepted", err)
	}
}

// A manager with nothing resolved must refuse before it writes: a login item pointing at
// an empty or relative path is one that fails at the next login, where nobody is watching.
func TestAnUnresolvedManagerRefusesBeforeTouchingTheRegistry(t *testing.T) {
	scratchRunKey(t)
	m := &Manager{ExecPath: "app-tail.exe", Home: t.TempDir()}

	if _, err := m.Enabled(); err == nil {
		t.Error("a relative executable path was accepted by Enabled")
	}
	if err := m.SetEnabled(true); err == nil {
		t.Error("a relative executable path was accepted by SetEnabled")
	}
	if installed, err := m.runValueInstalled(); err != nil || installed {
		t.Errorf("the refused install still wrote something: installed=%v err=%v", installed, err)
	}
}

// Both forms are consulted, not just the one the current mode uses. Answering "no" because
// the mode changed under an installed login item sends someone to install a second one,
// and two login items start two agents at the next login.
func TestEnabledConsultsTheRegistryFormWhateverModeTheManagerIsIn(t *testing.T) {
	scratchRunKey(t)
	m := winManager(t)
	m.Elevated = true

	if err := m.setRunValue(true); err != nil {
		t.Fatalf("install the registry login item: %v", err)
	}
	t.Cleanup(func() {
		if err := m.setRunValue(false); err != nil {
			t.Errorf("remove the registry login item: %v", err)
		}
	})

	enabled, err := m.Enabled()
	if err != nil {
		t.Fatalf("ask whether app-tail starts at login: %v", err)
	}
	if !enabled {
		t.Error("an elevated manager reports no login item while the registry one is installed")
	}
}

// A Windows image with no Task Scheduler splits two ways, and the split is the contract.
// Asking whether a login item is registered answers "no": a machine that cannot register one
// has none, and failing would take down every question about the login item including the
// registry form, which needs no Task Scheduler at all. Installing one refuses instead, with a
// sentence naming what is missing rather than a bare "file does not exist" from deeper down.
func TestAMachineWithNoTaskSchedulerAnswersQueriesAndRefusesInstalls(t *testing.T) {
	original := schtasks
	schtasks = filepath.Join(t.TempDir(), "schtasks.exe")
	t.Cleanup(func() { schtasks = original })

	m := winManager(t)
	m.Elevated = true

	installed, err := m.taskInstalled()
	if err != nil {
		t.Fatalf("asking about the login item on a machine with no Task Scheduler failed: %v", err)
	}
	if installed {
		t.Error("a machine with no Task Scheduler reported a registered login item")
	}
	if err := m.setTask(false); err != nil {
		t.Errorf("removing a login item that cannot exist was reported as a failure: %v", err)
	}

	err = m.setTask(true)
	if err == nil {
		t.Fatal("registering a scheduled task with no Task Scheduler was accepted")
	}
	if !strings.Contains(err.Error(), "Task Scheduler") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// The query answers from its exit status, because the tool prints a localized sentence
// rather than a distinguishable code. A non-zero exit is "no such task", which is an
// answer -- reporting it as a failure would make the menu unable to say anything at all.
func TestAQueryThatExitsNonZeroMeansNoSuchTaskRatherThanAFailure(t *testing.T) {
	original := schtasks
	// findstr refuses these arguments and exits non-zero, which is the shape the query
	// takes for a task that is not registered.
	schtasks = systemProgram("findstr.exe")
	t.Cleanup(func() { schtasks = original })

	if _, err := os.Stat(schtasks); err != nil {
		t.Skipf("this Windows installation has no findstr.exe to stand in for the query: %v", err)
	}

	installed, err := winManager(t).taskInstalled()
	if err != nil {
		t.Fatalf("a query that exited non-zero was reported as a failure: %v", err)
	}
	if installed {
		t.Error("a query that exited non-zero was read as a registered task")
	}
}

// The definition names the exact command that will run with administrator rights at every
// login, and schtasks reads it back by path. An account able to write the temp directory
// could otherwise replace it between the write and the read.
func TestTheTaskDefinitionIsNarrowedToThisAccountBeforeItIsWritten(t *testing.T) {
	fileowntest.RequireCanHandToAdministrators(t)
	m := winManager(t)
	m.Elevated = true

	path, err := writeTaskDefinition(m.windowsTaskXML("S-1-5-21-0-0-0-1000"))
	if err != nil {
		t.Fatalf("write the login item definition: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove the definition: %v", err)
		}
	})

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the access list of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read the access list's flags: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the definition still inherits the temp directory's access list, so whoever can write there can choose what runs elevated")
	}
}

// schtasks reads the definition as UTF-16, and a file written as UTF-8 is rejected with a
// message about the XML rather than about the encoding.
func TestTheTaskDefinitionIsWrittenAsUTF16(t *testing.T) {
	fileowntest.RequireCanHandToAdministrators(t)
	m := winManager(t)
	xml := m.windowsTaskXML("S-1-5-21-0-0-0-1000")

	path, err := writeTaskDefinition(xml)
	if err != nil {
		t.Fatalf("write the login item definition: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove the definition: %v", err)
		}
	})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the definition back: %v", err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("the definition is %d bytes, which is not a whole number of UTF-16 units", len(raw))
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	got := string(utf16.Decode(units))
	if !strings.HasSuffix(got, xml) {
		t.Errorf("the definition does not read back as the XML that was written:\n%q", got)
	}
	if !strings.Contains(got, m.ExecPath) {
		t.Errorf("the definition does not name %q", m.ExecPath)
	}
}
