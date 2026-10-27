// SPDX-License-Identifier: MIT

package autostart

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/sellitus/app-tail/internal/fileown"
)

// Kind names the sort of login item this manager installs, as the label beside Path in
// messages and docs. Windows has two, and which one is installed is the difference
// between the interface mode starting at login and a consent prompt at every login, so
// the two are never described by one name.
func (m *Manager) Kind() string {
	if m.Elevated {
		return "scheduled task, run with highest privileges"
	}
	return "HKCU Run registry value"
}

// runKeyPath is the per-user startup key. It needs no administrator rights, which is why
// it stays the login item for every mode but one: the contained mode is the default, and
// installing it must not ask anybody for anything.
//
// A variable so a test can point it at a key of its own: the real one is this user's live
// startup list.
var runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// schtasks is the Task Scheduler's command-line front end, addressed by absolute path so
// the login item this installs cannot be decided by the caller's PATH -- nor by the
// caller's environment, which is why Windows is asked for its own system directory rather
// than %SystemRoot% being read. The variable is also the seam a test points elsewhere.
var schtasks = systemProgram("schtasks.exe")

func systemProgram(name string) string {
	dir, err := windows.GetSystemDirectory()
	if err != nil || !filepath.IsAbs(dir) {
		// Empty rather than a guess built from %SystemRoot%: a relative path with a separator
		// in it is resolved against the working directory, which the caller chose, so the
		// fallback would run whatever sits at System32\schtasks.exe under it. haveSchtasks
		// reports the empty path as the tool being missing, which is what it is here.
		return ""
	}
	return filepath.Join(dir, name)
}

// schtasksCommand builds a Task Scheduler invocation that opens no console window.
//
// The window is the whole reason this exists. app-tail's windowed build owns no console,
// so a console program started from it is given a new one on screen -- and the menu reads
// the login item on every refresh, which turns that into a window appearing and vanishing
// every couple of seconds for as long as the app is running.
func schtasksCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, schtasks, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

// taskQueryTimeout bounds the query the menu makes on every refresh. The Task Scheduler
// is reached over RPC and a wedged service answers nothing at all, which without this
// would park the menu's refresh goroutine for as long as the app runs.
const taskQueryTimeout = 10 * time.Second

// Path describes where the login item lives, for messages.
func (m *Manager) Path() string {
	if m.Elevated {
		return "Task Scheduler: " + TaskName
	}
	return `HKCU\` + runKeyPath + `\` + ServiceName
}

// Enabled reports whether app-tail starts at login in any form.
//
// Both forms are consulted, not just the one this mode uses: the question a caller is
// asking is whether app-tail starts at login, and answering "no" because the mode
// changed under an installed login item would send someone to install a second one.
func (m *Manager) Enabled() (bool, error) {
	if err := m.Validate(); err != nil {
		return false, err
	}
	value, err := m.runValueInstalled()
	if err != nil || value {
		return value, err
	}
	return m.taskInstalled()
}

// NeedsReinstall reports whether the installed login item starts app-tail with the wrong
// rights for the current mode.
//
// Neither cause can be noticed at the moment it happens. Switching to the interface mode
// leaves a registry value that starts app-tail without rights, and the symptom is a consent
// prompt at the next login rather than an error anyone sees now. Moving the app leaves a
// value naming a program that is not there, and the symptom is app-tail simply not starting
// while every surface that asks only whether the value exists still reports it as on.
//
// ReinstallReason names both, for a person, because they share one remedy and this platform
// cannot tell which one a given machine is looking at without repeating the work.
func (m *Manager) ReinstallReason() string {
	return "It no longer matches this machine: it was installed for the other network mode, so it " +
		"starts app-tail with the wrong rights, or it starts two copies at once, or it names a " +
		"program that is no longer there."
}

func (m *Manager) NeedsReinstall() (bool, error) {
	if err := m.Validate(); err != nil {
		return false, err
	}
	stored, value, err := m.runValue()
	if err != nil {
		return false, err
	}
	task, err := m.taskInstalled()
	if err != nil {
		return false, err
	}
	if staleLoginItem(m.Elevated, value, task) {
		return true, nil
	}
	if value {
		dead, err := deadRunValue(stored)
		if dead || err != nil {
			return dead, err
		}
	}
	if task {
		return deadTask()
	}
	return false, nil
}

// deadTask reports whether the scheduled task starts a program that is no longer there.
//
// The definition is read back rather than assumed, because this is the form the interface
// mode installs and a moved app-tail is the state nothing else notices: the task is still
// registered, every surface that asks whether one exists still says yes, and nothing starts
// at the next logon. What is read is the task's own XML rather than a printed sentence, so
// there is nothing locale-dependent about it.
func deadTask() (bool, error) {
	command, err := taskCommand()
	if err != nil || command == "" {
		// A definition that could not be read or that names no program is not evidence of a
		// moved binary, and reinstalling on that basis would replace a login item over a
		// question this could not answer.
		return false, err
	}
	exists, err := fileExists(command)
	if err != nil {
		return false, err
	}
	return !exists, nil
}

// taskCommand is the program the registered task starts, empty when the definition could not
// be read as one.
func taskCommand() (string, error) {
	if !schtasksPresent() {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), taskQueryTimeout)
	defer cancel()
	raw, err := schtasksCommand(ctx, "/Query", "/TN", TaskName, "/XML", "ONE").Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("ask the Task Scheduler about %s: %w", TaskName, ctxErr)
		}
		// A query that failed is the same answer taskInstalled gives it: the task is not
		// there to describe. Its own call is what reports a Task Scheduler that is broken.
		return "", nil
	}
	var definition struct {
		Actions struct {
			Exec []struct {
				Command string `xml:"Command"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	if err := xml.Unmarshal(decodeTaskXML(raw), &definition); err != nil {
		return "", nil
	}
	if len(definition.Actions.Exec) == 0 {
		return "", nil
	}
	return strings.Trim(strings.TrimSpace(definition.Actions.Exec[0].Command), `"`), nil
}

// decodeTaskXML turns what schtasks printed into bytes the XML parser reads. The tool writes
// its definitions as UTF-16 with a byte order mark, which is what it was handed; a build or a
// locale that writes UTF-8 instead is passed through with its own mark removed.
func decodeTaskXML(raw []byte) []byte {
	switch {
	case len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE:
		units := make([]uint16, 0, (len(raw)-2)/2)
		for i := 2; i+1 < len(raw); i += 2 {
			units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
		}
		return []byte(string(utf16.Decode(units)))
	case len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF:
		return raw[3:]
	default:
		return raw
	}
}

// deadRunValue reports whether a stored login item names a program that is no longer there.
//
// Only a program that has genuinely vanished counts. A path that merely differs from this
// process's own is somebody running a second copy of app-tail, and rewriting the item to name
// whichever binary started last would move the user's login item without being asked.
func deadRunValue(stored string) (bool, error) {
	if stored == "" {
		return false, nil
	}
	args, err := windows.DecomposeCommandLine(stored)
	if err != nil || len(args) == 0 {
		// Unreadable is not vanished: the value is something app-tail did not write, and
		// replacing it on that basis would take over a login item belonging to something else.
		return false, nil //nolint:nilerr // an unreadable value is not a missing program; see above.
	}
	exists, err := fileExists(args[0])
	if err != nil {
		return false, err
	}
	return !exists, nil
}

// SetEnabled installs the login item this mode needs and removes the other one.
//
// The removal follows the install rather than accompanying it: two login items would start
// two agents at the next login, so the other form always goes -- but only once there is
// something to replace it with. An install that failed and took the working item with it
// leaves the machine with no login item at all, reported as switched off, and nothing on any
// later start notices that the user asked for one.
func (m *Manager) SetEnabled(enabled bool) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if !enabled {
		return errors.Join(m.setRunValue(false), m.setTask(false))
	}
	if m.Elevated {
		if err := m.setTask(true); err != nil {
			return err
		}
		return m.setRunValue(false)
	}
	if err := m.setRunValue(true); err != nil {
		return err
	}
	return m.setTask(false)
}

// runValueInstalled reports whether the HKCU Run value is present.
func (m *Manager) runValueInstalled() (bool, error) {
	_, installed, err := m.runValue()
	return installed, err
}

// runValue reads the HKCU Run value and whether it is there at all. The two answers come
// together because the question about a login item is rarely only whether one exists: what it
// starts is the other half, and reading it twice is two chances for them to disagree.
func (m *Manager) runValue() (string, bool, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("open %s: %w", m.runValuePath(), err)
	}
	defer key.Close()

	value, _, err := key.GetStringValue(ServiceName)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read %s: %w", m.runValuePath(), err)
	}
	return value, true, nil
}

// setRunValue writes or removes the HKCU Run value.
func (m *Manager) setRunValue(enabled bool) error {
	if !enabled {
		// Opened rather than created, so removing a login item that was never installed
		// does not leave the key behind as a trace of app-tail having been here.
		key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("open %s for writing: %w", m.runValuePath(), err)
		}
		defer key.Close()
		if err := key.DeleteValue(ServiceName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", m.runValuePath(), err)
		}
		return nil
	}

	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s for writing: %w", m.runValuePath(), err)
	}
	defer key.Close()
	if err := key.SetStringValue(ServiceName, m.windowsRunValue()); err != nil {
		return fmt.Errorf("write %s: %w", m.runValuePath(), err)
	}
	return nil
}

func (m *Manager) runValuePath() string {
	return `HKCU\` + runKeyPath + `\` + ServiceName
}

// taskInstalled reports whether the scheduled task exists.
//
// Presence is read from the query's exit status. The tool prints a localized sentence
// rather than a distinguishable code, so matching its text would break on any machine
// not in English -- and a Task Scheduler that is genuinely broken reads as "absent"
// here and then fails loudly at the create, which is where the real message is.
func (m *Manager) taskInstalled() (bool, error) {
	if !schtasksPresent() {
		// An answer rather than a failure: the task is only ever registered through this
		// tool, so a machine without it has none. Failing here instead would make every
		// question about the login item fail on such a machine, including the ones about
		// the registry value, which is the form that needs no Task Scheduler at all.
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), taskQueryTimeout)
	defer cancel()
	cmd := schtasksCommand(ctx, "/Query", "/TN", TaskName)
	if err := cmd.Run(); err != nil {
		// Checked before the exit status, and not folded into it: a query killed for
		// running past the deadline also exits non-zero, and reading that as "absent"
		// would report no login item on a machine that has one.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, fmt.Errorf("ask the Task Scheduler about %s: %w", TaskName, ctxErr)
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return false, nil
		}
		return false, fmt.Errorf("ask the Task Scheduler about %s: %w", TaskName, err)
	}
	return true, nil
}

// setTask registers or deletes the scheduled task.
func (m *Manager) setTask(enabled bool) error {
	if !enabled {
		installed, err := m.taskInstalled()
		if err != nil || !installed {
			return err
		}
		if out, err := runSchtasks("/Delete", "/TN", TaskName, "/F"); err != nil {
			return fmt.Errorf("remove the scheduled task %s: %w%s", TaskName, err, out)
		}
		return nil
	}

	if err := m.haveSchtasks(); err != nil {
		return err
	}
	if err := m.elevatedPathIsProtected(); err != nil {
		return err
	}
	// Asked of this process rather than read out of what schtasks prints when it refuses:
	// that sentence is localized, so matching it loses the remedy on every machine that is
	// not in English -- which is the machine the remedy is for as much as any other.
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("registering a login item that runs with administrator rights needs administrator " +
			"rights to set up. Run app-tail from an administrator prompt once, or turn the network-interface " +
			"mode off and use the ordinary login item")
	}

	who, err := user.Current()
	if err != nil {
		return fmt.Errorf("find out which account the login item should run as: %w", err)
	}
	definition, err := writeTaskDefinition(m.windowsTaskXML(who.Uid))
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(definition); err != nil {
			// Reported rather than swallowed: it is a file naming this user's account
			// left in the temp directory, which is exactly the kind of leftover this
			// project undertakes not to produce.
			fmt.Fprintf(os.Stderr, "app-tail: could not remove %s: %v\n", definition, err)
		}
	}()

	// /F replaces an existing definition rather than failing, so a moved binary is
	// picked up by installing again.
	out, err := runSchtasks("/Create", "/TN", TaskName, "/XML", definition, "/F")
	if err == nil {
		return nil
	}
	return fmt.Errorf("register the scheduled task %s: %w%s", TaskName, err, out)
}

// InstallBootRepair registers, or re-registers for a moved binary, the task that runs
// execPath's `dns restore` as SYSTEM at boot and at logon.
//
// It is left registered for good: with nothing recorded the restore changes nothing, and a
// machine that crashed with System DNS on is the one that most needs it to still be there.
func InstallBootRepair(execPath string) error {
	if !schtasksPresent() {
		return fmt.Errorf("this Windows installation has no Task Scheduler command at %s, so app-tail cannot "+
			"set up the boot-time repair that puts DNS back after a crash", schtasks)
	}
	// The task runs this path as SYSTEM with no prompt at every boot, so a program another
	// account could put there would be started with the machine's highest rights.
	replaceable, reason, err := fileown.ReplaceableByOtherAccounts(execPath)
	if err != nil {
		return err
	}
	if replaceable {
		return fmt.Errorf("%s, and the boot-time DNS repair would run it as SYSTEM. Install app-tail under "+
			"Program Files with `app-tail install` and turn System DNS on again", reason)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("setting up the boot-time DNS repair needs administrator rights")
	}

	definition, err := writeTaskDefinition(bootRepairTaskXML(execPath))
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(definition); err != nil {
			fmt.Fprintf(os.Stderr, "app-tail: could not remove %s: %v\n", definition, err)
		}
	}()
	if out, err := runSchtasks("/Create", "/TN", BootRepairTaskName, "/XML", definition, "/F"); err != nil {
		return fmt.Errorf("register the scheduled task %s: %w%s", BootRepairTaskName, err, out)
	}
	return nil
}

// taskDefinitionDir is the folder the definition is written in: app-tail's own under this
// machine's application data, narrowed to the administrators.
//
// Not the temp directory. Elevation on Windows keeps the same account and the same %TEMP%,
// so a file there narrowed to the account that owns it is a file the unelevated half of the
// same session can still rewrite -- and there is a window before any access list is applied
// at all, during which an open handle keeps whatever the parent directory handed down. A
// folder only the administrators can write closes both.
func taskDefinitionDir() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT_PATH)
	if err != nil {
		return "", fmt.Errorf("find where this machine keeps its machine-wide application data: %w", err)
	}
	dir := filepath.Join(root, "app-tail")
	if err := fileown.MakeRestrictedDir(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// writeTaskDefinition puts the task XML somewhere schtasks can read it and returns the
// path.
//
// It is narrowed to the administrators before anything is written into it: the definition
// names the exact command that will run with administrator rights at every login, and
// schtasks reads it back by path. Anything able to write it between the write and the read
// would choose that command.
func writeTaskDefinition(xml string) (string, error) {
	dir, err := taskDefinitionDir()
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, "app-tail-task-*.xml")
	if err != nil {
		return "", fmt.Errorf("write the scheduled task definition: %w", err)
	}
	path := file.Name()
	if err := fileown.RestrictToAdministrators(path); err != nil {
		return "", errors.Join(
			fmt.Errorf("narrow the scheduled task definition at %s to the administrators: %w", path, err),
			file.Close(), os.Remove(path))
	}
	_, writeErr := file.Write(utf16LE(xml))
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return "", errors.Join(fmt.Errorf("write the scheduled task definition to %s: %w", path, err), os.Remove(path))
	}
	return path, nil
}

// elevatedPathIsProtected refuses to register a task that starts a binary anybody can
// replace.
//
// The task runs app-tail with the highest rights this account has, at every logon, with no
// prompt -- so a program somebody else can put at that path is a program that gets those
// rights without the user ever seeing a consent dialog.
func (m *Manager) elevatedPathIsProtected() error {
	replaceable, reason, err := fileown.ReplaceableByOtherAccounts(m.ExecPath)
	if err != nil {
		return err
	}
	if replaceable {
		return fmt.Errorf("%s, so anything running as this account could have its own program started with "+
			"administrator rights at the next logon. Move app-tail under Program Files and turn this on again, "+
			"or leave the network-interface mode off and use the ordinary login item", reason)
	}
	return nil
}

// taskChangeTimeout bounds registering or removing the login item.
//
// It is generous rather than absent: the Task Scheduler is reached over RPC, somebody is
// waiting on the answer at a dashboard switch or a menu item, and a wedged service would
// otherwise hold that request open for as long as the app runs.
const taskChangeTimeout = 60 * time.Second

// runSchtasks runs one command and returns its output, which carries the reason a
// failure happened -- the exit status alone is 1 for every one of them.
func runSchtasks(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), taskChangeTimeout)
	defer cancel()
	out, err := schtasksCommand(ctx, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if text != "" {
		text = ": " + text
	}
	return text, err
}

// haveSchtasks refuses before running anything when the tool is missing, which is what
// turns a stripped-down Windows image into a sentence instead of "file does not exist".
//
// Only installing refuses. Asking whether a task is there, and removing one, answer for a
// machine that cannot have one rather than failing -- see taskInstalled.
func (m *Manager) haveSchtasks() error {
	if _, err := os.Stat(schtasks); err != nil {
		return fmt.Errorf("this Windows installation has no Task Scheduler command at %s, "+
			"so app-tail cannot install a login item that runs with administrator rights: %w", schtasks, err)
	}
	return nil
}

// schtasksPresent reports whether the Task Scheduler front end is on this machine.
func schtasksPresent() bool {
	_, err := os.Stat(schtasks)
	return err == nil
}
