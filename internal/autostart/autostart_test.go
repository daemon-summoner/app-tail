// SPDX-License-Identifier: MIT

package autostart

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

// A login item that does not name the binary starts nothing, and one whose template
// drifted silently would only be noticed after a reboot. Every renderer below is
// therefore pinned to its exact output on every platform, not just the host's.

func testManager(home string, args ...string) *Manager {
	return &Manager{ExecPath: "/usr/local/bin/app-tail", Args: args, Home: home}
}

func TestLaunchAgentPlistRunsTheAgentAtLoginAndRestartsAfterACrash(t *testing.T) {
	got := testManager("/home/u", "run", "--headless").plist()

	want := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.sellitus.app-tail</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/app-tail</string>
		<string>run</string>
		<string>--headless</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`
	if got != want {
		t.Errorf("plist drifted from the reviewed template:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// launchd refuses to load a plist it cannot parse, and it refuses silently. A home
// directory containing an ampersand is ordinary enough to reach real users.
func TestLaunchAgentPlistSurvivesPathsContainingXMLMetacharacters(t *testing.T) {
	// Every character Go's XML escaper rewrites, including the apostrophe it emits as
	// &apos; -- a home directory like /Users/o'brien is ordinary, and a plist that
	// round-trips the other four but not this one still fails to load.
	hostile := `/Users/o'brien/a&b/<tools>/app "tail"`
	m := &Manager{ExecPath: hostile, Home: "/home/u"}

	strs := plistStrings(t, m.plist())
	if len(strs) < 2 {
		t.Fatalf("plist carried %d strings, expected a label and at least one argument: %v", len(strs), strs)
	}
	if strs[0] != Label {
		t.Errorf("label = %q, want %q", strs[0], Label)
	}
	if strs[1] != hostile {
		t.Errorf("executable path did not survive XML escaping: got %q, want %q", strs[1], hostile)
	}
}

// plistStrings decodes the document and returns the contents of every <string>
// element in order. Decoding rather than substring-matching is the point: it proves
// the document actually parses.
func plistStrings(t *testing.T, doc string) []string {
	t.Helper()

	decoder := xml.NewDecoder(strings.NewReader(doc))
	decoder.Strict = true

	var (
		values  []string
		inValue bool
	)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("plist is not well-formed XML: %v\n%s", err, doc)
		}
		switch tok := token.(type) {
		case xml.StartElement:
			inValue = tok.Name.Local == "string"
		case xml.EndElement:
			inValue = false
		case xml.CharData:
			if inValue {
				values = append(values, string(tok))
			}
		}
	}
	return values
}

func TestSystemdUnitStartsAtLoginAndRestartsOnFailure(t *testing.T) {
	got := testManager("/home/u", "run", "--headless").systemdUnit()

	want := `[Unit]
Description=app-tail userspace Tailscale port forwarder
Documentation=https://github.com/sellitus/app-tail
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/app-tail run --headless
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`
	if got != want {
		t.Errorf("systemd unit drifted from the reviewed template:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// systemd splits ExecStart on whitespace, so an unquoted path with a space becomes
// two arguments and the unit fails to start with a confusing "no such file" error.
func TestSystemdExecLineQuotesArgumentsThatWouldOtherwiseSplit(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"plain", []string{"/usr/bin/app-tail", "run"}, "/usr/bin/app-tail run"},
		{"space in path", []string{"/opt/my apps/app-tail"}, `"/opt/my apps/app-tail"`},
		{"tab", []string{"/opt/a\tb"}, "\"/opt/a\tb\""},
		{"backslash", []string{`C:\bin\app-tail`}, `"C:\\bin\\app-tail"`},
		{"quote", []string{`/opt/a"b`}, `"/opt/a\"b"`},
		{"single quote", []string{"/opt/a'b"}, `"/opt/a'b"`},
		{"empty argument", []string{"/usr/bin/app-tail", ""}, `/usr/bin/app-tail ""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeExec(tc.args); got != tc.want {
				t.Errorf("escapeExec(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestWindowsRunValueQuotesArgumentsThatWouldOtherwiseSplit(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"plain", []string{`C:\bin\app-tail.exe`, "run"}, `C:\bin\app-tail.exe run`},
		{"space in path", []string{`C:\Program Files\app-tail.exe`}, `"C:\Program Files\app-tail.exe"`},
		{"quote", []string{`C:\a"b.exe`}, `"C:\a\"b.exe"`},
		{"empty argument", []string{`C:\app.exe`, ""}, `C:\app.exe ""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeWindowsArgs(tc.args); got != tc.want {
				t.Errorf("escapeWindowsArgs(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}

	// Backslashes are ordinary characters in a Windows path and must not be doubled
	// the way systemd requires, or the recorded command would point nowhere.
	m := &Manager{ExecPath: `C:\Program Files\app-tail\app-tail.exe`, Args: []string{"run", "--headless"}, Home: `C:\Users\u`}
	want := `"C:\Program Files\app-tail\app-tail.exe" run --headless`
	if got := m.windowsRunValue(); got != want {
		t.Errorf("windowsRunValue() = %q, want %q", got, want)
	}
}

// The scheduled task is the only login item that starts the interface mode without a
// consent prompt, and every one of the fields below is load-bearing: the wrong RunLevel
// starts it without the rights it needs, the wrong LogonType starts it in a session that
// has no desktop, and a time limit stops the agent after three days without a word.
func TestTheScheduledTaskStartsAppTailElevatedAtLogonAsTheInstallingAccount(t *testing.T) {
	const sid = "S-1-5-21-1004336348-1177238915-682003330-512"
	m := &Manager{
		ExecPath: `C:\Program Files\app-tail\app-tail.exe`,
		Args:     []string{"run", "--headless"},
		Home:     `C:\Users\u`,
		Elevated: true,
	}

	task := decodeTaskDefinition(t, m.windowsTaskXML(sid))

	if task.RunLevel != "HighestAvailable" {
		t.Errorf("RunLevel = %q, want HighestAvailable; the task would start without the rights the interface mode needs", task.RunLevel)
	}
	if task.LogonType != "InteractiveToken" {
		t.Errorf("LogonType = %q, want InteractiveToken; the tray needs the user's own desktop session", task.LogonType)
	}
	if task.TimeLimit != "PT0S" {
		t.Errorf("ExecutionTimeLimit = %q, want PT0S; anything else stops the agent after the limit expires", task.TimeLimit)
	}
	if task.Instances != "IgnoreNew" {
		t.Errorf("MultipleInstancesPolicy = %q, want IgnoreNew; a second agent fights the first over the state directory", task.Instances)
	}
	if task.TriggerEnabled != "true" {
		t.Errorf("LogonTrigger Enabled = %q, want true; a disabled trigger installs a task that never runs", task.TriggerEnabled)
	}
	if task.URI != TaskName {
		t.Errorf("URI = %q, want %q", task.URI, TaskName)
	}
	// Both, not just one: a task whose principal and trigger name different accounts is
	// accepted and then runs at the wrong logon, or at none.
	if task.RunAs != sid || task.TriggerUser != sid {
		t.Errorf("task runs as %q and triggers for %q, want %q for both", task.RunAs, task.TriggerUser, sid)
	}
	if task.Command != m.ExecPath {
		t.Errorf("Command = %q, want %q", task.Command, m.ExecPath)
	}
	// The arguments are one string here, so the executable path must not be repeated
	// into it -- that would start `app-tail app-tail run`, which exits with a usage error.
	if want := "run --headless"; task.Arguments != want {
		t.Errorf("Arguments = %q, want %q", task.Arguments, want)
	}
}

// schtasks rejects a definition it cannot parse, and an install path containing an
// ampersand is ordinary on a machine whose owner named a folder "R&D".
func TestTheScheduledTaskSurvivesPathsContainingXMLMetacharacters(t *testing.T) {
	hostile := `C:\R&D\<tools>\app "tail".exe`
	m := &Manager{ExecPath: hostile, Args: []string{"run", `--state=C:\a&b`}, Home: `C:\Users\u`, Elevated: true}

	task := decodeTaskDefinition(t, m.windowsTaskXML(`S-1-5-21-1-2-3-513`))

	if task.Command != hostile {
		t.Errorf("executable path did not survive XML escaping: got %q, want %q", task.Command, hostile)
	}
	// Two escapings are layered here: the command-line quoting the Windows parser reads
	// back, and then XML on top of it. Only the XML layer may be undone by decoding.
	if want := escapeWindowsArgs(m.Args); task.Arguments != want {
		t.Errorf("arguments did not survive XML escaping: got %q, want %q", task.Arguments, want)
	}
}

// schtasks picks the encoding from the byte-order mark and nothing else. A definition
// written as UTF-8 is rejected as malformed with a message that names no field, so this
// is the difference between the login item installing and an unexplainable failure.
func TestTheTaskDefinitionIsWrittenAsUTF16WithAByteOrderMark(t *testing.T) {
	encoded := utf16LE("<A/>")

	want := []byte{0xFF, 0xFE, '<', 0, 'A', 0, '/', 0, '>', 0}
	if !bytes.Equal(encoded, want) {
		t.Errorf("utf16LE(%q) = % x, want % x", "<A/>", encoded, want)
	}

	// A character outside the basic multilingual plane becomes a surrogate pair, which
	// is the case a naive "one rune, two bytes" encoder gets wrong.
	astral := utf16LE("\U0001F600")
	if got := decodeUTF16LE(t, astral); got != "\U0001F600" {
		t.Errorf("astral character did not round-trip: got %q", got)
	}
}

// Only Windows installs two kinds of login item, so only Windows can have the wrong one
// installed. Getting this wrong is silent in both directions: a stale registry value puts
// a consent prompt on screen at every login, and a false alarm reinstalls the login item
// on every start of the agent.
func TestOnlyAModeChangeUnderAnInstalledLoginItemNeedsANewOne(t *testing.T) {
	cases := []struct {
		name     string
		elevated bool
		runValue bool
		task     bool
		want     bool
	}{
		{"nothing installed, contained mode", false, false, false, false},
		{"nothing installed, interface mode", true, false, false, false},
		{"contained mode with its registry value", false, true, false, false},
		{"interface mode with its scheduled task", true, false, true, false},
		{"switched to the interface mode", true, true, false, true},
		{"switched back to the contained mode", false, false, true, true},
		// Both forms start app-tail at the same login, whichever mode the machine is in:
		// two copies race for the dashboard port and the loser exits into nothing.
		{"both installed, contained mode", false, true, true, true},
		{"both installed, interface mode", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := staleLoginItem(tc.elevated, tc.runValue, tc.task); got != tc.want {
				t.Errorf("staleLoginItem(elevated=%t, runValue=%t, task=%t) = %t, want %t",
					tc.elevated, tc.runValue, tc.task, got, tc.want)
			}
		})
	}
}

// The mode never changes which login item is installed anywhere but Windows, because the
// privileged work is a separate helper there. A platform that answered otherwise would
// reinstall its login item on every start.
func TestOnlyWindowsHasALoginItemThatCanBeWrongForTheMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reads the installed login item from the registry and the Task Scheduler")
	}
	m := testManager(t.TempDir(), "run")
	m.Elevated = true

	stale, err := m.NeedsReinstall()
	if err != nil {
		t.Fatalf("NeedsReinstall(): %v", err)
	}
	if stale {
		t.Errorf("%s reported its login item as wrong for the interface mode; it has only one kind", runtime.GOOS)
	}
}

// taskDefinition is the part of the scheduled task the install depends on.
type taskDefinition struct {
	XMLName        xml.Name `xml:"Task"`
	URI            string   `xml:"RegistrationInfo>URI"`
	TriggerEnabled string   `xml:"Triggers>LogonTrigger>Enabled"`
	TriggerUser    string   `xml:"Triggers>LogonTrigger>UserId"`
	RunAs          string   `xml:"Principals>Principal>UserId"`
	LogonType      string   `xml:"Principals>Principal>LogonType"`
	RunLevel       string   `xml:"Principals>Principal>RunLevel"`
	Instances      string   `xml:"Settings>MultipleInstancesPolicy"`
	TimeLimit      string   `xml:"Settings>ExecutionTimeLimit"`
	Command        string   `xml:"Actions>Exec>Command"`
	Arguments      string   `xml:"Actions>Exec>Arguments"`
}

// decodeTaskDefinition parses the exact bytes schtasks would read, encoding included.
// Rendering and encoding are checked together deliberately: a document that parses as a
// Go string but not as the file written beside it would pass a test and fail an install.
func decodeTaskDefinition(t *testing.T, doc string) taskDefinition {
	t.Helper()

	decoder := xml.NewDecoder(strings.NewReader(decodeUTF16LE(t, utf16LE(doc))))
	decoder.Strict = true
	// The declaration announces UTF-16 and the bytes above have already been decoded from
	// it, so the reader passes through -- but a declaration naming any other encoding is
	// one schtasks would read against the byte-order mark, and fails here.
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if !strings.EqualFold(charset, "UTF-16") {
			return nil, fmt.Errorf("task definition declares encoding %q, which does not match its byte-order mark", charset)
		}
		return input, nil
	}

	var task taskDefinition
	if err := decoder.Decode(&task); err != nil {
		t.Fatalf("task definition is not well-formed XML: %v\n%s", err, doc)
	}
	return task
}

// decodeUTF16LE reverses utf16LE, insisting on the byte-order mark that makes the file
// readable in the first place.
func decodeUTF16LE(t *testing.T, encoded []byte) string {
	t.Helper()

	if len(encoded) < 2 || encoded[0] != 0xFF || encoded[1] != 0xFE {
		t.Fatalf("definition does not begin with a little-endian byte-order mark: % x", encoded)
	}
	body := encoded[2:]
	if len(body)%2 != 0 {
		t.Fatalf("definition has %d bytes after the byte-order mark, which is not whole UTF-16 units", len(body))
	}
	units := make([]uint16, 0, len(body)/2)
	for i := 0; i < len(body); i += 2 {
		units = append(units, uint16(body[i])|uint16(body[i+1])<<8)
	}
	return string(utf16.Decode(units))
}

func TestValidateRejectsAManagerThatCouldNotInstallAWorkingLoginItem(t *testing.T) {
	// Absolute is the host's own answer rather than a spelling -- a rooted path carrying no
	// drive is absolute on unix and is not on Windows -- so the paths that are meant to pass
	// come from the framework. The cases are then about what Validate rejects.
	exe := filepath.Join(t.TempDir(), "app-tail")
	home := t.TempDir()

	cases := []struct {
		name    string
		manager *Manager
		wantErr string
	}{
		{"no executable", &Manager{Home: home}, "no executable path"},
		{"relative executable", &Manager{ExecPath: "app-tail", Home: home}, "absolute executable path"},
		{"blank executable", &Manager{ExecPath: "   ", Home: home}, "no executable path"},
		{"no home", &Manager{ExecPath: exe}, "no home directory"},
		{"valid", &Manager{ExecPath: exe, Home: home}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.manager.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// Enabled and SetEnabled must refuse an invalid manager rather than writing a login
// item that points at nothing.
func TestLoginItemOperationsRefuseAnInvalidManager(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("login-item files are only written on darwin and linux; %s uses a different mechanism", runtime.GOOS)
	}
	m := &Manager{ExecPath: "relative/app-tail", Home: t.TempDir()}

	if _, err := m.Enabled(); err == nil {
		t.Error("Enabled() accepted a relative executable path")
	}
	if err := m.SetEnabled(true); err == nil {
		t.Error("SetEnabled(true) accepted a relative executable path")
	}
}

// Installing from `go run` output or a build cache produces a login item that breaks
// at the next reboot, which the user would otherwise discover only by its absence.
func TestTemporaryPathWarningFiresForBuildLocationsOnly(t *testing.T) {
	buildCacheBinary := filepath.Join(os.TempDir(), "go-build123", "b001", "exe", "app-tail")

	cases := []struct {
		name     string
		execPath string
		wantWarn bool
	}{
		{"installed", "/usr/local/bin/app-tail", false},
		{"home", "/home/u/bin/app-tail", false},
		{"application bundle", "/Applications/app-tail.app/Contents/MacOS/app-tail", false},
		{"system temp", buildCacheBinary, true},
		{"unix tmp", "/tmp/app-tail", true},
		{"directory beside tmp", "/tmpfoo/app-tail", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{ExecPath: tc.execPath, Home: "/home/u"}
			warning := m.TemporaryPathWarning()
			if tc.wantWarn && warning == "" {
				t.Errorf("no warning for %q, which is a temporary build location", tc.execPath)
			}
			if !tc.wantWarn && warning != "" {
				t.Errorf("unexpected warning for %q: %s", tc.execPath, warning)
			}
			if tc.wantWarn && !strings.Contains(warning, tc.execPath) {
				t.Errorf("warning does not name the offending path: %s", warning)
			}
		})
	}
}

// On Windows the path a process reports for itself and the path the environment gives for
// the temporary directory routinely differ only in the case of the user's name. Comparing
// those byte for byte misses every binary built into that directory, which is exactly the
// install this warning exists to catch.
func TestATemporaryPathIsFoundThroughTheCaseWindowsIgnores(t *testing.T) {
	root := string(os.PathSeparator)
	recorded := filepath.Join(root, "Users", "Nate", "Temp")
	binary := filepath.Join(root, "Users", "nate", "Temp", "go-build1", "b001", "exe", "app-tail.exe")

	if !pathHasPrefix(binary, recorded, true) {
		t.Errorf("%q was not recognised as living under %q", binary, recorded)
	}
	if pathHasPrefix(binary, recorded, false) {
		t.Errorf("%q matched %q without folding case, so the folding proves nothing", binary, recorded)
	}
}

// A path is under another only by whole elements: a binary in /tmpfoo lives in its own
// directory, and warning about it would send somebody looking for a build location that
// is not there.
func TestADirectoryBesideATemporaryOneIsNotUnderIt(t *testing.T) {
	root := string(os.PathSeparator)
	if pathHasPrefix(filepath.Join(root, "tmpfoo", "app-tail"), filepath.Join(root, "tmp"), false) {
		t.Error("/tmpfoo was read as being under /tmp")
	}
	if !pathHasPrefix(filepath.Join(root, "tmp", "app-tail"), filepath.Join(root, "tmp"), false) {
		t.Error("/tmp/app-tail was not read as being under /tmp")
	}
}

// The whole point of the login item is that it survives a reboot, so installing it
// must actually leave a readable file behind and removing it must take it away.
func TestInstallingAndRemovingTheLoginItemRoundTrips(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("login-item files are only written on darwin and linux; %s uses a different mechanism", runtime.GOOS)
	}
	home := t.TempDir()
	// systemd honours XDG_CONFIG_HOME, so pin it inside the temp root or the test
	// would write into the developer's real ~/.config.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	m := testManager(home, "run", "--headless")

	enabled, err := m.Enabled()
	if err != nil {
		t.Fatalf("Enabled() before install: %v", err)
	}
	if enabled {
		t.Fatal("a fresh home reported an installed login item")
	}

	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	enabled, err = m.Enabled()
	if err != nil {
		t.Fatalf("Enabled() after install: %v", err)
	}
	if !enabled {
		t.Fatalf("login item at %s was not reported as installed", m.Path())
	}

	content, err := os.ReadFile(m.Path())
	if err != nil {
		t.Fatalf("read the installed login item: %v", err)
	}
	if !strings.Contains(string(content), m.ExecPath) {
		t.Errorf("installed login item does not name the binary:\n%s", content)
	}
	if !strings.HasPrefix(m.Path(), home) {
		t.Fatalf("login item was written to %s, outside the test home %s", m.Path(), home)
	}

	info, err := os.Stat(m.Path())
	if err != nil {
		t.Fatalf("stat the installed login item: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("login item mode = %#o, want 0644 so an operator can read it", perm)
	}

	// Reinstalling over an existing item must succeed; a user who moves the binary
	// and re-runs install-autostart should end up pointing at the new path.
	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("reinstall: %v", err)
	}

	if err := m.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	enabled, err = m.Enabled()
	if err != nil {
		t.Fatalf("Enabled() after removal: %v", err)
	}
	if enabled {
		t.Errorf("login item at %s survived removal", m.Path())
	}

	// Removing twice is what the API does when a user toggles start-at-login off
	// while it was never on.
	if err := m.SetEnabled(false); err != nil {
		t.Fatalf("second SetEnabled(false): %v", err)
	}
}

func TestNewResolvesTheRunningBinaryAndHome(t *testing.T) {
	m, err := New("run", "--headless")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("New produced a manager that cannot install: %v", err)
	}
	if want := []string{"run", "--headless"}; len(m.Args) != len(want) || m.Args[0] != want[0] || m.Args[1] != want[1] {
		t.Errorf("Args = %q, want %q", m.Args, want)
	}
	if got := m.command(); len(got) != 3 || got[0] != m.ExecPath {
		t.Errorf("command() = %q, want the executable followed by its args", got)
	}
}

func TestFileHelpersCreateReadAndRemoveWithoutSurprises(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "item.conf")

	exists, err := fileExists(path)
	if err != nil {
		t.Fatalf("fileExists on a missing path: %v", err)
	}
	if exists {
		t.Fatal("a path that was never written reported as existing")
	}

	if err := writeFile(path, "content\n"); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	exists, err = fileExists(path)
	if err != nil || !exists {
		t.Fatalf("fileExists after write = %v, %v; want true, nil", exists, err)
	}

	if err := removeFile(path); err != nil {
		t.Fatalf("removeFile: %v", err)
	}
	// Removing an absent file is success, not an error: SetEnabled(false) is called
	// unconditionally when a user toggles start-at-login off.
	if err := removeFile(path); err != nil {
		t.Fatalf("removeFile on a missing path: %v", err)
	}
}

// bootRepairDefinition is the boot-time repair task, read the way schtasks reads it.
type bootRepairDefinition struct {
	XMLName      xml.Name `xml:"Task"`
	URI          string   `xml:"RegistrationInfo>URI"`
	BootTriggers []struct {
		Enabled    string `xml:"Enabled"`
		Delay      string `xml:"Delay"`
		Repetition string `xml:"Repetition>Interval"`
	} `xml:"Triggers>BootTrigger"`
	LogonTriggers []struct {
		Enabled    string `xml:"Enabled"`
		UserID     string `xml:"UserId"`
		Repetition string `xml:"Repetition>Interval"`
	} `xml:"Triggers>LogonTrigger"`
	RunAs       string `xml:"Principals>Principal>UserId"`
	RunLevel    string `xml:"Principals>Principal>RunLevel"`
	Instances   string `xml:"Settings>MultipleInstancesPolicy"`
	TimeLimit   string `xml:"Settings>ExecutionTimeLimit"`
	OnBatteries string `xml:"Settings>DisallowStartIfOnBatteries"`
	Command     string `xml:"Actions>Exec>Command"`
	Arguments   string `xml:"Actions>Exec>Arguments"`
}

func decodeBootRepair(t *testing.T, doc string) bootRepairDefinition {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(decodeUTF16LE(t, utf16LE(doc))))
	decoder.Strict = true
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if !strings.EqualFold(charset, "UTF-16") {
			return nil, fmt.Errorf("task definition declares encoding %q, which does not match its byte-order mark", charset)
		}
		return input, nil
	}
	var task bootRepairDefinition
	if err := decoder.Decode(&task); err != nil {
		t.Fatalf("boot repair definition is not well-formed XML: %v\n%s", err, doc)
	}
	return task
}

// Windows has no helper that starts at boot, so a crash with the override in place leaves
// every adapter pointed at an address nothing listens on until somebody opens app-tail. This
// task is what puts it back first, and every field is load-bearing:
//   - a run at boot, before anyone logs in, puts back what the record names;
//   - a second run once the network is up finds the adapters the record lost, which are
//     not listed until they have an address;
//   - a run at every logon covers Fast Startup, where powering on is not a boot at all;
//   - SYSTEM, because nobody has logged in yet; no battery rule, or a laptop that booted
//     unplugged is skipped; and no repetition, since a running app-tail owns its override.
func TestTheBootRepairRunsTheRestoreAtBootOnceTheNetworkIsUpAndAtLogon(t *testing.T) {
	exe := `C:\Program Files\app-tail\app-tail.exe`

	task := decodeBootRepair(t, bootRepairTaskXML(exe))

	var atBoot, onceUp bool
	for _, trigger := range task.BootTriggers {
		if trigger.Enabled != "true" {
			t.Errorf("a boot trigger is not enabled (%q)", trigger.Enabled)
		}
		if trigger.Repetition != "" {
			t.Errorf("a boot trigger repeats every %s", trigger.Repetition)
		}
		switch trigger.Delay {
		case "":
			atBoot = true
		default:
			onceUp = true
		}
	}
	if !atBoot {
		t.Error("nothing runs the repair the moment the machine boots")
	}
	if !onceUp {
		t.Error("nothing runs the repair again once the network has had time to come up")
	}
	if len(task.LogonTriggers) != 1 {
		t.Fatalf("%d logon triggers, want 1 so a Fast Startup power-on is covered", len(task.LogonTriggers))
	}
	if logon := task.LogonTriggers[0]; logon.Enabled != "true" || logon.UserID != "" || logon.Repetition != "" {
		t.Errorf("logon trigger = %+v, want enabled, for every account, and not repeating", logon)
	}
	if task.RunAs != "S-1-5-18" || task.RunLevel != "HighestAvailable" {
		t.Errorf("runs as %q at %q, want the SYSTEM account with its full rights", task.RunAs, task.RunLevel)
	}
	if task.OnBatteries != "false" {
		t.Errorf("DisallowStartIfOnBatteries = %q, want false; a laptop that boots unplugged needs it too", task.OnBatteries)
	}
	// Bounded: a restore that hangs on a wedged adapter must not hold a SYSTEM process open
	// for as long as the machine is up.
	if task.TimeLimit == "" || task.TimeLimit == "PT0S" {
		t.Errorf("ExecutionTimeLimit = %q, want a bound", task.TimeLimit)
	}
	if task.Instances != "IgnoreNew" {
		t.Errorf("MultipleInstancesPolicy = %q, want IgnoreNew", task.Instances)
	}
	if task.URI != BootRepairTaskName {
		t.Errorf("URI = %q, want %q", task.URI, BootRepairTaskName)
	}
	if task.Command != exe || task.Arguments != "dns restore" {
		t.Errorf("runs %q %q, want %q %q", task.Command, task.Arguments, exe, "dns restore")
	}
}

func TestTheBootRepairSurvivesPathsContainingXMLMetacharacters(t *testing.T) {
	hostile := `C:\R&D\<tools>\app "tail".exe`

	if got := decodeBootRepair(t, bootRepairTaskXML(hostile)).Command; got != hostile {
		t.Errorf("executable path did not survive XML escaping: got %q, want %q", got, hostile)
	}
}
