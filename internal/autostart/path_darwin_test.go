// SPDX-License-Identifier: MIT

package autostart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// launchd only loads agents from ~/Library/LaunchAgents, and only ones whose filename
// is the label plus .plist. A path that drifted anywhere else would write a file the
// user can see, that app-tail reports as installed, and that launchd never reads --
// the login item silently stops working after the next reboot.
func TestTheLaunchAgentGoesExactlyWhereLaunchdLooksForIt(t *testing.T) {
	m := &Manager{ExecPath: "/usr/local/bin/app-tail", Home: "/Users/example"}

	got := m.Path()

	want := "/Users/example/Library/LaunchAgents/" + Label + ".plist"
	if got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
	// Spelled out separately, because a change to Label would update `want` above in
	// lockstep and hide a filename that no longer matches what launchd expects.
	if base := filepath.Base(got); !strings.HasSuffix(base, ".plist") {
		t.Errorf("Path() basename %q is not a plist; launchd ignores it", base)
	}
	if dir := filepath.Dir(got); filepath.Base(dir) != "LaunchAgents" {
		t.Errorf("Path() directory %q is not LaunchAgents; launchd never reads it", dir)
	}
}

// The path has to follow the manager's Home rather than the process's own, or a test
// -- or an install run under sudo -- writes into the wrong user's account.
func TestTheLaunchAgentPathFollowsTheManagersHome(t *testing.T) {
	home := t.TempDir()
	m := &Manager{ExecPath: "/usr/local/bin/app-tail", Home: home}

	if got := m.Path(); !strings.HasPrefix(got, home+string(filepath.Separator)) {
		t.Errorf("Path() = %q, want it under the manager's home %q", got, home)
	}
}

// installLoginItem writes a LaunchAgent naming program, the way an install done from
// that path would have left it, and returns a manager for a binary at exec.
//
// exec is spelled as a settled install location rather than a temp path, because
// t.TempDir() sits under /var/folders on macOS -- which the manager rightly treats as a
// build directory and declines to repair from. A fixture there passes for that reason
// instead of the one under test.
func installLoginItem(t *testing.T, program, exec string) *Manager {
	t.Helper()
	home := t.TempDir()
	installed := &Manager{ExecPath: program, Home: home}
	if err := installed.SetEnabled(true); err != nil {
		t.Fatalf("install the login item: %v", err)
	}
	m := &Manager{ExecPath: exec, Home: home}
	if m.TemporaryPathWarning() != "" {
		t.Fatalf("the fixture's running binary %q reads as a build path, so the test proves nothing", exec)
	}
	return m
}

// The bug this exists for: the app is installed, moves, and the plist keeps naming the
// old path. launchd fails the job with EX_CONFIG and penalty-boxes it, while Enabled()
// -- which only asks whether the file is there -- goes on reporting start-at-login as on.
// Nothing on any surface says the login item is dead.
func TestALoginItemNamingAProgramThatIsGoneIsReportedForRepair(t *testing.T) {
	// The shape of the real failure: an app-tail that used to live under the user's own
	// Applications folder and is not there any more.
	gone := filepath.Join(t.TempDir(), "Applications", "App-Tail.app", "Contents", "MacOS", "app-tail")
	here := "/opt/app-tail-fixture/App-Tail.app/Contents/MacOS/app-tail"
	m := installLoginItem(t, gone, here)

	// The state the user is actually in: installed, and useless.
	if enabled, err := m.Enabled(); err != nil || !enabled {
		t.Fatalf("Enabled() = %v, %v; want the item to look installed, which is the trap", enabled, err)
	}

	stale, err := m.NeedsReinstall()
	if err != nil {
		t.Fatalf("NeedsReinstall() errored: %v", err)
	}
	if !stale {
		t.Fatal("a login item whose program does not exist was not reported for repair; it will never start again")
	}

	// The repair has to be the one already wired at startup, not a new path.
	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("repair the login item: %v", err)
	}
	content, err := os.ReadFile(m.Path())
	if err != nil {
		t.Fatalf("read the repaired item: %v", err)
	}
	program, err := plistProgram(content)
	if err != nil {
		t.Fatalf("parse the repaired item: %v", err)
	}
	if program != here {
		t.Errorf("the repaired login item names %q, want the binary that is actually here, %q", program, here)
	}
	if stale, err := m.NeedsReinstall(); err != nil || stale {
		t.Errorf("NeedsReinstall() = %v, %v after the repair; it must settle or every start rewrites it", stale, err)
	}
}

// A second copy of app-tail running is not a broken login item. Rewriting the plist to
// name whichever binary happened to start last would move the user's login item without
// being asked -- a worse bug than the dead-path one, and a silent one.
func TestALoginItemNamingADifferentBinaryThatExistsIsLeftAlone(t *testing.T) {
	installed := filepath.Join(t.TempDir(), "installed-app-tail")
	if err := os.WriteFile(installed, []byte("binary"), 0o755); err != nil {
		t.Fatalf("create the installed binary: %v", err)
	}
	m := installLoginItem(t, installed, "/opt/app-tail-fixture/other-app-tail")

	stale, err := m.NeedsReinstall()
	if err != nil {
		t.Fatalf("NeedsReinstall() errored: %v", err)
	}
	if stale {
		t.Error("a login item pointing at a binary that exists was reported stale; the repair would hijack it")
	}
}

// Whether the item is broken and whether this copy of app-tail should rewrite it are two
// questions. Answering the first with the second -- staying quiet because the running
// binary sits in a build directory -- leaves every reporting surface unable to mention a
// login item that is already dead. Declining the rewrite is the caller's job.
func TestADeadLoginItemIsStillReportedFromATemporaryBuildPath(t *testing.T) {
	home := t.TempDir()
	gone := filepath.Join(t.TempDir(), "App-Tail.app", "Contents", "MacOS", "app-tail")
	if err := (&Manager{ExecPath: gone, Home: home}).SetEnabled(true); err != nil {
		t.Fatalf("install the login item: %v", err)
	}
	// Installed by the guarded helper everywhere else; spelled out here because this is
	// the one test whose running binary has to be a build path.
	m := &Manager{ExecPath: "/private/var/folders/zz/go-build123/b001/exe/app-tail", Home: home}
	if m.TemporaryPathWarning() == "" {
		t.Fatal("the fixture path is not treated as temporary, so this proves nothing")
	}

	stale, err := m.NeedsReinstall()
	if err != nil {
		t.Fatalf("NeedsReinstall() errored: %v", err)
	}
	if !stale {
		t.Error("a dead login item went unreported because the running binary was a build; nothing else would mention it")
	}
}

// Never installed means nothing to correct. Reporting stale would have the startup
// correction install a login item the user never asked for.
func TestNoLoginItemIsNotAStaleOne(t *testing.T) {
	m := &Manager{ExecPath: "/usr/local/bin/app-tail", Home: t.TempDir()}

	stale, err := m.NeedsReinstall()
	if err != nil {
		t.Fatalf("NeedsReinstall() errored: %v", err)
	}
	if stale {
		t.Error("an absent login item was reported stale; the correction would create one unasked")
	}
}

// The program is read back out of a real plist, so the parser has to survive the shapes
// launchd itself accepts rather than only the exact bytes this app writes.
func TestTheProgramIsReadOutOfWhateverShapeThePlistIsIn(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			"the file this app writes",
			(&Manager{ExecPath: "/Applications/App-Tail.app/Contents/MacOS/app-tail", Home: "/h"}).plist(),
			"/Applications/App-Tail.app/Contents/MacOS/app-tail",
		},
		{
			// The first entry is the program; the rest are its arguments.
			"a program carrying arguments",
			`<plist version="1.0"><dict><key>ProgramArguments</key><array>` +
				`<string>/opt/app-tail</string><string>--headless</string></array></dict></plist>`,
			"/opt/app-tail",
		},
		{
			// A path with an ampersand is stored escaped; comparing it against a real
			// filename means it has to come back unescaped.
			"a path that had to be escaped",
			`<plist version="1.0"><dict><key>ProgramArguments</key><array>` +
				`<string>/Users/a&amp;b/app-tail</string></array></dict></plist>`,
			"/Users/a&b/app-tail",
		},
		{
			// Keys before it must not be mistaken for the program, or the check compares
			// against the label and calls every item stale.
			"keys ahead of the one that matters",
			`<plist version="1.0"><dict><key>Label</key><string>com.example.thing</string>` +
				`<key>ProgramArguments</key><array><string>/opt/app-tail</string></array></dict></plist>`,
			"/opt/app-tail",
		},
		{
			"someone else's plist with no program at all",
			`<plist version="1.0"><dict><key>RunAtLoad</key><true/></dict></plist>`,
			"",
		},
		{
			"the key present but the array empty",
			`<plist version="1.0"><dict><key>ProgramArguments</key><array></array></dict></plist>`,
			"",
		},
		{
			// The array has to be closed as well as opened, or the next scalar in the file
			// is taken for the program: here that is the label, which stats as missing and
			// makes a perfectly good login item look dead enough to overwrite.
			"an empty array followed by an ordinary value",
			`<plist version="1.0"><dict><key>ProgramArguments</key><array></array>` +
				`<key>Label</key><string>com.sellitus.app-tail</string></dict></plist>`,
			"",
		},
		{
			// Same trap from the other side: values belonging to keys that come after the
			// program list must not be picked up once it has been read past.
			"an array for another key after the program list",
			`<plist version="1.0"><dict><key>ProgramArguments</key><array></array>` +
				`<key>WatchPaths</key><array><string>/etc/watched</string></array></dict></plist>`,
			"",
		},
		{
			"a string-valued key ahead of an array that is not the program list",
			`<plist version="1.0"><dict><key>Label</key><string>com.example.thing</string>` +
				`<key>WatchPaths</key><array><string>/etc/watched</string></array></dict></plist>`,
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := plistProgram([]byte(tc.content))
			if err != nil {
				t.Fatalf("plistProgram() errored: %v", err)
			}
			if got != tc.want {
				t.Errorf("plistProgram() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A plist that cannot be read is not evidence that the program is gone. Guessing "stale"
// would rewrite a file this app does not understand; guessing "fine" would hide the
// failure. It says so instead.
func TestAnUnreadablePlistIsReportedRatherThanGuessedAt(t *testing.T) {
	home := t.TempDir()
	m := &Manager{ExecPath: "/usr/local/bin/app-tail", Home: home}
	if err := os.MkdirAll(filepath.Dir(m.Path()), 0o755); err != nil {
		t.Fatalf("create the LaunchAgents directory: %v", err)
	}
	if err := os.WriteFile(m.Path(), []byte("<plist><dict><key>ProgramArguments"), 0o644); err != nil {
		t.Fatalf("write the truncated plist: %v", err)
	}

	stale, err := m.NeedsReinstall()
	if err == nil {
		t.Fatal("a malformed login item was judged silently; the failure has to reach the log")
	}
	if stale {
		t.Error("a malformed login item was reported stale, which would overwrite it")
	}
}

// The sentence is what a person is left with when the login item is dead, and it is the
// only place the cause is stated -- the CLI prints it verbatim beside the remedy. Naming
// neither the fault nor the thing that moved would leave them with "reinstall it" alone.
func TestTheStaleReasonSaysWhatWentWrong(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "Applications", "App-Tail.app", "Contents", "MacOS", "app-tail")
	reason := installLoginItem(t, gone, "/opt/app-tail-fixture/App-Tail.app/Contents/MacOS/app-tail").ReinstallReason()

	if reason == "" {
		t.Fatal("no reason given for a stale login item")
	}
	for _, want := range []string{"no longer there", "launchd"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not mention %q, so it does not say what happened: %q", want, reason)
		}
	}
}

// Every failure to read the item has to surface. Reporting "not stale" for a login item
// that could not be inspected is the same false all-clear as the one this whole change
// exists to remove, and reporting "stale" would overwrite a file nobody could read.
func TestALoginItemThatCannotBeInspectedIsAnError(t *testing.T) {
	t.Run("a manager with nothing to work from", func(t *testing.T) {
		if _, err := (&Manager{}).NeedsReinstall(); err == nil {
			t.Error("a manager with no exec path or home judged the login item anyway")
		}
	})

	t.Run("an item that exists but cannot be read", func(t *testing.T) {
		home := t.TempDir()
		m := &Manager{ExecPath: "/usr/local/bin/app-tail", Home: home}
		// A directory where the plist should be: it passes the existence check and then
		// fails to read, which is the shape of a half-installed or clobbered item.
		if err := os.MkdirAll(m.Path(), 0o755); err != nil {
			t.Fatalf("create the directory standing in for the plist: %v", err)
		}

		stale, err := m.NeedsReinstall()
		if err == nil {
			t.Error("an unreadable login item was judged silently")
		}
		if stale {
			t.Error("an unreadable login item was reported stale, which would overwrite it")
		}
	})

	t.Run("a program whose path cannot be stat-ed", func(t *testing.T) {
		// A path continuing through a regular file: not "absent" but "unanswerable", and
		// the two must not collapse into each other.
		file := filepath.Join(t.TempDir(), "regular")
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatalf("create the regular file: %v", err)
		}
		m := installLoginItem(t, filepath.Join(file, "app-tail"), "/opt/app-tail-fixture/app-tail")

		stale, err := m.NeedsReinstall()
		if err == nil {
			t.Error("a program path that could not be stat-ed was judged silently")
		}
		if stale {
			t.Error("a program that could not be stat-ed was reported gone")
		}
	})
}

// The parser is fed whatever is on disk, including files this app never wrote. A parse
// failure has to reach the caller: swallowed, it becomes "no program", which reads as a
// login item that is fine.
func TestAPlistThatCannotBeParsedIsReportedRatherThanReadAsEmpty(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"a document that is not XML at all", "\x00\x01binary plist garbage <<>>"},
		{"a tag that never closes", `<plist><dict><key>ProgramArguments</key><array>`},
		{"the program itself cut off mid-value", `<plist><dict><key>ProgramArguments</key><array><string>/opt/app`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			program, err := plistProgram([]byte(tc.content))
			if err == nil {
				t.Errorf("parsed %q without complaint, returning %q", tc.content, program)
			}
			if program != "" {
				t.Errorf("returned a program %q from a document it could not parse", program)
			}
		})
	}
}

// Problem is what the settings page prints beside a switch that reads as on. A login item
// that starts app-tail correctly must leave it empty, or every user is told something is
// wrong with an install that works.
func TestAWorkingLoginItemIsReportedAsHavingNoProblem(t *testing.T) {
	here := "/opt/app-tail-fixture/App-Tail.app/Contents/MacOS/app-tail"
	m := installLoginItem(t, here, here)

	if problem := m.Problem(); problem != "" {
		t.Errorf("a login item naming the running binary reported the problem %q", problem)
	}
}

// A dead login item reported from a build directory has two things wrong with it, and the
// one worth printing is the one the user can act on: reinstalling from a path that will not
// be there after a reboot repairs nothing.
func TestADeadLoginItemFromABuildPathSaysToInstallSomewhereStable(t *testing.T) {
	home := t.TempDir()
	gone := filepath.Join(t.TempDir(), "App-Tail.app", "Contents", "MacOS", "app-tail")
	if err := (&Manager{ExecPath: gone, Home: home}).SetEnabled(true); err != nil {
		t.Fatalf("install the login item: %v", err)
	}
	m := &Manager{ExecPath: "/private/var/folders/zz/go-build123/b001/exe/app-tail", Home: home}

	problem := m.Problem()

	if !strings.Contains(problem, "temporary build location") {
		t.Errorf("the problem given is %q, want it to name the build location as what to fix first", problem)
	}
}

// The same dead item, this time from a copy of app-tail that is where it will stay: the
// repair is the one command that fixes it, so the problem has to name it.
func TestADeadLoginItemFromASettledPathSaysHowToRepairIt(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "Applications", "App-Tail.app", "Contents", "MacOS", "app-tail")
	here := "/opt/app-tail-fixture/App-Tail.app/Contents/MacOS/app-tail"
	m := installLoginItem(t, gone, here)

	problem := m.Problem()

	if !strings.Contains(problem, "install-autostart") {
		t.Errorf("the problem given is %q, want it to name the command that repairs the login item", problem)
	}
}

// installBackgroundLoginItem writes the LaunchAgent app-tail installed before it asked
// launchd for an unthrottled class: the same item, carrying ProcessType Background.
func installBackgroundLoginItem(t *testing.T, program, exec string) *Manager {
	t.Helper()
	m := installLoginItem(t, program, exec)
	content, err := os.ReadFile(m.Path())
	if err != nil {
		t.Fatalf("read the installed item: %v", err)
	}
	current := "<key>ProcessType</key>\n\t<string>" + launchdProcessType + "</string>"
	if !strings.Contains(string(content), current) {
		t.Fatalf("the installed item does not carry ProcessType %s, so the fixture cannot age it:\n%s", launchdProcessType, content)
	}
	aged := strings.Replace(string(content), current, "<key>ProcessType</key>\n\t<string>Background</string>", 1)
	if err := os.WriteFile(m.Path(), []byte(aged), 0o644); err != nil {
		t.Fatalf("write the background item: %v", err)
	}
	return m
}

// The bug this exists for: launchd runs a Background job at the lowest priority on the
// efficiency cores, and the agent relays every interactive packet on this machine. With a
// build saturating those cores, keystrokes over SSH through the tailnet stalled for
// seconds while the network itself answered in milliseconds. An item installed by an
// older app-tail keeps that class until it is rewritten, so the startup repair has to
// see it.
func TestALoginItemRunningThisBinaryAsABackgroundJobIsReportedForRepair(t *testing.T) {
	here := "/opt/app-tail-fixture/App-Tail.app/Contents/MacOS/app-tail"
	m := installBackgroundLoginItem(t, here, here)

	stale, err := m.NeedsReinstall()
	if err != nil {
		t.Fatalf("NeedsReinstall() errored: %v", err)
	}
	if !stale {
		t.Fatal("a login item running app-tail as a throttled Background job was not reported for repair")
	}
	reason := m.ReinstallReason()
	for _, want := range []string{launchdProcessType, "throttle"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not mention %q, so it does not say what is wrong: %q", want, reason)
		}
	}
	if strings.Contains(reason, "no longer there") {
		t.Errorf("the reason blames a vanished program for an item whose program is right here: %q", reason)
	}

	// The startup repair is SetEnabled(true); it has to settle the item, not loop on it.
	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("repair the login item: %v", err)
	}
	content, err := os.ReadFile(m.Path())
	if err != nil {
		t.Fatalf("read the repaired item: %v", err)
	}
	if processType, err := plistProcessType(content); err != nil || processType != launchdProcessType {
		t.Errorf("the repaired item's ProcessType = %q, %v; want %q", processType, err, launchdProcessType)
	}
	if stale, err := m.NeedsReinstall(); err != nil || stale {
		t.Errorf("NeedsReinstall() = %v, %v after the repair; it must settle or every start rewrites it", stale, err)
	}
}

// Another copy's login item is still not this one's to rewrite, whatever class it runs
// in: correcting its ProcessType would also re-point it at whichever binary started last.
func TestABackgroundLoginItemNamingADifferentBinaryThatExistsIsLeftAlone(t *testing.T) {
	installed := filepath.Join(t.TempDir(), "installed-app-tail")
	if err := os.WriteFile(installed, []byte("binary"), 0o755); err != nil {
		t.Fatalf("create the installed binary: %v", err)
	}
	m := installBackgroundLoginItem(t, installed, "/opt/app-tail-fixture/other-app-tail")

	stale, err := m.NeedsReinstall()
	if err != nil {
		t.Fatalf("NeedsReinstall() errored: %v", err)
	}
	if stale {
		t.Error("another copy's login item was reported stale for its ProcessType; the repair would hijack it")
	}
}

// launchd reads a missing ProcessType as Standard, which still throttles CPU and I/O, so
// only the class the template writes counts as current.
func TestTheProcessTypeIsReadOutOfThePlist(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			"the file this app writes",
			(&Manager{ExecPath: "/Applications/App-Tail.app/Contents/MacOS/app-tail", Home: "/h"}).plist(),
			launchdProcessType,
		},
		{
			"an item with no ProcessType",
			`<plist version="1.0"><dict><key>Label</key><string>com.sellitus.app-tail</string></dict></plist>`,
			"",
		},
		{
			// A string inside the program list must not be taken for the class.
			"program arguments ahead of the key",
			`<plist version="1.0"><dict><key>ProgramArguments</key><array><string>Interactive</string></array>` +
				`<key>ProcessType</key><string>Background</string></dict></plist>`,
			"Background",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := plistProcessType([]byte(tc.content))
			if err != nil {
				t.Fatalf("plistProcessType() errored: %v", err)
			}
			if got != tc.want {
				t.Errorf("plistProcessType() = %q, want %q", got, tc.want)
			}
		})
	}
	for _, broken := range []string{
		"\x00\x01binary plist garbage <<>>",
		`<plist><dict><key>Process`,
		`<plist><dict><key>ProcessType</key><string>Inter`,
	} {
		if processType, err := plistProcessType([]byte(broken)); err == nil {
			t.Errorf("%q was read without complaint, returning %q; the failure has to reach the caller", broken, processType)
		}
	}
}

// An item whose program reads as this binary but whose class cannot be read is not known
// to be throttled. Rewriting it would overwrite a file nobody understood, and calling it
// fine would hide the failure, so both the check and the reason have to say so.
func TestALoginItemWhoseProcessTypeCannotBeReadIsReportedRatherThanGuessedAt(t *testing.T) {
	here := "/opt/app-tail-fixture/App-Tail.app/Contents/MacOS/app-tail"
	m := &Manager{ExecPath: here, Home: t.TempDir()}
	if err := os.MkdirAll(filepath.Dir(m.Path()), 0o755); err != nil {
		t.Fatalf("create the LaunchAgents directory: %v", err)
	}
	truncated := `<plist><dict><key>ProgramArguments</key><array><string>` + here +
		`</string></array><key>ProcessType</key><string>Inter`
	if err := os.WriteFile(m.Path(), []byte(truncated), 0o644); err != nil {
		t.Fatalf("write the truncated plist: %v", err)
	}

	stale, err := m.NeedsReinstall()
	if err == nil {
		t.Error("a login item whose class could not be read was judged silently")
	}
	if stale {
		t.Error("a login item whose class could not be read was reported stale, which would overwrite it")
	}
	if reason := m.ReinstallReason(); !strings.Contains(reason, "could not be read") {
		t.Errorf("the reason %q hides that the item could not be read", reason)
	}
}
