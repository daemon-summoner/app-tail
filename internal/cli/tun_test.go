// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/grants"
	"github.com/sellitus/app-tail/internal/hostnet"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// captureTunEnv builds an Env whose output a test can read back.
func captureTunEnv() (Env, *bytes.Buffer) {
	var out bytes.Buffer
	return Env{
		Stdout: &out,
		Stderr: &bytes.Buffer{},
		Getenv: func(string) string { return "" },
	}, &out
}

// The doctor is what someone runs when they suspect app-tail changed their machine, and
// the answer they need is one sentence, not a table of booleans. Each combination reaches
// a different one, and the wrong one sends them to the wrong remedy: installing a helper
// on a platform that has none, or looking for a socket that was never meant to exist.
func TestEveryHelperStateReachesItsOwnSentence(t *testing.T) {
	tests := []struct {
		name       string
		report     tsnode.InterfaceReport
		wantPhrase string
	}{
		{
			name: "a helper that answered",
			report: tsnode.InterfaceReport{Helper: tsnode.InterfaceHelperReport{
				Design: true, Installable: true, Installed: true, Running: true,
			}},
			wantPhrase: "installed and answering",
		},
		{
			name: "one that is installed and does not answer",
			report: tsnode.InterfaceReport{Helper: tsnode.InterfaceHelperReport{
				Design: true, Installable: true, Installed: true,
			}},
			wantPhrase: "not answering",
		},
		{
			// The command that needs no terminal and no sudo, because a machine
			// that can install it for you should not be told to go and do it.
			name: "one that was never installed",
			report: tsnode.InterfaceReport{Helper: tsnode.InterfaceHelperReport{
				Design: true, Installable: true,
			}},
			wantPhrase: "app-tail tun setup",
		},
		{
			name:       "a platform with the design but no installer",
			report:     tsnode.InterfaceReport{Helper: tsnode.InterfaceHelperReport{Design: true}},
			wantPhrase: "sudo app-tail tun helper",
		},
		{
			name:       "a platform that elevates instead",
			report:     tsnode.InterfaceReport{Helper: tsnode.InterfaceHelperReport{}},
			wantPhrase: "asks for administrator rights",
		},
		{
			name:       "and one that already has them",
			report:     tsnode.InterfaceReport{Privileged: true},
			wantPhrase: "already has the rights",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tunHelperWord(tt.report)
			if !strings.Contains(got, tt.wantPhrase) {
				t.Errorf("the report said %q, which does not mention %q", got, tt.wantPhrase)
			}
		})
	}
}

// A platform that cannot carry an interface must say so and stop, rather than print a
// table of states that are all beside the point.
func TestAnUnsupportedPlatformSaysOnlyThat(t *testing.T) {
	env, out := captureTunEnv()
	report := tsnode.InterfaceReport{Platform: "plan9", Supported: false}
	if err := writeTunReport(env, report); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "plan9") {
		t.Errorf("the report %q does not name the platform", text)
	}
	if !strings.Contains(text, "contained mode") {
		t.Errorf("the report %q does not say what does work here", text)
	}
	if strings.Contains(text, "Helper socket") {
		t.Errorf("the report %q describes a helper on a platform that has no interface mode", text)
	}
}

// The one situation the doctor exists for is the one where app-tail is not the thing that
// will clean up, so the leftovers have to arrive with the commands that remove them.
func TestLeftoversArriveWithTheCommandsThatRemoveThem(t *testing.T) {
	env, out := captureTunEnv()
	report := tsnode.InterfaceReport{
		Platform:  "darwin",
		Supported: true,
		Leftovers: []string{"/etc/resolver/example.ts.net"},
		Undo:      []string{"sudo rm /etc/resolver/example.ts.net", "sudo killall -HUP mDNSResponder"},
	}
	if err := writeTunReport(env, report); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	text := out.String()
	for _, want := range append(report.Leftovers, report.Undo...) {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not mention %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "This machine is clean") {
		t.Errorf("the report called a machine with leftovers clean:\n%s", text)
	}
}

// The reassurance is the answer to the question people actually have, and it has to be
// withheld the moment there is anything to report.
func TestACleanMachineIsSaidToBeClean(t *testing.T) {
	env, out := captureTunEnv()
	report := tsnode.InterfaceReport{Platform: "darwin", Supported: true}
	if err := writeTunReport(env, report); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	if !strings.Contains(out.String(), "This machine is clean") {
		t.Errorf("a machine with nothing on it was not reported as clean:\n%s", out.String())
	}
}

// A resolver a previous run left redirected is the one change that outlives the process
// that made it, and this command is where somebody asks what app-tail has done to their
// machine. Calling that machine clean is how a user ends up with nothing resolving and
// nothing telling them why.
func TestAMachineLeftResolvingThroughAppTailIsNotCalledClean(t *testing.T) {
	env, out := captureTunEnv()
	report := tsnode.InterfaceReport{
		Platform:      "darwin",
		Supported:     true,
		StaleOverride: "this machine's name resolution is still pointed at app-tail from an earlier run",
	}
	if err := writeTunReport(env, report); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "still pointed at app-tail") {
		t.Errorf("the report does not say the resolver is redirected:\n%s", text)
	}
	if !strings.Contains(text, "app-tail dns restore") {
		t.Errorf("the report names no way to put the resolver back:\n%s", text)
	}
	if strings.Contains(text, "This machine is clean") {
		t.Errorf("a machine still resolving through app-tail was reported as clean:\n%s", text)
	}
}

// A conflicting client is what stops the mode working at all, so it cannot be folded into
// the table -- and it must not be confused with the machine being clean, which it also is.
func TestAConflictingClientIsCalledOutOnItsOwn(t *testing.T) {
	env, out := captureTunEnv()
	report := tsnode.InterfaceReport{
		Platform:  "darwin",
		Supported: true,
		Conflict:  "the official Tailscale client is running on this machine",
	}
	if err := writeTunReport(env, report); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "official Tailscale client") {
		t.Errorf("the report does not name the conflict:\n%s", text)
	}
	if strings.Contains(text, "This machine is clean") {
		t.Errorf("a machine with another client running was reported as clean:\n%s", text)
	}
}

// A component that is not installed is the one thing the doctor can report that the user
// fixes by adding something rather than by stopping something, so it must not be folded
// into the conflict line -- and a machine missing one is not clean, however empty it is.
func TestAMissingComponentIsReportedAsSomethingToInstall(t *testing.T) {
	env, out := captureTunEnv()
	report := tsnode.InterfaceReport{
		Platform:  "windows",
		Supported: true,
		Missing:   "wintun.dll is not next to app-tail.exe",
	}
	if err := writeTunReport(env, report); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "wintun.dll") {
		t.Errorf("the report does not name the missing component:\n%s", text)
	}
	if strings.Contains(text, "This machine is clean") {
		t.Errorf("a machine missing what the mode needs was reported as clean:\n%s", text)
	}
}

// The recorded owner is the entire access control on a socket the root helper listens on.
// Getting it wrong is not cosmetic: too permissive hands out root, and unresolvable is a
// helper that refuses everything. So every ambiguous case is a refusal rather than a guess.
func TestTheHelpersOwnerIsResolvedOrRefused(t *testing.T) {
	tests := []struct {
		name       string
		flag       string
		sudoUID    string
		want       int
		wantErr    bool
		wantPhrase string
	}{
		{name: "the account that ran sudo", sudoUID: "501", want: 501},
		{name: "an explicit account wins over it", flag: "1000", sudoUID: "501", want: 1000},
		{name: "surrounding space is not a mistake", sudoUID: " 501\n", want: 501},
		{
			name: "no account at all is a refusal", wantErr: true,
			wantPhrase: "could not tell which account",
		},
		{
			name: "root is not an account the helper serves", sudoUID: "0",
			wantErr: true, wantPhrase: "root is not one",
		},
		{
			name: "and neither is something that is not a number", sudoUID: "nobody",
			wantErr: true, wantPhrase: "read the user id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := Env{Getenv: func(name string) string {
				if name == "SUDO_UID" {
					return tt.sudoUID
				}
				return ""
			}}
			got, err := helperOwner(env, tt.flag)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("helperOwner accepted %q, which would install a helper serving the wrong account", tt.sudoUID)
				}
				if !strings.Contains(err.Error(), tt.wantPhrase) {
					t.Errorf("the refusal said %q, which does not mention %q", err, tt.wantPhrase)
				}
				return
			}
			if err != nil {
				t.Fatalf("helperOwner: %v", err)
			}
			if got != tt.want {
				t.Errorf("helperOwner = %d, want %d", got, tt.want)
			}
		})
	}
}

// The line printed after an install is the next thing anyone will run, so it is checked by
// running it: every flag resolved against the registry, every value parsed, and the result
// applied. A hint naming a setting that was renamed, or a value the field does not take,
// turns a successful install into "unknown setting" -- and it is printed at the one moment
// a user has no idea what to do next.
func TestTheCommandPrintedAfterAnInstallTurnsTheModeOn(t *testing.T) {
	fields := strings.Fields(tunEnableCommand)
	patch := map[string]json.RawMessage{}
	for _, arg := range fields {
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		name, value, ok := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !ok {
			t.Fatalf("%q is not a --name=value pair, so `settings set` would not read it", arg)
		}
		field, known := config.SettingByName(name)
		if !known {
			t.Fatalf("the hint sets %q, which is not a setting this build has", name)
		}
		if field.Write != config.WritePatch {
			t.Errorf("the hint sets %q, which `settings set` will not write", name)
		}
		key, parsed, err := config.ParseSettingValue(name, value)
		if err != nil {
			t.Fatalf("the hint gives %s the value %q, which it does not take: %v", name, value, err)
		}
		raw, err := json.Marshal(parsed)
		if err != nil {
			t.Fatalf("encode %s: %v", name, err)
		}
		patch[key] = raw
	}
	if len(patch) == 0 {
		t.Fatal("the hint sets nothing at all")
	}

	cfg := config.Defaults()
	if err := config.ApplyPatchTo(cfg, patch); err != nil {
		t.Fatalf("the command printed after an install was refused: %v", err)
	}
	// The store validates what a patch produced before writing it, so a command that
	// applies cleanly and does not validate still fails for the person who ran it.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the command printed after an install produced settings the app will not store: %v", err)
	}
	if !cfg.Settings.TunSelected() {
		t.Error("the command printed after an install left the mode off")
	}
}

// The doctor is what someone runs when they suspect app-tail changed their machine, so it
// is the one command that must be safe to run on a machine in any state -- including one
// where nothing is installed and nothing is running. It reports; it never installs, never
// removes and never starts anything.
func TestTheDoctorReportsThisMachineWithoutChangingIt(t *testing.T) {
	installedBefore := hostnet.HelperInstalled()

	t.Run("as a report", func(t *testing.T) {
		env, out := captureTunEnv()
		if err := runTun(t.Context(), []string{"doctor"}, env); err != nil {
			t.Fatalf("tun doctor: %v", err)
		}
		if !strings.Contains(out.String(), runtime.GOOS) {
			t.Errorf("the report does not name the platform it ran on:\n%s", out.String())
		}
	})

	t.Run("as JSON", func(t *testing.T) {
		env, out := captureTunEnv()
		if err := runTun(t.Context(), []string{"doctor", "--json"}, env); err != nil {
			t.Fatalf("tun doctor --json: %v", err)
		}
		var report tsnode.InterfaceReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatalf("the JSON report does not parse: %v\n%s", err, out.String())
		}
		if report.Platform != runtime.GOOS {
			t.Errorf("the report names platform %q, want %q", report.Platform, runtime.GOOS)
		}
		if report.Supported != hostnet.Supported() {
			t.Errorf("the report says the mode is available = %t, want %t", report.Supported, hostnet.Supported())
		}
	})

	// With no arguments at all, because that is what someone types first.
	t.Run("with no subcommand", func(t *testing.T) {
		env, out := captureTunEnv()
		if err := runTun(t.Context(), nil, env); err != nil {
			t.Fatalf("tun: %v", err)
		}
		if out.Len() == 0 {
			t.Error("a bare `tun` printed nothing")
		}
	})

	if hostnet.HelperInstalled() != installedBefore {
		t.Errorf("running the doctor changed whether the helper is installed: %t -> %t",
			installedBefore, hostnet.HelperInstalled())
	}
}

// The subcommands are the whole of what this command does, and a name that falls through
// to something else is worse than one that is refused: `tun uninstall` silently running
// the doctor would look like a successful removal.
func TestAnUnknownTunSubcommandIsRefusedByName(t *testing.T) {
	env, _ := captureTunEnv()
	err := runTun(t.Context(), []string{"uninstall"}, env)
	if err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
	if !strings.Contains(err.Error(), "uninstall") {
		t.Errorf("the refusal said %q, which does not name what was asked for", err)
	}
	if !strings.Contains(err.Error(), "uninstall-helper") {
		t.Errorf("the refusal said %q, which does not list what is available", err)
	}
}

// The setup command is the one this whole path exists to offer, so it has to be reachable
// by that name. Registering it wrongly leaves `app-tail tun setup` answering "unknown
// subcommand" -- and the message that sends people here names it, so they would be told to
// run a command that does not work.
//
// It is driven to the argument check rather than through to the install: a real run raises
// the system's password dialog, which a suite must never do. Reaching a complaint about
// the argument is proof the dispatch found the command, since the fallthrough arm cannot
// produce one.
func TestTheSetupCommandIsReachableByTheNameEverythingElsePrints(t *testing.T) {
	env, _ := captureTunEnv()
	err := runTun(t.Context(), []string{"setup", "an-argument-it-takes-none-of"}, env)
	if err == nil {
		t.Fatal("`tun setup` accepted a positional argument")
	}
	if strings.Contains(err.Error(), "unknown tun subcommand") {
		t.Fatalf("`tun setup` is not registered: %v", err)
	}
	if !strings.Contains(err.Error(), "tun setup") {
		t.Errorf("the refusal said %q, which does not name the command it came from", err)
	}
}

// The list in the refusal is how somebody who mistyped finds the right name, so a command
// missing from it is a command they will not discover.
func TestAMistypedSubcommandNamesEveryRealOne(t *testing.T) {
	env, _ := captureTunEnv()
	err := runTun(t.Context(), []string{"instal-helper"}, env)
	if err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
	for _, name := range []string{"tun doctor", "tun setup", "tun install-helper", "tun uninstall-helper", "tun grant"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal %q does not mention `%s`", err, name)
		}
	}
}

// A setup that worked is the moment somebody expects the mode to start working, and it does
// not: the node is rebuilt for that. Ending without saying so leaves a machine that is ready
// and a user who thinks it is on.
func TestASuccessfulSetupSaysWhatIsStillLeftToDo(t *testing.T) {
	env, out := captureTunEnv()
	logged := 0
	mayElevate := false

	err := tunSetup(t.Context(), nil, env, true, func(_ context.Context, logf func(string, ...any), may bool, _ string) error {
		// The privileged side reports what it half-did through this, so a command that
		// passed a log nothing reads would drop it.
		logf("no previous helper was unloaded")
		mayElevate = may
		logged++
		return nil
	})

	if err != nil {
		t.Fatalf("tunSetup = %v, want a machine that is ready", err)
	}
	if logged != 1 {
		t.Errorf("the setup was performed %d times, want once", logged)
	}
	// Raising the dialog is what somebody ran this command for, so withholding it here
	// would make the command a no-op on every machine that needs it.
	if !mayElevate {
		t.Error("the setup command was not allowed to ask for administrator rights, so it can arrange nothing")
	}
	if !strings.Contains(out.String(), tunEnableCommand) {
		t.Errorf("the setup finished with %q, which does not say how to turn the mode on", out)
	}
	// The dialog is about to appear, and a password prompt nobody was warned about is one
	// people cancel.
	if !strings.Contains(out.String(), "password") {
		t.Errorf("the setup started with %q, which does not warn that macOS will ask for a password", out)
	}
}

// Setting the machine up from a config file also approves what that config uses, in the same
// dialog, so the mode it is being set up for is not refused the first thing it asks for.
func TestSetupGivenAConfigPassesItOnSoTheSameDialogApprovesWhatItUses(t *testing.T) {
	env, out := captureTunEnv()
	config := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write the config: %v", err)
	}
	var got string
	err := tunSetup(t.Context(), []string{"--config", config}, env, true, func(_ context.Context, _ func(string, ...any), _ bool, configPath string) error {
		got = configPath
		return nil
	})
	if err != nil {
		t.Fatalf("tunSetup = %v", err)
	}
	if got != config {
		t.Errorf("the setup was given config %q, want %q", got, config)
	}
	if !strings.Contains(out.String(), "also approve") {
		t.Errorf("the setup said %q, which does not warn that the password also approves the config's changes", out)
	}
}

// A config named on the command line that is not there is a mistake, found before the dialog
// rather than inside it.
func TestSetupGivenAConfigThatIsNotThereStopsBeforeTheDialog(t *testing.T) {
	env, _ := captureTunEnv()
	provisioned := 0
	err := tunSetup(t.Context(), []string{"--config", filepath.Join(t.TempDir(), "missing.json")}, env, true,
		func(context.Context, func(string, ...any), bool, string) error {
			provisioned++
			return nil
		})
	if !errors.Is(err, ErrUsage) {
		t.Errorf("got %v, want a usage error naming the missing config", err)
	}
	if provisioned != 0 {
		t.Errorf("the dialog was raised %d times for a config that is not there", provisioned)
	}
}

// Declining is a decision, not a breakage. Reporting it as a failed command leaves somebody
// looking for what went wrong with a machine that is working exactly as they chose.
func TestDecliningTheDialogSaysTheAppKeepsWorking(t *testing.T) {
	env, _ := captureTunEnv()

	err := tunSetup(t.Context(), nil, env, true, func(context.Context, func(string, ...any), bool, string) error {
		return hostnet.ErrDeclined
	})

	if err == nil {
		t.Fatal("a declined setup was reported as a machine that is ready")
	}
	if !strings.Contains(err.Error(), "declined") || !strings.Contains(err.Error(), "contained mode") {
		t.Errorf("the refusal said %q, which does not say the choice was honoured and what still works", err)
	}
}

// Any other failure is the machine's own, and its words are the only thing anyone can act
// on. Replacing them with the declined sentence would be worse than saying nothing.
func TestAFailedSetupCarriesWhatTheMachineSaid(t *testing.T) {
	env, _ := captureTunEnv()

	err := tunSetup(t.Context(), nil, env, true, func(context.Context, func(string, ...any), bool, string) error {
		return errors.New("write the helper's launch configuration: read-only file system")
	})

	if err == nil {
		t.Fatal("a failed setup was reported as a machine that is ready")
	}
	if !strings.Contains(err.Error(), "read-only file system") {
		t.Errorf("the failure said %q, which does not carry what the machine said", err)
	}
}

// A mistyped flag must stop the command rather than be ignored: this one raises a password
// dialog, and the wrong thing to do with an invocation nobody can read is to run it anyway.
func TestAMistypedFlagStopsTheSetupBeforeItAsksForAnything(t *testing.T) {
	env, out := captureTunEnv()
	provisioned := 0

	err := tunSetup(t.Context(), []string{"--no-prompt"}, env, true, func(context.Context, func(string, ...any), bool, string) error {
		provisioned++
		return nil
	})

	if err == nil {
		t.Fatal("an unreadable invocation was run anyway")
	}
	if !errors.Is(err, ErrUsage) {
		t.Errorf("the refusal is %v, which main would report as a failed command rather than a misuse", err)
	}
	if provisioned != 0 {
		t.Errorf("the setup ran %d times for an invocation that could not be read", provisioned)
	}
	if out.String() != "" {
		t.Errorf("the refusal was preceded by %q, which describes a dialog that never appears", out)
	}
}

// On a platform with no install step the command must refuse before it says a dialog is
// coming, because none is: printing the warning and then failing describes a prompt that
// was never going to appear.
func TestSetupOnAPlatformWithNoInstallerRefusesBeforePromisingADialog(t *testing.T) {
	env, out := captureTunEnv()
	provisioned := 0

	err := tunSetup(t.Context(), nil, env, false, func(context.Context, func(string, ...any), bool, string) error {
		provisioned++
		return nil
	})

	if err == nil {
		t.Fatal("a platform with no installer was told its machine is ready")
	}
	if !strings.Contains(err.Error(), noInstallerHere) {
		t.Errorf("the refusal said %q, which does not say why there is nothing to do here", err)
	}
	if provisioned != 0 {
		t.Errorf("the setup ran %d times on a platform that has none", provisioned)
	}
	if out.String() != "" {
		t.Errorf("the refusal was preceded by %q, which describes a dialog that never appears", out)
	}
}

// approvalsFile stands in for the root-owned approvals file: a plain file in a temporary
// folder, read and written without the ownership check, which needs root to pass.
type approvalsFile struct {
	path   string
	writes int
	// loadErr, when set, is what reading the file reports.
	loadErr error
}

func standInApprovals(t *testing.T, privileged bool) *approvalsFile {
	t.Helper()
	file := &approvalsFile{path: filepath.Join(t.TempDir(), "grants.json")}
	before := [4]any{grantsPath, loadGrants, writeGrants, grantsPrivileged}
	grantsPath = func() (string, error) { return file.path, nil }
	loadGrants = func(path string) (grants.Document, error) {
		if file.loadErr != nil {
			return grants.Document{}, file.loadErr
		}
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return grants.None(), nil
		}
		if err != nil {
			return grants.Document{}, err
		}
		return grants.Parse(data)
	}
	writeGrants = func(path string, doc grants.Document) error {
		file.writes++
		data, err := doc.Encode()
		if err != nil {
			return err
		}
		return os.WriteFile(path, data, 0o644)
	}
	grantsPrivileged = func() bool { return privileged }
	t.Cleanup(func() {
		grantsPath = before[0].(func() (string, error))
		loadGrants = before[1].(func(string) (grants.Document, error))
		writeGrants = before[2].(func(string, grants.Document) error)
		grantsPrivileged = before[3].(func() bool)
	})
	return file
}

func (f *approvalsFile) seed(t *testing.T, doc grants.Document) {
	t.Helper()
	data, err := doc.Encode()
	if err != nil {
		t.Fatalf("encode the approvals to start from: %v", err)
	}
	if err := os.WriteFile(f.path, data, 0o644); err != nil {
		t.Fatalf("write the approvals to start from: %v", err)
	}
}

func (f *approvalsFile) read(t *testing.T) grants.Document {
	t.Helper()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatalf("read the approvals back: %v", err)
	}
	doc, err := grants.Parse(data)
	if err != nil {
		t.Fatalf("the approvals written do not parse: %v", err)
	}
	return doc
}

// testCAPEM is a real self-signed certificate, so its pin is what CAPins computes for any
// certificate rather than for a fixture shaped to pass.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "app-tail test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create a certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A refusal from the helper ends with the one command that approves it, and an approval flow
// runs exactly that. So the contract is checked end to end: every kind of need the policy
// produces, turned into its command line, run through `tun grant`, leaves nothing missing.
// A flag spelled differently from what the command parses, or a value it reads back wrong,
// is an approval that never takes -- and a dashboard that asks again forever.
func TestTheCommandARefusalNamesApprovesEverythingItRefused(t *testing.T) {
	file := standInApprovals(t, true)
	ca := testCAPEM(t)
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	routes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}
	needsOf := func(doc grants.Document) []grants.Need {
		needs := doc.RouteNeeds(routes, lan)
		needs = append(needs, doc.InterfaceDNSNeeds([]netip.Addr{netip.MustParseAddr("100.100.100.100")}, []string{"corp.example."})...)
		needs = append(needs, doc.SystemDNSNeeds([]netip.Addr{netip.MustParseAddr("127.0.0.1")})...)
		vpn, err := doc.OpenVPNNeeds("vpn.example.com:1194", ca)
		if err != nil {
			t.Fatalf("OpenVPNNeeds: %v", err)
		}
		needs = append(needs, vpn...)
		return append(needs, doc.TLSInterceptionNeeds()...)
	}

	refused := needsOf(grants.None())
	kinds := map[grants.Kind]bool{}
	for _, need := range refused {
		kinds[need.Kind] = true
	}
	for _, kind := range []grants.Kind{grants.KindFullTunnel, grants.KindRoute, grants.KindDNSDomain,
		grants.KindSystemDNS, grants.KindOpenVPNRemote, grants.KindTLSInterception} {
		if !kinds[kind] {
			t.Fatalf("the starting request needs no %q approval, so this test would not cover it: %+v", kind, refused)
		}
	}

	env, _ := captureTunEnv()
	args := grants.GrantArgs(refused)
	if err := Run(t.Context(), args, env); err != nil {
		t.Fatalf("app-tail %s: %v", strings.Join(args, " "), err)
	}
	if left := needsOf(file.read(t)); len(left) > 0 {
		t.Errorf("after app-tail %s, still missing: %+v", strings.Join(args, " "), left)
	}
}

// Approvals accumulate. An administrator approving one more range must not take back the
// full tunnel they approved last week, which would quietly break a working setup the next
// time the helper is asked.
func TestAGrantAddsToWhatIsAlreadyApproved(t *testing.T) {
	file := standInApprovals(t, true)
	file.seed(t, grants.Document{Version: grants.Version, FullTunnel: true,
		Routes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})

	env, out := captureTunEnv()
	err := runTun(t.Context(), []string{"grant", "--route", "198.51.100.0/24", "--route=192.0.2.0/24", "--dns-domain", "corp.example"}, env)
	if err != nil {
		t.Fatalf("tun grant: %v", err)
	}
	got := file.read(t)
	if !got.FullTunnel {
		t.Error("adding a range took back the full-tunnel approval")
	}
	for _, want := range []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"} {
		if !slices.Contains(got.Routes, netip.MustParsePrefix(want)) {
			t.Errorf("the approvals hold %v, missing %s", got.Routes, want)
		}
	}
	if !slices.Contains(got.DNSDomains, "corp.example.") {
		t.Errorf("the approvals hold domains %v, missing corp.example.", got.DNSDomains)
	}
	if !strings.Contains(out.String(), "198.51.100.0/24") || !strings.Contains(out.String(), file.path) {
		t.Errorf("the confirmation does not show what is approved and where:\n%s", out.String())
	}
}

// The approvals file is what the helper trusts because only root writes it. Run without
// administrator rights, the command must say how to get them and leave the file alone,
// rather than fail halfway through a write.
func TestGrantingWithoutAdministratorRightsChangesNothing(t *testing.T) {
	file := standInApprovals(t, false)
	env, _ := captureTunEnv()
	err := runTun(t.Context(), []string{"grant", "--full-tunnel"}, env)
	if err == nil {
		t.Fatal("an unprivileged grant was accepted")
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("the refusal %q does not say administrator rights are what is missing", err)
	}
	if file.writes != 0 {
		t.Errorf("an unprivileged grant wrote the approvals %d times", file.writes)
	}
	if _, statErr := os.Stat(file.path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("an unprivileged grant left an approvals file behind: %v", statErr)
	}
}

func TestTheRefusalForMissingRightsNamesHowThisPlatformGetsThem(t *testing.T) {
	if got := grantNeedsAdmin("windows"); !strings.Contains(got, "administrator") || strings.Contains(got, "sudo") {
		t.Errorf("on Windows the refusal says %q", got)
	}
	for _, goos := range []string{"darwin", "linux"} {
		if got := grantNeedsAdmin(goos); !strings.Contains(got, "sudo") {
			t.Errorf("on %s the refusal says %q, which does not name sudo", goos, got)
		}
	}
}

// --show is how anyone checks what this machine allows, and it needs no rights to read a file
// that is world-readable on purpose. Combined with an approval it is ambiguous -- show, or
// change? -- so that is refused rather than guessed.
func TestShowPrintsTheApprovalsAndChangesNothing(t *testing.T) {
	file := standInApprovals(t, false)
	file.seed(t, grants.Document{Version: grants.Version, Routes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})

	env, out := captureTunEnv()
	if err := runTun(t.Context(), []string{"grant", "--show"}, env); err != nil {
		t.Fatalf("tun grant --show: %v", err)
	}
	if !strings.Contains(out.String(), "203.0.113.0/24") {
		t.Errorf("--show does not list the approved range:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "not approved") {
		t.Errorf("--show does not say what is not approved:\n%s", out.String())
	}

	env, _ = captureTunEnv()
	err := runTun(t.Context(), []string{"grant", "--show", "--full-tunnel"}, env)
	if !errors.Is(err, ErrUsage) {
		t.Errorf("--show with an approval returned %v, want a usage error", err)
	}
	if file.writes != 0 {
		t.Errorf("--show wrote the approvals %d times", file.writes)
	}
}

func TestAGrantNamingNothingIsAUsageError(t *testing.T) {
	file := standInApprovals(t, true)
	env, _ := captureTunEnv()
	err := runTun(t.Context(), []string{"grant"}, env)
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("a bare `tun grant` returned %v, want a usage error", err)
	}
	if !strings.Contains(err.Error(), "--show") {
		t.Errorf("the refusal %q does not offer --show", err)
	}
	if file.writes != 0 {
		t.Errorf("a bare `tun grant` wrote the approvals %d times", file.writes)
	}
}

// A mistyped value is caught on the command line, before anything is read or written: an
// approval for the wrong server, or a pin nothing can match, is worse than none.
func TestAMalformedApprovalIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	tests := []struct {
		name   string
		args   []string
		phrase string
	}{
		{"a range that is not one", []string{"--route", "203.0.113.0"}, "203.0.113.0"},
		{"a server with no certificate authority", []string{"--openvpn", "vpn.example.com:1194"}, "SHA256"},
		{"a pin that is not a SHA-256", []string{"--openvpn", "vpn.example.com:1194=abc"}, "vpn.example.com:1194=abc"},
		{"a server with no port", []string{"--openvpn", "vpn.example.com=" + pin}, "vpn.example.com"},
		{"a domain that is not one", []string{"--dns-domain", "bad domain"}, "bad domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := standInApprovals(t, true)
			env, _ := captureTunEnv()
			err := runTun(t.Context(), append([]string{"grant"}, tt.args...), env)
			if err == nil {
				t.Fatalf("tun grant %v was accepted", tt.args)
			}
			if !strings.Contains(err.Error(), tt.phrase) {
				t.Errorf("the refusal %q does not mention %q", err, tt.phrase)
			}
			if file.writes != 0 {
				t.Errorf("a refused grant wrote the approvals %d times", file.writes)
			}
		})
	}

	t.Run("a well-formed server is approved with its pins", func(t *testing.T) {
		file := standInApprovals(t, true)
		env, _ := captureTunEnv()
		other := strings.Repeat("cd", 32)
		if err := runTun(t.Context(), []string{"grant", "--openvpn", "vpn.example.com:1194=" + pin + "," + other}, env); err != nil {
			t.Fatalf("tun grant --openvpn: %v", err)
		}
		got := file.read(t).OpenVPN
		if len(got) != 1 || got[0].Remote != "vpn.example.com:1194" || !slices.Equal(got[0].CASHA256, []string{pin, other}) {
			t.Errorf("the approvals hold %+v", got)
		}
	})
}

// An approvals file that fails the helper's own check -- one somebody else could have written
// -- is reported, never merged: rewriting it as root would sign whatever was put there.
func TestAnApprovalsFileThatCannotBeTrustedIsNotRewritten(t *testing.T) {
	file := standInApprovals(t, true)
	file.loadErr = errors.New("the approvals file is writable by other accounts")
	env, _ := captureTunEnv()
	err := runTun(t.Context(), []string{"grant", "--full-tunnel"}, env)
	if err == nil || !strings.Contains(err.Error(), "writable by other accounts") {
		t.Fatalf("tun grant over an untrusted file returned %v", err)
	}
	if file.writes != 0 {
		t.Errorf("an untrusted approvals file was rewritten %d times", file.writes)
	}
}

// writeConfigFile writes cfg where a --config flag can name it, in the shape the store keeps.
func writeConfigFile(t *testing.T, cfg *config.Config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("encode the config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write the config: %v", err)
	}
	return path
}

func standInAttachedNetworks(t *testing.T, nets ...netip.Prefix) {
	t.Helper()
	before := attachedNetworks
	attachedNetworks = func() ([]netip.Prefix, error) { return nets, nil }
	t.Cleanup(func() { attachedNetworks = before })
}

// `install-helper --grant` is the one-step setup: install, and approve what this config
// already asks for, so the first connection does not stop at a refusal. It approves exactly
// that: a disabled connection, or a private range off this machine's own network, asks for
// nothing, and approving it anyway would widen what the helper accepts for no reason.
func TestInstallingWithGrantApprovesWhatTheConfigAsksFor(t *testing.T) {
	in := standInInstaller(t, true, nil)
	file := standInApprovals(t, true)
	standInAttachedNetworks(t, netip.MustParsePrefix("192.168.1.0/24"))
	ca := testCAPEM(t)

	cfg := config.Defaults()
	cfg.Settings.ExitNodeEnabled = true
	cfg.Settings.IPSIntercept = config.IPSInterceptOnly
	cfg.Settings.IPSInterceptAgreed = true
	cfg.Tunnels = []config.Tunnel{
		{ID: "wg1", Name: "Work", Type: config.TunnelWireGuard, Enabled: true, WireGuard: &config.WireGuardTunnel{
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")},
			Peer: config.WireGuardPeer{AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.0/24"),
				netip.MustParsePrefix("10.1.0.0/16"),
				netip.MustParsePrefix("192.168.1.0/24"),
			}},
		}},
		{ID: "wg2", Name: "Off", Type: config.TunnelWireGuard, Enabled: false, WireGuard: &config.WireGuardTunnel{
			Peer: config.WireGuardPeer{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
		}},
		{ID: "ovpn1", Name: "Office", Type: config.TunnelOpenVPN, Enabled: true, OpenVPN: &config.OpenVPNTunnel{
			Remote: "vpn.example.com:1194", CA: ca,
		}},
	}
	path := writeConfigFile(t, cfg)

	env, out := captureTunEnv()
	env.Getenv = func(name string) string {
		if name == "SUDO_UID" {
			return "501"
		}
		return ""
	}
	if err := runTun(t.Context(), []string{"install-helper", "--grant", "--config", path}, env); err != nil {
		t.Fatalf("tun install-helper --grant: %v", err)
	}
	if len(in.installs) != 1 {
		t.Fatalf("the helper was installed %d times", len(in.installs))
	}
	got := file.read(t)
	if !got.FullTunnel {
		t.Error("an exit node was not approved as the full tunnel")
	}
	if !got.TLSInterception {
		t.Error("agreed TLS interception was not approved")
	}
	wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	slices.SortFunc(got.Routes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	if !slices.Equal(got.Routes, wantRoutes) {
		t.Errorf("the approved ranges are %v, want %v (a disabled connection and a free private range ask for nothing)", got.Routes, wantRoutes)
	}
	if len(got.OpenVPN) != 1 || got.OpenVPN[0].Remote != "vpn.example.com:1194" {
		t.Fatalf("the approved OpenVPN servers are %+v", got.OpenVPN)
	}
	if left, err := got.OpenVPNNeeds("vpn.example.com:1194", ca); err != nil || len(left) > 0 {
		t.Errorf("the OpenVPN approval does not cover the server's own certificate authority: %v %+v", err, left)
	}
	if got.SystemDNS || len(got.DNSDomains) > 0 {
		t.Errorf("approved name resolution nothing in the config asks for: %+v", got)
	}
	if !strings.Contains(out.String(), path) {
		t.Errorf("the output does not say which config the approvals came from:\n%s", out.String())
	}
}

// The config is read before anything is installed, so a path that is wrong stops the command
// with the machine as it was, rather than with a helper installed and nothing approved.
func TestInstallingWithGrantAndAConfigThatCannotBeReadInstallsNothing(t *testing.T) {
	in := standInInstaller(t, true, nil)
	file := standInApprovals(t, true)
	standInAttachedNetworks(t)
	env, _ := captureTunEnv()
	env.Getenv = func(name string) string {
		if name == "SUDO_UID" {
			return "501"
		}
		return ""
	}
	missing := filepath.Join(t.TempDir(), "absent.json")
	err := runTun(t.Context(), []string{"install-helper", "--grant", "--config", missing}, env)
	if err == nil {
		t.Fatal("install-helper --grant with no config succeeded")
	}
	if !strings.Contains(err.Error(), "--config") {
		t.Errorf("the refusal %q does not say how to name another config", err)
	}
	if len(in.installs) != 0 || file.writes != 0 {
		t.Errorf("a config that could not be read still installed %d times and wrote %d times", len(in.installs), file.writes)
	}
}

// Without --grant the install approves nothing: an approval is a separate decision, and an
// installer that widened what the helper accepts on its own would make it nobody's.
func TestInstallingWithoutGrantApprovesNothing(t *testing.T) {
	standInInstaller(t, true, nil)
	file := standInApprovals(t, true)
	env, _ := captureTunEnv()
	env.Getenv = func(name string) string {
		if name == "SUDO_UID" {
			return "501"
		}
		return ""
	}
	if err := runTun(t.Context(), []string{"install-helper"}, env); err != nil {
		t.Fatalf("tun install-helper: %v", err)
	}
	if file.writes != 0 {
		t.Errorf("a plain install wrote the approvals %d times", file.writes)
	}
}

// Whoever decides whether to install the helper on a shared machine needs to know how far its
// trust in a caller goes on this platform. The doctor says so wherever there is a helper, and
// says nothing about one where there is none.
func TestTheDoctorSaysHowTheHelperTellsAppTailFromOtherPrograms(t *testing.T) {
	before := helperCallerCheck
	helperCallerCheck = func() hostnet.CallerCheck { return hostnet.CallerCheckExecutable }
	t.Cleanup(func() { helperCallerCheck = before })
	want := hostnet.CallerCheckExecutable.Describe()

	env, out := captureTunEnv()
	if err := writeTunReport(env, tsnode.InterfaceReport{Platform: "linux", Supported: true,
		Helper: tsnode.InterfaceHelperReport{Design: true}}); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	if !strings.Contains(out.String(), want) {
		t.Errorf("the report does not say how callers are checked:\n%s", out.String())
	}

	env, out = captureTunEnv()
	if err := writeTunReport(env, tsnode.InterfaceReport{Platform: "plan9"}); err != nil {
		t.Fatalf("writeTunReport: %v", err)
	}
	if strings.Contains(out.String(), want) {
		t.Errorf("a platform with no helper still describes its caller check:\n%s", out.String())
	}

	env, out = captureTunEnv()
	if err := runTun(t.Context(), []string{"doctor", "--json"}, env); err != nil {
		t.Fatalf("tun doctor --json: %v", err)
	}
	var report struct {
		CallerCheck hostnet.CallerCheck `json:"callerCheck"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("the JSON report does not parse: %v", err)
	}
	if report.CallerCheck != hostnet.CallerCheckExecutable {
		t.Errorf("the JSON report says callerCheck %q, want %q", report.CallerCheck, hostnet.CallerCheckExecutable)
	}
}
