// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// A mistyped menu choice has to re-prompt. Falling through to a save or a quit would
// act on a keystroke the user never meant, and returning an error would drop them out
// of the menu with their queued edits discarded.
func TestTheMenuReprompsOnAChoiceThatIsNotOnIt(t *testing.T) {
	tests := []struct {
		name   string
		choice string
	}{
		{"a word", "hostname"},
		{"a number below the list", "0"},
		{"a number past the end", "999"},
		{"a negative number", "-1"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stored := config.Defaults()
			tailnetOf(t, stored).Hostname = "unchanged"
			h := newHarness(t, settingsRoutes(t, stored, nil))

			p := &scriptedPrompter{lines: []string{tt.choice, "q"}}
			var out bytes.Buffer
			if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
				t.Fatalf("settingsMenu: %v", err)
			}

			if !strings.Contains(out.String(), "Enter one of the listed numbers") {
				t.Errorf("the menu did not explain the bad choice:\n%s", out.String())
			}
			if len(p.lines) != 0 {
				t.Errorf("%d scripted answers went unread, so the menu stopped instead of "+
					"re-prompting", len(p.lines))
			}
			if tailnetOf(t, stored).Hostname != "unchanged" {
				t.Errorf("a rejected choice still changed the hostname to %q", tailnetOf(t, stored).Hostname)
			}
		})
	}
}

// A value the field's parser refuses is the user's typo, not a program fault. The menu
// has to print the reason and keep going; returning the error would throw away every
// other edit already queued.
func TestAValueTheFieldRefusesIsReportedAndTheMenuKeepsGoing(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	// udp-timeout is an int field, so "soon" cannot parse; the retry after it must
	// still land.
	idx := menuFieldNumber(t, "udp-timeout")
	p := &scriptedPrompter{lines: []string{idx, "soon", idx, "45", "s"}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	if !strings.Contains(out.String(), "soon") {
		t.Errorf("the menu did not report what it could not parse:\n%s", out.String())
	}
	if stored.Settings.UDPSessionTimeoutSec != 45 {
		t.Errorf("udpSessionTimeoutSec = %d, want the value typed after the rejected one",
			stored.Settings.UDPSessionTimeoutSec)
	}
}

// Ctrl-D at the top-level prompt means "I am done", not "something went wrong". A menu
// that surfaced it as an error would have the CLI exit non-zero on a normal abort, and
// a shell script wrapping it would report a failure that never happened.
func TestEndingInputAtThePromptStopsTheMenuWithoutAnError(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).Hostname = "unchanged"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	// An exhausted scriptedPrompter returns errAborted, which is what Ctrl-D produces.
	p := &scriptedPrompter{}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("an aborted menu reported %v, want a clean stop", err)
	}
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut {
			t.Error("an aborted menu still wrote the settings")
		}
	}
}

// The same abort while editing a field must not save either -- the queued edits go with
// it. Reporting it as an error would again exit non-zero on a normal Ctrl-D.
func TestEndingInputWhileEditingAFieldDiscardsTheQueuedChanges(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).Hostname = "unchanged"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	// Queue a real edit, then abort inside the next field's prompt.
	p := &scriptedPrompter{lines: []string{"1", "typed-but-never-saved", "1"}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("an aborted edit reported %v, want a clean stop", err)
	}
	if tailnetOf(t, stored).Hostname != "unchanged" {
		t.Errorf("hostname = %q, want the aborted edit discarded", tailnetOf(t, stored).Hostname)
	}
}

// A prompter failure that is not an abort -- a closed terminal, a read error -- has to
// reach the caller. Swallowing it would leave the CLI exiting 0 having done nothing.
func TestARealInputFailureStopsTheMenuAndIsReported(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	broken := errors.New("terminal went away")
	p := &failingPrompter{err: broken}
	var out bytes.Buffer

	err := settingsMenu(context.Background(), h.client(), p, &out)

	if !errors.Is(err, broken) {
		t.Errorf("settingsMenu = %v, want the underlying read failure", err)
	}
}

// menuInterrupted is what decides whether the CLI exits 0 or reports a failure, so both
// halves matter: an abort is a clean stop, anything else passes through untouched.
func TestOnlyAnAbortCountsAsACleanStop(t *testing.T) {
	if err := menuInterrupted(errAborted); err != nil {
		t.Errorf("menuInterrupted(errAborted) = %v, want a clean stop", err)
	}
	// Wrapped, because errAborted travels back through editField's return path.
	wrapped := errors.Join(errors.New("while editing hostname"), errAborted)
	if err := menuInterrupted(wrapped); err != nil {
		t.Errorf("menuInterrupted(wrapped abort) = %v, want a clean stop", err)
	}
	real := errors.New("read /dev/tty: input/output error")
	if err := menuInterrupted(real); !errors.Is(err, real) {
		t.Errorf("menuInterrupted(%v) = %v, want it passed through", real, err)
	}
}

// Saving with nothing queued must not send a PUT. An empty patch would still make the
// agent re-resolve and could report a restart requirement for a change nobody made.
func TestSavingWithNothingQueuedWritesNothing(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	p := &scriptedPrompter{lines: []string{"s"}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	if !strings.Contains(out.String(), "Nothing changed.") {
		t.Errorf("the menu did not say why it saved nothing:\n%s", out.String())
	}
	for _, req := range h.recorded() {
		if req.Method == http.MethodPut {
			t.Error("an empty save still sent a settings write")
		}
	}
}

// Blank input at a field prompt means "leave it alone". Recording it as a value would
// clear the setting -- and for the hostname that silently renames the node on the next
// restart.
func TestBlankInputLeavesAFieldAlone(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).Hostname = "keep-me"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	p := &scriptedPrompter{lines: []string{"1", "   ", "s"}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	if tailnetOf(t, stored).Hostname != "keep-me" {
		t.Errorf("hostname = %q, want blank input to leave it alone", tailnetOf(t, stored).Hostname)
	}
	if !strings.Contains(out.String(), "Nothing changed.") {
		t.Errorf("a blank edit was queued as a change:\n%s", out.String())
	}
}

// The same rule for a secret: a blank no-echo prompt must not queue an empty auth key.
// Storing "" would clear a working key and break the next non-interactive enrollment
// with nothing on screen to explain it.
func TestBlankSecretInputLeavesTheStoredKeyAlone(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).AuthKey = "tskey-auth-still-good"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	p := &scriptedPrompter{
		lines:   []string{menuFieldNumber(t, "auth-key"), "s"},
		secrets: []string{""},
	}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	if tailnetOf(t, stored).AuthKey != "tskey-auth-still-good" {
		t.Errorf("auth key = %q, want a blank secret prompt to leave it alone", tailnetOf(t, stored).AuthKey)
	}
}

// Declining the restart has to leave the node running and tell the user how to apply
// the change later. Restarting anyway would drop every live forward on a change the
// user explicitly deferred.
func TestDecliningTheRestartLeavesTheNodeAloneAndSaysWhatToRunLater(t *testing.T) {
	tests := []struct {
		name   string
		answer string
	}{
		{"an explicit no", "n"},
		{"the empty default", ""},
		{"anything else", "later"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stored := config.Defaults()
			routes := settingsRoutes(t, stored, map[string]bool{"node": true})
			routes["POST /api/restart"] = func(w http.ResponseWriter, _ *http.Request) {
				t.Error("the node was restarted after the user declined")
				writeJSONResponse(t, w, http.StatusOK, map[string]string{})
			}
			h := newHarness(t, routes)

			p := &scriptedPrompter{lines: []string{"1", "renamed", "s", tt.answer}}
			var out bytes.Buffer
			if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
				t.Fatalf("settingsMenu: %v", err)
			}

			if !strings.Contains(out.String(), "app-tail restart") {
				t.Errorf("the menu did not say how to apply the change later:\n%s", out.String())
			}
			if tailnetOf(t, stored).Hostname != "renamed" {
				t.Errorf("hostname = %q, want the save to have landed regardless", tailnetOf(t, stored).Hostname)
			}
		})
	}
}

// A capital Y is the same answer as a lowercase one. Treating it as a decline would
// leave the user waiting for a restart they explicitly asked for.
func TestTheRestartOfferAcceptsAnyCasing(t *testing.T) {
	stored := config.Defaults()
	routes := settingsRoutes(t, stored, map[string]bool{"node": true})
	restarted := make(chan struct{}, 1)
	routes["POST /api/restart"] = func(w http.ResponseWriter, _ *http.Request) {
		restarted <- struct{}{}
		writeJSONResponse(t, w, http.StatusOK, map[string]string{"backendState": "Starting"})
	}
	h := newHarness(t, routes)

	p := &scriptedPrompter{lines: []string{"1", "renamed", "s", " Y "}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	select {
	case <-restarted:
	default:
		t.Error("an upper-case yes did not reach the agent")
	}
	if !strings.Contains(out.String(), "Node restarted.") {
		t.Errorf("the menu did not confirm the restart:\n%s", out.String())
	}
}

// A restart the agent refuses has to be reported. Printing "Node restarted." over a
// failure would have the user believe a hostname change took effect when the node is
// still enrolled under the old one.
func TestARestartTheAgentRefusesIsReported(t *testing.T) {
	stored := config.Defaults()
	routes := settingsRoutes(t, stored, map[string]bool{"node": true})
	routes["POST /api/restart"] = func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(t, w, http.StatusServiceUnavailable,
			map[string]string{"error": "the tailnet node is not running"})
	}
	h := newHarness(t, routes)

	p := &scriptedPrompter{lines: []string{"1", "renamed", "s", "y"}}
	var out bytes.Buffer

	err := settingsMenu(context.Background(), h.client(), p, &out)

	if err == nil {
		t.Fatal("a refused restart was reported as success")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("err = %v, want the agent's own reason", err)
	}
	if strings.Contains(out.String(), "Node restarted.") {
		t.Errorf("the menu claimed the node restarted:\n%s", out.String())
	}
}

// Moving the dashboard address costs the caller its own connection, and no in-place
// restart can apply it. The menu has to say so; offering the node restart instead would
// have the user restart the node and find the dashboard still on the old port.
func TestMovingTheDashboardAddressExplainsThatTheProcessMustRestart(t *testing.T) {
	stored := config.Defaults()
	routes := settingsRoutes(t, stored, map[string]bool{"ui": true})
	routes["POST /api/restart"] = func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a dashboard-address change asked for a node restart")
		writeJSONResponse(t, w, http.StatusOK, map[string]string{})
	}
	h := newHarness(t, routes)

	p := &scriptedPrompter{lines: []string{menuFieldNumber(t, "ui-addr"), "127.0.0.1:19999", "s"}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	if !strings.Contains(out.String(), "dashboard address changed") {
		t.Errorf("the menu did not explain the relisten:\n%s", out.String())
	}
	if stored.Settings.UIListen != "127.0.0.1:19999" {
		t.Errorf("uiListenAddr = %q, want the new address stored", stored.Settings.UIListen)
	}
}

// A write the agent rejects must surface, not be swallowed into a "Saved." the user
// believes. The menu returns rather than re-looping, so the reason has to travel.
func TestASaveTheAgentRejectsIsReported(t *testing.T) {
	stored := config.Defaults()
	routes := settingsRoutes(t, stored, nil)
	routes["PUT /api/settings"] = func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(t, w, http.StatusBadRequest,
			map[string]string{"error": "hostname must be a valid DNS label"})
	}
	h := newHarness(t, routes)

	p := &scriptedPrompter{lines: []string{"1", "not a label", "s"}}
	var out bytes.Buffer

	err := settingsMenu(context.Background(), h.client(), p, &out)

	if err == nil {
		t.Fatal("a rejected save was reported as success")
	}
	if !strings.Contains(err.Error(), "DNS label") {
		t.Errorf("err = %v, want the agent's own reason", err)
	}
	if strings.Contains(out.String(), "Saved.") {
		t.Errorf("the menu said it saved a rejected change:\n%s", out.String())
	}
}

// The menu is opened against a live agent, so an agent that cannot be reached has to
// fail before the first prompt. Rendering an empty field list would invite the user to
// type edits that go nowhere.
func TestTheMenuRefusesToOpenAgainstAnAgentItCannotRead(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"GET /api/settings": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusInternalServerError,
				map[string]string{"error": "settings are not wired"})
		},
	})

	p := &scriptedPrompter{lines: []string{"q"}}
	var out bytes.Buffer

	err := settingsMenu(context.Background(), h.client(), p, &out)

	if err == nil {
		t.Fatal("the menu opened against an agent that could not serve its settings")
	}
	if !strings.Contains(err.Error(), "not wired") {
		t.Errorf("err = %v, want the agent's own reason", err)
	}
	if len(p.lines) != 1 {
		t.Error("the menu prompted before it had anything to show")
	}
}

// A queued edit is marked in the listing so the user can see what is unsaved before
// committing. Losing the marker -- or showing the saved value next to it -- would have
// them save a change they think they already reverted.
func TestTheListingMarksAQueuedEditAndShowsItsPendingValue(t *testing.T) {
	stored := config.Defaults()
	tailnetOf(t, stored).Hostname = "on-disk"
	h := newHarness(t, settingsRoutes(t, stored, nil))

	p := &scriptedPrompter{lines: []string{"1", "queued-only", "q"}}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	// The listing is printed once before the edit and once after it.
	printed := out.String()
	if !strings.Contains(printed, "queued-only (unsaved)") {
		t.Errorf("the re-rendered menu does not show the pending value:\n%s", printed)
	}
	if !strings.Contains(printed, "* 1)") {
		t.Errorf("the edited row is not marked as changed:\n%s", printed)
	}
}

// The same for a secret, which must never be echoed even as a pending value: the whole
// point of the no-echo prompt is that the key does not reach the scrollback.
func TestAQueuedSecretIsShownAsSetRatherThanPrinted(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	p := &scriptedPrompter{
		lines:   []string{menuFieldNumber(t, "auth-key"), "q"},
		secrets: []string{"tskey-auth-do-not-print"},
	}
	var out bytes.Buffer
	if err := settingsMenu(context.Background(), h.client(), p, &out); err != nil {
		t.Fatalf("settingsMenu: %v", err)
	}

	if strings.Contains(out.String(), "tskey-auth-do-not-print") {
		t.Fatalf("the queued secret was printed:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "set (unsaved)") {
		t.Errorf("the queued secret is not marked as pending:\n%s", out.String())
	}
}

// A secret prompt that fails is not the user's typo, so it must not be reported as a
// parse error and re-looped: an abort ends the menu and any other failure travels.
func TestASecretPromptFailureEndsTheMenu(t *testing.T) {
	stored := config.Defaults()
	h := newHarness(t, settingsRoutes(t, stored, nil))

	broken := errors.New("cannot disable echo")
	p := &failingPrompter{err: broken, linesBeforeFailure: []string{menuFieldNumber(t, "auth-key")}}
	var out bytes.Buffer

	err := settingsMenu(context.Background(), h.client(), p, &out)

	if !errors.Is(err, broken) {
		t.Errorf("settingsMenu = %v, want the secret prompt's failure", err)
	}
}

// --- menuIndex ------------------------------------------------------------

// menuIndex is what stands between a typed digit and an out-of-range slice access. The
// range check has to reject both ends or a mistyped number panics the CLI.
func TestMenuIndexAcceptsOnlyANumberOnTheList(t *testing.T) {
	tests := []struct {
		choice  string
		n       int
		want    int
		wantOK  bool
		comment string
	}{
		{"1", 3, 0, true, "the first entry is 1-based"},
		{"3", 3, 2, true, "the last entry is in range"},
		{"0", 3, 0, false, "there is no zeroth entry"},
		{"4", 3, 0, false, "one past the end"},
		{"-1", 3, 0, false, "negative"},
		{"", 3, 0, false, "empty"},
		{"two", 3, 0, false, "not a number"},
		{"1.0", 3, 0, false, "not an integer"},
		{" 1", 3, 0, false, "Atoi rejects surrounding space; the caller trims first"},
		{"1", 0, 0, false, "an empty field list has no valid choice"},
	}

	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			got, ok := menuIndex(tt.choice, tt.n)
			if ok != tt.wantOK {
				t.Fatalf("menuIndex(%q, %d) ok = %v, want %v", tt.choice, tt.n, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("menuIndex(%q, %d) = %d, want %d", tt.choice, tt.n, got, tt.want)
			}
		})
	}
}

// --- ttyPrompter.line -----------------------------------------------------

// ttyPrompter.line is the only reader in the menu that touches real terminal input, and
// it has to strip the line ending itself. A retained "\r" on Windows would make every
// typed hostname end in a carriage return and every menu choice fail to parse.
func TestTheTerminalReaderStripsWhicheverLineEndingArrives(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"a unix line", "renamed-host\n", "renamed-host"},
		{"a windows line", "renamed-host\r\n", "renamed-host"},
		{"an empty line", "\n", ""},
		{"an empty windows line", "\r\n", ""},
		{"inner spaces survive", "  spaced out  \n", "  spaced out  "},
		// A last line with no terminator is what a piped heredoc produces.
		{"no trailing newline", "renamed-host", "renamed-host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			p := ttyPrompter{in: bufio.NewReader(strings.NewReader(tt.input)), out: &out}

			got, err := p.line("prompt> ")
			if err != nil {
				t.Fatalf("line: %v", err)
			}
			if got != tt.want {
				t.Errorf("line = %q, want %q", got, tt.want)
			}
			if !strings.Contains(out.String(), "prompt> ") {
				t.Errorf("the prompt was not written: %q", out.String())
			}
		})
	}
}

// End-of-input with nothing typed is Ctrl-D: a clean stop, not a value. Returning ""
// with a nil error would make the menu treat it as "leave unchanged" and loop forever
// on an input that can never produce another line.
func TestEndOfInputWithNothingTypedIsAnAbort(t *testing.T) {
	var out bytes.Buffer
	p := ttyPrompter{in: bufio.NewReader(strings.NewReader("")), out: &out}

	_, err := p.line("prompt> ")

	if !errors.Is(err, errAborted) {
		t.Errorf("line at end of input = %v, want errAborted", err)
	}
}

// A read failure that is not end-of-input has to travel. Folding it into an abort would
// exit the CLI 0 over a broken terminal.
func TestARealReadFailureIsNotMistakenForAnAbort(t *testing.T) {
	broken := errors.New("input/output error")
	var out bytes.Buffer
	p := ttyPrompter{in: bufio.NewReader(errReader{err: broken}), out: &out}

	_, err := p.line("prompt> ")

	if !errors.Is(err, broken) {
		t.Errorf("line = %v, want the underlying read failure", err)
	}
	if errors.Is(err, errAborted) {
		t.Error("a broken terminal was reported as a clean Ctrl-D")
	}
}

// --- helpers --------------------------------------------------------------

// failingPrompter answers a scripted prefix and then fails, so a test can drive the
// menu to a chosen prompt before the terminal breaks under it.
type failingPrompter struct {
	err                error
	linesBeforeFailure []string
}

func (p *failingPrompter) line(string) (string, error) {
	if len(p.linesBeforeFailure) == 0 {
		return "", p.err
	}
	next := p.linesBeforeFailure[0]
	p.linesBeforeFailure = p.linesBeforeFailure[1:]
	return next, nil
}

func (p *failingPrompter) secret(string) (string, error) { return "", p.err }

// errReader fails every read, standing in for a terminal that went away mid-session.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

var _ io.Reader = errReader{}

// menuFieldNumber returns the menu choice that selects the named field. Hardcoding the
// number would make every test here break the next time a field is added to the
// registry, which is exactly the churn that gets tests deleted.
func menuFieldNumber(t *testing.T, cliName string) string {
	t.Helper()
	for i, s := range writableSchemas() {
		if s.CLIName == cliName {
			return strconv.Itoa(i + 1)
		}
	}
	t.Fatalf("no writable settings field named %q", cliName)
	return ""
}

// A save that restarted the agent for administrator rights leaves nothing to ask: offering a
// node restart on top would be a question about a process already on its way out.
func TestTheMenuOffersNothingMoreAfterASaveRestartedTheAgentForRights(t *testing.T) {
	var out bytes.Buffer
	// An exhausted prompter answers errAborted, so any question asked fails the call.
	p := &scriptedPrompter{}
	err := offerRestart(context.Background(), nil, p, &out,
		SettingsResult{AdminRestart: true, AdminRelaunch: true, NodeRestart: true})
	if err != nil {
		t.Fatalf("offerRestart = %v, want no question asked", err)
	}
	if !strings.Contains(out.String(), "restarting so Windows can ask") {
		t.Errorf("output = %q, want it to say app-tail is restarting for the rights", out.String())
	}
}
