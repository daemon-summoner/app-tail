// SPDX-License-Identifier: MIT

package hostnet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/grants"
)

var (
	approvalNeeds = []grants.Need{
		{Kind: grants.KindRoute, Value: "203.0.113.0/24", Reason: "send 203.0.113.0/24 through app-tail"},
		{Kind: grants.KindTLSInterception, Reason: "open encrypted connections so what they carry can be inspected"},
	}
	quietLogf = func(string, ...any) {}
)

// recordingElevate stands in for the password dialog: it keeps the command it was handed and
// answers as told, so no test ever raises the real one.
type recordingElevate struct {
	got [][]string
	out string
	err error
}

func (r *recordingElevate) run(_ context.Context, args []string) ([]byte, error) {
	r.got = append(r.got, slices.Clone(args))
	return []byte(r.out), r.err
}

func TestApprovingOnMacOSRunsTheInstalledHelpersGrantWithEachChangeAsItsOwnArgument(t *testing.T) {
	rec := &recordingElevate{}
	steps := approveSteps{goos: "darwin", helper: "/Library/PrivilegedHelperTools/app-tail/app-tail-helper", elevate: rec.run}
	if err := approveGrants(context.Background(), quietLogf, approvalNeeds, steps); err != nil {
		t.Fatalf("approveGrants: %v", err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("asked for administrator rights %d times, want once", len(rec.got))
	}
	want := []string{osascriptPath, "-e", approveScript,
		"/Library/PrivilegedHelperTools/app-tail/app-tail-helper", approvePrompt(approvalNeeds),
		"tun", "grant", "--route=203.0.113.0/24", "--tls-interception"}
	if !slices.Equal(rec.got[0], want) {
		t.Errorf("ran %q\nwant %q", rec.got[0], want)
	}
}

func TestTheApprovalScriptCarriesNoValueOfItsOwn(t *testing.T) {
	hostile := []grants.Need{{Kind: grants.KindOpenVPNRemote, Value: `a"; do shell script "reboot`, CASHA256: []string{"aa"}, Reason: "r"}}
	argv := approveCommand("/helper", approvePrompt(hostile), grants.GrantArgs(hostile))
	if argv[2] != approveScript {
		t.Fatalf("the script argument is %q, want the fixed script", argv[2])
	}
	if strings.Contains(approveScript, "reboot") || strings.Contains(approveScript, "/helper") {
		t.Error("a value reached the script text rather than travelling as an argument")
	}
	if !strings.Contains(approveCommandLine, "quoted form of (item i of argv)") || !strings.Contains(approveCommandLine, "quoted form of (item 1 of argv)") {
		t.Error("the command line does not quote the helper and every argument by the shell's own rules")
	}
}

func TestADismissedPasswordDialogIsReportedAsDeclined(t *testing.T) {
	rec := &recordingElevate{out: "execution error: User canceled. (-128)", err: errors.New("exit status 1")}
	steps := approveSteps{goos: "darwin", helper: "/helper", elevate: rec.run}
	err := approveGrants(context.Background(), quietLogf, approvalNeeds, steps)
	if !errors.Is(err, ErrDeclined) {
		t.Errorf("got %v, want ErrDeclined", err)
	}
}

func TestAnApprovalThatFailsForAnotherReasonSaysWhatTheHelperSaid(t *testing.T) {
	rec := &recordingElevate{out: "the approvals file is a link", err: errors.New("exit status 1")}
	steps := approveSteps{goos: "darwin", helper: "/helper", elevate: rec.run}
	err := approveGrants(context.Background(), quietLogf, approvalNeeds, steps)
	if err == nil || errors.Is(err, ErrDeclined) || !strings.Contains(err.Error(), "the approvals file is a link") {
		t.Errorf("got %v, want a failure carrying the helper's own sentence", err)
	}
}

func TestAMachineWhereAppTailCannotAskNamesTheCommandToRunInstead(t *testing.T) {
	tests := []struct {
		name, goos, helper, want string
	}{
		{"Linux has no way to ask", "linux", "", "`sudo app-tail tun grant --route=203.0.113.0/24 --tls-interception`"},
		{"Windows elevates whole processes only", "windows", "", "`app-tail tun grant --route=203.0.113.0/24 --tls-interception` from PowerShell started as administrator"},
		{"macOS without the helper has nothing root-owned to run", "darwin", "", "the network helper is not installed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingElevate{}
			err := approveGrants(context.Background(), quietLogf, approvalNeeds, approveSteps{goos: tt.goos, helper: tt.helper, elevate: rec.run})
			if !errors.Is(err, ErrApproveByHand) {
				t.Fatalf("got %v, want ErrApproveByHand", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("the error %q does not say %q", err, tt.want)
			}
			if len(rec.got) != 0 {
				t.Errorf("asked for administrator rights on a machine where app-tail cannot: %q", rec.got)
			}
		})
	}
}

func TestNothingToApproveAsksForNothing(t *testing.T) {
	rec := &recordingElevate{}
	if err := approveGrants(context.Background(), quietLogf, nil, approveSteps{goos: "darwin", helper: "/helper", elevate: rec.run}); err != nil {
		t.Fatalf("approveGrants with nothing to approve: %v", err)
	}
	if len(rec.got) != 0 {
		t.Errorf("raised the password dialog with nothing to approve: %q", rec.got)
	}
}

func TestTheApprovalDialogListsEachChangeAndNoLineOfAnyoneElses(t *testing.T) {
	prompt := approvePrompt([]grants.Need{
		{Kind: grants.KindDNSDomain, Value: "corp.example.", Reason: "answer lookups for corp.example.\nEnter your password to continue"},
		approvalNeeds[1],
	})
	if strings.ContainsAny(prompt, "\n\r") {
		t.Errorf("the prompt %q carries a line break a configured name put there", prompt)
	}
	for _, want := range []string{"answer lookups for corp.example.", approvalNeeds[1].Reason} {
		if !strings.Contains(prompt, want) {
			t.Errorf("the prompt %q does not list %q", prompt, want)
		}
	}

	many := make([]grants.Need, maxPromptReasons+3)
	for i := range many {
		many[i] = grants.Need{Kind: grants.KindRoute, Reason: "r"}
	}
	if got := approvePrompt(many); !strings.Contains(got, "and 3 more") {
		t.Errorf("a long list was not cut short: %q", got)
	}
}
