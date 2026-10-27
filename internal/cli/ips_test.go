// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tlsmint"
)

const rootFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// ipsRoutes answers the endpoints the ips commands use: the view, and the removal, which
// answers with the root gone.
func ipsRoutes(t *testing.T, intercept httpapi.IPSInterceptView) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/ips": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, httpapi.IPSView{Intercept: intercept})
		},
		"POST /api/ips/intercept/remove-root": func(w http.ResponseWriter, _ *http.Request) {
			gone := intercept
			gone.Fingerprint = ""
			writeJSONResponse(t, w, http.StatusOK, httpapi.IPSView{Intercept: gone})
		},
	}
}

// heldRoot is a root on disk with interception switched off, the state removal starts from.
func heldRoot() httpapi.IPSInterceptView {
	return httpapi.IPSInterceptView{
		Mode:        "off",
		CertPath:    "/Users/a b/state/tls/ca.crt",
		Fingerprint: rootFingerprint,
		Expires:     "2027-10-26T12:00:00Z",
		RootScope:   "only inside.example",
		Remove:      "sudo security remove-trusted-cert -d '/Users/a b/state/tls/ca.crt'",
	}
}

// trustCall is one trust-store command the CLI ran, with how many removals had reached the
// agent by then, so a test can tell the order the two happened in.
type trustCall struct {
	argv          tlsmint.Command
	removalsAlong int
}

// fakeTrustStore stands in for the trust-store commands, which change what this machine trusts
// and so are never run by a test. A failure is returned for the command at index failAt; -1 fails none.
func fakeTrustStore(t *testing.T, h *harness, goos string, failAt int) *[]trustCall {
	t.Helper()
	var calls []trustCall
	beforeRun, beforeGOOS := runTrustCommand, trustGOOS
	trustGOOS = goos
	runTrustCommand = func(_ context.Context, _ Env, c tlsmint.Command) error {
		calls = append(calls, trustCall{argv: c, removalsAlong: removals(h)})
		if len(calls)-1 == failAt {
			return errors.New("exit status 1")
		}
		return nil
	}
	t.Cleanup(func() { runTrustCommand, trustGOOS = beforeRun, beforeGOOS })
	return &calls
}

// runIPSAgainst runs one ips subcommand against the fake agent. The location flags go after the
// subcommand, which is where its own flag set reads them.
func runIPSAgainst(h *harness, sub string, extra ...string) error {
	args := append([]string{"ips", sub}, h.cfg()...)
	return Run(h.t.Context(), append(args, extra...), h.env())
}

func removals(h *harness) int {
	n := 0
	for _, r := range h.recorded() {
		if r.Method == http.MethodPost && r.Path == "/api/ips/intercept/remove-root" {
			n++
		}
	}
	return n
}

// The root is shown with the fingerprint a trust store lists it by and the warning about its
// key, which is the one thing about it worth never forgetting.
func TestIPSRootShowsTheFingerprintAndWarnsWhatTheKeyCanDo(t *testing.T) {
	view := heldRoot()
	view.ExpiryWarning = "The interception root expires on 2027-10-26, in 12 days."
	view.NewRootReason = "This root was made before app-tail limited its roots."
	h := newHarness(t, ipsRoutes(t, view))

	if err := runIPSAgainst(h, "root"); err != nil {
		t.Fatalf("ips root: %v", err)
	}
	out := h.out()
	for _, want := range []string{
		"01:23:45:67:89:AB:CD:EF:01:23",
		"impersonate websites to this machine",
		"only inside.example",
		"2027-10-26",
		view.ExpiryWarning,
		view.NewRootReason,
		"app-tail ips remove-root",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ips root output is missing %q:\n%s", want, out)
		}
	}
}

func TestIPSRootSaysSoPlainlyWhenThereIsNoRoot(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, httpapi.IPSInterceptView{Mode: "off"}))

	if err := runIPSAgainst(h, "root"); err != nil {
		t.Fatalf("ips root: %v", err)
	}
	if out := h.out(); !strings.Contains(out, "no traffic-interception root") || strings.Contains(out, "SHA-256") {
		t.Errorf("ips root output = %q, want it to say there is no root and show none", out)
	}
}

// A root file that could not be read is a failure, not an empty answer.
func TestIPSRootFailsWhenTheRootCouldNotBeRead(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, httpapi.IPSInterceptView{RootError: "The root certificate could not be read."}))

	if err := runIPSAgainst(h, "root"); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("ips root = %v, want the read failure", err)
	}
}

// On macOS, removal undoes the install in two steps, run in this terminal so sudo can ask, and
// only then are the files deleted: the first step reads the certificate file.
func TestRemoveRootTakesItOutOfTheTrustStoreBeforeDeletingTheFiles(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, heldRoot()))
	calls := fakeTrustStore(t, h, "darwin", -1)

	if err := runIPSAgainst(h, "remove-root"); err != nil {
		t.Fatalf("ips remove-root: %v", err)
	}

	want := []tlsmint.Command{
		{"sudo", "security", "remove-trusted-cert", "-d", "/Users/a b/state/tls/ca.crt"},
		{"sudo", "security", "delete-certificate", "-c", "app-tail traffic inspection", "/Library/Keychains/System.keychain"},
	}
	if len(*calls) != len(want) {
		t.Fatalf("ran %+v, want %v", *calls, want)
	}
	for i, call := range *calls {
		if !reflect.DeepEqual(call.argv, want[i]) {
			t.Errorf("command %d = %q, want %q", i, call.argv, want[i])
		}
		if call.removalsAlong != 0 {
			t.Errorf("command %d ran after the files were deleted", i)
		}
	}
	if removals(h) != 1 {
		t.Errorf("the agent was asked to delete the files %d times, want once", removals(h))
	}
	if out := h.out(); !strings.Contains(out, "Deleted the root 01:23:45") {
		t.Errorf("output does not say which root was deleted:\n%s", out)
	}
}

func TestRemoveRootOnLinuxDeletesTheAnchorItInstalledAndRebuildsTheBundle(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, heldRoot()))
	calls := fakeTrustStore(t, h, "linux", -1)

	if err := runIPSAgainst(h, "remove-root"); err != nil {
		t.Fatalf("ips remove-root: %v", err)
	}

	want := []tlsmint.Command{
		{"sudo", "rm", "/usr/local/share/ca-certificates/app-tail.crt"},
		{"sudo", "update-ca-certificates", "--fresh"},
	}
	got := make([]tlsmint.Command, 0, len(*calls))
	for _, c := range *calls {
		got = append(got, c.argv)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ran %q, want %q", got, want)
	}
}

// A trust-store command that failed leaves the files, so the removal can be run again, and the
// error names the way out for a root that was never installed.
func TestRemoveRootKeepsTheFilesWhenTheTrustStoreCommandFails(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, heldRoot()))
	calls := fakeTrustStore(t, h, "darwin", 0)

	err := runIPSAgainst(h, "remove-root")

	if err == nil || !strings.Contains(err.Error(), "files were kept") || !strings.Contains(err.Error(), "--files-only") {
		t.Fatalf("ips remove-root = %v, want the failure with the files kept and --files-only named", err)
	}
	if len(*calls) != 1 {
		t.Errorf("ran %d commands, want the rest skipped after the first failed", len(*calls))
	}
	if removals(h) != 0 {
		t.Error("the files were deleted although the root may still be trusted")
	}
}

// While interception is on, a removed root would be replaced at once, so nothing is touched.
func TestRemoveRootIsRefusedWhileInterceptionIsOn(t *testing.T) {
	view := heldRoot()
	view.On = true
	h := newHarness(t, ipsRoutes(t, view))
	calls := fakeTrustStore(t, h, "darwin", -1)

	err := runIPSAgainst(h, "remove-root")

	if err == nil || !strings.Contains(err.Error(), "settings set ips.intercept off") {
		t.Fatalf("ips remove-root = %v, want a refusal naming how to switch interception off", err)
	}
	if len(*calls) != 0 || removals(h) != 0 {
		t.Errorf("ran %d commands and %d removals while interception was on, want none", len(*calls), removals(h))
	}
}

// --files-only is for a root that was never installed: the trust store is left alone.
func TestRemoveRootWithFilesOnlyLeavesTheTrustStoreAlone(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, heldRoot()))
	calls := fakeTrustStore(t, h, "darwin", -1)

	if err := runIPSAgainst(h, "remove-root", "--files-only"); err != nil {
		t.Fatalf("ips remove-root --files-only: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("ran %q, want no trust-store command", (*calls)[0].argv)
	}
	if removals(h) != 1 {
		t.Errorf("the agent was asked to delete the files %d times, want once", removals(h))
	}
}

// On a system app-tail has no commands for, removal stops rather than deleting files the
// trust store may still depend on.
func TestRemoveRootOnAnUnknownSystemAsksForTheManualRoute(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, heldRoot()))
	fakeTrustStore(t, h, "plan9", -1)

	err := runIPSAgainst(h, "remove-root")

	if err == nil || !strings.Contains(err.Error(), "--files-only") {
		t.Fatalf("ips remove-root = %v, want it to point at --files-only", err)
	}
	if removals(h) != 0 {
		t.Error("the files were deleted on a system whose trust store was not touched")
	}
}

// With no root held there is nothing to delete, but an earlier root may still be trusted, so
// the command that takes one out is printed rather than run.
func TestRemoveRootWithNoRootRunsNothingAndPrintsTheCommand(t *testing.T) {
	view := heldRoot()
	view.Fingerprint = ""
	h := newHarness(t, ipsRoutes(t, view))
	calls := fakeTrustStore(t, h, "darwin", -1)

	if err := runIPSAgainst(h, "remove-root"); err != nil {
		t.Fatalf("ips remove-root: %v", err)
	}
	if len(*calls) != 0 || removals(h) != 0 {
		t.Errorf("ran %d commands and %d removals with no root held, want none", len(*calls), removals(h))
	}
	if out := h.out(); !strings.Contains(out, "nothing to delete") || !strings.Contains(out, view.Remove) {
		t.Errorf("output = %q, want it to say so and print the removal command", out)
	}
}

func TestIPSWithoutASubcommandIsAUsageError(t *testing.T) {
	h := newHarness(t, ipsRoutes(t, heldRoot()))

	if err := h.run("ips"); !errors.Is(err, ErrUsage) {
		t.Fatalf("ips = %v, want a usage error", err)
	}
}
