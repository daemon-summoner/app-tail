// SPDX-License-Identifier: MIT

//go:build unix

package tsnode

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sellitus/app-tail/internal/hostnet"
)

// helperOwnerEnv names the account the helper takes commands from. The installer writes it
// into the helper's launch configuration, so a helper started by a test has to set it too
// or it refuses every connection.
const helperOwnerEnv = "APPTAIL_HELPER_OWNER"

// startHelper runs a real helper on a socket of its own and returns its path. Nothing here
// stands in for the privileged side: the report's whole claim is that the socket, the
// access check, the framing and the version handshake all work, and a stand-in would
// answer for none of them.
func startHelper(t *testing.T) string {
	t.Helper()
	t.Setenv(helperOwnerEnv, strconv.Itoa(os.Getuid()))

	// A unix socket path is bounded well below what a test's own name would produce, so
	// it goes somewhere short instead of under t.TempDir().
	dir, err := os.MkdirTemp("", "atr")
	if err != nil {
		t.Fatalf("make a directory for the socket: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove the socket directory: %v", err)
		}
	})
	path := filepath.Join(dir, "h.sock")

	ln, err := hostnet.ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := hostnet.Serve(ctx, ln, func(string, ...any) {}); err != nil {
			t.Errorf("the helper stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return path
}

// The state the report exists to distinguish: a helper that is really there and answering.
// Every other branch says why the mode cannot be turned on, and this is the only one that
// proves the path they describe the absence of actually works.
func TestAHelperThatAnswersIsReportedRunningWithWhatItSees(t *testing.T) {
	socket := startHelper(t)

	caps, err := probeHelper(t.Context(), socket, func(string, ...any) {})
	if err != nil {
		t.Fatalf("probe the helper: %v", err)
	}

	report := InterfaceReport{Helper: InterfaceHelperReport{Socket: socket}}
	applyHelperProbe(&report, caps, nil)

	if !report.Helper.Running {
		t.Error("a helper that answered is not reported as running")
	}
	if report.Helper.Problem != "" {
		t.Errorf("a helper that answered carries a problem: %q", report.Helper.Problem)
	}
	if report.Helper.Version == "" {
		t.Error("a helper that answered reported no version, so nothing says which build it is")
	}
}

// A report that named one socket and tried another would send someone to check a path
// nothing ever dialled.
func TestTheSocketTheReportNamesIsTheOneItTried(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "absent.sock")

	_, err := probeHelper(t.Context(), socket, func(string, ...any) {})
	if err == nil {
		t.Fatal("probing a socket with nothing behind it succeeded")
	}
	if !strings.Contains(err.Error(), socket) {
		t.Errorf("the failure is %q, which does not name the socket %q it was given", err, socket)
	}
}
