// SPDX-License-Identifier: MIT

package tsnode

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"

	"github.com/sellitus/app-tail/internal/config"
)

// A login URL is a credential until someone opens it: whoever has it first signs their
// own account in as this device. The log is read by more people and kept longer than the
// dashboard, so the URL is shown on the dashboard and withheld from every log line --
// both the lines a person sees and the tailscale stack's own, on either stack.
func TestTheLoginURLNeverReachesTheLog(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	n := New(Options{
		Params:  ServerParams{Hostname: "redact-test", Mode: AuthInteractive, Dir: t.TempDir()},
		Logger:  logger,
		Verbose: true,
	})
	srv, ok := n.srv.(*tsnet.Server)
	if !ok {
		t.Fatalf("backend is %T, want the userspace stack", n.srv)
	}

	const tailscaleLogin = "https://login.tailscale.com/a/1a2b3c4d5e6f"
	const headscaleLogin = "http://hs.example.net:8080/register/nodekey:0123abcd"
	// A control server free to put its login page anywhere is caught by remembering the
	// exact URL the backend handed over.
	const oddLogin = "https://sso.example.net/device?code=WXYZ-1234"
	n.applyNotify(t.Context(), ipn.Notify{BrowseToURL: ptrTo(oddLogin)})

	srv.UserLogf("To start this tsnet server, restart with TS_AUTHKEY set, or go to: %s", tailscaleLogin)
	srv.Logf("control: %s", headscaleLogin)
	srv.UserLogf("visit %s to finish", oddLogin)
	srv.UserLogf("control server is %s", "https://controlplane.tailscale.com/key?v=130")

	tun := New(Options{
		Params:  ServerParams{Hostname: "redact-tun-test", Mode: AuthInteractive, Network: config.NetworkTUN, Dir: t.TempDir()},
		Logger:  logger,
		Verbose: true,
	})
	backend, ok := tun.srv.(*tunBackend)
	if !ok {
		t.Fatalf("backend is %T, want the interface stack", tun.srv)
	}
	backend.userLogf("go to: %s", tailscaleLogin)
	backend.logf("auth: %s", headscaleLogin)

	logged := out.String()
	for _, url := range []string{tailscaleLogin, headscaleLogin, oddLogin, "1a2b3c4d5e6f", "nodekey:0123abcd", "WXYZ-1234"} {
		if strings.Contains(logged, url) {
			t.Errorf("the log carries %q:\n%s", url, logged)
		}
	}
	if got := strings.Count(logged, loginURLWithheld); got != 5 {
		t.Errorf("%d lines say the login URL was withheld, want 5:\n%s", got, logged)
	}
	// Only login URLs are withheld; the control server's address is what a person
	// debugging a connection needs to see.
	if !strings.Contains(logged, "https://controlplane.tailscale.com/key?v=130") {
		t.Errorf("an ordinary URL was withheld too:\n%s", logged)
	}
}

// tsnet uploads its log to Tailscale's log service unless the process has switched that
// off, and that log carries the login URL. The switch is thrown when a node is built, so
// it is already off by the time any node can start.
func TestLogUploadIsDisabledBeforeANodeStarts(t *testing.T) {
	New(Options{
		Params: ServerParams{Hostname: "upload-test", Mode: AuthInteractive, Dir: t.TempDir()},
		Logger: quietLogger(),
	})
	if !envknob.NoLogsNoSupport() {
		t.Error("a node was built with log upload still switched on")
	}
}

// stopAtStart is a backend whose Start reports what the state directory held at that
// moment and then fails, so the node goes no further.
type stopAtStart struct {
	backend
	dir  string
	seen []string
}

var errStoppedAtStart = errors.New("stopped at start")

func (s *stopAtStart) Start() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s.seen = append(s.seen, e.Name())
	}
	return errStoppedAtStart
}

// Switching upload off stops new lines from being kept, but a buffer left on disk by an
// earlier run -- one that may hold a login URL -- would still be sent the next time the
// stack starts. It is deleted first. Everything else in the directory is the node's
// identity and stays exactly as it was.
func TestLeftoverLogBuffersAreDeletedBeforeANodeStarts(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"tailscaled.log1.txt", "tailscaled.log2.txt", "tailscaled.log.conf", "tailscaled.state", "notes.txt"} {
		write(name)
	}
	if err := os.Mkdir(filepath.Join(dir, "tailscaled.logs.txt"), 0o700); err != nil {
		t.Fatal(err)
	}

	n := New(Options{
		Params: ServerParams{Hostname: "buffer-test", Mode: AuthInteractive, Dir: dir},
		Logger: quietLogger(),
	})
	fake := &stopAtStart{dir: dir}
	n.srv = fake
	if err := n.Start(t.Context()); !errors.Is(err, errStoppedAtStart) {
		t.Fatalf("Start = %v, want it to reach the backend", err)
	}

	want := []string{"notes.txt", "tailscaled.log.conf", "tailscaled.logs.txt", "tailscaled.state"}
	if strings.Join(fake.seen, ",") != strings.Join(want, ",") {
		t.Errorf("the backend started with %v in its directory, want %v", fake.seen, want)
	}
}

func ptrTo[T any](v T) *T { return &v }
