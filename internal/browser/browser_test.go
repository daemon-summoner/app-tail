// SPDX-License-Identifier: MIT

package browser

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// Open hands its argument to a system handler, so the guard in front of it is the
// only thing standing between a malformed stored URL and an unexpected launch.
func TestOpenRefusesAnythingThatIsNotAPlainWebURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr string
	}{
		{"http dashboard", "http://127.0.0.1:8377/", ""},
		{"https login", "https://login.tailscale.com/a/0123456789abcdef", ""},
		{"file", "file:///etc/passwd", "only http and https"},
		{"javascript", "javascript:alert(1)", "only http and https"},
		{"scheme-less", "127.0.0.1:8377", "refusing to open"},
		{"empty", "", "only http and https"},
		{"no host", "http://", "names no host"},
		{"leading dash", "-http://example.com", "command-line flag"},
		{"control characters", "http://exa\x7fmple.com/\x00", "refusing to open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkURL(tc.url)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkURL(%q) = %v, want nil", tc.url, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkURL(%q) = nil, want an error mentioning %q", tc.url, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("checkURL(%q) = %q, want it to mention %q", tc.url, err, tc.wantErr)
			}
		})
	}
}

// The URL must reach the launcher as one intact argument. A launcher that folded it
// into a shell string would let a query parameter run a command, and one that split
// it would open the wrong page.
func TestLauncherPassesTheURLAsASingleUnmodifiedArgument(t *testing.T) {
	// A real Tailscale login URL carries a query string; ampersands are the classic
	// place URL launching goes wrong.
	rawURL := "https://login.tailscale.com/a/abc?next=%2Fadmin&x=1"

	name, args, err := command(rawURL)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	if name == "" {
		t.Fatal("no launcher command for this platform")
	}
	if strings.ContainsAny(name, " |&;<>$") {
		t.Errorf("launcher %q looks like a shell string, not a program name", name)
	}

	var found bool
	for _, arg := range args {
		if arg == rawURL {
			found = true
			continue
		}
		if strings.Contains(arg, rawURL) {
			t.Errorf("argument %q wraps the URL instead of passing it verbatim", arg)
		}
	}
	if !found {
		t.Errorf("launcher args %q do not contain the URL as its own argument", args)
	}
}

// A URL that fails validation must never reach exec, so Open has to return the
// validation error rather than attempting a launch.
func TestOpenReturnsTheValidationErrorWithoutLaunchingAnything(t *testing.T) {
	err := Open("file:///etc/passwd")
	if err == nil {
		t.Fatal("Open accepted a file:// URL")
	}
	if !strings.Contains(err.Error(), "only http and https") {
		t.Errorf("Open error = %q, want the validation message", err)
	}
}

// A launcher that is not installed -- xdg-open missing from a minimal container, a
// stripped PATH under a login item -- has to be reported, not swallowed. The caller
// prints the URL instead, which is the whole fallback: a silent failure leaves the
// user staring at a dashboard that never opened with nothing to click.
func TestALauncherThatCannotStartIsReportedRatherThanIgnored(t *testing.T) {
	// A launcher named but not installed, with an empty PATH so the bare name resolves
	// nowhere. Windows names its launcher by full path, so removing PATH alone would still
	// start the real one.
	const missing = "app-tail-no-such-launcher"
	t.Setenv("PATH", "")
	restore := command
	command = func(rawURL string) (string, []string, error) { return missing, []string{rawURL}, nil }
	t.Cleanup(func() { command = restore })

	// Port 1 so that even a launcher that somehow did start opens a dead loopback
	// page rather than anything real.
	err := Open("http://127.0.0.1:1/")

	if err == nil {
		t.Fatal("Open reported success with no launcher on PATH; the caller would never " +
			"print the URL and the user would see nothing at all")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("err = %v, want it to name the launcher %q it could not run", err, missing)
	}
	// The lookup failure itself has to survive, or "launch open" says nothing about
	// whether the program is missing, unreadable, or the wrong architecture.
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("err = %v, want it to wrap the underlying lookup failure", err)
	}
}
