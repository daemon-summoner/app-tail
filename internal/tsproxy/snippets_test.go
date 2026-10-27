// SPDX-License-Identifier: MIT

package tsproxy

import (
	"strings"
	"testing"
)

// listening stands in for the instance the command line and the auto-configuration route
// reach when nothing names one, which is what every way of pointing a program at a proxy
// applies to.
func listening() SnippetConfig {
	return SnippetConfig{
		ProxyAddr:     "127.0.0.1:1080",
		DashboardAddr: "127.0.0.1:8377",
		Platform:      "darwin",
		Default:       true,
	}
}

// ids is what a client keys the commands on, which is what each test below asserts over.
func ids(cfg SnippetConfig) map[string]bool {
	out := map[string]bool{}
	for _, s := range Snippets(cfg) {
		out[s.ID] = true
	}
	return out
}

// socks5h is what makes the whole feature work: it leaves the name for the proxy to
// resolve. With socks5 the client resolves locally, and no MagicDNS name resolves on a
// machine running app-tail in userspace mode -- so every command would fail.
func TestTheSocksUrlLeavesNameResolutionToTheProxy(t *testing.T) {
	got := SOCKSURL(listening())
	if !strings.HasPrefix(got, "socks5h://") {
		t.Errorf("SOCKSURL = %q, want the socks5h scheme", got)
	}
	if strings.HasPrefix(got, "socks5://") {
		t.Error("SOCKSURL resolves names on the client, so MagicDNS names would fail")
	}
}

// Many tools mishandle a socks scheme in HTTP_PROXY, which is why the HTTP front end
// exists at all.
func TestTheHttpProxyUrlIsAnHttpUrl(t *testing.T) {
	if got := HTTPURL(listening()); !strings.HasPrefix(got, "http://") {
		t.Errorf("HTTPURL = %q, want an http URL", got)
	}
}

// Nothing is bound, so every URL would name a closed port.
func TestNothingIsOfferedWhileTheProxyIsNotListening(t *testing.T) {
	cfg := SnippetConfig{DashboardAddr: "127.0.0.1:8377", Platform: "darwin"}

	if got := SOCKSURL(cfg); got != "" {
		t.Errorf("SOCKSURL = %q with nothing bound, want empty", got)
	}
	if got := HTTPURL(cfg); got != "" {
		t.Errorf("HTTPURL = %q with nothing bound, want empty", got)
	}
	if got := Snippets(cfg); len(got) != 0 {
		t.Errorf("Snippets returned %d commands with nothing bound, want none", len(got))
	}
}

// A client handed a URL with no credential against a proxy that wants one gets an
// authentication failure it cannot diagnose from the message.
func TestTheUrlsCarryTheCredentialFormOnceOneIsRequired(t *testing.T) {
	cfg := listening()
	cfg.RequiresPassword = true

	for name, got := range map[string]string{"SOCKSURL": SOCKSURL(cfg), "HTTPURL": HTTPURL(cfg)} {
		if !strings.Contains(got, ProxyUser+":") {
			t.Errorf("%s = %q, want it to carry the proxy user", name, got)
		}
		if !strings.Contains(got, passwordPlaceholder) {
			t.Errorf("%s = %q, want a stand-in the user replaces", name, got)
		}
	}
}

// The commands go into a shell the user is actually running, and cmd.exe does not
// understand export.
func TestTheEnvironmentCommandUsesTheShellTheUserIsRunning(t *testing.T) {
	posix := envSnippet(listening(), "socks5h://127.0.0.1:1080", "http://127.0.0.1:1080")
	if !strings.Contains(posix, "export ALL_PROXY=") {
		t.Errorf("the POSIX command is %q, want export", posix)
	}

	win := listening()
	win.Platform = "windows"
	got := envSnippet(win, "socks5h://127.0.0.1:1080", "http://127.0.0.1:1080")
	if !strings.Contains(got, "set ALL_PROXY=") {
		t.Errorf("the Windows command is %q, want set", got)
	}
	if strings.Contains(got, "export ") {
		t.Errorf("the Windows command is %q, want no POSIX export", got)
	}
}

// Without the dashboard in NO_PROXY a program started from that shell that calls the
// app-tail API sends the call through the proxy, back to this same machine.
func TestTheEnvironmentCommandKeepsLocalCallsOffTheProxy(t *testing.T) {
	got := envSnippet(listening(), "socks5h://127.0.0.1:1080", "http://127.0.0.1:1080")

	for _, want := range []string{"127.0.0.1:8377", "localhost", "127.0.0.1", "::1"} {
		if !strings.Contains(got, want) {
			t.Errorf("NO_PROXY does not cover %q: %s", want, got)
		}
	}
}

// Launching a browser is a genuinely different command per platform, not one command
// quoted differently -- on macOS the app bundle is not on PATH at all.
func TestTheBrowserCommandMatchesThePlatform(t *testing.T) {
	tests := map[string]string{
		"darwin":  "open -na",
		"windows": `chrome.exe`,
		"linux":   "google-chrome",
	}
	for platform, want := range tests {
		cfg := listening()
		cfg.Platform = platform
		if got := chromeCommand(cfg); !strings.Contains(got, want) {
			t.Errorf("chromeCommand(%s) = %q, want it to contain %q", platform, got, want)
		}
	}
}

// The browser commands need somewhere to fetch the script from; without a dashboard
// address there is no URL to give them, so offering the command would mislead.
func TestTheBrowserCommandsAreOnlyOfferedWithAnAutoConfigUrl(t *testing.T) {
	cfg := listening()
	cfg.DashboardAddr = ""

	for _, s := range Snippets(cfg) {
		if s.ID == "chromium" || s.ID == "firefox" {
			t.Errorf("a browser command was offered with no auto-config URL: %+v", s)
		}
	}
	if got := PACURL(""); got != "" {
		t.Errorf("PACURL = %q with no dashboard address, want empty", got)
	}
}

// The commands that go back through app-tail itself -- and the browser script it serves --
// address the one instance the command line reaches when nothing names one. Offering them
// on another instance's card would point a program at the default proxy's permissions from
// a card describing a different set, which is the one mistake per-instance permissions
// exist to prevent.
func TestOnlyTheDefaultProxyIsOfferedTheWaysThatGoBackThroughTheApp(t *testing.T) {
	cfg := listening()
	cfg.Default = false

	got := ids(cfg)
	for _, id := range []string{"exec", "ssh", "chromium", "firefox"} {
		if got[id] {
			t.Errorf("%q was offered for an instance that is not the default one", id)
		}
	}
	// Something has to remain, or this guard would pass on a config that offers nothing at
	// all and the per-instance card would have no way to point a program at it.
	for _, id := range []string{"curl", "env"} {
		if !got[id] {
			t.Errorf("%q is not offered, so a non-default instance cannot be used at all", id)
		}
	}
}

// The gate above is only meaningful if the default instance still gets everything.
func TestTheDefaultProxyIsOfferedEveryWayOfPointingAProgramAtIt(t *testing.T) {
	got := ids(listening())
	for _, id := range []string{"exec", "ssh", "curl", "env", "chromium", "firefox"} {
		if !got[id] {
			t.Errorf("%q is not offered for the default proxy", id)
		}
	}
}

// Every command is something a user pastes, so each needs a label and a body, and the
// description is where the non-obvious part lives.
func TestEveryCommandIsCompleteEnoughToPaste(t *testing.T) {
	got := Snippets(listening())
	if len(got) == 0 {
		t.Fatal("no commands were offered for a listening proxy")
	}

	seen := map[string]bool{}
	for _, s := range got {
		if s.ID == "" || s.Label == "" || s.Command == "" || s.Description == "" {
			t.Errorf("incomplete command: %+v", s)
		}
		if seen[s.ID] {
			t.Errorf("two commands share the id %q, so a client keyed on it drops one", s.ID)
		}
		seen[s.ID] = true
	}
}

// The URLs carry a stand-in where the password goes, so every command that pastes one
// has to say what to put there and who the user name is. Without it the command looks
// complete, runs, and fails authentication with nothing on screen explaining why.
func TestEveryCommandSaysWhatToReplaceOnceAPasswordIsRequired(t *testing.T) {
	cfg := listening()
	cfg.RequiresPassword = true

	carriesPlaceholder := 0
	for _, s := range Snippets(cfg) {
		if !strings.Contains(s.Command, passwordPlaceholder) {
			continue
		}
		carriesPlaceholder++
		if !strings.Contains(s.Description, passwordPlaceholder) {
			t.Errorf("%s pastes a stand-in password but never says to replace it: %q", s.ID, s.Description)
		}
		if !strings.Contains(s.Description, ProxyUser) {
			t.Errorf("%s asks for a password without naming the user it goes with: %q", s.ID, s.Description)
		}
	}
	if carriesPlaceholder == 0 {
		t.Fatal("no command carries the password stand-in, so this guard covers nothing")
	}
}
