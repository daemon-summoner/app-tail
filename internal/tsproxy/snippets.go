// SPDX-License-Identifier: MIT

package tsproxy

import (
	"fmt"
	"net/url"
)

// Snippet is one ready-to-run command that points a program at the proxy.
//
// They are built here rather than in the dashboard for one reason: a shell command
// assembled in the UI is a shell command nothing tests. The quoting, the socks5h scheme
// and the credential form are each easy to get subtly wrong and impossible to notice
// until a user pastes one and it fails.
type Snippet struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Command     string `json:"command"`
}

// SnippetConfig is what the commands are rendered from.
type SnippetConfig struct {
	// ProxyAddr is the bound host:port. Empty means nothing is listening, and no
	// command is offered rather than one that would fail.
	ProxyAddr string
	// DashboardAddr is the host:port serving the auto-config script.
	DashboardAddr string
	// RequiresPassword makes the URLs carry the credential form, since a client given
	// a URL without one gets an authentication failure it cannot diagnose.
	RequiresPassword bool
	// Platform is a runtime.GOOS value, deciding the shell syntax and how a browser is
	// launched. It is a field rather than a runtime.GOOS read so every platform's
	// commands stay testable from one machine.
	Platform string
	// Default reports that this is the proxy `app-tail exec`, `app-tail proxy connect` and
	// the auto-configuration route reach when nothing names one.
	//
	// The ways of pointing a program at a proxy that go back through app-tail itself are
	// offered only for it. On any other instance they would point a program at the default
	// proxy's permissions from a card describing a different set -- which is the one mistake
	// per-instance permissions exist to prevent.
	Default bool
}

// passwordPlaceholder stands in for the configured password. The real one is a stored
// secret and is redacted everywhere else in the API, so echoing it into a command the
// dashboard displays would be the one place it leaks.
const passwordPlaceholder = "PASSWORD"

// SOCKSURL is the proxy as a client library expects it.
//
// The scheme is socks5h, not socks5: with socks5 the client resolves the name itself
// and a MagicDNS name fails, since only the proxy can resolve one.
func SOCKSURL(cfg SnippetConfig) string {
	return proxyURL("socks5h", cfg)
}

// HTTPURL is the proxy as HTTP_PROXY expects it. Many tools mishandle a socks scheme
// in that variable, so the HTTP front end is what goes there.
func HTTPURL(cfg SnippetConfig) string {
	return proxyURL("http", cfg)
}

func proxyURL(scheme string, cfg SnippetConfig) string {
	if cfg.ProxyAddr == "" {
		return ""
	}
	u := url.URL{Scheme: scheme, Host: cfg.ProxyAddr}
	if cfg.RequiresPassword {
		u.User = url.UserPassword(ProxyUser, passwordPlaceholder)
	}
	return u.String()
}

// PACURL is where a browser fetches the auto-config script.
func PACURL(dashboardAddr string) string {
	if dashboardAddr == "" {
		return ""
	}
	return "http://" + dashboardAddr + "/proxy.pac"
}

// Snippets renders every way to point something at the proxy, in the order a user
// would try them: the one that needs no configuration first.
func Snippets(cfg SnippetConfig) []Snippet {
	if cfg.ProxyAddr == "" {
		return nil
	}

	socks := SOCKSURL(cfg)
	httpProxy := HTTPURL(cfg)
	credential := ""
	if cfg.RequiresPassword {
		credential = fmt.Sprintf(
			" Replace %s with the proxy password you set; the user name is %q.",
			passwordPlaceholder, ProxyUser)
	}

	out := []Snippet{}
	if cfg.Default {
		out = append(out, Snippet{
			ID:    "exec",
			Label: "Run a command through the tailnet",
			Description: "Sets every proxy variable for one command and nothing else on the machine." +
				" Tailnet names and addresses work verbatim inside it.",
			Command: "app-tail exec -- curl http://peer.your-tailnet.ts.net:8080/",
		}, Snippet{
			ID:          "ssh",
			Label:       "SSH to a peer",
			Description: "Works identically on macOS, Linux and Windows; it needs no netcat.",
			Command:     `ssh -o ProxyCommand="app-tail proxy connect %h %p" user@peer.your-tailnet.ts.net`,
		})
	}
	out = append(out, Snippet{
		ID:    "curl",
		Label: "curl",
		Description: "--socks5-hostname is what leaves the name for the proxy to resolve;" +
			" --socks5 would resolve it locally and fail." + credential,
		Command: fmt.Sprintf("curl --socks5-hostname %s http://peer.your-tailnet.ts.net:8080/", curlTarget(cfg)),
	}, Snippet{
		ID:          "env",
		Label:       "Proxy environment variables",
		Description: "Applies to every program started from this shell that honours them." + credential,
		Command:     envSnippet(cfg, socks, httpProxy),
	})

	// The script the two browser entries name is served for the default proxy, so they are
	// gated here rather than only at the caller: a dashboard address handed in for another
	// instance would otherwise point a browser at the default proxy's permissions.
	if pac := PACURL(cfg.DashboardAddr); cfg.Default && pac != "" {
		out = append(out, Snippet{
			ID:    "chromium",
			Label: "Chrome or Edge",
			Description: "Starts the browser against the auto-config script, so tailnet names go" +
				" through the proxy and everything else goes direct. Close the browser first," +
				" or it reuses the running process and ignores the flag.",
			Command: fmt.Sprintf("%s --proxy-pac-url=%s", chromeCommand(cfg), pac),
		}, Snippet{
			ID:    "firefox",
			Label: "Firefox",
			Description: "Firefox has its own proxy setting and ignores the system one." +
				" Settings > Network Settings > Automatic proxy configuration URL:",
			Command: pac,
		})
	}
	return out
}

// curlTarget is the host:port curl wants, with the credential passed the way curl takes
// it -- it has no place for one inside --socks5-hostname.
func curlTarget(cfg SnippetConfig) string {
	if cfg.RequiresPassword {
		return fmt.Sprintf("%s:%s@%s", ProxyUser, passwordPlaceholder, cfg.ProxyAddr)
	}
	return cfg.ProxyAddr
}

// envSnippet writes the variables in the shell the user is actually running.
//
// NO_PROXY carries the dashboard's own address as well as loopback: without it a
// program started from this shell that calls the app-tail API would send that call
// through the proxy, back to the same machine.
func envSnippet(cfg SnippetConfig, socks, httpProxy string) string {
	noProxy := "localhost,127.0.0.1,::1"
	if cfg.DashboardAddr != "" {
		noProxy += "," + cfg.DashboardAddr
	}

	if cfg.Platform == "windows" {
		return fmt.Sprintf("set ALL_PROXY=%s\r\nset HTTP_PROXY=%s\r\nset HTTPS_PROXY=%s\r\nset NO_PROXY=%s",
			socks, httpProxy, httpProxy, noProxy)
	}
	return fmt.Sprintf("export ALL_PROXY=%q\nexport HTTP_PROXY=%q\nexport HTTPS_PROXY=%q\nexport NO_PROXY=%q",
		socks, httpProxy, httpProxy, noProxy)
}

// chromeCommand is how the browser is launched with a flag on each platform. They are
// genuinely different commands, not one command with different quoting: macOS goes
// through open(1) because the app bundle is not on PATH.
func chromeCommand(cfg SnippetConfig) string {
	switch cfg.Platform {
	case "windows":
		return `"C:\Program Files\Google\Chrome\Application\chrome.exe"`
	case "darwin":
		return `open -na "Google Chrome" --args`
	default:
		return "google-chrome"
	}
}
