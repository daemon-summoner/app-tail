// SPDX-License-Identifier: MIT

// Package browser opens a URL in the user's default browser.
//
// It is used for two things: showing the loopback dashboard, and handing the user
// the Tailscale login URL. Both are user-visible conveniences, so a failure here is
// reported to the caller rather than hidden -- the caller prints the URL instead.
package browser

import (
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

// command is how this platform's launcher is named. It is a variable so a test can stand
// in a program that is not installed: reporting that failure is what the caller's fallback
// -- printing the URL instead -- depends on, and every platform's real launcher is present
// on the machines the tests run on.
var command = platformCommand

// Open launches url in the user's default browser.
func Open(rawURL string) error {
	if err := checkURL(rawURL); err != nil {
		return err
	}
	name, args, err := command(rawURL)
	if err != nil {
		return err
	}
	// The launcher is handed to the operating system and released below, so a context
	// that could cancel it would cancel the user's browser opening.
	cmd := exec.Command(name, args...) //nolint:noctx // outliving this call is the point; see below.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch %s: %w", name, err)
	}
	// The browser outlives this process; reaping it here would block until the user
	// closes their browser. Release lets the OS adopt it.
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release %s: %w", name, err)
	}
	return nil
}

// checkURL rejects anything that is not a plain web URL. The opener passes its
// argument to a system handler, so a "file://" or "javascript:" URL reaching it
// would be a real capability, and a leading dash would be read as a flag.
func checkURL(rawURL string) error {
	if strings.HasPrefix(rawURL, "-") {
		return fmt.Errorf("refusing to open %q: a URL starting with a dash would be read as a command-line flag", rawURL)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("refusing to open %q: %w", rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("refusing to open %q: only http and https URLs are opened, got scheme %q", rawURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("refusing to open %q: it names no host", rawURL)
	}
	return nil
}
