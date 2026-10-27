// SPDX-License-Identifier: MIT

//go:build !windows

package sysproxy

import (
	"strings"
	"testing"
)

// Both answers are rendered on the card as the whole explanation for why the switch is
// not there, so neither may be a stub for the other: a Linux user told the change "needs
// an administrator" would go looking for sudo, and a Mac user told there is "no single
// setting" would never find the command that does work.
func TestEachPlatformSaysWhyItsProxyCannotBeSetInItsOwnTerms(t *testing.T) {
	tests := []struct {
		goos string
		want string
	}{
		{"darwin", "needs an administrator"},
		{"linux", "no single proxy setting"},
		{"freebsd", "no single proxy setting"},
	}
	for _, tc := range tests {
		t.Run(tc.goos, func(t *testing.T) {
			supported, reason := unsupportedReason(tc.goos)
			if supported {
				t.Fatalf("%s reports a proxy setting app-tail can write, but this is the path for platforms that have none", tc.goos)
			}
			if !strings.Contains(reason, tc.want) {
				t.Errorf("%s explains itself as %q, want it to say %q", tc.goos, reason, tc.want)
			}
		})
	}
}

// The limits are what a user reads before deciding whether pointing programs at the proxy
// by hand is worth it, so each platform has to list its own. macOS has the per-service
// trap that makes a setting silently stop applying; everywhere else the point is that
// there was never one setting to begin with.
func TestEachPlatformListsTheLimitsThatActuallyApplyToIt(t *testing.T) {
	mac := limitsFor("darwin")
	if len(mac) < 2 {
		t.Fatalf("macOS lists %d limits, want both the per-service trap and the programs that ignore it", len(mac))
	}
	if !strings.Contains(strings.Join(mac, " "), "per network service") {
		t.Errorf("macOS limits read %v, want the per-service behaviour named", mac)
	}

	other := limitsFor("linux")
	if len(other) == 0 {
		t.Fatal("a platform with no single proxy setting lists no limits, so the card explains nothing")
	}
	if strings.Contains(strings.Join(other, " "), "per network service") {
		t.Errorf("limits read %v, want macOS's per-service behaviour left off a platform it does not apply to", other)
	}
}
