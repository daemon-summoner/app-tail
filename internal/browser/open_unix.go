// SPDX-License-Identifier: MIT

//go:build !darwin && !windows

package browser

// platformCommand returns the launcher for Linux and the other Unixes. xdg-open is the
// freedesktop standard and is present on every desktop environment that has a
// browser to open in the first place.
func platformCommand(rawURL string) (string, []string, error) {
	return "xdg-open", []string{rawURL}, nil
}
