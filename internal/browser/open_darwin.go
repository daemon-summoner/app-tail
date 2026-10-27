// SPDX-License-Identifier: MIT

package browser

// platformCommand returns the launcher for macOS. Arguments are passed as a list, never
// through a shell, so a URL containing shell metacharacters cannot execute anything.
func platformCommand(rawURL string) (string, []string, error) {
	return "open", []string{rawURL}, nil
}
