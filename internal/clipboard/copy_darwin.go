// SPDX-License-Identifier: MIT

package clipboard

// commands returns the clipboard writer for macOS. pbcopy ships with the system, so
// there is nothing to fall back to and nothing that can be missing.
func commands() ([][]string, error) {
	return [][]string{{"pbcopy"}}, nil
}
