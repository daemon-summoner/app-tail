// SPDX-License-Identifier: MIT

//go:build !darwin && !windows

package clipboard

// commands returns the clipboard writers for Linux and the other Unixes, in the order
// they are tried. Which one works is a property of the running session rather than of
// the installation -- wl-copy needs a Wayland compositor, xclip and xsel need an X
// server -- so the list is walked rather than chosen between.
func commands() ([][]string, error) {
	return [][]string{
		{"wl-copy"},
		{"xclip", "-selection", "clipboard"},
		{"xsel", "--clipboard", "--input"},
	}, nil
}
