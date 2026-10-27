// SPDX-License-Identifier: MIT

//go:build !windows

package elevate

// Relaunch is what a platform that does not obtain rights this way answers with.
//
// macOS and Linux install a small root helper instead, so an elevated agent there would
// put the tray, the dashboard and the config directory into a root process to obtain
// something the helper already holds. Refusing is the design rather than a gap in it.
func Relaunch(Request) error { return ErrUnsupported }
