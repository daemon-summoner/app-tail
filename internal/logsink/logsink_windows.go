// SPDX-License-Identifier: MIT

package logsink

import "golang.org/x/sys/windows"

// StderrUsable reports whether this process has a standard error to write to.
//
// A process linked with -H=windowsgui is given no standard handles at all, and the
// question is exactly that -- not whether the handle is a console. A console build with
// its output redirected to a file or a pipe holds a perfectly usable handle that is not
// a console, and must keep writing there rather than divert into a log file nobody asked
// for.
func StderrUsable() bool {
	handle, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err != nil {
		return false
	}
	return handle != 0 && handle != windows.InvalidHandle
}
