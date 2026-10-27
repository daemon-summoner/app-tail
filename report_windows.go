// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/sellitus/app-tail/internal/logsink"
)

// reportFatal puts a message where somebody will see it, for the failures that happen
// before there is anywhere to log to and the ones that happen after the log is closed.
//
// The windowed build is linked with -H=windowsgui and is handed no standard error at all, so
// a run that could not open its log file has nowhere left to say so: it would exit with a
// status nobody reads and a window that never appeared. A message box is the one surface such
// a build still has.
//
// Nothing here reports its own failure, because there is nowhere left to report it to. This
// runs on the way out of a process that is ending either way.
func reportFatal(message string) {
	if logsink.StderrUsable() {
		fmt.Fprintf(os.Stderr, "app-tail: %s\n", message)
		return
	}
	text, textErr := windows.UTF16PtrFromString("app-tail: " + message)
	caption, captionErr := windows.UTF16PtrFromString("app-tail")
	if textErr != nil || captionErr != nil {
		fmt.Fprintf(os.Stderr, "app-tail: %s\n", message)
		return
	}
	windows.MessageBox(0, text, caption, //nolint:errcheck // there is nowhere left to report a failure to; see above.
		windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}
