// SPDX-License-Identifier: MIT

package alert

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/sellitus/app-tail/internal/logsink"
)

// show writes to standard error when there is one and raises a message box when there is not.
//
// Nothing here reports its own failure, because this is the surface of last resort: a caller
// reaches it precisely because everywhere else it could have said this is unavailable.
//
// MessageBox is safe from any thread and needs no COM apartment, unlike the ShellExecute the
// elevation prompt goes through, so this carries no requirement about where it is called from.
func show(message string) {
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
