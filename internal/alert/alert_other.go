// SPDX-License-Identifier: MIT

//go:build !windows

package alert

import (
	"fmt"
	"os"
)

// show writes to standard error, which on these platforms is always somewhere: app-tail is
// started from a terminal, from launchd or from a service manager, and all three keep one.
// There is no windowed build here with nothing behind it, so there is nothing for a dialog to
// rescue.
func show(message string) {
	fmt.Fprintf(os.Stderr, "app-tail: %s\n", message)
}
