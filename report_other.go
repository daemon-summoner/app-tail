// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"fmt"
	"os"
)

// reportFatal writes to standard error, which every process on these platforms is given --
// pointing at a terminal, or at the log of the launch agent or systemd unit that started it.
func reportFatal(message string) {
	fmt.Fprintf(os.Stderr, "app-tail: %s\n", message)
}
