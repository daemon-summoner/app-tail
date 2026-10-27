// SPDX-License-Identifier: MIT

// Package alert puts one message in front of the user on a build that has nowhere to print
// one.
//
// The windowed Windows build is linked with -H=windowsgui and is handed no standard error, so
// a line written there goes nowhere at all: no console appears, and the only trace of a
// refusal is a machine that behaves as though nothing was said. That build is the reason this
// exists, and it is the only one that gets a dialog -- everywhere else a terminal or a log is
// already carrying the same sentence.
package alert

// Show puts message in front of the user, returning once it has been dismissed. A caller on
// a startup path is holding that path open for as long as the message is up.
func Show(message string) { show(message) }
