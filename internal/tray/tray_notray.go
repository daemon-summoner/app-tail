// SPDX-License-Identifier: MIT

//go:build notray

package tray

import (
	"context"
	"errors"
)

// This build has no tray front end. It exists so the binary can be produced with
// CGO_ENABLED=0 -- systray needs cgo on macOS and Windows -- and for containers,
// where a tray would be meaningless. Everything else, including the dashboard, is
// unchanged; the agent simply runs headless.

// Supported reports whether a tray icon can be shown, which it never can here.
func Supported() bool {
	return false
}

// Options configures the tray front end. It is kept identical to the tray build so
// main compiles unchanged.
type Options struct {
	// Controller is the agent the menu would drive.
	Controller Controller
	// OnError would receive action failures.
	OnError func(error)
}

// Run always fails, so a caller that reaches it falls back to headless rather than
// blocking forever on a tray that will never appear.
func Run(context.Context, Options) error {
	return errors.New("tray: this binary was built without tray support (-tags notray); run with --headless")
}
