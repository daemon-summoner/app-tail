// SPDX-License-Identifier: MIT

// Package grantwrite stores what an administrator approves. Only the commands an
// administrator runs import it -- `app-tail tun grant` and the helper's installer -- so
// nothing the unprivileged agent runs can reach the code that writes approvals.
package grantwrite

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sellitus/app-tail/internal/fileown"
	"github.com/sellitus/app-tail/internal/grants"
)

// ownDir makes the folder holding the approvals root's alone. A seam so a suite running
// unprivileged can write into a folder of its own.
var ownDir = restrictDir

// Write replaces the approvals at path with doc in one step, readable by everyone and
// writable by root alone. A reader sees the old approvals or the new ones, never part of
// either.
func Write(path string, doc grants.Document) error {
	data, err := doc.Encode()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("make %s: %w", dir, err)
	}
	if err := ownDir(dir); err != nil {
		return fmt.Errorf("make %s root's alone: %w", dir, err)
	}
	return fileown.WriteRestricted(path, data, 0o644)
}
