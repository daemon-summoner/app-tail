// Package ui embeds the built dashboard so the agent ships as a single binary.
//
// The dist directory is produced by `npm run build` in this directory; the script
// quartet at the repo root builds it before any Go build, because go:embed fails
// outright when it is missing.
package ui

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built dashboard rooted at the directory holding index.html.
func FS() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("open the embedded dashboard: %w", err)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, fmt.Errorf(
			"the embedded dashboard has no index.html; run `npm run build` in ui/: %w", err)
	}
	return sub, nil
}
