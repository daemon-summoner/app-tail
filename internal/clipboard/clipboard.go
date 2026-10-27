// SPDX-License-Identifier: MIT

// Package clipboard puts text on the system clipboard.
//
// It shells out to the platform's own clipboard program rather than binding the
// window system, because the alternative needs cgo and this binary is built without
// it. The text travels on stdin, never as an argument, so nothing in it can be read
// as a flag or a shell word.
package clipboard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

// waitDelay bounds how long a finished clipboard program's output is waited on. Some of
// them fork and go on serving the selection after the command exits, holding the pipes
// they inherited open; without this, a copy that already succeeded never returns.
const waitDelay = 500 * time.Millisecond

// Copy puts text on the system clipboard.
func Copy(ctx context.Context, text string) error {
	candidates, err := commands()
	if err != nil {
		return err
	}
	return copyWith(ctx, candidates, text)
}

// copyWith takes the candidate programs as an argument so the order they are tried in can
// be exercised against programs whose behaviour is known.
func copyWith(ctx context.Context, candidates [][]string, text string) error {
	if err := checkText(text); err != nil {
		return err
	}
	if len(candidates) == 0 {
		return errors.New("this platform has no clipboard program app-tail knows how to use")
	}
	// Every candidate is tried: a machine can have wl-copy installed and no Wayland
	// session to talk to, and the next program is the one that works there.
	attempts := make([]error, 0, len(candidates))
	for _, argv := range candidates {
		err := run(ctx, argv, text)
		if err == nil {
			return nil
		}
		attempts = append(attempts, err)
	}
	return fmt.Errorf("could not put it on the clipboard: %w", errors.Join(attempts...))
}

// checkText rejects what a clipboard cannot usefully hold. An empty copy is the one
// worth naming: it leaves whatever was there before, so the click reads as having done
// nothing at all.
func checkText(text string) error {
	if text == "" {
		return errors.New("there is nothing to copy")
	}
	for _, r := range text {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return fmt.Errorf("refusing to copy %q: it contains a control character", text)
		}
	}
	return nil
}

func run(ctx context.Context, argv []string, text string) error {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	cmd.Stdin = strings.NewReader(text)
	cmd.WaitDelay = waitDelay
	hideConsole(cmd)
	// A program that exited cleanly and left the pipes to a child it forked has copied the
	// text; only the reading of its output was abandoned.
	out, err := cmd.CombinedOutput()
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		if said := strings.TrimSpace(string(out)); said != "" {
			return fmt.Errorf("%s: %w: %s", argv[0], err, said)
		}
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	return nil
}
