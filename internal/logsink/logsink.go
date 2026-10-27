// SPDX-License-Identifier: MIT

// Package logsink decides where this process writes what it has to say.
//
// It exists for one platform and one build: the Windows agent is linked with
// -H=windowsgui so that starting it from Explorer does not leave a console window on
// screen, and a process linked that way has no standard error at all. Every message
// this program produces before the dashboard is up -- a config file it cannot parse, a
// port already taken, a driver that is not installed -- is written to that handle, so
// on the build most people run it was written nowhere.
//
// Where there is somewhere to write, this changes nothing: standard error is returned
// as it is, and no file is created.
package logsink

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/fileown"
)

// fileName is the log a run with nowhere to print writes to. It sits in the state
// directory, beside the config file it is most often complaining about.
const fileName = "app-tail.log"

// maxBytes is how large the log grows before the previous run's is set aside. One
// generation is kept: this is read after something went wrong, and what is wanted then
// is this start and the one before it, not a month of them.
const maxBytes = 4 << 20

// previousSuffix names the set-aside generation.
const previousSuffix = ".1"

// Open returns where this process should write its diagnostics.
//
// The returned closer is always safe to call, and closes nothing when the sink is
// standard error. stateDir is asked for a directory only when a file is needed, and never
// where standard error works: it is resolved from the account this process runs as, and
// the root helper launchd starts has no account directory to resolve. The directory is
// created if it does not exist, since the alternative is discarding the diagnostics for a
// state directory that could not be made.
func Open(stateDir func() (string, error)) (io.Writer, func() error, error) {
	if StderrUsable() {
		return os.Stderr, func() error { return nil }, nil
	}
	dir, err := stateDir()
	if err != nil {
		return nil, nil, fmt.Errorf("this build has no console to write to and the state directory for a log could not be located: %w", err)
	}
	return openFile(dir)
}

// openFile is Open's file half, without the platform question, so the rotation and the
// permissions are exercised on every machine rather than only on a Windows GUI build.
func openFile(stateDir string) (io.Writer, func() error, error) {
	if err := os.MkdirAll(stateDir, config.DirMode); err != nil {
		return nil, nil, fmt.Errorf("this build has no console to write to and %s could not be created for a log: %w", stateDir, err)
	}
	path := filepath.Join(stateDir, fileName)
	// A log that cannot be set aside is not a reason to start with the diagnostics going
	// nowhere. Windows opens files without FILE_SHARE_DELETE, so anything else holding this
	// log open -- a second agent, a text editor, a tail -- makes the rename fail, and a run
	// that hits that needs somewhere to write far more than it needs a fresh file. The
	// failure goes into the log it could not rotate.
	rotateErr := rotate(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, config.FileMode)
	if err != nil {
		return nil, nil, fmt.Errorf("this build has no console to write to and %s could not be opened for a log: %w", path, err)
	}
	if err := fileown.RestrictToOwner(path); err != nil {
		return nil, nil, discard(file, fmt.Errorf("this build has no console to write to and %s could not be narrowed to this account for a log: %w", path, err))
	}
	if rotateErr != nil {
		if _, err := fmt.Fprintf(file, "app-tail: %v; this log grows past its %d byte cap until that is resolved\n", rotateErr, maxBytes); err != nil {
			return nil, nil, discard(file, fmt.Errorf("write to the log at %s: %w", path, err))
		}
	}
	return file, file.Close, nil
}

// discard closes a log this call is giving up on and returns the reason it gave up, so a
// failure after the open does not leak the handle it opened.
func discard(file *os.File, cause error) error {
	if err := file.Close(); err != nil {
		return errors.Join(cause, fmt.Errorf("close %s: %w", file.Name(), err))
	}
	return cause
}

// rotate sets the current log aside when it has grown past the cap, so an agent left
// running for months cannot fill the disk it is logging to.
func rotate(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the size of %s: %w", path, err)
	}
	if info.Size() < maxBytes {
		return nil
	}
	if err := os.Rename(path, path+previousSuffix); err != nil {
		return fmt.Errorf("set aside the previous %s: %w", path, err)
	}
	return nil
}
