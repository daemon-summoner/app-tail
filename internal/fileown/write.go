// SPDX-License-Identifier: MIT

package fileown

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteRestricted replaces path in one step, through a temporary file in the same directory,
// with the permissions and the owner of a file only an administrator may write.
//
// The callers' files are the ones that remember what an elevated app-tail changed about this
// machine. A truncating write that a killed process interrupts leaves a file that parses as
// nothing, and a record that parses as nothing leaves the machine changed with no way back to
// what the user had.
//
// The permissions and the owner are set on the temporary file, before the rename rather than
// after it: both travel with the file, so the record is never briefly writable by another
// account at the path something else reads it from.
func WriteRestricted(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	discard := func(cause error) error {
		return errors.Join(cause, tmp.Close(), os.Remove(name))
	}
	if err := tmp.Chmod(mode); err != nil {
		return discard(fmt.Errorf("narrow %s: %w", path, err))
	}
	if err := RestrictToAdministrators(name); err != nil {
		return discard(fmt.Errorf("narrow %s: %w", path, err))
	}
	if _, err := tmp.Write(data); err != nil {
		return discard(fmt.Errorf("write %s: %w", path, err))
	}
	if err := tmp.Sync(); err != nil {
		return discard(fmt.Errorf("write %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), os.Remove(name))
	}
	if err := replace(name, path); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), os.Remove(name))
	}
	return nil
}

// MakeRestrictedDir creates the directory a restricted file lives in, and narrows it.
//
// The narrowing is repeated on every write rather than done once at creation: the mode bits
// carry it everywhere but Windows, where the directory this lives under can be created by any
// account before app-tail ever runs elevated.
func MakeRestrictedDir(dir string, mode fs.FileMode) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("make %s: %w", dir, err)
	}
	if err := RestrictTreeToAdministrators(dir); err != nil {
		return fmt.Errorf("narrow %s: %w", dir, err)
	}
	return nil
}
