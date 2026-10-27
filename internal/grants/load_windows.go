// SPDX-License-Identifier: MIT

package grants

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sellitus/app-tail/internal/fileown"
)

// Load reads the approvals at path. No file there is a machine with no approvals. A file that
// is there and cannot be relied on is an error: one, or a folder holding one, that belongs to
// an account other than the administrators, or one that does not parse. The caller refuses
// whatever needed an approval in that case, which is what an unreadable approval should mean.
func Load(path string) (Document, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return None(), nil
	}
	for _, each := range []string{filepath.Dir(path), path} {
		owned, owner, err := fileown.OwnedByAdministrators(each)
		if err != nil {
			return Document{}, err
		}
		if !owned {
			return Document{}, fmt.Errorf("the approvals file %s is reached through %s, which belongs to %s rather than to the administrators, so that account could write its own approvals",
				path, each, owner)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("read the approvals file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Document{}, fmt.Errorf("read the approvals file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Document{}, fmt.Errorf("the approvals file %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Document{}, fmt.Errorf("read the approvals file: %w", err)
	}
	return Parse(data)
}
