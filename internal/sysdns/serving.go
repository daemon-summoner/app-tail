// SPDX-License-Identifier: MIT

package sysdns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sellitus/app-tail/internal/fileown"
)

// servingFileName is the lock beside the record that says an app-tail is serving the
// resolver this machine is pointed at.
const servingFileName = "systemdns-serving.lock"

// Serving is held by the process that has this machine pointed at app-tail, for as long as
// it does, and by a repair for as long as it runs.
//
// It is what lets a repair tell a machine left pointed at nothing from one an app-tail is
// serving, whichever process that app-tail is: the operating system drops the lock when its
// holder ends, however it ends, so a lock nobody holds is exactly a machine nobody is
// serving. It lives in the record's root-only directory, so no other account can hold it to
// keep a repair away.
type Serving struct {
	file *os.File
}

// TryHoldServing takes the serving lock beside recordPath without waiting, reporting false
// when another holder has it.
func TryHoldServing(recordPath string) (*Serving, bool, error) {
	if recordPath == "" {
		return nil, false, errors.New("app-tail could not work out where this machine keeps its machine-wide " +
			"application data, so it cannot tell whether an app-tail is serving this machine's resolver")
	}
	dir := filepath.Dir(recordPath)
	if err := fileown.MakeRestrictedDir(dir, dirMode); err != nil {
		return nil, false, fmt.Errorf("make the directory for the resolver lock: %w", err)
	}
	path := filepath.Join(dir, servingFileName)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, fileMode)
	if err != nil {
		return nil, false, fmt.Errorf("open the resolver lock: %w", err)
	}
	held, err := fileown.TryLock(file)
	if err != nil || !held {
		closeErr := file.Close()
		if err != nil {
			return nil, false, errors.Join(fmt.Errorf("lock %s: %w", path, err), closeErr)
		}
		return nil, false, closeErr
	}
	return &Serving{file: file}, true, nil
}

// Release gives the lock up.
func (s *Serving) Release() error {
	return errors.Join(fileown.Unlock(s.file), s.file.Close())
}
