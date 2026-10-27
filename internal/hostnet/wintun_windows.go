// SPDX-License-Identifier: MIT

package hostnet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// pinnedWintun is the wintun module loadPinnedWintun loaded, kept for the life of the
// process and never freed. The wintun binding later loads "wintun.dll" by bare name, and a
// module of that name already in the process is what the loader hands back, so holding this
// one is what makes the binding use the file that was checked rather than whatever is at the
// path by then.
var (
	pinnedWintunMu sync.Mutex
	pinnedWintun   windows.Handle
)

// loadPinnedWintun loads the wintun.dll at path, after checking it is the release this
// build pins, and must run before the first adapter is created. path is the copy the
// binding's own loader would open, from firstWintun.
//
// A second call returns at once: the module stays loaded, and checking a file again after
// it is mapped would vouch for nothing.
func loadPinnedWintun(path string) error {
	pinnedWintunMu.Lock()
	defer pinnedWintunMu.Unlock()
	if pinnedWintun != 0 {
		return nil
	}
	module, err := loadVerifiedWintun(path, runtime.GOARCH)
	if err != nil {
		return err
	}
	pinnedWintun = module
	return nil
}

// firstWintun is the first copy of wintun.dll in dirs, which is the one the loader opens,
// and reports whether there is one at all. A copy that could not be looked for is an error
// rather than an absence: the one that matters is most often in exactly that directory.
func firstWintun(dirs []string) (string, bool, error) {
	for _, dir := range dirs {
		path := filepath.Join(dir, wintunDLL)
		_, err := os.Stat(path)
		switch {
		case err == nil:
			return path, true, nil
		case !errors.Is(err, os.ErrNotExist):
			return "", false, fmt.Errorf("whether %s is there could not be checked: %w", path, err)
		}
	}
	return "", false, nil
}

// loadVerifiedWintun hashes the file at path and loads it only if it matches the pin for
// goarch.
//
// The file is held open with read sharing alone from before the hash until after the load,
// which is what makes the two about the same bytes: nothing can write it, delete it, or
// rename another file over it while that handle is open. The load itself takes the full
// path, so it cannot be answered by some other file of the same name.
func loadVerifiedWintun(path, goarch string) (windows.Handle, error) {
	file, err := openWintunForPinning(path)
	if err != nil {
		return 0, err
	}
	module, err := loadIfPinned(file, path, goarch)
	if closeErr := file.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("close %s after checking it: %w", path, closeErr))
		if module != 0 {
			err = errors.Join(err, windows.FreeLibrary(module))
		}
	}
	if err != nil {
		return 0, err
	}
	return module, nil
}

func loadIfPinned(file *os.File, path, goarch string) (windows.Handle, error) {
	sum, err := sha256Of(file)
	if err != nil {
		return 0, fmt.Errorf("read %s to check it: %w", path, err)
	}
	if err := CheckWintunPin(goarch, sum); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	module, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return 0, fmt.Errorf("load %s: %w", path, err)
	}
	return module, nil
}

// openWintunForPinning opens path for reading with read sharing only, which denies every
// other handle the right to write, delete or rename it while this one is open.
//
// A reparse point is refused rather than followed: a link can be pointed somewhere else
// between the check and the load without touching the file the check read.
func openWintunForPinning(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode %q: %w", path, err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s to check it: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, errors.Join(fmt.Errorf("read what kind of file %s is: %w", path, err), file.Close())
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.Join(fmt.Errorf("%s is a link rather than the file itself, so it is not loaded into a "+
			"process with administrator rights", path), file.Close())
	}
	return file, nil
}

func sha256Of(r io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
