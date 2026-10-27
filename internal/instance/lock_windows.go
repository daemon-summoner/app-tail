// SPDX-License-Identifier: MIT

package instance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	// maxImagePath bounds the buffer grown for a process's program path. Windows extended
	// paths stop here, so a longer answer is a broken one rather than a bigger buffer.
	maxImagePath = 32768
)

// The two calls that reach another process, held so a test can stand in for a process it
// must not really end and for a path longer than the first buffer.
var (
	openProcess               = windows.OpenProcess
	queryFullProcessImageName = windows.QueryFullProcessImageName
)

// stopHolder asks the agent running as pid to shut down.
//
// The loopback API is the only orderly way to ask on Windows: there is no signal that means
// "shut down cleanly", and a console control event cannot reach a process started from
// Explorer or from the login item, which is how this one usually runs. The process id is
// unused for that reason -- the address the agent recorded is what names it.
func stopHolder(ctx context.Context, configPath string, _ int) error {
	return askAgentToQuit(ctx, configPath)
}

// killHolder ends a process that did not stop when it was asked.
func killHolder(_ context.Context, pid int) error {
	if pid <= 0 || pid > math.MaxUint32 {
		return fmt.Errorf("end process %d: that is not a process id", pid)
	}
	const access = windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION
	handle, err := openProcess(access, false, uint32(pid))
	if err != nil {
		// The process went between the claim being read and this call, which is the outcome
		// this wanted rather than a failure.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil
		}
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle) //nolint:errcheck // nothing can be done about a handle that will not close
	if err := sameProgram(handle, pid); err != nil {
		return err
	}
	if err := windows.TerminateProcess(handle, 1); err != nil {
		return fmt.Errorf("end process %d: %w", pid, err)
	}
	return nil
}

// sameProgram refuses to end a process that is not another copy of this program.
//
// Windows hands a process id straight back out once the process holding it is gone, and this
// one came out of a file: between the claim being written and this call it can have come to
// name something else entirely, and ending the wrong process is not a recoverable mistake.
func sameProgram(handle windows.Handle, pid int) error {
	running, err := imagePath(handle)
	if err != nil {
		return fmt.Errorf("read what process %d is running: %w", pid, err)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program: %w", err)
	}
	if !strings.EqualFold(filepath.Base(running), filepath.Base(self)) {
		return fmt.Errorf("process %d is running %s, not another copy of %s",
			pid, filepath.Base(running), filepath.Base(self))
	}
	return nil
}

// imagePath reports the program a process is running.
func imagePath(handle windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		size := uint32(len(buf))
		err := queryFullProcessImageName(handle, 0, &buf[0], &size)
		if err == nil {
			return windows.UTF16ToString(buf[:size]), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || len(buf) >= maxImagePath {
			return "", err
		}
		buf = make([]uint16, len(buf)*2)
	}
}
