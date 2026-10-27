// SPDX-License-Identifier: MIT

package instance

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Ending a process is the one step of a takeover that cannot be taken back, and Windows hands
// a process id straight back out once its process is gone: the id read from the claim file
// can name anything by the time it is acted on. Every guard in front of TerminateProcess is
// pinned here without ever ending a process the test did not start.

// standInProcesses answers OpenProcess with the test's own handle for the ids it names and
// with the error given for the rest, and never opens a process the test did not name.
func standInProcesses(t *testing.T, known map[uint32]windows.Handle, otherwise error) *[]uint32 {
	t.Helper()
	was := openProcess
	t.Cleanup(func() { openProcess = was })
	var asked []uint32
	openProcess = func(_ uint32, _ bool, pid uint32) (windows.Handle, error) {
		asked = append(asked, pid)
		if handle, ok := known[pid]; ok {
			return handle, nil
		}
		return 0, otherwise
	}
	return &asked
}

// The claim file is written by another process and read back as text, so what it says is a
// process id is checked before anything is opened by it: a zero, a negative number or one
// past what Windows can hold names nothing, and OpenProcess is never asked about it.
func TestANumberThatIsNotAProcessIdIsRefusedBeforeAnythingIsOpened(t *testing.T) {
	asked := standInProcesses(t, nil, errors.New("must not be reached"))

	for _, pid := range []int{0, -1, 1 << 32, 1<<32 + 4} {
		err := killHolder(context.Background(), pid)
		if err == nil || !strings.Contains(err.Error(), "not a process id") {
			t.Errorf("killHolder(%d) = %v, want it refused as not a process id", pid, err)
		}
	}
	if len(*asked) != 0 {
		t.Errorf("OpenProcess was asked about %v", *asked)
	}
}

// A process that went between the claim being read and the kill is the outcome the kill
// wanted: Windows reports the id as an invalid parameter, and that is a clean result.
func TestAProcessThatIsAlreadyGoneIsACleanKill(t *testing.T) {
	standInProcesses(t, nil, windows.ERROR_INVALID_PARAMETER)

	if err := killHolder(context.Background(), 4242); err != nil {
		t.Errorf("killHolder of a process already gone = %v, want nil", err)
	}
}

// Any other refusal to open the process is reported with the id: access denied is a process
// owned by another account, and the takeover cannot proceed past it silently.
func TestARefusalToOpenTheProcessIsReportedAgainstItsId(t *testing.T) {
	standInProcesses(t, nil, windows.ERROR_ACCESS_DENIED)

	err := killHolder(context.Background(), 4242)
	if err == nil || !strings.Contains(err.Error(), "open process 4242") || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("killHolder = %v, want the refusal named against the process", err)
	}
}

// The id from the claim file now names a different program. It is not ended, and the refusal
// says what was found there, since ending the wrong process is not a recoverable mistake.
func TestAProcessIdThatNowNamesAnotherProgramIsNotEnded(t *testing.T) {
	other := exec.Command(os.Getenv("ComSpec"), "/c", "pause")
	stdin, err := other.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := other.Start(); err != nil {
		t.Fatalf("start a process that is not this program: %v", err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = other.Process.Kill()
		_ = other.Wait()
	})

	err = killHolder(context.Background(), other.Process.Pid)

	if err == nil {
		t.Fatal("a process running a different program was ended by a takeover that read its id off a file")
	}
	if !strings.Contains(err.Error(), "cmd.exe") || !strings.Contains(err.Error(), "not another copy of") {
		t.Errorf("killHolder = %v, want it to name the program found running as the id", err)
	}
	// Still there: the refusal came before TerminateProcess, not after.
	done := make(chan error, 1)
	go func() { done <- other.Wait() }()
	select {
	case <-done:
		t.Error("the process was ended despite the refusal")
	case <-time.After(300 * time.Millisecond):
	}
}

// Another copy of this program is what the takeover exists to end, and this process is one.
func TestThisProgramIsRecognisedAsItself(t *testing.T) {
	if err := sameProgram(windows.CurrentProcess(), os.Getpid()); err != nil {
		t.Errorf("sameProgram(this process) = %v, want it recognised", err)
	}
}

// standInImagePath answers QueryFullProcessImageName the way Windows does for a path longer
// than the buffer offered: a size error until the buffer can hold it, then the path.
func standInImagePath(t *testing.T, path string) *int {
	t.Helper()
	was := queryFullProcessImageName
	t.Cleanup(func() { queryFullProcessImageName = was })
	encoded, err := windows.UTF16FromString(path)
	if err != nil {
		t.Fatalf("UTF16FromString: %v", err)
	}
	calls := 0
	queryFullProcessImageName = func(_ windows.Handle, _ uint32, buf *uint16, size *uint32) error {
		calls++
		// Without the terminator, which is what the size Windows reports leaves out.
		if int(*size) < len(encoded) {
			return windows.ERROR_INSUFFICIENT_BUFFER
		}
		copy(unsafe.Slice(buf, int(*size)), encoded)
		*size = uint32(len(encoded) - 1)
		return nil
	}
	return &calls
}

// A program path longer than MAX_PATH is ordinary on a machine with long paths enabled, and
// the first buffer is MAX_PATH: the buffer grows until the whole path fits, and the path read
// is whole rather than cut where the first buffer ended.
func TestAProgramPathLongerThanTheFirstBufferIsReadWhole(t *testing.T) {
	long := `C:\` + strings.Repeat("directory-with-a-long-name\\", 20) + "app-tail.exe"
	if len(long) <= windows.MAX_PATH {
		t.Fatalf("the path is %d characters, which the first buffer holds", len(long))
	}
	calls := standInImagePath(t, long)

	got, err := imagePath(windows.CurrentProcess())

	if err != nil {
		t.Fatalf("imagePath: %v", err)
	}
	if got != long {
		t.Errorf("imagePath = %q, want the whole path", got)
	}
	if *calls < 2 {
		t.Errorf("the path was read in %d call, so the first buffer held it and this proves nothing", *calls)
	}
	if filepath.Base(got) != "app-tail.exe" {
		t.Errorf("the program read back is %q", filepath.Base(got))
	}
}

// An answer that never fits is a broken one: the buffer stops growing where Windows paths
// stop, and the size error comes back rather than the loop going on.
func TestAnAnswerThatNeverFitsIsAnErrorRatherThanAnEndlessBuffer(t *testing.T) {
	was := queryFullProcessImageName
	t.Cleanup(func() { queryFullProcessImageName = was })
	largest := 0
	queryFullProcessImageName = func(_ windows.Handle, _ uint32, _ *uint16, size *uint32) error {
		largest = max(largest, int(*size))
		return windows.ERROR_INSUFFICIENT_BUFFER
	}

	_, err := imagePath(windows.CurrentProcess())

	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		t.Fatalf("imagePath = %v, want the size error once the buffer stopped growing", err)
	}
	if largest < maxImagePath || largest > 2*maxImagePath {
		t.Errorf("the buffer stopped at %d characters, want it grown to the Windows limit and no further", largest)
	}
}
