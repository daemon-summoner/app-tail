// SPDX-License-Identifier: MIT

package hostnet

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procPeer checks a connecting process through a /proc file system: the Linux half of the
// caller check, kept free of build tags so a suite on any platform can run it against a
// directory laid out the same way.
type procPeer struct {
	// root is where the process file system is mounted: /proc in production.
	root string
}

// check refuses a process that is being traced or that runs another program than this one.
//
// The trace comes first. A tracer can make the process do anything, so whatever program it is
// running says nothing about what it will ask for.
//
// The program is compared by what the kernel says each process runs -- the exe link resolves
// to the mapped file itself, not to whatever now sits at the path it was started from. The
// helper is normally a copy of the agent rather than the same file, so a different file is
// compared by content.
func (p procPeer) check(pid int) error {
	status, err := os.ReadFile(filepath.Join(p.root, strconv.Itoa(pid), "status"))
	if err != nil {
		return fmt.Errorf("read the connecting process's state: %w", err)
	}
	tracer, err := parseTracerPid(status)
	if err != nil {
		return err
	}
	if tracer != 0 {
		return fmt.Errorf("the connecting process (pid %d) is being traced by process %d, which could make it ask for anything", pid, tracer)
	}
	self := filepath.Join(p.root, "self", "exe")
	peer := filepath.Join(p.root, strconv.Itoa(pid), "exe")
	same, err := sameProgram(self, peer)
	if err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("the connecting process (pid %d) is running a different program from this helper, so it is not app-tail", pid)
	}
	return nil
}

// sameProgram reports whether two paths lead to the same program: the same file, or files
// with the same contents.
func sameProgram(self, peer string) (bool, error) {
	selfInfo, err := os.Stat(self)
	if err != nil {
		return false, fmt.Errorf("read this helper's own program: %w", err)
	}
	peerInfo, err := os.Stat(peer)
	if err != nil {
		return false, fmt.Errorf("read the connecting process's program: %w", err)
	}
	if os.SameFile(selfInfo, peerInfo) {
		return true, nil
	}
	if selfInfo.Size() != peerInfo.Size() {
		return false, nil
	}
	selfID, err := hashExecutable(func() (string, error) { return self, nil })
	if err != nil {
		return false, err
	}
	peerID, err := hashExecutable(func() (string, error) { return peer, nil })
	if err != nil {
		return false, fmt.Errorf("read the connecting process's program: %w", err)
	}
	return selfID == peerID, nil
}

// parseTracerPid reads the TracerPid line of a /proc/<pid>/status file. A file without one is
// an error rather than "not traced": that is a kernel this check does not understand.
func parseTracerPid(status []byte) (int, error) {
	s := bufio.NewScanner(bytes.NewReader(status))
	for s.Scan() {
		value, ok := strings.CutPrefix(s.Text(), "TracerPid:")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, fmt.Errorf("read whether the connecting process is traced: %q is not a process id", strings.TrimSpace(value))
		}
		return pid, nil
	}
	if err := s.Err(); err != nil {
		return 0, fmt.Errorf("read whether the connecting process is traced: %w", err)
	}
	return 0, errors.New("the connecting process's state does not say whether it is traced")
}

// refuseLoaderStartedProgram refuses an ELF program the dynamic loader starts. The loader
// honours LD_PRELOAD, which puts any library into the program ahead of its own code without
// changing its file, and the caller check compares files: every program running as the
// helper's owner could load its own code into app-tail and be accepted as app-tail.
func refuseLoaderStartedProgram(name string, r io.ReaderAt) error {
	f, err := elf.NewFile(r)
	if err != nil {
		return fmt.Errorf("read %s as a Linux program: %w", name, err)
	}
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return fmt.Errorf("%s is dynamically linked, so any program running as your account "+
				"could load its own code into it with LD_PRELOAD and pass as app-tail; build it "+
				"with CGO_ENABLED=0 and start the helper from that build", name)
		}
	}
	return nil
}
