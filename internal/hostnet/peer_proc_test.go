// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProc lays out a directory the way /proc is for one connecting process: self/exe and
// <pid>/exe lead to the programs given, and <pid>/status says who traces it.
func fakeProc(t *testing.T, selfExe, peerExe string, tracer string) procPeer {
	t.Helper()
	root := t.TempDir()
	for dir, target := range map[string]string{"self": selfExe, "4321": peerExe} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	status := "Name:\tapp-tail\nState:\tS (sleeping)\n"
	if tracer != "" {
		status += "TracerPid:\t" + tracer + "\n"
	}
	status += "Uid:\t501\t501\t501\t501\n"
	if err := os.WriteFile(filepath.Join(root, "4321", "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	return procPeer{root: root}
}

// copyOf writes a copy of the file at src, optionally with bytes appended, and returns its path.
func copyOf(t *testing.T, src, extra string) string {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	dst := filepath.Join(t.TempDir(), "program")
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if _, err := out.WriteString(extra); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return dst
}

func ownProgram(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestAPeerRunningTheHelpersOwnProgramIsAcceptedThroughProc(t *testing.T) {
	exe := ownProgram(t)
	if err := fakeProc(t, exe, exe, "0").check(4321); err != nil {
		t.Fatalf("the helper's own program was refused: %v", err)
	}
}

// The installed helper is a copy of the agent rather than the same file.
func TestAPeerRunningACopyOfTheHelpersProgramIsAcceptedThroughProc(t *testing.T) {
	exe := ownProgram(t)
	if err := fakeProc(t, exe, copyOf(t, exe, ""), "0").check(4321); err != nil {
		t.Fatalf("a byte-identical copy was refused: %v", err)
	}
}

func TestAPeerRunningAnotherProgramIsRefusedThroughProc(t *testing.T) {
	exe := ownProgram(t)
	for name, other := range map[string]string{
		"a file of the same size": func() string {
			p := copyOf(t, exe, "")
			f, err := os.OpenFile(p, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteAt([]byte("X"), 100); err != nil {
				t.Fatal(err)
			}
			return p
		}(),
		"a longer file": copyOf(t, exe, "appended"),
	} {
		err := fakeProc(t, exe, other, "0").check(4321)
		if err == nil || !strings.Contains(err.Error(), "different program") {
			t.Errorf("%s: got %v, want a refusal for a different program", name, err)
		}
	}
}

func TestATracedPeerIsRefusedEvenRunningTheHelpersOwnProgram(t *testing.T) {
	exe := ownProgram(t)
	err := fakeProc(t, exe, exe, "777").check(4321)
	if err == nil || !strings.Contains(err.Error(), "traced by process 777") {
		t.Fatalf("got %v, want a refusal naming the tracer", err)
	}
}

func TestAPeerWhoseStateDoesNotSayWhetherItIsTracedIsRefused(t *testing.T) {
	exe := ownProgram(t)
	for _, tracer := range []string{"", "nobody"} {
		if err := fakeProc(t, exe, exe, tracer).check(4321); err == nil {
			t.Errorf("TracerPid %q was taken as untraced", tracer)
		}
	}
}

func TestAPeerThatIsGoneIsRefused(t *testing.T) {
	exe := ownProgram(t)
	if err := fakeProc(t, exe, exe, "0").check(9999); err == nil {
		t.Fatal("a process with no entry was accepted")
	}
}

// elfStartedBy builds a 64-bit ELF executable whose only program header names interp as the
// loader that starts it, which is what a dynamically linked program carries.
func elfStartedBy(interp string) []byte {
	const ehsize, phentsize = 64, 56
	out := make([]byte, ehsize+phentsize)
	copy(out, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(out[16:], 2)
	binary.LittleEndian.PutUint16(out[18:], 62)
	binary.LittleEndian.PutUint32(out[20:], 1)
	binary.LittleEndian.PutUint64(out[32:], ehsize)
	binary.LittleEndian.PutUint16(out[52:], ehsize)
	binary.LittleEndian.PutUint16(out[54:], phentsize)
	binary.LittleEndian.PutUint16(out[56:], 1)
	ph := out[ehsize:]
	binary.LittleEndian.PutUint32(ph[0:], uint32(elf.PT_INTERP))
	binary.LittleEndian.PutUint64(ph[8:], uint64(len(out)))
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(interp)+1))
	binary.LittleEndian.PutUint64(ph[40:], uint64(len(interp)+1))
	return append(append(out, interp...), 0)
}

// LD_PRELOAD makes the loader put any library into a program it starts, ahead of the
// program's own code, without changing the file the helper compares. A program no loader
// starts never reads it.
func TestAProgramTheLoaderStartsIsRefusedToServeAsTheHelper(t *testing.T) {
	err := refuseLoaderStartedProgram("app-tail", bytes.NewReader(elfStartedBy("/lib64/ld-linux-x86-64.so.2")))
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") || !strings.Contains(err.Error(), "CGO_ENABLED=0") {
		t.Errorf("a dynamically linked helper = %v, want a refusal naming LD_PRELOAD and the static build", err)
	}
	if err := refuseLoaderStartedProgram("app-tail", bytes.NewReader(elfProgram())); err != nil {
		t.Errorf("a statically linked helper was refused: %v", err)
	}
	if err := refuseLoaderStartedProgram("app-tail", strings.NewReader("not a program")); err == nil {
		t.Error("a file that is not an ELF program was taken for a static one")
	}
}
