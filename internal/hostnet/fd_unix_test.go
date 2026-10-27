// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The descriptor carrying the interface is the one thing that crosses the helper boundary
// that is not text, and a descriptor mishandled is an interface left alive with nothing
// driving it. Every way the receiving side can be handed something other than exactly one
// descriptor is pinned here.

// dupOf is a second descriptor on the same pipe end, so the test can hand a number to the
// code under test without giving up the one it asserts through.
func dupOf(t *testing.T, file *os.File) int {
	t.Helper()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	return fd
}

// isOpen reports whether a descriptor number is still open in this process.
func isOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

// The helper sends one descriptor. A control message carrying more is not the helper this
// side expects, and every descriptor past the first is closed rather than left open; the first
// is still the one handed back, and it still reaches the pipe it was made from.
func TestOnlyTheFirstDescriptorIsKeptAndTheRestAreClosed(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	first := dupOf(t, writeEnd)
	second := dupOf(t, writeEnd)
	third := dupOf(t, writeEnd)

	file, err := fileFromControl(unix.UnixRights(first, second, third))

	if err != nil {
		t.Fatalf("fileFromControl: %v", err)
	}
	defer file.Close()
	if int(file.Fd()) != first {
		t.Errorf("the file handed back is descriptor %d, want the first one sent, %d", file.Fd(), first)
	}
	if isOpen(second) || isOpen(third) {
		t.Error("the descriptors past the first were left open")
	}
	if _, err := file.WriteString("through\n"); err != nil {
		t.Fatalf("write through the descriptor handed back: %v", err)
	}
	if line, err := bufio.NewReader(readEnd).ReadString('\n'); err != nil || line != "through\n" {
		t.Errorf("the descriptor carried %q (%v), so it is not the one that was sent", line, err)
	}
}

// An extra descriptor that will not close means this process cannot account for what it was
// sent, so the first goes too and the failure names the close that went wrong. Nothing is
// handed back that would keep the interface alive.
func TestAnExtraDescriptorThatCannotBeClosedTakesTheFirstWithIt(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	first := dupOf(t, writeEnd)
	// A number that is not open: closing it is the one close that fails without root.
	stale := dupOf(t, writeEnd)
	if err := unix.Close(stale); err != nil {
		t.Fatalf("close: %v", err)
	}

	file, err := fileFromControl(unix.UnixRights(first, stale))

	if err == nil {
		file.Close()
		t.Fatal("a control message this side could not account for was accepted")
	}
	if !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), "extra descriptors") {
		t.Errorf("fileFromControl = %v, want the failed close named", err)
	}
	if file != nil {
		t.Error("a file was handed back beside the failure")
	}
	if isOpen(first) {
		t.Error("the first descriptor was left open by a receive that reported failure")
	}
}

// A control message with no descriptor in it is a reply that promised one and did not deliver.
func TestAControlMessageWithNoDescriptorIsRefused(t *testing.T) {
	if _, err := fileFromControl(nil); err == nil || !strings.Contains(err.Error(), "no interface descriptor") {
		t.Errorf("fileFromControl(nil) = %v, want the missing descriptor named", err)
	}
	if _, err := fileFromControl([]byte{1, 2, 3}); err == nil {
		t.Error("bytes that are not a control message were accepted")
	}
}

// The descriptor rides on a datagram the buffered reader cannot ask for, so a reader that has
// already taken bytes off the socket has taken the reply the descriptor was attached to. That
// is refused up front rather than left to block on a reply that already arrived.
func TestAReplyAlreadyBufferedCannotBeReadWithADescriptor(t *testing.T) {
	server, client := unixPair(t)
	r := bufio.NewReader(client)
	if _, err := server.Write([]byte("{\"interface\":\"utun7\"}\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := r.Peek(1); err != nil {
		t.Fatalf("fill the reader: %v", err)
	}

	_, file, err := readWithFile(client, r)

	if err == nil || !strings.Contains(err.Error(), "before the descriptor") {
		t.Fatalf("readWithFile = %v, want the buffered bytes refused", err)
	}
	if file != nil {
		t.Error("a file was handed back beside the refusal")
	}
}

// Only a unix socket can carry a descriptor, and asking anything else is a programming error
// reported rather than a read that never returns.
func TestADescriptorCannotBeReceivedOverAnythingButAUnixSocket(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	_, file, err := readWithFile(near, bufio.NewReader(near))

	if err == nil || !strings.Contains(err.Error(), "cannot be received over") {
		t.Fatalf("readWithFile = %v, want the connection type refused", err)
	}
	if file != nil {
		t.Error("a file was handed back beside the refusal")
	}
}

// A refusal from the helper carries no descriptor, and that is the helper's answer rather than
// a failure to receive: the caller gets the refusal to act on. A reply that is not a refusal and
// still carries nothing is the failure.
func TestARefusalArrivesWithoutADescriptorAndAPromiseWithoutOneIsAFailure(t *testing.T) {
	t.Run("a refusal", func(t *testing.T) {
		server, client := unixPair(t)
		if _, err := server.Write([]byte("{\"error\":\"no interface for you\"}\n")); err != nil {
			t.Fatalf("write: %v", err)
		}

		resp, file, err := readWithFile(client, bufio.NewReader(client))

		if err != nil {
			t.Fatalf("readWithFile: %v", err)
		}
		if resp.Error != "no interface for you" || file != nil {
			t.Errorf("readWithFile = %+v, %v; want the refusal and no file", resp, file)
		}
	})

	t.Run("a promise with nothing attached", func(t *testing.T) {
		server, client := unixPair(t)
		if _, err := server.Write([]byte("{\"interface\":\"utun7\"}\n")); err != nil {
			t.Fatalf("write: %v", err)
		}

		_, file, err := readWithFile(client, bufio.NewReader(client))

		if err == nil || !strings.Contains(err.Error(), "no interface descriptor") {
			t.Fatalf("readWithFile = %v, want the missing descriptor named", err)
		}
		if file != nil {
			t.Error("a file was handed back beside the failure")
		}
	})

	t.Run("a helper that went away", func(t *testing.T) {
		server, client := unixPair(t)
		if err := server.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		_, _, err := readWithFile(client, bufio.NewReader(client))

		if err == nil {
			t.Fatal("a helper that closed the connection was read as a reply")
		}
	})

	t.Run("a reply that is not a message", func(t *testing.T) {
		server, client := unixPair(t)
		if _, err := server.Write([]byte("not json\n")); err != nil {
			t.Fatalf("write: %v", err)
		}

		_, _, err := readWithFile(client, bufio.NewReader(client))

		if err == nil || !strings.Contains(err.Error(), "read the reply carrying the descriptor") {
			t.Fatalf("readWithFile = %v, want the unreadable reply named", err)
		}
	})
}
