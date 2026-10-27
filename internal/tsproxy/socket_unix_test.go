// SPDX-License-Identifier: MIT

//go:build unix

package tsproxy

// The instance socket beside each listener's TCP port. It is where an unforgeable identity
// comes from -- the kernel reports the connecting account -- so the modes on it are the
// grant boundary rather than tidiness: a proxy carries everything its rules allow, and a
// socket another account on this machine could open hands that grant away silently.

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// shortTempDir is a temporary directory with a short path. t.TempDir() embeds the test's
// name, and a unix socket path is capped near 104 bytes on the platforms this file builds
// for -- a test named after what it proves would fail on the length rather than on the
// behaviour.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "px")
	if err != nil {
		t.Fatalf("creating a temporary directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// modeOf is the permission bits on one path, and a failure when it is not there at all.
func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func TestTheInstanceSocketIsReachableOnlyByTheAccountRunningThisApp(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "proxies")
	path := filepath.Join(dir, "psql.sock")

	ln, err := listenLocal(path)
	if err != nil {
		t.Fatalf("opening the instance socket: %v", err)
	}
	defer ln.Close()

	if got := modeOf(t, path); got != 0o600 {
		t.Errorf("the socket is mode %04o, want 0600 -- another account could open it", got)
	}
	if got := modeOf(t, dir); got != 0o700 {
		t.Errorf("the directory is mode %04o, want 0700 -- the socket is briefly reachable "+
			"between the bind and the chmod, so the directory is what closes that window", got)
	}
	// And it works: a boundary that refused this app's own connections would be checked by
	// nobody and discovered by the first person who tried to use it.
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connecting to the instance's own socket: %v", err)
	}
	conn.Close()
}

// A directory an earlier version left behind carries whatever mode that version chose, and
// MkdirAll leaves an existing one alone. Re-applying the mode is what stops an upgrade from
// inheriting a window that was open before it.
func TestADirectoryLeftOpenByAnEarlierRunIsClosedAgain(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "proxies")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating the directory an earlier version left: %v", err)
	}
	path := filepath.Join(dir, "psql.sock")

	ln, err := listenLocal(path)
	if err != nil {
		t.Fatalf("opening the instance socket: %v", err)
	}
	defer ln.Close()

	if got := modeOf(t, dir); got != 0o700 {
		t.Errorf("the directory is still mode %04o, want it closed to 0700", got)
	}
}

// A socket file outlives the process that made it, so a start after a crash finds this app's
// own leftover in the way. Bind-failing on it would leave an instance permanently down after
// one hard stop, with nothing but a restart of the machine to clear it.
func TestASocketLeftBehindByACrashIsReplacedRatherThanFatal(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "proxies")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("creating the socket directory: %v", err)
	}
	path := filepath.Join(dir, "psql.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("creating the leftover socket: %v", err)
	}
	// Closed without removing the file, which is what a crash leaves behind.
	stale.SetUnlinkOnClose(false)
	stale.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the leftover socket is not there, so this test proves nothing: %v", err)
	}

	ln, err := listenLocal(path)
	if err != nil {
		t.Fatalf("opening over a leftover socket: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the replacement socket does not answer: %v", err)
	}
	conn.Close()
}

// A path that cannot be a socket has to say so rather than leave the instance believing it
// has a local socket it does not.
func TestASocketThatCannotBeOpenedIsReportedWithItsPath(t *testing.T) {
	// A file where the directory has to go, so creating the directory itself fails.
	blocked := filepath.Join(shortTempDir(t), "proxies")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("creating the file in the way: %v", err)
	}

	ln, err := listenLocal(filepath.Join(blocked, "psql.sock"))

	if err == nil {
		ln.Close()
		t.Fatal("a socket was opened inside a path that is not a directory")
	}
	if ln != nil {
		t.Error("a listener was handed back alongside the failure")
	}
}

// Removing the socket of a stopped instance costs nothing at run time, so a path that is
// already gone -- or was never opened, which is every platform without one -- must not be
// treated as a failure worth raising.
func TestRemovingASocketThatIsAlreadyGoneIsNothingHappening(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "psql.sock")

	removeLocal("", quietLogger())
	removeLocal(path, quietLogger())

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat after removing a socket that was never there = %v, want it absent", err)
	}
}

// The socket a stopped instance leaves behind is removed, or the next start finds its own
// leftover and the directory fills with sockets for instances that no longer exist.
func TestAStoppedInstancesSocketIsRemoved(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "proxies")
	path := filepath.Join(dir, "psql.sock")
	ln, err := listenLocal(path)
	if err != nil {
		t.Fatalf("opening the instance socket: %v", err)
	}
	ln.Close()

	removeLocal(path, quietLogger())

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat after the instance stopped = %v, want the socket gone", err)
	}
}
