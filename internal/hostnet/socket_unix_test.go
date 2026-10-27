// SPDX-License-Identifier: MIT

//go:build unix

package hostnet

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The helper runs as root and the agent does not, so a socket left as root's own is one
// the only account it exists for cannot open. That failure reaches the user as an app that
// installed a helper and then could not talk to it.
func TestTheSocketIsOpenedForTheAccountTheHelperServes(t *testing.T) {
	ownedByThisUser(t)
	path := shortSocketPath(t)
	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("look at the helper socket: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("the helper socket reported no owner")
	}
	if int(stat.Uid) != os.Getuid() {
		t.Errorf("the socket belongs to user %d, and the helper serves user %d", stat.Uid, os.Getuid())
	}
	// The other half of the same property: it belongs to that account and to nobody else.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the socket is mode %o, which is not the account's alone", perm)
	}
}

// The directory is the first thing in the way: an account with no right to walk through it
// cannot open the socket inside whatever the socket itself says. A directory an earlier
// install left shut is exactly the machine this has to work on, so the mode is re-applied
// rather than assumed from the one this run would have created.
func TestADirectoryFromAnEarlierInstallStopsShuttingTheOwnerOut(t *testing.T) {
	ownedByThisUser(t)
	path := shortSocketPath(t)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("shut the socket directory the way an earlier install left it: %v", err)
	}

	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("listen on the helper socket: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("look at the socket directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("the socket directory is mode %o, which the account the helper serves cannot walk through", perm)
	}
}

// A socket the served account was never given is one that account cannot open, and a
// helper listening on it looks from the agent's side exactly like a machine where the
// interface mode does not work. It stops instead, with the reason.
func TestASocketThatCannotBeGivenToTheAccountItServesIsNotOpened(t *testing.T) {
	// Every account but this process's own is one it cannot hand a file to, which is the
	// state a helper started without the rights it needs is in.
	t.Setenv(ownerEnv, strconv.Itoa(os.Getuid()+1))
	path := shortSocketPath(t)

	ln, err := ListenHelper(path)
	if err == nil {
		ln.Close()
		t.Fatal("a socket was opened for an account it was never given to")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a socket was left behind by a listen that failed")
	}
}

// A helper with no account recorded serves nobody, and the socket is what carries that
// sentence to whoever asks. Refusing to open one would leave the agent looking at a path
// that is not there, which reads as a helper that was never installed.
func TestAHelperWithNoRecordedOwnerStillOpensASocketToRefuseOn(t *testing.T) {
	t.Setenv(ownerEnv, "")
	path := shortSocketPath(t)
	ln, err := ListenHelper(path)
	if err != nil {
		t.Fatalf("a helper with no recorded owner did not open a socket: %v", err)
	}
	defer ln.Close()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("there is no socket to refuse a connection on: %v", err)
	}
}

// An account that cannot be resolved is a different thing from none being recorded: the
// installer named one and this machine disagrees, and opening a socket for whoever the
// zero value points at is how a helper ends up serving the wrong account.
func TestNoSocketIsOpenedForAnAccountThisMachineDoesNotHave(t *testing.T) {
	const missing = "app-tail-no-such-account"
	t.Setenv(ownerEnv, missing)
	path := shortSocketPath(t)

	ln, err := ListenHelper(path)
	if err == nil {
		ln.Close()
		t.Fatal("a socket was opened for an account this machine does not have")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("the refusal said %q, which does not name the account it could not find", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a socket was left behind by a listen that failed")
	}
}

// A directory that could not be shut is one the socket must not be created in: the window
// between the bind and the mode being set is only closed by the directory being shut for
// it, and a socket made in an open one is reachable by anyone for as long as that takes.
func TestASocketIsNotCreatedInADirectoryThatCouldNotBeShut(t *testing.T) {
	ownedByThisUser(t)
	path := shortSocketPath(t)
	refuse := errors.New("this directory is not yours to change")

	ln, err := listenHelper(path, func(name string, mode os.FileMode) error {
		if name == filepath.Dir(path) && mode == 0o700 {
			return refuse
		}
		return os.Chmod(name, mode)
	})
	if err == nil {
		ln.Close()
		t.Fatal("a socket was created in a directory that could not be shut")
	}
	if !errors.Is(err, refuse) {
		t.Errorf("the refusal said %q, which is not why the directory could not be shut", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a socket was left behind in a directory that could not be shut")
	}
}

// A directory that could not be opened again leaves a socket nothing can reach, and a
// helper listening on one is indistinguishable from a machine where the interface mode
// does not work. It stops, and takes the socket with it.
func TestASocketIsNotLeftListeningBehindADirectoryThatCouldNotBeOpened(t *testing.T) {
	ownedByThisUser(t)
	path := shortSocketPath(t)
	refuse := errors.New("this directory is not yours to change")

	ln, err := listenHelper(path, func(name string, mode os.FileMode) error {
		if name == filepath.Dir(path) && mode == 0o755 {
			return refuse
		}
		return os.Chmod(name, mode)
	})
	if err == nil {
		ln.Close()
		t.Fatal("a socket was left listening behind a directory nothing can walk through")
	}
	if !errors.Is(err, refuse) {
		t.Errorf("the refusal said %q, which is not why the directory could not be opened", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a socket was left behind by a listen that failed")
	}
}

// The two are opposite instructions. A helper this account cannot reach is installed
// already, and reporting it as missing sends the user back to an install they have done --
// which is where they stop, because doing it again appears to change nothing.
func TestASocketThisAccountCannotOpenIsNotReportedAsAMissingHelper(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on a socket for the helper: %v", err)
	}
	defer ln.Close()
	// What a helper installed by an older build, or from another account, leaves behind.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("close the socket to this account: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, Options{SocketPath: path, Logf: func(string, ...any) {}})
	closeIfOpen(t, client)
	if err == nil {
		t.Fatal("a socket this account cannot open was dialled successfully")
	}
	if !errors.Is(err, ErrHelperNotOpenToThisAccount) {
		t.Errorf("the failure was %q, which is not the one that says the helper is there", err)
	}
	if errors.Is(err, ErrNoHelper) {
		t.Errorf("the failure was %q, which sends the user to install a helper that is already installed", err)
	}
}
