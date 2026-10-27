// SPDX-License-Identifier: MIT

package hostnet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// The helper is this same binary, copied somewhere root owns and run as a daemon, so
// whether it is the build this app expects is answerable exactly: the two files either
// hold the same bytes or they do not. A version string cannot answer it -- two builds of
// one commit report the same version and are not the same program -- and the helper holds
// root while reading a wire protocol that carries no compatibility rules of its own.

// buildID is the hash of the running program's binary, resolved once. The file cannot
// change under a running process in a way that would make a later answer more correct:
// replacing it leaves this process running the bytes it started with.
var buildID = sync.OnceValues(func() (string, error) { return hashExecutable(os.Executable) })

// BuildID identifies this program by the contents of its own binary.
func BuildID() (string, error) { return buildID() }

// hashExecutable hashes the file the locator names. The locator is a parameter so the
// failures below are reachable without an unreadable binary to run the suite from.
func hashExecutable(locate func() (string, error)) (id string, reterr error) {
	path, err := locate()
	if err != nil {
		return "", fmt.Errorf("find this program's own binary to identify it: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read this program's own binary to identify it: %w", err)
	}
	defer func() { reterr = errors.Join(reterr, f.Close()) }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash this program's own binary to identify it: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkBuild refuses a helper running a different binary from this one.
//
// A helper that says nothing is refused as well: the field is the answer to the only
// question that matters here, and a build old enough to omit it is exactly the one this
// exists to catch.
func checkBuild(want, got string) error {
	if got == "" {
		return fmt.Errorf("%w: it did not say which binary it is running", ErrHelperFromAnotherBuild)
	}
	if want != got {
		return fmt.Errorf("%w: it is running a different binary from this one", ErrHelperFromAnotherBuild)
	}
	return nil
}

// expectedBuild reports whether the helper that answered is the one this app speaks to.
//
// Both checks run because they answer different questions: the version is what a person
// can act on, since it names the two releases, and the binary hash is what is actually
// true.
func expectedBuild(caps Capabilities) error { return checkAgainst(caps, BuildID) }

// checkAgainst is the comparison expectedBuild makes, taking this side's own identity as a
// parameter so the refusal for a binary that could not be identified is reachable without
// a suite running from one.
func checkAgainst(caps Capabilities, identify func() (string, error)) error {
	if err := checkVersion(Version, caps.Version); err != nil {
		return err
	}
	id, err := identify()
	if err != nil {
		return fmt.Errorf("identify this app's own binary to check the helper against it: %w", err)
	}
	return checkBuild(id, caps.Build)
}
