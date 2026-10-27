// SPDX-License-Identifier: MIT

package apiauth

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sellitus/app-tail/internal/fileown"
)

// maxTokenFileBytes bounds the read. A token is 48 bytes; anything far larger is not one.
const maxTokenFileBytes = 1024

// errUntrusted marks a token file that exists but that another account could have
// written or can read.
var errUntrusted = errors.New("untrusted token file")

// LoadOrCreate returns the agent's API keys, reading the token stored in dir or writing a
// new one there. A stored token that another account could read or could have written is
// replaced rather than used, and Replaced says why.
//
// dir is the directory the dashboard-address record lives in. It must belong to the
// account running the agent and be writable by nobody else, since whoever can write the
// directory can swap the file; the agent refuses to start otherwise rather than serve an
// API anyone on the machine could take over.
func LoadOrCreate(dir string, opts ...Option) (*Keys, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the directory for the API token %s: %w", dir, err)
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}

	k := newKeys(dir, opts)
	salt, err := k.random(runSaltBytes)
	if err != nil {
		return nil, fmt.Errorf("draw the session key for this run: %w", err)
	}
	k.runSalt = salt
	token, err := readToken(filepath.Join(dir, TokenFileName))
	switch {
	case err == nil && wellFormedToken(token):
		k.install(token)
		return k, nil
	case err == nil:
		k.replaced = "the stored API token was not one this version issues"
	case errors.Is(err, errUntrusted):
		k.replaced = err.Error()
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, err
	}

	if err := k.Rotate(); err != nil {
		return nil, err
	}
	return k, nil
}

// Read returns the API token stored in dir, for the CLI. It applies the checks
// LoadOrCreate does and refuses, rather than repairs, what fails them: the CLI is not the
// file's owner of record, and a token others can read is not a secret worth presenting.
// A missing file is reported as fs.ErrNotExist.
func Read(dir string) (string, error) {
	if err := checkDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, TokenFileName)
	token, err := readToken(path)
	if err != nil {
		return "", err
	}
	if !wellFormedToken(token) {
		return "", fmt.Errorf("%s does not hold an app-tail API token; restart the agent to write a new one", path)
	}
	return token, nil
}

// Rotate writes a new token over the stored one and switches to it. Every session and
// every outstanding launch token dies with the old one.
func (k *Keys) Rotate() error {
	k.rotating.Lock()
	defer k.rotating.Unlock()
	token, err := k.newToken()
	if err != nil {
		return err
	}
	if err := writeToken(k.dir, token); err != nil {
		return err
	}
	k.install(token)
	return nil
}

// readToken opens the token file without following a symlink, and checks the opened file
// itself -- not the path, which could be swapped between a check and an open.
func readToken(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		if isSymlinkRefusal(err) {
			return "", fmt.Errorf("%w: %s is a symbolic link", errUntrusted, path)
		}
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("read the API token: %w", err)
		}
		return "", fmt.Errorf("open the API token %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect the API token %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file", errUntrusted, path)
	}
	if reason := untrustedFile(info); reason != "" {
		return "", fmt.Errorf("%w: %s %s", errUntrusted, path, reason)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes))
	if err != nil {
		return "", fmt.Errorf("read the API token %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// writeToken replaces the token file through a temporary file in the same directory,
// narrowed to this account before anything is written to it, so the token is never
// readable by anyone else even under its temporary name.
func writeToken(dir, token string) error {
	tmp, err := os.CreateTemp(dir, ".api-token-*")
	if err != nil {
		return fmt.Errorf("write the API token: %w", err)
	}
	name := tmp.Name()
	discard := func(cause error) error {
		return errors.Join(fmt.Errorf("write the API token: %w", cause), tmp.Close(), os.Remove(name))
	}
	if err := tmp.Chmod(0o600); err != nil {
		return discard(err)
	}
	if err := fileown.RestrictToOwner(name); err != nil {
		return discard(err)
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		return discard(err)
	}
	if err := tmp.Sync(); err != nil {
		return discard(err)
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("write the API token: %w", err), os.Remove(name))
	}
	if err := os.Rename(name, filepath.Join(dir, TokenFileName)); err != nil {
		return errors.Join(fmt.Errorf("write the API token: %w", err), os.Remove(name))
	}
	return nil
}

// Remove deletes the token file in dir, for rotating while no agent is running: the next
// agent to start writes a new one. A file that is already gone is not an error.
func Remove(dir string) error {
	err := os.Remove(filepath.Join(dir, TokenFileName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the API token: %w", err)
	}
	return nil
}
