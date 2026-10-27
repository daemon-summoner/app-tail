// SPDX-License-Identifier: MIT

// Package secretstore keeps app-tail's credentials in a file of their own, secrets.json,
// beside config.json.
//
// The split is what lets config.json be read, diffed, attached to a bug report or backed
// up without handing over an auth key with it. This file is the one that must never leave
// the machine: it is owner-only everywhere, and on Windows its contents are also sealed
// with DPAPI to the account that wrote them, since an access list there is only as strong
// as whoever can take ownership of the file.
package secretstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sellitus/app-tail/internal/fileown"
)

// FileName is what the credentials file is called, in the directory config.json is in.
const FileName = "secrets.json"

// FileMode is the permission mask the file is created with.
const FileMode fs.FileMode = 0o600

// dirMode is the permission mask for a directory this has to create to write the file.
const dirMode fs.FileMode = 0o700

// formatVersion is the shape of the document inside the file. A file declaring any other
// is refused rather than read as this one: a credential misread is a credential sent
// somewhere, or one silently missing.
const formatVersion = 1

// Secrets is every stored credential, by the kind of entity that holds it ("tunnels",
// "proxies"), that entity's stable id, and the field's wire key. Keying by id rather than
// by position is what keeps a renamed or reordered connection with its own key.
type Secrets map[string]map[string]map[string]string

// document is the file's contents once unsealed.
type document struct {
	Version int     `json:"version"`
	Secrets Secrets `json:"secrets"`
}

// Path is the credentials file that belongs to the config document at configPath.
func Path(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), FileName)
}

// Load reads the credentials file at path. A file that is not there comes back as an
// error matching fs.ErrNotExist, for the caller to treat as "nothing stored yet".
//
// Any other failure names the file and is never an empty result: starting without the
// credentials a file that is present was meant to supply would look like a sign-out, and
// the next write would make it one.
func Load(path string) (Secrets, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("read the stored credentials in %s: %w", path, err)
	}
	plain, err := unseal(sealed)
	if err != nil {
		return nil, fmt.Errorf("%s holds the stored credentials and could not be unsealed by this account: %w", path, err)
	}
	var doc document
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("%s holds the stored credentials and could not be read as JSON: %w", path, err)
	}
	if doc.Version != formatVersion {
		return nil, fmt.Errorf("%s holds the stored credentials in format %d, and this build reads format %d",
			path, doc.Version, formatVersion)
	}
	return doc.Secrets, nil
}

// Save replaces the credentials file at path with secrets, in one step: through a temp
// file in the same directory, owner-only before it holds anything, renamed over the
// target. A crash mid-write leaves the previous file whole.
func Save(path string, secrets Secrets) error {
	plain, err := json.MarshalIndent(document{Version: formatVersion, Secrets: compact(secrets)}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the stored credentials: %w", err)
	}
	sealed, err := seal(append(plain, '\n'))
	if err != nil {
		return fmt.Errorf("seal the stored credentials for %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create state dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".secrets-*.json")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	name := tmp.Name()
	discard := func(cause error) error {
		return errors.Join(cause, tmp.Close(), os.Remove(name))
	}
	if err := tmp.Chmod(FileMode); err != nil {
		return discard(fmt.Errorf("chmod temp file for %s: %w", path, err))
	}
	// Narrowed while still empty: the rename carries the access list onto the real path,
	// so the credentials are never readable by another account, even under the temp name.
	if err := fileown.RestrictToOwner(name); err != nil {
		return discard(fmt.Errorf("restrict access to temp file for %s: %w", path, err))
	}
	if _, err := tmp.Write(sealed); err != nil {
		return discard(fmt.Errorf("write temp file for %s: %w", path, err))
	}
	if err := tmp.Sync(); err != nil {
		return discard(fmt.Errorf("sync temp file for %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("close temp file for %s: %w", path, err), os.Remove(name))
	}
	if err := os.Rename(name, path); err != nil {
		return errors.Join(fmt.Errorf("replace %s: %w", path, err), os.Remove(name))
	}
	return nil
}

// compact drops empty values and the entities and kinds left with none, so the file holds
// exactly the credentials that are set and two equal sets always encode the same way.
func compact(secrets Secrets) Secrets {
	out := Secrets{}
	for kind, entities := range secrets {
		for id, fields := range entities {
			for key, value := range fields {
				if value == "" {
					continue
				}
				if out[kind] == nil {
					out[kind] = map[string]map[string]string{}
				}
				if out[kind][id] == nil {
					out[kind][id] = map[string]string{}
				}
				out[kind][id][key] = value
			}
		}
	}
	return out
}

// Equal reports whether a and b hold the same credentials, ignoring empty values.
func Equal(a, b Secrets) bool {
	ca, cb := compact(a), compact(b)
	if len(ca) != len(cb) {
		return false
	}
	for kind, entities := range ca {
		other := cb[kind]
		if len(entities) != len(other) {
			return false
		}
		for id, fields := range entities {
			theirs := other[id]
			if len(fields) != len(theirs) {
				return false
			}
			for key, value := range fields {
				if held, ok := theirs[key]; !ok || held != value {
					return false
				}
			}
		}
	}
	return true
}
