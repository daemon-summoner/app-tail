// SPDX-License-Identifier: MIT

package config

// Recovering from a config document this build cannot use.
//
// The config file is the one piece of state that can stop everything at once: the tray,
// the dashboard, every forward and the record that puts this machine's resolver back all
// hang off a document that loads. Refusing to start leaves a user with a background
// process that never appears and no surface to fix it from, so a document this build
// cannot use is moved aside and defaults take its place.
//
// Nothing is ever deleted. The document that could not be used is kept beside the one
// that replaced it, every surface says so, and `app-tail config restore` puts it back.
//
// A document's credentials live in secrets.json rather than in the document, so they travel
// with it: whenever a document is moved aside for the defaults, secrets.json is moved aside
// under the same suffix, and restoring that copy brings them back. A copy with no such
// partner -- a pre-migration backup -- is restored onto the credentials in place.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/secretstore"
)

// quarantineSuffix names a document moved aside because this build could not use it,
// carrying the moment it happened so a second bad document never overwrites the first.
const quarantineSuffix = ".unusable-"

// replacedSuffix names a document moved aside by a restore or a reset. A perfectly good
// document is set aside that way, and filing it under "unusable" would tell the person
// reading the directory the opposite of what happened to it.
const replacedSuffix = ".replaced-"

// quarantineStamp is the time format in that name: sortable, and the same length for
// every moment, so the newest copy is the last one alphabetically.
const quarantineStamp = "20060102-150405"

// UnusableError is a config document this build cannot run.
//
// It is deliberately distinct from a file that could not be read at all: a permission or
// I/O fault is a fault of the machine rather than of the document, and moving the file
// aside to work around a disk that is merely busy would destroy the state it holds.
type UnusableError struct {
	// Reason is what is wrong with it, as a sentence for a person to read. It is a field
	// rather than something to be parsed back out of the message, because every surface
	// that reports this shows exactly this sentence.
	Reason string
	// Cause is what reported it.
	Cause error
}

func (e *UnusableError) Error() string { return e.Reason }
func (e *UnusableError) Unwrap() error { return e.Cause }

// unusable builds the error for a document that cannot be used.
func unusable(cause error, format string, args ...any) error {
	return &UnusableError{Reason: fmt.Sprintf(format, args...), Cause: cause}
}

// Quarantine records a document that was moved aside so the app could start.
type Quarantine struct {
	// Path is where the unusable document is now. It is never deleted.
	Path string `json:"path"`
	// Reason is what was wrong with it, in the words the load failed with.
	Reason string `json:"reason"`
	// At is when it was moved.
	At time.Time `json:"at"`
}

// Quarantined reports the document this store had to move aside on load, or nil when the
// stored config loaded cleanly. It is read by every surface that tells the user their
// settings are not the ones they left behind.
func (s *Store) Quarantined() *Quarantine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.quarantined
}

// quarantineFile moves a document aside under suffix and reports where it went.
//
// A rename rather than a copy: the file must be gone from the path the app reads, and
// leaving a copy of a document holding auth keys behind under a second name doubles what
// an attacker who reaches the state directory finds.
func quarantineFile(path string, cause error, suffix string) (*Quarantine, error) {
	reason := cause.Error()
	var bad *UnusableError
	if errors.As(cause, &bad) {
		reason = bad.Reason
	}

	now := time.Now()
	moved, err := freeQuarantinePath(path, now, suffix, secretstore.Path(path))
	if err != nil {
		return nil, err
	}
	if err := os.Rename(path, moved); err != nil {
		return nil, fmt.Errorf("move %s aside: %w", filepath.Base(path), err)
	}
	// The document keeps whatever it was written with, and a config placed by hand or by an
	// older build may have been written open: it still holds auth keys and OAuth secrets.
	if err := restrictToOwner(moved); err != nil {
		return nil, fmt.Errorf("narrow %s: %w", filepath.Base(moved), err)
	}
	return &Quarantine{Path: moved, Reason: reason, At: now}, nil
}

// freeQuarantinePath finds a name beside the config that nothing is using yet. Two bad
// loads within the same second are rare and would otherwise destroy the first document,
// which is the one thing this whole file exists to prevent.
//
// partner, when set, is a file that moves aside under the same suffix right after path --
// the credentials file beside the config -- and its suffixed name has to be free as well.
// Otherwise the config would already be gone when the partner's move found its name taken.
func freeQuarantinePath(path string, now time.Time, suffix, partner string) (string, error) {
	stamp := suffix + now.UTC().Format(quarantineStamp)
	for attempt := 0; attempt < 100; attempt++ {
		if attempt > 0 {
			stamp = fmt.Sprintf("%s%s-%d", suffix, now.UTC().Format(quarantineStamp), attempt+1)
		}
		free, err := nameIsFree(path + stamp)
		if err == nil && free && partner != "" {
			free, err = nameIsFree(partner + stamp)
		}
		if err != nil {
			return "", err
		}
		if free {
			return path + stamp, nil
		}
	}
	return "", fmt.Errorf("no free name to move %s aside to", filepath.Base(path))
}

func nameIsFree(candidate string) (bool, error) {
	_, err := os.Stat(candidate)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("check for %s: %w", filepath.Base(candidate), err)
	}
	return false, nil
}

// salvagedMachineID is the install identity carried over from a document that could not
// be used. The id feeds the {id} hostname token, so generating a new one would rename this
// machine on every tailnet it is on -- worth keeping whenever the document decoded far
// enough to still hold it.
func salvagedMachineID(doc document) string {
	if doc.cfg == nil {
		return ""
	}
	return doc.cfg.Settings.MachineID
}

// SavedDocument is a copy of the config kept beside it: a pre-migration backup, or a
// document moved aside because this build could not use it.
type SavedDocument struct {
	Path string `json:"path"`
	// Kind is "backup" for a copy taken before a migration, "quarantine" for a document
	// this build could not use, "replaced" for one a restore or a reset set aside. They
	// are restored the same way and differ only in why they exist.
	Kind string `json:"kind"`
	// At is the file's own timestamp, which is when it was written.
	At time.Time `json:"at"`
	// Usable reports whether this build could run this copy, and Reason why not. A
	// restore that installs a document the app cannot load only moves the fault.
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
}

// Inspection is what `app-tail config check` reports: whether the stored document loads,
// and what else is on disk to go back to.
type Inspection struct {
	Path string `json:"path"`
	// Exists reports a file at Path. A machine that has never run the app has none, and
	// that is not a fault.
	Exists bool `json:"exists"`
	// Version is the shape the stored document declares, and Current the shape this build
	// writes. Version above Current is a document written by a newer app-tail.
	Version int `json:"version"`
	Current int `json:"current"`
	// Usable reports that this build can load the document, and Reason why not.
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
	// Saved is every copy beside it, newest first.
	Saved []SavedDocument `json:"saved,omitempty"`
}

// Inspect reports on the document at path without changing it. It never creates a config
// file, which is the whole difference between this and opening the store.
//
// The error return is for a machine that could not be read at all. A document that cannot
// be used is the report's own answer, not an error: saying so is what the command is for.
func Inspect(path string) (Inspection, error) {
	report := Inspection{Path: path, Current: ConfigVersion}
	doc, err := loadDocument(path, secretstore.Path(path))
	report.Version = doc.arrived

	var bad *UnusableError
	switch {
	case errors.Is(err, fs.ErrNotExist):
		report.Reason = "there is no config file here yet; the next run writes one with the defaults"
	case errors.As(err, &bad):
		report.Exists = true
		report.Reason = bad.Reason
	case err != nil:
		return Inspection{}, err
	default:
		report.Exists = true
		report.Usable = true
	}

	saved, err := savedBeside(path)
	if err != nil {
		return Inspection{}, err
	}
	report.Saved = saved
	return report, nil
}

// DashboardAddr is where an agent running against the document at path would be listening,
// read without opening or creating it -- opening it is what replaces a document the repair
// commands exist to preserve.
//
// A document that cannot be read falls back to the address the app binds when it starts on
// the defaults, which is exactly the state an agent running against an unusable document is
// in.
func DashboardAddr(path string) string {
	// A running agent records where it bound, which is the answer even when the document
	// asks for another address: a port the agent could not have is exactly the case the
	// record exists for.
	if addr := ReadDashboardAddr(path); addr != "" {
		return addr
	}
	// Whether the document loads is not the question here: one that failed validation has
	// still been decoded, and the address it names is as good an answer as a whole
	// document's. Only a document that decoded to nothing has none. The address is not a
	// credential, so the credentials file is not read.
	doc, err := loadDocument(path, "")
	if (err == nil || doc.cfg != nil) && doc.cfg.Settings.UIListen != "" {
		return doc.cfg.Settings.UIListen
	}
	return DefaultUIListenAddr
}

// savedBeside lists the copies of the config kept next to it, newest first.
func savedBeside(path string) ([]SavedDocument, error) {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	prefix := filepath.Base(path)
	var saved []SavedDocument
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		kind := savedKind(prefix, name)
		if kind == "" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		full := filepath.Join(dir, name)
		one := SavedDocument{Path: full, Kind: kind, At: info.ModTime()}
		secrets, _, err := secretsFor(path, full)
		if err != nil {
			return nil, err
		}
		if _, err := loadDocument(full, secrets); err != nil {
			var bad *UnusableError
			if errors.As(err, &bad) {
				one.Reason = bad.Reason
			} else {
				return nil, err
			}
		} else {
			one.Usable = true
		}
		saved = append(saved, one)
	}
	sort.Slice(saved, func(i, j int) bool { return saved[i].At.After(saved[j].At) })
	return saved, nil
}

// savedKind is the SavedDocument kind of the file called name beside a config called
// prefix, or empty when it is not a saved copy of that config.
func savedKind(prefix, name string) string {
	switch {
	case strings.HasPrefix(name, prefix+quarantineSuffix):
		return "quarantine"
	case strings.HasPrefix(name, prefix+replacedSuffix):
		return "replaced"
	case strings.HasPrefix(name, prefix+".v") && strings.HasSuffix(name, ".bak"):
		return "backup"
	}
	return ""
}

// Restore puts a saved copy back as the config, after proving this build can load it.
//
// from empty means the newest saved copy this build can use. The document being replaced
// is moved aside rather than overwritten, so a restore that turns out to be the wrong one
// is itself undoable.
func Restore(path, from string) (installed string, moved *Quarantine, err error) {
	chosen := from
	if chosen == "" {
		saved, err := savedBeside(path)
		if err != nil {
			return "", nil, err
		}
		for _, one := range saved {
			if one.Usable {
				chosen = one.Path
				break
			}
		}
		if chosen == "" {
			return "", nil, errors.New("there is no saved config beside this one that this build can use")
		}
	}

	// Proved before anything is moved, with the credentials it would run with: installing a
	// document the app cannot load would replace one fault with the same fault under a
	// different name.
	secrets, paired, err := secretsFor(path, chosen)
	if err != nil {
		return "", nil, err
	}
	if _, err := loadDocument(chosen, secrets); err != nil {
		var bad *UnusableError
		if errors.As(err, &bad) {
			return "", nil, fmt.Errorf("%s cannot be restored: %s", filepath.Base(chosen), bad.Reason)
		}
		return "", nil, err
	}

	data, err := os.ReadFile(chosen)
	if err != nil {
		return "", nil, fmt.Errorf("read %s: %w", filepath.Base(chosen), err)
	}
	moved, err = setAside(path, "replaced by "+filepath.Base(chosen))
	if err != nil {
		return "", nil, err
	}
	if paired {
		if err := setSecretsAside(path, moved); err != nil {
			return "", nil, err
		}
		// Moved rather than copied: a second copy of the credentials is a second place to
		// find them.
		if err := os.Rename(secrets, secretstore.Path(path)); err != nil {
			return "", nil, fmt.Errorf("restore the credentials kept with %s: %w", filepath.Base(chosen), err)
		}
	}
	if err := writeConfigFile(path, data); err != nil {
		return "", nil, err
	}
	return chosen, moved, nil
}

// Reset replaces the config with the defaults, keeping the current one beside it.
func Reset(path string) (*Quarantine, error) {
	moved, err := setAside(path, "replaced by the defaults")
	if err != nil {
		return nil, err
	}
	if err := setSecretsAside(path, moved); err != nil {
		return nil, err
	}
	fresh := Defaults()
	id := ""
	if moved != nil {
		// The install keeps its identity across a reset: a reset is a user clearing their
		// settings, not a new machine, and a new id renames this device on every tailnet.
		if doc, err := loadDocument(moved.Path, ""); err == nil || doc.cfg != nil {
			id = salvagedMachineID(doc)
		}
	}
	if id == "" {
		if id, err = NewMachineID(); err != nil {
			return nil, err
		}
	}
	fresh.Settings.MachineID = id
	fresh.Settings.StateDir = filepath.Dir(path)

	data, err := encodeConfig(fresh)
	if err != nil {
		return nil, err
	}
	if err := writeConfigFile(path, data); err != nil {
		return nil, err
	}
	return moved, nil
}

// setAside moves the current document out of the way, reporting nil when there was none
// to move. The reason is recorded for the surfaces that explain what happened.
func setAside(path, reason string) (*Quarantine, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return quarantineFile(path, errors.New(reason), replacedSuffix)
}

// setSecretsAside moves the credentials file beside the config at path out of the way, so
// the defaults about to replace the document do not start with its credentials. A default
// tailnet handed another connection's key would send it to Tailscale's control server
// whatever server it was for.
//
// moved is where the document they belong to went; the credentials take the same suffix,
// which is how a restore of that copy finds them. With no document moved, they get a name of
// their own. Nothing to move is not an error.
func setSecretsAside(path string, moved *Quarantine) error {
	secrets := secretstore.Path(path)
	if _, err := os.Stat(secrets); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", filepath.Base(secrets), err)
	}

	var aside string
	if partner, ok := pairedSecretsPath(path, movedPath(moved)); ok {
		aside = partner
		if _, err := os.Stat(aside); err == nil {
			return fmt.Errorf("move %s aside: %s already exists", filepath.Base(secrets), filepath.Base(aside))
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("check for %s: %w", filepath.Base(aside), err)
		}
	} else {
		free, err := freeQuarantinePath(secrets, time.Now(), replacedSuffix, "")
		if err != nil {
			return err
		}
		aside = free
	}
	if err := os.Rename(secrets, aside); err != nil {
		return fmt.Errorf("move %s aside: %w", filepath.Base(secrets), err)
	}
	return nil
}

func movedPath(moved *Quarantine) string {
	if moved == nil {
		return ""
	}
	return moved.Path
}

// pairedSecretsPath is where the credentials kept with the copy at saved would be: the
// credentials file's name with the suffix the copy carries after the config's own name. A
// copy that is not a suffixed sibling of the config has no partner.
func pairedSecretsPath(path, saved string) (string, bool) {
	if saved == "" || filepath.Dir(saved) != filepath.Dir(path) {
		return "", false
	}
	suffix, ok := strings.CutPrefix(filepath.Base(saved), filepath.Base(path))
	if !ok || suffix == "" {
		return "", false
	}
	return secretstore.Path(path) + suffix, true
}

// secretsFor is the credentials file a restore of saved would run with, and whether it is
// one kept with that copy rather than the one in place.
func secretsFor(path, saved string) (string, bool, error) {
	if partner, ok := pairedSecretsPath(path, saved); ok {
		_, err := os.Stat(partner)
		switch {
		case err == nil:
			return partner, true, nil
		case !errors.Is(err, fs.ErrNotExist):
			return "", false, fmt.Errorf("check for %s: %w", filepath.Base(partner), err)
		}
	}
	return secretstore.Path(path), false, nil
}
