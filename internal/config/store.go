// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/sellitus/app-tail/internal/secretstore"
)

// FileMode is the permission mask for config.json. Its credentials live in secrets.json
// (see secretsplit.go), but it still maps this machine's connections, servers and
// forwards, and an older build or a hand edit can still put a credential in it.
const FileMode fs.FileMode = 0o600

// DirMode is the permission mask for the state directory.
const DirMode fs.FileMode = 0o700

// Store owns the config document and its file, serializing every read and write.
// Mutations are transactional: the change is applied to a copy, validated, and
// persisted before it becomes visible, so a rejected edit leaves state untouched.
type Store struct {
	path string

	mu  sync.RWMutex
	cfg *Config
	// migratedFrom is the version the loaded document arrived as, when it was brought
	// forward on load. It is held rather than acted on immediately so that a run which
	// never writes -- `app-tail --version`, a status query -- leaves the file exactly as
	// it found it; the copy is taken on the first write, which is when the old shape is
	// actually about to be replaced.
	migratedFrom int
	// quarantined is the document this store had to move aside to start, when the stored
	// one could not be used. See recover.go.
	quarantined *Quarantine

	// secretsPath is the file the document's credentials live in, beside path.
	secretsPath string
	// heldSecrets is what that file holds as of this store's last read or write of it, so a
	// write that changes no credential leaves it alone and a failed one can put it back.
	heldSecrets secretstore.Secrets
	// writeConfig puts the encoded document at path, and saveSecrets the credentials at
	// secretsPath. They are fields so a test can fail either of the writes a save makes.
	writeConfig func(path string, data []byte) error
	saveSecrets func(path string, secrets secretstore.Secrets) error
	// strayBlocks is set while config.json still holds a block the load dropped, which can
	// carry a credential the secrets comparison never sees.
	strayBlocks bool
}

// document is one load of the stored file: what it decoded to, the version it arrived as,
// whether it had to be brought forward to reach the shape this build expects, whether a
// connection carried a block of another type that the load dropped, and what the
// credentials file merged into it held.
type document struct {
	cfg         *Config
	arrived     int
	migrated    bool
	strayBlocks bool
	secrets     secretstore.Secrets
}

// Open loads the config at path, creating it with first-run defaults if absent.
// A machine id is generated on first creation and persists from then on.
//
// A document this build cannot use does not stop the app: it is moved aside, defaults
// take its place, and what happened is recorded on the store for every surface to report
// (see recover.go). A file that could not be read at all is still an error -- nothing
// here can tell a broken document from a busy disk, and guessing would move state aside
// to work around a fault that clears on its own. So is a credentials file that could not
// be read: starting without the credentials it holds would look like a sign-out, and the
// next write would make it one.
//
// The defaults never start with another document's credentials. A credentials file found
// with no document, or beside one that had to be moved aside, is moved aside too.
func Open(path string) (*Store, error) {
	s := &Store{path: path, secretsPath: secretstore.Path(path), writeConfig: writeConfigFile, saveSecrets: secretstore.Save}
	doc, err := loadDocument(path, s.secretsPath)

	var bad *UnusableError
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := setSecretsAside(path, nil); err != nil {
			return nil, err
		}
		return s, s.createFresh("")
	case errors.As(err, &bad):
		note, moveErr := quarantineFile(path, err, quarantineSuffix)
		if moveErr != nil {
			return nil, moveErr
		}
		if err := setSecretsAside(path, note); err != nil {
			return nil, err
		}
		if err := s.createFresh(salvagedMachineID(doc)); err != nil {
			return nil, err
		}
		s.quarantined = note
		return s, nil
	case err != nil:
		return nil, err
	}

	if doc.migrated {
		s.migratedFrom = max(doc.arrived, 1)
	}
	s.cfg = doc.cfg
	s.heldSecrets = doc.secrets
	s.strayBlocks = doc.strayBlocks
	return s, nil
}

// loadDocument reads the stored document and brings it up to the shape this build
// expects, without writing anything.
//
// A fault in the document itself comes back as an UnusableError, and the partially loaded
// document comes back with it, so what can still be salvaged from it -- the install's own
// identity -- is reachable.
//
// The credentials in secretsPath are merged in before validation, since a document is only
// valid with them: a WireGuard connection needs its key. A credentials file that cannot be
// read is an error, not an UnusableError -- moving the document aside would not make the
// credentials readable. secretsPath empty reads no credentials, for a caller that wants
// something other than the credentials out of the document.
func loadDocument(path, secretsPath string) (document, error) {
	cfg, raw, err := readFile(path)
	if err != nil {
		return document{}, err
	}
	doc := document{cfg: cfg, arrived: cfg.Version}

	// Migration runs before defaults so a default is never mistaken for a stored value
	// the old shape carried, and before validation so an older document is judged by the
	// rules of the shape it has been brought up to.
	doc.strayBlocks = dropBlocksOfOtherTypes(cfg)
	migrated, err := migrate(cfg, raw)
	if err != nil {
		return doc, unusable(err, "%s could not be brought up to the shape this build expects: %v",
			filepath.Base(path), err)
	}
	doc.migrated = migrated

	applyDefaults(cfg)
	if secretsPath != "" {
		held, err := loadSecrets(secretsPath)
		if err != nil {
			return doc, err
		}
		mergeSecrets(cfg, held)
		doc.secrets = held
	}
	if err := adoptNetworkFacingForwards(cfg, raw); err != nil {
		return doc, unusable(err, "%s could not be read as JSON: %v", filepath.Base(path), err)
	}
	if cfg.Settings.MachineID == "" {
		id, err := NewMachineID()
		if err != nil {
			return doc, err
		}
		cfg.Settings.MachineID = id
	}
	if err := cfg.Validate(); err != nil {
		// A document from the future is not invalid, it is unreadable here: migration
		// skips it entirely, so it is then judged by rules written before the fields it
		// carries existed. Saying "invalid" would send someone looking for a mistake in a
		// file that is perfectly correct for the build that wrote it.
		if doc.arrived > ConfigVersion {
			return doc, unusable(err, "%s was written by a newer app-tail (document version %d, this build understands %d): %v",
				filepath.Base(path), doc.arrived, ConfigVersion, err)
		}
		return doc, unusable(err, "%s is not a valid configuration for this build: %v",
			filepath.Base(path), err)
	}
	return doc, nil
}

// adoptNetworkFacingForwards sets ExposeToNetwork on every to_local forward the stored
// document has listening beyond loopback without saying anything about exposure.
//
// Such a forward was written before the field existed, by someone who chose that address,
// and refusing it now would move the whole document aside over a choice already made. A
// forward whose stored form carries the field keeps the answer it holds, so this changes
// nothing once the document has been written back, and running it again is a no-op.
func adoptNetworkFacingForwards(cfg *Config, raw []byte) error {
	var stored struct {
		Forwards []map[string]json.RawMessage `json:"forwards"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	// Keyed by id rather than position, so a migration that reshaped the list cannot
	// pair one forward with another's stored form.
	answered := make(map[string]bool, len(stored.Forwards))
	for _, held := range stored.Forwards {
		rawID, hasID := held["id"]
		if _, said := held["exposeToNetwork"]; !said || !hasID {
			continue
		}
		var id string
		if err := json.Unmarshal(rawID, &id); err != nil {
			return fmt.Errorf("forward id: %w", err)
		}
		answered[id] = true
	}
	for i := range cfg.Forwards {
		f := &cfg.Forwards[i]
		if answered[f.ID] || f.Direction != ToLocal {
			continue
		}
		if addr, err := netip.ParseAddr(f.BindAddr); err == nil && !addr.IsLoopback() {
			f.ExposeToNetwork = true
		}
	}
	return nil
}

// createFresh installs the first-run defaults and writes them. id carries an install
// identity forward from a document that had to be replaced; empty means generate one.
func (s *Store) createFresh(id string) error {
	cfg := Defaults()
	if id == "" {
		fresh, err := NewMachineID()
		if err != nil {
			return err
		}
		id = fresh
	}
	cfg.Settings.MachineID = id
	cfg.Settings.StateDir = filepath.Dir(s.path)
	s.cfg = cfg
	return s.persist(cfg)
}

// Path returns the file this store persists to.
func (s *Store) Path() string { return s.path }

// Get returns a snapshot of the current config. The caller owns the copy.
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Clone()
}

// Settings returns a snapshot of just the settings.
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.cfg.Settings
	// The slices are copied so a caller sorting or appending to what it was handed does
	// not reach into the stored document behind the lock it just released.
	out.AutoMapPorts = append([]string(nil), s.cfg.Settings.AutoMapPorts...)
	out.SystemDNSLocalSuffixes = slices.Clone(s.cfg.Settings.SystemDNSLocalSuffixes)
	return out
}

// Update applies mutate to a copy of the config, validates the result, writes it to
// disk, and only then swaps it in. Any error leaves the store and file unchanged.
//
// It is UpdateReporting for a caller with nowhere to show the report. The rules the
// report describes are applied either way.
func (s *Store) Update(mutate func(*Config) error) (*Config, error) {
	next, _, err := s.UpdateReporting(mutate)
	return next, err
}

// ScrubSavedCopies takes the credentials out of the copies of the config kept beside it that
// still hold them inline, keeping each one restorable (see scrubSavedCopies). It returns the
// copies that do not decode as a config document, which are left as they are.
func (s *Store) ScrubSavedCopies() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scrubSavedCopies(s.path)
}

// MoveInlineCredentials writes the document back when config.json still carries
// credentials inline, or a block the load dropped, so the credentials land in secrets.json
// and leave config.json now rather than at the next settings change. It reports whether it
// wrote. Open never writes, which keeps
// a command that only reads from changing the file; the agent calls this as it starts.
func (s *Store) MoveInlineCredentials() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil || (!s.strayBlocks && secretstore.Equal(collectSecrets(s.cfg), s.heldSecrets)) {
		return false, nil
	}
	if err := s.persist(s.cfg); err != nil {
		return false, err
	}
	return true, nil
}

// UpdateReport is what a write did beyond what the mutation asked for, for the caller to
// tell the person who made it.
type UpdateReport struct {
	// ClearedCredentials are the tailnet credentials dropped because their connection
	// moved to another control server in this write.
	ClearedCredentials []ClearedCredential
}

// ClearedCredential names a connection whose stored credential was dropped, and the
// control server it now needs one for.
type ClearedCredential struct {
	TunnelID   string
	ControlURL string
}

// Notice is the sentence that tells the person what happened and what to do about it.
func (c ClearedCredential) Notice() string {
	return "the credential was cleared because the control server changed; enter it again for " + c.ControlURL
}

// CredentialWrite names a tailnet credential a write supplies explicitly: the connection
// it belongs to and its JSON key.
type CredentialWrite struct {
	TunnelID string
	Key      string
}

// credentialKeys are the JSON keys of the credentials a connection hands its control server.
var credentialKeys = []string{"authKey", "oauthClientSecret", "oauthClientSecretFile"}

// CredentialWritesIn lists the credentials patch writes on the connection tunnelID. The
// RedactedSecret value is not one: it keeps the stored value, which nobody entered for
// whatever control server the same patch names.
func CredentialWritesIn(tunnelID string, patch map[string]json.RawMessage) []CredentialWrite {
	var out []CredentialWrite
	for _, key := range credentialKeys {
		raw, ok := patch[key]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil && value == RedactedSecret {
			continue
		}
		out = append(out, CredentialWrite{TunnelID: tunnelID, Key: key})
	}
	return out
}

// UpdateReporting is Update, also returning what the write did beyond the mutation.
//
// supplied names the credentials the write itself entered. Those survive a change of
// control server in the same write even when the value matches the one stored: the person
// entered it for the new server, and only the patch, not the values, can say so.
func (s *Store) UpdateReporting(mutate func(*Config) error, supplied ...CredentialWrite) (*Config, UpdateReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	if err := mutate(next); err != nil {
		return nil, UpdateReport{}, err
	}
	report := UpdateReport{ClearedCredentials: clearMovedCredentials(s.cfg, next, supplied)}
	applyDefaults(next)
	if err := next.Validate(); err != nil {
		return nil, UpdateReport{}, err
	}
	if err := s.persist(next); err != nil {
		return nil, UpdateReport{}, err
	}
	s.cfg = next
	return next.Clone(), report, nil
}

// clearMovedCredentials drops every stored credential of a tailnet connection whose
// control server changed between prev and next, unless that credential was itself
// rewritten in the same change or is named in supplied.
//
// The node hands its credential to whatever control server the connection names on its
// next start, so a key for one tailnet left in place under a new server is that key sent
// to a server its owner never chose to give it to. Only the stored document is touched:
// a credential or a server supplied by the environment never passes through here.
func clearMovedCredentials(prev, next *Config, supplied []CredentialWrite) []ClearedCredential {
	var cleared []ClearedCredential
	for i := range next.Tunnels {
		after := next.Tunnels[i].Tailscale
		if after == nil {
			continue
		}
		held, ok := prev.Tunnel(next.Tunnels[i].ID)
		if !ok || held.Tailscale == nil {
			continue
		}
		before := held.Tailscale
		if effectiveControlURL(before.ControlURL) == effectiveControlURL(after.ControlURL) {
			continue
		}
		id := next.Tunnels[i].ID
		dropped := false
		for _, field := range []struct {
			key           string
			before, after *string
		}{
			{"authKey", &before.AuthKey, &after.AuthKey},
			{"oauthClientSecret", &before.OAuthClientSecret, &after.OAuthClientSecret},
			{"oauthClientSecretFile", &before.OAuthClientSecretFile, &after.OAuthClientSecretFile},
		} {
			if slices.Contains(supplied, CredentialWrite{TunnelID: id, Key: field.key}) {
				continue
			}
			if *field.after != "" && *field.after == *field.before {
				*field.after = ""
				dropped = true
			}
		}
		if dropped {
			cleared = append(cleared, ClearedCredential{
				TunnelID:   id,
				ControlURL: effectiveControlURL(after.ControlURL),
			})
		}
	}
	return cleared
}

// effectiveControlURL is the server a stored control URL sends the node to: empty means
// Tailscale's own.
//
// The result is canonical, so the same server written with another letter case, its default
// port or a trailing slash compares equal and does not count as a move to another server.
func effectiveControlURL(stored string) string {
	v := strings.TrimSpace(stored)
	if v == "" {
		return TailscaleControlURL
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return v
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	canonical := scheme + "://" + host + strings.TrimSuffix(u.EscapedPath(), "/")
	if u.RawQuery != "" {
		canonical += "?" + u.RawQuery
	}
	return canonical
}

// persist writes cfg's credentials to secrets.json and the rest of it to config.json, each
// through a temp file in the same directory renamed over the target, so a crash mid-write
// can never leave a truncated file behind.
//
// The credentials are written first. A crash between the two writes then leaves
// secrets.json already holding every credential config.json is about to stop carrying --
// never config.json without a credential that secrets.json does not yet have.
func (s *Store) persist(cfg *Config) error {
	if s.migratedFrom != 0 {
		if err := backupBeforeMigration(s.path, s.migratedFrom); err != nil {
			return fmt.Errorf("back up %s before replacing it with the migrated document: %w", s.path, err)
		}
		s.migratedFrom = 0
	}
	data, err := encodeConfig(cfg)
	if err != nil {
		return err
	}
	secrets := collectSecrets(cfg)
	changed := !secretstore.Equal(secrets, s.heldSecrets)
	if changed {
		if err := s.saveSecrets(s.secretsPath, secrets); err != nil {
			return err
		}
	}
	if err := s.writeConfig(s.path, data); err != nil {
		if !changed {
			return err
		}
		// The write is refused, so the store keeps the previous document, and so does
		// config.json. The credentials go back to the ones they both expect: left as
		// written, a removal refused here would still have taken its connection's key.
		if restoreErr := s.saveSecrets(s.secretsPath, s.heldSecrets); restoreErr != nil {
			// A save either replaces the file whole or leaves it be, so secrets.json still
			// holds this write's credentials. Holding that keeps the next write from
			// skipping the save that brings the file back in line with the document.
			s.heldSecrets = secrets
			return errors.Join(err, fmt.Errorf("put back the credentials in %s: %w", s.secretsPath, restoreErr))
		}
		return err
	}
	if changed {
		s.heldSecrets = secrets
	}
	s.strayBlocks = false
	return nil
}

// loadSecrets reads the credentials file at path. One that is not there holds nothing.
func loadSecrets(path string) (secretstore.Secrets, error) {
	held, err := secretstore.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return secretstore.Secrets{}, nil
	}
	return held, err
}

// encodeConfig renders a config the way the file holds it: everything but its credentials.
func encodeConfig(cfg *Config) ([]byte, error) {
	stored := cfg.Clone()
	clearSecrets(stored)
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return append(data, '\n'), nil
}

// writeConfigFile puts data at path through a temp file in the same directory, renamed
// over the target, so a crash mid-write can never leave a truncated config behind.
func writeConfigFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("create state dir %s: %w", dir, err)
	}
	tmpName, err := writeTempFile(dir, ".config-*.json", data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return errors.Join(fmt.Errorf("replace config: %w", err), os.Remove(tmpName))
	}
	return nil
}

// writeTempFile writes data to a new file in dir, reachable only by the account running
// this process, and returns its name for the caller to rename into place. A failure
// leaves nothing behind.
func writeTempFile(dir, pattern string, data []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	// The file is going away either way, so what went wrong closing or removing it cannot
	// matter more than the cause -- but a temp file left in the state directory is worth
	// naming rather than dropping.
	discard := func(cause error) (string, error) {
		return "", errors.Join(cause, tmp.Close(), os.Remove(name))
	}

	if err := tmp.Chmod(FileMode); err != nil {
		return discard(fmt.Errorf("chmod temp file: %w", err))
	}
	// The rename carries the access this grants onto the real path, so the file is never
	// reachable by anyone else even for the moment it spends under its temporary name.
	if err := restrictToOwner(name); err != nil {
		return discard(fmt.Errorf("restrict access to temp file: %w", err))
	}
	if _, err := tmp.Write(data); err != nil {
		return discard(fmt.Errorf("write temp file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return discard(fmt.Errorf("sync temp file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return "", errors.Join(fmt.Errorf("close temp file: %w", err), os.Remove(name))
	}
	return name, nil
}

// readFile returns the decoded document and the bytes it was decoded from. The bytes are
// what a migration reads a field this build no longer has out of.
func readFile(path string) (*Config, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, nil, unusable(err, "%s could not be read as JSON: %v", filepath.Base(path), err)
	}
	return &cfg, data, nil
}
