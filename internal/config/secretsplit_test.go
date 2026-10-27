// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
	"github.com/sellitus/app-tail/internal/secretstore"
)

// The credentials the fixture stores. They were made up for this suite and unlock nothing.
// The WireGuard keys and the OpenVPN key are the suite's own fixtures, which validation
// requires to decode and the secret scanner already knows, and the static keys are built by
// the suite's helper so no key block appears in the source.
const (
	fixtureAuthKey       = "tskey-auth-kFIXTURE-auth-key-value"
	fixtureOAuthSecret   = "tskey-client-kFIXTURE-oauth-secret-value"
	fixtureWGPrivateKey  = testPrivateKey
	fixtureWGPreshared   = testPublicKey
	fixtureOVPNPass      = "fixture-ovpn-key-passphrase"
	fixtureOVPNPassword  = "fixture-ovpn-account-password"
	fixtureProxyPassword = "fixture-proxy-token-value"
)

var (
	fixtureOVPNKey      = ovpnKeyPEM
	fixtureOVPNTLSCrypt = staticKeyBlock("a1b2c3d4e5f60718293a4b5c6d7e8f90")
	fixtureOVPNTLSAuth  = staticKeyBlock("f0e1d2c3b4a5968778695a4b3c2d1e0f")
)

// Connection ids the fixture adds beside the primary tailnet.
const (
	fixtureWGID       = "tn_wgfix"
	fixtureOVPNID     = "tn_ovfix"
	fixtureOVPNAuthID = "tn_oafix"
)

// fixtureSecrets labels every credential the fixture stores. A failure names the label,
// never the value.
var fixtureSecrets = map[string]string{
	"tailnet auth key":         fixtureAuthKey,
	"tailnet OAuth secret":     fixtureOAuthSecret,
	"WireGuard private key":    fixtureWGPrivateKey,
	"WireGuard pre-shared key": fixtureWGPreshared,
	"OpenVPN private key":      fixtureOVPNKey,
	"OpenVPN key passphrase":   fixtureOVPNPass,
	"OpenVPN password":         fixtureOVPNPassword,
	"OpenVPN tls-crypt key":    fixtureOVPNTLSCrypt,
	"OpenVPN tls-auth key":     fixtureOVPNTLSAuth,
	"proxy password":           fixtureProxyPassword,
}

// storeEverySecret fills c with a value in every credential field a document can hold.
func storeEverySecret(c *Config) error {
	primary, err := c.PrimaryTailscale()
	if err != nil {
		return err
	}
	primary.AuthKey = fixtureAuthKey
	primary.OAuthClientSecret = fixtureOAuthSecret
	primary.Tags = []string{"tag:fixture"}

	wg := NewTunnel(fixtureWGID, "wgfix", "WireGuard fixture", TunnelWireGuard)
	fixture := wireGuardFixture()
	fixture.Peer.PresharedKey = fixtureWGPreshared
	wg.WireGuard = &fixture

	ovpn := func(id, slug string) Tunnel {
		held := NewTunnel(id, slug, slug, TunnelOpenVPN)
		held.OpenVPN = &OpenVPNTunnel{
			Remote: "vpn.example.com:1194", Proto: OpenVPNProtoUDP,
			CA:   ovpnCAPEM,
			Cert: ovpnCertPEM,
			Key:  fixtureOVPNKey, KeyPassphrase: fixtureOVPNPass,
			AuthUserPass: true, Username: "fixture-user", Password: fixtureOVPNPassword,
			Routes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")},
		}
		return held
	}
	crypt := ovpn(fixtureOVPNID, "ovfix")
	crypt.OpenVPN.TLSCrypt = fixtureOVPNTLSCrypt
	auth := ovpn(fixtureOVPNAuthID, "oafix")
	auth.OpenVPN.TLSAuth = fixtureOVPNTLSAuth
	auth.OpenVPN.KeyDirection = OpenVPNKeyDirectionClient
	c.Tunnels = append(c.Tunnels, wg, crypt, auth)

	proxy, ok := c.Proxy(DefaultProxyID)
	if !ok {
		return errors.New("the document has no default proxy to put a password on")
	}
	for i := range c.Proxies {
		if c.Proxies[i].ID == proxy.ID {
			c.Proxies[i].RequireToken = true
			c.Proxies[i].Token = fixtureProxyPassword
		}
	}
	return nil
}

// storeWithEverySecret is a store whose document holds every credential, written once.
func storeWithEverySecret(t *testing.T) (*Store, string) {
	t.Helper()
	s, path := newStore(t)
	if _, err := s.Update(storeEverySecret); err != nil {
		t.Fatalf("storing every secret: %v", err)
	}
	return s, path
}

// inlineDocument renders cfg the way a build that kept credentials in config.json wrote it.
func inlineDocument(t *testing.T, cfg *Config) []byte {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("encoding the inline document: %v", err)
	}
	return data
}

// requireNoSecretIn fails for every fixture credential found in data, naming only its label.
func requireNoSecretIn(t *testing.T, what string, data []byte) {
	t.Helper()
	for label, value := range fixtureSecrets {
		if strings.Contains(string(data), value) {
			t.Errorf("%s holds the %s", what, label)
		}
	}
}

// heldSecrets reads back what a loaded document carries in each credential field, by the
// fixture's labels.
func heldSecrets(t *testing.T, cfg *Config) map[string]string {
	t.Helper()
	held := map[string]string{}
	if primary, ok := cfg.Tunnel(PrimaryTunnelID); ok {
		held["tailnet auth key"] = primary.TS().AuthKey
		held["tailnet OAuth secret"] = primary.TS().OAuthClientSecret
	}
	if wg, ok := cfg.Tunnel(fixtureWGID); ok {
		held["WireGuard private key"] = wg.WG().PrivateKey
		held["WireGuard pre-shared key"] = wg.WG().Peer.PresharedKey
	}
	if crypt, ok := cfg.Tunnel(fixtureOVPNID); ok {
		held["OpenVPN private key"] = crypt.OVPN().Key
		held["OpenVPN key passphrase"] = crypt.OVPN().KeyPassphrase
		held["OpenVPN password"] = crypt.OVPN().Password
		held["OpenVPN tls-crypt key"] = crypt.OVPN().TLSCrypt
	}
	if auth, ok := cfg.Tunnel(fixtureOVPNAuthID); ok {
		held["OpenVPN tls-auth key"] = auth.OVPN().TLSAuth
	}
	if proxy, ok := cfg.Proxy(DefaultProxyID); ok {
		held["proxy password"] = proxy.Token
	}
	return held
}

// requireEverySecret fails for every fixture credential the document does not carry.
func requireEverySecret(t *testing.T, what string, cfg *Config) {
	t.Helper()
	held := heldSecrets(t, cfg)
	for label, want := range fixtureSecrets {
		if held[label] != want {
			t.Errorf("%s does not carry the %s", what, label)
		}
	}
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	return data
}

// The fixture is only a proof if it reaches every credential field there is. A secret field
// added to a registry without a value here would be a field nothing checks stays out of
// config.json.
func TestTheFixtureStoresAValueInEverySecretField(t *testing.T) {
	cfg := Defaults()
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the fixture document is not valid: %v", err)
	}
	for _, f := range settingsRegistry.Fields() {
		if f.Kind.Secret() {
			t.Errorf("settings field %s is secret and the fixture stores nothing in it", f.JSONKey)
		}
	}
	for _, f := range tunnelRegistry.Fields() {
		if !f.Kind.Secret() {
			continue
		}
		found := false
		for i := range cfg.Tunnels {
			if tunnelRegistry.applies(f, &cfg.Tunnels[i]) && f.get(&cfg.Tunnels[i]) != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("connection field %s is secret and the fixture stores nothing in it", f.JSONKey)
		}
	}
	for _, f := range proxyRegistry.Fields() {
		if !f.Kind.Secret() {
			continue
		}
		found := false
		for i := range cfg.Proxies {
			if f.get(&cfg.Proxies[i]) != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("proxy field %s is secret and the fixture stores nothing in it", f.JSONKey)
		}
	}
}

func TestAFreshWriteLeavesNoSecretInTheConfigFile(t *testing.T) {
	_, path := storeWithEverySecret(t)

	requireNoSecretIn(t, "config.json", readBytes(t, path))
	secrets := secretstore.Path(path)
	fileowntest.AssertOwnerOnly(t, secrets, secretstore.FileMode)
}

func TestEveryStoredSecretComesBackOnTheNextStart(t *testing.T) {
	s, path := storeWithEverySecret(t)
	requireEverySecret(t, "the store that wrote them", s.Get())

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	requireEverySecret(t, "the reopened store", reopened.Get())
}

// Keyed by connection id: a reorder or a rename must leave each key with its own connection.
func TestASecretStaysWithItsConnectionAcrossAReorderAndARename(t *testing.T) {
	s, path := storeWithEverySecret(t)
	if _, err := s.Update(func(c *Config) error {
		for i, j := 0, len(c.Tunnels)-1; i < j; i, j = i+1, j-1 {
			c.Tunnels[i], c.Tunnels[j] = c.Tunnels[j], c.Tunnels[i]
		}
		for i := range c.Tunnels {
			c.Tunnels[i].Name += " renamed"
		}
		return nil
	}); err != nil {
		t.Fatalf("reorder and rename: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	requireEverySecret(t, "the reopened store", reopened.Get())
}

func TestAClearedSecretIsGoneFromTheSecretsFile(t *testing.T) {
	s, path := storeWithEverySecret(t)
	if _, err := s.Update(func(c *Config) error {
		primary, err := c.PrimaryTailscale()
		if err != nil {
			return err
		}
		primary.AuthKey = ""
		return nil
	}); err != nil {
		t.Fatalf("clearing the auth key: %v", err)
	}
	if strings.Contains(string(readBytes(t, secretstore.Path(path))), fixtureAuthKey) {
		t.Error("secrets.json still holds the auth key that was cleared")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if held := heldSecrets(t, reopened.Get())["tailnet auth key"]; held != "" {
		t.Error("the cleared auth key came back on the next start")
	}
}

// A deleted connection's key is not kept anywhere: a credential nothing shows and nothing
// can clear is one that outlives the connection it was for.
func TestARemovedConnectionTakesItsSecretsWithIt(t *testing.T) {
	s, path := storeWithEverySecret(t)
	if _, err := s.Update(func(c *Config) error {
		for i := range c.Tunnels {
			if c.Tunnels[i].ID == fixtureWGID {
				c.Tunnels = append(c.Tunnels[:i], c.Tunnels[i+1:]...)
				return nil
			}
		}
		return errors.New("no WireGuard connection to remove")
	}); err != nil {
		t.Fatalf("removing the connection: %v", err)
	}
	stored := readBytes(t, secretstore.Path(path))
	if strings.Contains(string(stored), fixtureWGPreshared) || strings.Contains(string(stored), fixtureWGID) {
		t.Error("secrets.json still holds the removed connection's keys")
	}
}

// A write that touches no credential has no reason to rewrite the file holding them.
func TestAWriteThatChangesNoSecretLeavesTheSecretsFileAlone(t *testing.T) {
	s, path := storeWithEverySecret(t)
	before, err := os.Stat(secretstore.Path(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(func(c *Config) error {
		c.Forwards = append(c.Forwards, validForward())
		return nil
	}); err != nil {
		t.Fatalf("adding a forward: %v", err)
	}
	after, err := os.Stat(secretstore.Path(path))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("secrets.json was replaced by a write that changed no credential")
	}
}

// The upgrade every existing install takes: a document from a build that kept credentials
// inline still starts with them, and its next write moves them.
func TestADocumentWithInlineSecretsMovesThemOnItsNextWrite(t *testing.T) {
	cases := []struct {
		name string
		body func(t *testing.T) []byte
	}{
		{"current shape", func(t *testing.T) []byte {
			cfg := Defaults()
			cfg.Settings.MachineID = "abcd1234"
			if err := storeEverySecret(cfg); err != nil {
				t.Fatal(err)
			}
			return inlineDocument(t, cfg)
		}},
		{"an older shape", func(t *testing.T) []byte {
			cfg := Defaults()
			cfg.Settings.MachineID = "abcd1234"
			if err := storeEverySecret(cfg); err != nil {
				t.Fatal(err)
			}
			cfg.Version = ConfigVersion - 1
			return inlineDocument(t, cfg)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, string(tc.body(t)))

			s, err := Open(path)
			if err != nil {
				t.Fatalf("opening the inline document: %v", err)
			}
			requireEverySecret(t, "the store that loaded the inline document", s.Get())
			if _, err := os.Stat(secretstore.Path(path)); !errors.Is(err, os.ErrNotExist) {
				t.Error("loading alone wrote secrets.json; a run that only reads must change nothing")
			}

			if _, err := s.Update(func(*Config) error { return nil }); err != nil {
				t.Fatalf("the first write: %v", err)
			}
			requireNoSecretIn(t, "config.json after the first write", readBytes(t, path))
			reopened, err := Open(path)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			requireEverySecret(t, "the reopened store", reopened.Get())
		})
	}
}

// The agent does not wait for a settings change to take inline credentials out of
// config.json: it moves them as it starts, and a start with nothing to move writes nothing.
func TestTheAgentMovesInlineSecretsOutAsItStarts(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, string(inlineDocument(t, cfg)))
	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening the inline document: %v", err)
	}

	moved, err := s.MoveInlineCredentials()
	if err != nil {
		t.Fatalf("moving the inline credentials: %v", err)
	}
	if !moved {
		t.Error("credentials were found inline, but the store reports nothing moved")
	}
	requireNoSecretIn(t, "config.json after the start", readBytes(t, path))
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	requireEverySecret(t, "the reopened store", reopened.Get())

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	moved, err = reopened.MoveInlineCredentials()
	if err != nil {
		t.Fatalf("a second start: %v", err)
	}
	if moved {
		t.Error("a start with nothing inline reported moving credentials")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("a start with nothing inline rewrote config.json")
	}
}

func TestAStartWithNoCredentialsCreatesNoSecretsFile(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	path := writeConfig(t, string(inlineDocument(t, cfg)))
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := s.MoveInlineCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if moved {
		t.Error("a document with no credentials reported moving some")
	}
	if _, err := os.Stat(secretstore.Path(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("secrets.json was created for a document with no credentials (stat: %v)", err)
	}
}

// The tailnet's credentials lived in the settings document before a connection could hold
// them. They move onto the connection and then out of the file, in the same first write.
func TestTheOldestShapesCredentialsEndUpInTheSecretsFile(t *testing.T) {
	path := writeConfig(t, fmt.Sprintf(`{"settings":{"authKey":%q,"oauthClientSecret":%q,"tags":["tag:fixture"],`+
		`"proxy.requireToken":true,"proxy.token":%q},"forwards":[]}`,
		fixtureAuthKey, fixtureOAuthSecret, fixtureProxyPassword))

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if _, err := s.Update(func(*Config) error { return nil }); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	requireNoSecretIn(t, "config.json", readBytes(t, path))
	requireNoSecretIn(t, "the pre-migration backup", readBytes(t, path+backupSuffix(1)))

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	held := heldSecrets(t, reopened.Get())
	for _, label := range []string{"tailnet auth key", "tailnet OAuth secret", "proxy password"} {
		if held[label] != fixtureSecrets[label] {
			t.Errorf("the reopened store does not carry the %s", label)
		}
	}
}

// The copy kept for going back is a second place an attacker would look. It holds the old
// shape, every setting in it, and no credential.
func TestTheMigrationBackupHoldsNoSecret(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Version = ConfigVersion - 1
	path := writeConfig(t, string(inlineDocument(t, cfg)))

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if _, err := s.Update(func(*Config) error { return nil }); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	backup := readBytes(t, path+backupSuffix(ConfigVersion-1))
	requireNoSecretIn(t, "the pre-migration backup", backup)
	var held Config
	if err := json.Unmarshal(backup, &held); err != nil {
		t.Fatalf("the backup is no longer JSON: %v", err)
	}
	if held.Version != ConfigVersion-1 || len(held.Tunnels) != len(cfg.Tunnels) {
		t.Errorf("the backup is version %d with %d connections, want the original %d with %d",
			held.Version, len(held.Tunnels), ConfigVersion-1, len(cfg.Tunnels))
	}
	if wg, ok := held.Tunnel(fixtureWGID); !ok || wg.WG().Peer.PublicKey != testPeerKey {
		t.Error("scrubbing took a setting that is not a credential out of the backup")
	}
	if crypt, ok := held.Tunnel(fixtureOVPNID); !ok || crypt.OVPN().Username != "fixture-user" {
		t.Error("scrubbing took the OpenVPN username, which is not a credential, out of the backup")
	}
}

// Restoring the scrubbed copy must not sign every connection out: the credentials it no
// longer carries are the ones still in secrets.json.
func TestRestoringAScrubbedBackupKeepsTheCurrentSecrets(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Version = ConfigVersion - 1
	path := writeConfig(t, string(inlineDocument(t, cfg)))
	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if _, err := s.Update(func(*Config) error { return nil }); err != nil {
		t.Fatalf("the first write: %v", err)
	}

	backup := path + backupSuffix(ConfigVersion-1)
	if _, _, err := Restore(path, backup); err != nil {
		t.Fatalf("restoring the backup: %v", err)
	}
	restored, err := Open(path)
	if err != nil {
		t.Fatalf("opening the restored document: %v", err)
	}
	requireEverySecret(t, "the restored document", restored.Get())
}

// A failed second write must leave every credential somewhere a restart finds it.
func TestAFailedConfigWriteLeavesEverySecretRecoverable(t *testing.T) {
	t.Run("moving inline secrets out", func(t *testing.T) {
		cfg := Defaults()
		cfg.Settings.MachineID = "abcd1234"
		if err := storeEverySecret(cfg); err != nil {
			t.Fatal(err)
		}
		path := writeConfig(t, string(inlineDocument(t, cfg)))
		s, err := Open(path)
		if err != nil {
			t.Fatalf("opening: %v", err)
		}
		s.writeConfig = func(string, []byte) error { return errors.New("disk full") }
		if _, err := s.Update(func(*Config) error { return nil }); err == nil {
			t.Fatal("the write succeeded with the config write failing")
		}
		reopened, err := Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		requireEverySecret(t, "the store reopened after the failed write", reopened.Get())
	})

	t.Run("removing a connection", func(t *testing.T) {
		s, path := storeWithEverySecret(t)
		s.writeConfig = func(string, []byte) error { return errors.New("disk full") }
		if _, err := s.Update(func(c *Config) error {
			c.Tunnels = c.Tunnels[:1]
			return nil
		}); err == nil {
			t.Fatal("the write succeeded with the config write failing")
		}
		// The removal was refused, so the document on disk still names every connection, and
		// each one still needs its key.
		reopened, err := Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		requireEverySecret(t, "the store reopened after the failed write", reopened.Get())
	})
}

// A crash can land on either side of the config write, and the config write is the one
// that takes the credentials out of config.json. A restart from the disk as it stands just
// before it, and just after it, must find every credential.
func TestACrashBetweenTheTwoWritesLosesNoSecret(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, string(inlineDocument(t, cfg)))
	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}

	restartFinds := func(moment string) {
		restarted, err := Open(path)
		if err != nil {
			t.Errorf("a restart %s failed: %v", moment, err)
			return
		}
		requireEverySecret(t, "a restart "+moment, restarted.Get())
	}
	reached := false
	s.writeConfig = func(target string, data []byte) error {
		reached = true
		restartFinds("just before config.json is replaced")
		if err := writeConfigFile(target, data); err != nil {
			return err
		}
		restartFinds("just after config.json is replaced")
		return nil
	}
	if _, err := s.Update(func(*Config) error { return nil }); err != nil {
		t.Fatalf("the write: %v", err)
	}
	if !reached {
		t.Fatal("the config write was never reached")
	}
}

// When the credentials cannot be put back after a refused write, the store must not go on
// believing they were: the next write has to bring secrets.json back in line with the
// document, or the connections it still names start without their keys.
func TestAFailedRestoreOfTheCredentialsIsRepairedByTheNextWrite(t *testing.T) {
	s, path := storeWithEverySecret(t)
	s.writeConfig = func(string, []byte) error { return errors.New("disk full") }
	saves := 0
	s.saveSecrets = func(target string, secrets secretstore.Secrets) error {
		saves++
		if saves == 2 {
			return errors.New("disk full")
		}
		return secretstore.Save(target, secrets)
	}
	if _, err := s.Update(func(c *Config) error {
		c.Tunnels = c.Tunnels[:1]
		return nil
	}); err == nil {
		t.Fatal("the write succeeded with the config write failing")
	}
	if saves != 2 {
		t.Fatalf("secrets.json was saved %d times, want the write and the restore", saves)
	}

	s.writeConfig = writeConfigFile
	s.saveSecrets = secretstore.Save
	if _, err := s.Update(func(c *Config) error {
		c.Settings.UDPSessionTimeoutSec = 45
		return nil
	}); err != nil {
		t.Fatalf("the write after the disk cleared: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	requireEverySecret(t, "the store reopened after the repairing write", reopened.Get())
}

// A tailnet credential is only ever handed to the control server it was entered for, even
// when config.json and secrets.json on disk come from different moments.
func TestACredentialIsNeverPairedWithAControlServerItWasNotSavedFor(t *testing.T) {
	const (
		serverA = "https://a.example.com"
		serverB = "https://b.example.com"
		keyA    = "tskey-auth-kFIXTURE-server-a"
		keyB    = "tskey-auth-kFIXTURE-server-b"
	)
	onServer := func(url, key string) func(*Config) error {
		return func(c *Config) error {
			primary, err := c.PrimaryTailscale()
			if err != nil {
				return err
			}
			primary.ControlURL = url
			primary.AuthKey = key
			return nil
		}
	}
	keyAfterRestart := func(t *testing.T, path string) (string, string) {
		t.Helper()
		restarted, err := Open(path)
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
		primary, ok := restarted.Get().Tunnel(PrimaryTunnelID)
		if !ok {
			t.Fatal("the restarted document has no primary connection")
		}
		return primary.TS().ControlURL, primary.TS().AuthKey
	}
	supplied := CredentialWrite{TunnelID: PrimaryTunnelID, Key: "authKey"}

	t.Run("a crash between the two writes", func(t *testing.T) {
		s, path := newStore(t)
		if _, err := s.Update(onServer(serverA, keyA)); err != nil {
			t.Fatal(err)
		}
		reached := false
		s.writeConfig = func(string, []byte) error {
			reached = true
			url, key := keyAfterRestart(t, path)
			if url == serverA && key == keyB {
				t.Error("a restart from the disk between the writes hands server B's key to server A")
			}
			return errors.New("the machine lost power")
		}
		if _, _, err := s.UpdateReporting(onServer(serverB, keyB), supplied); err == nil {
			t.Fatal("the write succeeded with the config write failing")
		}
		if !reached {
			t.Fatal("the config write was never reached")
		}
	})

	t.Run("an older copy restored over the document", func(t *testing.T) {
		s, path := newStore(t)
		if _, err := s.Update(onServer(serverA, keyA)); err != nil {
			t.Fatal(err)
		}
		older := readBytes(t, path)
		if _, _, err := s.UpdateReporting(onServer(serverB, keyB), supplied); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, older, 0o600); err != nil {
			t.Fatal(err)
		}
		url, key := keyAfterRestart(t, path)
		if url != serverA {
			t.Fatalf("the restored document names %q, want server A", url)
		}
		if key == keyB {
			t.Error("the restored document naming server A was given server B's key")
		}
	})

	t.Run("the server it was saved for", func(t *testing.T) {
		s, path := newStore(t)
		if _, err := s.Update(onServer(serverA, keyA)); err != nil {
			t.Fatal(err)
		}
		if _, key := keyAfterRestart(t, path); key != keyA {
			t.Errorf("a restart has key %q, want the one saved for its own server", key)
		}
	})
}

// A file that holds the credentials and cannot be read must stop the start, naming it.
// Starting without them would look like a sign-out, and the next write would make it one.
func TestAnUnreadableSecretsFileIsALoudError(t *testing.T) {
	_, path := storeWithEverySecret(t)
	secrets := secretstore.Path(path)
	if err := os.WriteFile(secrets, []byte("{this is not the file it was"), secretstore.FileMode); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("the store opened over an unreadable secrets.json")
	} else {
		if !strings.Contains(err.Error(), secrets) {
			t.Errorf("error %q does not name secrets.json", err)
		}
		var bad *UnusableError
		if errors.As(err, &bad) {
			t.Error("an unreadable secrets.json was treated as an unusable config, which moves the config aside")
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config.json is gone after the refused start: %v", err)
	}
	if _, err := Inspect(path); err == nil || !strings.Contains(err.Error(), secrets) {
		t.Errorf("config check over an unreadable secrets.json = %v, want an error naming it", err)
	}
}

// A credential still inline is one the document says outright, which only another build, a
// hand edit or a restored older copy puts there. It is the one that applies.
func TestASecretInTheConfigFileWinsOverTheSecretsFile(t *testing.T) {
	_, path := storeWithEverySecret(t)
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	primary, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatal(err)
	}
	primary.AuthKey = "tskey-auth-kINLINE-replacement"
	if err := os.WriteFile(path, inlineDocument(t, cfg), FileMode); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if got := heldSecrets(t, s.Get())["tailnet auth key"]; got != "tskey-auth-kINLINE-replacement" {
		t.Error("the auth key in secrets.json was used over the one config.json states")
	}
}

// A reset is a start from the defaults, so it starts without credentials -- and a default
// tailnet handed the old one's key would send it to Tailscale's control server whatever
// server it was for. The credentials go aside with the document they belonged to.
func TestAResetStartsWithoutTheOldSecretsAndARestoreBringsThemBack(t *testing.T) {
	_, path := storeWithEverySecret(t)

	moved, err := Reset(path)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	fresh, err := Open(path)
	if err != nil {
		t.Fatalf("opening the reset document: %v", err)
	}
	for label, value := range heldSecrets(t, fresh.Get()) {
		if value != "" {
			t.Errorf("the reset document carries the old %s", label)
		}
	}

	if _, _, err := Restore(path, moved.Path); err != nil {
		t.Fatalf("restoring the replaced document: %v", err)
	}
	restored, err := Open(path)
	if err != nil {
		t.Fatalf("opening the restored document: %v", err)
	}
	requireEverySecret(t, "the restored document", restored.Get())
}

// A credentials copy already sitting under the name a reset would pair with must not stop
// the reset halfway, with config.json moved aside and nothing put in its place.
func TestAResetIsNotStoppedHalfwayByACredentialsCopyUnderThePairedName(t *testing.T) {
	_, path := storeWithEverySecret(t)
	now := time.Now().UTC()
	for _, at := range []time.Time{now, now.Add(time.Second)} {
		squatter := secretstore.Path(path) + replacedSuffix + at.Format(quarantineStamp)
		if err := os.WriteFile(squatter, []byte("{}"), FileMode); err != nil {
			t.Fatal(err)
		}
	}

	moved, err := Reset(path)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no config.json after the reset: %v", err)
	}
	if _, _, err := Restore(path, moved.Path); err != nil {
		t.Fatalf("restoring the replaced document: %v", err)
	}
	restored, err := Open(path)
	if err != nil {
		t.Fatalf("opening the restored document: %v", err)
	}
	requireEverySecret(t, "the restored document", restored.Get())
}

// A document moved aside because this build could not use it takes its credentials with it,
// for the same reason as a reset: the defaults that replace it are not the connections they
// were for.
func TestAQuarantinedDocumentTakesItsSecretsAsideWithIt(t *testing.T) {
	_, path := storeWithEverySecret(t)
	if err := os.WriteFile(path, []byte("{not json"), FileMode); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening over an unusable document: %v", err)
	}
	for label, value := range heldSecrets(t, s.Get()) {
		if value != "" {
			t.Errorf("the replacement defaults carry the old %s", label)
		}
	}
	quarantined := s.Quarantined()
	if quarantined == nil {
		t.Fatal("the unusable document was not moved aside")
	}
	suffix := strings.TrimPrefix(quarantined.Path, path)
	beside := secretstore.Path(path) + suffix
	held, err := secretstore.Load(beside)
	if err != nil {
		t.Fatalf("the credentials were not set aside beside the document: %v", err)
	}
	if held["tunnels"][PrimaryTunnelID]["authKey"] != fixtureAuthKey {
		t.Error("the credentials set aside do not include the tailnet's auth key")
	}
}

// A secrets.json with no config.json beside it belongs to no document this run can name.
// Adopting it would hand the fresh defaults another document's keys.
func TestAFreshStartDoesNotAdoptASecretsFileLeftBehind(t *testing.T) {
	_, path := storeWithEverySecret(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	for label, value := range heldSecrets(t, s.Get()) {
		if value != "" {
			t.Errorf("the fresh document adopted the left-behind %s", label)
		}
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	keptAside := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), secretstore.FileName+replacedSuffix) {
			keptAside = true
		}
	}
	if !keptAside {
		t.Error("the left-behind secrets.json was not kept aside")
	}
}

// writeInlineCopy puts cfg beside the config at path under suffix, credentials inline, the
// way an older build kept its copies, and dates it at.
func writeInlineCopy(t *testing.T, path, suffix string, cfg *Config, at time.Time) string {
	t.Helper()
	saved := path + suffix
	if err := os.WriteFile(saved, inlineDocument(t, cfg), FileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(saved, at, at); err != nil {
		t.Fatal(err)
	}
	return saved
}

// requireRestoresEverySecret restores saved and fails for every fixture credential the
// restored document does not carry.
func requireRestoresEverySecret(t *testing.T, path, saved string) {
	t.Helper()
	if _, _, err := Restore(path, saved); err != nil {
		t.Fatalf("restoring %s: %v", filepath.Base(saved), err)
	}
	restored, err := Open(path)
	if err != nil {
		t.Fatalf("opening the restored document: %v", err)
	}
	requireEverySecret(t, "the restored "+filepath.Base(saved), restored.Get())
}

// A backup an older build wrote holds every credential in plain text. Its credentials are
// all in secrets.json already, so it loses them in place, keeps the moment it was saved --
// which is the order a restore picks the newest copy by -- and gains no second credentials
// file.
func TestAnOldBackupIsScrubbedInPlaceAndStillRestoresEverySecret(t *testing.T) {
	s, path := storeWithEverySecret(t)
	old := s.Get()
	old.Version = ConfigVersion - 1
	savedAt := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	backup := writeInlineCopy(t, path, backupSuffix(ConfigVersion-1), old, savedAt)

	unread, err := scrubSavedCopies(path)
	if err != nil {
		t.Fatalf("scrubSavedCopies: %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("copies reported unreadable: %v", unread)
	}
	requireNoSecretIn(t, "the old backup", readBytes(t, backup))
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(savedAt) {
		t.Errorf("the backup is dated %v after the scrub, want the %v it was saved at", info.ModTime(), savedAt)
	}
	if _, err := os.Stat(secretstore.Path(path) + backupSuffix(ConfigVersion-1)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a credentials file was written beside a backup whose credentials secrets.json holds: %v", err)
	}
	requireRestoresEverySecret(t, path, backup)
}

// A backup can hold a credential secrets.json has since lost -- a key removed after the
// backup was taken. Taking it out of the backup with nowhere else holding it would make the
// backup restore signed out, so it is kept in a credentials file paired with the backup.
func TestScrubbingABackupKeepsACredentialTheCurrentSecretsFileNoLongerHolds(t *testing.T) {
	s, path := storeWithEverySecret(t)
	old := s.Get()
	old.Version = ConfigVersion - 1
	backup := writeInlineCopy(t, path, backupSuffix(ConfigVersion-1), old, time.Now().Add(-time.Hour))
	if _, err := s.Update(func(c *Config) error {
		primary, err := c.PrimaryTailscale()
		if err != nil {
			return err
		}
		primary.AuthKey = ""
		return nil
	}); err != nil {
		t.Fatalf("removing the auth key: %v", err)
	}

	if _, err := scrubSavedCopies(path); err != nil {
		t.Fatalf("scrubSavedCopies: %v", err)
	}
	requireNoSecretIn(t, "the old backup", readBytes(t, backup))
	requireRestoresEverySecret(t, path, backup)
}

// A document set aside with its own credentials file restores with that file. A credential
// the document held inline and the file lacks moves into the file before it leaves the
// document.
func TestScrubbingASetAsideDocumentMovesItsInlineCredentialsIntoItsOwnSecretsFile(t *testing.T) {
	s, path := storeWithEverySecret(t)
	suffix := quarantineSuffix + "20250101-000000"
	saved := writeInlineCopy(t, path, suffix, s.Get(), time.Now().Add(-time.Hour))
	paired := collectSecrets(s.Get())
	delete(paired[secretsOfProxies], DefaultProxyID)
	if err := secretstore.Save(secretstore.Path(path)+suffix, paired); err != nil {
		t.Fatal(err)
	}

	if _, err := scrubSavedCopies(path); err != nil {
		t.Fatalf("scrubSavedCopies: %v", err)
	}
	requireNoSecretIn(t, "the set-aside document", readBytes(t, saved))
	requireRestoresEverySecret(t, path, saved)
}

// A copy that is not a config document cannot be told apart into credentials and settings,
// so it is left exactly as it is and named back to the caller rather than passed over.
func TestACopyThatIsNotJSONIsLeftAsItIsAndReported(t *testing.T) {
	_, path := storeWithEverySecret(t)
	broken := path + quarantineSuffix + "20250101-000000"
	body := []byte(`{"settings":{"hostname":"workstation"`)
	if err := os.WriteFile(broken, body, FileMode); err != nil {
		t.Fatal(err)
	}

	unread, err := scrubSavedCopies(path)
	if err != nil {
		t.Fatalf("scrubSavedCopies: %v", err)
	}
	if len(unread) != 1 || unread[0] != broken {
		t.Errorf("unreadable copies = %v, want [%s]", unread, broken)
	}
	if got := readBytes(t, broken); string(got) != string(body) {
		t.Errorf("the copy that could not be read was rewritten:\n%s", got)
	}
}

// A block of another type on a stored connection, from a hand edit or an older build, is
// dropped as the document loads rather than costing the user the whole document: the rest
// of it is their working setup, and the block is settings nothing reads. The key it held
// leaves config.json with it and is not carried into secrets.json either.
func TestAStrayBlockIsDroppedOnLoadAndItsKeyLeavesTheConfigFile(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].ID == fixtureOVPNID {
			stray := wireGuardFixture()
			cfg.Tunnels[i].WireGuard = &stray
		}
	}
	path := writeConfig(t, string(inlineDocument(t, cfg)))

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if moved := s.Quarantined(); moved != nil {
		t.Fatalf("the whole document was moved aside over the stray block: %s", moved.Reason)
	}
	if held, ok := s.Get().Tunnel(fixtureOVPNID); !ok || held.WireGuard != nil {
		t.Error("the OpenVPN connection still carries the WireGuard block after loading")
	}
	requireEverySecret(t, "the loaded document", s.Get())

	if _, err := s.Update(func(*Config) error { return nil }); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	requireNoSecretIn(t, "config.json", readBytes(t, path))
	held, err := secretstore.Load(secretstore.Path(path))
	if err != nil {
		t.Fatal(err)
	}
	for key := range held[secretsOfTunnels][fixtureOVPNID] {
		if strings.HasPrefix(key, "wg.") {
			t.Errorf("secrets.json holds %s for the OpenVPN connection", key)
		}
	}
}

// A stray block is the one credential carrier the secrets file comparison cannot see, so the
// start has to take it out of config.json on its own account.
func TestTheAgentStartTakesAStrayBlocksKeyOutOfTheConfigFile(t *testing.T) {
	_, path := storeWithEverySecret(t)
	var doc map[string]any
	if err := json.Unmarshal(readBytes(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	stray := wireGuardFixture()
	block, err := json.Marshal(stray)
	if err != nil {
		t.Fatal(err)
	}
	var strayBlock any
	if err := json.Unmarshal(block, &strayBlock); err != nil {
		t.Fatal(err)
	}
	placed := false
	for _, entry := range doc["tunnels"].([]any) {
		tunnel := entry.(map[string]any)
		if tunnel["id"] == fixtureOVPNID {
			tunnel["wireguard"] = strayBlock
			placed = true
		}
	}
	if !placed {
		t.Fatal("the fixture has no OpenVPN connection to put the stray block on")
	}
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, FileMode); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readBytes(t, path)), fixtureWGPrivateKey) {
		t.Fatal("the edited config.json does not carry the stray key, so this case proves nothing")
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	moved, err := s.MoveInlineCredentials()
	if err != nil {
		t.Fatalf("the start: %v", err)
	}
	if !moved {
		t.Error("the start reports nothing written while config.json carries a stray key")
	}
	requireNoSecretIn(t, "config.json after the start", readBytes(t, path))
}

// The start scrubs the copies an older build left beside the config with keys inline.
func TestTheAgentStartScrubsTheCopiesKeptBesideTheConfig(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.MachineID = "abcd1234"
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	s, path := storeWithEverySecret(t)
	backup := path + backupSuffix(6)
	if err := os.WriteFile(backup, inlineDocument(t, cfg), FileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScrubSavedCopies(); err != nil {
		t.Fatalf("scrubbing: %v", err)
	}
	requireNoSecretIn(t, "the old backup after the start", readBytes(t, backup))
}

// The scrub is driven by the registries, so a secret field the backup would keep has to be
// one whose stored key the registries do not name.
func TestScrubbingRemovesEverySecretFieldOfTheStoredShape(t *testing.T) {
	cfg := Defaults()
	if err := storeEverySecret(cfg); err != nil {
		t.Fatal(err)
	}
	scrubbed, err := scrubSecrets(inlineDocument(t, cfg))
	if err != nil {
		t.Fatalf("scrubSecrets: %v", err)
	}
	requireNoSecretIn(t, "the scrubbed document", scrubbed)
}

// A document with no credential in it is copied byte for byte.
func TestScrubbingADocumentWithNoSecretLeavesItAsItWas(t *testing.T) {
	body := []byte(`{"settings":{"hostname":"workstation"},"forwards":[]}`)
	scrubbed, err := scrubSecrets(body)
	if err != nil {
		t.Fatalf("scrubSecrets: %v", err)
	}
	if string(scrubbed) != string(body) {
		t.Errorf("a document with nothing to scrub was rewritten:\n%s", scrubbed)
	}
}
