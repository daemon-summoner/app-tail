// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/fileown/fileowntest"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, path
}

func TestOpenCreatesFirstRunConfig(t *testing.T) {
	s, path := newStore(t)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first run did not create %s: %v", path, err)
	}
	cfg := s.Get()
	if cfg.Settings.MachineID == "" {
		t.Error("first run did not generate a machine id")
	}
	if cfg.Settings.UIListen != DefaultUIListenAddr {
		t.Errorf("uiListenAddr = %q, want %q", cfg.Settings.UIListen, DefaultUIListenAddr)
	}
	if got := tailnetOf(t, cfg).HostnameTemplate; got != DefaultHostnameTemplate {
		t.Errorf("hostnameTemplate = %q, want %q", got, DefaultHostnameTemplate)
	}
	if len(cfg.Forwards) != 0 {
		t.Errorf("first run should have no forwards, got %d", len(cfg.Forwards))
	}
}

// The file holds auth keys and OAuth secrets, so anyone else who can read it has them.
// How a system spells "only the owner" differs, which is why the check is per platform.
func TestOpenWritesOwnerOnlyPermissions(t *testing.T) {
	_, path := newStore(t)
	fileowntest.AssertOwnerOnly(t, path, FileMode)
}

func TestOpenIsIdempotentAcrossRestarts(t *testing.T) {
	s, path := newStore(t)
	firstID := s.Get().Settings.MachineID

	if _, err := s.Update(func(c *Config) error {
		f := validForward()
		c.Forwards = append(c.Forwards, f)
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	cfg := reopened.Get()
	if cfg.Settings.MachineID != firstID {
		t.Errorf("machine id changed across restart: %q -> %q", firstID, cfg.Settings.MachineID)
	}
	if len(cfg.Forwards) != 1 || cfg.Forwards[0].Target != "buildbox:22" {
		t.Fatalf("forwards did not round-trip: %+v", cfg.Forwards)
	}
}

func TestUpdateRejectsInvalidChangeWithoutTouchingState(t *testing.T) {
	s, path := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		c.Forwards = append(c.Forwards, validForward())
		return nil
	}); err != nil {
		t.Fatalf("seed Update: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Update(func(c *Config) error {
		bad := validForward()
		bad.ID = "f_bad"
		bad.ListenPort = 99999
		c.Forwards = append(c.Forwards, bad)
		return nil
	})
	if err == nil {
		t.Fatal("Update accepted an invalid forward")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is %T (%v), want *ValidationError", err, err)
	}

	if got := s.Get(); len(got.Forwards) != 1 {
		t.Errorf("in-memory config changed after a rejected update: %d forwards", len(got.Forwards))
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("config file changed after a rejected update")
	}
}

func TestUpdateKeepsMemoryAndDiskInSyncWhenWriteFails(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		c.Forwards = append(c.Forwards, validForward())
		return nil
	}); err != nil {
		t.Fatalf("seed Update: %v", err)
	}

	// Redirect the store at a path that cannot be written: the parent is a regular file.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(blocker, ConfigFileName)

	_, err := s.Update(func(c *Config) error {
		c.Forwards[0].Target = "changed:1"
		return nil
	})
	if err == nil {
		t.Fatal("Update reported success even though the config could not be written")
	}
	// The change never reached disk, so it must not be visible in memory either;
	// otherwise the running process diverges from what a restart would load.
	if got := s.Get().Forwards[0].Target; got != "buildbox:22" {
		t.Errorf("target = %q; an unpersisted change became visible in memory", got)
	}
}

func TestUpdatePropagatesMutatorError(t *testing.T) {
	s, _ := newStore(t)
	sentinel := errors.New("mutator said no")
	if _, err := s.Update(func(*Config) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Update swallowed the mutator error: got %v", err)
	}
	if len(s.Get().Forwards) != 0 {
		t.Error("failed mutation left changes behind")
	}
}

func TestUpdateLeavesNoTemporaryFiles(t *testing.T) {
	s, path := newStore(t)
	for i := 0; i < 5; i++ {
		if _, err := s.Update(func(c *Config) error {
			c.Settings.UDPSessionTimeoutSec = 30 + i
			return nil
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Errorf("atomic write left a temp file behind: %s", e.Name())
		}
	}
}

func TestGetReturnsAnIsolatedSnapshot(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		c.Forwards = append(c.Forwards, validForward())
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	snapshot := s.Get()
	snapshot.Forwards[0].Target = "hijacked:1"
	snapshot.Tunnels[0].Tailscale.Tags[0] = "tag:hijacked"

	fresh := s.Get()
	if fresh.Forwards[0].Target != "buildbox:22" {
		t.Error("mutating a snapshot corrupted the store's forwards")
	}
	// The connection's tailnet block is behind a pointer, so a snapshot that copied the
	// pointer would hand every holder a way to edit the stored document.
	if fresh.Tunnels[0].Tailscale.Tags[0] != DefaultTag {
		t.Error("mutating a snapshot corrupted the store's tags")
	}
}

func TestSettingsSnapshotIsIsolated(t *testing.T) {
	s, _ := newStore(t)
	got := s.Settings()
	got.AutoMapPorts = append(got.AutoMapPorts, "9999")
	got.SystemDNSLocalSuffixes = append(got.SystemDNSLocalSuffixes, "hijacked")
	if len(s.Settings().AutoMapPorts) != len(Defaults().Settings.AutoMapPorts) {
		t.Error("appending to a settings snapshot corrupted the store")
	}
}

// A damaged config must never be silently replaced: the store carries what happened so
// every surface can say it, and the document itself is still on disk to be repaired.
func TestOpenMovesACorruptConfigAsideAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte("{not json"), FileMode); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	note := store.Quarantined()
	if note == nil {
		t.Fatal("a corrupt config was replaced with no record that it happened")
	}
	if !strings.Contains(note.Reason, "JSON") {
		t.Errorf("reason = %q, want it to say the document could not be read as JSON", note.Reason)
	}
	kept, err := os.ReadFile(note.Path)
	if err != nil {
		t.Fatalf("read the document that was moved aside: %v", err)
	}
	if string(kept) != "{not json" {
		t.Errorf("the document was changed on the way aside: %q", kept)
	}
}

// A document that binds the dashboard where anyone on the network reaches it is refused
// the same way, and the refusal names the field so the user knows what to edit.
func TestOpenMovesAnInvalidConfigAsideNamingTheField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	doc := `{"settings":{"uiListenAddr":"0.0.0.0:8377"},"forwards":[]}`
	if err := os.WriteFile(path, []byte(doc), FileMode); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	note := store.Quarantined()
	if note == nil {
		t.Fatal("an invalid config was replaced with no record that it happened")
	}
	if !strings.Contains(note.Reason, "uiListenAddr") {
		t.Errorf("reason = %q, want it to name the field that has to be fixed", note.Reason)
	}
	if got := store.Settings().UIListen; got != Defaults().Settings.UIListen {
		t.Errorf("dashboard address = %q, want the default the app started on", got)
	}
}

func TestOpenBackfillsDefaultsForPartialConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	doc := `{"settings":{},"forwards":[{"id":"f_x","direction":"to_local","protocol":"tcp","listenPort":9000,"target":"box:80","enabled":true}]}`
	if err := os.WriteFile(path, []byte(doc), FileMode); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	cfg := s.Get()
	if cfg.Settings.UDPBufferBytes != DefaultUDPBufferBytes {
		t.Errorf("udpBufferBytes = %d, want default %d", cfg.Settings.UDPBufferBytes, DefaultUDPBufferBytes)
	}
	if cfg.Settings.MachineID == "" {
		t.Error("machine id was not backfilled")
	}
	if cfg.Forwards[0].BindAddr != DefaultBindAddr {
		t.Errorf("bindAddr = %q, want default %q", cfg.Forwards[0].BindAddr, DefaultBindAddr)
	}
}

func TestEnabledForwards(t *testing.T) {
	on := validForward()
	on.ID = "f_on"
	off := validForward()
	off.ID = "f_off"
	off.Enabled = false
	cfg := &Config{Forwards: []Forward{on, off}}
	got := cfg.EnabledForwards()
	if len(got) != 1 || got[0].ID != "f_on" {
		t.Fatalf("EnabledForwards = %+v, want only f_on", got)
	}
}

func TestFindForward(t *testing.T) {
	cfg := &Config{Forwards: []Forward{validForward()}}
	if _, ok := cfg.FindForward("f_aaaaaa"); !ok {
		t.Error("FindForward missed an existing forward")
	}
	if _, ok := cfg.FindForward("f_nope"); ok {
		t.Error("FindForward reported a nonexistent forward as found")
	}
}

// A stored auth key or OAuth secret is sent to whatever control server the connection
// names on its next start. Pointing the connection at another server without entering the
// credential again would hand the old tailnet's key to that server.
func TestChangingTheControlServerDropsTheStoredCredential(t *testing.T) {
	s, _ := newStore(t)
	secretFile := filepath.Join(t.TempDir(), "oauth")
	if _, err := s.Update(func(c *Config) error {
		held := primaryTailnet(t, c)
		held.AuthKey = "tskey-auth-kOLD-secret"
		held.OAuthClientSecret = "tskey-client-kOLD-secret"
		held.OAuthClientSecretFile = secretFile
		return nil
	}); err != nil {
		t.Fatalf("store credentials: %v", err)
	}

	_, report, err := s.UpdateReporting(func(c *Config) error {
		primaryTailnet(t, c).ControlURL = "https://control.example.net"
		return nil
	})
	if err != nil {
		t.Fatalf("change control server: %v", err)
	}

	held := tailnetOf(t, s.Get())
	if held.AuthKey != "" || held.OAuthClientSecret != "" || held.OAuthClientSecretFile != "" {
		t.Errorf("credentials survived the control server change: authKey=%q oauthClientSecret=%q oauthClientSecretFile=%q",
			held.AuthKey, held.OAuthClientSecret, held.OAuthClientSecretFile)
	}
	if len(report.ClearedCredentials) != 1 {
		t.Fatalf("report names %d cleared credentials, want 1: %+v", len(report.ClearedCredentials), report)
	}
	cleared := report.ClearedCredentials[0]
	if cleared.TunnelID != PrimaryTunnelID {
		t.Errorf("cleared credential names connection %q, want %q", cleared.TunnelID, PrimaryTunnelID)
	}
	want := "the credential was cleared because the control server changed; enter it again for https://control.example.net"
	if got := cleared.Notice(); got != want {
		t.Errorf("notice = %q, want %q", got, want)
	}
	reread, err := Open(s.Path())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := tailnetOf(t, reread.Get()).AuthKey; got != "" {
		t.Errorf("the file still holds the auth key %q after the clear", got)
	}
}

// The same server written another way is not a move, so its key stays. A different path on
// the same host can be a different tailnet and still counts as one.
func TestTheSameControlServerWrittenDifferentlyKeepsItsCredential(t *testing.T) {
	for _, tc := range []struct {
		to   string
		kept bool
	}{
		{"https://Control.Example.net:443/", true},
		{"https://control.example.net/other-tailnet", false},
		{"https://control.example.net:8443", false},
	} {
		t.Run(tc.to, func(t *testing.T) {
			s, _ := newStore(t)
			if _, err := s.Update(func(c *Config) error {
				held := primaryTailnet(t, c)
				held.ControlURL = "https://control.example.net"
				held.AuthKey = "tskey-auth-kSAME-server"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Update(func(c *Config) error {
				primaryTailnet(t, c).ControlURL = tc.to
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			reread, err := Open(s.Path())
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			if kept := tailnetOf(t, reread.Get()).AuthKey != ""; kept != tc.kept {
				t.Errorf("auth key kept = %v after writing the server as %q, want %v", kept, tc.to, tc.kept)
			}
		})
	}
}

// Someone moving to a new control server and entering that server's key in the same
// write has done exactly what the clear asks for, so their new key stays.
func TestChangingTheControlServerTogetherWithTheCredentialKeepsTheNewCredential(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		primaryTailnet(t, c).AuthKey = "tskey-auth-kOLD-secret"
		return nil
	}); err != nil {
		t.Fatalf("store credential: %v", err)
	}

	_, report, err := s.UpdateReporting(func(c *Config) error {
		held := primaryTailnet(t, c)
		held.ControlURL = "https://control.example.net"
		held.AuthKey = "tskey-auth-kNEW-secret"
		return nil
	})
	if err != nil {
		t.Fatalf("change control server and key: %v", err)
	}
	if got := tailnetOf(t, s.Get()).AuthKey; got != "tskey-auth-kNEW-secret" {
		t.Errorf("authKey = %q, want the key entered with the new server", got)
	}
	if len(report.ClearedCredentials) != 0 {
		t.Errorf("report names cleared credentials when nothing was cleared: %+v", report)
	}
}

// Entering the key already stored, in the same write that moves the connection, is the
// person handing that key to the new server; the value matching what was there before does
// not make it a leftover.
func TestReenteringTheSameCredentialWithTheNewControlServerKeepsIt(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		primaryTailnet(t, c).AuthKey = "tskey-auth-kSAME-secret"
		return nil
	}); err != nil {
		t.Fatalf("store credential: %v", err)
	}

	patch := map[string]json.RawMessage{
		"controlURL": json.RawMessage(`"https://control.example.net"`),
		"authKey":    json.RawMessage(`"tskey-auth-kSAME-secret"`),
	}
	_, report, err := s.UpdateReporting(func(c *Config) error {
		held := primaryTailnet(t, c)
		held.ControlURL = "https://control.example.net"
		held.AuthKey = "tskey-auth-kSAME-secret"
		return nil
	}, CredentialWritesIn(PrimaryTunnelID, patch)...)
	if err != nil {
		t.Fatalf("change control server and re-enter key: %v", err)
	}
	if got := tailnetOf(t, s.Get()).AuthKey; got != "tskey-auth-kSAME-secret" {
		t.Errorf("authKey = %q, want the key re-entered with the new server", got)
	}
	if len(report.ClearedCredentials) != 0 {
		t.Errorf("report names cleared credentials when the key was re-entered: %+v", report)
	}
}

// A client saving the form it was served sends RedactedSecret back for a stored
// secret. That keeps the stored value, which is not the person entering it for the new
// control server, so the old server's key must not follow the connection there.
func TestTheRedactedValueDoesNotCarryAKeyToANewControlServer(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		held := primaryTailnet(t, c)
		held.AuthKey = "tskey-auth-kOLD-secret"
		held.OAuthClientSecret = "tskey-client-kOLD-secret"
		return nil
	}); err != nil {
		t.Fatalf("store credentials: %v", err)
	}

	patch := map[string]json.RawMessage{
		"controlURL":        json.RawMessage(`"https://control.example.net"`),
		"authKey":           json.RawMessage(`"` + RedactedSecret + `"`),
		"oauthClientSecret": json.RawMessage(`"` + RedactedSecret + `"`),
	}
	if got := CredentialWritesIn(PrimaryTunnelID, patch); len(got) != 0 {
		t.Errorf("CredentialWritesIn = %+v, want RedactedSecret not counted as entered", got)
	}
	_, report, err := s.UpdateReporting(func(c *Config) error {
		primaryTailnet(t, c).ControlURL = "https://control.example.net"
		return nil
	}, CredentialWritesIn(PrimaryTunnelID, patch)...)
	if err != nil {
		t.Fatalf("change control server: %v", err)
	}
	held := tailnetOf(t, s.Get())
	if held.AuthKey != "" || held.OAuthClientSecret != "" {
		t.Errorf("credentials = %q, %q followed the connection to the new control server", held.AuthKey, held.OAuthClientSecret)
	}
	if len(report.ClearedCredentials) == 0 {
		t.Error("the report does not say the credentials were cleared")
	}
}

// Only the credential the write names is kept; another one left over from the old server
// is still dropped.
func TestReenteringOneCredentialStillDropsTheOthers(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		held := primaryTailnet(t, c)
		held.AuthKey = "tskey-auth-kSAME-secret"
		held.OAuthClientSecret = "tskey-client-kOLD-secret"
		return nil
	}); err != nil {
		t.Fatalf("store credentials: %v", err)
	}

	patch := map[string]json.RawMessage{
		"controlURL": json.RawMessage(`"https://control.example.net"`),
		"authKey":    json.RawMessage(`"tskey-auth-kSAME-secret"`),
	}
	_, report, err := s.UpdateReporting(func(c *Config) error {
		primaryTailnet(t, c).ControlURL = "https://control.example.net"
		return nil
	}, CredentialWritesIn(PrimaryTunnelID, patch)...)
	if err != nil {
		t.Fatalf("change control server: %v", err)
	}
	held := tailnetOf(t, s.Get())
	if held.AuthKey != "tskey-auth-kSAME-secret" {
		t.Errorf("authKey = %q, want the re-entered key kept", held.AuthKey)
	}
	if held.OAuthClientSecret != "" {
		t.Errorf("oauthClientSecret = %q survived the control server change without being re-entered", held.OAuthClientSecret)
	}
	if len(report.ClearedCredentials) != 1 {
		t.Errorf("report names %d cleared credentials, want 1: %+v", len(report.ClearedCredentials), report)
	}
}

func TestAnUnchangedControlServerKeepsTheStoredCredential(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		held := primaryTailnet(t, c)
		held.ControlURL = "https://control.example.net"
		held.AuthKey = "tskey-auth-kOLD-secret"
		return nil
	}); err != nil {
		t.Fatalf("store credential: %v", err)
	}

	_, report, err := s.UpdateReporting(func(c *Config) error {
		primaryTailnet(t, c).Hostname = "renamed"
		return nil
	})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := tailnetOf(t, s.Get()).AuthKey; got != "tskey-auth-kOLD-secret" {
		t.Errorf("authKey = %q after an edit that left the control server alone", got)
	}
	if len(report.ClearedCredentials) != 0 {
		t.Errorf("report names cleared credentials: %+v", report)
	}
}

// Writing out Tailscale's own server in place of the empty value that already meant it
// points nothing anywhere new, so it is not a change of server.
func TestSpellingOutTailscalesOwnServerKeepsTheStoredCredential(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update(func(c *Config) error {
		primaryTailnet(t, c).AuthKey = "tskey-auth-kOLD-secret"
		return nil
	}); err != nil {
		t.Fatalf("store credential: %v", err)
	}
	if _, err := s.Update(func(c *Config) error {
		primaryTailnet(t, c).ControlURL = TailscaleControlURL
		return nil
	}); err != nil {
		t.Fatalf("spell out the default server: %v", err)
	}
	if got := tailnetOf(t, s.Get()).AuthKey; got != "tskey-auth-kOLD-secret" {
		t.Errorf("authKey = %q after naming the server it already used", got)
	}
}

func primaryTailnet(t *testing.T, c *Config) *TailscaleTunnel {
	t.Helper()
	held, err := c.PrimaryTailscale()
	if err != nil {
		t.Fatalf("primary tailnet: %v", err)
	}
	return held
}

// A forward stored before exposeToNetwork existed, already listening on the network, was
// exposed on purpose by whoever set it up. Loading it must carry on doing so rather than
// refuse the whole document.
func TestAForwardAlreadyOnTheNetworkKeepsWorkingAfterTheUpgrade(t *testing.T) {
	_, path := newStore(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	lan := map[string]any{
		"id": "f_lan000", "name": "LAN", "direction": "to_local", "protocol": "tcp",
		"bindAddr": "0.0.0.0", "listenPort": 2222, "target": "buildbox:22", "enabled": true,
	}
	local := map[string]any{
		"id": "f_loc000", "name": "Local", "direction": "to_local", "protocol": "tcp",
		"bindAddr": "127.0.0.1", "listenPort": 2223, "target": "buildbox:22", "enabled": true,
	}
	doc["forwards"] = []any{lan, local}
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, FileMode); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if q := reopened.Quarantined(); q != nil {
		t.Fatalf("the document was moved aside instead of upgraded: %+v", q)
	}
	got, ok := reopened.Get().FindForward("f_lan000")
	if !ok || !got.ExposeToNetwork {
		t.Errorf("forward on 0.0.0.0 = %+v, want exposeToNetwork set on load", got)
	}
	got, ok = reopened.Get().FindForward("f_loc000")
	if !ok || got.ExposeToNetwork {
		t.Errorf("loopback forward = %+v, want exposeToNetwork left off", got)
	}

	// Once the document carries the field, it is the user's answer: a forward they turned
	// it off on is not switched back on by the next load.
	if _, err := reopened.Update(func(c *Config) error {
		for i := range c.Forwards {
			if c.Forwards[i].ID == "f_lan000" {
				c.Forwards[i].BindAddr = "127.0.0.1"
				c.Forwards[i].ExposeToNetwork = false
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("narrow the forward: %v", err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after narrowing: %v", err)
	}
	if got, _ := again.Get().FindForward("f_lan000"); got.ExposeToNetwork {
		t.Error("exposeToNetwork came back on after the user turned it off")
	}
}
