// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeConfig puts a document on disk exactly as given, so a test can hand Open the
// shape an older version wrote rather than one this build produced.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte(body), FileMode); err != nil {
		t.Fatalf("writing the config: %v", err)
	}
	return path
}

// The upgrade every existing install takes. Before this version there was no way to name
// the tailnet, so a document that names none is one that predates connections being data
// -- and the tailnet it describes has to survive the upgrade under a name.
func TestAnOlderDocumentGainsTheConnectionItAlwaysHad(t *testing.T) {
	path := writeConfig(t, `{"settings":{"hostname":"workstation"},"forwards":[]}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a pre-connection config: %v", err)
	}

	cfg := store.Get()
	if cfg.Version != ConfigVersion {
		t.Errorf("version = %d, want %d", cfg.Version, ConfigVersion)
	}
	primary, ok := cfg.Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatalf("no primary connection after migrating; got %+v", cfg.Tunnels)
	}
	if primary.Type != TunnelTailscale {
		t.Errorf("primary type = %q, want %q", primary.Type, TunnelTailscale)
	}
	if primary.Slug != PrimaryTunnelSlug {
		t.Errorf("primary slug = %q, want %q", primary.Slug, PrimaryTunnelSlug)
	}
	// Before this version the tailnet could not be switched off, so every existing
	// install has one that is meant to be up. Migrating it to disabled would present the
	// upgrade as a disconnection.
	if !primary.Enabled {
		t.Error("the migrated connection is disabled, so upgrading would take the tailnet down")
	}
	// The settings the old document carried are the ones that describe it; a migration
	// that reset them would move the node.
	if got := primary.TS().Hostname; got != "workstation" {
		t.Errorf("hostname = %q, want the stored value carried through", got)
	}
}

// Loading is not editing. A run that only reads -- a version query, a status check --
// must leave the file byte-for-byte as it found it, or every such run would rewrite a
// document the user did not ask to change.
func TestMigratingDoesNotRewriteTheFileUntilSomethingIsWritten(t *testing.T) {
	body := `{"settings":{"hostname":"workstation"},"forwards":[]}`
	path := writeConfig(t, body)

	if _, err := Open(path); err != nil {
		t.Fatalf("opening: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(after) != body {
		t.Errorf("the file was rewritten on load:\n%s", after)
	}
	if _, err := os.Stat(path + backupSuffix(1)); !os.IsNotExist(err) {
		t.Error("a backup was taken for a load that changed nothing")
	}
}

// The copy is what makes the migration reversible. Taking it at the moment the old shape
// is about to be replaced is the only point at which it is both needed and still there.
func TestTheOriginalIsKeptBesideTheFirstMigratedWrite(t *testing.T) {
	body := `{"settings":{"hostname":"workstation"},"forwards":[]}`
	path := writeConfig(t, body)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if _, err := store.Update(func(c *Config) error {
		return renameTailnet(c, "laptop")
	}); err != nil {
		t.Fatalf("writing: %v", err)
	}

	backup, err := os.ReadFile(path + backupSuffix(1))
	if err != nil {
		t.Fatalf("reading the backup: %v", err)
	}
	if string(backup) != body {
		t.Errorf("the backup holds a migrated document rather than the original:\n%s", backup)
	}
	// And the live file is the new shape, or the backup would be a copy of the thing
	// still in place rather than of what was replaced.
	current, _, err := readFile(path)
	if err != nil {
		t.Fatalf("reading the config back: %v", err)
	}
	if current.Version != ConfigVersion || len(current.Tunnels) != 1 {
		t.Errorf("the written document is version %d with %d connections, want %d with 1",
			current.Version, len(current.Tunnels), ConfigVersion)
	}
}

// A second migration must not overwrite the copy of the shape someone may still need to
// go back to. Keeping the first is the whole point of naming the file after the version
// it holds.
func TestAnExistingBackupIsNotReplaced(t *testing.T) {
	path := writeConfig(t, `{"settings":{},"forwards":[]}`)
	backup := path + backupSuffix(1)
	if err := os.WriteFile(backup, []byte("the original"), FileMode); err != nil {
		t.Fatalf("seeding the backup: %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if _, err := store.Update(func(*Config) error { return nil }); err != nil {
		t.Fatalf("writing: %v", err)
	}

	held, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("reading the backup: %v", err)
	}
	if string(held) != "the original" {
		t.Errorf("backup = %q, want the earlier copy left alone", held)
	}
}

// A document already at this version is not a document to migrate. Re-running the
// migration would be harmless today and is exactly the thing that stops being harmless
// once a migration does more than add a default.
func TestACurrentDocumentIsLeftAlone(t *testing.T) {
	body, err := json.Marshal(Config{
		Version:  ConfigVersion,
		Tunnels:  []Tunnel{{ID: "tn_abc123", Slug: "office", Name: "Office", Type: TunnelWireGuard, Enabled: true}},
		Settings: Defaults().Settings,
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	path := writeConfig(t, string(body))

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}

	cfg := store.Get()
	if len(cfg.Tunnels) != 1 || cfg.Tunnels[0].ID != "tn_abc123" {
		t.Errorf("connections = %+v, want the stored one untouched and no primary added", cfg.Tunnels)
	}
}

// Back-filling the primary on every load would mean a connection the user removed comes
// back on the next write, which is the one failure mode a deletion must not have.
func TestARemovedConnectionStaysRemoved(t *testing.T) {
	body, err := json.Marshal(Config{Version: ConfigVersion, Settings: Defaults().Settings})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	path := writeConfig(t, string(body))

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	cfg, err := store.Update(func(c *Config) error {
		c.Settings.UIListen = "127.0.0.1:9123"
		return nil
	})
	if err != nil {
		t.Fatalf("writing: %v", err)
	}

	if len(cfg.Tunnels) != 0 {
		t.Errorf("connections = %+v, want none re-added", cfg.Tunnels)
	}
}

// Every stored forward crossed the one tailnet there was, so the upgrade has to say so.
// A forward left naming no connection would be one the manager could not resolve a
// network for, which stops it -- the upgrade would read as every forward going down.
func TestAnOlderDocumentsForwardsNameTheConnectionTheyCrossed(t *testing.T) {
	cfg := &Config{Forwards: []Forward{{ID: "fw_1", Name: "db", ListenPort: 15432, Target: "db:5432"}}}

	if _, err := migrate(cfg, []byte(`{}`)); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	if got := cfg.Forwards[0].TunnelID; got != PrimaryTunnelID {
		t.Errorf("forward connection = %q, want %q", got, PrimaryTunnelID)
	}
}

// The one migration that is not merely a default. An assignment's key is what holds a
// local port still across runs, and a device id is only unique inside the network that
// issued it -- so an unprefixed key would be claimed by whichever network reported a
// device with that id next, moving a bookmarked port onto a different machine.
func TestAnOlderDocumentsPortAssignmentsNameTheirConnection(t *testing.T) {
	cfg := &Config{AutoMap: map[string]int{
		"nA/22": 14000,
		"nA/80": 14001,
	}}

	if _, err := migrate(cfg, []byte(`{}`)); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	want := map[string]int{
		PrimaryTunnelID + "/nA/22": 14000,
		PrimaryTunnelID + "/nA/80": 14001,
	}
	for key, port := range want {
		if cfg.AutoMap[key] != port {
			t.Errorf("assignment %q = %d, want %d; a bookmarked port moved", key, cfg.AutoMap[key], port)
		}
	}
	if len(cfg.AutoMap) != len(want) {
		t.Errorf("assignments = %v, want exactly the rewritten pair", cfg.AutoMap)
	}
}

// A newer build's document loaded by an older one and written back arrives here with keys
// that already name a connection. Prefixing those again would orphan the assignment, which
// is the same moved-port failure the rewrite exists to prevent.
func TestAPortAssignmentThatAlreadyNamesAConnectionIsLeftAlone(t *testing.T) {
	cfg := &Config{AutoMap: map[string]int{
		"tn_office/nA/22": 14000,
		"nA/22":           14001,
	}}

	if _, err := migrate(cfg, []byte(`{}`)); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	if cfg.AutoMap["tn_office/nA/22"] != 14000 {
		t.Errorf("an already-owned assignment was rewritten: %v", cfg.AutoMap)
	}
	if cfg.AutoMap[PrimaryTunnelID+"/nA/22"] != 14001 {
		t.Errorf("the unowned assignment was not given an owner: %v", cfg.AutoMap)
	}
}

// A forward naming a connection that is not in the document is one nothing can carry, and
// it would sit in the dashboard reporting stopped with no reason a user could act on.
// Refusing at load is what turns that into a message naming the forward.
func TestAForwardNamingAConnectionThatIsNotThereIsRefused(t *testing.T) {
	cfg := Defaults()
	cfg.Forwards = []Forward{{
		ID: "fw_1", Name: "db", TunnelID: "tn_gone",
		Direction: ToLocal, Protocol: TCP, BindAddr: DefaultBindAddr,
		ListenPort: 15432, Target: "db:5432", Enabled: true,
	}}

	err := cfg.Validate()

	if err == nil || !strings.Contains(err.Error(), "tn_gone") {
		t.Errorf("error = %v, want a refusal naming the missing connection", err)
	}
}

func TestTwoConnectionsCannotShareAnID(t *testing.T) {
	err := validateTunnels(&Settings{}, []Tunnel{
		{ID: "tn_a", Slug: "one", Name: "One", Type: TunnelTailscale},
		{ID: "tn_a", Slug: "two", Name: "Two", Type: TunnelWireGuard},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("error = %v, want a refusal naming the duplicate id", err)
	}
}

// Two connections under one slug means two networks answer for one name suffix, and the
// resolver has no way to say which one a lookup meant.
func TestTwoConnectionsCannotShareASlug(t *testing.T) {
	err := validateTunnels(&Settings{}, []Tunnel{
		{ID: "tn_a", Slug: "office", Name: "Office", Type: TunnelTailscale},
		{ID: "tn_b", Slug: "office", Name: "Office", Type: TunnelWireGuard},
	})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("error = %v, want a refusal naming the collision", err)
	}
}

// The slug becomes a label in every name this connection answers for, so one that is
// only valid here would produce names nothing can look up.
func TestASlugThatCannotBeADNSLabelIsRefused(t *testing.T) {
	for _, bad := range []string{"", "Office", "of fice", "-office", "office-", "of.fice", strings.Repeat("a", MaxSlugLen+1)} {
		err := validateTunnels(&Settings{}, []Tunnel{{ID: "tn_a", Slug: bad, Name: "Office", Type: TunnelTailscale}})
		if err == nil {
			t.Errorf("slug %q was accepted", bad)
		}
	}
	if err := validateTunnels(&Settings{}, []Tunnel{{ID: "tn_a", Slug: "office-2", Name: "Office", Type: TunnelTailscale}}); err != nil {
		t.Errorf("a valid slug was refused: %v", err)
	}
}

// A type this build cannot connect must be refused at load rather than started as
// something else, which is what would happen if the runtime fell back to a default kind.
func TestAnUnknownConnectionTypeIsRefused(t *testing.T) {
	err := validateTunnels(&Settings{}, []Tunnel{{ID: "tn_a", Slug: "office", Name: "Office", Type: TunnelType("ipsec")}})
	if err == nil || !strings.Contains(err.Error(), "ipsec") {
		t.Errorf("error = %v, want a refusal naming the unknown type", err)
	}
}

// A fresh install has never been migrated, but it still has to describe the tailnet its
// settings configure.
func TestAFreshInstallStartsWithThePrimaryConnection(t *testing.T) {
	cfg := Defaults()

	if cfg.Version != ConfigVersion {
		t.Errorf("version = %d, want %d", cfg.Version, ConfigVersion)
	}
	if _, ok := cfg.Tunnel(PrimaryTunnelID); !ok {
		t.Errorf("connections = %+v, want the primary one", cfg.Tunnels)
	}
	if _, ok := cfg.TunnelBySlug(PrimaryTunnelSlug); !ok {
		t.Errorf("no connection answers to %q", PrimaryTunnelSlug)
	}
}

// A snapshot that shared the connection slice would let a caller editing one edit every
// other holder's copy, which is the same hazard the rest of Clone already guards.
func TestASnapshotOwnsItsConnectionList(t *testing.T) {
	cfg := Defaults()

	clone := cfg.Clone()
	clone.Tunnels[0].Slug = "elsewhere"

	if cfg.Tunnels[0].Slug != PrimaryTunnelSlug {
		t.Errorf("the original now reads %q; a snapshot shares its storage", cfg.Tunnels[0].Slug)
	}
}

// The upgrade that put the node preferences on the connection whose node holds them. An
// install that was accepting subnet routes and using an exit node has to still be doing
// both after the upgrade: these are the settings that decide where this machine's traffic
// goes, and losing them silently reroutes it.
func TestAnOlderDocumentsNodePreferencesMoveOntoItsConnection(t *testing.T) {
	path := writeConfig(t, `{
		"version": 4,
		"settings": {
			"routes.enabled": true,
			"routes.accept": true,
			"routes.serve": true,
			"routes.advertise": ["10.0.0.0/24"],
			"exitNode.enabled": true,
			"exitNode.nodeId": "nABC",
			"exitNode.allowLanAccess": true,
			"exitNode.onFailure": "next",
			"dns.enabled": true,
			"dns.useTailnet": true,
			"security.enabled": true,
			"security.shieldsUp": true
		},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a pre-preferences config: %v", err)
	}

	cfg := store.Get()
	primary, ok := cfg.Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatalf("no primary connection after migrating; got %+v", cfg.Tunnels)
	}
	ts := primary.TS()
	if !ts.RoutesAccept || !ts.RoutesServe {
		t.Errorf("accept=%v serve=%v, want both carried onto the connection",
			ts.RoutesAccept, ts.RoutesServe)
	}
	if len(ts.RoutesAdvertise) != 1 || ts.RoutesAdvertise[0].String() != "10.0.0.0/24" {
		t.Errorf("advertised routes = %v, want the stored network carried through", ts.RoutesAdvertise)
	}
	if ts.ExitNodeID != "nABC" || !ts.ExitNodeAllowLANAccess || ts.ExitNodeOnFailure != FailureNext {
		t.Errorf("exit node = %+v, want the stored choice carried through", ts.TailnetPrefs)
	}
	if !ts.DNSUseTailnet || !ts.ShieldsUp {
		t.Errorf("dns=%v shields=%v, want both carried onto the connection", ts.DNSUseTailnet, ts.ShieldsUp)
	}
	// The modules stay on the settings document: a switch says how much of the app is on
	// screen, which is a statement about the installation rather than about one network.
	if !cfg.Settings.RoutesEnabled || !cfg.Settings.ExitNodeEnabled ||
		!cfg.Settings.DNSEnabled || !cfg.Settings.SecurityEnabled {
		t.Errorf("a module switch moved off the settings document: %+v", cfg.Settings)
	}
}

// Adoption is a fact about one node: it records that this install already read what that
// node was doing. Left on the document, the second connection would find the flag set by
// the first and skip its own adoption, turning off whatever its node was configured with.
func TestTheRecordOfAdoptionMovesOntoTheConnectionItWasAbout(t *testing.T) {
	path := writeConfig(t, `{
		"version": 4,
		"prefsAdopted": true,
		"settings": {"routes.enabled": true, "routes.accept": true},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config that had adopted its node's preferences: %v", err)
	}

	primary, ok := store.Get().Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatal("no primary connection after migrating")
	}
	if !primary.PrefsAdopted {
		t.Error("the connection reads as never having been asked what its node was doing, so " +
			"the next reconcile would turn off what the node already had")
	}
}

// A preference the old document never carried must stay at its default rather than being
// written as a stored false: the two are the same on the wire and opposite in meaning, and
// a stored false is what adoption refuses to take from a node.
func TestAPreferenceAnOlderDocumentNeverCarriedIsLeftAtItsDefault(t *testing.T) {
	path := writeConfig(t, `{
		"version": 4,
		"settings": {},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation","exitNode.onFailure":"next"}}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config carrying no preferences: %v", err)
	}

	primary, _ := store.Get().Tunnel(PrimaryTunnelID)
	if got := primary.TS().ExitNodeOnFailure; got != FailureNext {
		t.Errorf("exitNode.onFailure = %q, want the connection's own %q left alone", got, FailureNext)
	}
}

// The upgrade that turns the one proxy into an instance. Its address, its credential and the
// reach its scope described all have to survive, or an install that upgrades finds the
// program pointed at it either unable to connect or reaching more than it was granted.
func TestTheOneProxyBecomesAnInstanceCarryingWhatItHad(t *testing.T) {
	path := writeConfig(t, `{
		"version": 5,
		"settings": {
			"proxy.enabled": true,
			"proxy.listenAddr": "127.0.0.1:1099",
			"proxy.scope": "tailnet",
			"proxy.resolveVia": "tailnet",
			"proxy.requireToken": true,
			"proxy.token": "hunter2",
			"proxy.dialTimeoutSec": 45
		},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config that predates proxy instances: %v", err)
	}

	cfg := store.Get()
	held, ok := cfg.Proxy(DefaultProxyID)
	if !ok {
		t.Fatalf("no default instance after migrating; got %+v", cfg.Proxies)
	}
	if held.ListenAddr != "127.0.0.1:1099" {
		t.Errorf("listenAddr = %q, want the address programs are already pointed at", held.ListenAddr)
	}
	if held.ResolveVia != ResolveViaTailnet {
		t.Errorf("resolveVia = %q, want the stored resolver carried through", held.ResolveVia)
	}
	if !held.RequireToken || held.Token != "hunter2" {
		t.Errorf("instance = %+v, want the credential carried through", held)
	}
	if held.DialTimeoutSec != 45 {
		t.Errorf("dialTimeoutSec = %d, want the stored timeout carried through", held.DialTimeoutSec)
	}
	// The module switch is not a fact about one listener, so it stays where it was.
	if !cfg.Settings.ProxyEnabled {
		t.Error("the module switch was moved onto the instance, so the proxy would stop running")
	}
	if !held.Enabled {
		t.Error("the migrated instance is switched off, so turning the module on would leave " +
			"a proxy that still listens nowhere")
	}
}

// The scope was a two-valued setting and both readings were grants. Writing them as rules is
// what makes them separately revocable; reading either as the other would widen a proxy the
// user deliberately kept narrow, or cut off a browser pointed entirely at it.
func TestTheOldScopeBecomesTheRulesItAlwaysMeant(t *testing.T) {
	tests := []struct {
		scope string
		want  ProxyScope
		rules int
	}{
		{"tailnet", ScopeTailnet, 1},
		{"all", ScopeAll, 2},
	}
	for _, tc := range tests {
		t.Run(tc.scope, func(t *testing.T) {
			path := writeConfig(t, `{
				"version": 5,
				"settings": {"proxy.enabled": true, "proxy.scope": "`+tc.scope+`"},
				"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
					"tailscale":{"hostname":"workstation"}}],
				"forwards": []
			}`)

			store, err := Open(path)
			if err != nil {
				t.Fatalf("opening a config with proxy scope %q: %v", tc.scope, err)
			}

			held, ok := store.Get().Proxy(DefaultProxyID)
			if !ok {
				t.Fatal("no default instance after migrating")
			}
			if len(held.Rules) != tc.rules {
				t.Fatalf("the instance holds %d rules, want %d: %+v", len(held.Rules), tc.rules, held.Rules)
			}
			if got := DerivedProxyScope(held.Rules); got != tc.want {
				t.Errorf("the migrated rules read back as %q, want %q", got, tc.want)
			}
			if held.Rules[0].Tunnel != PrimaryTunnelID {
				t.Errorf("the first rule names %q, want the connection the proxy carried",
					held.Rules[0].Tunnel)
			}
		})
	}
}

// A document that carried no proxy settings at all still gets the instance every install
// has: without one, every settings key that writes to the proxy would be refused with
// nowhere to put it.
func TestADocumentWithNoProxySettingsStillGetsTheInstance(t *testing.T) {
	path := writeConfig(t, `{
		"version": 5,
		"settings": {},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config carrying no proxy settings: %v", err)
	}

	held, ok := store.Get().Proxy(DefaultProxyID)
	if !ok {
		t.Fatal("no default instance after migrating")
	}
	if held.ListenAddr != DefaultProxyListenAddr {
		t.Errorf("listenAddr = %q, want the default %q", held.ListenAddr, DefaultProxyListenAddr)
	}
	// The scope defaulted to the tailnet while it was a setting, so an install that never
	// chose one was carrying that connection and must go on carrying it.
	if got := DerivedProxyScope(held.Rules); got != ScopeTailnet {
		t.Errorf("the migrated rules read back as %q, want the default reach %q", got, ScopeTailnet)
	}
}

// A document a newer build already migrated must not gain a second instance under the same
// id: every lookup of it would be ambiguous, and the older one would win or lose by map order.
func TestAnInstanceThatIsAlreadyThereIsNotAddedTwice(t *testing.T) {
	path := writeConfig(t, `{
		"version": 5,
		"settings": {"proxy.listenAddr": "127.0.0.1:1099"},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"proxies": [{"id":"px_default","slug":"default","name":"Default","enabled":true,
			"listenAddr":"127.0.0.1:1080",
			"rules":[{"id":"ar_connection","action":"allow","tunnel":"tn_primary"}]}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config a newer build had already migrated: %v", err)
	}

	cfg := store.Get()
	if len(cfg.Proxies) != 1 {
		t.Fatalf("the document holds %d instances, want the one that was already there: %+v",
			len(cfg.Proxies), cfg.Proxies)
	}
	if cfg.Proxies[0].ListenAddr != "127.0.0.1:1080" {
		t.Errorf("listenAddr = %q, want the instance left exactly as it was found",
			cfg.Proxies[0].ListenAddr)
	}
}

// An instance a user removed stays removed. A migration that re-added it on the next load
// would put a listener back that somebody deliberately deleted.
func TestARemovedInstanceStaysRemoved(t *testing.T) {
	path := writeConfig(t, `{
		"version": 6,
		"settings": {},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"proxies": [],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config whose instances were removed: %v", err)
	}

	if got := store.Get().Proxies; len(got) != 0 {
		t.Errorf("the document holds %+v, want the instance list left empty", got)
	}
}

// The interface settings were named for the tun device behind one of the two interfaces
// this app can create. Renaming the keys without carrying the values across would take a
// machine that is on a network interface back to running inside app-tail alone -- silently,
// on the upgrade, with the settings page showing the defaults as though nobody had ever
// chosen anything.
func TestTheInterfaceSettingsSurviveBeingRenamed(t *testing.T) {
	path := writeConfig(t, `{
		"version": 6,
		"settings": {
			"tun.enabled": true,
			"tun.mode": "fabric",
			"tun.interfaceName": "apptail0",
			"tun.virtualPool": ["198.19.0.0/16"]
		},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"proxies": [{"id":"px_default","slug":"default","name":"Default","enabled":true,
			"listenAddr":"127.0.0.1:1080","rules":[]}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config written before the interface settings were renamed: %v", err)
	}

	s := store.Get().Settings
	if !s.InterfaceEnabled {
		t.Error("the interface module is off after the rename, so the upgrade took this machine off its networks")
	}
	if s.InterfaceMode != NetworkFabric {
		t.Errorf("mode = %q, want %q carried across", s.InterfaceMode, NetworkFabric)
	}
	if s.InterfaceName != "apptail0" {
		t.Errorf("interface name = %q, want the stored name carried across", s.InterfaceName)
	}
	if len(s.InterfaceVirtualPool) != 1 || s.InterfaceVirtualPool[0].String() != "198.19.0.0/16" {
		t.Errorf("pool = %v, want the stored range carried across", s.InterfaceVirtualPool)
	}
}

// A document that never carried the old keys must not have its defaults overwritten by the
// rename: an absent key and a stored false read the same way out of JSON, and writing the
// zero value over a default is how a migration turns something off that was never on.
func TestARenameFindsNothingToCarryAndChangesNothing(t *testing.T) {
	path := writeConfig(t, `{
		"version": 6,
		"settings": {},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"proxies": [{"id":"px_default","slug":"default","name":"Default","enabled":true,
			"listenAddr":"127.0.0.1:1080","rules":[]}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config that never named an interface: %v", err)
	}

	s := store.Get().Settings
	if s.InterfaceEnabled {
		t.Error("the interface module came on by itself, which installs an interface nobody asked for")
	}
	if s.InterfaceMode != NetworkUserspace {
		t.Errorf("mode = %q, want the default %q", s.InterfaceMode, NetworkUserspace)
	}
}

// An install that predates the tailnet-route repair comes up with it on, the same as a fresh
// one. A switch that defaults on is the one default the back-fill cannot apply -- an absent key
// and a stored false decode alike -- so without the migration the machines that have been
// running longest, which are the ones that have had time to lose the route, would be the only
// ones the repair never watches.
func TestAnInstallFromBeforeTheTailnetRouteRepairGetsIt(t *testing.T) {
	path := writeConfig(t, `{
		"version": 7,
		"settings": {},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"proxies": [{"id":"px_default","slug":"default","name":"Default","enabled":true,
			"listenAddr":"127.0.0.1:1080","rules":[]}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config written before the tailnet-route repair existed: %v", err)
	}

	if !store.Get().Settings.TailnetRouteRepair {
		t.Error("the repair is off on an upgraded install, so a machine that loses the route " +
			"to its tailnet stays unreachable with nothing watching")
	}
}

// A document already at the current version is not migrated, so a user who turned the repair
// off keeps it off. Turning it back on unconditionally would make the switch undo itself on
// every load.
func TestTheRepairStaysOffOnADocumentThatAlreadySaysSo(t *testing.T) {
	path := writeConfig(t, `{
		"version": `+strconv.Itoa(ConfigVersion)+`,
		"settings": {"tailnet.repairRoutes": false},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"proxies": [{"id":"px_default","slug":"default","name":"Default","enabled":true,
			"listenAddr":"127.0.0.1:1080","rules":[]}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config that switched the repair off: %v", err)
	}

	if store.Get().Settings.TailnetRouteRepair {
		t.Error("the repair came back on by itself, so the switch cannot be turned off")
	}
}

// An older document that wrote its listening address as empty must still land on one.
//
// It reads as "the default" in v1, where the address was resolved when the proxy started.
// Carried through as it stands it becomes an instance that listens nowhere, with a module
// switched on and nothing to point a program at.
func TestAProxyThatNeverStoredAnAddressLandsOnTheDefaultOne(t *testing.T) {
	path := writeConfig(t, `{
		"version": 5,
		"settings": {"proxy.enabled": true, "proxy.listenAddr": ""},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config whose proxy stored no address: %v", err)
	}

	held, ok := store.Get().Proxy(DefaultProxyID)
	if !ok {
		t.Fatal("no default instance after migrating")
	}
	if held.ListenAddr != DefaultProxyListenAddr {
		t.Errorf("listenAddr = %q, want %q -- an instance with no address listens nowhere",
			held.ListenAddr, DefaultProxyListenAddr)
	}
}

// Tags decide what a tailnet's own policy lets this device do, so a document that carried
// them has to carry them onto the connection. Left behind, the device enrolls untagged and
// is refused by every rule written for its tag -- which reads as a broken network, not as a
// setting that went missing in an upgrade.
func TestAnOlderDocumentsTagsMoveOntoItsConnection(t *testing.T) {
	path := writeConfig(t, `{
		"version": 2,
		"settings": {"hostname": "workstation", "tags": ["tag:server", "tag:ci"]},
		"tunnels": [{"id":"tn_primary","slug":"tailnet","name":"Tailnet","type":"tailscale","enabled":true,
			"tailscale":{"hostname":"workstation"}}],
		"forwards": []
	}`)

	store, err := Open(path)
	if err != nil {
		t.Fatalf("opening a config that stored its tags globally: %v", err)
	}

	held, ok := store.Get().Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatal("no primary connection after migrating")
	}
	got := held.TS().Tags
	if len(got) != 2 || got[0] != "tag:server" || got[1] != "tag:ci" {
		t.Errorf("tags = %q, want both carried onto the connection in order", got)
	}
}
