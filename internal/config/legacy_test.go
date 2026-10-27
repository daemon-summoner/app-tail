// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The command-line surface is the promise the redirect makes: a key that named the one
// tailnet keeps naming it. A key that fell out of the schema is a command someone runs in
// a script that now fails, and a key that landed at the end of the numbered menu is one
// they can no longer find where they have always found it.
func TestEveryRedirectedKeyKeepsThePositionItHadOnTheCommandLine(t *testing.T) {
	slotted(t, tailnetRedirect)
	slotted(t, proxyRedirect)

	schema := SettingsCLISchema()
	order := make(map[string]int, len(schema))
	for i, s := range schema {
		if _, repeated := order[s.Key]; repeated {
			t.Fatalf("%q is served twice by the command-line schema", s.Key)
		}
		order[s.Key] = i
	}

	// The exact neighbours the document had before the move, which is what an existing
	// install's menu numbering is built from.
	wantBefore := [][2]string{
		{"hostname", "hostnameTemplate"},
		{"hostnameTemplate", "tags"},
		{"oauthClientSecretFile", "advancedNetworking"},
		{"advancedNetworking", "controlURL"},
		{"controlURL", "ephemeral"},
		{"machineId", "effectiveHostname"},
	}
	for _, pair := range wantBefore {
		first, second := order[pair[0]], order[pair[1]]
		if second != first+1 {
			t.Errorf("%q is served at %d and %q at %d; they were adjacent, in that order",
				pair[0], first, pair[1], second)
		}
	}
	if order["hostname"] != 0 {
		t.Errorf("hostname is served at %d; it opened the list", order["hostname"])
	}

	// The proxy keys sat together directly behind the switch that governs them, and the
	// switch stayed in the settings document -- so the whole block has to land there.
	for i, key := range proxyRedirect.keys {
		if got, want := order[key], order["proxy.enabled"]+1+i; got != want {
			t.Errorf("%q is served at %d, want %d: the proxy keys followed proxy.enabled in "+
				"the order they are declared", key, got, want)
		}
	}
}

// slotted checks that every key a redirect answers for is named by one of its slots, so it
// is served where it always was rather than appended to the end of the numbered menu.
func slotted[T any](t *testing.T, r redirect[T]) {
	t.Helper()
	for _, key := range r.keys {
		var found bool
		for _, keys := range r.slots {
			found = found || slices.Contains(keys, key)
		}
		if !found {
			t.Errorf("%q has moved onto another entity but no slot says where it used to "+
				"sit, so it is served at the end of the list instead of where it was", key)
		}
	}
}

// A redirected key is described by the field it writes to, so its help cannot say one
// thing while the write does another -- and it says where the setting went, because a key
// that silently works from the command line while being absent from the dashboard is one
// nobody can find again.
func TestARedirectedKeyIsDescribedByWhatItWritesTo(t *testing.T) {
	served := make(map[string]FieldSchema)
	for _, s := range SettingsCLISchema() {
		served[s.Key] = s
	}
	describedBy(t, served, tailnetRedirect)
	describedBy(t, served, proxyRedirect)
}

// describedBy checks one redirect's keys against the fields they now write to.
func describedBy[T any](t *testing.T, served map[string]FieldSchema, r redirect[T]) {
	t.Helper()
	for _, key := range r.keys {
		s, ok := served[key]
		if !ok {
			t.Errorf("%q is not served by the command-line schema at all", key)
			continue
		}
		field, ok := r.registry.ByJSONKey(key)
		if !ok {
			t.Errorf("%q redirects to a field that does not exist", key)
			continue
		}
		if s.Kind != field.Kind || s.CLIName != field.CLIName || s.Write != field.Write {
			t.Errorf("%q is described as %+v but writes to a field declaring kind %q, "+
				"CLI name %q and write %q", key, s, field.Kind, field.CLIName, field.Write)
		}
		if !strings.Contains(s.Help, r.note) {
			t.Errorf("the help for %q does not say where the setting went: %q", key, s.Help)
		}
	}
}

// The proxy half of the same promise: a script that has always set the proxy's address
// keeps setting it, and it lands on the instance that address has always belonged to.
func TestARedirectedProxyKeyWritesTheDefaultInstance(t *testing.T) {
	cfg := Defaults()
	// The module switch stayed in the settings document while the fields it gates moved, so
	// the same one save carries both -- which is the case ApplyPatchTo orders itself for.
	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"proxy.enabled":        json.RawMessage(`true`),
		"proxy.listenAddr":     json.RawMessage(`"127.0.0.1:1081"`),
		"proxy.dialTimeoutSec": json.RawMessage(`45`),
	}); err != nil {
		t.Fatalf("ApplyPatchTo: %v", err)
	}

	held, ok := cfg.Proxy(DefaultProxyID)
	if !ok {
		t.Fatal("the default proxy is missing after a patch that named it")
	}
	if got := held.ListenAddr; got != "127.0.0.1:1081" {
		t.Errorf("the instance listens on %q, want the address the patch carried", got)
	}
	if got := held.DialTimeoutSec; got != 45 {
		t.Errorf("the instance's dial timeout = %d, want 45", got)
	}

	view := SettingsViewOf(cfg)
	if got := view["proxy.listenAddr"]; got != "127.0.0.1:1081" {
		t.Errorf("the settings view holds %#v under \"proxy.listenAddr\"", got)
	}
	// The scope key survives as a reading of the rules rather than as a stored value, so a
	// caller that has always read it is answered rather than told the key is gone.
	if got := view["proxy.scope"]; got != string(DerivedProxyScope(held.Rules)) {
		t.Errorf("the settings view holds %#v under \"proxy.scope\", want the scope the "+
			"instance's rules describe", got)
	}
}

// The scope key is read-only now, and a write has to be refused rather than accepted and
// dropped: `settings set proxy-scope all` silently doing nothing would leave somebody
// believing they had widened a grant they had not.
func TestWritingTheScopeKeyIsRefusedRatherThanDropped(t *testing.T) {
	cfg := Defaults()
	err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"proxy.enabled": json.RawMessage(`true`),
		"proxy.scope":   json.RawMessage(`"all"`),
	})
	if err == nil {
		t.Fatal("a write to the derived scope key was accepted")
	}
	if !strings.Contains(err.Error(), "proxy.scope") {
		t.Errorf("error = %v, want the key that cannot be written named", err)
	}
}

// A patch naming a redirected proxy key with no instance to write it to has to say so,
// for the same reason the connection half does.
func TestARedirectedProxyKeyWithNoInstanceIsRefusedByName(t *testing.T) {
	cfg := Defaults()
	cfg.Proxies = nil

	err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"proxy.listenAddr": json.RawMessage(`"127.0.0.1:1081"`),
	})
	if err == nil {
		t.Fatal("a patch naming the proxy was accepted with no proxy to write it to")
	}
	if !strings.Contains(err.Error(), "proxy.listenAddr") {
		t.Errorf("error = %v, want the key that could not be applied named", err)
	}
}

// The whole point of the redirect: a caller that names one of these keys writes the
// tailnet this app has always run, rather than being refused or writing a settings field
// nothing reads.
func TestARedirectedKeyWritesTheConnectionItNames(t *testing.T) {
	cfg := Defaults()
	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"hostname": json.RawMessage(`"renamed-node"`),
		"showTray": json.RawMessage(`false`),
	}); err != nil {
		t.Fatalf("ApplyPatchTo: %v", err)
	}

	primary, ok := cfg.Tunnel(PrimaryTunnelID)
	if !ok {
		t.Fatal("the primary connection is missing after a patch that named it")
	}
	if got := primary.TS().Hostname; got != "renamed-node" {
		t.Errorf("the connection's device name = %q, want the value the patch carried", got)
	}
	if cfg.Settings.ShowTray {
		t.Error("the settings half of the same patch was not applied")
	}

	// And it reads back under the key it was written with, or a form that saves what it
	// was served would clear the value it never saw.
	view := SettingsViewOf(cfg)
	if got := view["hostname"]; got != "renamed-node" {
		t.Errorf("the settings view holds %#v under \"hostname\"", got)
	}
}

// A module can gate a field that has moved, and the switch that gates it stayed behind.
// Applying the connection half first would judge it against the configuration as it was
// before the save, so turning a module on and configuring it would take two saves -- with
// the first one refused for a reason the form cannot explain.
func TestAModuleAndTheConnectionFieldItGatesSaveTogether(t *testing.T) {
	cfg := Defaults()
	err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"advancedNetworking": json.RawMessage(`true`),
		"controlURL":         json.RawMessage(`"https://headscale.example.com"`),
	})
	if err != nil {
		t.Fatalf("turning a module on and configuring it in one save: %v", err)
	}

	primary, _ := cfg.Tunnel(PrimaryTunnelID)
	if got := primary.TS().ControlURL; got != "https://headscale.example.com" {
		t.Errorf("the connection's control server = %q, want the value the patch carried", got)
	}
}

// Switching a module off returns what it governs to its defaults, and half of what this
// one governs now lives on a connection. A switch reading off while a connection still
// joins a private coordination server is a setting nobody can see or turn off, because an
// off module hides its own fields.
func TestSwitchingAModuleOffClearsTheConnectionFieldsItGoverned(t *testing.T) {
	cfg := Defaults()
	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"advancedNetworking": json.RawMessage(`true`),
		"controlURL":         json.RawMessage(`"https://headscale.example.com"`),
	}); err != nil {
		t.Fatalf("ApplyPatchTo: %v", err)
	}

	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"advancedNetworking": json.RawMessage(`false`),
	}); err != nil {
		t.Fatalf("switching the module off: %v", err)
	}

	primary, _ := cfg.Tunnel(PrimaryTunnelID)
	if got := primary.TS().ControlURL; got != "" {
		t.Errorf("the connection still points at %q with the module that governs it off", got)
	}
}

// The reverse of adoption: a document written before the switch existed carries the value
// with the switch off, and the first write would silently reset it -- moving a node off
// the coordination server it was pointed at.
func TestAStoredConnectionValueTurnsItsModuleOn(t *testing.T) {
	cfg := Defaults()
	i := primaryIndex(cfg.Tunnels)
	cfg.Tunnels[i].Tailscale.ControlURL = "https://headscale.example.com"
	cfg.Settings.AdvancedNetworking = false

	applyDefaults(cfg)

	if !cfg.Settings.AdvancedNetworking {
		t.Error("a connection pointed at a private coordination server loaded with the " +
			"module that governs it off; the first write would reset it")
	}
}

// A patch naming a redirected key with no connection to write it to has to say so. Silent
// success would report a device name the app never stored.
func TestARedirectedKeyWithNoConnectionIsRefusedByName(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnels = nil

	err := ApplyPatchTo(cfg, map[string]json.RawMessage{"hostname": json.RawMessage(`"x"`)})
	if err == nil {
		t.Fatal("a patch naming the tailnet was accepted with no tailnet to write it to")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("error = %v, want the key that could not be applied named", err)
	}
}
