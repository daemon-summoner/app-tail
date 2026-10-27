// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

// switchModule is the one-key save a switch in the UI sends.
func switchModule(t *testing.T, cfg *Config, key string, on bool) {
	t.Helper()
	state := json.RawMessage(`false`)
	if on {
		state = json.RawMessage(`true`)
	}
	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{key: state}); err != nil {
		t.Fatalf("setting %s to %v: %v", key, on, err)
	}
}

// Turning a module off is one click, and it must not be how someone loses the resolver,
// the suffixes and the address they set up. The reset that makes "off" mean off stays;
// what it took is put back when the switch goes on again.
func TestTurningAModuleBackOnRestoresWhatItHeld(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.SystemDNSEnabled = true
	cfg.Settings.SystemDNSProfile = "nextdns"
	cfg.Settings.SystemDNSLocalSuffixes = []string{"corp.example.com"}
	cfg.Settings.SystemDNSListenAddr = "127.0.0.55:53"

	switchModule(t, cfg, "systemDns.enabled", false)
	// The reset still has to happen, or a machine-wide resolver stays pointed somewhere
	// under a switch that reads off.
	if cfg.Settings.SystemDNSProfile != DefaultSystemDNSProfile {
		t.Errorf("systemDns.profile = %q while the module is off, want the default",
			cfg.Settings.SystemDNSProfile)
	}

	switchModule(t, cfg, "systemDns.enabled", true)
	if got := cfg.Settings.SystemDNSProfile; got != "nextdns" {
		t.Errorf("systemDns.profile = %q after the module came back on, want %q", got, "nextdns")
	}
	if got := cfg.Settings.SystemDNSLocalSuffixes; !reflect.DeepEqual(got, []string{"corp.example.com"}) {
		t.Errorf("systemDns.localSuffixes = %v, want the suffix that was set", got)
	}
	if got := cfg.Settings.SystemDNSListenAddr; got != "127.0.0.55:53" {
		t.Errorf("systemDns.listenAddr = %q, want the address that was set", got)
	}
	// Once restored the value is the live setting again. A second copy would go stale the
	// moment it is changed, and then contradict it on the next switch.
	if cfg.Settings.Shelved != nil {
		t.Errorf("the shelf still holds %v after everything was put back", cfg.Settings.Shelved)
	}
}

// A module's fields live on the connection as well as in the settings document, and the
// two halves have to behave the same way: a control URL taken away by a switch has to come
// back with it.
func TestTurningAModuleBackOnRestoresTheConnectionFieldsItGoverned(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.AdvancedNetworking = true
	ts, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatal(err)
	}
	ts.ControlURL = "https://headscale.example.com"

	switchModule(t, cfg, "advancedNetworking", false)
	if got := tailnetOf(t, cfg).ControlURL; got != "" {
		t.Fatalf("controlURL = %q while the module is off, want it cleared", got)
	}

	switchModule(t, cfg, "advancedNetworking", true)
	if got := tailnetOf(t, cfg).ControlURL; got != "https://headscale.example.com" {
		t.Errorf("controlURL = %q after the module came back on, want the stored server", got)
	}
	if cfg.Tunnels[0].Shelved != nil {
		t.Errorf("the connection's shelf still holds %v after everything was put back",
			cfg.Tunnels[0].Shelved)
	}
}

// Turning a module on and configuring it is one action to a user, so it is one save. What
// they just chose has to win over what the shelf remembers, or the form silently reverts
// the value they typed beside the switch they flipped.
func TestASettingSavedWithTheSwitchWinsOverTheShelf(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.SystemDNSEnabled = true
	cfg.Settings.SystemDNSProfile = "nextdns"
	switchModule(t, cfg, "systemDns.enabled", false)

	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"systemDns.enabled": json.RawMessage(`true`),
		"systemDns.profile": json.RawMessage(`"cloudflare"`),
	}); err != nil {
		t.Fatalf("turning the module on and choosing a resolver: %v", err)
	}
	if got := cfg.Settings.SystemDNSProfile; got != "cloudflare" {
		t.Errorf("systemDns.profile = %q, want the one saved with the switch", got)
	}
}

// A module switched off and on again with nothing configured must not start writing a
// shelf into the stored document: an entry holding the default and no entry at all restore
// identically, and the file is read by people.
func TestNothingIsShelvedForSettingsAtTheirDefaults(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.SystemDNSEnabled = true

	switchModule(t, cfg, "systemDns.enabled", false)
	if cfg.Settings.Shelved != nil {
		t.Errorf("the shelf holds %v for a module that was never configured", cfg.Settings.Shelved)
	}
}

// A save that moves no switch must leave the shelf alone. Re-shelving on every write would
// overwrite what a module held with the defaults it was reset to.
func TestAnUnrelatedSaveLeavesTheShelfAlone(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.SystemDNSEnabled = true
	cfg.Settings.SystemDNSProfile = "nextdns"
	switchModule(t, cfg, "systemDns.enabled", false)
	held := cfg.Settings.Shelved["systemDns.profile"]

	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"hostname": json.RawMessage(`"my-box"`),
	}); err != nil {
		t.Fatalf("apply an unrelated setting: %v", err)
	}
	if got := string(cfg.Settings.Shelved["systemDns.profile"]); got != string(held) {
		t.Errorf("the shelf holds %q after an unrelated save, want %q", got, held)
	}
}

// The interface mode a switch turns on is the one the shelf holds, which the stored mode
// stops saying the moment the module goes off. A dashboard writing the mode beside the
// switch reads this, and reading the stored mode instead is how a machine arranged for the
// one-interface mode comes back on the tailnet-only one with nothing saying so.
func TestTheInterfaceModeChosenSurvivesTheModuleBeingOff(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.InterfaceEnabled = true
	cfg.Settings.InterfaceMode = NetworkFabric

	switchModule(t, cfg, "interface.enabled", false)
	if cfg.Settings.InterfaceMode != NetworkUserspace {
		t.Fatalf("interface.mode = %q while the module is off, want the default", cfg.Settings.InterfaceMode)
	}
	if got := cfg.Settings.InterfaceModeChosen(); got != NetworkFabric {
		t.Errorf("the mode chosen reads %q while the module is off, want the shelved %q", got, NetworkFabric)
	}

	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"interface.enabled": json.RawMessage(`true`),
		"interface.mode":    json.RawMessage(`"fabric"`),
	}); err != nil {
		t.Fatalf("turning the module on with the mode it reported: %v", err)
	}
	if got := cfg.Settings.InterfaceModeChosen(); got != NetworkFabric {
		t.Errorf("the mode chosen reads %q with the module on, want the stored %q", got, NetworkFabric)
	}
}

// With nothing on the shelf the switch turns on the stored mode, so a module never
// configured reports the default -- and an entry this build cannot read is what the switch
// would drop, so it is not reported as what comes on either.
func TestTheInterfaceModeChosenFallsBackToTheStoredMode(t *testing.T) {
	s := Defaults().Settings
	if got := s.InterfaceModeChosen(); got != NetworkUserspace {
		t.Errorf("a module never configured reports %q, want %q", got, NetworkUserspace)
	}
	s.Shelved = map[string]json.RawMessage{"interface.mode": json.RawMessage(`"bridge"`)}
	if got := s.InterfaceModeChosen(); got != NetworkUserspace {
		t.Errorf("an unreadable shelf entry reports %q, want the stored %q", got, NetworkUserspace)
	}
}

// shelfEntity is a stand-in for a configurable thing with one secret and one ordinary
// field under the same module. No real entity has a module-owned secret today, and the
// rule has to hold for the one that does: the credential is forgotten, not filed away
// somewhere no screen shows and no switch reaches.
type shelfEntity struct {
	Token string
	Name  string
}

func TestASecretIsForgottenRatherThanShelved(t *testing.T) {
	r := NewRegistry([]FieldOf[shelfEntity]{
		{
			JSONKey: "token", Kind: KindSecret, Module: ModuleSystemDNS,
			get: func(e *shelfEntity) any { return e.Token },
			set: func(e *shelfEntity, v any) { e.Token = typed[string](v) },
		},
		{
			JSONKey: "name", Kind: KindString, Module: ModuleSystemDNS,
			get: func(e *shelfEntity) any { return e.Name },
			set: func(e *shelfEntity, v any) { e.Name = typed[string](v) },
		},
	})

	entity := shelfEntity{Token: "s3cret", Name: "work"}
	shelf := r.shelve(&entity, ModuleSystemDNS, nil)
	if entity.Token != "" {
		t.Errorf("token = %q after the module went off, want it cleared", entity.Token)
	}
	if _, held := shelf["token"]; held {
		t.Error("the secret was written to the shelf, where nothing can show it and no switch reaches it")
	}
	if _, held := shelf["name"]; !held {
		t.Fatalf("the ordinary field was not shelved: %v", shelf)
	}

	shelf = r.unshelve(&entity, ModuleSystemDNS, shelf)
	if entity.Name != "work" {
		t.Errorf("name = %q after the module came back on, want %q", entity.Name, "work")
	}
	if entity.Token != "" {
		t.Errorf("token = %q, want the credential to stay forgotten", entity.Token)
	}
	if shelf != nil {
		t.Errorf("the shelf still holds %v", shelf)
	}
}

// A shelf entry from a field that has since changed shape must not be able to fail the
// save that turns a module on: the user never made that record, and refusing is a worse
// answer than the default they get instead.
func TestAShelfEntryThisBuildCannotUseIsDroppedRatherThanRefused(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.Shelved = map[string]json.RawMessage{
		"systemDns.profile":       json.RawMessage(`{"was":"a string"}`),
		"systemDns.listenAddr":    json.RawMessage(`"not an address"`),
		"systemDns.localSuffixes": json.RawMessage(`["corp.example.com"]`),
	}

	switchModule(t, cfg, "systemDns.enabled", true)
	if got := cfg.Settings.SystemDNSProfile; got != DefaultSystemDNSProfile {
		t.Errorf("systemDns.profile = %q, want the default a bad entry falls back to", got)
	}
	if got := cfg.Settings.SystemDNSListenAddr; got != DefaultSystemDNSListenAddr {
		t.Errorf("systemDns.listenAddr = %q, want the default a refused entry falls back to", got)
	}
	// The entries that were usable still land: one bad record does not cost the rest.
	if got := cfg.Settings.SystemDNSLocalSuffixes; !reflect.DeepEqual(got, []string{"corp.example.com"}) {
		t.Errorf("systemDns.localSuffixes = %v, want the entry that was usable", got)
	}
	if cfg.Settings.Shelved != nil {
		t.Errorf("the shelf still holds %v; a dropped entry has to be cleared too",
			cfg.Settings.Shelved)
	}
}
