// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// These strings are the wire contract. They land in the settings schema the dashboard
// fetches and in the TypeScript unions the generator writes, so renaming one silently
// makes the schema unrenderable by a client that still expects the old word: a field
// whose kind no longer matches a union member falls through to a plain text box --
// including the secrets.
func TestEveryFieldKindSerializesToItsDocumentedWireWord(t *testing.T) {
	tests := []struct {
		kind FieldKind
		want string
	}{
		{KindString, "string"},
		{KindBool, "bool"},
		{KindInt, "int"},
		{KindStringList, "stringList"},
		{KindSecret, "secret"},
		{KindSecretFile, "secretFile"},
		// An unmapped kind must read as a plain string rather than an empty word, so a
		// schema built against a newer registry still renders.
		{FieldKind(99), "string"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			raw, err := json.Marshal(tt.kind)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != `"`+tt.want+`"` {
				t.Errorf("JSON = %s, want %q; an integer here would reach the dashboard "+
					"as an opaque number no union member matches", raw, tt.want)
			}
		})
	}
}

// The restart class is what the dashboard turns into "restart the node to apply". A
// word the client does not recognise means the notice never appears and the user waits
// for a change that will not take effect until they restart on their own.
func TestEveryRestartClassSerializesToItsDocumentedWireWord(t *testing.T) {
	tests := []struct {
		class RestartClass
		want  string
	}{
		{RestartNone, "none"},
		{RestartPrefs, "prefs"},
		{RestartNode, "node"},
		{RestartUI, "ui"},
		{RestartClass(99), "none"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.class.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			raw, err := json.Marshal(tt.class)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != `"`+tt.want+`"` {
				t.Errorf("JSON = %s, want %q", raw, tt.want)
			}
		})
	}
}

// The write route tells the dashboard which endpoint applies a field. Sending a login
// item through the settings patch endpoint is refused by the agent, so a wrong word
// here turns the start-at-login switch into one that always errors.
func TestEveryWriteRouteSerializesToItsDocumentedWireWord(t *testing.T) {
	tests := []struct {
		via  WriteVia
		want string
	}{
		{WritePatch, "patch"},
		{WriteAutostart, "autostart"},
		{WriteNone, "none"},
		{WriteVia(99), "patch"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.via.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			raw, err := json.Marshal(tt.via)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != `"`+tt.want+`"` {
				t.Errorf("JSON = %s, want %q", raw, tt.want)
			}
		})
	}
}

// The registry is the single source every consumer reads: the schema endpoint, the CLI
// menu, and the TypeScript generator. Handing back a copy or a subset would let one of
// them drift from the others without anything failing.
func TestTheRegistryAccessorReturnsTheAuthoredFieldsInOrder(t *testing.T) {
	fields := SettingsFields()
	if len(fields) == 0 {
		t.Fatal("the settings registry is empty")
	}

	schema := SettingsSchema()
	if len(schema) != len(fields) {
		t.Fatalf("the schema has %d entries, the registry has %d", len(schema), len(fields))
	}
	for i, f := range fields {
		if schema[i].Key != f.JSONKey {
			t.Errorf("schema entry %d = %q, registry has %q", i, schema[i].Key, f.JSONKey)
		}
	}
}

// The schema is what a client renders a settings form from. Every derived value the
// schema advertises has to match the field it came from, because a secret marked
// writable renders as a text box that echoes back what was typed, and a read-only
// field marked writable renders a control whose every save is refused.
func TestTheSchemaProjectsEachFieldsRulesFaithfully(t *testing.T) {
	byKey := make(map[string]FieldSchema, len(SettingsSchema()))
	for _, s := range SettingsSchema() {
		byKey[s.Key] = s
	}

	for _, f := range SettingsFields() {
		s, ok := byKey[f.JSONKey]
		if !ok {
			t.Errorf("field %q is in the registry but not the schema", f.JSONKey)
			continue
		}
		if got, want := s.Secret, f.Kind == KindSecret; got != want {
			t.Errorf("%s: Secret = %v, want %v", f.JSONKey, got, want)
		}
		if got, want := s.ReadOnly, f.Derived || f.Write == WriteNone; got != want {
			t.Errorf("%s: ReadOnly = %v, want %v", f.JSONKey, got, want)
		}
		if s.Derived != f.Derived {
			t.Errorf("%s: Derived = %v, want %v", f.JSONKey, s.Derived, f.Derived)
		}
		if s.ViewKey == "" {
			t.Errorf("%s: the schema advertises no view key, so a client cannot find "+
				"the value in the settings document", f.JSONKey)
		}
		if s.Kind != f.Kind || s.Restart != f.Restart || s.Write != f.Write {
			t.Errorf("%s: schema kind/restart/write = %v/%v/%v, registry has %v/%v/%v",
				f.JSONKey, s.Kind, s.Restart, s.Write, f.Kind, f.Restart, f.Write)
		}
		if s.Help == "" {
			t.Errorf("%s: no help text, so the form renders a bare label", f.JSONKey)
		}
	}
}

// The module name is what a client groups fields by and what a rejection names when a
// setting belongs to a module that is off. Two modules sharing a word merge into one
// section on screen; an unrecognised one strands its fields under a heading nothing
// matches, which is why an unknown value reads as core rather than as itself.
func TestEveryFeatureModuleSerializesToItsDocumentedWireWord(t *testing.T) {
	tests := []struct {
		module FeatureModule
		want   string
	}{
		{ModuleCore, "core"},
		{ModuleAdvancedNetworking, "advancedNetworking"},
		{ModuleProxy, "proxy"},
		{ModuleAutoMap, "automap"},
		{ModuleExitNode, "exitNode"},
		{ModuleRouting, "routing"},
		{ModuleDNS, "dns"},
		{ModuleSystemDNS, "systemDns"},
		{ModuleDNSBlock, "dnsBlock"},
		{ModuleSecurity, "security"},
		{ModuleInterface, "interface"},
		{ModuleTelemetry, "telemetry"},
		{ModuleIPS, "ips"},
		{FeatureModule(99), "core"},
	}

	seen := make(map[string]bool, len(tests))
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.module.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			raw, err := json.Marshal(tt.module)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != `"`+tt.want+`"` {
				t.Errorf("JSON = %s, want %q", raw, tt.want)
			}
		})
		if tt.module != FeatureModule(99) && seen[tt.want] {
			t.Errorf("two modules both call themselves %q, so their fields merge on screen", tt.want)
		}
		seen[tt.want] = true
	}

	// The authored list is what the schema endpoint publishes; a module missing from the
	// table above would keep its own name here and read as core to every client.
	for _, m := range FeatureModules() {
		if !seen[m.ID.String()] {
			t.Errorf("module %s is offered to clients but has no word of its own", m.ID)
		}
	}
}

// A secret's view key must differ from its patch key. Sharing one would put the
// presence boolean where the dashboard expects a value, and a round-trip would PUT
// `true` as the auth key.
func TestASecretsPresenceKeyIsDistinctFromItsPatchKey(t *testing.T) {
	// Every schema a form is built from, because the secrets moved onto the entities and a
	// guard left behind on the settings table alone would cover none of them.
	schemas := map[string][]FieldSchema{
		"settings":     SettingsSchema(),
		"connections":  tunnelRegistry.Schema(),
		"proxies":      proxyRegistry.Schema(),
		"settings CLI": SettingsCLISchema(),
	}
	for surface, schema := range schemas {
		found := 0
		for _, s := range schema {
			if !s.Secret {
				continue
			}
			found++
			if s.ViewKey == s.Key {
				t.Errorf("%s secret %q reports its presence under its own key; a dashboard "+
					"round-trip would store the presence boolean as the secret", surface, s.Key)
			}
		}
		if found == 0 && surface != "settings" {
			t.Errorf("no secret fields in the %s schema; this guard is covering nothing there", surface)
		}
	}
}

// An enum field's choices are a closed set, and the refusal has to list them: the client
// that sent the value has the schema, but the person reading the error in a terminal has
// only the sentence. An empty value stays acceptable -- that is how a field says "unset",
// which the accessors resolve to their own default.
func TestAnEnumFieldRefusesAValueOutsideItsChoicesAndListsThem(t *testing.T) {
	var field SettingField
	for _, f := range settingsFields {
		if len(f.Options) > 1 {
			field = f
			break
		}
	}
	if field.JSONKey == "" {
		t.Fatal("no field in the registry declares choices, so this guard covers nothing")
	}

	if err := field.ValidateValue(""); err != nil {
		t.Errorf("%s refused an empty value: %v", field.JSONKey, err)
	}
	for _, opt := range field.Options {
		if err := field.ValidateValue(opt.Value); err != nil {
			t.Errorf("%s refused its own choice %q: %v", field.JSONKey, opt.Value, err)
		}
	}

	err := field.ValidateValue("not-one-of-them")
	if err == nil {
		t.Fatalf("%s accepted a value outside its choices", field.JSONKey)
	}
	for _, opt := range field.Options {
		if !strings.Contains(err.Error(), opt.Value) {
			t.Errorf("refusal is %q, want it to offer %q", err, opt.Value)
		}
	}
	if !strings.Contains(err.Error(), "not-one-of-them") {
		t.Errorf("refusal is %q, want it to quote the value that was sent", err)
	}
}
