// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// readGenerated returns the checked-in dashboard types with line endings normalized.
// git sets core.autocrlf on Windows checkouts, so the working copy of a text file there
// has CRLF endings that the generator never emits; comparing raw bytes would fail on
// that platform for a file that is perfectly up to date.
func readGenerated(t *testing.T) string {
	t.Helper()
	path, err := outputPath()
	if err != nil {
		t.Fatalf("resolve output path: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated types: %v", err)
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

// The dashboard's Settings and SettingsPatch types are projected from the Go settings
// registry. A registry change that is not regenerated ships a dashboard whose types
// describe the previous release: fields the API now rejects still typecheck, and fields
// it now accepts are invisible. The ship gate checks this by running the generator
// against the working tree, which means it cannot run in the inner loop -- so until
// someone runs verify.sh, drift is silent. render is pure, so the same guarantee is
// available here as an ordinary test.
func TestGeneratedTypeScriptMatchesTheRegistryWithoutRunningTheGenerator(t *testing.T) {
	want, err := render(config.SettingsCLISchema())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	got := readGenerated(t)
	if got != string(want) {
		t.Errorf("checked-in settingsSchema.ts is stale; run: go generate ./internal/config\n"+
			"generated %d bytes, on disk %d bytes", len(want), len(got))
	}
}

// The generated module is checked in, so every machine has to write the same bytes.
// go:embed hands the preamble over exactly as the checkout left it on disk, and git
// rewrites text line endings on a Windows checkout -- which would otherwise mean a
// `go generate` there produces a file everyone else sees as modified.
func TestTheGeneratedModuleCarriesTheSameLineEndingsOnEveryPlatform(t *testing.T) {
	if got := withoutCarriageReturns("a\r\nb\r\n"); got != "a\nb\n" {
		t.Errorf("withoutCarriageReturns left %q, want the CRLF endings rewritten", got)
	}

	out, err := render(config.SettingsCLISchema())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if i := bytes.IndexByte(out, '\r'); i >= 0 {
		t.Errorf("the generated module carries a carriage return at byte %d, so this machine "+
			"writes a file every other machine reads as changed", i)
	}
}

// outputPath walks up three directories from this source file. That is positional: move
// the generator one level and it silently writes a settingsSchema.ts into a directory
// nothing imports, while the drift check above keeps comparing against that same
// orphaned file and passes forever.
func TestOutputPathResolvesTheDashboardFileRegardlessOfWorkingDirectory(t *testing.T) {
	got, err := outputPath()
	if err != nil {
		t.Fatalf("outputPath: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("outputPath() = %q, want an absolute path so go generate's working directory cannot matter", got)
	}
	suffix := filepath.Join("ui", "src", "generated", "settingsSchema.ts")
	if !strings.HasSuffix(got, suffix) {
		t.Errorf("outputPath() = %q, want it to end in %q", got, suffix)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("outputPath() = %q, but nothing is there: %v -- the generator is writing somewhere the dashboard does not read", got, err)
	}
}

// A secret is asymmetric on the wire: outward it is a presence boolean under its view
// key, inward it is the value itself under its json key. Rendering that backwards ships
// a dashboard that PUTs `true` as an OAuth secret and shows the stored key on screen.
func TestSecretFieldsAppearAsAPresenceBooleanInSettingsAndAValueInThePatch(t *testing.T) {
	schema := []config.FieldSchema{{
		Key: "authKey", ViewKey: "hasAuthKey", Kind: config.KindSecret,
		Secret: true, Write: config.WritePatch,
	}}

	var view bytes.Buffer
	writeSettingsInterface(&view, schema)
	if want := "hasAuthKey: boolean"; !strings.Contains(view.String(), want) {
		t.Errorf("Settings interface = %q, want it to carry %q", view.String(), want)
	}
	if strings.Contains(view.String(), "authKey: string") {
		t.Errorf("Settings interface leaks the secret's value type:\n%s", view.String())
	}

	var patch bytes.Buffer
	writePatchInterface(&patch, schema)
	if want := "authKey?: string"; !strings.Contains(patch.String(), want) {
		t.Errorf("SettingsPatch = %q, want it to carry %q", patch.String(), want)
	}
	if strings.Contains(patch.String(), "hasAuthKey") {
		t.Errorf("SettingsPatch offers the presence boolean as if it were writable:\n%s", patch.String())
	}
}

// The patch type is the dashboard's contract for what PUT /api/settings will accept.
// Offering a read-only or autostart-managed field there makes the type system promise a
// write the API answers with 400, and the failure surfaces as a mystery at runtime
// rather than as a compile error.
func TestPatchInterfaceOmitsEveryFieldTheAPIWillNotAccept(t *testing.T) {
	schema := config.SettingsCLISchema()
	var patch bytes.Buffer
	writePatchInterface(&patch, schema)
	got := patch.String()

	var excluded, included int
	for _, f := range schema {
		key := "  " + tsProperty(f.Key) + "?:"
		if f.Write == config.WritePatch {
			included++
			if !strings.Contains(got, key) {
				t.Errorf("SettingsPatch is missing writable field %q", f.Key)
			}
			continue
		}
		excluded++
		if strings.Contains(got, key) {
			t.Errorf("SettingsPatch offers %q, which is written via %s, not PUT /api/settings", f.Key, f.Write)
		}
	}
	if excluded == 0 || included == 0 {
		t.Fatalf("registry no longer has both writable and non-writable fields (%d writable, %d not); this test proves nothing", included, excluded)
	}
}

// tsType's default arm quietly renders any kind it does not recognize as `string`, and
// the union it must agree with lives in the embedded preamble. A new KindDuration would
// therefore generate `duration: string` against a SettingKind union that has no
// 'duration' member -- the Go suite stays green and the dashboard fails to typecheck.
func TestTSTypeMapsEveryFieldKindToTheTypeTheUnionDeclares(t *testing.T) {
	tests := []struct {
		name string
		kind config.FieldKind
		want string
		wire string
	}{
		{"a plain string", config.KindString, "string", "string"},
		{"a boolean", config.KindBool, "boolean", "bool"},
		{"an integer", config.KindInt, "number", "int"},
		{"a list of strings", config.KindStringList, "string[]", "stringList"},
		{"a write-only secret", config.KindSecret, "string", "secret"},
		{"a path to a secret", config.KindSecretFile, "string", "secretFile"},
		{"a host:port", config.KindAddrPort, "string", "addrPort"},
		{"a URL", config.KindURL, "string", "url"},
		{"a choice from a fixed set", config.KindEnum, "string", "enum"},
		{"a device named by its stable id", config.KindNodeRef, "string", "nodeRef"},
		{"a resolver profile named by its id", config.KindProfileRef, "string", "profileRef"},
		{"a connection named by its id", config.KindTunnelRef, "string", "tunnelRef"},
		{"an ordered list of connections", config.KindTunnelRefList, "string[]", "tunnelRefList"},
		{"a list of networks", config.KindCidrList, "string[]", "cidrList"},
	}

	// The table above is authored, so on its own it says nothing about a kind added to
	// the registry and never listed here -- which is exactly the case it exists to catch.
	// Reading the kinds off the registry is what makes it a gate rather than a record of
	// the kinds someone remembered.
	listed := make(map[config.FieldKind]bool, len(tests))
	for _, tt := range tests {
		listed[tt.kind] = true
	}
	for _, f := range config.SettingsCLISchema() {
		if !listed[f.Kind] {
			t.Errorf("setting %q is a %s, a kind this test does not cover; add it above so its "+
				"TypeScript type and union member are checked", f.Key, f.Kind)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tsType(tt.kind); got != tt.want {
				t.Errorf("tsType(%v) = %q, want %q", tt.kind, got, tt.want)
			}
			if got := tt.kind.String(); got != tt.wire {
				t.Errorf("%v.String() = %q, want %q", tt.kind, got, tt.wire)
			}
			member := "'" + tt.wire + "'"
			if !strings.Contains(preamble, member) {
				t.Errorf("the SettingKind union has no %s member, so a field of this kind will not typecheck in the dashboard", member)
			}
		})
	}
}

// RestartClass and WriteVia are serialized into the schema payload as words, and the TS
// unions naming those words live in the embedded preamble. The dashboard switches on them
// to decide whether to offer "Restart node", "Restart app", or nothing at all -- a word the
// union does not carry degrades silently to no notice, and the user never restarts.
func TestEveryRestartClassAndWriteViaAppearsInTheEmbeddedUnions(t *testing.T) {
	known := []config.RestartClass{
		config.RestartNone, config.RestartPrefs, config.RestartNode, config.RestartUI,
		config.RestartApp,
	}
	for _, r := range known {
		member := "'" + r.String() + "'"
		if !strings.Contains(preamble, member) {
			t.Errorf("the RestartClass union has no %s member", member)
		}
		if got := marshalString(t, r); got != r.String() {
			t.Errorf("RestartClass(%d) marshals as %q but stringifies as %q", r, got, r.String())
		}
	}
	// The list above is written by hand, so a class added later would be checked nowhere.
	// Sweeping the schema is what catches that: a field declaring a class the list forgot
	// is a word already on the wire.
	declared := map[config.RestartClass]bool{}
	for _, r := range known {
		declared[r] = true
	}
	for _, f := range config.SettingsCLISchema() {
		if !declared[f.Restart] {
			t.Errorf("%s declares restart class %q, which this test does not check against "+
				"the TS union", f.Key, f.Restart)
		}
	}
	for _, w := range []config.WriteVia{config.WritePatch, config.WriteAutostart, config.WriteNone} {
		member := "'" + w.String() + "'"
		if !strings.Contains(preamble, member) {
			t.Errorf("the WriteVia union has no %s member", member)
		}
		if got := marshalString(t, w); got != w.String() {
			t.Errorf("WriteVia(%d) marshals as %q but stringifies as %q", w, got, w.String())
		}
	}
}

// The group and module tables are emitted verbatim as typed consts, so a section or
// module added to the registry without its union member makes settingsSchema.ts fail to
// typecheck -- which surfaces as a broken dashboard build rather than as a Go test
// failure naming the line that has to change.
func TestEverySectionAndModuleAppearsInTheEmbeddedUnions(t *testing.T) {
	for _, g := range config.SettingsGroups() {
		member := "'" + marshalString(t, g.ID) + "'"
		if !strings.Contains(preamble, member) {
			t.Errorf("the SettingGroup union has no %s member, so the generated settingsGroups table will not typecheck", member)
		}
	}
	for _, m := range config.FeatureModules() {
		member := "'" + marshalString(t, m.ID) + "'"
		if !strings.Contains(preamble, member) {
			t.Errorf("the FeatureModule union has no %s member, so the generated featureModules table will not typecheck", member)
		}
	}
}

// A generator that silently emitted an empty table would satisfy the drift test forever,
// because the checked-in file it is compared against would be empty too. Every table the
// dashboard reads has to arrive non-empty and with distinct ids.
func TestEveryGeneratedTableIsNonEmptyAndFreeOfDuplicateIDs(t *testing.T) {
	fieldKeys := make(map[string]bool)
	for _, f := range config.SettingsCLISchema() {
		if fieldKeys[f.Key] {
			t.Errorf("two registry fields share the key %q", f.Key)
		}
		fieldKeys[f.Key] = true
	}
	connectionKeys := make(map[string]bool)
	for _, f := range config.TunnelSchemaStatic() {
		if connectionKeys[f.Key] {
			t.Errorf("two connection fields share the key %q", f.Key)
		}
		connectionKeys[f.Key] = true
	}
	if len(connectionKeys) == 0 {
		t.Error("the connection table generated empty, so the connection form has no fields")
	}
	if len(fieldKeys) == 0 {
		t.Error("the settings schema is empty; the drift test would compare an empty file against an empty render forever")
	}

	groupIDs := make(map[string]bool)
	for _, g := range config.SettingsGroups() {
		id := marshalString(t, g.ID)
		if groupIDs[id] {
			t.Errorf("two sections share the id %q", id)
		}
		groupIDs[id] = true
		if g.Label == "" || g.Description == "" {
			t.Errorf("section %q has an empty label or description; the dashboard renders both verbatim", id)
		}
	}
	if len(groupIDs) == 0 {
		t.Error("the section table is empty")
	}

	moduleIDs := make(map[string]bool)
	for _, m := range config.FeatureModules() {
		id := marshalString(t, m.ID)
		if moduleIDs[id] {
			t.Errorf("two modules share the id %q", id)
		}
		moduleIDs[id] = true
		if m.Label == "" || m.Description == "" {
			t.Errorf("module %q has an empty label or description", id)
		}
		if !fieldKeys[m.SwitchKey] {
			t.Errorf("module %q names switch key %q, which is not a registry field", id, m.SwitchKey)
		}
	}
	if len(moduleIDs) == 0 {
		t.Error("the module table is empty")
	}
}

func marshalString(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %v: %v", v, err)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%v marshalled as %s, which is not a JSON string", v, raw)
	}
	return s
}

// Settings keys are namespaced once a module owns several of them, and "proxy.enabled"
// is not a JavaScript identifier. Emitting one bare produces a settingsSchema.ts that
// does not parse, which fails every dashboard test at once with an esbuild error naming
// a file nobody edited -- and never names the registry row that caused it.
func TestNamespacedKeysAreEmittedAsPropertyNamesThatParse(t *testing.T) {
	schema := []config.FieldSchema{
		{Key: "proxy.enabled", ViewKey: "proxy.enabled", Kind: config.KindBool, Write: config.WritePatch},
		{Key: "proxy.token", ViewKey: "proxy.hasToken", Kind: config.KindSecret, Secret: true, Write: config.WritePatch},
		{Key: "hostname", ViewKey: "hostname", Kind: config.KindString, Write: config.WritePatch},
	}

	var view bytes.Buffer
	writeSettingsInterface(&view, schema)
	for _, want := range []string{`"proxy.enabled": boolean`, `"proxy.hasToken": boolean`, "hostname: string"} {
		if !strings.Contains(view.String(), want) {
			t.Errorf("Settings interface is missing %q:\n%s", want, view.String())
		}
	}

	var patch bytes.Buffer
	writePatchInterface(&patch, schema)
	for _, want := range []string{`"proxy.enabled"?: boolean`, `"proxy.token"?: string`, "hostname?: string"} {
		if !strings.Contains(patch.String(), want) {
			t.Errorf("SettingsPatch is missing %q:\n%s", want, patch.String())
		}
	}
}

// Every key the registry actually carries has to survive that rule, not just the ones
// this file thought to name.
func TestEveryRegistryKeyRendersAsAValidPropertyName(t *testing.T) {
	valid := regexp.MustCompile(`^([A-Za-z_$][A-Za-z0-9_$]*|"[^"\\]*")$`)
	for _, f := range config.SettingsCLISchema() {
		for _, key := range []string{f.Key, f.ViewKey} {
			if got := tsProperty(key); !valid.MatchString(got) {
				t.Errorf("tsProperty(%q) = %s, which is not a property name TypeScript accepts", key, got)
			}
		}
	}
}

// A registry entry's Default is an `any`, so a field can be authored carrying a value no
// JSON encoder can represent. Generation must abort on that rather than write the module
// it got as far as: a truncated settingsSchema.ts fails to parse, and the drift test then
// reports "stale types" for a file that is not stale but broken.
func TestRenderAbortsOnARegistryEntryItCannotSerialize(t *testing.T) {
	_, err := render([]config.FieldSchema{{Key: "unserializable", Default: make(chan int)}})
	if err == nil {
		t.Fatal("render accepted a field whose default cannot be marshalled; the generator " +
			"would write a truncated TypeScript module")
	}
	if !strings.Contains(err.Error(), "settingsSchema") {
		t.Errorf("render error = %q, want it to name the table that failed", err)
	}
}

// writeTable marshals before it writes so that a failure leaves the buffer untouched.
// Writing the declaration first and the rows second would emit `export const x = ` with
// no value, which is a syntax error a reader would blame on the registry rather than on
// the generator giving up halfway.
func TestWriteTableEmitsNothingWhenItCannotSerializeTheTable(t *testing.T) {
	var b bytes.Buffer
	err := writeTable(&b, "broken", "Broken", "doc", map[string]any{"rows": make(chan int)})
	if err == nil {
		t.Fatal("writeTable accepted an unserializable table")
	}
	if b.Len() != 0 {
		t.Errorf("writeTable wrote %q before failing; a partial declaration does not parse", b.String())
	}
}
