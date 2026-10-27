// SPDX-License-Identifier: MIT

// Command gen emits the TypeScript projection of the settings field registry and the
// docs/settings.md reference, so the dashboard's types, the documentation and the Go
// source of truth cannot drift. It is run by the //go:generate directive in
// internal/config/settingsfield.go; the tests compare both renders against the
// checked-in files on every test run, so a stale copy fails the suite rather than
// waiting for the ship gate.
//
// Usage: go generate ./internal/config  (or: go run ./internal/config/gen)
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
)

// preamble is the hand-written head of the generated module: the file banner, the string
// unions the schema's enums serialize as, and the interfaces describing the tables below
// it. It is a TypeScript file rather than a Go string so it reads and edits as the
// TypeScript it becomes.
//
//go:embed preamble.ts.tmpl
var preamble string

// preambleLF is what actually gets written. go:embed hands over whatever the checkout
// put on disk, and git rewrites text line endings on a Windows one -- so without this the
// same generator writes a different checked-in file depending on the machine it ran on.
var preambleLF = withoutCarriageReturns(preamble)

// withoutCarriageReturns rewrites CRLF line endings as LF.
func withoutCarriageReturns(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	types, err := outputPath()
	if err != nil {
		return err
	}
	reference, err := docsPath()
	if err != nil {
		return err
	}
	schema := config.SettingsCLISchema()
	// Both are rendered before either is written, so a registry entry one of them
	// refuses leaves neither file half updated.
	typesContent, err := render(schema)
	if err != nil {
		return err
	}
	referenceContent, err := renderSettingsDoc(schema)
	if err != nil {
		return err
	}
	for _, out := range []struct {
		path    string
		content []byte
	}{{types, typesContent}, {reference, referenceContent}} {
		if err := os.MkdirAll(filepath.Dir(out.path), 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
		if err := os.WriteFile(out.path, out.content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", out.path, err)
		}
	}
	return nil
}

// outputPath resolves the target file from this source file's location, so it is
// correct regardless of the working directory go generate happens to use.
func outputPath() (string, error) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate generator source path")
	}
	// self = <root>/internal/config/gen/main.go
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	return filepath.Join(root, "ui", "src", "generated", "settingsSchema.ts"), nil
}

// render projects a settings registry into the dashboard's TypeScript module. It takes
// the schema rather than reading the registry itself so a test can render one it
// authored, which is the only way to exercise a table the generator cannot serialize.
func render(schema []config.FieldSchema) ([]byte, error) {
	tables := []struct {
		name, elem, doc string
		rows            any
	}{
		{"settingsSchema", "SettingFieldSchema",
			"The settings field registry, in authored (menu and dashboard) order.", schema},
		{"settingsGroups", "SettingGroupInfo",
			"The sections a settings form renders, in display order.", config.SettingsGroups()},
		{"featureModules", "FeatureModuleInfo",
			"The optional modules, each off until its switch setting is turned on.", config.FeatureModules()},
		{"tunnelSchema", "SettingFieldSchema",
			"The connection form's field registry, in authored order. A field carrying a " +
				"variant applies only to a connection of that type.", config.TunnelSchemaStatic()},
	}

	var b bytes.Buffer
	b.WriteString(preambleLF)
	for _, t := range tables {
		if err := writeTable(&b, t.name, t.elem, t.doc, t.rows); err != nil {
			return nil, err
		}
	}

	writeSettingsInterface(&b, schema)
	b.WriteString("\n")
	writePatchInterface(&b, schema)

	return b.Bytes(), nil
}

// writeTable emits one registry side table as a readonly const of the named type. It
// marshals before it writes anything, so a table it cannot serialize aborts generation
// instead of leaving a truncated declaration in the buffer.
func writeTable(b *bytes.Buffer, name, elem, doc string, table any) error {
	pretty, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	fmt.Fprintf(b, "/** %s */\n", doc)
	fmt.Fprintf(b, "export const %s: readonly %s[] = ", name, elem)
	b.Write(pretty)
	b.WriteString(" as const\n\n")
	return nil
}

// writeSettingsInterface renders the outward view: every field by its view key, with
// secrets reduced to a presence boolean.
func writeSettingsInterface(b *bytes.Buffer, schema []config.FieldSchema) {
	b.WriteString("/** The settings document the API returns. Secrets appear only as presence\n")
	b.WriteString(" *  booleans (hasAuthKey, ...); their values are never serialized outward. */\n")
	b.WriteString("export interface Settings {\n")
	for _, f := range schema {
		if f.Secret {
			fmt.Fprintf(b, "  %s: boolean\n", tsProperty(f.ViewKey))
			continue
		}
		fmt.Fprintf(b, "  %s: %s\n", tsProperty(f.Key), tsType(f.Kind))
	}
	b.WriteString("}\n")
}

// writePatchInterface renders the write shape: only fields applied through
// PUT /api/settings, keyed by their json key, each optional so a present key means a
// change. A secret is written as its value, not a presence boolean.
func writePatchInterface(b *bytes.Buffer, schema []config.FieldSchema) {
	b.WriteString("/** A settings write. A present key changes that field; an absent key is left\n")
	b.WriteString(" *  alone. Read-only and autostart-managed fields are intentionally excluded. */\n")
	b.WriteString("export interface SettingsPatch {\n")
	for _, f := range schema {
		if f.Write != config.WritePatch {
			continue
		}
		t := tsType(f.Kind)
		if f.Secret {
			t = "string"
		}
		fmt.Fprintf(b, "  %s?: %s\n", tsProperty(f.Key), t)
	}
	b.WriteString("}\n")
}

// tsProperty renders a settings key as an interface member name. Namespaced keys like
// "proxy.enabled" are not identifiers, and emitting one bare produces a module that does
// not parse -- which surfaces as an esbuild error in an unrelated test file rather than
// as anything pointing at the registry row that caused it.
func tsProperty(key string) string {
	if !identifier.MatchString(key) {
		return strconv.Quote(key)
	}
	return key
}

// identifier matches the subset of JavaScript identifiers a settings key can be. It is
// deliberately narrower than the language's: a key outside it is quoted, which is always
// valid, so widening it would only remove quotes rather than fix anything.
var identifier = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

// tsType maps a field kind to its TypeScript type for non-secret values.
func tsType(k config.FieldKind) string {
	switch k {
	case config.KindBool:
		return "boolean"
	case config.KindInt:
		return "number"
	case config.KindStringList, config.KindTunnelRefList, config.KindCidrList,
		config.KindInterfaceAddrList, config.KindIPList:
		return "string[]"
	default:
		return "string"
	}
}
