// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

// docs/settings.md is the reference a person reads before touching a setting. A registry
// change that is not regenerated documents the previous release: a default that moved, a
// flag that was renamed, a setting that no longer exists.
func TestTheSettingsReferenceMatchesTheRegistry(t *testing.T) {
	want, err := renderSettingsDoc(config.SettingsCLISchema())
	if err != nil {
		t.Fatalf("renderSettingsDoc: %v", err)
	}
	path, err := docsPath()
	if err != nil {
		t.Fatalf("docsPath: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the settings reference: %v", err)
	}
	if got := strings.ReplaceAll(string(raw), "\r\n", "\n"); got != string(want) {
		t.Errorf("checked-in docs/settings.md is stale; run: go generate ./internal/config\n"+
			"generated %d bytes, on disk %d bytes", len(want), len(got))
	}
}

func TestDocsPathResolvesTheSettingsReferenceRegardlessOfWorkingDirectory(t *testing.T) {
	got, err := docsPath()
	if err != nil {
		t.Fatalf("docsPath: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("docsPath() = %q, want an absolute path", got)
	}
	if want := filepath.Join("docs", "settings.md"); !strings.HasSuffix(got, want) {
		t.Errorf("docsPath() = %q, want it to end in %q", got, want)
	}
	if _, err := os.Stat(filepath.Dir(got)); err != nil {
		t.Errorf("docsPath() = %q, but its directory is missing: %v", got, err)
	}
}

// rowOf returns the table row documenting key, split into its cells.
func rowOf(t *testing.T, doc, key string) []string {
	t.Helper()
	prefix := "| `" + key + "` |"
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, prefix) {
			return splitRow(line)
		}
	}
	t.Fatalf("no row documents %q in:\n%s", key, doc)
	return nil
}

// splitRow splits a Markdown table row on its unescaped pipes.
func splitRow(line string) []string {
	var cells []string
	var cell strings.Builder
	for i := 1; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line) && line[i+1] == '|':
			cell.WriteString(`\|`)
			i++
		case line[i] == '|':
			cells = append(cells, strings.TrimSpace(cell.String()))
			cell.Reset()
		default:
			cell.WriteByte(line[i])
		}
	}
	return cells
}

func TestTheSettingsReferenceDocumentsEachSettingWhereAReaderLooksForIt(t *testing.T) {
	one, three := 1, 3
	schema := []config.FieldSchema{
		{
			Key: "proxy.token", CLIName: "proxy-token", Kind: config.KindSecret, Secret: true,
			Label: "Proxy token", Group: config.GroupProxy, Module: config.ModuleProxy,
			Tier: config.TierAdvanced, Default: "never-print-me",
			Help: "Callers send it as user|pass.\nWrite-only.",
		},
		{
			Key: "hostname", CLIName: "hostname", Kind: config.KindString,
			Label: "Device name", Group: config.GroupIdentity, Restart: config.RestartNode,
			Help: "Device name on the tailnet.", Pinnable: []string{"APPTAIL_HOSTNAME"},
		},
		{
			Key: "proxy.enabled", CLIName: "proxy", Kind: config.KindBool,
			Label: "Proxy", Group: config.GroupProxy, ModuleSwitch: config.ModuleProxy,
			Help: "Run the proxy.",
		},
		{
			Key: "ips.mode", CLIName: "ips-mode", Kind: config.KindEnum,
			Label: "Mode", Group: config.GroupIPS, Default: "detect",
			Options: []config.EnumOption{{Value: "detect"}, {Value: "prevent"}},
			Help:    "What a match does.",
		},
		{
			Key: "dnsBlock.refreshHours", CLIName: "dns-block-refresh-hours", Kind: config.KindInt,
			Label: "Refresh", Group: config.GroupDNSBlock, Default: 1,
			Constraint: config.Constraint{Min: &one, Max: &three}, Help: "Hours between downloads.",
		},
		{
			Key: "stateDir", Kind: config.KindString, ReadOnly: true, Write: config.WriteNone,
			Label: "State directory", Group: config.GroupAbout, Help: "Where state lives.",
		},
	}
	out, err := renderSettingsDoc(schema)
	if err != nil {
		t.Fatalf("renderSettingsDoc: %v", err)
	}
	doc := string(out)

	if strings.Contains(doc, "never-print-me") {
		t.Error("the reference printed a secret's stored default; secrets are write-only everywhere")
	}
	token := rowOf(t, doc, "proxy.token")
	if len(token) != 6 {
		t.Fatalf("proxy.token row has %d cells, want 6 -- an unescaped pipe in the help split it: %q", len(token), token)
	}
	if token[3] != "write-only" {
		t.Errorf("secret default cell = %q, want write-only", token[3])
	}
	if !strings.Contains(token[5], `user\|pass`) || strings.Contains(token[5], "\n") {
		t.Errorf("secret description = %q, want its pipe escaped and its newline flattened", token[5])
	}
	if !strings.Contains(token[5], "`proxy.enabled`") {
		t.Errorf("proxy.token description = %q, want it to name the switch it waits on", token[5])
	}

	if !strings.Contains(rowOf(t, doc, "proxy.enabled")[5], "Turns the whole") {
		t.Error("the proxy's master switch is not marked as the switch for its feature")
	}
	if got := rowOf(t, doc, "proxy.enabled")[3]; got != "off" {
		t.Errorf("an unset bool default renders as %q, want off", got)
	}
	host := rowOf(t, doc, "hostname")
	if host[1] != "`--hostname`" || host[4] != "after `app-tail restart`" {
		t.Errorf("hostname row = %q, want its CLI flag and its restart class", host)
	}
	if !strings.Contains(host[5], "`APPTAIL_HOSTNAME`") {
		t.Errorf("hostname description = %q, want the environment variable that pins it", host[5])
	}
	if got := rowOf(t, doc, "ips.mode")[2]; !strings.Contains(got, "`detect`") || !strings.Contains(got, "`prevent`") {
		t.Errorf("enum type cell = %q, want every choice listed", got)
	}
	if got := rowOf(t, doc, "dnsBlock.refreshHours")[2]; got != "number, 1 to 3" {
		t.Errorf("bounded int type cell = %q, want its range", got)
	}
	state := rowOf(t, doc, "stateDir")
	if state[1] != "" || !strings.Contains(state[5], "Read-only") {
		t.Errorf("stateDir row = %q, want no CLI flag and a read-only note", state)
	}

	identity := strings.Index(doc, "\n## Identity")
	proxy := strings.Index(doc, "\n## Proxy")
	about := strings.Index(doc, "\n## About")
	if identity < 0 || proxy < 0 || about < 0 || !(identity < proxy && proxy < about) {
		t.Errorf("sections out of display order: identity at %d, proxy at %d, about at %d", identity, proxy, about)
	}
	if strings.Contains(doc, "\n## Routing") {
		t.Error("the reference drew a section no setting is in")
	}
}

func TestTheSettingsReferenceRefusesARowItCannotDescribe(t *testing.T) {
	cases := map[string]config.FieldSchema{
		"default of a type the reference has no words for": {
			Key: "odd", Kind: config.KindString, Group: config.GroupIdentity, Default: 1.5, Help: "x",
		},
		"kind the reference has no words for": {
			Key: "odder", Kind: config.FieldKind(250), Group: config.GroupIdentity, Help: "x",
		},
		"section that does not exist": {
			Key: "lost", Kind: config.KindBool, Group: config.Group(250), Help: "x",
		},
	}
	for name, field := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := renderSettingsDoc([]config.FieldSchema{field}); err == nil {
				t.Fatalf("renderSettingsDoc accepted %+v; the reference would silently misdescribe or drop it", field)
			} else if !strings.Contains(err.Error(), field.Key) {
				t.Errorf("error %q does not name the setting %q", err, field.Key)
			}
		})
	}
}
