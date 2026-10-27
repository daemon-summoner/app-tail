// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// gadget stands in for the second kind of configurable thing the registry exists to
// serve. It is deliberately not Settings: everything asserted below has to hold for an
// entity the settings table knows nothing about, or the machinery is not generic and the
// next entity gets a hand-written validator after all.
type gadget struct {
	Name   string
	Port   int
	Secret string
	Tags   []string
}

var gadgetFields = []FieldOf[gadget]{
	{
		JSONKey: "name", CLIName: "name", Kind: KindString,
		Label: "Name", Group: GroupIdentity, Tier: TierBasic,
		Default: "unnamed", Help: "What this gadget is called.",
		get: func(g *gadget) any { return g.Name },
		set: func(g *gadget, v any) { g.Name = typed[string](v) },
	},
	{
		JSONKey: "port", CLIName: "port", Kind: KindInt,
		Label: "Port", Group: GroupIdentity, Tier: TierBasic,
		Default: 8080, Constraint: between(1, 65535), Help: "Which port it listens on.",
		get: func(g *gadget) any { return g.Port },
		set: func(g *gadget, v any) { g.Port = typed[int](v) },
	},
	{
		JSONKey: "secret", ViewKey: "hasSecret", Kind: KindSecret,
		Label: "Secret", Group: GroupIdentity, Tier: TierAdvanced,
		Help:    "Never returned once stored.",
		get:     func(g *gadget) any { return g.Secret },
		set:     func(g *gadget, v any) { g.Secret = typed[string](v) },
		present: func(g *gadget) bool { return g.Secret != "" },
	},
	{
		JSONKey: "tags", CLIName: "tags", Kind: KindStringList,
		Label: "Tags", Group: GroupIdentity, Tier: TierAdvanced,
		Help: "Labels carried alongside.",
		get:  func(g *gadget) any { return g.Tags },
		set:  func(g *gadget, v any) { g.Tags = typed[[]string](v) },
	},
	{
		JSONKey: "kind", Kind: KindString, Write: WriteNone,
		Label: "Kind", Group: GroupIdentity, Tier: TierBasic,
		Derived: true, Help: "Computed, never stored.",
		derive: func(g gadget, _ *Settings) any { return "gadget/" + g.Name },
	},
}

func gadgetRegistry(t *testing.T) *Registry[gadget] {
	t.Helper()
	return NewRegistry(gadgetFields)
}

func patch(t *testing.T, pairs ...string) map[string]json.RawMessage {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatalf("patch takes key/value pairs, got %d arguments", len(pairs))
	}
	out := make(map[string]json.RawMessage, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out[pairs[i]] = json.RawMessage(pairs[i+1])
	}
	return out
}

// The whole point of the registry: an entity that is not Settings gets the view, the
// patch and the schema without writing any of them.
func TestASecondEntityGetsTheViewWithoutWritingOne(t *testing.T) {
	r := gadgetRegistry(t)
	g := gadget{Name: "widget", Port: 9000, Secret: "hunter2", Tags: []string{"a"}}

	view := r.View(g, &Settings{})

	if view["name"] != "widget" || view["port"] != 9000 {
		t.Errorf("view = %v, want the stored name and port", view)
	}
	if view["kind"] != "gadget/widget" {
		t.Errorf("kind = %v, want the derived value", view["kind"])
	}
	// A secret reports presence under its view key and its value under no key at all.
	if view["hasSecret"] != true {
		t.Errorf("hasSecret = %v, want true", view["hasSecret"])
	}
	if _, leaked := view["secret"]; leaked {
		t.Error("the view carries the secret's value, not only its presence")
	}
}

func TestAPatchWritesOnlyTheKeysItCarried(t *testing.T) {
	r := gadgetRegistry(t)
	g := gadget{Name: "widget", Port: 9000, Tags: []string{"a"}}

	if err := r.ApplyPatch(&g, &Settings{}, patch(t, "port", "1234")); err != nil {
		t.Fatalf("applying a patch: %v", err)
	}

	if g.Port != 1234 {
		t.Errorf("port = %d, want 1234", g.Port)
	}
	if g.Name != "widget" || len(g.Tags) != 1 {
		t.Errorf("gadget = %+v, want the absent keys left alone", g)
	}
}

// A bound declared once in the table has to be enforced on every surface. If the generic
// applier skipped Constraint, an out-of-range value would be stored and only refused
// later by whichever consumer happened to re-check it.
func TestAPatchIsRefusedByTheBoundTheTableDeclares(t *testing.T) {
	r := gadgetRegistry(t)
	g := gadget{Port: 9000}

	err := r.ApplyPatch(&g, &Settings{}, patch(t, "port", "70000"))

	if err == nil {
		t.Fatal("a port above the declared maximum was accepted")
	}
	if !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "65535") {
		t.Errorf("error = %q, want it to name the field and the bound", err)
	}
	if g.Port != 9000 {
		t.Errorf("port = %d, want the stored value left alone after a refusal", g.Port)
	}
}

func TestAnUnknownKeyIsRefusedByName(t *testing.T) {
	r := gadgetRegistry(t)
	g := gadget{}

	err := r.ApplyPatch(&g, &Settings{}, patch(t, "colour", `"red"`))

	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(err.Error(), "colour") {
		t.Errorf("error = %q, want it to name the unknown key", err)
	}
}

// A derived field is computed from the others, so accepting a write to one would store a
// value that the next read silently replaces.
func TestADerivedFieldIsReadOnly(t *testing.T) {
	r := gadgetRegistry(t)
	g := gadget{Name: "widget"}

	err := r.ApplyPatch(&g, &Settings{}, patch(t, "kind", `"something else"`))

	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("error = %v, want a refusal saying the field is read-only", err)
	}
}

// The dashboard renders a stored secret as the redaction mask, so saving an untouched
// form sends the mask back. Storing it would replace the secret with the word that stands
// in for it -- and the failure only shows up the next time the secret is used.
func TestSavingTheRedactionMaskLeavesTheStoredSecretAlone(t *testing.T) {
	r := gadgetRegistry(t)
	g := gadget{Secret: "hunter2"}

	if err := r.ApplyPatch(&g, &Settings{}, patch(t, "secret", `"`+RedactedSecret+`"`)); err != nil {
		t.Fatalf("applying a patch: %v", err)
	}

	if g.Secret != "hunter2" {
		t.Errorf("secret = %q, want the stored value untouched", g.Secret)
	}
}

func TestDefaultsComeFromTheTable(t *testing.T) {
	r := gadgetRegistry(t)
	var g gadget

	r.Defaults(&g)

	if g.Name != "unnamed" || g.Port != 8080 {
		t.Errorf("gadget = %+v, want the declared defaults", g)
	}
}

// A schema a client cannot tell apart from a settings schema is what makes one form
// component render both. Anything missing here is a control the dashboard cannot draw.
func TestTheSchemaCarriesWhatAFormNeedsToRenderTheEntity(t *testing.T) {
	r := gadgetRegistry(t)

	schema := r.Schema()

	if len(schema) != len(gadgetFields) {
		t.Fatalf("schema has %d entries, want %d", len(schema), len(gadgetFields))
	}
	byKey := make(map[string]FieldSchema, len(schema))
	for _, f := range schema {
		byKey[f.Key] = f
	}
	if got := byKey["port"]; got.Default != 8080 || got.Constraint.Max == nil || *got.Constraint.Max != 65535 {
		t.Errorf("port schema = %+v, want the declared default and bound", got)
	}
	if got := byKey["secret"]; !got.Secret || got.ViewKey != "hasSecret" {
		t.Errorf("secret schema = %+v, want it marked secret and pointed at its view key", got)
	}
	if got := byKey["kind"]; !got.ReadOnly || !got.Derived {
		t.Errorf("kind schema = %+v, want it marked derived and read-only", got)
	}
	// Availability is resolved against the app rather than the entity, and every gadget
	// field is core, so the served schema reports them all writable with no reason.
	for _, f := range r.SchemaFor(&Settings{}) {
		if f.Derived || f.Write == WriteNone {
			continue
		}
		if f.Available == nil || !*f.Available {
			t.Errorf("%s reads as unavailable (%q) with nothing gating it", f.Key, f.AvailableReason)
		}
	}
}

// Two fields answering to one wire key means whichever the index happened to keep is the
// only one that can ever be written, and the other silently cannot be. Failing at
// construction is what turns that into a test failure rather than a missing control.
func TestATableWithADuplicateKeyIsRefusedRatherThanIndexed(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a table with two fields under one wire key was accepted")
		}
		if !strings.Contains(fmtPanic(r), "wire keys") {
			t.Errorf("panic = %v, want it to say the wire keys collide", r)
		}
	}()

	NewRegistry([]FieldOf[gadget]{
		{JSONKey: "name", Kind: KindString},
		{JSONKey: "name", Kind: KindInt},
	})
}

func fmtPanic(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
