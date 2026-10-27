// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// jsonTag returns the wire key a struct field serializes to, or "" if the field
// is not serialized.
func jsonTag(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	return strings.Split(tag, ",")[0]
}

// bookkeeping names the stored keys that are not settings: nobody chooses them, no
// surface offers them, and the app writes them about itself. Every other key must be in
// the registry, which is what the two guards below enforce. Adding to this map is a
// decision to keep a value out of the view, the patch, the CLI and the generated types.
var bookkeeping = map[string]bool{
	// What a module's settings held when it was switched off, restored when it comes
	// back on. It mirrors registry fields rather than being one.
	"shelvedSettings": true,
}

// The registry is the single source of truth: adding a field to Settings without a
// registry entry means the new setting silently never reaches the view, the patch,
// the CLI, or the generated types. This is the guard that turns that mistake into a
// failing test rather than a runtime gap.
func TestEverySettingsStructFieldIsRegistered(t *testing.T) {
	registered := make(map[string]SettingField, len(settingsFields))
	for _, f := range settingsFields {
		registered[f.JSONKey] = f
	}

	st := reflect.TypeOf(Settings{})
	for i := range st.NumField() {
		key := jsonTag(st.Field(i))
		if key == "" || bookkeeping[key] {
			continue
		}
		f, ok := registered[key]
		if !ok {
			t.Errorf("Settings field %q (json %q) has no registry entry", st.Field(i).Name, key)
			continue
		}
		if f.Derived {
			t.Errorf("field %q maps to a stored struct field but is marked Derived", key)
		}
		if f.get == nil {
			t.Errorf("field %q has no get closure, so its value can never be read", key)
		}
	}
}

// The reverse guard: a registry entry whose JSONKey names no struct field (and is not
// derived) would try to read or write a field that does not exist.
func TestNoStaleRegistryKeys(t *testing.T) {
	structKeys := make(map[string]bool)
	st := reflect.TypeOf(Settings{})
	for i := range st.NumField() {
		if key := jsonTag(st.Field(i)); key != "" {
			structKeys[key] = true
		}
	}

	for _, f := range settingsFields {
		if f.Derived {
			continue
		}
		if !structKeys[f.JSONKey] {
			t.Errorf("registry key %q names no Settings struct field and is not Derived", f.JSONKey)
		}
	}
}

// Every registry field must be internally consistent: secrets carry a presence probe
// and no plain getter in the view, writable non-secret fields carry a setter, and
// read-only/derived fields carry neither.
func TestRegistryClosuresMatchTheirKind(t *testing.T) {
	for _, f := range settingsFields {
		switch {
		case f.Derived:
			if f.derive == nil {
				t.Errorf("derived field %q has no derive closure", f.JSONKey)
			}
		case f.Kind == KindSecret:
			if f.present == nil {
				t.Errorf("secret field %q has no present closure", f.JSONKey)
			}
			if f.ViewKey == "" {
				t.Errorf("secret field %q must set ViewKey so the view never carries its json key", f.JSONKey)
			}
		}
		writable := f.Write == WritePatch
		if writable && f.set == nil {
			t.Errorf("writable field %q has no set closure", f.JSONKey)
		}
		if !writable && !f.Derived && f.set != nil {
			t.Errorf("non-writable field %q has a set closure that can never be reached through a patch", f.JSONKey)
		}
	}
}

// The view must report a secret only as a presence boolean; the raw value and the raw
// json key must never appear.
func TestViewNeverLeaksSecretsAndUsesPresenceKeys(t *testing.T) {
	cfg := Defaults()
	ts, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatal(err)
	}
	ts.AuthKey = "tskey-auth-leak-me"
	ts.OAuthClientSecret = "tskey-client-leak-me"

	// The view the API serves, which is where a leak would actually reach a client: the
	// settings document's own fields plus the credentials that moved onto the connection.
	view := SettingsViewOf(cfg)

	if _, ok := view["authKey"]; ok {
		t.Error("view carries the raw authKey key")
	}
	if _, ok := view["oauthClientSecret"]; ok {
		t.Error("view carries the raw oauthClientSecret key")
	}
	if got, _ := view["hasAuthKey"].(bool); !got {
		t.Error("hasAuthKey is not true for a stored auth key")
	}
	if got, _ := view["hasOAuthClientSecret"].(bool); !got {
		t.Error("hasOAuthClientSecret is not true for a stored OAuth secret")
	}

	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	for _, secret := range []string{"tskey-auth-leak-me", "tskey-client-leak-me"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("view leaked secret %q: %s", secret, raw)
		}
	}
}

// The view's key set must be exactly the registry's view keys -- no missing field, no
// stray key -- so a consumer rendering from the schema sees every value.
func TestViewKeySetMatchesTheRegistry(t *testing.T) {
	view := BuildSettingsView(Settings{})
	if len(view) != len(settingsFields) {
		t.Fatalf("view has %d keys, registry has %d fields", len(view), len(settingsFields))
	}
	for _, f := range settingsFields {
		if _, ok := view[f.viewKey()]; !ok {
			t.Errorf("view is missing the key %q for field %q", f.viewKey(), f.JSONKey)
		}
	}
}

// A patch applied through the driver must actually reach the stored struct field for
// every writable field -- the round trip proves the get/set closures target the same
// field, which is what keeps the view honest about what a write did.
func TestApplyPatchRoundTripsEachWritableField(t *testing.T) {
	for _, f := range settingsFields {
		if f.Write != WritePatch {
			continue
		}
		if !f.onThisPlatform() {
			// No settings value makes this writable here, which is the point of the
			// gate. TestAPlatformGatedSettingIsRefusedOffItsPlatform covers the refusal.
			continue
		}
		want := sampleFor(t, f)
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal sample for %q: %v", f.JSONKey, err)
		}

		var s Settings
		enableModuleOf(t, &s, f)
		if err := ApplySettingsPatch(&s, map[string]json.RawMessage{f.JSONKey: raw}); err != nil {
			t.Fatalf("apply %q: %v", f.JSONKey, err)
		}
		if f.get == nil {
			continue
		}
		if got := f.get(&s); !reflect.DeepEqual(got, want) {
			t.Errorf("field %q round-trip: stored %#v, want %#v", f.JSONKey, got, want)
		}
	}
}

// enableModuleOf turns on the module owning f, so a round trip exercises the field
// rather than stopping at the availability rejection.
func enableModuleOf(t *testing.T, s *Settings, f SettingField) {
	t.Helper()
	if f.Module == ModuleCore {
		return
	}
	sw, ok := moduleSwitchFor(f.Module)
	if !ok {
		t.Fatalf("field %q belongs to module %s, which has no switch", f.JSONKey, f.Module)
	}
	sw.set(s, true)
}

// sampleFor returns a non-zero value of the type this field's setter expects, in the
// shape its kind requires and inside whatever the field itself declares: a generic
// word, or a number outside a declared range, would be turned away by validation
// rather than round-tripped.
//
// Candidates are offered to the field's own validation rather than chosen by kind
// alone. Two fields of one kind can demand incompatible formats -- qualified tags and
// port numbers are both string lists -- and a per-field table here would be the second
// list of settings this registry exists to prevent.
func sampleFor(t *testing.T, f SettingField) any {
	t.Helper()
	candidates := sampleCandidates(f)
	for _, candidate := range candidates {
		if f.ValidateValue(candidate) == nil {
			return candidate
		}
	}
	t.Fatalf("no sample value satisfies field %q; add one to sampleCandidates for kind %s",
		f.JSONKey, f.Kind)
	return nil
}

// sampleCandidates offers values of a kind's Go type, most generic first. A field whose
// format none of them fit fails sampleFor loudly, which is the prompt to add one here.
func sampleCandidates(f SettingField) []any {
	switch f.Kind {
	case KindBool:
		return []any{true}
	case KindInt:
		return []any{withinBounds(f.Constraint, 4242)}
	case KindStringList:
		return []any{
			[]string{"tag:alpha", "tag:beta"},
			[]string{"22", "8080"},
			[]string{`a sample signature = "sample-bytes"`},
		}
	case KindTunnelRefList:
		return []any{[]string{"tn_alpha", "tn_beta"}}
	case KindCidrList:
		return []any{[]netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}}
	case KindAddrPort:
		return []any{"127.0.0.1:19191"}
	case KindURL:
		return []any{"https://control.example.com"}
	case KindEnum:
		// The last option rather than the first: a field's default is usually the
		// first, and a round trip that stores the default proves nothing.
		return []any{f.Options[len(f.Options)-1].Value}
	default:
		return []any{"sample-value"}
	}
}

// withinBounds pulls n inside a declared range, so a field with tighter bounds than
// the generic sample still round-trips a value it accepts.
func withinBounds(c Constraint, n int) int {
	if c.Max != nil && n > *c.Max {
		n = *c.Max
	}
	if c.Min != nil && n < *c.Min {
		n = *c.Min
	}
	return n
}

// A read-only field is rejected by name rather than silently applied.
func TestApplyPatchRejectsReadOnlyDerivedAndAutostartKeys(t *testing.T) {
	// Through the document rather than the settings alone: effectiveHostname is a derived
	// field of the connection now, and a client sending it is owed the same sentence
	// whichever table it landed in.
	cases := map[string]string{
		"stateDir":          "is read-only",
		"machineId":         "is read-only",
		"effectiveHostname": "is read-only",
		"startAtLogin":      "autostart",
		"notAKey":           "not a known setting",
	}
	for key, wantMsg := range cases {
		cfg := Defaults()
		err := ApplyPatchTo(cfg, map[string]json.RawMessage{key: json.RawMessage(`true`)})
		if err == nil {
			t.Errorf("patch with %q was accepted, want rejection", key)
			continue
		}
		if !strings.Contains(err.Error(), wantMsg) {
			t.Errorf("patch with %q: error %q does not mention %q", key, err.Error(), wantMsg)
		}
	}
}

// A patch is JSON from a client, so a value of the wrong shape is an ordinary request,
// not an internal error. It must be refused by the key the client sent, and it must leave
// the settings it was applied to untouched -- a partially applied patch would persist a
// half-configured node under a save the client was told had failed.
func TestApplyPatchRejectsAValueOfTheWrongShapeAndChangesNothing(t *testing.T) {
	cases := map[string]json.RawMessage{
		"ephemeral":            json.RawMessage(`"yes"`),
		"udpBufferBytes":       json.RawMessage(`"large"`),
		"tags":                 json.RawMessage(`"tag:one"`),
		"udpSessionTimeoutSec": json.RawMessage(`{}`),
	}
	for key, raw := range cases {
		before := Defaults().Settings
		s := before
		err := ApplySettingsPatch(&s, map[string]json.RawMessage{key: raw})
		if err == nil {
			t.Errorf("patch %s=%s was accepted, want rejection", key, raw)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("patch %s=%s: error %q does not name the key the client sent", key, raw, err)
		}
		if !reflect.DeepEqual(s, before) {
			t.Errorf("patch %s=%s was refused but still mutated the settings", key, raw)
		}
	}
}

// A list of networks arrives as an array of strings, and a client that sends one string
// instead is the ordinary mistake. The refusal has to show the shape that would work,
// because the field's own name says "networks" and gives no clue that a comma-separated
// line is not what the wire takes.
func TestARouteListSentAsAnythingButAnArrayIsRefusedWithTheShapeThatWorks(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`"10.0.0.0/24"`),
		json.RawMessage(`{"networks":["10.0.0.0/24"]}`),
		json.RawMessage(`7`),
	} {
		cfg := Defaults()
		err := ApplyPatchTo(cfg, map[string]json.RawMessage{
			"routes.enabled":   json.RawMessage(`true`),
			"routes.advertise": raw,
		})
		if err == nil {
			t.Errorf("patch routes.advertise=%s was accepted, want rejection", raw)
			continue
		}
		if !strings.Contains(err.Error(), "routes.advertise") {
			t.Errorf("patch routes.advertise=%s: error %q does not name the key the client sent", raw, err)
		}
		if !strings.Contains(err.Error(), `["10.0.0.0/24"]`) {
			t.Errorf("patch routes.advertise=%s: error %q does not show the shape that would work", raw, err)
		}
		primary, _ := cfg.Tunnel(PrimaryTunnelID)
		if got := primary.TS().RoutesAdvertise; len(got) != 0 {
			t.Errorf("patch routes.advertise=%s was refused but still stored %v", raw, got)
		}
	}
}

// The patch decoder and the document validator must agree: a value the file would be
// rejected for is a value the API refuses, attributed to its key. Skipping the rule on
// the patch path would store a setting that then makes the config unloadable on the next
// start -- a write that succeeds and a process that will not come back.
func TestApplyPatchEnforcesTheSameRulesTheDocumentValidatorDoes(t *testing.T) {
	cases := map[string]json.RawMessage{
		"udpBufferBytes":       json.RawMessage(`70000`),
		"udpSessionTimeoutSec": json.RawMessage(`-1`),
		"uiListenAddr":         json.RawMessage(`"0.0.0.0:8377"`),
		"tags":                 json.RawMessage(`["app-tail"]`),
	}
	for key, raw := range cases {
		s := Defaults().Settings
		err := ApplySettingsPatch(&s, map[string]json.RawMessage{key: raw})
		if err == nil {
			t.Errorf("patch %s=%s was accepted, but Settings.Validate rejects that value", key, raw)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("patch %s=%s: error %q does not name the offending key", key, raw, err)
		}
	}
}

// A field that declares no Default falls back to the zero of its kind. That zero is fed
// straight into the field's setter, which asserts the type the kind promises, so a wrong
// zero is not a wrong value but a panic on the first Defaults() call.
func TestZeroValueOfMatchesTheGoTypeEachKindStores(t *testing.T) {
	tests := []struct {
		kind FieldKind
		want any
	}{
		{KindString, ""},
		{KindBool, false},
		{KindInt, 0},
		{KindStringList, []string(nil)},
		{KindCidrList, []netip.Prefix(nil)},
		{KindSecret, ""},
		{KindSecretFile, ""},
		{KindAddrPort, ""},
		{KindURL, ""},
	}
	for _, tc := range tests {
		t.Run(tc.kind.String(), func(t *testing.T) {
			got := zeroValueOf(tc.kind)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("zeroValueOf(%s) = %#v, want %#v", tc.kind, got, tc.want)
			}
		})
	}
}

// The redaction mask standing in for an unchanged secret must be dropped, not stored.
func TestApplyPatchDropsTheRedactionMask(t *testing.T) {
	cfg := Defaults()
	ts, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatal(err)
	}
	ts.AuthKey = "tskey-real"

	raw, _ := json.Marshal(RedactedSecret)
	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{"authKey": raw}); err != nil {
		t.Fatalf("apply masked secret: %v", err)
	}

	if got := ts.AuthKey; got != "tskey-real" {
		t.Errorf("auth key = %q, want the mask dropped and the real key kept", got)
	}
}

// ApplyImpact must derive what a change needs from each field's declared class, so the
// dashboard can offer the right recovery action for the exact field that changed.
//
// Driven off the registry rather than three hand-picked fields, like its siblings in
// this file: a field added with the wrong Restart class -- or with the class declared
// but never consulted -- is exactly the mistake that ships a settings change the user
// is told is live when it is not, and a hand-picked table cannot see it.
func TestApplyImpactAgreesWithEveryFieldsDeclaredClass(t *testing.T) {
	for _, f := range settingsFields {
		if f.Derived || f.Write != WritePatch || f.set == nil {
			continue
		}
		t.Run(f.JSONKey, func(t *testing.T) {
			base := Defaults().Settings
			changed := base
			if !changeField(t, &changed, f) {
				t.Skipf("no distinct second value can be constructed for a %s field", f.Kind)
			}

			impact := ApplyImpact(base, changed)

			if want := f.Restart == RestartNode; impact.NodeRestart != want {
				t.Errorf("changing %q reported nodeRestart=%v, want %v (declared class %q)",
					f.JSONKey, impact.NodeRestart, want, f.Restart)
			}
			if want := f.Restart == RestartUI; impact.UIRelisten != want {
				t.Errorf("changing %q reported uiRelisten=%v, want %v (declared class %q)",
					f.JSONKey, impact.UIRelisten, want, f.Restart)
			}
			if want := f.Restart == RestartApp; impact.AppRestart != want {
				t.Errorf("changing %q reported appRestart=%v, want %v (declared class %q)",
					f.JSONKey, impact.AppRestart, want, f.Restart)
			}
			// Always empty, and that is the assertion. A preference lives on a node, and a
			// settings-document field names no connection, so there is no node to push it
			// to: the class belongs to the connection registry alone. A settings field
			// declaring it would be stored and silently never applied.
			if len(impact.Prefs) != 0 {
				t.Errorf("changing %q named %d node preferences to push; the settings document "+
					"has no connection to push one to", f.JSONKey, len(impact.Prefs))
			}
			if f.Restart == RestartPrefs {
				t.Errorf("%q declares the %q class, which only a connection field can carry: "+
					"the value would be stored and never reach any node", f.JSONKey, RestartPrefs)
			}
		})
	}
}

// changeField writes a value into s that differs from whatever is already there,
// staying inside what the field will accept. It reports false when the kind offers no
// second valid value to move to.
func changeField(t *testing.T, s *Settings, f SettingField) bool {
	t.Helper()
	current := f.get(s)
	var next any
	switch f.Kind {
	case KindString, KindSecret, KindSecretFile, KindAddrPort, KindURL:
		next = sampleFor(t, f)
		if next == current {
			next = "changed-value-2"
		}
	case KindEnum:
		next = sampleFor(t, f)
		if next == current {
			next = f.Options[0].Value
		}
	case KindBool:
		b, ok := current.(bool)
		if !ok {
			t.Fatalf("field %q is declared bool but reads as %T", f.JSONKey, current)
		}
		next = !b
	case KindInt:
		n, ok := current.(int)
		if !ok {
			t.Fatalf("field %q is declared int but reads as %T", f.JSONKey, current)
		}
		next = n + 7
	case KindStringList:
		next = []string{"tag:changed"}
	case KindCidrList:
		next = []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}
	default:
		return false
	}
	f.set(s, next)
	return true
}

// The dashboard drawer is hand-built (only its types are generated), so a new writable
// field could ship to the API and the CLI yet be silently missing from the settings UI.
// This grep-level guard keeps the drawer honest about covering every writable field.
// The dashboard renders a setting through the control its kind names, so a kind with no
// case in the switchboard falls to the default arm: a text box plus a notice that this
// build does not understand the type. That is the right behaviour for a dashboard older
// than the agent it is talking to, and the wrong behaviour for a kind added here -- the
// user would be typing a bare string into, say, a duration whose control should have
// offered units. Grepping the switchboard is what keeps a new kind from shipping with
// the skew notice showing on a perfectly current build.
func TestEveryFieldKindHasARendererCase(t *testing.T) {
	path := filepath.Join("..", "..", "ui", "src", "components", "settings", "SettingField.tsx")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the dashboard's field renderer: %v", err)
	}
	switchboard := string(src)

	// Both tables, because both render through this one component. A kind used only by a
	// connection field -- which is where the address lists live -- would otherwise reach the
	// dashboard as an unknown type with nothing having checked.
	kinds := make([]FieldKind, 0, len(settingsFields)+len(tunnelFields))
	for _, f := range settingsFields {
		kinds = append(kinds, f.Kind)
	}
	for _, f := range tunnelFields {
		kinds = append(kinds, f.Kind)
	}

	seen := map[FieldKind]bool{}
	for _, kind := range kinds {
		if seen[kind] {
			continue
		}
		seen[kind] = true
		// A bool never reaches the kind switch: the renderer answers it first, because
		// a switch row carries its own label rather than one above the control.
		if kind == KindBool {
			if !strings.Contains(switchboard, "field.kind === 'bool'") {
				t.Error("SettingField.tsx no longer routes bool to the switch row before the kind switch")
			}
			continue
		}
		if !strings.Contains(switchboard, fmt.Sprintf("case '%s':", kind)) {
			t.Errorf("kind %s has no case in SettingField.tsx, so the dashboard would render it "+
				"as an unknown type and tell the user to update the app", kind)
		}
	}
}

// The tray renders a setting as a click and nothing else -- a boolean is one checkbox,
// an enum is one checkbox per option, and the menu has no room for anything with a range
// of values and no way to ask a follow-up question. That makes three separate rules
// load-bearing across three files that cannot see each other, so marking a field for the
// tray is the one place they can be checked at once.
//
// A field with a free value would reach the menu as a checkbox for something that has no
// two positions; a read-only field would offer a click with nothing to write; and a field
// needing a rebuild would have to pop a "restart now?" dialog the tray cannot show, so it
// would either restart the node behind the user's back or store a value that never takes.
//
// RestartApp is allowed with the rest: it is read once at start and acted on nowhere else,
// so the click stores a real value and there is nothing to ask about. What the menu owes
// the user there is a row that says so, which the tray takes from the field's own help.
//
// Over the CLI schema rather than the settings table, because that is what the menu is
// built from: some of what the tray offers is stored on the primary connection now, and a
// settings-only sweep would stop checking exactly the fields that moved.
func TestOnlyASettingTheTrayCanActuallyOfferIsMarkedForIt(t *testing.T) {
	for _, f := range SettingsCLISchema() {
		if !f.Tray {
			continue
		}
		if f.Kind != KindBool && f.Kind != KindEnum {
			t.Errorf("%s is marked for the tray as a %s: the menu renders it as a click "+
				"and hands back one of a fixed set, so its real value is unreachable",
				f.Key, f.Kind)
		}
		if f.Write == WriteNone {
			t.Errorf("%s is marked for the tray but is read-only, so the checkbox offers a "+
				"click that can never write anything", f.Key)
		}
		switch f.Restart {
		case RestartNone, RestartPrefs:
		case RestartApp:
			// The click stores a value that is honoured on the next start, so the one thing
			// the menu has to do is say so on the row rather than leave a checkbox that
			// appears to change nothing.
			if !strings.Contains(strings.ToLower(f.Help), "next start") {
				t.Errorf("%s is marked for the tray and takes effect on the next start, but its "+
					"help does not say so, so the menu row reads as a click that did nothing",
					f.Key)
			}
		default:
			t.Errorf("%s is marked for the tray but needs a %s restart, which the menu has no "+
				"way to ask about", f.Key, f.Restart)
		}
	}
}

// Through ParseSettingValue rather than a single field, because that is the CLI's own
// entry point: a name a user types resolves across both the settings document and the
// connection the redirected keys now live on.
func TestParseCLIValue(t *testing.T) {
	parse := func(cli, raw string) (any, error) {
		_, v, err := ParseSettingValue(cli, raw)
		return v, err
	}

	got, err := parse("ephemeral", "true")
	if err != nil || got != true {
		t.Errorf("ephemeral=true parsed to %#v, err %v", got, err)
	}
	if _, err := parse("ephemeral", "maybe"); err == nil {
		t.Error("ephemeral=maybe was accepted, want a boolean error")
	}

	got, err = parse("udp-timeout", "120")
	if err != nil || got != 120 {
		t.Errorf("udp-timeout=120 parsed to %#v, err %v", got, err)
	}

	// Tags normalize through ParseTags so the CLI, env, and dashboard agree on the
	// tag: prefix.
	got, err = parse("tags", "alpha, beta")
	if err != nil {
		t.Fatalf("tags parse: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"tag:alpha", "tag:beta"}) {
		t.Errorf("tags parsed to %#v, want the tag:-prefixed pair", got)
	}
}

// What a connection edit needs before it is in force, which is the difference between a
// live push and a reconnection the user watches. A field misreported here either drops an
// edit that never reaches the node or tears a working connection down for nothing.
func TestWhatAConnectionEditNeedsBeforeItIsInForce(t *testing.T) {
	held := primaryTunnel()

	t.Run("nothing changed needs nothing", func(t *testing.T) {
		impact := TunnelsImpact([]Tunnel{held}, []Tunnel{held})

		if impact.NodeRestart || impact.UIRelisten || len(impact.Prefs) > 0 {
			t.Errorf("an unchanged connection reported %+v, want nothing to do", impact)
		}
	})

	// A node is built from the connection it runs, so one that is not there yet has
	// nothing running it.
	t.Run("a connection that appeared", func(t *testing.T) {
		added := NewTunnel("tn_a1b2c3", "office", "Office", TunnelTailscale)

		impact := TunnelsImpact([]Tunnel{held}, []Tunnel{held, added})

		if !impact.NodeRestart {
			t.Error("adding a connection reported no node restart, so nothing would start it")
		}
	})

	t.Run("a connection that went away", func(t *testing.T) {
		gone := NewTunnel("tn_a1b2c3", "office", "Office", TunnelTailscale)

		impact := TunnelsImpact([]Tunnel{held, gone}, []Tunnel{held})

		if !impact.NodeRestart {
			t.Error("removing a connection reported no node restart, so its node would keep running")
		}
	})

	// The one that makes an edit live: pushed to the node already running that connection
	// rather than applied by rebuilding it.
	t.Run("a preference the running node holds", func(t *testing.T) {
		edited := primaryTunnel()
		edited.ts().ShieldsUp = !held.TS().ShieldsUp

		impact := TunnelsImpact([]Tunnel{held}, []Tunnel{edited})

		if impact.NodeRestart {
			t.Error("a preference change reported a node restart, which reconnects for a live edit")
		}
		if len(impact.Prefs) != 1 {
			t.Fatalf("%d preferences to push, want the one that changed", len(impact.Prefs))
		}
		if impact.Prefs[0].TunnelID != held.ID {
			t.Errorf("the preference names connection %q, want %q", impact.Prefs[0].TunnelID, held.ID)
		}
		if impact.Prefs[0].Field.JSONKey != "security.shieldsUp" {
			t.Errorf("the preference is %q, want security.shieldsUp", impact.Prefs[0].Field.JSONKey)
		}
	})

	// The other half: a value the node is built from cannot be pushed, so the node is
	// rebuilt around it.
	t.Run("a value the node is built from", func(t *testing.T) {
		edited := primaryTunnel()
		edited.ts().ControlURL = "https://headscale.example.com"

		impact := TunnelsImpact([]Tunnel{held}, []Tunnel{edited})

		if !impact.NodeRestart {
			t.Error("changing where the connection enrolls reported no restart, so it would keep talking to the old one")
		}
		if len(impact.Prefs) > 0 {
			t.Errorf("it also reported %d preferences to push, want none", len(impact.Prefs))
		}
	})
}

// The two kinds a WireGuard connection is described with, parsed the way a command line
// hands them over: comma separated, one string. Without this the kinds are reachable only
// through JSON, and the day either field is given a CLI name the parse would be the one
// step nothing had ever run.
func TestTheAddressListsAConnectionHoldsAreParsedFromOneString(t *testing.T) {
	addresses, ok := tunnelRegistry.ByJSONKey("wg.addresses")
	if !ok {
		t.Fatal("no connection field holds the addresses this device has")
	}
	resolvers, ok := tunnelRegistry.ByJSONKey("wg.dns")
	if !ok {
		t.Fatal("no connection field holds the resolvers inside the network")
	}

	got, err := addresses.ParseCLIValue("10.7.0.4/24, fd00::4/64")
	if err != nil {
		t.Fatalf("parsing a pair of addresses: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.7.0.4/24"),
		netip.MustParsePrefix("fd00::4/64"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("addresses parsed to %#v, want %v", got, want)
	}

	got, err = resolvers.ParseCLIValue("10.7.0.1, 10.7.0.2")
	if err != nil {
		t.Fatalf("parsing a pair of resolvers: %v", err)
	}
	wantAddrs := []netip.Addr{netip.MustParseAddr("10.7.0.1"), netip.MustParseAddr("10.7.0.2")}
	if !reflect.DeepEqual(got, wantAddrs) {
		t.Errorf("resolvers parsed to %#v, want %v", got, wantAddrs)
	}
}

// An address written without its network size is the whole of what it names, which is what
// a WireGuard configuration means by "Address = 10.0.0.2": this device and nothing else.
func TestAnAddressWithNoNetworkSizeIsTheAddressAlone(t *testing.T) {
	addresses, _ := tunnelRegistry.ByJSONKey("wg.addresses")

	got, err := addresses.ParseCLIValue("10.7.0.4")

	if err != nil {
		t.Fatalf("parsing a bare address: %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.7.0.4/32")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed to %#v, want %v", got, want)
	}
}

// The distinction the two kinds exist for: a resolver is an address, never a network.
// Accepting a range would store something no query can be sent to.
func TestANetworkIsNotAResolver(t *testing.T) {
	resolvers, _ := tunnelRegistry.ByJSONKey("wg.dns")

	if _, err := resolvers.ParseCLIValue("10.7.0.1/24"); err == nil {
		t.Error("a network was accepted as a resolver")
	}
}

// The shape a request has to send. A value of the wrong shape is refused with the form
// that works, because the alternative is a 400 that says only that something was wrong.
func TestAnAddressListSentAsAnythingButAnArrayIsRefusedWithTheShapeThatWorks(t *testing.T) {
	cases := []struct{ key, sent, want string }{
		{"wg.addresses", `"10.7.0.4/24"`, `such as ["10.0.0.2/24"]`},
		{"wg.dns", `"10.7.0.1"`, `such as ["10.0.0.1"]`},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			tun := primaryTunnel()
			tun.Type = TunnelWireGuard
			app := Defaults().Settings
			// The resolvers a connection publishes are a setting of the DNS module, so
			// without it on the write is refused for a different reason entirely.
			app.DNSEnabled = true

			err := ApplyTunnelPatch(&tun, &app, map[string]json.RawMessage{tc.key: json.RawMessage(tc.sent)})

			if err == nil {
				t.Fatalf("%s = %s was accepted, want the array form asked for", tc.key, tc.sent)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

// A name the CLI accepts has to reach the field that stores it. A redirected key that
// resolved to nothing would turn `settings set hostname foo` into "unknown setting" on
// every existing script.
func TestEveryRedirectedKeyStillResolvesFromTheCommandLine(t *testing.T) {
	resolvesFromCLI(t, tailnetRedirect)
	resolvesFromCLI(t, proxyRedirect)
}

// resolvesFromCLI checks one redirect's keys, and the CLI names they answer to, against
// the name resolution the settings command goes through.
func resolvesFromCLI[T any](t *testing.T, r redirect[T]) {
	t.Helper()
	for _, key := range r.keys {
		f, ok := r.registry.ByJSONKey(key)
		if !ok {
			t.Fatalf("%s names no field, so the redirect points at nothing", key)
		}
		if _, ok := SettingByName(key); !ok {
			t.Errorf("%s is not a settings name any more", key)
		}
		if f.CLIName == "" {
			continue
		}
		if _, ok := SettingByName(f.CLIName); !ok {
			t.Errorf("%s is not resolvable by its CLI name %q", key, f.CLIName)
		}
	}
}

// The CLI parses a value locally before sending it, so it must apply the same rules
// the API does. Parsing without checking sends a value the agent then refuses, turning
// a typo the CLI could have named on the spot into a round trip and a 400.
func TestParseCLIValueAppliesTheSameRulesAsTheAPI(t *testing.T) {
	tests := []struct {
		cli  string
		raw  string
		want string
	}{
		{"udp-timeout", "-1", "must be >= 0, got -1"},
		{"udp-buffer", "70000", "must be 0-65535, got 70000"},
		{"ui-addr", "0.0.0.0:8377", "must bind a loopback address, got \"0.0.0.0\""},
		{"ui-addr", "not-an-address", "must be host:port, got \"not-an-address\""},
		{"control-url", "headscale.example.com", "must be an http(s) URL, got \"headscale.example.com\""},
		{"tags", "alpha", ""}, // ParseTags adds the prefix, so this one is accepted
	}
	for _, tt := range tests {
		t.Run(tt.cli+"="+tt.raw, func(t *testing.T) {
			if _, ok := SettingByName(tt.cli); !ok {
				t.Fatalf("no setting named %q", tt.cli)
			}
			_, _, err := ParseSettingValue(tt.cli, tt.raw)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("ParseCLIValue(%q) = %v, want it accepted", tt.raw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseCLIValue(%q) was accepted, want %q", tt.raw, tt.want)
			}
			// Bare, not prefixed with the json key: the CLI names the setting itself
			// using the name the user typed, so a prefix here reads as "udp-timeout:
			// udpSessionTimeoutSec: must be >= 0".
			if got := err.Error(); got != tt.want {
				t.Errorf("ParseCLIValue(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// Both registry guards above skip a struct field whose json tag is empty or "-", so a
// field marked `json:"-"` slips past both at once: it is not registered, and its
// absence from the registry is not reported either. The setting would then exist in
// the struct, be settable in Go, and never reach the config file, the view, the patch,
// the CLI or the generated types -- a value the agent reads that no user can ever set.
func TestNoSettingsFieldOptsOutOfJSONSerialization(t *testing.T) {
	st := reflect.TypeOf(Settings{})
	for i := range st.NumField() {
		field := st.Field(i)
		tag, ok := field.Tag.Lookup("json")
		if !ok {
			t.Errorf("Settings field %q has no json tag, so it serializes under its Go "+
				"name and no registry entry can match it", field.Name)
			continue
		}
		if name := strings.Split(tag, ",")[0]; name == "" || name == "-" {
			t.Errorf("Settings field %q is tagged %q, opting out of serialization; it "+
				"evades both registry guards and can never be read or written by a user",
				field.Name, tag)
		}
	}
}

// A registry entry that declares one kind and stores into a differently typed struct
// field is a table error the compiler cannot see, because every value crosses the
// closures as an any. Silently substituting the zero value would blank a setting the
// user had just set, so the conversion is loud instead.
func TestAMismatchedRegistryTypeIsLoudRatherThanSilentlyZero(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("typed accepted a value of the wrong type; a mismatched registry entry " +
				"would store a zero value under a setting the user had just written")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panicked with %T, want a string naming both types", r)
		}
		if !strings.Contains(msg, "int") || !strings.Contains(msg, "string") {
			t.Errorf("panic %q names neither the value's type nor the wanted one", msg)
		}
	}()
	typed[string](42)
}

func TestTypedPassesThroughAValueOfTheDeclaredType(t *testing.T) {
	if got := typed[string](any("keep")); got != "keep" {
		t.Errorf("typed[string](%q) = %q", "keep", got)
	}
	if got := typed[[]string](any([]string{"tag:one"})); len(got) != 1 || got[0] != "tag:one" {
		t.Errorf("typed[[]string] returned %v", got)
	}
}

// Settings held on the node are the stored half of the comparison the dashboard renders
// beside the node's own values. A setting missing here reads as absent rather than as
// disagreeing, which is the one state that looks like nothing is wrong.
func TestEverySettingHeldOnTheNodeReportsItsStoredValue(t *testing.T) {
	s := Defaults().Settings
	s.RoutesEnabled = true
	held := tailnetWith(TailnetPrefs{RoutesAccept: true})

	values := PrefValues(&s, held)
	if len(values) != len(PrefsFields()) {
		t.Fatalf("PrefValues reported %d settings, want the %d declared as node preferences",
			len(values), len(PrefsFields()))
	}
	// Against the module-resolved value rather than the raw stored one: what the node is
	// asked for is what the dashboard has to show beside what the node answers, or a
	// preference a switch is holding off reads as a disagreement with the tailnet.
	want := held
	prefs := s.TailnetPrefsOf(held)
	ts := want.TS()
	ts.TailnetPrefs = prefs
	want.Tailscale = &ts

	for _, f := range PrefsFields() {
		got, ok := values[f.JSONKey]
		if !ok {
			t.Errorf("PrefValues has no entry for %q", f.JSONKey)
			continue
		}
		if !reflect.DeepEqual(got, f.get(&want)) {
			t.Errorf("PrefValues[%q] = %v, want the in-force %v", f.JSONKey, got, f.get(&want))
		}
	}
}

// A module that is off has to read as off everywhere, and PrefValues is where the
// dashboard reads it. Reporting the stored value instead would show a preference as in
// force while the node is deliberately not being asked for it.
func TestASettingHeldOnTheNodeReportsAsOffWhileItsModuleIs(t *testing.T) {
	s := Defaults().Settings
	s.RoutesEnabled = false
	held := tailnetWith(TailnetPrefs{RoutesAccept: true})

	if got := PrefValues(&s, held)["routes.accept"]; got != false {
		t.Errorf("routes.accept reported as %v with the routing module off, want false", got)
	}
}

// A node someone already enrolled arrives carrying preferences. Adoption is what keeps
// the first reconcile from turning them off -- settings the user never touched here,
// changed by installing this app -- and it has to bring the module with it, or the value
// lands under a switch that reads as off and cannot be seen or changed.
func TestAdoptionTakesThePreferencesTheNodeHoldsAndRevealsThem(t *testing.T) {
	s := Defaults().Settings
	held := tailnetWith(TailnetPrefs{})
	if held.TS().RoutesAccept || s.RoutesEnabled {
		t.Fatal("a fresh install already accepts routes; this test cannot tell adoption from the default")
	}

	taken := AdoptPrefValues(&s, &held, map[string]any{"routes.accept": true})

	if !slices.Equal(taken, []string{"routes.accept"}) {
		t.Errorf("adopted %v, want [routes.accept]", taken)
	}
	if !held.TS().RoutesAccept {
		t.Error("the node accepts subnet routes but the adopted connection does not, so the first " +
			"reconcile would turn it off")
	}
	if !s.RoutesEnabled {
		t.Error("the adopted setting's module is still off, so the value is stored where the " +
			"user can neither see nor change it")
	}
}

// Adoption is for what someone else set, not for what this app would have set anyway.
// Taking a default would switch a module on for every install against a fresh node,
// which is exactly the opt-in the module system exists to protect.
func TestAdoptionLeavesAPreferenceThatMatchesTheDefaultAlone(t *testing.T) {
	s := Defaults().Settings
	held := tailnetWith(TailnetPrefs{})

	taken := AdoptPrefValues(&s, &held, map[string]any{"routes.accept": false})

	if len(taken) != 0 {
		t.Errorf("adopted %v, want nothing: the node holds this app's own default", taken)
	}
	if s.RoutesEnabled {
		t.Error("adopting nothing still switched a module on")
	}
}

// The live values come from the tailnet boundary, which knows preferences this registry
// may not. An unknown key is not this app's setting to store.
func TestAdoptionIgnoresAValueForNoSettingItHas(t *testing.T) {
	s := Defaults().Settings
	held := tailnetWith(TailnetPrefs{})

	if taken := AdoptPrefValues(&s, &held, map[string]any{"nothing.here": true}); len(taken) != 0 {
		t.Errorf("adopted %v from a key no setting claims", taken)
	}
}

// A preference lives on a node, and a settings-document field names no connection, so
// there is no node for one to be pushed to. A settings field declaring the class would be
// accepted, stored, and then silently never applied -- the exact failure the class exists
// to prevent, inverted.
//
// Unconditional, unlike the impact sweep above, which only reaches the fields a patch can
// write: a derived or read-only field carrying the class is just as wrong and would slip
// straight past it.
func TestNoSettingsFieldClaimsToLiveOnANode(t *testing.T) {
	for _, f := range settingsFields {
		if f.Restart == RestartPrefs {
			t.Errorf("%q declares the %q class on the settings document, which has no connection "+
				"to push it to; it belongs in tunnelFields", f.JSONKey, RestartPrefs)
		}
	}
}

// The mirror addresses a preference by wire key, so two connection fields sharing one key
// would have a push send whichever the table reached first -- and the drift comparison
// would read one field's value out of the other's preference.
func TestEveryPrefBackedConnectionFieldHasItsOwnKey(t *testing.T) {
	seen := make(map[string]bool)
	for _, f := range PrefsFields() {
		if seen[f.JSONKey] {
			t.Errorf("two connection fields are declared as node preferences under %q", f.JSONKey)
		}
		seen[f.JSONKey] = true
		if f.Variant != string(TunnelTailscale) {
			t.Errorf("%q is declared as a node preference on the %q variant; only a tailnet node "+
				"holds preferences, so nothing would ever push it", f.JSONKey, f.Variant)
		}
	}
	if len(seen) == 0 {
		t.Error("no connection field is declared as a node preference, so the mirror has nothing " +
			"to push and every one of these settings is stored and never applied")
	}
}
