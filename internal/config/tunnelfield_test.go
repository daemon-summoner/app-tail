// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func patchOf(t *testing.T, pairs map[string]any) map[string]json.RawMessage {
	t.Helper()
	out := make(map[string]json.RawMessage, len(pairs))
	for k, v := range pairs {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("encoding %s: %v", k, err)
		}
		out[k] = raw
	}
	return out
}

// The generated TypeScript renders this table, and a checked-in file cannot know the
// machine that will run it. An availability baked in there would have the dashboard hide a
// field on every installation because it was unavailable on the one that generated it.
func TestTheTableTheGeneratedFormRendersAnswersForNoParticularMachine(t *testing.T) {
	static := TunnelSchemaStatic()

	if len(static) == 0 {
		t.Fatal("the connection form's table is empty")
	}
	for _, f := range static {
		if f.Available != nil {
			t.Errorf("%s carries an availability answered for one installation", f.Key)
		}
		if f.AvailableReason != "" {
			t.Errorf("%s carries the reason it was unavailable somewhere: %q", f.Key, f.AvailableReason)
		}
	}
	// The other half: served to a client, availability is what says which fields this
	// installation can write, so it must be answered there.
	app := Defaults().Settings
	for _, f := range TunnelSchema(&app) {
		if f.Available == nil {
			t.Errorf("%s was served without saying whether it can be written", f.Key)
		}
	}
}

func TestRenamingAConnectionWritesBothNames(t *testing.T) {
	tun := primaryTunnel()
	app := Defaults().Settings

	err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"name": "Work", "slug": "work"}))
	if err != nil {
		t.Fatalf("patching: %v", err)
	}

	if tun.Name != "Work" || tun.Slug != "work" {
		t.Errorf("connection = %+v, want both names written", tun)
	}
	// The id is what forwards and rules point at, so a rename must not move it.
	if tun.ID != PrimaryTunnelID {
		t.Errorf("id = %q, want it unchanged by a rename", tun.ID)
	}
}

// A patch carries only what changed. A field the request omitted must keep its stored
// value, or every save from a partial form would blank the rest of the connection.
func TestAPatchLeavesWhatItDidNotCarryAlone(t *testing.T) {
	tun := primaryTunnel()
	app := Defaults().Settings

	if err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"name": "Work"})); err != nil {
		t.Fatalf("patching: %v", err)
	}

	if tun.Slug != PrimaryTunnelSlug {
		t.Errorf("slug = %q, want the stored value kept", tun.Slug)
	}
}

// The same DNS-label rule as the document validator, reached through the field's own
// declaration so a form and a hand-edited file cannot disagree about what a slug is.
func TestASlugThatIsNotADNSLabelIsRefusedByTheForm(t *testing.T) {
	tun := primaryTunnel()
	app := Defaults().Settings

	err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"slug": "Work Network"}))

	if err == nil {
		t.Fatal("a slug that cannot be a DNS label was accepted")
	}
	if tun.Slug != PrimaryTunnelSlug {
		t.Errorf("slug = %q, want the refused write not applied", tun.Slug)
	}
}

func TestAConnectionCannotBeLeftUnnamed(t *testing.T) {
	tun := primaryTunnel()
	app := Defaults().Settings

	if err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"name": "   "})); err == nil {
		t.Fatal("a blank name was accepted, so the connection would render as an empty row")
	}
}

// Changing the type in place would leave the settings of the old type stored against an
// entity that no longer has them.
func TestTheTypeCannotBeChangedInPlace(t *testing.T) {
	tun := primaryTunnel()
	app := Defaults().Settings

	err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"type": string(TunnelWireGuard)}))

	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("error = %v, want a refusal saying the type is read-only", err)
	}
	if tun.Type != TunnelTailscale {
		t.Errorf("type = %q, want it unchanged", tun.Type)
	}
}

func TestAKeyThisFormDoesNotHaveIsRefusedByName(t *testing.T) {
	tun := primaryTunnel()
	app := Defaults().Settings

	err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"proxy.enabled": true}))

	if err == nil || !strings.Contains(err.Error(), "proxy.enabled") {
		t.Errorf("error = %v, want a refusal naming the key", err)
	}
}

// A field of another protocol is not a field of this connection. Storing it would leave a
// device name and a tag list against a WireGuard peer, where nothing reads them -- which
// is how a value somebody typed goes nowhere with no error anywhere.
func TestAFieldOfAnotherProtocolIsRefusedByName(t *testing.T) {
	tun := NewTunnel("tn_a1b2c3", "office", "Office", TunnelWireGuard)
	app := Defaults().Settings

	err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"hostname": "workstation"}))

	if err == nil {
		t.Fatal("a tailnet device name was accepted on a WireGuard connection")
	}
	if !strings.Contains(err.Error(), "hostname") || !strings.Contains(err.Error(), string(TunnelWireGuard)) {
		t.Errorf("error = %v, want it to name the field and the kind of connection", err)
	}
}

// And the view leaves it out rather than reporting it empty: an absent key says this
// connection has no such thing, where a zero value would say it has one and it is unset.
func TestTheViewLeavesOutTheFieldsOfAnotherProtocol(t *testing.T) {
	app := Defaults().Settings
	tun := NewTunnel("tn_a1b2c3", "office", "Office", TunnelWireGuard)

	view := BuildTunnelView(tun, &app)

	for _, key := range []string{"hostname", "tags", "controlURL", "hasAuthKey"} {
		if _, held := view[key]; held {
			t.Errorf("a WireGuard connection's view carries %q", key)
		}
	}
	if view["name"] != "Office" {
		t.Errorf("name = %v, want the stored name", view["name"])
	}
}

// The view is what the connection screen renders, so every field the schema promises has
// to be in it -- a client that found a key missing would render an empty control over a
// stored value.
func TestTheViewCarriesEveryFieldTheSchemaPromises(t *testing.T) {
	app := Defaults().Settings
	tun := primaryTunnel()
	view := BuildTunnelView(tun, &app)

	for _, f := range TunnelSchema(&app) {
		if f.Variant != "" && f.Variant != string(tun.Type) {
			continue
		}
		if _, ok := view[f.ViewKey]; !ok {
			t.Errorf("the view has no %q, which the schema declares", f.ViewKey)
		}
	}
	if view["type"] != string(TunnelTailscale) {
		t.Errorf("type = %v, want the stored type", view["type"])
	}
}

// A form needs more than a key: without a label and a kind it has nothing to render, and
// without help the user is guessing what the field is.
func TestEveryConnectionFieldCarriesWhatAFormNeeds(t *testing.T) {
	app := Defaults().Settings

	schema := TunnelSchema(&app)

	if len(schema) == 0 {
		t.Fatal("the connection schema is empty, so the form would render nothing")
	}
	for _, f := range schema {
		if f.Label == "" {
			t.Errorf("%s has no label", f.Key)
		}
		if f.Help == "" {
			t.Errorf("%s has no help", f.Key)
		}
		// A field inside a module that is off is legitimately unavailable, but it still owes
		// the user a reason -- a control that will not save with nothing said about why is
		// the failure this asserts against.
		if f.Available == nil {
			t.Errorf("%s does not say whether it can be written", f.Key)
			continue
		}
		if !*f.Available && f.AvailableReason == "" {
			t.Errorf("%s is unavailable with no reason given", f.Key)
		}
		if !*f.Available && f.Module == ModuleCore {
			t.Errorf("%s is unavailable on this installation: %s", f.Key, f.AvailableReason)
		}
	}
}

// The picker's choices come from the one type list, so a type this build can connect and
// a type a picker offers cannot come apart.
func TestTheTypePickerOffersEveryTypeThisBuildKnows(t *testing.T) {
	app := Defaults().Settings

	var options []EnumOption
	for _, f := range TunnelSchema(&app) {
		if f.Key == "type" {
			options = options[:0]
			options = append(options, f.Options...)
		}
	}

	if len(options) != len(TunnelTypes) {
		t.Fatalf("the picker offers %d types, want %d", len(options), len(TunnelTypes))
	}
	for i, want := range TunnelTypes {
		if options[i].Value != string(want) {
			t.Errorf("option %d = %q, want %q", i, options[i].Value, want)
		}
		if options[i].Label == "" || options[i].Label == options[i].Value {
			t.Errorf("option %q has no written label", options[i].Value)
		}
	}
}

// A relative secret file is read from wherever the agent was started, which for a
// service is a directory nobody chose, so the write is refused where it is made.
func TestARelativeOAuthSecretFileIsRefusedOnWrite(t *testing.T) {
	tun := primaryTunnel()
	app := Defaults().Settings

	err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"oauthClientSecretFile": "secrets/oauth"}))
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error = %v, want a relative secret file refused for not being absolute", err)
	}

	absolute := filepath.Join(t.TempDir(), "oauth")
	if err := ApplyTunnelPatch(&tun, &app, patchOf(t, map[string]any{"oauthClientSecretFile": absolute})); err != nil {
		t.Fatalf("an absolute secret file was refused: %v", err)
	}
	if got := tun.TS().OAuthClientSecretFile; got != absolute {
		t.Errorf("oauthClientSecretFile = %q, want %q", got, absolute)
	}
}

// A relative secret file already in a stored document is refused when it is read, not
// when the document is loaded: failing validation would quarantine the whole file, every
// connection with it, over one path the read already refuses on its own.
func TestARelativeOAuthSecretFileAlreadyStoredStillLoads(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnels[primaryIndex(cfg.Tunnels)].ts().OAuthClientSecretFile = "secrets/oauth"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a stored document with a relative secret file failed validation: %v", err)
	}
	if _, err := LoadOAuthSecret(TailscaleTunnel{OAuthClientSecretFile: "secrets/oauth"}); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("reading a relative secret file: error = %v, want it refused for not being absolute", err)
	}
}
