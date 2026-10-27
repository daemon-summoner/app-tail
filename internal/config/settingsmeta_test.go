// SPDX-License-Identifier: MIT

package config

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Every field is rendered from its metadata alone, by consumers that have no
// per-setting knowledge. A missing label renders a control with no name; a group or
// module the side tables do not declare puts the control in a section that does not
// exist, so it is dropped from the form without anything erroring.
func TestEveryFieldCarriesMetadataAConsumerCanRenderFrom(t *testing.T) {
	groups := make(map[Group]bool, len(settingsGroups))
	for _, g := range settingsGroups {
		groups[g.ID] = true
	}
	modules := map[FeatureModule]bool{ModuleCore: true}
	for _, m := range featureModules {
		modules[m.ID] = true
	}

	for _, f := range settingsFields {
		if f.Label == "" {
			t.Errorf("field %q has no Label, so a form renders its control unnamed", f.JSONKey)
		}
		if !groups[f.Group] {
			t.Errorf("field %q is in group %s, which settingsGroups does not declare", f.JSONKey, f.Group)
		}
		if !modules[f.Module] {
			t.Errorf("field %q belongs to module %s, which featureModules does not declare", f.JSONKey, f.Module)
		}
		if f.ModuleSwitch != ModuleCore && !modules[f.ModuleSwitch] {
			t.Errorf("field %q switches module %s, which featureModules does not declare", f.JSONKey, f.ModuleSwitch)
		}
		// A view key nothing serves reads as absent, and a control told to show an
		// absent value as its sample shows nothing at all -- the form looks right and
		// silently stops telling the user what is in force.
		if f.ExampleFrom != "" && !viewKeys()[f.ExampleFrom] {
			t.Errorf("field %q draws its sample from view key %q, which the settings view "+
				"does not carry", f.JSONKey, f.ExampleFrom)
		}
	}
}

// A tray click is the whole interaction: the click is the save, and the menu closes on
// it. There is nowhere to type a value and no way to ask "restart now?" -- so a setting
// that is not a click, needs a restart, or has no write path at all cannot honestly be
// offered there. A boolean is one checkbox and an enum is one checkbox per option, so
// both are a click; anything with a range of values is not. A setting the tailnet node
// holds is fine: the click applies it, and a refusal comes back on the menu like any
// other failed command. Everything else reaches the user through the menu's "Settings..."
// item, which opens the same registry in the form.
//
// An enum's options have to be the fixed set the registry declares: the menu is built
// once, at start, and a set that arrives later has no item to land in.
func TestOnlyASettingATrayClickCanFullyApplyIsOfferedInTheMenu(t *testing.T) {
	for _, f := range settingsFields {
		if !f.Tray {
			continue
		}
		if f.Kind != KindBool && f.Kind != KindEnum {
			t.Errorf("field %q is in the tray but is a %s; a menu click has no way to enter one",
				f.JSONKey, f.Kind)
		}
		if f.Kind == KindEnum && f.OptionsFrom != "" {
			t.Errorf("field %q is in the tray and draws its options from %q at run time; the menu "+
				"is built once and has no item for a choice that arrives later",
				f.JSONKey, f.OptionsFrom)
		}
		if f.Restart == RestartNode || f.Restart == RestartUI {
			t.Errorf("field %q is in the tray but needs a %s restart, which a menu click cannot ask about",
				f.JSONKey, f.Restart)
		}
		if f.Write == WriteNone {
			t.Errorf("field %q is in the tray but nothing writes it, so the click would never move it",
				f.JSONKey)
		}
	}
}

// A choice is only a choice if the registry says what the choices are. A KindEnum
// with no options renders as an empty picker and accepts anything; options on a field
// of any other kind are offered by a control that then has its value rejected.
func TestOnlyEnumFieldsDeclareOptionsAndEveryEnumDoes(t *testing.T) {
	for _, f := range settingsFields {
		if f.Kind == KindEnum && len(f.Options) == 0 {
			t.Errorf("field %q is an enum but declares no options, so nothing can offer or check its values", f.JSONKey)
		}
		if f.Kind != KindEnum && len(f.Options) > 0 {
			t.Errorf("field %q declares options but is a %s, whose values are not a fixed set", f.JSONKey, f.Kind)
		}

		seen := make(map[string]bool, len(f.Options))
		for _, opt := range f.Options {
			if opt.Value == "" {
				t.Errorf("field %q has an option with no value, which no control can select", f.JSONKey)
			}
			if opt.Label == "" {
				t.Errorf("field %q option %q has no label, so a picker offers it unnamed", f.JSONKey, opt.Value)
			}
			if seen[opt.Value] {
				t.Errorf("field %q offers %q twice; a picker would show two entries that do the same thing", f.JSONKey, opt.Value)
			}
			seen[opt.Value] = true
		}

		// A default outside the set is stored on a fresh install and then refused by
		// the validator the first time anything writes the document back.
		if f.Kind == KindEnum && f.Default != nil {
			if err := f.ValidateValue(f.Default); err != nil {
				t.Errorf("field %q defaults to a value it will not accept: %v", f.JSONKey, err)
			}
		}
	}
}

// viewKeys is the set of keys BuildSettingsView emits.
func viewKeys() map[string]bool {
	keys := make(map[string]bool, len(settingsFields))
	for _, f := range settingsFields {
		keys[f.viewKey()] = true
	}
	return keys
}

// A module is only usable if exactly one writable boolean turns it on. With none it is
// permanently off and its settings are unreachable; with two the state is ambiguous
// and which one wins depends on registry order.
func TestEveryModuleHasExactlyOneWritableBoolSwitch(t *testing.T) {
	switches := make(map[FeatureModule][]string)
	for _, f := range settingsFields {
		if f.ModuleSwitch == ModuleCore {
			continue
		}
		switches[f.ModuleSwitch] = append(switches[f.ModuleSwitch], f.JSONKey)
		if f.Kind != KindBool || f.Write != WritePatch || f.set == nil || f.get == nil {
			t.Errorf("switch %q for module %s must be a writable bool, got kind %s written via %s",
				f.JSONKey, f.ModuleSwitch, f.Kind, f.Write)
		}
		if f.Module != ModuleCore {
			t.Errorf("switch %q is itself inside module %s, so the module could never be "+
				"turned on from a fresh install", f.JSONKey, f.Module)
		}
	}

	if len(featureModules) == 0 {
		t.Fatal("no optional modules are declared; this guard is covering nothing")
	}
	for _, m := range featureModules {
		keys := switches[m.ID]
		if len(keys) != 1 {
			t.Errorf("module %s has %d switches (%v), want exactly one", m.ID, len(keys), keys)
			continue
		}
		if keys[0] != m.SwitchKey {
			t.Errorf("module %s declares SwitchKey %q but %q carries the switch", m.ID, m.SwitchKey, keys[0])
		}
		delete(switches, m.ID)
	}
	for module, keys := range switches {
		t.Errorf("%v switch module %s, which featureModules does not declare", keys, module)
	}
}

// The two side tables are what a consumer renders sections and module cards from. An
// entry with no label renders a blank heading, and duplicate ids make one entry
// unreachable because a client keys them by id.
func TestTheGroupAndModuleTablesAreCompleteAndUniquelyKeyed(t *testing.T) {
	// Read through the accessors rather than the package vars: those are what the
	// generator and the schema endpoint call, so an accessor returning the wrong
	// table is the failure that reaches a consumer.
	groups, modules := SettingsGroups(), FeatureModules()
	if len(groups) == 0 {
		t.Fatal("SettingsGroups() is empty, so no settings section has a name")
	}
	seenGroup := make(map[Group]bool, len(groups))
	for _, g := range groups {
		if seenGroup[g.ID] {
			t.Errorf("group %s appears twice in SettingsGroups()", g.ID)
		}
		seenGroup[g.ID] = true
		if g.Label == "" || g.Description == "" {
			t.Errorf("group %s has an empty label or description", g.ID)
		}
	}

	if len(modules) == 0 {
		t.Fatal("FeatureModules() is empty, so the module machinery is exercised by nothing")
	}
	seenModule := make(map[FeatureModule]bool, len(modules))
	for _, m := range modules {
		if m.ID == ModuleCore {
			t.Error("ModuleCore is listed as an optional module; it is neither optional nor switchable")
		}
		if seenModule[m.ID] {
			t.Errorf("module %s appears twice in FeatureModules()", m.ID)
		}
		seenModule[m.ID] = true
		if m.Label == "" || m.Description == "" || m.SwitchKey == "" {
			t.Errorf("module %s has an empty label, description or switch key", m.ID)
		}
	}
}

// GroupsFor is what lets one section table serve several entities. It must answer with the
// sections those fields are in and no others, still in the authored display order -- a
// consumer draws its headings in the order they arrive.
func TestOnlyTheSectionsTheseFieldsAreInAreReturnedAndInDisplayOrder(t *testing.T) {
	got := GroupsFor([]FieldSchema{
		{Key: "b", Group: GroupSecurity},
		{Key: "a", Group: GroupIdentity},
		{Key: "c", Group: GroupSecurity},
	})

	want := []Group{GroupIdentity, GroupSecurity}
	if len(got) != len(want) {
		t.Fatalf("got %d sections %v, want exactly %v", len(got), got, want)
	}
	for i, g := range got {
		if g.ID != want[i] {
			t.Errorf("section %d = %s, want %s in the order SettingsGroups() lists them", i, g.ID, want[i])
		}
		if g.Label == "" {
			t.Errorf("section %s came back without its label", g.ID)
		}
	}
}

// The same rule for the module list, which a form needs for a different reason: a field
// gated on a switch the entity does not hold is hidden until the client is told which
// switch that is. Naming modules no field is gated on would have it watch switches that
// decide nothing here, and ModuleCore is not a switch at all.
func TestOnlyTheModulesTheseFieldsAreGatedOnAreReturnedAndInDisplayOrder(t *testing.T) {
	got := ModulesFor([]FieldSchema{
		{Key: "b", Module: ModuleSecurity},
		{Key: "a", Module: ModuleRouting},
		{Key: "plain", Module: ModuleCore},
		{Key: "c", Module: ModuleSecurity},
	})

	var order []FeatureModule
	for _, m := range FeatureModules() {
		if m.ID == ModuleRouting || m.ID == ModuleSecurity {
			order = append(order, m.ID)
		}
	}
	if len(got) != len(order) {
		t.Fatalf("got %d modules %v, want exactly %v", len(got), got, order)
	}
	for i, m := range got {
		if m.ID != order[i] {
			t.Errorf("module %d = %s, want %s in the order FeatureModules() lists them", i, m.ID, order[i])
		}
		if m.SwitchKey == "" {
			t.Errorf("module %s came back without the key that switches it, which is the only "+
				"part a form gating on it can use", m.ID)
		}
	}
}

// A section heading and a control inside it are two different things a user points at,
// and the dashboard names both from these tables. Give them the same words and the
// section's accessible name collides with the control's: a form that looks right and
// cannot be driven by name, by a screen reader or by a test.
//
// A module's own switch is exempt from the module's name, and only from that: a checkbox
// labelled after the thing it turns on is the point, not a collision.
func TestNoFieldLabelIsAlsoASectionOrModuleName(t *testing.T) {
	sections := make(map[string]string)
	for _, g := range SettingsGroups() {
		sections[g.Label] = "the " + g.ID.String() + " section"
	}
	modules := make(map[string]FeatureModule)
	for _, m := range FeatureModules() {
		modules[m.Label] = m.ID
	}

	for _, f := range SettingsFields() {
		if f.Label == "" {
			continue
		}
		if owner, taken := sections[f.Label]; taken {
			t.Errorf("field %s is labelled %q, which already names %s", f.JSONKey, f.Label, owner)
		}
		if module, taken := modules[f.Label]; taken && f.ModuleSwitch != module {
			t.Errorf("field %s is labelled %q, which already names the %s module it does not switch",
				f.JSONKey, f.Label, module)
		}
	}
}

// Bounds are only checked against integers, so a Constraint on any other kind is a
// limit the author wrote and nothing enforces -- silently, on the field where it
// mattered enough to declare one.
func TestOnlyIntegerFieldsDeclareBounds(t *testing.T) {
	declared := 0
	for _, f := range settingsFields {
		if f.Constraint == (Constraint{}) {
			continue
		}
		declared++
		if f.Kind != KindInt {
			t.Errorf("field %q is a %s but declares bounds, which are only applied to integers",
				f.JSONKey, f.Kind)
		}
	}
	if declared == 0 {
		t.Fatal("no field declares bounds; this guard is covering nothing")
	}
}

// The wording is the API's and the CLI's contract for a rejected number. A client that
// surfaces the reason verbatim -- as both of ours do -- shows whatever this returns.
func TestConstraintReportsEachBoundInTheWordingTheAPIHasAlwaysUsed(t *testing.T) {
	tests := []struct {
		name string
		c    Constraint
		v    any
		want string
	}{
		{"below a range", between(0, 65535), -1, "must be 0-65535, got -1"},
		{"above a range", between(0, 65535), 70000, "must be 0-65535, got 70000"},
		{"inside a range", between(0, 65535), 4096, ""},
		{"below a floor", atLeast(0), -1, "must be >= 0, got -1"},
		{"on a floor", atLeast(0), 0, ""},
		{"above a ceiling", Constraint{Max: ptrTo(10)}, 11, "must be <= 10, got 11"},
		{"under a ceiling", Constraint{Max: ptrTo(10)}, 10, ""},
		{"unbounded", Constraint{}, -999, ""},
		// Bounds are meaningless for a value that is not a number, and applying them
		// would have to invent a comparison.
		{"a string against a range", between(0, 10), "not a number", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.check(tt.v)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("check(%v) = %v, want it accepted", tt.v, err)
			case tt.want != "" && err == nil:
				t.Errorf("check(%v) was accepted, want %q", tt.v, tt.want)
			case tt.want != "" && err.Error() != tt.want:
				t.Errorf("check(%v) = %q, want %q", tt.v, err, tt.want)
			}
		})
	}
}

func ptrTo(n int) *int { return &n }

// A setting inside a module that is off must be refused by name, and the reason has to
// say which module to turn on: "unknown setting" or a bare rejection leaves the user with
// a control that will not save and no way to find out why. The reason is prose shown to a
// person, so it carries the module's label; the switch a client has to drive is reachable
// mechanically from the module table, which the second half asserts.
func TestPatchingASettingWhoseModuleIsOffIsRefusedAndNamesTheModule(t *testing.T) {
	cfg := Defaults() // advancedNetworking is off in a fresh document
	err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"controlURL": json.RawMessage(`"https://headscale.example.com"`),
	})
	if err == nil {
		t.Fatal("a setting inside a module that is off was accepted")
	}
	label := ModuleLabel(ModuleAdvancedNetworking)
	if got := err.Error(); !strings.Contains(got, "controlURL") || !strings.Contains(got, label) {
		t.Errorf("rejection reads %q; it must name both the setting and the %q module that would enable it", got, label)
	}
	if got := tailnetOf(t, cfg).ControlURL; got != "" {
		t.Errorf("controlURL = %q after a rejected patch, want it untouched", got)
	}
	s := cfg.Settings

	// The prose alone is not enough to act on: a client turning the module on has to
	// find the setting that does it without matching on a human sentence.
	var switchKey string
	for _, m := range FeatureModules() {
		if m.ID == ModuleAdvancedNetworking {
			switchKey = m.SwitchKey
		}
	}
	if _, ok := fieldByJSONKey[switchKey]; !ok {
		t.Fatalf("module %s advertises switch key %q, which is not a setting a client can write",
			ModuleAdvancedNetworking, switchKey)
	}
	if err := ApplySettingsPatch(&s, map[string]json.RawMessage{switchKey: json.RawMessage(`true`)}); err != nil {
		t.Fatalf("writing the switch key the module table advertises: %v", err)
	}
	controlURL, ok := tunnelRegistry.ByJSONKey("controlURL")
	if !ok {
		t.Fatal("no connection field named controlURL")
	}
	if ok, reason := controlURL.Available(&s); !ok {
		t.Errorf("controlURL is still unavailable after writing %q: %s", switchKey, reason)
	}
}

// Turning a module on and configuring it is one action to a user, so it arrives as one
// save. Applying the patch in map order would accept or reject the module's settings
// depending on which key Go happened to visit first: a save that works most of the time
// and fails at random is worse than one that never works.
func TestAModuleCanBeTurnedOnAndConfiguredInASingleSave(t *testing.T) {
	const url = "https://headscale.example.com"
	// Repeated because map iteration order is randomized per range: one pass could
	// pick the order that happens to work even without the switch-first pass.
	for range 32 {
		cfg := Defaults()
		err := ApplyPatchTo(cfg, map[string]json.RawMessage{
			"advancedNetworking": json.RawMessage(`true`),
			"controlURL":         json.RawMessage(`"` + url + `"`),
		})
		if err != nil {
			t.Fatalf("enabling a module and configuring it in one patch: %v", err)
		}
		if !cfg.Settings.AdvancedNetworking {
			t.Fatal("the module switch did not stick")
		}
		if got := tailnetOf(t, cfg).ControlURL; got != url {
			t.Fatalf("controlURL = %q, want %q", got, url)
		}
	}
}

// Turning a module off has to make the app behave as if it had never been on. A stored
// value that kept applying under a switch reading "off" is a setting the user can
// neither see nor turn off -- here, a node still joining a private coordination server
// after its owner switched the feature off.
func TestTurningAModuleOffReturnsItsSettingsToTheirDefaults(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.AdvancedNetworking = true
	ts, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatal(err)
	}
	ts.ControlURL = "https://headscale.example.com"

	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"advancedNetworking": json.RawMessage(`false`),
	}); err != nil {
		t.Fatalf("turning the module off: %v", err)
	}

	if cfg.Settings.AdvancedNetworking {
		t.Fatal("the module is still on")
	}
	// The module owns a connection's field rather than a setting, and "off" has to mean
	// the same thing either way: a node still joining a private coordination server under
	// a switch reading off is a setting nobody can see or turn off.
	if got := tailnetOf(t, cfg).ControlURL; got != "" {
		t.Errorf("controlURL = %q after the module was switched off, want it cleared", got)
	}
}

// A save that touches neither the switch nor the module's settings must leave them
// alone. Resetting on every write would erase a configured coordination server the
// moment the user changed an unrelated setting.
func TestASaveThatTouchesNoSwitchLeavesModuleSettingsAlone(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.AdvancedNetworking = true
	ts, err := cfg.PrimaryTailscale()
	if err != nil {
		t.Fatal(err)
	}
	ts.ControlURL = "https://headscale.example.com"

	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"hostname": json.RawMessage(`"my-box"`),
	}); err != nil {
		t.Fatalf("apply an unrelated setting: %v", err)
	}

	if got := tailnetOf(t, cfg).ControlURL; got != "https://headscale.example.com" {
		t.Errorf("controlURL = %q after an unrelated save, want it untouched", got)
	}
	if !cfg.Settings.AdvancedNetworking {
		t.Error("the module was switched off by an unrelated save")
	}
}

// The machine's resolver and the tailnet's are separate modules, and the reset above is
// the reason that is a correctness requirement rather than a filing decision. One click on
// "Use tailnet DNS" must not put this machine back on its router's resolver: a user who
// switched a tailnet feature off did not ask for their NextDNS profile to be dropped.
func TestTurningTheTailnetDNSModuleOffLeavesTheSystemProfileAlone(t *testing.T) {
	cfg := Defaults()
	cfg.Settings.DNSEnabled = true
	cfg.Settings.SystemDNSEnabled = true
	cfg.Settings.SystemDNSProfile = "nextdns"
	cfg.Tunnels[0].Tailscale.DNSUseTailnet = true

	if err := ApplyPatchTo(cfg, map[string]json.RawMessage{
		"dns.enabled": json.RawMessage(`false`),
	}); err != nil {
		t.Fatalf("turning the tailnet DNS module off: %v", err)
	}
	if tailnetOf(t, cfg).DNSUseTailnet {
		t.Error("the tailnet DNS module's own setting survived its switch going off")
	}
	if !cfg.Settings.SystemDNSEnabled {
		t.Error("the machine-wide resolver was switched off with the tailnet one")
	}
	if cfg.Settings.SystemDNSProfile != "nextdns" {
		t.Errorf("systemDns.profile = %q, want it left at %q", cfg.Settings.SystemDNSProfile, "nextdns")
	}
}

// Upgrading past the release that put controlURL behind a module must not move a node
// onto Tailscale's coordination server: the stored document has the URL set and the
// switch absent, which decodes to off. Adopting the configuration already on disk is
// what keeps the next save from resetting it.
func TestLoadingAConfigWrittenBeforeAModuleExistedAdoptsIt(t *testing.T) {
	// The value sits on the connection, which is where the module's field now lives, and
	// the switch is a setting. Adoption has to reach across the two or an upgraded install
	// runs on a coordination server its own dashboard says is not configured.
	cfg := &Config{Tunnels: []Tunnel{primaryTunnel()}}
	cfg.Tunnels[0].Tailscale.ControlURL = "https://headscale.example.com"
	applyDefaults(cfg)

	if !cfg.Settings.AdvancedNetworking {
		t.Fatal("a stored control URL did not turn its module on, so the next save would clear it")
	}
	if got := tailnetOf(t, cfg).ControlURL; got != "https://headscale.example.com" {
		t.Errorf("controlURL = %q, want the stored value kept", got)
	}
}

// The reverse: a document with nothing set must stay minimal. Adoption that fired on a
// default value would turn every module on for every user, which is the opposite of
// what the module machinery exists for.
func TestLoadingAFreshConfigLeavesEveryModuleOff(t *testing.T) {
	cfg := Defaults()
	applyDefaults(cfg)

	for _, sw := range settingsFields {
		if sw.ModuleSwitch == ModuleCore {
			continue
		}
		if sw.get(&cfg.Settings).(bool) {
			t.Errorf("module %s is on in a fresh configuration; every module must be opt-in",
				sw.ModuleSwitch)
		}
	}
}

// The served schema is what a client renders from. Without a resolved availability the
// dashboard would offer controls for every module whether or not it is on, and every
// save of one would be refused with an error the form never predicted.
func TestTheServedSchemaResolvesAvailabilityAndTheStaticOneLeavesItUnset(t *testing.T) {
	for _, s := range SettingsSchema() {
		if s.Available != nil {
			t.Errorf("the static schema resolved availability for %q; it cannot know the "+
				"stored configuration, and a wrong answer is worse than none", s.Key)
		}
	}

	// The redirected keys are served from the connection table, and a module gates them
	// exactly as it gated them when they were settings: what the form renders has to
	// follow the switch across the move, or the dashboard offers a control every save
	// refuses.
	for _, s := range SettingsCLISchema() {
		if s.Available != nil {
			t.Errorf("the command-line schema resolved availability for %q; it cannot know "+
				"the stored configuration, and a wrong answer is worse than none", s.Key)
		}
	}

	off := byKey(t, LegacyTailnetSchema(&Settings{}))
	if got := off["controlURL"]; got.Available == nil || *got.Available {
		t.Errorf("controlURL reads as available with its module off (%v)", got.Available)
	} else if got.AvailableReason == "" {
		t.Error("controlURL is unavailable with no reason, so the form cannot say why")
	}
	if got := off["hostname"]; got.Available == nil || !*got.Available {
		t.Errorf("hostname, which is in no module, reads as unavailable (%v)", got.Available)
	}

	on := byKey(t, LegacyTailnetSchema(&Settings{AdvancedNetworking: true}))
	if got := on["controlURL"]; got.Available == nil || !*got.Available {
		t.Errorf("controlURL is still unavailable with its module on (%v)", got.Available)
	} else if got.AvailableReason != "" {
		t.Errorf("controlURL is available but carries the reason %q", got.AvailableReason)
	}
}

// A form lets a module switch move locally and reveals that module's settings before any
// save. The platform is the half of availability no local edit can move, so it is served
// on its own: without it a Mac that turns the proxy module on reveals a Windows-only
// setting, and the agent refuses the whole save by that key.
func TestTheServedSchemaSaysWhichSettingsThisMachineHasAtAll(t *testing.T) {
	for _, s := range SettingsSchema() {
		if s.PlatformSupported != nil {
			t.Errorf("the static schema answered the platform question for %q; it is generated "+
				"on one machine and read on another", s.Key)
		}
	}

	served := byKey(t, SettingsSchemaFor(Settings{ProxyEnabled: true}))
	got, ok := served["proxy.system"]
	if !ok {
		t.Fatal("proxy.system is missing from the served schema")
	}
	if got.PlatformSupported == nil {
		t.Fatal("the served schema left the platform question unanswered for proxy.system")
	}
	// The setting writes this Windows account's own proxy configuration, and no other
	// platform has one setting to write.
	if want := runtime.GOOS == "windows"; *got.PlatformSupported != want {
		t.Errorf("proxy.system reads as platform-supported = %v on %s", *got.PlatformSupported, runtime.GOOS)
	}
	if buffer := served["udpBufferBytes"]; buffer.PlatformSupported == nil || !*buffer.PlatformSupported {
		t.Errorf("udpBufferBytes, which every platform has, reads as unsupported (%v)", buffer.PlatformSupported)
	}
}

func byKey(t *testing.T, schema []FieldSchema) map[string]FieldSchema {
	t.Helper()
	out := make(map[string]FieldSchema, len(schema))
	for _, s := range schema {
		out[s.Key] = s
	}
	return out
}

// A module with no switch cannot be turned on. Reporting its settings as available
// would put controls on the form that every save refuses; failing closed keeps them
// off it until the registry is fixed, which the guard above is what forces.
func TestASettingInAModuleWithNoSwitchIsUnavailableRatherThanExposed(t *testing.T) {
	orphan := SettingField{JSONKey: "orphaned", Module: FeatureModule(99)}
	available, reason := orphan.Available(&Settings{})
	if available {
		t.Fatal("a setting whose module has no switch reads as available")
	}
	if !strings.Contains(reason, "no switch") {
		t.Errorf("reason = %q, want it to say the module has no switch to turn on", reason)
	}
}

// A setting the running OS cannot act on must be refused, not accepted and ignored. A
// switch that saves and then does nothing is the shape of bug a user files as "the
// feature is broken", when the honest answer is that it was never offered here.
func TestAPlatformGatedSettingIsRefusedOffItsPlatform(t *testing.T) {
	// A platform no build of this app runs on, so the gate is exercised identically
	// whichever machine runs the suite.
	elsewhere := SettingField{JSONKey: "elsewhere", Platforms: []string{"plan9"}}

	available, reason := elsewhere.Available(&Settings{})
	if available {
		t.Fatal("a setting for another platform reads as available here")
	}
	if !strings.Contains(reason, PlatformLabel(runtime.GOOS)) {
		t.Errorf("reason = %q, want it to name the platform the user is on", reason)
	}
	if !strings.Contains(reason, "plan9") {
		t.Errorf("reason = %q, want it to name the platform the setting is for", reason)
	}

	// The gate outranks the module switch: there is no module state that makes this
	// writable, so pointing at one to turn on would send the user after a dead end.
	gated := SettingField{JSONKey: "gated", Platforms: []string{"plan9"}, Module: ModuleProxy}
	if _, reason := gated.Available(&Settings{ProxyEnabled: true}); !strings.Contains(reason, "plan9") {
		t.Errorf("reason = %q, want the platform rather than the module", reason)
	}
}

// A platform gate is only honest if it names platforms that exist. A typo would hide a
// setting on every machine, silently, with the module switch reporting itself fine.
func TestEveryPlatformGateNamesAPlatformThisAppRunsOn(t *testing.T) {
	supported := []string{"darwin", "linux", "windows"}
	for _, f := range settingsFields {
		for _, goos := range f.Platforms {
			if !slices.Contains(supported, goos) {
				t.Errorf("setting %q is gated to %q, which is not one of %v",
					f.JSONKey, goos, supported)
			}
		}
	}
}

// The reason is rendered verbatim wherever the control would have been, so it has to
// read as a sentence for one platform and for several.
func TestThePlatformReasonReadsAsProseHoweverManyThereAre(t *testing.T) {
	for _, tc := range []struct {
		goos []string
		want string
	}{
		{[]string{"windows"}, "Windows"},
		{[]string{"windows", "linux"}, "Windows and Linux"},
		{[]string{"windows", "linux", "darwin"}, "Windows, Linux and macOS"},
	} {
		if got := platformList(tc.goos); got != tc.want {
			t.Errorf("platformList(%v) = %q, want %q", tc.goos, got, tc.want)
		}
	}
}

// The schema carries each setting's default so a form can offer "reset to default" and
// show what blank means. A default of the wrong type would be stored by the setter as
// a panic on the first Defaults() call, so this also pins the table's types.
func TestEveryDeclaredDefaultIsWhatAFreshConfigurationHolds(t *testing.T) {
	fresh := Defaults().Settings
	declared := 0
	for _, f := range settingsFields {
		if f.get == nil {
			continue
		}
		if f.Default != nil {
			declared++
		}
		if got, want := f.get(&fresh), f.defaultValue(); !reflect.DeepEqual(got, want) {
			t.Errorf("a fresh configuration holds %#v for %q, but the registry declares %#v",
				got, f.JSONKey, want)
		}
	}
	if declared == 0 {
		t.Fatal("no field declares a default; Defaults() would return an empty document")
	}

	// A connection is held to the same rule, for the same reason: a fresh one that does
	// not hold what its field declares is a form whose "reset to default" writes a value
	// the document never starts from.
	// Only the fields that declare one: a connection's identity -- its id, slug, name and
	// protocol -- is supplied when it is created, so those legitimately hold something a
	// table of defaults never described.
	freshTunnel := primaryTunnel()
	for _, f := range tunnelFields {
		if f.get == nil || f.Default == nil || !tunnelRegistry.applies(f, &freshTunnel) {
			continue
		}
		if got, want := f.get(&freshTunnel), f.defaultValue(); !reflect.DeepEqual(got, want) {
			t.Errorf("a fresh connection holds %#v for %q, but the registry declares %#v",
				got, f.JSONKey, want)
		}
	}

	// The registry's own slice must never be handed out: a consumer appending to the
	// default tag list would change what every later fresh install starts with.
	tags, ok := tunnelRegistry.ByJSONKey("tags")
	if !ok {
		t.Fatal("the tags field is missing from the registry")
	}
	first := tags.defaultValue().([]string)
	first[0] = "tag:mutated"
	if second := tags.defaultValue().([]string); second[0] == "tag:mutated" {
		t.Error("defaultValue hands out the registry's own slice; mutating it changed the default")
	}

	// The same protection has to hold for a list of networks. No field declares one
	// today, so the guard is tested against a field shaped like the one that would:
	// without it, the first install to reset a route list would edit the table itself
	// and every later fresh configuration would start from the edited value.
	routes := SettingField{
		Kind:    KindCidrList,
		Default: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}
	firstRoutes := routes.defaultValue().([]netip.Prefix)
	firstRoutes[0] = netip.MustParsePrefix("192.168.9.0/24")
	if second := routes.defaultValue().([]netip.Prefix); second[0].String() != "10.0.0.0/24" {
		t.Errorf("defaultValue hands out the registry's own network list; it now reads %v", second)
	}
}

// applyDefaults exists to make a partial or older document loadable. Back-filling a
// boolean or a list would overwrite a deliberate "off" or "no tags" with the default on
// every single load, because neither is distinguishable from an absent key.
func TestApplyDefaultsFillsOnlyWhatAnAbsentKeyCannotBeConfusedWith(t *testing.T) {
	cfg := &Config{
		Settings: Settings{ShowTray: false, AutoOpenDashboard: false},
		Tunnels:  []Tunnel{{ID: PrimaryTunnelID, Slug: PrimaryTunnelSlug, Name: "Tailnet", Type: TunnelTailscale}},
	}
	applyDefaults(cfg)

	if cfg.Settings.UIListen != DefaultUIListenAddr {
		t.Errorf("uiListenAddr = %q, want the default filled in", cfg.Settings.UIListen)
	}
	if cfg.Settings.UDPSessionTimeoutSec != DefaultUDPTimeoutSec {
		t.Errorf("udpSessionTimeoutSec = %d, want the default filled in", cfg.Settings.UDPSessionTimeoutSec)
	}
	if cfg.Settings.ShowTray || cfg.Settings.AutoOpenDashboard {
		t.Error("a switch the user turned off was turned back on by loading the file")
	}
	// A stored connection carrying nothing under a field is back-filled the same way, and
	// held to the same carve-out: an empty tag list is a choice, not an absent key.
	ts := tailnetOf(t, cfg)
	if ts.HostnameTemplate != DefaultHostnameTemplate {
		t.Errorf("hostnameTemplate = %q, want the default filled in", ts.HostnameTemplate)
	}
	if len(ts.Tags) != 0 {
		t.Errorf("tags = %v, want an explicitly empty list left empty", ts.Tags)
	}
}

// The CLI prints these words in its settings table and the dashboard switches on them.
// A renamed word makes a field of that kind fall through to a plain text box in the
// dashboard -- including, for the two new formatted kinds, one with no validation.
func TestTheNewFieldKindsSerializeToTheirDocumentedWireWords(t *testing.T) {
	for kind, want := range map[FieldKind]string{KindAddrPort: "addrPort", KindURL: "url"} {
		if got := kind.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
		raw, err := json.Marshal(kind)
		if err != nil {
			t.Fatalf("marshal %v: %v", kind, err)
		}
		if string(raw) != `"`+want+`"` {
			t.Errorf("JSON = %s, want %q", raw, want)
		}
	}
}

// Tier, group and module all reach the dashboard as words and are switched on there.
// An unmapped value must degrade to the zero member rather than an empty string, so a
// schema built by a newer agent still renders every control somewhere.
func TestEveryTierGroupAndModuleSerializesToItsDocumentedWireWord(t *testing.T) {
	cases := []struct {
		value any
		want  string
	}{
		{TierBasic, "basic"},
		{TierAdvanced, "advanced"},
		{Tier(99), "basic"},
		{GroupIdentity, "identity"},
		{GroupAuth, "auth"},
		{GroupTailnet, "tailnet"},
		{GroupForwarding, "forwarding"},
		{GroupApplication, "application"},
		{GroupAbout, "about"},
		{Group(99), "identity"},
		{ModuleCore, "core"},
		{ModuleAdvancedNetworking, "advancedNetworking"},
		{FeatureModule(99), "core"},
	}
	for _, tc := range cases {
		stringer, ok := tc.value.(interface{ String() string })
		if !ok {
			t.Fatalf("%T has no String method, so the schema would carry an integer", tc.value)
		}
		if got := stringer.String(); got != tc.want {
			t.Errorf("%T(%v).String() = %q, want %q", tc.value, tc.value, got, tc.want)
		}
		raw, err := json.Marshal(tc.value)
		if err != nil {
			t.Fatalf("marshal %v: %v", tc.value, err)
		}
		if string(raw) != `"`+tc.want+`"` {
			t.Errorf("%T(%v) marshals as %s, want %q", tc.value, tc.value, raw, tc.want)
		}
	}
}

// ModuleLabel is what a message uses to tell a user which feature to turn on. A module
// with no entry must still read as something, or the sentence has a hole in it.
func TestModuleLabelNamesTheModuleAUserWouldRecognize(t *testing.T) {
	if got := ModuleLabel(ModuleAdvancedNetworking); got != "Advanced networking" {
		t.Errorf("ModuleLabel(advancedNetworking) = %q, want the declared label", got)
	}
	if got := ModuleLabel(FeatureModule(99)); got == "" {
		t.Error("ModuleLabel of an undeclared module is empty, leaving a gap in the sentence")
	}
}

// A schema that cannot be read back is a schema no Go client can use. Every enum in it is
// written as a word so the dashboard and the generated TypeScript read something legible,
// and the CLI is the consumer that has to turn those words back into values -- it renders
// the connection form from the schema the agent serves rather than from a compiled-in copy.
//
// This is also what keeps the decoders honest: each walks the values up to a declared last
// one, and a kind, section, module, tier, restart class or write path added past that last
// value fails here the moment a field uses it.
func TestEverySchemaTheAgentServesCanBeReadBack(t *testing.T) {
	for name, fields := range map[string][]FieldSchema{
		"settings":    SettingsCLISchema(),
		"connections": TunnelSchemaStatic(),
	} {
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("encode the %s schema: %v", name, err)
		}
		var read []FieldSchema
		if err := json.Unmarshal(encoded, &read); err != nil {
			t.Fatalf("read the %s schema back: %v", name, err)
		}
		if len(read) != len(fields) {
			t.Fatalf("the %s schema came back with %d fields, want %d", name, len(read), len(fields))
		}
		for i, want := range fields {
			got := read[i]
			if got.Key != want.Key {
				t.Fatalf("the %s schema came back in a different order at %d: %q, want %q",
					name, i, got.Key, want.Key)
			}
			for _, c := range [][3]any{
				{"kind", got.Kind, want.Kind},
				{"section", got.Group, want.Group},
				{"tier", got.Tier, want.Tier},
				{"module", got.Module, want.Module},
				{"module switch", got.ModuleSwitch, want.ModuleSwitch},
				{"restart class", got.Restart, want.Restart},
				{"write path", got.Write, want.Write},
			} {
				if c[1] != c[2] {
					t.Errorf("%s: the %s of %s came back as %v, want %v", name, c[0], want.Key, c[1], c[2])
				}
			}
		}
	}
}

// The sections and modules travel beside the fields, and a client labels a field's section
// by matching this list against it. Read back as a different value, every field would be
// filed under the first section instead.
func TestTheSectionsAndModulesBesideASchemaCanBeReadBack(t *testing.T) {
	fields := TunnelSchemaStatic()

	encoded, err := json.Marshal(map[string]any{
		"groups":  GroupsFor(fields),
		"modules": ModulesFor(fields),
	})
	if err != nil {
		t.Fatalf("encode the schema's sections and modules: %v", err)
	}
	var read struct {
		Groups  []GroupInfo  `json:"groups"`
		Modules []ModuleInfo `json:"modules"`
	}
	if err := json.Unmarshal(encoded, &read); err != nil {
		t.Fatalf("read the schema's sections and modules back: %v", err)
	}

	for i, want := range GroupsFor(fields) {
		if read.Groups[i].ID != want.ID {
			t.Errorf("section %q came back as %q", want.ID, read.Groups[i].ID)
		}
	}
	for i, want := range ModulesFor(fields) {
		if read.Modules[i].ID != want.ID {
			t.Errorf("module %q came back as %q", want.ID, read.Modules[i].ID)
		}
	}
}

// A word no value answers to is refused rather than silently read as the zero value, which
// would file a field under the wrong section or, worse, report a secret as an ordinary
// string.
func TestAnUnknownNameInASchemaIsRefusedRatherThanReadAsTheZeroValue(t *testing.T) {
	var field FieldSchema
	err := json.Unmarshal([]byte(`{"key":"x","kind":"quantum"}`), &field)
	if err == nil {
		t.Fatal("a field kind no value answers to was accepted")
	}
	if !strings.Contains(err.Error(), "quantum") {
		t.Errorf("the refusal reads %q, want it to name the value it could not read", err)
	}
}
