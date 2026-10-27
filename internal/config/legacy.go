// SPDX-License-Identifier: MIT

package config

// The settings keys that named the one tailnet, and the one proxy, before either could be
// named at all.
//
// They now name fields of an entity, and they keep working. A script, a fleet profile, a
// deployment or a bookmarked API call that sets `hostname` is naming the tailnet this app
// has always run, and one that sets `proxy-addr` is naming the proxy it has always had.
// There is exactly one thing either can mean. The alternative -- refusing the key --
// would break every existing automation on upgrade to no purpose, since the destination
// is unambiguous.
//
// This file is the whole of the redirect: two key lists and the projections over them.
// The metadata, the parsing and the validation all come from the destination's own field,
// so a redirected key cannot describe or accept something different from where it lands.

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// redirect is one set of settings keys that have moved onto another entity, together with
// where they moved and where they sat in the settings list.
//
// It is generic over the destination because the two redirects differ only in those three
// things: the same lookup, the same schema projection and the same note apply to both, and
// a second hand-written copy would be a second place for a key to be forgotten.
type redirect[T any] struct {
	// keys are the settings keys this redirect answers for, in the order the settings
	// document listed them.
	keys     []string
	registry *Registry[T]
	// note is appended to a redirected key's help, so anyone reading `settings list` is
	// told where the setting went rather than left to discover it is gone.
	note string
	// slots says which settings key each redirected key used to sit behind, "" meaning it
	// opened the list. The interactive menu is a numbered list and `settings list` prints
	// in this order, so a key that changed position is a key the person who has been
	// running this app for a year can no longer find where they have always found it. The
	// redirect exists to keep those callers working; moving their rows would undo half of it.
	slots map[string][]string
}

// effectiveHostname is on the list and is read-only: it is the name the dashboard's about
// panel reads, and a redirect that carried only the writable keys would leave that panel
// blank while every write still worked.
var tailnetRedirect = redirect[Tunnel]{
	keys: []string{
		"hostname", "hostnameTemplate", "effectiveHostname", "tags", "advertiseTagsOnLogin",
		"authKey", "oauthClientSecret", "oauthClientSecretFile", "controlURL", "ephemeral",
		"exitNode.nodeId", "exitNode.auto", "exitNode.allowLanAccess", "exitNode.onFailure",
		"exitNode.rotate.enabled", "exitNode.rotate.strategy", "exitNode.rotate.intervalSec",
		"exitNode.rotate.pauseOnActive", "exitNode.rotate.maxDeferrals",
		"routes.accept", "routes.advertise", "routes.serve", "routes.netfilter",
		"routes.advertiseExitNode",
		"dns.useTailnet",
		"security.shieldsUp", "security.postureChecking",
	},
	registry: tunnelRegistry,
	note: " Moved to the connection \"" + PrimaryTunnelSlug +
		"\"; this key still works and writes there.",
	slots: map[string][]string{
		"": {
			"hostname", "hostnameTemplate", "tags", "advertiseTagsOnLogin",
			"authKey", "oauthClientSecret", "oauthClientSecretFile",
		},
		"advancedNetworking": {"controlURL", "ephemeral"},
		"machineId":          {"effectiveHostname"},
		"exitNode.enabled": {
			"exitNode.nodeId", "exitNode.auto", "exitNode.allowLanAccess", "exitNode.onFailure",
			"exitNode.rotate.enabled", "exitNode.rotate.strategy", "exitNode.rotate.intervalSec",
			"exitNode.rotate.pauseOnActive", "exitNode.rotate.maxDeferrals",
		},
		"routes.enabled": {
			"routes.accept", "routes.advertise", "routes.serve", "routes.netfilter",
			"routes.advertiseExitNode",
		},
		"dns.enabled":      {"dns.useTailnet"},
		"security.enabled": {"security.shieldsUp", "security.postureChecking"},
	},
}

// proxy.scope is on the list and is read-only, for the same reason effectiveHostname is:
// a caller who has been reading it deserves an answer, and one who writes it deserves the
// sentence saying rules replaced it rather than a key that has silently vanished.
var proxyRedirect = redirect[ProxyInstance]{
	keys: []string{
		"proxy.listenAddr", "proxy.scope", "proxy.resolveVia",
		"proxy.requireToken", "proxy.token", "proxy.dialTimeoutSec",
	},
	registry: proxyRegistry,
	note: " Moved to the proxy \"" + DefaultProxySlug +
		"\"; this key still works and writes there.",
	slots: map[string][]string{
		"proxy.enabled": {
			"proxy.listenAddr", "proxy.scope", "proxy.resolveVia",
			"proxy.requireToken", "proxy.token", "proxy.dialTimeoutSec",
		},
	},
}

// handles reports whether this redirect answers for a settings key.
func (r redirect[T]) handles(key string) bool { return slices.Contains(r.keys, key) }

// schemaOf picks the redirected keys out of a destination schema, in the order the
// settings document listed them, with the note saying where each one went.
func (r redirect[T]) schemaOf(served []FieldSchema) []FieldSchema {
	out := make([]FieldSchema, 0, len(r.keys))
	for _, key := range r.keys {
		for _, f := range served {
			if f.Key != key {
				continue
			}
			f.Help += r.note
			out = append(out, f)
			break
		}
	}
	return out
}

// field resolves a redirected settings name -- a wire key or a CLI name -- to the
// destination field now serving it. It walks the redirect list rather than the whole
// destination table, so a field that never was a setting -- a slug, an enabled switch --
// cannot be reached through the settings command.
func (r redirect[T]) field(name string) (FieldOf[T], bool) {
	for _, wire := range r.keys {
		f, ok := r.registry.ByJSONKey(wire)
		if !ok {
			continue
		}
		if name == f.JSONKey || (f.CLIName != "" && name == f.CLIName) {
			return f, true
		}
	}
	return FieldOf[T]{}, false
}

// viewOf is the destination's values under the keys the settings document used to carry
// them, taken from a view the destination itself built.
func (r redirect[T]) viewOf(full map[string]any) map[string]any {
	out := make(map[string]any, len(r.keys))
	for _, key := range r.keys {
		f, ok := r.registry.ByJSONKey(key)
		if !ok {
			continue
		}
		if value, held := full[f.viewKey()]; held {
			out[f.viewKey()] = value
		}
	}
	return out
}

// IsLegacyTailnetKey reports whether this settings key is one that has moved onto the
// primary connection.
func IsLegacyTailnetKey(key string) bool { return tailnetRedirect.handles(key) }

// IsLegacyProxyKey reports whether this settings key is one that has moved onto the
// default proxy instance.
func IsLegacyProxyKey(key string) bool { return proxyRedirect.handles(key) }

// LegacyTailnetSchema is the tailnet's redirected keys as a CLI or a form sees them: the
// connection field's own metadata, with each field's availability resolved against this
// installation and a note saying where the setting now lives.
func LegacyTailnetSchema(app *Settings) []FieldSchema {
	return tailnetRedirect.schemaOf(tunnelRegistry.SchemaFor(app))
}

// LegacyProxySchema is the same for the proxy's redirected keys.
func LegacyProxySchema(app *Settings) []FieldSchema {
	return proxyRedirect.schemaOf(proxyRegistry.SchemaFor(app))
}

// SettingsCLISchema is every key the settings command and the interactive menu accept:
// the settings document's own fields, with the ones that have moved onto another entity
// back in the positions they held. Availability is left unresolved, as SettingsSchema
// leaves it, because a command-line caller is told what a key needs rather than shown a
// shorter list.
func SettingsCLISchema() []FieldSchema {
	moved := make(map[string]FieldSchema, len(tailnetRedirect.keys)+len(proxyRedirect.keys))
	for _, s := range tailnetRedirect.schemaOf(tunnelRegistry.Schema()) {
		moved[s.Key] = s
	}
	for _, s := range proxyRedirect.schemaOf(proxyRegistry.Schema()) {
		moved[s.Key] = s
	}
	slots := make(map[string][]string, len(tailnetRedirect.slots)+len(proxyRedirect.slots))
	for anchor, keys := range tailnetRedirect.slots {
		slots[anchor] = append(slots[anchor], keys...)
	}
	for anchor, keys := range proxyRedirect.slots {
		slots[anchor] = append(slots[anchor], keys...)
	}

	placed := make(map[string]bool, len(moved))
	slot := func(out []FieldSchema, anchor string) []FieldSchema {
		for _, key := range slots[anchor] {
			s, ok := moved[key]
			if !ok {
				continue
			}
			placed[key] = true
			out = append(out, s)
		}
		return out
	}

	settings := SettingsSchema()
	out := make([]FieldSchema, 0, len(settings)+len(moved))
	out = slot(out, "")
	for _, s := range settings {
		out = append(out, s)
		out = slot(out, s.Key)
	}
	// A key no slot named is still served, at the end. Losing it would take a working
	// command away with nothing said; the ordering test is what keeps it from landing here.
	for _, key := range slices.Concat(tailnetRedirect.keys, proxyRedirect.keys) {
		if s, ok := moved[key]; ok && !placed[key] {
			out = append(out, s)
		}
	}
	return out
}

// SettingByName resolves a settings name -- a CLI name or a wire key, redirected keys
// included -- to the schema that serves it.
func SettingByName(key string) (FieldSchema, bool) {
	for _, s := range SettingsCLISchema() {
		if s.Key == key || (s.CLIName != "" && s.CLIName == key) {
			return s, true
		}
	}
	return FieldSchema{}, false
}

// ParseSettingValue turns a command-line string into the typed value a settings key
// stores, and returns the wire key a patch carries it under.
//
// It is the one entry point for all three tables because a caller typing `hostname` is
// naming a setting and should not have to know that the value now lives on a connection.
// Parsing through the destination's own field is what makes the redirect total: the same
// normalization and the same refusal, whichever table the key ended up in.
func ParseSettingValue(key, raw string) (string, any, error) {
	if f, ok := tailnetRedirect.field(key); ok {
		v, err := f.ParseCLIValue(raw)
		return f.JSONKey, v, err
	}
	if f, ok := proxyRedirect.field(key); ok {
		v, err := f.ParseCLIValue(raw)
		return f.JSONKey, v, err
	}
	f, ok := settingsRegistry.ByCLIName(key)
	if !ok {
		if f, ok = settingsRegistry.ByJSONKey(key); !ok {
			return "", nil, fmt.Errorf("%q is not a known setting", key)
		}
	}
	v, err := f.ParseCLIValue(raw)
	return f.JSONKey, v, err
}

// LegacyTailnetView is the primary connection's values under the keys the settings
// document used to carry them. A connection that is not there contributes nothing, which
// is the honest answer: the values are gone with it, and inventing empty ones would
// report a device name of "" for a tailnet nothing is joining.
func LegacyTailnetView(s Settings, tunnels []Tunnel) map[string]any {
	i := primaryIndex(tunnels)
	if i < 0 {
		return nil
	}
	return tailnetRedirect.viewOf(BuildTunnelView(tunnels[i], &s))
}

// LegacyProxyView is the same for the default proxy instance.
func LegacyProxyView(s Settings, proxies []ProxyInstance) map[string]any {
	i := defaultProxyIndex(proxies)
	if i < 0 {
		return nil
	}
	return proxyRedirect.viewOf(BuildProxyView(proxies[i], &s))
}

// SettingsViewOf is the settings map the API serves: what the settings document holds,
// plus the keys that have moved onto another entity. Every half comes through one
// function so no consumer can be served part of the answer.
func SettingsViewOf(c *Config) map[string]any {
	view := BuildSettingsView(c.Settings)
	maps.Copy(view, LegacyTailnetView(c.Settings, c.Tunnels))
	maps.Copy(view, LegacyProxyView(c.Settings, c.Proxies))
	return view
}

// ApplyPatchTo applies a settings patch to the whole document, which is what a write goes
// through now that some of the keys name an entity rather than the app. Everything the
// settings document still holds is applied to it; a key that has moved is applied to its
// destination through that destination's own field, so it passes exactly the rule a write
// on that entity's form passes.
func ApplyPatchTo(cfg *Config, patch map[string]json.RawMessage) error {
	settingsPatch := make(map[string]json.RawMessage, len(patch))
	tailnetPatch := make(map[string]json.RawMessage)
	proxyPatch := make(map[string]json.RawMessage)
	for key, raw := range patch {
		switch {
		case IsLegacyTailnetKey(key):
			tailnetPatch[key] = raw
		case IsLegacyProxyKey(key):
			proxyPatch[key] = raw
		default:
			settingsPatch[key] = raw
		}
	}

	// The settings go first, and the order is load-bearing rather than incidental: the
	// module switches are settings, and a redirected field inside a module is judged
	// against the configuration this patch is asking for. Turning a module on and setting
	// the field it governs is one action to a user, so it has to be one save.
	before := cfg.Settings
	if err := ApplySettingsPatch(&cfg.Settings, settingsPatch); err != nil {
		return err
	}
	applyTunnelModuleSwitchChanges(cfg, &before)

	if len(tailnetPatch) > 0 {
		i := primaryIndex(cfg.Tunnels)
		if i < 0 {
			return fmt.Errorf("connection %q is missing, so there is nothing to apply %s to",
				PrimaryTunnelID, keyList(tailnetPatch))
		}
		if err := ApplyTunnelPatch(&cfg.Tunnels[i], &cfg.Settings, tailnetPatch); err != nil {
			return err
		}
	}
	if len(proxyPatch) > 0 {
		i := defaultProxyIndex(cfg.Proxies)
		if i < 0 {
			return fmt.Errorf("proxy %q is missing, so there is nothing to apply %s to",
				DefaultProxyID, keyList(proxyPatch))
		}
		if err := ApplyProxyPatch(&cfg.Proxies[i], &cfg.Settings, proxyPatch); err != nil {
			return err
		}
	}
	return nil
}

// keyList names the keys of a patch in a stable order, for an error a person reads.
func keyList(patch map[string]json.RawMessage) string {
	return strings.Join(slices.Sorted(maps.Keys(patch)), ", ")
}

// applyTunnelModuleSwitchChanges shelves each connection's fields for every module this
// patch switched off and puts them back for every module it switched on, which is the same
// rule the settings document applies to its own -- stated once more here because a
// module's fields can live on both, and a switch reading off while a connection still joins
// a private coordination server would be a setting the user can neither see nor turn off.
func applyTunnelModuleSwitchChanges(cfg *Config, before *Settings) {
	for _, sw := range settingsFields {
		if sw.ModuleSwitch == ModuleCore {
			continue
		}
		was, now := typed[bool](sw.get(before)), typed[bool](sw.get(&cfg.Settings))
		if was == now {
			continue
		}
		for i := range cfg.Tunnels {
			t := &cfg.Tunnels[i]
			if was {
				t.Shelved = tunnelRegistry.shelve(t, sw.ModuleSwitch, t.Shelved)
			} else {
				t.Shelved = tunnelRegistry.unshelve(t, sw.ModuleSwitch, t.Shelved)
			}
		}
	}
}

// primaryIndex is where the connection every install has sits in a list, or -1.
func primaryIndex(tunnels []Tunnel) int {
	for i := range tunnels {
		if tunnels[i].ID == PrimaryTunnelID {
			return i
		}
	}
	return -1
}

// defaultProxyIndex is where the instance every install has sits in a list, or -1.
func defaultProxyIndex(proxies []ProxyInstance) int {
	for i := range proxies {
		if proxies[i].ID == DefaultProxyID {
			return i
		}
	}
	return -1
}
