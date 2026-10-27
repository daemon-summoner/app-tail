// SPDX-License-Identifier: MIT

package config

// Keeping credentials out of config.json.
//
// The split happens at the file boundary and nowhere else. In memory a document carries its
// credentials exactly where it always did, so every reader keeps reading
// cfg.Tunnels[i].Tailscale.AuthKey; on the way to disk they are lifted out into
// secrets.json (see internal/secretstore), and on the way back they are put back in.
//
// Which fields are credentials is the registries' answer -- every field whose kind is secret
// -- so a secret field added to a registry is kept out of config.json without anything here
// changing.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sellitus/app-tail/internal/secretstore"
)

// The kinds of entity a credential is stored under in secrets.json, each keyed by its own
// stable id.
const (
	secretsOfSettings = "settings"
	secretsOfTunnels  = "tunnels"
	secretsOfProxies  = "proxies"
)

// settingsSecretsID is the id the settings document's credentials are stored under. There
// is only ever one settings document, so the id is fixed.
const settingsSecretsID = "settings"

// controlServerKey sits beside a tailnet connection's credentials in secrets.json and names
// the control server they were saved for. The "@" keeps it apart from every wire key.
//
// config.json and secrets.json are separate files, so the pair on disk can come from two
// moments: a crash between the two writes of a save, or an older config.json restored
// beside the current credentials. A credential is only put back into a connection that
// still names the server it was saved for; anything else would hand one tailnet's key to
// another tailnet's server on the next start.
const controlServerKey = "@controlServer"

// collectSecrets reads every credential cfg carries, by entity kind, id and wire key. cfg
// is not changed.
func collectSecrets(cfg *Config) secretstore.Secrets {
	out := secretstore.Secrets{}
	add := func(kind, id string, fields map[string]string) {
		if len(fields) == 0 {
			return
		}
		if out[kind] == nil {
			out[kind] = map[string]map[string]string{}
		}
		out[kind][id] = fields
	}
	add(secretsOfSettings, settingsSecretsID, settingsRegistry.secretValues(&cfg.Settings))
	for i := range cfg.Tunnels {
		fields := tunnelRegistry.secretValues(&cfg.Tunnels[i])
		if ts := cfg.Tunnels[i].Tailscale; ts != nil && len(fields) > 0 {
			fields[controlServerKey] = effectiveControlURL(ts.ControlURL)
		}
		add(secretsOfTunnels, cfg.Tunnels[i].ID, fields)
	}
	for i := range cfg.Proxies {
		add(secretsOfProxies, cfg.Proxies[i].ID, proxyRegistry.secretValues(&cfg.Proxies[i]))
	}
	return out
}

// clearSecrets empties every credential field in cfg.
func clearSecrets(cfg *Config) {
	settingsRegistry.clearSecretValues(&cfg.Settings)
	for i := range cfg.Tunnels {
		tunnelRegistry.clearSecretValues(&cfg.Tunnels[i])
	}
	for i := range cfg.Proxies {
		proxyRegistry.clearSecretValues(&cfg.Proxies[i])
	}
}

// mergeSecrets puts held back into cfg, matching each credential to its entity by id.
//
// A field cfg already holds a value for keeps it. This build never writes a credential into
// config.json, so one found there was put there by an older build, a hand edit or a restored
// older copy -- each a statement about this document more recent than secrets.json.
// Credentials for an id cfg does not have are left out; the next write drops them.
func mergeSecrets(cfg *Config, held secretstore.Secrets) {
	settingsRegistry.fillSecretValues(&cfg.Settings, held[secretsOfSettings][settingsSecretsID])
	for i := range cfg.Tunnels {
		tunnelRegistry.fillSecretValues(&cfg.Tunnels[i], credentialsFor(&cfg.Tunnels[i], held[secretsOfTunnels][cfg.Tunnels[i].ID]))
	}
	for i := range cfg.Proxies {
		proxyRegistry.fillSecretValues(&cfg.Proxies[i], held[secretsOfProxies][cfg.Proxies[i].ID])
	}
}

// credentialsFor is the part of held that t may be given. A tailnet connection gets its
// credentials only when they were saved for the control server it names now.
func credentialsFor(t *Tunnel, held map[string]string) map[string]string {
	if t.Tailscale == nil || held[controlServerKey] == effectiveControlURL(t.Tailscale.ControlURL) {
		return held
	}
	return nil
}

// secretFields lists the secret fields that apply to v.
func (r *Registry[T]) secretFields(v *T) []FieldOf[T] {
	var out []FieldOf[T]
	for _, f := range r.fields {
		if f.Kind.Secret() && f.set != nil && r.applies(f, v) {
			out = append(out, f)
		}
	}
	return out
}

// secretValues reads v's non-empty credentials by wire key.
func (r *Registry[T]) secretValues(v *T) map[string]string {
	out := map[string]string{}
	for _, f := range r.secretFields(v) {
		if value := secretString(f, v); value != "" {
			out[f.JSONKey] = value
		}
	}
	return out
}

// clearSecretValues empties v's credentials. A field already empty is not written, so a
// connection with no block for its type does not gain an empty one.
func (r *Registry[T]) clearSecretValues(v *T) {
	for _, f := range r.secretFields(v) {
		if secretString(f, v) != "" {
			f.set(v, "")
		}
	}
}

// fillSecretValues writes each held credential into a field of v that is empty.
func (r *Registry[T]) fillSecretValues(v *T, held map[string]string) {
	if len(held) == 0 {
		return
	}
	for _, f := range r.secretFields(v) {
		if value := held[f.JSONKey]; value != "" && secretString(f, v) == "" {
			f.set(v, value)
		}
	}
}

// secretString is f's value on v. Every secret kind is text, so anything else is a table
// error, and it panics for the same reason NewRegistry does: a credential this cannot read
// is one that would silently stay in config.json.
func secretString[T any](f FieldOf[T], v *T) string {
	value, ok := f.get(v).(string)
	if !ok {
		panic(fmt.Sprintf("config: secret field %s holds %T, not text", f.JSONKey, f.get(v)))
	}
	return value
}

// secretKeyNames are the names a credential has ever been stored under in config.json: each
// secret field's wire key ("proxy.token", which the settings document used before proxies
// were instances) and the last segment of it, which is the member's name inside its block
// ("wg.peer.presharedKey" is "presharedKey" inside "peer").
func secretKeyNames() map[string]bool {
	names := map[string]bool{}
	add := func(key string) {
		names[key] = true
		names[key[strings.LastIndex(key, ".")+1:]] = true
	}
	for _, f := range settingsRegistry.Fields() {
		if f.Kind.Secret() {
			add(f.JSONKey)
		}
	}
	for _, f := range tunnelRegistry.Fields() {
		if f.Kind.Secret() {
			add(f.JSONKey)
		}
	}
	for _, f := range proxyRegistry.Fields() {
		if f.Kind.Secret() {
			add(f.JSONKey)
		}
	}
	return names
}

// scrubSecrets returns the stored document raw with every credential removed, for a copy
// kept beside config.json. It works on the raw document rather than a decoded Config
// because the copy is of an older shape, kept so an older build can read it, and decoding
// it into this build's types would drop what that build still needs.
//
// A document with no credential in it comes back byte for byte. One with credentials is
// re-encoded, which keeps every value and may reorder keys.
func scrubSecrets(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers stay as written: a float64 round trip would change a large integer.
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("read the document to remove its credentials: %w", err)
	}
	if !scrubTree(doc, secretKeyNames()) {
		return raw, nil
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode the document without its credentials: %w", err)
	}
	return append(out, '\n'), nil
}

// scrubTree removes every non-empty text value stored under a credential's name anywhere in
// node, reporting whether it removed any.
func scrubTree(node any, names map[string]bool) bool {
	removed := false
	switch held := node.(type) {
	case map[string]any:
		for key, child := range held {
			if text, ok := child.(string); ok && text != "" && names[key] {
				delete(held, key)
				removed = true
				continue
			}
			if scrubTree(child, names) {
				removed = true
			}
		}
	case []any:
		for _, child := range held {
			if scrubTree(child, names) {
				removed = true
			}
		}
	}
	return removed
}
