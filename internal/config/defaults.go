// SPDX-License-Identifier: MIT

package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

// DefaultStateDir is where identity, config and presets live when no override is given.
func DefaultStateDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(dir, AppDirName), nil
}

// Defaults returns the zero-config first-run document, built from the default each
// registry field declares. StateDir is left empty for the caller to fill from
// DefaultStateDir or an override, since resolution order decides it.
func Defaults() *Config {
	var s Settings
	for _, f := range settingsFields {
		if f.set != nil {
			f.set(&s, f.defaultValue())
		}
	}
	return &Config{
		Version:  ConfigVersion,
		Settings: s,
		Tunnels:  []Tunnel{primaryTunnel()},
		Proxies:  []ProxyInstance{defaultProxy(true, DefaultProxyListenAddr, reachOneConnection(PrimaryTunnelID))},
	}
}

// applyDefaults fills empty fields on a loaded document so older or partial configs
// keep working. It never overwrites a value the user set.
func applyDefaults(c *Config) {
	settingsRegistry.BackfillDefaults(&c.Settings)
	// A stored connection is back-filled the same way, for the same reason: one written
	// before a field existed carries nothing under it, and a connection with no hostname
	// template would render no device name at all.
	for i := range c.Tunnels {
		tunnelRegistry.BackfillDefaults(&c.Tunnels[i])
	}
	adoptModulesInUse(c)
	// Connections are deliberately not back-filled here. A document that names none is a
	// document whose connections were removed, and re-adding one on the next write would
	// resurrect a connection the user deleted. The only two moments a connection is
	// synthesized are a first run and the migration, both of which say so explicitly.
	for i := range c.Forwards {
		if c.Forwards[i].Direction == ToLocal && c.Forwards[i].BindAddr == "" {
			c.Forwards[i].BindAddr = DefaultBindAddr
		}
		// A forward that names no connection was written when there was only one to name.
		// Filled in rather than read as "the primary one" at every use: the document then
		// says which network each forward crosses, and every reader answers that question
		// the same way.
		if c.Forwards[i].TunnelID == "" {
			c.Forwards[i].TunnelID = PrimaryTunnelID
		}
	}
}

// adoptModulesInUse turns on any module whose stored configuration already carries a
// non-default value. A config written before the module existed -- or before that setting
// was placed behind one -- has those values set while the switch reads off, and the first
// write would silently reset them. Adopting the stored configuration is what keeps an
// upgrade from moving a node onto a coordination server it was never pointed at.
//
// The connections are walked alongside the settings because a module can own fields of
// both: the switch is a fact about the installation, but the value it governs may be a
// connection's. Looking only at the settings would leave a document that carries a private
// coordination server reporting the module off, which is the exact state this exists to
// prevent -- and one nothing on screen could correct, since an off module hides its own
// fields.
func adoptModulesInUse(c *Config) {
	for _, sw := range settingsFields {
		if sw.ModuleSwitch == ModuleCore || typed[bool](sw.get(&c.Settings)) {
			continue
		}
		if moduleIsConfigured(c, sw.ModuleSwitch) {
			sw.set(&c.Settings, true)
		}
	}
}

// moduleIsConfigured reports whether anything this module owns holds a value other than
// the one it would have had if the module had never been touched.
func moduleIsConfigured(c *Config, m FeatureModule) bool {
	for _, f := range settingsFields {
		if f.Module != m || f.get == nil {
			continue
		}
		v := f.get(&c.Settings)
		// A switch that is off is the absence of configuration, never evidence of it.
		// Counting it would make a switch whose default later turns on adopt the module
		// for every document written before the change, which stores the old default.
		if f.Kind == KindBool && !typed[bool](v) {
			continue
		}
		if !reflect.DeepEqual(v, f.defaultValue()) {
			return true
		}
	}
	for i := range c.Tunnels {
		for _, f := range tunnelFields {
			if f.Module != m || f.get == nil || !tunnelRegistry.applies(f, &c.Tunnels[i]) {
				continue
			}
			if !reflect.DeepEqual(f.get(&c.Tunnels[i]), f.defaultValue()) {
				return true
			}
		}
	}
	return false
}

// SanitizeHostname reduces s to a DNS label Tailscale will accept: lowercase
// alphanumerics and interior hyphens, at most 63 characters.
func SanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	return out
}

// RenderHostname expands the {hostname}, {os} and {id} tokens of a hostname template.
// A template that renders empty falls back to the app name so a node is never nameless.
func RenderHostname(template, osHostname, machineID string) string {
	if template == "" {
		template = DefaultHostnameTemplate
	}
	r := strings.NewReplacer(
		"{hostname}", SanitizeHostname(osHostname),
		"{os}", runtime.GOOS,
		"{id}", machineID,
	)
	out := SanitizeHostname(r.Replace(template))
	if out == "" {
		return AppDirName
	}
	return out
}

// NewMachineID returns a short stable identifier for this install, used by the
// {id} hostname token to keep fleet hostnames unique.
func NewMachineID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate machine id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// NewForwardID returns a unique identifier for a new forward.
func NewForwardID() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate forward id: %w", err)
	}
	return "f_" + hex.EncodeToString(b), nil
}

// OSHostname returns this machine's hostname, or "unknown" when the OS cannot say.
func OSHostname() string {
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "unknown"
	}
	// Strip any DNS suffix; only the first label is meaningful as a device name.
	if i := strings.Index(h, "."); i > 0 {
		h = h[:i]
	}
	return h
}
