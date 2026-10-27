// SPDX-License-Identifier: MIT

// Package presets supplies the service templates that prefill the add-forward flow.
package presets

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
)

// builtIn is the shipped catalog. Entries are ordered by how often they are wanted
// rather than alphabetically, since this list is a picker, not a reference.
var builtIn = []config.Preset{
	{ID: "ssh", Name: "SSH", Protocol: config.TCP, RemotePort: 22, BuiltIn: true},
	{ID: "http", Name: "HTTP", Protocol: config.TCP, RemotePort: 80, BuiltIn: true},
	{ID: "https", Name: "HTTPS", Protocol: config.TCP, RemotePort: 443, BuiltIn: true},
	{ID: "rdp", Name: "RDP", Protocol: config.TCP, RemotePort: 3389, BuiltIn: true},
	{ID: "vnc", Name: "VNC", Protocol: config.TCP, RemotePort: 5900, BuiltIn: true},
	{ID: "postgresql", Name: "PostgreSQL", Protocol: config.TCP, RemotePort: 5432, BuiltIn: true},
	{ID: "mysql", Name: "MySQL", Protocol: config.TCP, RemotePort: 3306, BuiltIn: true},
	{ID: "redis", Name: "Redis", Protocol: config.TCP, RemotePort: 6379, BuiltIn: true},
	{ID: "smb", Name: "SMB", Protocol: config.TCP, RemotePort: 445, BuiltIn: true},
	{ID: "dns", Name: "DNS", Protocol: config.Both, RemotePort: 53, BuiltIn: true},
	{ID: "wireguard", Name: "WireGuard", Protocol: config.UDP, RemotePort: 51820, BuiltIn: true},
}

// BuiltIn returns a copy of the shipped catalog.
func BuiltIn() []config.Preset {
	return append([]config.Preset(nil), builtIn...)
}

// IsBuiltIn reports whether an id belongs to the shipped catalog, which callers
// use to refuse deletion of entries they do not own.
func IsBuiltIn(id string) bool {
	for _, p := range builtIn {
		if p.ID == id {
			return true
		}
	}
	return false
}

// Catalog merges the shipped presets with the user's own, built-ins first and
// user entries sorted by name so the picker is stable between loads.
func Catalog(user []config.Preset) []config.Preset {
	out := BuiltIn()
	custom := make([]config.Preset, 0, len(user))
	for _, p := range user {
		if IsBuiltIn(p.ID) {
			continue // a shipped preset is never shadowed by a stored copy
		}
		p.BuiltIn = false
		custom = append(custom, p)
	}
	// Stable: nothing stops two user presets sharing a name, and an unstable sort
	// would reorder them between loads, moving entries under the user's cursor.
	sort.SliceStable(custom, func(i, j int) bool { return custom[i].Name < custom[j].Name })
	return append(out, custom...)
}

// Validate checks a user-supplied preset.
func Validate(p config.Preset) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("name is required")
	}
	switch p.Protocol {
	case config.TCP, config.UDP, config.Both:
	default:
		return fmt.Errorf("protocol must be %q, %q or %q, got %q", config.TCP, config.UDP, config.Both, p.Protocol)
	}
	if p.RemotePort < 1 || p.RemotePort > 65535 {
		return fmt.Errorf("remotePort must be 1-65535, got %d", p.RemotePort)
	}
	return nil
}

// NewID derives a stable, readable id from a preset name, suffixed as needed so it
// does not collide with an existing entry.
func NewID(name string, taken func(string) bool) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	base := strings.Trim(b.String(), "-")
	if base == "" {
		base = "preset"
	}
	id := base
	for i := 2; IsBuiltIn(id) || taken(id); i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	return id
}
