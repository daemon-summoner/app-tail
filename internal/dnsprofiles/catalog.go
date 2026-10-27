// SPDX-License-Identifier: MIT

// Package dnsprofiles supplies the named resolver sets the system-wide DNS switch picks
// between, and the grammar of a single upstream address.
//
// A profile is a name and an ordered list of upstreams. The order is the whole meaning:
// the first is where every name goes, and the rest are tried only when it does not answer
// at all. A backup is a fallback for an unreachable server, never a second opinion on an
// answer -- "no such name" is an answer, which is what keeps a filtering resolver
// filtering.
package dnsprofiles

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
)

// SystemID names the profile that changes nothing. It is the default and the way back:
// selecting it takes app-tail's override off the machine entirely rather than pointing
// the machine at a different resolver.
const SystemID = "system"

// TailnetID names the profile that resolves through whatever nameservers the tailnet
// publishes -- the ones the admin console configures, which every other device on the
// tailnet already uses. Its servers are not stored: they are read from the node each time
// the profile is applied, so changing them in the admin console changes them here without
// anybody editing a profile.
const TailnetID = "tailnet"

// NeedsTailnet reports a profile whose resolvers come from the tailnet rather than from
// the stored list. Callers that build the resolver pool have to fill the servers in first,
// and a caller that forgets would apply a profile with no resolvers at all.
func NeedsTailnet(id string) bool { return id == TailnetID }

// Quad9ID names the shipped profile that resolves through Quad9 over HTTPS. It is also
// what a fresh install looks up resolver hostnames through, which is why it ships: the
// bootstrap lookup has to go to a resolver that is reached at a literal address and
// verified by certificate, or the address a hostname resolver ends up at is whatever the
// network decided to answer.
const Quad9ID = "quad9"

// Quad9UnfilteredID names the shipped profile that resolves through Quad9's unsecured
// addresses: the same resolver with the malware feed and DNSSEC validation switched off.
// It exists as the answer to "is this site down, or did my resolver block it".
const Quad9UnfilteredID = "quad9-unfiltered"

// MaxServers bounds one profile's upstream list. Failover is sequential, so a long list
// is a long wait before the first answer, and nobody has five resolvers they trust
// equally.
const MaxServers = 4

// builtIn is the shipped catalog. System comes first because it is the default and the
// undo; the rest are ordered by how often they are wanted rather than alphabetically,
// since this list is a picker, not a reference.
//
// The public resolvers are shipped as DNS over HTTPS at their own addresses, not as bare
// IPs. Plain DNS on port 53 is answered by whatever sits on the path -- a router or an ISP
// that redirects port 53 answers in Cloudflare's name, and the switch looks like it did
// nothing because nothing about the machine's resolution changed. HTTPS on 443 reaches the
// resolver that was picked or it fails loudly, which is the promise this feature makes. The
// address is a literal, so choosing one of these never depends on resolving a name.
//
// Quad9 leads them because it is the default bootstrap resolver: it answers at a literal
// address, filters known-malicious names, and keeps no per-query logs.
//
// Both Quad9 tiers ship because the filtering is the reason to pick it and also the reason a
// name can stop resolving: 9.9.9.9 refuses names on its threat feed, and a false positive
// there looks exactly like a site being down. 9.9.9.10 is the same resolver with the feed and
// DNSSEC validation off, so the pair is the check -- if a name answers on the second and not
// the first, Quad9 blocked it deliberately.
var builtIn = []config.DNSProfile{
	{ID: SystemID, Name: "System default", BuiltIn: true},
	{ID: TailnetID, Name: "Tailnet DNS", BuiltIn: true},
	{ID: Quad9ID, Name: "Quad9 (malware blocking)", Servers: []string{"https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"}, BuiltIn: true},
	{ID: Quad9UnfilteredID, Name: "Quad9 (unfiltered)", Servers: []string{"https://9.9.9.10/dns-query", "https://149.112.112.10/dns-query"}, BuiltIn: true},
	{ID: "cloudflare", Name: "Cloudflare", Servers: []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"}, BuiltIn: true},
	{ID: "google", Name: "Google", Servers: []string{"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"}, BuiltIn: true},
}

// OverrideWanted reports settings that ask for this machine's own resolver to be changed.
// The module being on is not enough: the System default profile is the one that
// deliberately changes nothing, so treating it as a want would arrange administrator
// rights, a login item that elevates and a helper session for a setting that does nothing.
//
// It lives here because three separate decisions read it -- the elevation prompt before an
// agent exists, the Windows login item's form, and the reconcile that arranges the machine
// -- and a copy that drifted would put a password dialog in front of the one profile that
// exists to avoid needing one.
func OverrideWanted(s config.Settings) bool {
	return s.SystemDNSEnabled && s.SystemDNSProfile != SystemID
}

// BuiltIn returns a copy of the shipped catalog, servers included.
func BuiltIn() []config.DNSProfile {
	out := make([]config.DNSProfile, len(builtIn))
	for i, p := range builtIn {
		out[i] = p
		out[i].Servers = append([]string(nil), p.Servers...)
	}
	return out
}

// IsBuiltIn reports whether an id belongs to the shipped catalog, which callers use to
// refuse editing or deleting entries they do not own.
func IsBuiltIn(id string) bool {
	for _, p := range builtIn {
		if p.ID == id {
			return true
		}
	}
	return false
}

// Catalog merges the shipped profiles with the user's own, built-ins first and user
// entries sorted by name so the picker is stable between loads.
func Catalog(user []config.DNSProfile) []config.DNSProfile {
	out := BuiltIn()
	custom := make([]config.DNSProfile, 0, len(user))
	for _, p := range user {
		if IsBuiltIn(p.ID) {
			continue // a shipped profile is never shadowed by a stored copy
		}
		p.BuiltIn = false
		p.Servers = append([]string(nil), p.Servers...)
		custom = append(custom, p)
	}
	// Stable: two user profiles can differ only in case, and an unstable sort would
	// reorder them between loads, moving entries under the user's cursor.
	sort.SliceStable(custom, func(i, j int) bool {
		return strings.ToLower(custom[i].Name) < strings.ToLower(custom[j].Name)
	})
	return append(out, custom...)
}

// ByID finds one profile in the merged catalog.
func ByID(user []config.DNSProfile, id string) (config.DNSProfile, bool) {
	for _, p := range Catalog(user) {
		if p.ID == id {
			return p, true
		}
	}
	return config.DNSProfile{}, false
}

// Validate checks a user-supplied profile. It is not applied to the shipped catalog: the
// system profile deliberately has no servers, and a user profile with none would be a
// switch that silently does nothing.
func Validate(p config.DNSProfile) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(p.Servers) == 0 {
		return fmt.Errorf("at least one resolver address is required; to leave this machine's DNS alone, pick %q instead", "System default")
	}
	if len(p.Servers) > MaxServers {
		return fmt.Errorf("at most %d resolver addresses, got %d", MaxServers, len(p.Servers))
	}
	seen := make(map[string]bool, len(p.Servers))
	for i, s := range p.Servers {
		u, err := ParseUpstream(s)
		if err != nil {
			return fmt.Errorf("resolver %d: %w", i+1, err)
		}
		key := strings.ToLower(strings.TrimSpace(s))
		if seen[key] {
			// A duplicate backup is a backup that does not back anything up, and it
			// reads on the card as though it does.
			return fmt.Errorf("resolver %d repeats %s; a backup has to be a different server to be a backup", i+1, u.Text)
		}
		seen[key] = true
	}
	return nil
}

// Upstreams parses every address in a profile, in order.
func Upstreams(p config.DNSProfile) ([]Upstream, error) {
	out := make([]Upstream, 0, len(p.Servers))
	for i, s := range p.Servers {
		u, err := ParseUpstream(s)
		if err != nil {
			return nil, fmt.Errorf("%s: resolver %d: %w", p.Name, i+1, err)
		}
		out = append(out, u)
	}
	return out, nil
}

// Dialable returns the upstreams in a profile that carry a literal address, in order.
//
// It is what a profile can offer as a bootstrap resolver -- the one that turns another
// profile's hostnames into addresses. An upstream named by hostname is left out because it
// cannot answer the question it would be asked: resolving its own name is the thing that
// has not happened yet. An address that does not parse is left out too, and reported where
// the pool is built rather than swallowed here.
func Dialable(p config.DNSProfile) []Upstream {
	out := make([]Upstream, 0, len(p.Servers))
	for _, s := range p.Servers {
		u, err := ParseUpstream(s)
		if err != nil {
			continue
		}
		if _, ok := u.Endpoint(); ok {
			out = append(out, u)
		}
	}
	return out
}

// NameTaken reports whether a name is already in use, ignoring case and ignoring the
// profile being edited. Names are unique because the CLI and the tray resolve a profile
// by the name the user typed, and two profiles called "Work" make that a coin flip.
func NameTaken(user []config.DNSProfile, name, exceptID string) bool {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, p := range Catalog(user) {
		if p.ID == exceptID {
			continue
		}
		if strings.ToLower(strings.TrimSpace(p.Name)) == want {
			return true
		}
	}
	return false
}

// NewID derives a stable, readable id from a profile name, suffixed as needed so it does
// not collide with an existing entry.
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
	// Runs collapse so "Home  Wi-Fi" is home-wi-fi rather than home--wi-fi: the id shows
	// up in CLI output and in URLs, and a doubled separator reads as a mistake.
	base := strings.Trim(b.String(), "-")
	for strings.Contains(base, "--") {
		base = strings.ReplaceAll(base, "--", "-")
	}
	if base == "" {
		base = "profile"
	}
	id := base
	for i := 2; IsBuiltIn(id) || taken(id); i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	return id
}
