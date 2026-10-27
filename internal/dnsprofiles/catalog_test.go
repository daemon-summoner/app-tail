// SPDX-License-Identifier: MIT

package dnsprofiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

func find(list []config.DNSProfile, id string) (config.DNSProfile, bool) {
	for _, p := range list {
		if p.ID == id {
			return p, true
		}
	}
	return config.DNSProfile{}, false
}

func TestBuiltInCatalogCarriesTheDocumentedProfiles(t *testing.T) {
	want := map[string][]string{
		SystemID:          nil,
		TailnetID:         nil,
		Quad9ID:           {"https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"},
		Quad9UnfilteredID: {"https://9.9.9.10/dns-query", "https://149.112.112.10/dns-query"},
		"cloudflare":      {"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"},
		"google":          {"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"},
	}
	got := BuiltIn()
	if len(got) != len(want) {
		t.Fatalf("built-in catalog has %d entries, want %d", len(got), len(want))
	}
	if got[0].ID != SystemID {
		t.Errorf("first entry is %q, want %q -- the default and the undo comes first", got[0].ID, SystemID)
	}
	for id, servers := range want {
		p, ok := find(got, id)
		if !ok {
			t.Fatalf("built-in catalog is missing %q", id)
		}
		if !p.BuiltIn {
			t.Errorf("%s: BuiltIn = false, want true", id)
		}
		if strings.TrimSpace(p.Name) == "" {
			t.Errorf("%s: has no name", id)
		}
		if len(p.Servers) != len(servers) {
			t.Fatalf("%s: servers = %v, want %v", id, p.Servers, servers)
		}
		for i, s := range servers {
			if p.Servers[i] != s {
				t.Errorf("%s: server %d = %q, want %q", id, i, p.Servers[i], s)
			}
			if _, err := ParseUpstream(s); err != nil {
				t.Errorf("%s: shipped server %q does not parse: %v", id, s, err)
			}
		}
	}
}

// A network that redirects port 53 answers plain queries itself, so a shipped profile of
// bare IPs would silently resolve through the network it was picked to get away from --
// the switch appears to work and nothing about resolution changes. Every shipped resolver
// is therefore encrypted, and this is what stops a well-meaning "simplify these to IPs".
func TestEveryShippedResolverIsEncrypted(t *testing.T) {
	for _, p := range BuiltIn() {
		for _, s := range p.Servers {
			u, err := ParseUpstream(s)
			if err != nil {
				t.Fatalf("%s: shipped server %q does not parse: %v", p.ID, s, err)
			}
			if u.Protocol == Plain {
				t.Errorf("%s: %q is plain DNS, which a network that redirects port 53 answers itself", p.ID, s)
			}
		}
	}
}

// The tailnet profile stores no servers for the same reason the system profile stores
// none: what it resolves through is decided elsewhere. Storing a copy of the tailnet's
// nameservers would go stale the moment the admin console changed them.
func TestTheTailnetProfileNamesNoServersOfItsOwn(t *testing.T) {
	p, ok := find(BuiltIn(), TailnetID)
	if !ok {
		t.Fatalf("no %q profile", TailnetID)
	}
	if len(p.Servers) != 0 {
		t.Errorf("%q has servers %v, want none -- they come from the tailnet", TailnetID, p.Servers)
	}
	if !NeedsTailnet(p.ID) {
		t.Errorf("NeedsTailnet(%q) = false, so nothing would fill its servers in", p.ID)
	}
	if NeedsTailnet(SystemID) {
		t.Errorf("NeedsTailnet(%q) = true, which would send the do-nothing profile looking for resolvers", SystemID)
	}
}

// The shipped default for looking up a resolver's hostname has to be reachable without a
// lookup of its own, or a fresh install could not bootstrap anything at all.
func TestTheDefaultBootstrapResolverNeedsNoLookupOfItsOwn(t *testing.T) {
	p, ok := find(BuiltIn(), Quad9ID)
	if !ok {
		t.Fatalf("no %q profile", Quad9ID)
	}
	if len(p.Servers) == 0 {
		t.Fatalf("%q ships with no resolvers", Quad9ID)
	}
	if got := Dialable(p); len(got) != len(p.Servers) {
		t.Errorf("%q: %d of %d resolvers can be dialled without a lookup, want all of them",
			Quad9ID, len(got), len(p.Servers))
	}
}

// A resolver named by hostname cannot look another resolver's hostname up: resolving its own
// name is the thing that has not happened yet. Handing one out as a bootstrap would be a pool
// whose every entry is waiting on the answer it was asked for.
func TestDialableLeavesOutTheResolversThatWouldNeedALookupThemselves(t *testing.T) {
	p := config.DNSProfile{Name: "Mixed", Servers: []string{
		"https://dns.example.com/dns-query",
		"tls://9.9.9.9",
		"tls://dns.example.com",
		"192.0.2.53",
		"not a resolver address",
	}}

	got := Dialable(p)

	want := []string{"tls://9.9.9.9", "192.0.2.53"}
	if len(got) != len(want) {
		t.Fatalf("dialable = %+v, want %v", got, want)
	}
	for i, text := range want {
		if got[i].Text != text {
			t.Errorf("dialable %d = %q, want %q", i, got[i].Text, text)
		}
	}
}

// The system profile is the way back: it must name no servers, or picking it would point
// the machine at a resolver instead of taking the override off.
func TestTheSystemProfileNamesNoServers(t *testing.T) {
	p, ok := find(BuiltIn(), SystemID)
	if !ok {
		t.Fatalf("no %q profile", SystemID)
	}
	if len(p.Servers) != 0 {
		t.Errorf("%q has servers %v, want none", SystemID, p.Servers)
	}
}

// The returned slice must not alias package state, or one caller's edit would rewrite the
// catalog for everyone. Servers is a slice of its own, so the copy has to be deep.
func TestBuiltInDoesNotAliasPackageState(t *testing.T) {
	first := BuiltIn()
	for i := range first {
		first[i].Name = "clobbered"
		for j := range first[i].Servers {
			first[i].Servers[j] = "9.9.9.9"
		}
	}
	second := BuiltIn()
	for _, p := range second {
		if p.Name == "clobbered" {
			t.Fatalf("%s: the shipped catalog was edited through a returned copy", p.ID)
		}
		for _, s := range p.Servers {
			if s == "9.9.9.9" {
				t.Fatalf("%s: the shipped servers were edited through a returned copy", p.ID)
			}
		}
	}
}

func TestCatalogPutsBuiltInsFirstAndSortsTheRest(t *testing.T) {
	user := []config.DNSProfile{
		{ID: "work", Name: "work vpn", Servers: []string{"10.0.0.1"}},
		{ID: "nextdns", Name: "NextDNS", Servers: []string{"https://dns.nextdns.io/abc"}},
		// A stored copy of a shipped id is dropped rather than shadowing the shipped one.
		{ID: "cloudflare", Name: "Not Cloudflare", Servers: []string{"10.0.0.9"}},
	}
	got := Catalog(user)
	var ids []string
	for _, p := range got {
		ids = append(ids, p.ID)
	}
	want := []string{SystemID, TailnetID, Quad9ID, Quad9UnfilteredID, "cloudflare", "google", "nextdns", "work"}
	if len(ids) != len(want) {
		t.Fatalf("catalog ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("catalog ids = %v, want %v", ids, want)
		}
	}
	cf, _ := find(got, "cloudflare")
	if cf.Name != "Cloudflare" {
		t.Errorf("a stored profile shadowed the shipped %q: name = %q", "cloudflare", cf.Name)
	}
	for _, p := range got[len(BuiltIn()):] {
		if p.BuiltIn {
			t.Errorf("%s: BuiltIn = true on a user profile", p.ID)
		}
	}
}

// A document written before this feature existed carries no profiles at all, and loading it
// must be inert: the shipped profiles are available to pick, nothing is written into the
// user's document, and the machine goes on resolving names exactly as it did.
func TestAConfigWithNoProfilesLoadsWithTheBuiltInsAndChangesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"settings":{"hostname":"my-box"}}`), 0o600); err != nil {
		t.Fatalf("write the stored document: %v", err)
	}
	store, err := config.Open(path)
	if err != nil {
		t.Fatalf("load a config written before resolver profiles existed: %v", err)
	}
	cfg := store.Get()

	if len(cfg.DNSProfiles) != 0 {
		t.Errorf("loading invented %d stored profiles: %v", len(cfg.DNSProfiles), cfg.DNSProfiles)
	}
	catalog := Catalog(cfg.DNSProfiles)
	if len(catalog) != len(BuiltIn()) {
		t.Fatalf("catalog has %d entries, want the %d built-ins", len(catalog), len(BuiltIn()))
	}
	for _, p := range catalog {
		if !p.BuiltIn {
			t.Errorf("%s: BuiltIn = false, want the catalog to be built-ins only", p.ID)
		}
	}
	if cfg.Settings.SystemDNSEnabled {
		t.Error("the machine-wide resolver switched itself on")
	}
	if cfg.Settings.SystemDNSProfile != SystemID {
		t.Errorf("systemDns.profile = %q, want %q", cfg.Settings.SystemDNSProfile, SystemID)
	}
	selected, ok := ByID(cfg.DNSProfiles, cfg.Settings.SystemDNSProfile)
	if !ok {
		t.Fatalf("the default profile %q is not in the catalog", cfg.Settings.SystemDNSProfile)
	}
	if len(selected.Servers) != 0 {
		t.Errorf("the default profile names servers %v, so a fresh load would redirect this machine", selected.Servers)
	}
}

func TestByIDFindsBuiltInAndUserProfiles(t *testing.T) {
	user := []config.DNSProfile{{ID: "work", Name: "Work", Servers: []string{"10.0.0.1"}}}
	for _, id := range []string{SystemID, "google", "work"} {
		if _, ok := ByID(user, id); !ok {
			t.Errorf("ByID(%q) not found", id)
		}
	}
	if _, ok := ByID(user, "missing"); ok {
		t.Errorf("ByID(%q) found something", "missing")
	}
}

func TestValidateRefusesProfilesThatCannotWork(t *testing.T) {
	tests := []struct {
		name    string
		profile config.DNSProfile
		says    string
	}{
		{"no name", config.DNSProfile{Servers: []string{"1.1.1.1"}}, "name is required"},
		{"blank name", config.DNSProfile{Name: "  ", Servers: []string{"1.1.1.1"}}, "name is required"},
		{"no servers", config.DNSProfile{Name: "Empty"}, "System default"},
		{
			"too many servers",
			config.DNSProfile{Name: "Many", Servers: []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}},
			"at most 4",
		},
		{"bad server", config.DNSProfile{Name: "Bad", Servers: []string{"1.1.1.1", "nope"}}, "resolver 2"},
		{"duplicate server", config.DNSProfile{Name: "Dup", Servers: []string{"1.1.1.1", "1.1.1.1"}}, "backup"},
		{"duplicate ignoring case", config.DNSProfile{Name: "Dup", Servers: []string{"tls://dns.google", "TLS://DNS.GOOGLE"}}, "backup"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.profile)
			if err == nil {
				t.Fatalf("Validate(%+v) = nil error", tc.profile)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("Validate = %q, want it to mention %q", err, tc.says)
			}
		})
	}
}

func TestValidateAcceptsAMixedProfile(t *testing.T) {
	p := config.DNSProfile{
		Name:    "NextDNS",
		Servers: []string{"https://dns.nextdns.io/abc123", "tls://abc123.dns.nextdns.io", "45.90.28.0"},
	}
	if err := Validate(p); err != nil {
		t.Fatalf("Validate = %v", err)
	}
	got, err := Upstreams(p)
	if err != nil {
		t.Fatalf("Upstreams = %v", err)
	}
	want := []Protocol{DoH, DoT, Plain}
	if len(got) != len(want) {
		t.Fatalf("Upstreams returned %d, want %d", len(got), len(want))
	}
	for i, proto := range want {
		if got[i].Protocol != proto {
			t.Errorf("upstream %d protocol = %q, want %q", i, got[i].Protocol, proto)
		}
	}
}

// Order survives parsing, because order is the whole meaning of the list: the first
// server answers and the rest are only tried when it does not answer at all.
func TestUpstreamsKeepsTheOrderTheUserWrote(t *testing.T) {
	p := config.DNSProfile{Name: "Ordered", Servers: []string{"9.9.9.9", "1.1.1.1", "8.8.8.8"}}
	got, err := Upstreams(p)
	if err != nil {
		t.Fatalf("Upstreams = %v", err)
	}
	for i, s := range p.Servers {
		if got[i].Text != s {
			t.Errorf("upstream %d = %q, want %q", i, got[i].Text, s)
		}
	}
}

func TestUpstreamsNamesTheProfileAndThePositionThatFailed(t *testing.T) {
	_, err := Upstreams(config.DNSProfile{Name: "Work", Servers: []string{"1.1.1.1", "http://x.example.com"}})
	if err == nil {
		t.Fatal("Upstreams = nil error")
	}
	for _, want := range []string{"Work", "resolver 2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Upstreams = %q, want it to mention %q", err, want)
		}
	}
}

func TestNameTakenIgnoresCaseAndTheProfileBeingEdited(t *testing.T) {
	user := []config.DNSProfile{{ID: "work", Name: "Work", Servers: []string{"10.0.0.1"}}}
	if !NameTaken(user, "work", "") {
		t.Error("NameTaken(work) = false, want true -- names collide regardless of case")
	}
	if !NameTaken(user, " Cloudflare ", "") {
		t.Error("NameTaken(Cloudflare) = false, want true -- a shipped name is taken too")
	}
	if NameTaken(user, "Work", "work") {
		t.Error("NameTaken with exceptID = true, want false -- a profile does not collide with itself")
	}
	if NameTaken(user, "Home", "") {
		t.Error("NameTaken(Home) = true, want false")
	}
}

func TestNewIDIsReadableAndNeverCollides(t *testing.T) {
	taken := map[string]bool{"work-vpn": true}
	tests := []struct {
		name string
		want string
	}{
		{"NextDNS", "nextdns"},
		{"Work VPN", "work-vpn-2"},
		{"  Home  Wi-Fi ", "home-wi-fi"},
		{"!!!", "profile"},
		{"Cloudflare", "cloudflare-2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewID(tc.name, func(id string) bool { return taken[id] })
			if got != tc.want {
				t.Errorf("NewID(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}
