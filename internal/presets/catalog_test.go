// SPDX-License-Identifier: MIT

package presets

import (
	"fmt"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
)

func find(list []config.Preset, id string) (config.Preset, bool) {
	for _, p := range list {
		if p.ID == id {
			return p, true
		}
	}
	return config.Preset{}, false
}

func TestBuiltInCatalogCarriesTheDocumentedServices(t *testing.T) {
	want := map[string]struct {
		protocol config.Protocol
		port     int
	}{
		"ssh":        {config.TCP, 22},
		"http":       {config.TCP, 80},
		"https":      {config.TCP, 443},
		"rdp":        {config.TCP, 3389},
		"vnc":        {config.TCP, 5900},
		"postgresql": {config.TCP, 5432},
		"mysql":      {config.TCP, 3306},
		"redis":      {config.TCP, 6379},
		"smb":        {config.TCP, 445},
		"dns":        {config.Both, 53},
		"wireguard":  {config.UDP, 51820},
	}

	got := BuiltIn()
	if len(got) != len(want) {
		t.Fatalf("built-in catalog has %d entries, want %d", len(got), len(want))
	}
	for id, spec := range want {
		p, ok := find(got, id)
		if !ok {
			t.Errorf("built-in catalog is missing %q", id)
			continue
		}
		if p.Protocol != spec.protocol {
			t.Errorf("%s: protocol = %q, want %q", id, p.Protocol, spec.protocol)
		}
		if p.RemotePort != spec.port {
			t.Errorf("%s: remotePort = %d, want %d", id, p.RemotePort, spec.port)
		}
		if !p.BuiltIn {
			t.Errorf("%s: BuiltIn = false, want true", id)
		}
	}
}

// The returned slice must not alias package state, or one caller's edit would
// rewrite the catalog for everyone.
func TestBuiltInReturnsACopy(t *testing.T) {
	first := BuiltIn()
	if len(first) == 0 {
		t.Fatal("built-in catalog is empty")
	}
	first[0].Name = "clobbered"
	first[0].RemotePort = 1

	second := BuiltIn()
	if second[0].Name == "clobbered" || second[0].RemotePort == 1 {
		t.Fatal("mutating the returned slice changed the package catalog")
	}
}

func TestIsBuiltInIdentifiesShippedEntries(t *testing.T) {
	if !IsBuiltIn("ssh") {
		t.Error(`IsBuiltIn("ssh") = false, want true`)
	}
	if IsBuiltIn("my-custom-thing") {
		t.Error(`IsBuiltIn("my-custom-thing") = true, want false`)
	}
	if IsBuiltIn("") {
		t.Error(`IsBuiltIn("") = true, want false`)
	}
}

func TestCatalogPutsBuiltInsFirstAndSortsUserPresetsByName(t *testing.T) {
	user := []config.Preset{
		{ID: "zeta", Name: "Zeta", Protocol: config.TCP, RemotePort: 9000},
		{ID: "alpha", Name: "Alpha", Protocol: config.UDP, RemotePort: 9001},
		{ID: "mid", Name: "Middle", Protocol: config.TCP, RemotePort: 9002},
	}

	got := Catalog(user)
	builtInCount := len(BuiltIn())
	if len(got) != builtInCount+len(user) {
		t.Fatalf("catalog has %d entries, want %d", len(got), builtInCount+len(user))
	}
	for i, p := range got[:builtInCount] {
		if !p.BuiltIn {
			t.Fatalf("entry %d (%s) should be a built-in", i, p.ID)
		}
	}

	custom := got[builtInCount:]
	wantOrder := []string{"Alpha", "Middle", "Zeta"}
	for i, name := range wantOrder {
		if custom[i].Name != name {
			t.Errorf("user preset %d = %q, want %q", i, custom[i].Name, name)
		}
		if custom[i].BuiltIn {
			t.Errorf("user preset %q is flagged BuiltIn", custom[i].Name)
		}
	}
}

// A stored preset claiming a built-in id must not replace the shipped entry, or a
// corrupted config file could silently redirect "SSH" to another port.
func TestCatalogDoesNotLetAStoredPresetShadowABuiltIn(t *testing.T) {
	got := Catalog([]config.Preset{
		{ID: "ssh", Name: "Not SSH", Protocol: config.UDP, RemotePort: 9999},
	})

	ssh, ok := find(got, "ssh")
	if !ok {
		t.Fatal(`built-in "ssh" disappeared from the catalog`)
	}
	if ssh.Name != "SSH" || ssh.RemotePort != 22 || ssh.Protocol != config.TCP {
		t.Fatalf("built-in ssh was overwritten: %+v", ssh)
	}
	if len(got) != len(BuiltIn()) {
		t.Fatalf("shadowing preset was kept: catalog has %d entries, want %d", len(got), len(BuiltIn()))
	}
}

func TestCatalogWithNoUserPresetsReturnsJustTheBuiltIns(t *testing.T) {
	if got := Catalog(nil); len(got) != len(BuiltIn()) {
		t.Fatalf("catalog has %d entries, want %d", len(got), len(BuiltIn()))
	}
}

func TestValidateRejectsBadPresets(t *testing.T) {
	tests := []struct {
		name    string
		preset  config.Preset
		wantErr bool
	}{
		{"valid tcp", config.Preset{Name: "Grafana", Protocol: config.TCP, RemotePort: 3000}, false},
		{"valid udp", config.Preset{Name: "Syslog", Protocol: config.UDP, RemotePort: 514}, false},
		{"valid both", config.Preset{Name: "DNS", Protocol: config.Both, RemotePort: 53}, false},
		{"empty name", config.Preset{Name: "", Protocol: config.TCP, RemotePort: 3000}, true},
		{"blank name", config.Preset{Name: "   ", Protocol: config.TCP, RemotePort: 3000}, true},
		{"missing protocol", config.Preset{Name: "X", RemotePort: 3000}, true},
		{"bogus protocol", config.Preset{Name: "X", Protocol: config.Protocol("sctp"), RemotePort: 3000}, true},
		{"port zero", config.Preset{Name: "X", Protocol: config.TCP, RemotePort: 0}, true},
		{"port negative", config.Preset{Name: "X", Protocol: config.TCP, RemotePort: -1}, true},
		{"port too high", config.Preset{Name: "X", Protocol: config.TCP, RemotePort: 65536}, true},
		{"port at max", config.Preset{Name: "X", Protocol: config.TCP, RemotePort: 65535}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.preset)
			if tt.wantErr && err == nil {
				t.Fatalf("Validate(%+v) = nil, want an error", tt.preset)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate(%+v) = %v, want nil", tt.preset, err)
			}
		})
	}
}

func TestNewIDSlugifiesTheName(t *testing.T) {
	none := func(string) bool { return false }
	tests := []struct {
		name string
		want string
	}{
		{"Grafana", "grafana"},
		{"My Service", "my-service"},
		{"Weird!!Chars", "weirdchars"},
		{"Port 8080", "port-8080"},
		{"--leading-and-trailing--", "leading-and-trailing"},
		{"!!!", "preset"},
	}
	for _, tt := range tests {
		if got := NewID(tt.name, none); got != tt.want {
			t.Errorf("NewID(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestNewIDAvoidsCollidingWithExistingAndBuiltInIDs(t *testing.T) {
	taken := map[string]bool{"grafana": true, "grafana-2": true}
	if got := NewID("Grafana", func(id string) bool { return taken[id] }); got != "grafana-3" {
		t.Errorf("NewID with grafana and grafana-2 taken = %q, want %q", got, "grafana-3")
	}

	// A user preset named "SSH" must not claim the built-in's id.
	got := NewID("SSH", func(string) bool { return false })
	if got == "ssh" {
		t.Fatal(`NewID("SSH") returned the built-in id "ssh"`)
	}
	if IsBuiltIn(got) {
		t.Fatalf("NewID returned built-in id %q", got)
	}
}

// The picker's order has to survive a reload. Nothing prevents two user presets from
// sharing a name -- the store de-duplicates ids, never names -- so an unstable sort
// would reshuffle the equally named ones and move an entry under the user's cursor
// between rendering the list and clicking it.
//
// The shape of the input is the point: twenty entries defeats the insertion sort that
// short slices are dispatched to and happens to be stable, and the duplicates are
// interleaved with distinct names so the sort really has to partition rather than
// recognising an all-equal run and leaving it alone.
func TestUserPresetsSharingANameKeepTheirStoredOrderAcrossLoads(t *testing.T) {
	const count = 20
	user := make([]config.Preset, 0, count)
	for i := range count {
		name := fmt.Sprintf("Service %02d", i)
		if i%2 == 0 {
			name = "Grafana"
		}
		user = append(user, config.Preset{
			ID:         fmt.Sprintf("preset-%02d", i),
			Name:       name,
			Protocol:   config.TCP,
			RemotePort: 9000 + i,
		})
	}

	// The stored order is the input order, so the duplicates must come back in it.
	var wantIDs []string
	for i := range count {
		if i%2 == 0 {
			wantIDs = append(wantIDs, fmt.Sprintf("preset-%02d", i))
		}
	}

	for load := 1; load <= 5; load++ {
		var gotIDs []string
		for _, p := range Catalog(user)[len(BuiltIn()):] {
			if p.Name == "Grafana" {
				gotIDs = append(gotIDs, p.ID)
			}
		}
		if len(gotIDs) != len(wantIDs) {
			t.Fatalf("load %d returned %d entries named Grafana, want %d", load, len(gotIDs), len(wantIDs))
		}
		for i, id := range gotIDs {
			if id != wantIDs[i] {
				t.Fatalf("load %d, entry %d = %q, want %q: the picker reshuffled equally "+
					"named presets", load, i, id, wantIDs[i])
			}
		}
	}
}
