// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
)

// newDNSProfileAPI builds the resolver catalog over a throwaway store, seeded with the
// user's own entries.
//
// The agent behind it is never started, which is what every test here wants except the
// delete cases: a write that ends in a reconcile needs a lifecycle goroutine to reconcile,
// and those go through the harness instead.
func newDNSProfileAPI(t *testing.T, stored ...config.DNSProfile) (dnsProfilesAPI, *config.Store) {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if len(stored) > 0 {
		if _, err := store.Update(func(c *config.Config) error {
			c.DNSProfiles = append(c.DNSProfiles, stored...)
			return nil
		}); err != nil {
			t.Fatalf("seed resolver profiles: %v", err)
		}
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return dnsProfilesAPI{a: agent}, store
}

func userProfile(id, name string, servers ...string) config.DNSProfile {
	return config.DNSProfile{ID: id, Name: name, Servers: servers}
}

// The resolver picker renders exactly what this returns. Serving only the stored half
// would empty the picker on a fresh install -- including the System default entry, which
// is the way back off the feature -- and serving only the shipped half would hide every
// profile the user added.
func TestListingResolverProfilesMergesTheShippedCatalogWithTheUsersOwn(t *testing.T) {
	api, _ := newDNSProfileAPI(t, userProfile("work", "Work", "https://dns.example/dns-query"))

	got := api.List()

	if len(got) != len(dnsprofiles.BuiltIn())+1 {
		t.Fatalf("catalog has %d entries, want the %d built-ins plus one user profile",
			len(got), len(dnsprofiles.BuiltIn()))
	}
	byID := make(map[string]config.DNSProfile, len(got))
	for _, p := range got {
		byID[p.ID] = p
	}
	system, ok := byID[dnsprofiles.SystemID]
	if !ok {
		t.Fatal("the System default profile is missing, so there is no way back to an unchanged machine")
	}
	if !system.BuiltIn || len(system.Servers) != 0 {
		t.Errorf("System default = %+v, want a shipped profile with no servers", system)
	}
	mine, ok := byID["work"]
	if !ok {
		t.Fatal("the user's own profile is missing from the list")
	}
	if mine.BuiltIn {
		t.Error("a user profile is flagged BuiltIn, so the dashboard would refuse to edit or delete it")
	}
	if len(mine.Servers) != 1 || mine.Servers[0] != "https://dns.example/dns-query" {
		t.Errorf("user profile servers = %v, want the one it was stored with", mine.Servers)
	}
}

// The management API answers every process on this machine, whatever account it runs as,
// while the document the profile is stored in is this account's alone. A DoH provider
// identifies an account by the URL's path, so handing that path out over the API gives away
// the resolver and its query log to anything that asks.
func TestListingResolverProfilesDoesNotHandOutWhatIdentifiesTheAccount(t *testing.T) {
	api, _ := newDNSProfileAPI(t, userProfile("work", "Work", "https://dns.nextdns.io/abc123"))

	var mine config.DNSProfile
	for _, p := range api.List() {
		if p.ID == "work" {
			mine = p
		}
	}

	if len(mine.Servers) != 1 {
		t.Fatalf("user profile servers = %v, want the one it was stored with", mine.Servers)
	}
	if strings.Contains(mine.Servers[0], "abc123") {
		t.Errorf("servers = %v, want the part that identifies the account left out", mine.Servers)
	}
	// The host stays, or the profile is a row of punctuation nobody can recognise.
	if !strings.Contains(mine.Servers[0], "dns.nextdns.io") {
		t.Errorf("servers = %v, want the provider still named", mine.Servers)
	}
}

// A profile is edited by sending back the list that was shown, and what was shown carries
// a stand-in. Storing that verbatim would point the machine at a URL no provider
// answers, while looking on every screen like a resolver somebody chose.
func TestEditingAProfileKeepsTheResolverItsStandInStandsFor(t *testing.T) {
	api, store := newDNSProfileAPI(t, userProfile("work", "Work", "https://dns.nextdns.io/abc123"))

	shown := api.List()
	var edited config.DNSProfile
	for _, p := range shown {
		if p.ID == "work" {
			edited = p
		}
	}
	edited.Name = "Work resolvers"

	if _, err := api.Update("work", edited); err != nil {
		t.Fatalf("update: %v", err)
	}

	stored, ok := dnsprofiles.ByID(store.Get().DNSProfiles, "work")
	if !ok {
		t.Fatal("the edited profile is gone")
	}
	if len(stored.Servers) != 1 || stored.Servers[0] != "https://dns.nextdns.io/abc123" {
		t.Errorf("stored servers = %v, want the resolver the stand-in stood for", stored.Servers)
	}
	if stored.Name != "Work resolvers" {
		t.Errorf("name = %q, want the edit that was made", stored.Name)
	}
}

// A stand-in standing for nothing is somebody typing what they saw, or a client
// inventing one. Either way the machine may not end up resolving through it.
func TestAResolverStandInForNothingIsRefused(t *testing.T) {
	api, store := newDNSProfileAPI(t, userProfile("work", "Work", "9.9.9.9"))

	if _, err := api.Update("work", userProfile("work", "Work", "https://dns.nextdns.io/...")); err == nil {
		t.Error("a stand-in that stands for no stored resolver was saved")
	}
	if _, err := api.Create(userProfile("", "New", "https://dns.nextdns.io/...")); err == nil {
		t.Error("a new profile was created around a stand-in that stands for nothing")
	}

	stored, _ := dnsprofiles.ByID(store.Get().DNSProfiles, "work")
	if len(stored.Servers) != 1 || stored.Servers[0] != "9.9.9.9" {
		t.Errorf("stored servers = %v, want the refused edit to have changed nothing", stored.Servers)
	}
}

// Two profiles sharing an id would make edit and delete ambiguous, and the settings point
// at a profile by id: the wrong one winning is the machine resolving through a resolver
// nobody chose.
func TestCreatingAResolverProfileMintsAFreshIDWhenTheProposedOneIsTaken(t *testing.T) {
	api, store := newDNSProfileAPI(t, userProfile("work", "Work", "9.9.9.9"))

	created, err := api.Create(userProfile("work", "Work Backup", "9.9.9.10"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID == "work" {
		t.Fatal("the new profile kept the taken id")
	}
	if created.ID == "" {
		t.Fatal("the new profile was stored with no id at all")
	}
	if stored := store.Get().DNSProfiles; len(stored) != 2 || stored[0].ID == stored[1].ID {
		t.Fatalf("stored profiles = %+v, want two with distinct ids", stored)
	}
}

// A stored profile claiming a shipped id is dropped by the catalog merge, so the profile
// would vanish the moment it was saved with the API still reporting success.
func TestCreatingAResolverProfileCannotClaimAShippedID(t *testing.T) {
	api, _ := newDNSProfileAPI(t)

	created, err := api.Create(userProfile("cloudflare", "My Cloudflare", "1.1.1.1"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if dnsprofiles.IsBuiltIn(created.ID) {
		t.Fatalf("the new profile was given the shipped id %q, and the catalog merge would drop it",
			created.ID)
	}
	if _, found := dnsprofiles.ByID(api.a.store.Get().DNSProfiles, created.ID); !found {
		t.Error("the created profile is not in the catalog it was just added to")
	}
}

// The CLI and the tray resolve a profile by the name the user typed, so two profiles
// called "Work" make `app-tail dns use Work` a coin flip.
func TestAResolverProfileNameIsClaimedOnlyOnce(t *testing.T) {
	api, store := newDNSProfileAPI(t, userProfile("work", "Work", "9.9.9.9"))

	_, err := api.Create(userProfile("", "  wOrK  ", "1.1.1.1"))

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("Create with a taken name = %v, want a validation failure the dashboard can show", err)
	}
	// Trimmed and case-insensitive, because that is how the CLI and the tray look one up.
	if !strings.Contains(invalid.Message, `"wOrK"`) {
		t.Errorf("message = %q, want it to quote the name that collided, trimmed", invalid.Message)
	}
	if stored := store.Get().DNSProfiles; len(stored) != 1 {
		t.Errorf("stored %d profiles, want the refused one not to have been written", len(stored))
	}
}

// A profile with no servers is a switch that silently changes nothing, which is the one
// thing the System default entry is for.
func TestCreatingAResolverProfileWithNothingToResolveThroughIsRefused(t *testing.T) {
	api, store := newDNSProfileAPI(t)

	_, err := api.Create(config.DNSProfile{Name: "Empty"})

	var invalid *config.ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("Create with no servers = %v, want a validation failure", err)
	}
	if !strings.Contains(invalid.Message, "System default") {
		t.Errorf("message = %q, want it to point at the profile that does change nothing", invalid.Message)
	}
	if stored := store.Get().DNSProfiles; len(stored) != 0 {
		t.Errorf("stored %+v, want nothing written for a refused profile", stored)
	}
}

// The settings point at a profile by id, so an edit that minted a new one would leave the
// machine resolving through a profile that no longer exists.
func TestEditingAResolverProfileKeepsItsIDAndReplacesItsServers(t *testing.T) {
	api, store := newDNSProfileAPI(t, userProfile("work", "Work", "9.9.9.9"))

	updated, err := api.Update("work", userProfile("something-else", "Work", "1.1.1.1", "1.0.0.1"))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if updated.ID != "work" {
		t.Errorf("ID = %q, want the id the settings already point at", updated.ID)
	}
	stored := store.Get().DNSProfiles
	if len(stored) != 1 {
		t.Fatalf("stored %d profiles, want the edit to have replaced the one in place", len(stored))
	}
	if len(stored[0].Servers) != 2 || stored[0].Servers[0] != "1.1.1.1" {
		t.Errorf("stored servers = %v, want the ones the edit supplied", stored[0].Servers)
	}
	if stored[0].BuiltIn {
		t.Error("the edited profile claims to be shipped, which would make it undeletable")
	}
}

// The shipped three are the way back when a profile the user added is what broke
// resolution, so they cannot be edited into the same broken state.
func TestEditingOrDeletingAShippedResolverProfileIsRefused(t *testing.T) {
	api, store := newDNSProfileAPI(t)

	_, updateErr := api.Update("cloudflare", userProfile("cloudflare", "Cloudflare", "9.9.9.9"))
	deleteErr := api.Delete(context.Background(), "google")

	var invalid *config.ValidationError
	if !errors.As(updateErr, &invalid) {
		t.Errorf("Update of a built-in = %v, want a validation failure", updateErr)
	}
	if !errors.As(deleteErr, &invalid) {
		t.Errorf("Delete of a built-in = %v, want a validation failure", deleteErr)
	}
	if stored := store.Get().DNSProfiles; len(stored) != 0 {
		t.Errorf("stored %+v, want a refused write on a shipped profile to store nothing", stored)
	}
}

// A dashboard open in two tabs is the ordinary way to reach this: one deletes a profile,
// the other still has its edit form. Anything other than not-found reads as an agent bug.
func TestEditingAResolverProfileThatIsNoLongerThereIsNotFound(t *testing.T) {
	api, _ := newDNSProfileAPI(t)

	_, err := api.Update("ghost", userProfile("ghost", "Ghost", "1.1.1.1"))

	if !errors.Is(err, config.ErrNotFound) {
		t.Errorf("Update of a missing profile = %v, want it to be reported as not found", err)
	}
}

// The picker shows a name and what it resolves through, because "Work" and "Home" say
// nothing about which servers they hold.
func TestTheResolverPickerNamesWhatEachProfileResolvesThrough(t *testing.T) {
	api, _ := newDNSProfileAPI(t, userProfile("work", "Work", "https://dns.example/dns-query"))

	choices := api.a.dnsProfileChoices()

	byValue := make(map[string]config.EnumOption, len(choices))
	for _, c := range choices {
		byValue[c.Value] = c
	}
	if got := byValue[dnsprofiles.SystemID]; !strings.Contains(got.Help, "exactly as it is") {
		t.Errorf("System default help = %q, want it to say the machine is left alone", got.Help)
	}
	if got := byValue["cloudflare"]; got.Help != "https://1.1.1.1/dns-query, https://1.0.0.1/dns-query" {
		t.Errorf("Cloudflare help = %q, want its shipped servers", got.Help)
	}
	if got := byValue["work"]; got.Label != "Work" || got.Help != "https://dns.example/dns-query" {
		t.Errorf("user choice = %+v, want its own name and server", got)
	}
}

// The stored id is what the machine is arranged from, so a write naming a profile that
// does not exist has to be refused where somebody is looking rather than discovered by a
// resolver that cannot be built.
func TestAWriteNamingAResolverProfileThatDoesNotExistIsRefused(t *testing.T) {
	api, _ := newDNSProfileAPI(t, userProfile("work", "Work", "9.9.9.9"))

	cases := []struct {
		name  string
		patch map[string]json.RawMessage
		want  string
	}{
		{"a profile nobody added", map[string]json.RawMessage{"systemDns.profile": json.RawMessage(`"ghost"`)}, "ghost"},
		{"the user's own", map[string]json.RawMessage{"systemDns.profile": json.RawMessage(`"work"`)}, ""},
		{"a shipped one", map[string]json.RawMessage{"systemDns.profile": json.RawMessage(`"cloudflare"`)}, ""},
		{"the empty default", map[string]json.RawMessage{"systemDns.profile": json.RawMessage(`""`)}, ""},
		{"not a string at all", map[string]json.RawMessage{"systemDns.profile": json.RawMessage(`7`)}, ""},
		{"a patch about something else", map[string]json.RawMessage{"dns.enabled": json.RawMessage(`true`)}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := api.a.checkDNSProfilePatch(tc.patch)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("checkDNSProfilePatch = %v, want it accepted here", err)
				}
				return
			}
			var invalid *config.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("checkDNSProfilePatch = %v, want a validation failure", err)
			}
			if invalid.Field != "systemDns.profile" || !strings.Contains(invalid.Message, tc.want) {
				t.Errorf("refusal = %+v, want it to name the field and the missing profile", invalid)
			}
		})
	}
}

// Deleting the profile in force would leave the settings pointing at nothing while the
// machine is still resolving through app-tail, and the machine's own resolver is the worst
// place to discover a dangling reference.
func TestDeletingTheProfileThisMachineIsResolvingThroughIsRefused(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.DNSProfiles = append(c.DNSProfiles, userProfile("work", "Work", "9.9.9.9"))
		c.Settings.SystemDNSEnabled = true
		c.Settings.SystemDNSProfile = "work"
	})

	resp, body := h.request(http.MethodDelete, "/api/dns/profiles/work", nil)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DELETE /api/dns/profiles/work = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "switch to another profile first") {
		t.Errorf("body = %s, want it to say how to get out of the refusal", body)
	}
	if stored := h.store.Get().DNSProfiles; len(stored) != 1 {
		t.Errorf("stored %+v, want the refused delete to have kept the profile", stored)
	}
}

// A profile the settings do not name is an ordinary delete, even while another profile has
// this machine's resolver: nothing points at it, so nothing is left dangling.
func TestDeletingAProfileTheMachineIsNotResolvingThroughRemovesIt(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.DNSProfiles = append(c.DNSProfiles,
			userProfile("work", "Work", "9.9.9.9"),
			userProfile("spare", "Spare", "9.9.9.10"))
		c.Settings.SystemDNSEnabled = true
		c.Settings.SystemDNSProfile = "work"
	})

	resp, body := h.request(http.MethodDelete, "/api/dns/profiles/spare", nil)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/dns/profiles/spare = %d: %s", resp.StatusCode, body)
	}
	stored := h.store.Get().DNSProfiles
	if len(stored) != 1 || stored[0].ID != "work" {
		t.Errorf("stored %+v, want only the profile in force left", stored)
	}
}
