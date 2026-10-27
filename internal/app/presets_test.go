// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/presets"
)

// newPresetAPI builds the preset catalog over a throwaway store, seeded with the
// user's own entries.
func newPresetAPI(t *testing.T, stored ...config.Preset) (presetsAPI, *config.Store) {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), config.ConfigFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if len(stored) > 0 {
		if _, err := store.Update(func(c *config.Config) error {
			c.Presets = append(c.Presets, stored...)
			return nil
		}); err != nil {
			t.Fatalf("seed presets: %v", err)
		}
	}
	agent, err := New(Options{Store: store, Getenv: emptyEnv, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return presetsAPI{a: agent}, store
}

// The add-forward dialog renders exactly what this returns. Serving only the stored
// half would empty the picker on a fresh install; serving only the shipped half would
// hide every preset the user made.
func TestListingPresetsMergesTheShippedCatalogWithTheUsersOwn(t *testing.T) {
	mine := config.Preset{ID: "grafana", Name: "Grafana", Protocol: config.TCP, RemotePort: 3000}
	api, _ := newPresetAPI(t, mine)

	got := api.List()

	if len(got) != len(presets.BuiltIn())+1 {
		t.Fatalf("catalog has %d entries, want the %d built-ins plus one user preset",
			len(got), len(presets.BuiltIn()))
	}

	byID := make(map[string]config.Preset, len(got))
	for _, p := range got {
		byID[p.ID] = p
	}
	ssh, ok := byID["ssh"]
	if !ok {
		t.Fatal("the shipped catalog is missing from the list")
	}
	if !ssh.BuiltIn {
		t.Error("a shipped preset is not flagged BuiltIn, so the dashboard would offer to delete it")
	}
	user, ok := byID["grafana"]
	if !ok {
		t.Fatal("the user's own preset is missing from the list")
	}
	if user.BuiltIn {
		t.Error("a user preset is flagged BuiltIn, so the dashboard would refuse to delete it")
	}
	if user.RemotePort != 3000 {
		t.Errorf("user preset remotePort = %d, want 3000", user.RemotePort)
	}
}

// Two presets sharing an id would make delete ambiguous and the picker's keys
// duplicate. The store is the only place that can settle it, because the id the
// client proposed is only known to be taken there.
func TestCreatingAPresetMintsAFreshIDWhenTheProposedOneIsTaken(t *testing.T) {
	existing := config.Preset{ID: "grafana", Name: "Grafana", Protocol: config.TCP, RemotePort: 3000}
	api, store := newPresetAPI(t, existing)

	created, err := api.Create(config.Preset{
		ID: "grafana", Name: "Grafana", Protocol: config.TCP, RemotePort: 3001,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID == existing.ID {
		t.Fatalf("the new preset kept the taken id %q", created.ID)
	}
	if created.ID == "" {
		t.Fatal("the new preset was stored with no id at all")
	}

	stored := store.Get().Presets
	if len(stored) != 2 {
		t.Fatalf("stored %d presets, want 2", len(stored))
	}
	if stored[0].ID == stored[1].ID {
		t.Fatalf("both stored presets carry the id %q", stored[0].ID)
	}
}

// A user preset that claimed a shipped id would be dropped by the catalog merge --
// shipped entries are never shadowed -- so the preset would vanish the moment it was
// saved, with the API still reporting success.
func TestCreatingAPresetCannotClaimAShippedID(t *testing.T) {
	api, _ := newPresetAPI(t)

	created, err := api.Create(config.Preset{
		ID: "ssh", Name: "My SSH", Protocol: config.TCP, RemotePort: 2222,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if presets.IsBuiltIn(created.ID) {
		t.Fatalf("the new preset was given the shipped id %q; the catalog merge would "+
			"drop it and the user's preset would silently disappear", created.ID)
	}
	if _, ok := findPreset(api.List(), created.ID); !ok {
		t.Error("the created preset is not in the catalog it was just added to")
	}
}

// The dashboard sends no id when the user names a new preset, so the id has to come
// from somewhere. Deriving it from the name is what keeps it readable in the config
// file the user may well edit by hand.
func TestCreatingAPresetWithNoIDDerivesOneFromItsName(t *testing.T) {
	api, _ := newPresetAPI(t)

	created, err := api.Create(config.Preset{
		Name: "My Service", Protocol: config.UDP, RemotePort: 9000,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID != "my-service" {
		t.Errorf("ID = %q, want it derived from the name", created.ID)
	}
}

// BuiltIn is what the dashboard reads to decide whether to offer a delete button. A
// client that set it would make its own preset undeletable through the UI.
func TestACreatedPresetIsNeverFlaggedAsShipped(t *testing.T) {
	api, store := newPresetAPI(t)

	created, err := api.Create(config.Preset{
		Name: "Impostor", Protocol: config.TCP, RemotePort: 1234, BuiltIn: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.BuiltIn {
		t.Error("the returned preset claims to be shipped")
	}
	if stored := store.Get().Presets; len(stored) != 1 || stored[0].BuiltIn {
		t.Errorf("stored preset = %+v, want BuiltIn false", stored)
	}
}

// An invalid preset must come back as a validation failure, which the API maps to 400.
// Anything else reaches the dashboard as a 500 and reads as an agent bug rather than
// a form the user can fix.
func TestCreatingAnInvalidPresetIsAValidationFailureAndStoresNothing(t *testing.T) {
	tests := []struct {
		name   string
		preset config.Preset
	}{
		{"no name", config.Preset{Protocol: config.TCP, RemotePort: 3000}},
		{"no protocol", config.Preset{Name: "X", RemotePort: 3000}},
		{"port out of range", config.Preset{Name: "X", Protocol: config.TCP, RemotePort: 70000}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, store := newPresetAPI(t)

			_, err := api.Create(tt.preset)

			var validation *config.ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("err = %v (%T), want a *config.ValidationError so the API answers 400", err, err)
			}
			if validation.Field != "preset" {
				t.Errorf("field = %q, want %q", validation.Field, "preset")
			}
			if stored := store.Get().Presets; len(stored) != 0 {
				t.Errorf("a rejected preset was stored anyway: %+v", stored)
			}
		})
	}
}

// Shipped presets belong to the binary: deleting one would appear to work and then be
// back after the next restart. Refusing by name is the only honest answer.
func TestDeletingAShippedPresetIsRefusedRatherThanSilentlyIgnored(t *testing.T) {
	api, _ := newPresetAPI(t)

	err := api.Delete("ssh")

	var validation *config.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("err = %v (%T), want a *config.ValidationError", err, err)
	}
	if !strings.Contains(err.Error(), "ssh") {
		t.Errorf("err = %v, want it to name the preset", err)
	}
	if _, ok := findPreset(api.List(), "ssh"); !ok {
		t.Error("the shipped preset was removed from the catalog anyway")
	}
}

// A delete of something that is not there has to be a 404, not a silent success: the
// dashboard would otherwise remove the row from its own view and diverge from the agent.
func TestDeletingAnUnknownPresetReportsItWasNotFound(t *testing.T) {
	api, _ := newPresetAPI(t)

	err := api.Delete("no-such-preset")

	if !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("err = %v, want config.ErrNotFound so the API answers 404", err)
	}
	if !strings.Contains(err.Error(), "no-such-preset") {
		t.Errorf("err = %v, want it to name the preset", err)
	}
}

// Deleting has to remove exactly one entry. The removal splices the slice in place,
// which is where an off-by-one takes a neighbour with it.
func TestDeletingAPresetLeavesItsNeighboursAlone(t *testing.T) {
	api, store := newPresetAPI(t,
		config.Preset{ID: "first", Name: "First", Protocol: config.TCP, RemotePort: 1000},
		config.Preset{ID: "second", Name: "Second", Protocol: config.TCP, RemotePort: 2000},
		config.Preset{ID: "third", Name: "Third", Protocol: config.TCP, RemotePort: 3000},
	)

	if err := api.Delete("second"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	stored := store.Get().Presets
	if len(stored) != 2 {
		t.Fatalf("stored %d presets, want 2: %+v", len(stored), stored)
	}
	for _, want := range []string{"first", "third"} {
		if _, ok := findPreset(stored, want); !ok {
			t.Errorf("deleting %q also removed %q", "second", want)
		}
	}
	if _, ok := findPreset(stored, "second"); ok {
		t.Error("the deleted preset is still stored")
	}
}

func findPreset(list []config.Preset, id string) (config.Preset, bool) {
	for _, p := range list {
		if p.ID == id {
			return p, true
		}
	}
	return config.Preset{}, false
}
