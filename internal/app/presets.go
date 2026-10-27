// SPDX-License-Identifier: MIT

package app

import (
	"fmt"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/presets"
)

// presetsAPI presents the agent as the management API's preset catalog.
type presetsAPI struct{ a *Agent }

var _ httpapi.Presets = presetsAPI{}

// Presets exposes the agent as the management API's preset catalog.
func (a *Agent) Presets() httpapi.Presets { return presetsAPI{a: a} }

// List returns the shipped catalog merged with the user's own entries.
func (pa presetsAPI) List() []config.Preset {
	return presets.Catalog(pa.a.store.Get().Presets)
}

func (pa presetsAPI) Create(p config.Preset) (config.Preset, error) {
	if err := presets.Validate(p); err != nil {
		return config.Preset{}, &config.ValidationError{Field: "preset", Message: err.Error()}
	}
	p.BuiltIn = false

	if _, err := pa.a.store.Update(func(c *config.Config) error {
		taken := func(id string) bool {
			for _, existing := range c.Presets {
				if existing.ID == id {
					return true
				}
			}
			return false
		}
		if p.ID == "" || taken(p.ID) || presets.IsBuiltIn(p.ID) {
			p.ID = presets.NewID(p.Name, taken)
		}
		c.Presets = append(c.Presets, p)
		return nil
	}); err != nil {
		return config.Preset{}, err
	}
	return p, nil
}

// Delete removes a user preset. Shipped presets belong to the binary, so deleting
// one is refused rather than silently ignored.
func (pa presetsAPI) Delete(id string) error {
	if presets.IsBuiltIn(id) {
		return &config.ValidationError{
			Field:   "preset",
			Message: fmt.Sprintf("%q is a built-in preset and cannot be deleted", id),
		}
	}
	_, err := pa.a.store.Update(func(c *config.Config) error {
		for i, p := range c.Presets {
			if p.ID == id {
				c.Presets = append(c.Presets[:i], c.Presets[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("preset %q: %w", id, config.ErrNotFound)
	})
	return err
}
