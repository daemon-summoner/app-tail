// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsprofiles"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// dnsProfilesAPI presents the agent as the management API's resolver catalog.
type dnsProfilesAPI struct{ a *Agent }

var _ httpapi.DNSProfiles = dnsProfilesAPI{}

// DNSProfiles exposes the resolver catalog.
func (a *Agent) DNSProfiles() httpapi.DNSProfiles { return dnsProfilesAPI{a: a} }

// List returns the shipped catalog merged with the user's own entries, with the part of a
// resolver URL that identifies its account hidden: this answer goes to every local process
// that asks, whatever account it runs as.
func (d dnsProfilesAPI) List() []config.DNSProfile {
	return dnsprofiles.HideProfiles(dnsprofiles.Catalog(d.a.store.Get().DNSProfiles))
}

func (d dnsProfilesAPI) Create(p config.DNSProfile) (config.DNSProfile, error) {
	// Trimmed before anything reads it: every comparison downstream trims, so a name kept
	// with its surrounding spaces would match a profile it does not look like, and show up
	// in the picker and in `app-tail dns` indented by whatever the form happened to send.
	p.Name = strings.TrimSpace(p.Name)
	// A new profile has nothing stored behind it, so a stand-in stands for nothing here
	// and is refused here rather than saved as a URL no provider answers.
	servers, err := dnsprofiles.Reveal(p.Servers, nil)
	if err != nil {
		return config.DNSProfile{}, &config.ValidationError{Field: "dnsProfile", Message: err.Error()}
	}
	p.Servers = servers
	if err := dnsprofiles.Validate(p); err != nil {
		return config.DNSProfile{}, &config.ValidationError{Field: "dnsProfile", Message: err.Error()}
	}
	p.BuiltIn = false

	if _, err := d.a.store.Update(func(c *config.Config) error {
		if dnsprofiles.NameTaken(c.DNSProfiles, p.Name, "") {
			// Names are unique because the CLI and the tray resolve a profile by the name
			// the user typed, and two profiles called "Work" make that a coin flip.
			return &config.ValidationError{
				Field:   "dnsProfile",
				Message: fmt.Sprintf("a resolver profile called %q already exists", p.Name),
			}
		}
		taken := func(id string) bool {
			for _, existing := range c.DNSProfiles {
				if existing.ID == id {
					return true
				}
			}
			return false
		}
		if p.ID == "" || taken(p.ID) || dnsprofiles.IsBuiltIn(p.ID) {
			p.ID = dnsprofiles.NewID(p.Name, taken)
		}
		c.DNSProfiles = append(c.DNSProfiles, p)
		return nil
	}); err != nil {
		return config.DNSProfile{}, err
	}
	return dnsprofiles.HideProfile(p), nil
}

// Update replaces a user profile in place, keeping its id.
//
// The id is what the settings point at, so editing a profile the machine is currently
// resolving through has to leave that pointer valid. The next reconcile picks the new
// resolvers up; nothing has to be switched off and on again.
func (d dnsProfilesAPI) Update(id string, p config.DNSProfile) (config.DNSProfile, error) {
	if dnsprofiles.IsBuiltIn(id) {
		return config.DNSProfile{}, &config.ValidationError{
			Field:   "dnsProfile",
			Message: fmt.Sprintf("%q is a built-in resolver profile and cannot be edited; add your own to change the servers", id),
		}
	}
	p.Name = strings.TrimSpace(p.Name)
	p.ID, p.BuiltIn = id, false

	// What the caller edited is what List handed it, which carries a stand-in where a
	// resolver URL identifies its account. Both halves of that -- putting the stored URL
	// back, and judging what results -- happen against the document being written, because
	// the profile is read and replaced under the store's own lock.
	var stored config.DNSProfile
	if _, err := d.a.store.Update(func(c *config.Config) error {
		if dnsprofiles.NameTaken(c.DNSProfiles, p.Name, id) {
			return &config.ValidationError{
				Field:   "dnsProfile",
				Message: fmt.Sprintf("a resolver profile called %q already exists", p.Name),
			}
		}
		for i, existing := range c.DNSProfiles {
			if existing.ID != id {
				continue
			}
			updated := p
			servers, err := dnsprofiles.Reveal(p.Servers, existing.Servers)
			if err != nil {
				return &config.ValidationError{Field: "dnsProfile", Message: err.Error()}
			}
			updated.Servers = servers
			if err := dnsprofiles.Validate(updated); err != nil {
				return &config.ValidationError{Field: "dnsProfile", Message: err.Error()}
			}
			c.DNSProfiles[i], stored = updated, updated
			return nil
		}
		return fmt.Errorf("resolver profile %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return config.DNSProfile{}, err
	}
	d.a.pokeReconcile()
	return dnsprofiles.HideProfile(stored), nil
}

// Delete removes a user profile. A profile the machine is currently resolving through is
// refused rather than deleted: removing it would leave the settings pointing at nothing,
// and the machine's own resolver is not the place to discover a dangling reference.
func (d dnsProfilesAPI) Delete(ctx context.Context, id string) error {
	if dnsprofiles.IsBuiltIn(id) {
		return &config.ValidationError{
			Field:   "dnsProfile",
			Message: fmt.Sprintf("%q is a built-in resolver profile and cannot be deleted", id),
		}
	}
	if _, err := d.a.store.Update(func(c *config.Config) error {
		if c.Settings.SystemDNSProfile == id && c.Settings.SystemDNSEnabled {
			return &config.ValidationError{
				Field: "dnsProfile",
				Message: fmt.Sprintf("this machine is resolving names through %q right now; "+
					"switch to another profile first", id),
			}
		}
		for i, p := range c.DNSProfiles {
			if p.ID == id {
				c.DNSProfiles = append(c.DNSProfiles[:i], c.DNSProfiles[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("resolver profile %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return err
	}
	// A profile that is stored but not in force can still be the one the settings name --
	// with the module off, or after a failed apply -- and the reconcile is what turns that
	// into a stated reason rather than a silent no-op.
	d.a.reconcileNow(ctx)
	return nil
}

// dnsProfileChoices fills the resolver picker: the shipped catalog plus the user's own,
// in the order the catalog lists them.
//
// The help is what each profile actually resolves through, because the names people give
// their profiles ("Work", "Home") say nothing about which servers they hold, and a picker
// of four names with no addresses is a guess.
func (a *Agent) dnsProfileChoices() []config.EnumOption {
	catalog := dnsprofiles.Catalog(a.store.Get().DNSProfiles)
	out := make([]config.EnumOption, 0, len(catalog))
	for _, p := range catalog {
		help := strings.Join(dnsprofiles.Hidden(p.Servers), ", ")
		switch {
		case dnsprofiles.NeedsTailnet(p.ID):
			// Its servers are not in the catalog -- they are whatever the tailnet publishes
			// at the moment it is applied -- so the help says where they come from rather
			// than showing an empty list that reads as "no servers".
			help = "Whatever nameservers your tailnet publishes, as set in the Tailscale admin console."
		case len(p.Servers) == 0:
			help = "Leaves this machine's own resolver exactly as it is."
		}
		out = append(out, config.EnumOption{Value: p.ID, Label: p.Name, Help: help})
	}
	return out
}

// dnsBootstrapChoices fills the picker for the resolver that looks up another resolver's
// hostname. Same catalog, different meanings: System default is what sends the lookup to this
// network rather than what leaves the machine alone, and a profile with no literal address in
// it says so instead of being silently unusable.
func (a *Agent) dnsBootstrapChoices() []config.EnumOption {
	catalog := dnsprofiles.Catalog(a.store.Get().DNSProfiles)
	out := make([]config.EnumOption, 0, len(catalog))
	for _, p := range catalog {
		help := strings.Join(dnsprofiles.Hidden(p.Servers), ", ")
		switch {
		case p.ID == dnsprofiles.SystemID:
			help = "Send the lookup to this network's own resolvers, which leaves this network " +
				"able to decide which address answers for a resolver hostname."
		case dnsprofiles.NeedsTailnet(p.ID):
			help = "Whatever nameservers your tailnet publishes, which needs the tailnet node running."
		case len(dnsprofiles.Dialable(p)) == 0:
			help = "Cannot be used here: every resolver in it is named by a hostname, which " +
				"needs the lookup this setting is for."
		}
		out = append(out, config.EnumOption{Value: p.ID, Label: p.Name, Help: help})
	}
	return out
}

// checkDNSProfilePatch refuses a write that points this machine at a resolver profile that
// does not exist.
//
// The settings registry cannot do this itself: the catalog is the user's own document, and
// the field's choices arrive at run time. Refused at the write rather than at the reconcile
// because the write is where somebody is looking -- a stored id naming a deleted profile
// still loads and reports as degraded, which is the right answer for a document that was
// already saved and the wrong one for a save happening now.
func (a *Agent) checkDNSProfilePatch(patch map[string]json.RawMessage) error {
	// Both fields name a profile by id, and both are the user's own document, so both are
	// checked the same way: the bootstrap resolver that does not exist is a silent downgrade
	// to this network's resolvers rather than a broken machine, which is a worse thing to
	// find out later, not a better one.
	for _, field := range []string{"systemDns.profile", "systemDns.bootstrapProfile"} {
		raw, ok := patch[field]
		if !ok {
			continue
		}
		// Only a value this check can read is this check's business. A value that is not a
		// string is the patch decoder's to report, in its own words and with a field
		// attribution this cannot improve on, and an empty id is the registry's default rather
		// than somebody naming a profile.
		var id string
		if err := json.Unmarshal(raw, &id); err != nil || id == "" {
			continue
		}
		if _, found := dnsprofiles.ByID(a.store.Get().DNSProfiles, id); !found {
			return &config.ValidationError{
				Field:   field,
				Message: fmt.Sprintf("there is no resolver profile called %q", id),
			}
		}
	}
	return nil
}
