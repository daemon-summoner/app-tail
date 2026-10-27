// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsblock"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// dnsBlockAPI presents the agent as the management API's name blocking.
type dnsBlockAPI struct{ a *Agent }

var _ httpapi.DNSBlock = dnsBlockAPI{}

// DNSBlock exposes name blocking: the lists, the counters and the controls that do not
// belong in the settings document.
func (a *Agent) DNSBlock() httpapi.DNSBlock { return dnsBlockAPI{a: a} }

func (d dnsBlockAPI) View() httpapi.DNSBlockView {
	a := d.a
	c := a.store.Get()
	s := c.Settings

	// The answer shape and the interval are read as stored: a document written before
	// either setting existed carries them back-filled by the time it is readable here.
	view := httpapi.DNSBlockView{
		Enabled:         s.DNSBlockEnabled,
		Own:             s.DNSBlockOwn,
		System:          s.DNSBlockSystem,
		Answer:          s.DNSBlockAnswer,
		RefreshHours:    s.DNSBlockRefreshHours,
		Allow:           slices.Clone(s.DNSBlockAllow),
		Deny:            slices.Clone(s.DNSBlockDeny),
		RetryOnNXDOMAIN: s.SystemDNSEnabled && s.SystemDNSRetryOnNXDOMAIN,
	}
	for _, p := range dnsblock.Presets() {
		view.Presets = append(view.Presets, httpapi.DNSBlockPresetView{
			ID: p.ID, Name: p.Name, Summary: p.Summary, Recommended: p.Recommended, Lists: p.Lists,
		})
	}

	lists := a.blocklistLists()
	view.Lists = make([]httpapi.DNSBlockListView, 0, len(lists))
	var onShipped []string
	var oldest time.Time
	for _, l := range lists {
		if l.Enabled && l.BuiltIn {
			onShipped = append(onShipped, l.ID)
		}
		entry := httpapi.DNSBlockListView{
			ID: l.ID, Provider: l.Provider, Name: l.Name, URL: l.URL, Format: l.Format,
			BuiltIn: l.BuiltIn, Enabled: l.Enabled, Rules: l.Rules, Skipped: l.Skipped,
			Bytes: l.Bytes, Error: l.Error, Note: l.Note,
		}
		if !l.UpdatedAt.IsZero() {
			entry.UpdatedAt = l.UpdatedAt.UTC().Format(time.RFC3339)
			if l.Enabled && (oldest.IsZero() || l.UpdatedAt.Before(oldest)) {
				oldest = l.UpdatedAt
			}
		}
		view.Lists = append(view.Lists, entry)
	}
	// Only the shipped lists decide the rung: a list the user added is theirs, and every
	// rung leaves it alone, so holding one has never meant leaving the ladder.
	view.Preset, _ = dnsblock.MatchPreset(onShipped)

	if runner := a.currentBlocklists(); runner != nil {
		if set := runner.set.Load(); set != nil {
			view.Rules = set.Rules()
		}
		if _, compiledAt := runner.snapshot(); !compiledAt.IsZero() {
			view.CompiledAt = compiledAt.UTC().Format(time.RFC3339)
		}
		if until, paused := runner.paused(); paused {
			view.PausedUntil = until.UTC().Format(time.RFC3339)
		}
	}
	if !oldest.IsZero() {
		view.NextRefresh = oldest.Add(time.Duration(view.RefreshHours) * time.Hour).UTC().Format(time.RFC3339)
	}

	if runner := a.currentSystemDNS(); runner != nil {
		view.Blocked = runner.snapshot().stats.Blocked
	}
	view.Error = a.blocklistRoundError()

	view.Capability = dnsBlockCapability(view)
	return view
}

// dnsBlockCapability states what blocking is really doing, and when it is not doing what
// the switches say, why.
//
// The order is the ladder a user climbs: switched on at all, then pointed at something,
// then having something to point with, then actually in force.
func dnsBlockCapability(view httpapi.DNSBlockView) httpapi.Capability {
	limits := []string{
		"Blocking happens where names are resolved, so a port forward -- which carries an " +
			"address rather than a name -- is not filtered by it.",
		"Lists are downloaded and kept on this machine. A list that cannot be downloaded " +
			"keeps blocking from the copy already here.",
		"A browser-filter list only contributes the rules a resolver can express; the rest " +
			"are counted as skipped.",
	}
	switch {
	case !view.Enabled:
		return httpapi.Capability{
			Available: true,
			Reason:    "Blocking is off, so no name is refused by app-tail.",
			Limits:    limits,
		}
	case !view.Own && !view.System:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Blocking is on but neither switch under it is, so nothing is filtered. " +
				"Turn on app-tail's own resolution, this machine's resolution, or both.",
			Limits: limits,
		}
	case view.PausedUntil != "":
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Blocking is paused; every name resolves normally until it resumes.",
			Limits: limits,
		}
	case view.Rules == 0:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "No list has been downloaded yet, so nothing is blocked. Switch a list on, " +
				"or refresh to download the ones already chosen.",
			Limits: limits,
		}
	case view.System && view.RetryOnNXDOMAIN:
		// The one setting elsewhere that undoes this one. It is reported here because the
		// card would otherwise show a million rules in force while every blocked name still
		// resolves through this network.
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "This machine's resolver is set to retry a name your resolver says does not " +
				"exist against this network, which is how a blocked name resolves anyway. " +
				"Turn that off to make blocking hold machine-wide.",
			Limits: limits,
		}
	}
	return httpapi.Capability{Available: true, Limits: limits}
}

// Refresh downloads every enabled list now.
func (d dnsBlockAPI) Refresh(ctx context.Context) error {
	err := d.a.reconcileBlocklists(ctx, true)
	// Recorded as well as returned: the caller reads the refusal once, and the card keeps
	// showing it until a round succeeds.
	d.a.noteBlocklistRound(err)
	return err
}

// Pause stops blocking for a while. It takes effect on the next query rather than on the
// next reconcile: a pause is asked for because something is broken right now. The reconcile
// is asked for as well, now and when the pause ends, because what the machine cached while
// the names were blocked is still being answered from until it moves resolver address.
func (d dnsBlockAPI) Pause(dur time.Duration) time.Time {
	runner := d.a.currentBlocklists()
	if runner == nil {
		return time.Time{}
	}
	until := runner.pause(dur)
	d.a.pokeReconcile()
	time.AfterFunc(dur, d.a.pokeReconcile)
	return until
}

func (d dnsBlockAPI) Resume() {
	if runner := d.a.currentBlocklists(); runner != nil {
		runner.resume()
		d.a.pokeReconcile()
	}
}

// Check reports whether one name is blocked and by what. Every answer says why, including
// the ones that are not about a list: blocking off, both switches off, or paused.
func (d dnsBlockAPI) Check(name string) httpapi.DNSBlockCheckView {
	a := d.a
	s := a.settings()
	normalized := dnsblock.Normalize(name)
	out := httpapi.DNSBlockCheckView{Name: normalized}

	runner := a.currentBlocklists()
	switch {
	case normalized == "":
		out.Reason = "that is not a name"
		return out
	case !s.DNSBlockEnabled:
		out.Reason = "blocking is switched off"
		return out
	case !s.DNSBlockOwn && !s.DNSBlockSystem:
		out.Reason = "blocking is on but neither app-tail's own resolution nor this machine's is set to use it"
		return out
	case runner == nil:
		out.Reason = "the blocklists have not been loaded yet"
		return out
	}
	if until, paused := runner.paused(); paused {
		out.Reason = fmt.Sprintf("blocking is paused until %s", until.Format(time.Kitchen))
		return out
	}

	set := runner.set.Load()
	if set == nil {
		out.Reason = "no list has been downloaded yet"
		return out
	}
	if list, blocked := set.Blocks(normalized); blocked {
		out.Blocked, out.List = true, list
		out.Reason = "on " + list
		return out
	}
	out.Reason = fmt.Sprintf("not on any of the %d names the lists you turned on hold", set.Rules())
	return out
}

// ApplyPreset switches on exactly the lists one rung of the ladder names.
//
// The lists the user added keep whatever they had: a rung curates the shipped catalog, and
// silently switching off a list somebody went and found is not curation. The write goes
// through the settings API rather than the store, so a preset lands under the same
// validation, precedence and reconcile as somebody typing the setting out by hand.
func (d dnsBlockAPI) ApplyPreset(ctx context.Context, id string) error {
	preset, ok := dnsblock.PresetByID(id)
	if !ok {
		return &config.ValidationError{
			Field:   "preset",
			Message: fmt.Sprintf("%q is not one of the levels; use %s", id, strings.Join(presetIDs(), ", ")),
		}
	}

	wanted := slices.Clone(preset.Lists)
	for _, l := range d.a.blocklistLists() {
		if l.Enabled && !l.BuiltIn {
			wanted = append(wanted, l.ID)
		}
	}
	encoded, err := json.Marshal(wanted)
	if err != nil {
		return fmt.Errorf("encode the lists %s turns on: %w", preset.Name, err)
	}
	_, _, err = settingsAPI(d).Update(ctx, map[string]json.RawMessage{
		"dnsBlock.lists": encoded,
	})
	return err
}

// presetIDs names the rungs, for the sentence a refusal ends with.
func presetIDs() []string {
	all := dnsblock.Presets()
	out := make([]string, 0, len(all))
	for _, p := range all {
		out = append(out, p.ID)
	}
	return out
}

// CreateList adds one of the user's own lists to the catalog.
func (d dnsBlockAPI) CreateList(l config.Blocklist) (config.Blocklist, error) {
	l.Name = strings.TrimSpace(l.Name)
	l.URL = strings.TrimSpace(l.URL)
	l.BuiltIn = false
	if err := dnsblock.Validate(l); err != nil {
		return config.Blocklist{}, &config.ValidationError{Field: "blocklist", Message: err.Error()}
	}

	if _, err := d.a.store.Update(func(c *config.Config) error {
		if dnsblock.NameTaken(c.Blocklists, l.Name, "") {
			// Names are unique because the CLI and the card name a list by what the user
			// called it, and two lists called "Work" make that a coin flip.
			return &config.ValidationError{
				Field:   "blocklist",
				Message: fmt.Sprintf("a blocklist called %q already exists", l.Name),
			}
		}
		taken := func(id string) bool {
			for _, existing := range c.Blocklists {
				if existing.ID == id {
					return true
				}
			}
			return false
		}
		if l.ID == "" || taken(l.ID) || dnsblock.IsBuiltIn(l.ID) {
			l.ID = dnsblock.NewID(l.Name, taken)
		}
		c.Blocklists = append(c.Blocklists, l)
		return nil
	}); err != nil {
		return config.Blocklist{}, err
	}
	return l, nil
}

// UpdateList replaces one of the user's own lists in place, keeping its id so the setting
// naming it stays valid across an edit.
//
// A changed address is a different list, so what was downloaded under this id is dropped:
// keeping it would leave the old list's names blocking under the new list's name.
func (d dnsBlockAPI) UpdateList(id string, l config.Blocklist) (config.Blocklist, error) {
	if dnsblock.IsBuiltIn(id) {
		return config.Blocklist{}, &config.ValidationError{
			Field:   "blocklist",
			Message: fmt.Sprintf("%q ships with app-tail and cannot be edited; add your own to point somewhere else", id),
		}
	}
	l.Name = strings.TrimSpace(l.Name)
	l.URL = strings.TrimSpace(l.URL)
	l.ID, l.BuiltIn = id, false
	if err := dnsblock.Validate(l); err != nil {
		return config.Blocklist{}, &config.ValidationError{Field: "blocklist", Message: err.Error()}
	}

	var moved bool
	if _, err := d.a.store.Update(func(c *config.Config) error {
		if dnsblock.NameTaken(c.Blocklists, l.Name, id) {
			return &config.ValidationError{
				Field:   "blocklist",
				Message: fmt.Sprintf("a blocklist called %q already exists", l.Name),
			}
		}
		for i, existing := range c.Blocklists {
			if existing.ID != id {
				continue
			}
			moved = existing.URL != l.URL || existing.Format != l.Format
			c.Blocklists[i] = l
			return nil
		}
		return fmt.Errorf("blocklist %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return config.Blocklist{}, err
	}

	if moved {
		if runner := d.a.currentBlocklists(); runner != nil {
			if err := runner.forget(id); err != nil {
				// The stored entry is already the new one, so the download is what is stale.
				// It is re-downloaded on the next round either way; what is worth saying is
				// that the old copy is still on disk.
				d.a.logger.Warn("removing the downloaded copy of an edited blocklist failed",
					"list", id, "error", err)
			}
		}
	}
	d.a.pokeReconcile()
	// A list whose address changed has had its copy forgotten just above, so the round this
	// asks for is what downloads the new one.
	d.a.pokeBlocklists()
	return l, nil
}

// DeleteList removes one of the user's own lists, and the copy downloaded for it. A list
// that is switched on is refused rather than deleted: removing it would leave the setting
// naming a list nothing can download.
func (d dnsBlockAPI) DeleteList(ctx context.Context, id string) error {
	if dnsblock.IsBuiltIn(id) {
		return &config.ValidationError{
			Field:   "blocklist",
			Message: fmt.Sprintf("%q ships with app-tail and cannot be deleted; switch it off instead", id),
		}
	}
	if _, err := d.a.store.Update(func(c *config.Config) error {
		if slices.Contains(c.Settings.DNSBlockLists, id) {
			return &config.ValidationError{
				Field:   "blocklist",
				Message: fmt.Sprintf("%q is switched on right now; switch it off before deleting it", id),
			}
		}
		for i, l := range c.Blocklists {
			if l.ID == id {
				c.Blocklists = append(c.Blocklists[:i], c.Blocklists[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("blocklist %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return err
	}
	if runner := d.a.currentBlocklists(); runner != nil {
		if err := runner.forget(id); err != nil {
			return err
		}
	}
	d.a.reconcileNow(ctx)
	return nil
}
