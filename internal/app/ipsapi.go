// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/ipsfeed"
)

// ipsAPI presents the agent as the management API's traffic inspection.
type ipsAPI struct{ a *Agent }

var _ httpapi.IPS = ipsAPI{}

// IPS exposes traffic inspection: what the rules hold, what they have matched, and the
// pause that does not belong in the settings document.
func (a *Agent) IPS() httpapi.IPS { return ipsAPI{a: a} }

func (i ipsAPI) View() httpapi.IPSView {
	a := i.a
	s := a.store.Get().Settings

	// The interval is read as stored: a document written before the setting existed carries it
	// back-filled by the time it is readable here.
	refreshHours := s.IPSRefreshHours
	view := httpapi.IPSView{
		Enabled:      s.IPSEnabled,
		Mode:         s.IPSMode,
		Names:        s.IPSNames,
		Destinations: s.IPSDestinations,
		Anomaly:      s.IPSAnomaly,
		Handshake:    s.IPSHandshake,
		Fingerprints: s.IPSHandshake && s.IPSFingerprints,
		Payload:      s.IPSHandshake && s.IPSPayload,
		RefreshHours: refreshHours,
		Allow:        slices.Clone(s.IPSAllow),
		Deny:         slices.Clone(s.IPSDeny),
	}

	for _, p := range ipsfeed.Presets() {
		view.Presets = append(view.Presets, httpapi.IPSPresetView{
			ID: p.ID, Name: p.Name, Summary: p.Summary, Recommended: p.Recommended, Feeds: p.Feeds,
		})
	}

	states := a.ipsFeedStates()
	view.Feeds = make([]httpapi.IPSFeedView, 0, len(states))
	var onShipped []string
	var oldest time.Time
	for _, f := range states {
		if f.Enabled && f.BuiltIn {
			onShipped = append(onShipped, f.ID)
		}
		entry := httpapi.IPSFeedView{
			ID: f.ID, Provider: f.Provider, Name: f.Name, URL: f.URL,
			BuiltIn: f.BuiltIn, Enabled: f.Enabled, Rules: f.Rules, Skipped: f.Skipped,
			Bytes: f.Bytes, Error: f.Error, Note: f.Note,
		}
		if !f.UpdatedAt.IsZero() {
			entry.UpdatedAt = f.UpdatedAt.UTC().Format(time.RFC3339)
			if f.Enabled && (oldest.IsZero() || f.UpdatedAt.Before(oldest)) {
				oldest = f.UpdatedAt
			}
		}
		view.Feeds = append(view.Feeds, entry)
	}
	// Only the shipped feeds decide the rung: a feed the user added is theirs, and every rung
	// leaves it alone, so holding one has never meant leaving the ladder.
	view.Preset, _ = ipsfeed.MatchPreset(onShipped)
	if !oldest.IsZero() {
		view.NextRefresh = oldest.Add(time.Duration(refreshHours) * time.Hour).UTC().Format(time.RFC3339)
	}
	view.Error = a.ipsFeedRoundError()

	runner := a.currentIPS()
	if rules := runner.rules.Load(); rules != nil {
		view.Rules = rules.Count()
		for _, source := range rules.Sources() {
			view.Skipped += source.Skipped
		}
	}
	view.Signatures = runner.signatureCount()
	if at := runner.compiled(); !at.IsZero() {
		view.CompiledAt = at.UTC().Format(time.RFC3339)
	}
	if until, paused := runner.paused(); paused {
		view.PausedUntil = until.UTC().Format(time.RFC3339)
	}
	view.Matched, view.Refused, view.Anomalies = runner.totals()
	for _, d := range runner.recentMatches() {
		view.Recent = append(view.Recent, httpapi.IPSDetectionView{
			At:          d.At.UTC().Format(time.RFC3339),
			Signal:      d.Signal,
			Value:       d.Value,
			Source:      d.Source,
			Reason:      d.Reason,
			Where:       d.Where,
			Protocol:    d.Protocol,
			Peer:        d.Peer,
			Fingerprint: d.Fingerprint,
			Refused:     d.Refused,
		})
	}

	for _, b := range runner.beacons(a.now()) {
		view.Beacons = append(view.Beacons, httpapi.IPSBeaconView{
			Source: b.Source(),
			Addr:   b.Addr,
			Every:  b.Every.Seconds(),
			Jitter: b.Jitter,
			Count:  b.Count,
			Since:  b.Since.UTC().Format(time.RFC3339),
		})
	}

	view.Intercept = a.ipsInterceptView()
	view.Capability = ipsCapability(view)
	return view
}

// ipsLimits are what traffic inspection does not reach, stated where a user reads what it
// does. They never clear: each one is a property of where in app-tail traffic is carried,
// not a state that a setting or a download fixes.
var ipsLimits = []string{
	"Inspection covers what app-tail itself carries -- the network interface in fabric mode, " +
		"the proxy, and connections other devices on the tailnet route through this one. It is " +
		"not a filter on everything this machine does.",
	"In tun mode this machine's own networking carries the tailnet's traffic rather than " +
		"app-tail, so nothing on that path is inspected. Fabric mode is the one that is.",
	"Traffic OpenVPN puts on its own interface never passes through app-tail and is not " +
		"inspected. What app-tail carries over an OpenVPN tunnel is.",
	"A port forward carries an address chosen in the settings, so there is nothing there to " +
		"refuse before it is dialled. What the connections it carries ask for is read from " +
		"their opening bytes, with reading the start of each connection on.",
	"Without reading the start of each connection, the network interface knows only the " +
		"address a connection is bound for: the name a program asked for reaches inspection " +
		"through the proxy and this machine's resolver only.",
	"A browser that reaches a destination over QUIC sends nothing readable, so only that it " +
		"is QUIC is known. Refusing it makes every browser fall back to the ordinary " +
		"connection, where the name is readable.",
	"Encrypted client hello, as it arrives, puts the name inside the encrypted part of the " +
		"handshake. Where a connection uses it, the name read here is the cover name the " +
		"server published rather than the one the program asked for, and the finding says so.",
	"A connection another device on the tailnet routes through this one arrives through the " +
		"tailnet's own networking, which does not always offer a way to cut one. Where it does " +
		"not, a connection stopped part-way is closed instead, and the device that sent it sees " +
		"the connection end rather than the reset the other paths send.",
	"Your own byte patterns are read only over the first few kilobytes a connection sends, " +
		"and only over what is sent in the clear. Nothing inside a TLS connection is read, and " +
		"a pattern that appears later in a transfer is not seen.",
	"A connection stopped for one of your byte patterns is stopped rather than prevented: the " +
		"bytes ahead of the match have already been passed along by the time it is found, so " +
		"what stopping ends is the rest of that connection.",
	"Opening encrypted connections works only for programs that trust the certificate app-tail " +
		"generated. A program that checks for a particular certificate of its own -- app stores, " +
		"system updates, banking and messaging apps, several package managers -- refuses the " +
		"connection instead, which is why the list app-tail ships leaves those alone.",
	"A connection that proves who the program is with a certificate of its own cannot be " +
		"opened: app-tail does not hold that program's private key and never will. Such a " +
		"connection has to be left alone or it stops working.",
	"Opening a connection needs the real server's certificate to verify first. Where it does " +
		"not, the connection is stopped rather than carried, which is the whole point: the " +
		"alternative is app-tail vouching for a server nothing could check.",
	"Unusual patterns are reported for this machine as a whole, not for the program that " +
		"caused them: this machine's resolver serves loopback and connections arrive already " +
		"made, so nothing on either path says which program asked. Only a pattern another " +
		"device on the tailnet caused names that device.",
}

// ipsCapability states what inspection is really doing, and when it is not doing what the
// switches say, why.
//
// The order is the ladder a user climbs: switched on at all, then pointed at something, then
// running rather than paused, then having something to match with.
func ipsCapability(view httpapi.IPSView) httpapi.Capability {
	switch {
	case !view.Enabled:
		return httpapi.Capability{
			Available: true,
			Reason:    "Traffic inspection is off, so no connection is refused by app-tail.",
			Limits:    ipsLimits,
		}
	// Ahead of every other state, and degraded while it is working exactly as asked: opening
	// connections is the one thing here that changes what the program at the far end sees, and
	// a machine doing it should say so on the card rather than only in a setting.
	case view.Intercept.Running && !view.Intercept.Installed:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "app-tail is opening encrypted connections, and this machine does not trust " +
				"the certificate it presents. Every connection it opens fails until the " +
				"certificate is installed, so install it or turn opening connections back off.",
			Limits: ipsLimits,
		}
	case view.Intercept.Running:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "app-tail is opening encrypted connections to read them, presenting its own " +
				"certificate to the programs on this machine. Everything they send inside those " +
				"connections is readable here while this is on.",
			Limits: ipsLimits,
		}
	case !view.Names && !view.Destinations && !view.Anomaly && !view.Handshake:
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Inspection is on but no signal under it is, so nothing is inspected. " +
				"Turn on the names programs ask for, the addresses connections are bound for, " +
				"the start of each connection, the watch for unusual patterns, or any " +
				"combination of them.",
			Limits: ipsLimits,
		}
	// Reading the opening bytes finds a name and has nothing to measure it against, which is
	// a switch that costs a window per connection and can never match. Byte patterns read the
	// same window against something else, so a written one answers this on its own; the
	// switch with none written is not read against anything and does not.
	case view.Handshake && !view.Names && (!view.Payload || view.Signatures == 0):
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "The start of each connection is read, but the names in it are not " +
				"inspected, so nothing it finds can match. Turn on the names programs ask for, " +
				"or write a byte pattern of your own.",
			Limits: ipsLimits,
		}
	case view.PausedUntil != "":
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Inspection is paused; every connection is carried until it resumes.",
			Limits: ipsLimits,
		}
	// Only where a signal that matches against the lists is on. The watch for unusual patterns
	// matches against nothing anybody typed, and byte patterns match against their own list,
	// so on a machine running either of those alone an empty list is the state it is meant to
	// be in rather than a thing left undone. Reading the start of a connection is not listed:
	// without the names it is caught above, and with them the names cover it.
	case view.Rules == 0 && (view.Names || view.Destinations):
		// A feed switched on and nothing downloaded is a different state from nothing chosen
		// at all: one is waiting for a download, the other is waiting for the user.
		for _, f := range view.Feeds {
			if f.Enabled {
				return httpapi.Capability{
					Available: true, Degraded: true,
					Reason: "No feed has been downloaded yet, so nothing is matched. Refresh to " +
						"download the ones already chosen.",
					Limits: ipsLimits,
				}
			}
		}
		return httpapi.Capability{
			Available: true, Degraded: true,
			Reason: "Inspection is on but there is nothing to match: switch on a feed of known-bad " +
				"addresses, or add a domain or an address to the list of what to stop.",
			Limits: ipsLimits,
		}
	}
	return httpapi.Capability{Available: true, Limits: ipsLimits}
}

// Refresh downloads every enabled feed now.
func (i ipsAPI) Refresh(ctx context.Context) error {
	err := i.a.reconcileIPSFeeds(ctx, true)
	// Recorded as well as returned: the caller reads the refusal once, and the card keeps
	// showing it until a round succeeds.
	i.a.noteIPSFeedRound(err)
	return err
}

// ApplyPreset switches on exactly the feeds one rung of the ladder names.
//
// The feeds the user added keep whatever they had: a rung curates the shipped catalog, and
// silently switching off a feed somebody went and found is not curation. The write goes
// through the settings API rather than the store, so a preset lands under the same validation,
// precedence and reconcile as somebody typing the setting out by hand.
func (i ipsAPI) ApplyPreset(ctx context.Context, id string) error {
	preset, ok := ipsfeed.PresetByID(id)
	if !ok {
		return &config.ValidationError{
			Field:   "preset",
			Message: fmt.Sprintf("%q is not one of the levels; use %s", id, strings.Join(ipsPresetIDs(), ", ")),
		}
	}

	wanted := slices.Clone(preset.Feeds)
	for _, f := range i.a.ipsFeedStates() {
		if f.Enabled && !f.BuiltIn {
			wanted = append(wanted, f.ID)
		}
	}
	encoded, err := json.Marshal(wanted)
	if err != nil {
		return fmt.Errorf("encode the feeds %s turns on: %w", preset.Name, err)
	}
	_, _, err = settingsAPI(i).Update(ctx, map[string]json.RawMessage{
		"ips.lists": encoded,
	})
	return err
}

// ipsPresetIDs names the rungs, for the sentence a refusal ends with.
func ipsPresetIDs() []string {
	all := ipsfeed.Presets()
	out := make([]string, 0, len(all))
	for _, p := range all {
		out = append(out, p.ID)
	}
	return out
}

// CreateFeed adds one of the user's own feeds to the catalog.
func (i ipsAPI) CreateFeed(f config.IPSFeed) (config.IPSFeed, error) {
	f.Name = strings.TrimSpace(f.Name)
	f.URL = strings.TrimSpace(f.URL)
	f.BuiltIn = false
	if err := ipsfeed.Validate(f); err != nil {
		return config.IPSFeed{}, &config.ValidationError{Field: "ipsFeed", Message: err.Error()}
	}

	if _, err := i.a.store.Update(func(c *config.Config) error {
		if ipsfeed.NameTaken(c.IPSFeeds, f.Name, "") {
			// Names are unique because the CLI and the card name a feed by what the user called
			// it, and two feeds called "Work" make that a coin flip.
			return &config.ValidationError{
				Field:   "ipsFeed",
				Message: fmt.Sprintf("an inspection feed called %q already exists", f.Name),
			}
		}
		taken := func(id string) bool {
			for _, existing := range c.IPSFeeds {
				if existing.ID == id {
					return true
				}
			}
			return false
		}
		if f.ID == "" || taken(f.ID) || ipsfeed.IsBuiltIn(f.ID) {
			f.ID = ipsfeed.NewID(f.Name, taken)
		}
		c.IPSFeeds = append(c.IPSFeeds, f)
		return nil
	}); err != nil {
		return config.IPSFeed{}, err
	}
	return f, nil
}

// UpdateFeed replaces one of the user's own feeds in place, keeping its id so the setting
// naming it stays valid across an edit.
//
// A changed address is a different feed, so what was downloaded under this id is dropped:
// keeping it would leave the old feed's addresses matching under the new feed's name.
func (i ipsAPI) UpdateFeed(id string, f config.IPSFeed) (config.IPSFeed, error) {
	if ipsfeed.IsBuiltIn(id) {
		return config.IPSFeed{}, &config.ValidationError{
			Field:   "ipsFeed",
			Message: fmt.Sprintf("%q ships with app-tail and cannot be edited; add your own to point somewhere else", id),
		}
	}
	f.Name = strings.TrimSpace(f.Name)
	f.URL = strings.TrimSpace(f.URL)
	f.ID, f.BuiltIn = id, false
	if err := ipsfeed.Validate(f); err != nil {
		return config.IPSFeed{}, &config.ValidationError{Field: "ipsFeed", Message: err.Error()}
	}

	var moved bool
	if _, err := i.a.store.Update(func(c *config.Config) error {
		if ipsfeed.NameTaken(c.IPSFeeds, f.Name, id) {
			return &config.ValidationError{
				Field:   "ipsFeed",
				Message: fmt.Sprintf("an inspection feed called %q already exists", f.Name),
			}
		}
		for idx, existing := range c.IPSFeeds {
			if existing.ID != id {
				continue
			}
			moved = existing.URL != f.URL
			c.IPSFeeds[idx] = f
			return nil
		}
		return fmt.Errorf("inspection feed %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return config.IPSFeed{}, err
	}

	if moved {
		if runner := i.a.currentIPSFeeds(); runner != nil {
			if err := runner.forget(id); err != nil {
				// The stored entry is already the new one, so the download is what is stale. It
				// is re-downloaded on the next round either way; what is worth saying is that
				// the old copy is still on disk.
				i.a.logger.Warn("removing the downloaded copy of an edited inspection feed failed",
					"feed", id, "error", err)
			}
		}
	}
	i.a.pokeReconcile()
	// A feed whose address changed has had its copy forgotten just above, so the round this
	// asks for is what downloads the new one.
	i.a.pokeIPSFeeds()
	return f, nil
}

// DeleteFeed removes one of the user's own feeds, and the copy downloaded for it. A feed that
// is switched on is refused rather than deleted: removing it would leave the setting naming a
// feed nothing can download.
func (i ipsAPI) DeleteFeed(ctx context.Context, id string) error {
	if ipsfeed.IsBuiltIn(id) {
		return &config.ValidationError{
			Field:   "ipsFeed",
			Message: fmt.Sprintf("%q ships with app-tail and cannot be deleted; switch it off instead", id),
		}
	}
	if _, err := i.a.store.Update(func(c *config.Config) error {
		if slices.Contains(c.Settings.IPSLists, id) {
			return &config.ValidationError{
				Field:   "ipsFeed",
				Message: fmt.Sprintf("%q is switched on right now; switch it off before deleting it", id),
			}
		}
		for idx, f := range c.IPSFeeds {
			if f.ID == id {
				c.IPSFeeds = append(c.IPSFeeds[:idx], c.IPSFeeds[idx+1:]...)
				return nil
			}
		}
		return fmt.Errorf("inspection feed %q: %w", id, config.ErrNotFound)
	}); err != nil {
		return err
	}
	if runner := i.a.currentIPSFeeds(); runner != nil {
		if err := runner.forget(id); err != nil {
			return err
		}
	}
	i.a.reconcileNow(ctx)
	return nil
}

// Pause stops inspection for a while. It takes effect on the next connection rather than on
// the next reconcile: a pause is asked for because something is broken right now.
func (i ipsAPI) Pause(d time.Duration) time.Time { return i.a.currentIPS().pause(d) }

func (i ipsAPI) Resume() { i.a.currentIPS().resume() }

// Check answers what the rules say about one destination without a connection having to be
// made to find out.
//
// It reads the same switches the data path reads, so a destination the rules name while the
// signal that would see it is off answers "carried", which is what actually happens.
func (i ipsAPI) Check(dest string) httpapi.IPSCheckView {
	dest = strings.TrimSpace(dest)
	view := httpapi.IPSCheckView{Destination: dest}

	s := i.a.store.Get().Settings
	runner := i.a.currentIPS()
	if !s.IPSEnabled {
		view.Reason = "Traffic inspection is off, so this is carried."
		return view
	}

	var name string
	var addr netip.Addr
	if parsed, err := netip.ParseAddr(dest); err == nil {
		addr = parsed
		if !s.IPSDestinations {
			view.Reason = "Addresses are not inspected, so this is carried. " +
				"Turn on the addresses connections are bound for to inspect it."
			return view
		}
	} else {
		name = dest
		if !s.IPSNames {
			view.Reason = "Names are not inspected, so this is carried. " +
				"Turn on the names programs ask for to inspect it."
			return view
		}
	}

	rules := runner.rules.Load()
	if rules == nil {
		view.Reason = "No inspection rules are compiled yet, so this is carried."
		return view
	}
	found, ok := rules.Check(name, addr)
	if !ok {
		view.Reason = "No rule names this, so it is carried."
		return view
	}

	view.Matched = true
	view.Signal = string(found.Signal)
	view.Value = found.Value
	view.Source = found.Source
	view.Reason = found.Reason()

	if _, paused := runner.paused(); paused {
		view.Reason += ", but inspection is paused, so it is carried"
		return view
	}
	if s.IPSMode != config.IPSModePrevent {
		view.Reason += ", and is recorded and carried"
		return view
	}
	view.Refused = true
	view.Reason += ", and is refused"
	return view
}
