// SPDX-License-Identifier: MIT

// Package ipsfeed is the catalog of address feeds traffic inspection matches against, and
// the parser for what they contain.
//
// It is the address half of what package dnsblock is for names: which feeds ship, who
// publishes them, what each is for, and how one line of a downloaded file becomes an entry.
// It holds no state and opens no socket -- downloading is internal/feeds, matching is
// internal/inspect, and deciding which feeds are on is the runner.
package ipsfeed

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
)

// MaxNameLen bounds a feed's name. It is shown in the reason a connection matched, which is
// one line in a CLI and one row on a card.
const MaxNameLen = 64

// DefaultFeedID is the feed a fresh install switches on when address feeds are turned on for
// the first time. FireHOL level 1 is the tier its author describes as safe to block outright:
// networks with no legitimate traffic at all, rather than addresses that have misbehaved.
const DefaultFeedID = "firehol-level1"

// UserProvider is the group a feed the user added belongs to. Nobody but the user vouches
// for it, which is the distinction the grouping is there to draw.
const UserProvider = "Your feeds"

// builtIn is the shipped catalog, grouped by who publishes it and ordered inside a group by
// how much it stops rather than alphabetically: a picker here is read as "how aggressive do
// I want to be", and the aggressive tiers are the ones that need the entry above them for
// contrast.
//
// Every entry is one address or one network per line. That is not a format a feed declares:
// it is what these files are, and a feed that is something else is one this side cannot use.
var builtIn = []config.IPSFeed{
	{ID: DefaultFeedID, Name: "FireHOL Level 1", URL: "https://iplists.firehol.org/files/firehol_level1.netset", BuiltIn: true},
	{ID: "firehol-level2", Name: "FireHOL Level 2", URL: "https://iplists.firehol.org/files/firehol_level2.netset", BuiltIn: true},
	{ID: "firehol-level3", Name: "FireHOL Level 3", URL: "https://iplists.firehol.org/files/firehol_level3.netset", BuiltIn: true},
	{ID: "firehol-webserver", Name: "FireHOL Web server attacks", URL: "https://iplists.firehol.org/files/firehol_webserver.netset", BuiltIn: true},
	{ID: "spamhaus-drop", Name: "Spamhaus DROP", URL: "https://iplists.firehol.org/files/spamhaus_drop.netset", BuiltIn: true},
	{ID: "spamhaus-edrop", Name: "Spamhaus Extended DROP", URL: "https://iplists.firehol.org/files/spamhaus_edrop.netset", BuiltIn: true},
	{ID: "dshield", Name: "DShield top attackers", URL: "https://iplists.firehol.org/files/dshield.netset", BuiltIn: true},
	{ID: "alienvault", Name: "AlienVault reputation", URL: "https://iplists.firehol.org/files/alienvault_reputation.ipset", BuiltIn: true},
	{ID: "feodo", Name: "Feodo Tracker botnet C2", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", BuiltIn: true},
	{ID: "emerging-compromised", Name: "Emerging Threats compromised hosts", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", BuiltIn: true},
	{ID: "cins-badguys", Name: "CINS Army", URL: "https://cinsscore.com/list/ci-badguys.txt", BuiltIn: true},
	{ID: "blocklist-de", Name: "blocklist.de attackers", URL: "https://lists.blocklist.de/lists/all.txt", BuiltIn: true},
	{ID: "binarydefense", Name: "Binary Defense ban list", URL: "https://www.binarydefense.com/banlist.txt", BuiltIn: true},
	{ID: "greensnow", Name: "GreenSnow attackers", URL: "https://blocklist.greensnow.co/greensnow.txt", BuiltIn: true},
	{ID: "ipsum-3", Name: "IPsum Level 3", URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", BuiltIn: true},
	{ID: "ipsum-5", Name: "IPsum Level 5", URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt", BuiltIn: true},
	{ID: "tor-exits", Name: "Tor exit nodes", URL: "https://check.torproject.org/torbulkexitlist", BuiltIn: true},
}

// providers names who publishes each shipped feed. A catalog read as "which FireHOL level do
// I want" is a choice; the same entries as a flat list are a wall.
var providers = map[string]string{
	DefaultFeedID:          "FireHOL",
	"firehol-level2":       "FireHOL",
	"firehol-level3":       "FireHOL",
	"firehol-webserver":    "FireHOL",
	"spamhaus-drop":        "Spamhaus",
	"spamhaus-edrop":       "Spamhaus",
	"dshield":              "DShield",
	"alienvault":           "AlienVault",
	"feodo":                "abuse.ch",
	"emerging-compromised": "Emerging Threats",
	"cins-badguys":         "CINS",
	"blocklist-de":         "blocklist.de",
	"binarydefense":        "Binary Defense",
	"greensnow":            "GreenSnow",
	"ipsum-3":              "IPsum",
	"ipsum-5":              "IPsum",
	"tor-exits":            "Tor Project",
}

// Provider names who publishes a feed.
func Provider(f config.IPSFeed) string {
	if p, ok := providers[f.ID]; ok {
		return p
	}
	return UserProvider
}

// notes carries what a shipped feed is for, and where it is known to disappoint. The card
// shows it beside the switch, because "why is this one matching nothing" and "why did this
// one stop something I use" are the two questions a catalog this size creates.
var notes = map[string]string{
	DefaultFeedID:          "Networks with no legitimate traffic at all, merged from several sources. The tier to start with: it is meant to be safe to refuse outright.",
	"firehol-level2":       "Addresses seen attacking something in the last two days. Recent and specific, and short-lived by design.",
	"firehol-level3":       "A month of attack sources rather than two days. Wider, older, and more likely to hold an address somebody else has since been given.",
	"firehol-webserver":    "Addresses seen attacking web servers specifically. Narrow, and worth carrying beside a wider tier rather than alone.",
	"spamhaus-drop":        "Networks Spamhaus says are controlled outright by criminals. Very short, very high confidence.",
	"spamhaus-edrop":       "The extended list: networks leased to the same operators through somebody else. Sits beside DROP rather than replacing it.",
	"dshield":              "The twenty networks the SANS Internet Storm Center sees the most attacks from today. Tiny and current.",
	"alienvault":           "Addresses with a poor reputation in AlienVault's open threat exchange.",
	"feodo":                "Servers running botnet command and control, from abuse.ch. Very short, and what a machine that is already infected talks to.",
	"emerging-compromised": "Hosts Emerging Threats has seen compromised and used to attack others.",
	"cins-badguys":         "The CINS Army list: addresses with a poor score across Sentinel deployments.",
	"blocklist-de":         "Addresses reported by fail2ban installations for attacking SSH, mail and web services. Large, and made of hosts rather than networks.",
	"binarydefense":        "Binary Defense's ban list, built from their own honeypots and sensors.",
	"greensnow":            "Addresses seen attacking servers, refreshed continuously.",
	"ipsum-3":              "Addresses on at least three of the thirty public feeds IPsum merges. The everyday tier of that merge.",
	"ipsum-5":              "Addresses on at least five feeds. Roughly a fifth the size of level 3 and correspondingly harder to argue with.",
	"tor-exits":            "Every current Tor exit node. Not malicious: this is here for a machine that has decided not to accept Tor traffic, and refusing it in the outbound direction breaks Tor for this machine.",
}

// Note reports what a shipped feed is for. A user feed has none: its description is the name
// the user gave it.
func Note(id string) string { return notes[id] }

// BuiltIn returns a copy of the shipped catalog.
func BuiltIn() []config.IPSFeed {
	return append([]config.IPSFeed(nil), builtIn...)
}

// IsBuiltIn reports whether an id belongs to the shipped catalog, which callers use to refuse
// editing or deleting entries they do not own.
func IsBuiltIn(id string) bool {
	for _, f := range builtIn {
		if f.ID == id {
			return true
		}
	}
	return false
}

// Catalog merges the shipped feeds with the user's own, built-ins first and user entries
// sorted by name so the picker is stable between loads.
func Catalog(user []config.IPSFeed) []config.IPSFeed {
	out := BuiltIn()
	custom := make([]config.IPSFeed, 0, len(user))
	for _, f := range user {
		if IsBuiltIn(f.ID) {
			continue // a shipped feed is never shadowed by a stored copy
		}
		f.BuiltIn = false
		custom = append(custom, f)
	}
	// Stable: two user feeds can differ only in case, and an unstable sort would reorder them
	// between loads, moving entries under the user's cursor.
	sort.SliceStable(custom, func(i, j int) bool {
		return strings.ToLower(custom[i].Name) < strings.ToLower(custom[j].Name)
	})
	return append(out, custom...)
}

// ByID finds one feed in the merged catalog.
func ByID(user []config.IPSFeed, id string) (config.IPSFeed, bool) {
	for _, f := range Catalog(user) {
		if f.ID == id {
			return f, true
		}
	}
	return config.IPSFeed{}, false
}

// Validate checks a user-supplied feed.
func Validate(f config.IPSFeed) error {
	name := strings.TrimSpace(f.Name)
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("name is at most %d characters, got %d", MaxNameLen, len(name))
	}
	return ValidateURL(f.URL)
}

// ValidateURL checks where a feed is fetched from. Only HTTPS is accepted: the body that
// comes back decides which connections this machine refuses, so whoever can rewrite it in
// flight decides that instead -- both which hostile networks stop being refused and which
// working ones start being. A file:// or ftp:// entry is refused for the duller reason that
// the feed is fetched by a transport speaking neither, so it would never load.
//
// Where the address points is checked again once it resolves, at the fetch itself: a name
// this side has approved can still resolve somewhere it may not reach.
func ValidateURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("a URL to fetch the feed from is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("that is not a URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		// Named on its own because it is the mistake people make, and because the cost is not
		// the download failing but the download succeeding with somebody else's addresses.
		return fmt.Errorf("a feed must be fetched over https://, not http:// -- anyone between you and the server could rewrite a feed served in the clear, and a feed decides which connections this machine refuses")
	default:
		return fmt.Errorf("the URL has to start with https://, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("the URL is missing a host")
	}
	return nil
}

// NameTaken reports whether a name is already in use, ignoring case and ignoring the feed
// being edited. Names are unique because the CLI and the card name a feed by the name the
// user typed, and two feeds called "Work" make that a coin flip.
func NameTaken(user []config.IPSFeed, name, exceptID string) bool {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, f := range Catalog(user) {
		if f.ID == exceptID {
			continue
		}
		if strings.ToLower(strings.TrimSpace(f.Name)) == want {
			return true
		}
	}
	return false
}

// NewID derives a stable, readable id from a feed name, suffixed as needed so it does not
// collide with an existing entry.
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
	// Runs collapse so "Bad  hosts-feed" is bad-hosts-feed rather than bad--hosts-feed: the id
	// shows up in CLI output and in URLs, and a doubled separator reads as a mistake.
	base := strings.Trim(b.String(), "-")
	for strings.Contains(base, "--") {
		base = strings.ReplaceAll(base, "--", "-")
	}
	if base == "" {
		base = "feed"
	}
	id := base
	for i := 2; IsBuiltIn(id) || taken(id); i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	return id
}
