// SPDX-License-Identifier: MIT

package dnsblock

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/sellitus/app-tail/internal/config"
)

// MaxNameLen bounds a list's name. It is shown in the reason a name was blocked, which is
// one line in a CLI and one row on a card.
const MaxNameLen = 64

// DefaultListID is the list a fresh install switches on when blocking is turned on for the
// first time. Hagezi Pro is the tier its author recommends for everyday use: it stops
// advertising, tracking and known-malicious names without the breakage the wider tiers
// accept.
const DefaultListID = config.DefaultDNSBlockList

// UserProvider is the group a list the user added belongs to. Nobody but the user vouches
// for it, which is the distinction the grouping is there to draw.
const UserProvider = "Your lists"

// builtIn is the shipped catalog, grouped by who publishes it and ordered inside a group
// the way a picker wants rather than alphabetically: the general-purpose tiers first, then
// the threat feed, then the topic lists, then the per-vendor telemetry lists.
//
// Every entry declares its format rather than relying on detection. Detection exists for a
// URL a user pastes; a shipped entry whose format is guessed would change meaning the day
// its author changes the file's shape.
var builtIn = []config.Blocklist{
	{ID: "hagezi-light", Name: "Hagezi Light", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-normal", Name: "Hagezi Normal", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: DefaultListID, Name: "Hagezi Pro", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-proplus", Name: "Hagezi Pro++", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-ultimate", Name: "Hagezi Ultimate", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-tif", Name: "Hagezi Threat feed", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-gambling", Name: "Hagezi Gambling", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-fake", Name: "Hagezi Fake sites", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-doh-bypass", Name: "Hagezi DoH and bypass", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-hoster", Name: "Hagezi Bad hosters", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-dyndns", Name: "Hagezi Dynamic DNS", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-apple", Name: "Hagezi Apple telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.apple.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-microsoft", Name: "Hagezi Windows and Office telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-amazon", Name: "Hagezi Amazon telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.amazon.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-samsung", Name: "Hagezi Samsung telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-xiaomi", Name: "Hagezi Xiaomi telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-huawei", Name: "Hagezi Huawei telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.huawei.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-oppo", Name: "Hagezi Oppo and Realme telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.oppo-realme.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "hagezi-native-tiktok", Name: "Hagezi TikTok telemetry", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "stevenblack", Name: "StevenBlack Unified", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Format: string(FormatHosts), BuiltIn: true},
	{ID: "stevenblack-fakenews", Name: "StevenBlack Fake news", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts", Format: string(FormatHosts), BuiltIn: true},
	{ID: "stevenblack-gambling", Name: "StevenBlack Gambling", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts", Format: string(FormatHosts), BuiltIn: true},
	{ID: "stevenblack-porn", Name: "StevenBlack Adult", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts", Format: string(FormatHosts), BuiltIn: true},
	{ID: "stevenblack-social", Name: "StevenBlack Social media", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts", Format: string(FormatHosts), BuiltIn: true},
	{ID: "oisd-small", Name: "OISD Small", URL: "https://raw.githubusercontent.com/sjhgvr/oisd/main/abp_small.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "oisd-big", Name: "OISD Big", URL: "https://raw.githubusercontent.com/sjhgvr/oisd/main/abp_big.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "oisd-nsfw", Name: "OISD Adult", URL: "https://raw.githubusercontent.com/sjhgvr/oisd/main/abp_nsfw.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "onehosts-lite", Name: "1Hosts Lite", URL: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "onehosts-xtra", Name: "1Hosts Xtra", URL: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/adblock.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "adguard-dns", Name: "AdGuard DNS filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "urlhaus-filter", Name: "URLhaus filter", URL: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "phishing-filter", Name: "Phishing filter", URL: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "botnet-filter", Name: "Botnet command-and-control filter", URL: "https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "phishing-army", Name: "Phishing Army Extended", URL: "https://phishing.army/download/phishing_army_blocklist_extended.txt", Format: string(FormatHosts), BuiltIn: true},
	{ID: "urlhaus", Name: "URLhaus malware", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", Format: string(FormatHosts), BuiltIn: true},
	{ID: "yoyo", Name: "Peter Lowe's ad servers", URL: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", Format: string(FormatHosts), BuiltIn: true},
	{ID: "someonewhocares", Name: "Dan Pollock's hosts", URL: "https://someonewhocares.org/hosts/zero/hosts", Format: string(FormatHosts), BuiltIn: true},
	{ID: "adaway", Name: "AdAway mobile ads", URL: "https://adaway.org/hosts.txt", Format: string(FormatHosts), BuiltIn: true},
	{ID: "cname-cloaking", Name: "CNAME-cloaked trackers", URL: "https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains", Format: string(FormatHosts), BuiltIn: true},
	{ID: "dandelion-malware", Name: "Dandelion Sprout Anti-Malware", URL: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", Format: string(FormatHosts), BuiltIn: true},
	{ID: "easylist", Name: "EasyList", URL: "https://easylist.to/easylist/easylist.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "easyprivacy", Name: "EasyPrivacy", URL: "https://easylist.to/easylist/easyprivacy.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "fanboy-annoyance", Name: "Fanboy's Annoyance", URL: "https://easylist.to/easylist/fanboy-annoyance.txt", Format: string(FormatABP), BuiltIn: true},
	{ID: "notrack", Name: "NoTrack trackers", URL: "https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/trackers.hosts", Format: string(FormatHosts), BuiltIn: true},
	{ID: "hblock", Name: "hBlock", URL: "https://hblock.molinero.dev/hosts", Format: string(FormatHosts), BuiltIn: true},
}

// providers names who publishes each shipped list. A catalog this size is read as "which
// Hagezi tier do I want" rather than as forty unrelated files, so every surface that lists
// them groups by this.
var providers = map[string]string{
	"hagezi-light":            "Hagezi",
	"hagezi-normal":           "Hagezi",
	DefaultListID:             "Hagezi",
	"hagezi-proplus":          "Hagezi",
	"hagezi-ultimate":         "Hagezi",
	"hagezi-tif":              "Hagezi",
	"hagezi-gambling":         "Hagezi",
	"hagezi-fake":             "Hagezi",
	"hagezi-doh-bypass":       "Hagezi",
	"hagezi-hoster":           "Hagezi",
	"hagezi-dyndns":           "Hagezi",
	"hagezi-native-apple":     "Hagezi",
	"hagezi-native-microsoft": "Hagezi",
	"hagezi-native-amazon":    "Hagezi",
	"hagezi-native-samsung":   "Hagezi",
	"hagezi-native-xiaomi":    "Hagezi",
	"hagezi-native-huawei":    "Hagezi",
	"hagezi-native-oppo":      "Hagezi",
	"hagezi-native-tiktok":    "Hagezi",
	"stevenblack":             "StevenBlack",
	"stevenblack-fakenews":    "StevenBlack",
	"stevenblack-gambling":    "StevenBlack",
	"stevenblack-porn":        "StevenBlack",
	"stevenblack-social":      "StevenBlack",
	"oisd-small":              "OISD",
	"oisd-big":                "OISD",
	"oisd-nsfw":               "OISD",
	"onehosts-lite":           "1Hosts",
	"onehosts-xtra":           "1Hosts",
	"adguard-dns":             "AdGuard",
	"urlhaus-filter":          "malware-filter",
	"phishing-filter":         "malware-filter",
	"botnet-filter":           "malware-filter",
	"phishing-army":           "Phishing Army",
	"urlhaus":                 "abuse.ch",
	"yoyo":                    "Peter Lowe",
	"someonewhocares":         "Dan Pollock",
	"adaway":                  "AdAway",
	"cname-cloaking":          "NextDNS",
	"dandelion-malware":       "Dandelion Sprout",
	"easylist":                "EasyList",
	"easyprivacy":             "EasyList",
	"fanboy-annoyance":        "EasyList",
	"notrack":                 "NoTrack",
	"hblock":                  "hBlock",
}

// Provider names who publishes a list.
func Provider(l config.Blocklist) string {
	if p, ok := providers[l.ID]; ok {
		return p
	}
	return UserProvider
}

// notes carries what a shipped list is for, and where it is known to disappoint. The card
// shows it beside the switch, because "why is this one blocking nothing" and "why did this
// one break a site" are the two questions a catalog this size creates.
var notes = map[string]string{
	"hagezi-light":            "Advertising and tracking only. The tier to pick when something broke on a wider one.",
	"hagezi-normal":           "Advertising, tracking and known-malicious names.",
	DefaultListID:             "The everyday tier: advertising, tracking, malware and telemetry.",
	"hagezi-proplus":          "Pro plus native app telemetry. Blocks more, breaks more.",
	"hagezi-ultimate":         "The widest tier. Expect to need the allowlist.",
	"hagezi-tif":              "Names seen hosting malware and phishing. Aggressive by design.",
	"hagezi-gambling":         "Gambling sites. The largest list in the catalog by a wide margin.",
	"hagezi-fake":             "Fake shops, fake support and scam sites.",
	"hagezi-doh-bypass":       "Public DoH, VPN and proxy endpoints, which is how a device on this network gets around the blocking.",
	"hagezi-hoster":           "Hosters that answer abuse reports with silence.",
	"hagezi-dyndns":           "Dynamic-DNS providers, heavily used by malware for command and control. Blocks legitimate home servers on the same providers.",
	"hagezi-native-apple":     "Telemetry Apple devices send on their own. Blocking it can delay software updates.",
	"hagezi-native-microsoft": "Telemetry Windows and Office send on their own.",
	"hagezi-native-amazon":    "Telemetry Amazon devices and apps send on their own.",
	"hagezi-native-samsung":   "Telemetry Samsung devices send on their own.",
	"hagezi-native-xiaomi":    "Telemetry Xiaomi devices send on their own.",
	"hagezi-native-huawei":    "Telemetry Huawei devices send on their own.",
	"hagezi-native-oppo":      "Telemetry Oppo and Realme devices send on their own.",
	"hagezi-native-tiktok":    "TikTok's own tracking endpoints. Leaves the app itself reachable.",
	"stevenblack":             "The long-standing unified hosts file: advertising and malware.",
	"stevenblack-fakenews":    "Sites carrying fabricated news, on top of the unified list.",
	"stevenblack-gambling":    "Gambling sites, on top of the unified list.",
	"stevenblack-porn":        "Adult sites, on top of the unified list.",
	"stevenblack-social":      "Social networks, on top of the unified list. Blocks the sites themselves, not only their trackers.",
	"oisd-small":              "Advertising and tracking, curated against breakage.",
	"oisd-big":                "The wider OISD tier, adding malware and phishing.",
	"oisd-nsfw":               "Adult sites. Stands on its own; the other OISD tiers do not carry it.",
	"onehosts-lite":           "Advertising and tracking, tuned to leave sites working.",
	"onehosts-xtra":           "The wide 1Hosts tier. Blocks a great deal and breaks a fair amount with it.",
	"urlhaus-filter":          "Domains extracted from the full abuse.ch malware-URL feed.",
	"phishing-filter":         "Phishing domains, rebuilt several times a day.",
	"botnet-filter":           "Domains seen serving botnet command and control.",
	"phishing-army":           "Phishing domains from Phishing Initiative and CERT feeds.",
	"urlhaus":                 "The hosts export abuse.ch publishes itself, which is a small slice of what URLhaus knows.",
	"yoyo":                    "Ad servers only, curated slowly and conservatively for many years.",
	"someonewhocares":         "A hand-curated hosts file: advertising, tracking and hostile sites.",
	"adaway":                  "Ad servers used by phone apps rather than by web pages.",
	"cname-cloaking":          "The alias names trackers hide behind to look first-party. Short, and meant to sit beside a wider list rather than alone.",
	"dandelion-malware":       "Malware and scam domains, maintained by hand at a fast pace.",
	"adguard-dns":             "AdGuard's filter written for resolvers rather than browsers.",
	"easylist":                "A browser filter list. Most of its rules name URL paths or page elements, which no resolver can act on, so only its domain rules survive here and the skipped count is large by nature.",
	"easyprivacy":             "EasyList's tracking half: analytics, web bugs and beacons. A browser filter list too, so most of its rules are skipped here and the domain rules are what remain.",
	"fanboy-annoyance":        "Pop-ups, cookie banners and in-page social widgets. Written for a browser, so the handful of domain rules it carries is all a resolver can use.",
	"notrack":                 "Tracking and analytics domains, curated separately from every other source here, which is what makes it worth carrying beside them.",
	"hblock":                  "A very wide merge of many hosts files. The largest list in the catalog outside the category lists, and wide enough to need the allowlist.",
}

// Note reports what a shipped list is for. A user list has none: its description is the
// name the user gave it.
func Note(id string) string { return notes[id] }

// BuiltIn returns a copy of the shipped catalog.
func BuiltIn() []config.Blocklist {
	return append([]config.Blocklist(nil), builtIn...)
}

// IsBuiltIn reports whether an id belongs to the shipped catalog, which callers use to
// refuse editing or deleting entries they do not own.
func IsBuiltIn(id string) bool {
	for _, l := range builtIn {
		if l.ID == id {
			return true
		}
	}
	return false
}

// Catalog merges the shipped lists with the user's own, built-ins first and user entries
// sorted by name so the picker is stable between loads.
func Catalog(user []config.Blocklist) []config.Blocklist {
	out := BuiltIn()
	custom := make([]config.Blocklist, 0, len(user))
	for _, l := range user {
		if IsBuiltIn(l.ID) {
			continue // a shipped list is never shadowed by a stored copy
		}
		l.BuiltIn = false
		custom = append(custom, l)
	}
	// Stable: two user lists can differ only in case, and an unstable sort would reorder
	// them between loads, moving entries under the user's cursor.
	sort.SliceStable(custom, func(i, j int) bool {
		return strings.ToLower(custom[i].Name) < strings.ToLower(custom[j].Name)
	})
	return append(out, custom...)
}

// ByID finds one list in the merged catalog.
func ByID(user []config.Blocklist, id string) (config.Blocklist, bool) {
	for _, l := range Catalog(user) {
		if l.ID == id {
			return l, true
		}
	}
	return config.Blocklist{}, false
}

// Validate checks a user-supplied list.
func Validate(l config.Blocklist) error {
	name := strings.TrimSpace(l.Name)
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("name is at most %d characters, got %d", MaxNameLen, len(name))
	}
	if err := ValidateFormat(l.Format); err != nil {
		return err
	}
	return ValidateURL(l.URL)
}

// ValidateURL checks where a list is fetched from. Only HTTPS is accepted: the body that
// comes back decides what the whole machine stops resolving, so whoever can rewrite it in
// flight decides that instead -- both which threat domains stop being blocked and which
// working ones start being. A file:// or ftp:// entry is refused for the duller reason that
// the list is fetched by a transport speaking neither, so it would never load.
//
// Where the address points is checked again once it resolves, at the fetch itself: a name
// this side has approved can still resolve somewhere it may not reach.
func ValidateURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("a URL to fetch the list from is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("that is not a URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		// Named on its own because it is the mistake people make, and because the cost is
		// not the download failing but the download succeeding with somebody else's rules.
		return fmt.Errorf("a blocklist must be fetched over https://, not http:// -- anyone between you and the server could rewrite a list served in the clear, and a blocklist decides what this machine can reach")
	default:
		return fmt.Errorf("the URL has to start with https://, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("the URL is missing a host")
	}
	return nil
}

// ValidateFormat checks a declared format, treating an empty one as auto so a list added
// without an opinion is a list that sniffs.
func ValidateFormat(f string) error {
	switch Format(strings.TrimSpace(strings.ToLower(f))) {
	case "", FormatAuto, FormatHosts, FormatABP:
		return nil
	}
	return fmt.Errorf("unknown list format %q; use one of auto, hosts, abp", f)
}

// NameTaken reports whether a name is already in use, ignoring case and ignoring the list
// being edited. Names are unique because the CLI and the card name a list by the name the
// user typed, and two lists called "Work" make that a coin flip.
func NameTaken(user []config.Blocklist, name, exceptID string) bool {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, l := range Catalog(user) {
		if l.ID == exceptID {
			continue
		}
		if strings.ToLower(strings.TrimSpace(l.Name)) == want {
			return true
		}
	}
	return false
}

// NewID derives a stable, readable id from a list name, suffixed as needed so it does not
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
	// Runs collapse so "Ad  block-list" is ad-block-list rather than ad--block-list: the id
	// shows up in CLI output and in URLs, and a doubled separator reads as a mistake.
	base := strings.Trim(b.String(), "-")
	for strings.Contains(base, "--") {
		base = strings.ReplaceAll(base, "--", "-")
	}
	if base == "" {
		base = "list"
	}
	id := base
	for i := 2; IsBuiltIn(id) || taken(id); i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	return id
}
