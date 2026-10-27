// SPDX-License-Identifier: MIT

package dnsblock

import "slices"

// Preset is a curated set of shipped lists, offered as one choice. Forty-five switches are
// a research project; six named rungs are a decision, and every rung is a set somebody
// can turn on without reading a single list description.
type Preset struct {
	ID      string
	Name    string
	Summary string
	// Recommended marks the one rung somebody should pick without reading the others. Exactly
	// one rung carries it, which is what makes it an answer rather than another opinion.
	Recommended bool
	// Lists is every shipped id the rung turns on, in catalog order.
	Lists []string
}

// presetStep is one rung stated as what it changes about the rung below it, which is how
// the ladder is read: "High is Medium plus these, with that tier swapped for the wider
// one". Supersedes names lists the rung's own additions already contain -- a broader tier
// from the same publisher -- so the compiled set never carries a list whose every name a
// list beside it also holds.
type presetStep struct {
	id, name, summary string
	recommended       bool
	add               []string
	supersedes        []string
}

// presetSteps is the ladder, lowest first.
//
// Two rules decided every entry, and both come from what a blocklist costs rather than
// from what it claims:
//
//   - A list whose worst case is a blocked advertiser, tracker or malicious host goes in
//     early. Nothing a person does stops working because a malware feed refused a name, so
//     the malware, phishing, botnet and CNAME-cloaking feeds are all on at Minimum.
//   - A list whose worst case is a site not loading arrives late, or never. The category
//     lists (gambling, adult, social media, fake news) are a choice about what to allow
//     rather than protection, and the three lists that break working things -- bad
//     hosters, dynamic DNS, and the DoH/VPN/proxy bypass list, which blocks the endpoints
//     other VPN and proxy software needs -- are in no rung at all. They stay one switch
//     away in the catalog, which is where a deliberate choice belongs. The top rung is the
//     one place breakage is the stated bargain, so the widest tiers live there and nowhere
//     below it.
//
// Breadth comes from independent publishers rather than from one publisher's widest file:
// two lists built from different sources catch different things, while one list's next
// tier up mostly adds what its author was least sure about. That is why the recommended
// rung stacks eight publishers on a middle Hagezi tier instead of reaching for a wider one.
var presetSteps = []presetStep{
	{
		id:      "minimum",
		name:    "Minimum",
		summary: "Everything that costs nothing to block: the light ad and tracking tier, and every malware, phishing and botnet feed.",
		add: []string{
			"hagezi-light",
			"urlhaus-filter",
			"phishing-filter",
			"botnet-filter",
			"cname-cloaking",
		},
	},
	{
		id:      "low",
		name:    "Low",
		summary: "Wider advertising and tracking, plus phone-app ad servers and two more threat feeds.",
		add: []string{
			"hagezi-normal",
			"adaway",
			"phishing-army",
			"dandelion-malware",
		},
		supersedes: []string{"hagezi-light"},
	},
	{
		id:      "medium",
		name:    "Medium",
		summary: "The everyday tier: advertising, tracking, malware and telemetry, with two more curated sources beside it.",
		add: []string{
			"oisd-small",
			"adguard-dns",
			"yoyo",
			"urlhaus",
		},
	},
	{
		id:          "high",
		name:        "High",
		summary:     "The one to pick. Eight independent publishers on a middle Hagezi tier: the big curated sets, the long-standing hosts files, the EasyList family, and fake shops and scam sites.",
		recommended: true,
		add: []string{
			"stevenblack",
			"hagezi-fake",
			"oisd-big",
			"onehosts-lite",
			"someonewhocares",
			"easylist",
			"easyprivacy",
			"fanboy-annoyance",
			"notrack",
		},
		supersedes: []string{"oisd-small"},
	},
	{
		id:      "pro",
		name:    "Pro",
		summary: "Adds the telemetry apps and devices send on their own, Hagezi's threat-intelligence feed, and a very wide merged hosts file.",
		add: []string{
			"hagezi-proplus",
			"hagezi-tif",
			"hblock",
		},
		supersedes: []string{"hagezi-normal"},
	},
	{
		id:      "ultimate",
		name:    "Ultimate",
		summary: "The widest tier of every source that has one. Blocks the most and breaks the most with it, so expect to use the allowlist.",
		add: []string{
			"hagezi-ultimate",
			"onehosts-xtra",
		},
		supersedes: []string{"hagezi-proplus", "onehosts-lite"},
	},
}

// presets is the ladder compiled: each rung is the one below it, minus what this rung's
// own lists supersede, plus what it adds -- in catalog order, so every surface prints the
// set grouped the way the picker shows it.
var presets = buildPresets()

func buildPresets() []Preset {
	order := make(map[string]int, len(builtIn))
	for i, l := range builtIn {
		order[l.ID] = i
	}

	out := make([]Preset, 0, len(presetSteps))
	var carried []string
	for _, step := range presetSteps {
		lists := make([]string, 0, len(carried)+len(step.add))
		for _, id := range carried {
			if !slices.Contains(step.supersedes, id) {
				lists = append(lists, id)
			}
		}
		lists = append(lists, step.add...)
		slices.SortFunc(lists, func(a, b string) int { return order[a] - order[b] })
		carried = lists
		out = append(out, Preset{
			ID:          step.id,
			Name:        step.name,
			Summary:     step.summary,
			Recommended: step.recommended,
			Lists:       lists,
		})
	}
	return out
}

// Presets returns the ladder, lowest first.
func Presets() []Preset {
	out := make([]Preset, len(presets))
	for i, p := range presets {
		p.Lists = slices.Clone(p.Lists)
		out[i] = p
	}
	return out
}

// PresetByID finds one rung. An id nothing carries is reported rather than treated as the
// empty set, which would switch every list off.
func PresetByID(id string) (Preset, bool) {
	for _, p := range presets {
		if p.ID == id {
			return Preset{
				ID: p.ID, Name: p.Name, Summary: p.Summary,
				Recommended: p.Recommended, Lists: slices.Clone(p.Lists),
			}, true
		}
	}
	return Preset{}, false
}

// MatchPreset names the rung a set of shipped lists is, and reports nothing for a set that
// is not one of them. Order does not matter; membership does. Callers pass only the
// shipped ids that are on: a list the user added is theirs to keep, and holding one has
// never meant they left a rung.
func MatchPreset(enabled []string) (string, bool) {
	want := slices.Clone(enabled)
	slices.Sort(want)
	want = slices.Compact(want)
	for _, p := range presets {
		got := slices.Clone(p.Lists)
		slices.Sort(got)
		if slices.Equal(want, got) {
			return p.ID, true
		}
	}
	return "", false
}
