// SPDX-License-Identifier: MIT

package ipsfeed

import "slices"

// Preset is a curated set of shipped feeds, offered as one choice. Seventeen switches are a
// research project; six named rungs are a decision, and every rung is a set somebody can turn
// on without reading a single feed description.
type Preset struct {
	ID      string
	Name    string
	Summary string
	// Recommended marks the one rung somebody should pick without reading the others. Exactly
	// one rung carries it, which is what makes it an answer rather than another opinion.
	Recommended bool
	// Feeds is every shipped id the rung turns on, in catalog order.
	Feeds []string
}

// presetStep is one rung stated as what it changes about the rung below it, which is how the
// ladder is read: "Pro is High plus these, with that tier swapped for the wider one".
// Supersedes names feeds the rung's own additions already contain, so the compiled set never
// carries a feed whose every address a feed beside it also holds.
type presetStep struct {
	id, name, summary string
	recommended       bool
	add               []string
	supersedes        []string
}

// presetSteps is the ladder, lowest first.
//
// What ordered it is what a wrong entry costs here, which is not what a wrong entry costs a
// blocklist: a name blocked in error means a page does not load, while an address refused in
// error means a connection is reset, and the two are not the same complaint. So the ordering
// signal is how long an entry stays true rather than how much each feed holds:
//
//   - Networks criminals control outright, and the servers infected machines talk to, are
//     first. An address there is not somebody else's tomorrow, and refusing it costs nothing
//     that was working.
//   - Address reputation -- what attacked something recently -- comes next, narrowest window
//     first. These age out: an address that attacked somebody last month may be a home
//     connection this month, so the wider the window, the higher the rung.
//   - Wide merged lists of individual hosts are last. They hold the most and they carry the
//     most addresses somebody else has since been given, which is the breakage the top rung
//     names as its bargain.
//
// The Tor exit list is in no rung at all. Nothing on it is malicious -- it is there for a
// machine that has decided not to carry Tor traffic, and switching it on in the outbound
// direction stops Tor working from this machine. That is a deliberate choice about what to
// allow rather than protection, so it stays one switch away in the catalog, which is where a
// deliberate choice belongs.
var presetSteps = []presetStep{
	{
		id:      "minimum",
		name:    "Minimum",
		summary: "The addresses nobody argues about: networks with no legitimate traffic at all, networks run by criminals outright, and the servers infected machines report to.",
		add: []string{
			DefaultFeedID,
			"spamhaus-drop",
			"feodo",
		},
	},
	{
		id:      "low",
		name:    "Low",
		summary: "Adds the networks leased to the same operators through somebody else, today's busiest attack sources, and hosts known to be compromised.",
		add: []string{
			"spamhaus-edrop",
			"dshield",
			"emerging-compromised",
		},
	},
	{
		id:      "medium",
		name:    "Medium",
		summary: "Adds what has been seen attacking something in the last two days, and addresses scored badly across a wide sensor network.",
		add: []string{
			"firehol-level2",
			"cins-badguys",
		},
	},
	{
		id:          "high",
		name:        "High",
		summary:     "The one to pick. Five independent sources of recent attack traffic beside the criminal networks, including the addresses several public feeds agree on.",
		recommended: true,
		add: []string{
			"alienvault",
			"binarydefense",
			"ipsum-5",
		},
	},
	{
		id:      "pro",
		name:    "Pro",
		summary: "Widens the window from two days to a month, and adds continuously refreshed attackers and the addresses seen going after web servers.",
		add: []string{
			"firehol-level3",
			"firehol-webserver",
			"greensnow",
		},
	},
	{
		id:      "ultimate",
		name:    "Ultimate",
		summary: "Every source that has a wider tier, on its widest. Millions of individual hosts, so expect a connection you wanted to be refused and to name it as allowed.",
		add: []string{
			"ipsum-3",
			"blocklist-de",
		},
		// Level 3 is every address on at least three of the feeds IPsum merges, so it already
		// holds every address level 5 does.
		supersedes: []string{"ipsum-5"},
	},
}

// presets is the ladder compiled: each rung is the one below it, minus what this rung's own
// feeds supersede, plus what it adds -- in catalog order, so every surface prints the set
// grouped the way the picker shows it.
var presets = buildPresets()

func buildPresets() []Preset {
	order := make(map[string]int, len(builtIn))
	for i, f := range builtIn {
		order[f.ID] = i
	}

	out := make([]Preset, 0, len(presetSteps))
	var carried []string
	for _, step := range presetSteps {
		feeds := make([]string, 0, len(carried)+len(step.add))
		for _, id := range carried {
			if !slices.Contains(step.supersedes, id) {
				feeds = append(feeds, id)
			}
		}
		feeds = append(feeds, step.add...)
		slices.SortFunc(feeds, func(a, b string) int { return order[a] - order[b] })
		carried = feeds
		out = append(out, Preset{
			ID:          step.id,
			Name:        step.name,
			Summary:     step.summary,
			Recommended: step.recommended,
			Feeds:       feeds,
		})
	}
	return out
}

// Presets returns the ladder, lowest first.
func Presets() []Preset {
	out := make([]Preset, len(presets))
	for i, p := range presets {
		p.Feeds = slices.Clone(p.Feeds)
		out[i] = p
	}
	return out
}

// PresetByID finds one rung. An id nothing carries is reported rather than treated as the
// empty set, which would switch every feed off.
func PresetByID(id string) (Preset, bool) {
	for _, p := range presets {
		if p.ID == id {
			return Preset{
				ID: p.ID, Name: p.Name, Summary: p.Summary,
				Recommended: p.Recommended, Feeds: slices.Clone(p.Feeds),
			}, true
		}
	}
	return Preset{}, false
}

// MatchPreset names the rung a set of shipped feeds is, and reports nothing for a set that is
// not one of them. Order does not matter; membership does. Callers pass only the shipped ids
// that are on: a feed the user added is theirs to keep, and holding one has never meant they
// left a rung.
func MatchPreset(enabled []string) (string, bool) {
	want := slices.Clone(enabled)
	slices.Sort(want)
	want = slices.Compact(want)
	for _, p := range presets {
		got := slices.Clone(p.Feeds)
		slices.Sort(got)
		if slices.Equal(want, got) {
			return p.ID, true
		}
	}
	return "", false
}
