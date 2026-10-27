// SPDX-License-Identifier: MIT

package cli

// What the blocking commands print, and what they write when they change something.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
)

// blockingView is a machine with blocking on, one shipped list downloaded and one of the
// user's own switched off -- the state every one of these commands is read against.
func blockingView() httpapi.DNSBlockView {
	return httpapi.DNSBlockView{
		Enabled: true, Own: true, System: true,
		Answer:       "nxdomain",
		Rules:        152403,
		Blocked:      87,
		RefreshHours: 24,
		NextRefresh:  "2026-09-01T09:00:00Z",
		Allow:        []string{"ads.example.com"},
		Preset:       "medium",
		Presets: []httpapi.DNSBlockPresetView{
			{ID: "minimum", Name: "Minimum", Summary: "Everything that costs nothing to block.", Lists: []string{"hagezi-light"}},
			{ID: "medium", Name: "Medium", Summary: "The everyday tier.", Lists: []string{"hagezi-pro"}},
			{ID: "high", Name: "High", Summary: "Adds native telemetry.", Recommended: true, Lists: []string{"hagezi-proplus"}},
		},
		Lists: []httpapi.DNSBlockListView{
			{
				ID: "hagezi-pro", Provider: "Hagezi", Name: "Hagezi Pro",
				URL:     "https://lists.example/pro.txt",
				BuiltIn: true, Enabled: true, Rules: 152403, Skipped: 12,
				UpdatedAt: "2026-08-31T09:00:00Z",
			},
			{
				ID: "work", Provider: "Your lists", Name: "Work list",
				URL: "https://lists.example/work.txt", Format: "hosts",
			},
		},
		Capability: httpapi.Capability{Available: true},
	}
}

// blockAgent serves the blocking routes against one view, and moves that view the way the
// agent's own writes move it. A fake that ignored the settings patch would let every
// command that reads its own write back agree with itself.
func blockAgent(t *testing.T, view httpapi.DNSBlockView) (map[string]http.HandlerFunc, func() httpapi.DNSBlockView) {
	t.Helper()
	var mu sync.Mutex

	routes := map[string]http.HandlerFunc{
		"GET /api/dns/block": func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			writeJSONResponse(t, w, http.StatusOK, view)
		},
		"POST /api/dns/block/refresh": func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			for i := range view.Lists {
				view.Lists[i].UpdatedAt = "2026-08-31T12:00:00Z"
			}
			writeJSONResponse(t, w, http.StatusOK, view)
		},
		"POST /api/dns/block/pause": func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Minutes int `json:"minutes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode the pause request: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			paused := view
			paused.PausedUntil = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC).
				Add(time.Duration(body.Minutes) * time.Minute).Format(time.RFC3339)
			writeJSONResponse(t, w, http.StatusOK, paused)
		},
		"POST /api/dns/block/preset": func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Preset string `json:"preset"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode the preset request: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, p := range view.Presets {
				if p.ID != body.Preset {
					continue
				}
				view.Preset = p.ID
				for i, l := range view.Lists {
					view.Lists[i].Enabled = slices.Contains(p.Lists, l.ID)
				}
				writeJSONResponse(t, w, http.StatusOK, view)
				return
			}
			writeJSONResponse(t, w, http.StatusBadRequest,
				map[string]string{"error": body.Preset + " is not one of the levels"})
		},
		"POST /api/dns/block/resume": func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			writeJSONResponse(t, w, http.StatusOK, view)
		},
		"GET /api/dns/block/check": func(w http.ResponseWriter, r *http.Request) {
			name := r.URL.Query().Get("name")
			result := httpapi.DNSBlockCheckView{
				Name: name, Reason: "no list carries it",
			}
			if name == "doubleclick.net" {
				result.Blocked, result.List, result.Reason = true, "Hagezi Pro", "on Hagezi Pro"
			}
			writeJSONResponse(t, w, http.StatusOK, result)
		},
		"POST /api/dns/block/lists": func(w http.ResponseWriter, r *http.Request) {
			var added config.Blocklist
			if err := json.NewDecoder(r.Body).Decode(&added); err != nil {
				t.Errorf("decode the created list: %v", err)
			}
			added.ID = "custom"
			mu.Lock()
			view.Lists = append(view.Lists, httpapi.DNSBlockListView{
				ID: added.ID, Name: added.Name, URL: added.URL, Format: added.Format,
			})
			mu.Unlock()
			writeJSONResponse(t, w, http.StatusCreated, added)
		},
		"DELETE /api/dns/block/lists/{id}": func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			mu.Lock()
			kept := make([]httpapi.DNSBlockListView, 0, len(view.Lists))
			for _, l := range view.Lists {
				if l.ID != id {
					kept = append(kept, l)
				}
			}
			view.Lists = kept
			mu.Unlock()
			writeJSONResponse(t, w, http.StatusNoContent, nil)
		},
		"PUT /api/settings": func(w http.ResponseWriter, r *http.Request) {
			var patch struct {
				Enabled *bool     `json:"dnsBlock.enabled"`
				Own     *bool     `json:"dnsBlock.own"`
				System  *bool     `json:"dnsBlock.system"`
				Lists   *[]string `json:"dnsBlock.lists"`
				Allow   *[]string `json:"dnsBlock.allow"`
				Deny    *[]string `json:"dnsBlock.deny"`
			}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Errorf("decode the settings patch: %v", err)
			}
			mu.Lock()
			if patch.Enabled != nil {
				view.Enabled = *patch.Enabled
			}
			if patch.Own != nil {
				view.Own = *patch.Own
			}
			if patch.System != nil {
				view.System = *patch.System
			}
			if patch.Lists != nil {
				for i, l := range view.Lists {
					view.Lists[i].Enabled = false
					for _, on := range *patch.Lists {
						if on == l.ID {
							view.Lists[i].Enabled = true
						}
					}
				}
			}
			if patch.Allow != nil {
				view.Allow = *patch.Allow
			}
			if patch.Deny != nil {
				view.Deny = *patch.Deny
			}
			mu.Unlock()
			writeJSONResponse(t, w, http.StatusOK, map[string]any{})
		},
	}

	return routes, func() httpapi.DNSBlockView {
		mu.Lock()
		defer mu.Unlock()
		return view
	}
}

// blockArgs puts --config where Go's flag package can still see it: after the last
// subcommand word, ahead of the first positional.
func blockArgs(h *harness, sub []string, rest ...string) []string {
	full := append([]string{"dns", "block"}, sub...)
	full = append(full, h.cfg()...)
	return append(full, rest...)
}

// settingsPatches returns every settings write the command made, decoded.
func settingsPatches(t *testing.T, h *harness) []map[string]json.RawMessage {
	t.Helper()
	var patches []map[string]json.RawMessage
	for _, req := range h.recorded() {
		if req.Method != http.MethodPut || req.Path != "/api/settings" {
			continue
		}
		var patch map[string]json.RawMessage
		if err := json.Unmarshal([]byte(req.Body), &patch); err != nil {
			t.Fatalf("parse the settings patch %q: %v", req.Body, err)
		}
		patches = append(patches, patch)
	}
	return patches
}

// The two switches reach different things, and a status line saying only "on" leaves a
// user with a filtered browser and an unfiltered proxy no way to tell which they have.
func TestDNSBlockReportsTheTwoSwitchesApart(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, nil), h.env()); err != nil {
		t.Fatalf("dns block: %v", err)
	}
	out := h.out()
	for _, want := range []string{
		"app-tail's own resolution", "This machine's resolution", "nxdomain", "152403", "87",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dns block output is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Hagezi Pro") {
		t.Errorf("dns block does not name the list that is on:\n%s", out)
	}
	if strings.Contains(out, "Work list") {
		t.Errorf("dns block listed a switched-off list among the ones in force:\n%s", out)
	}
	if !strings.Contains(out, "ads.example.com") {
		t.Errorf("dns block does not show the names that are never blocked:\n%s", out)
	}
}

// A stale copy that is still blocking is the state worth reporting: the list works, and
// the reason it has stopped being updated is the only thing that says so.
func TestDNSBlockListShowsEveryListAndWhyOneFailed(t *testing.T) {
	view := blockingView()
	view.Lists[1].Error = "lists.example could not be reached"
	routes, _ := blockAgent(t, view)
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"list"}), h.env()); err != nil {
		t.Fatalf("dns block list: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "Hagezi Pro") || !strings.Contains(out, "Work list") {
		t.Errorf("dns block list leaves out a list:\n%s", out)
	}
	if !strings.Contains(out, "12") {
		t.Errorf("dns block list does not say how many rules were skipped:\n%s", out)
	}
	if !strings.Contains(h.stderr.String(), "could not be reached") {
		t.Errorf("the download failure is not reported:\n%s", h.stderr.String())
	}
}

// Sixteen shipped lists are read as "which of this author's tiers do I want", so they are
// printed grouped by who publishes them: one provider's lists together, and the provider
// named on the first of its rows rather than repeated down the table.
func TestDNSBlockListGroupsTheListsByWhoPublishesThem(t *testing.T) {
	view := blockingView()
	view.Lists = []httpapi.DNSBlockListView{
		{ID: "hagezi-pro", Provider: "Hagezi", Name: "Hagezi Pro", BuiltIn: true, Enabled: true},
		{ID: "work", Provider: "Your lists", Name: "Work list"},
		{ID: "hagezi-tif", Provider: "Hagezi", Name: "Hagezi Threat feed", BuiltIn: true},
	}
	routes, _ := blockAgent(t, view)
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"list"}), h.env()); err != nil {
		t.Fatalf("dns block list: %v", err)
	}
	out := h.out()

	if !strings.Contains(out, "PROVIDER") {
		t.Errorf("dns block list has no provider column:\n%s", out)
	}
	pro, tif, work := strings.Index(out, "hagezi-pro"), strings.Index(out, "hagezi-tif"), strings.Index(out, "work")
	if pro < 0 || tif < 0 || work < 0 {
		t.Fatalf("dns block list leaves out a list:\n%s", out)
	}
	if !(pro < tif && tif < work) {
		t.Errorf("the two Hagezi lists are not printed together:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "hagezi-tif") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			t.Errorf("the second row of a provider's run repeats its name:\n%s", line)
		}
	}
	if strings.Count(out, "Your lists") != 1 {
		t.Errorf("the group a user's own lists share is not named exactly once:\n%s", out)
	}
}

// Turning blocking on with neither half on is the state people report as broken, so the
// switch that turns it on turns on both halves in the same write.
func TestDNSBlockOnTurnsOnBothHalvesInOneWrite(t *testing.T) {
	view := blockingView()
	view.Enabled, view.Own, view.System = false, false, false
	routes, state := blockAgent(t, view)
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"on"}), h.env()); err != nil {
		t.Fatalf("dns block on: %v", err)
	}

	patches := settingsPatches(t, h)
	if len(patches) != 1 {
		t.Fatalf("dns block on took %d writes, want one", len(patches))
	}
	for _, key := range []string{"dnsBlock.enabled", "dnsBlock.own", "dnsBlock.system"} {
		if string(patches[0][key]) != "true" {
			t.Errorf("%s = %s, want blocking on for both halves", key, patches[0][key])
		}
	}
	if got := state(); !got.Enabled || !got.Own || !got.System {
		t.Errorf("the agent holds enabled=%v own=%v system=%v after the switch", got.Enabled, got.Own, got.System)
	}
}

// Off names the module and nothing else: the two halves are the module's own settings,
// and naming one in the write that switches the module off names a setting that write has
// just put out of reach.
func TestDNSBlockOffNamesOnlyTheModule(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"off"}), h.env()); err != nil {
		t.Fatalf("dns block off: %v", err)
	}

	patches := settingsPatches(t, h)
	if len(patches) != 1 {
		t.Fatalf("dns block off took %d writes, want one", len(patches))
	}
	if string(patches[0]["dnsBlock.enabled"]) != "false" {
		t.Errorf("dnsBlock.enabled = %s, want blocking switched off", patches[0]["dnsBlock.enabled"])
	}
	if _, named := patches[0]["dnsBlock.own"]; named {
		t.Errorf("the write names a setting the same write makes unavailable: %v", patches[0])
	}
}

// Adding a list is two calls that have to agree: the list is stored, then switched on by
// id. A list added and left off is the outcome a user reads as the command not working.
func TestDNSBlockAddStoresTheListAndSwitchesItOn(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"add"},
		"--name", "Custom", "--url", "https://lists.example/custom.txt", "--format", "hosts"), h.env())
	if err != nil {
		t.Fatalf("dns block add: %v", err)
	}

	patches := settingsPatches(t, h)
	if len(patches) != 1 {
		t.Fatalf("dns block add took %d settings writes, want one", len(patches))
	}
	var wanted []string
	if err := json.Unmarshal(patches[0]["dnsBlock.lists"], &wanted); err != nil {
		t.Fatalf("parse dnsBlock.lists %s: %v", patches[0]["dnsBlock.lists"], err)
	}
	if !slices.Contains(wanted, "custom") || !slices.Contains(wanted, "hagezi-pro") {
		t.Errorf("dnsBlock.lists = %v, want the new list on beside the ones already on", wanted)
	}
	if got := state(); len(got.Lists) != 3 {
		t.Errorf("the agent holds %d lists, want the added one stored", len(got.Lists))
	}
}

// A list added with --enable=false is stored and left off, and the command has to say how
// to switch it on or the user is left looking at a list that blocks nothing.
func TestDNSBlockAddCanLeaveTheListOffAndSaysHowToSwitchItOn(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"add"},
		"--name", "Custom", "--url", "https://lists.example/custom.txt", "--enable=false"), h.env())
	if err != nil {
		t.Fatalf("dns block add: %v", err)
	}

	if patches := settingsPatches(t, h); len(patches) != 0 {
		t.Errorf("a list added switched off was switched on anyway: %v", patches)
	}
	if !strings.Contains(h.out(), "dns block enable custom") {
		t.Errorf("dns block add never says how to switch the list on:\n%s", h.out())
	}
}

func TestDNSBlockAddRefusesAListWithNothingToDownload(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"add"}, "--name", "Custom"), h.env())

	if err == nil {
		t.Fatal("a list with no address was accepted")
	}
	if !strings.Contains(err.Error(), "--url") {
		t.Errorf("the refusal reads %q, which does not say what is missing", err)
	}
}

// Switching one list must not switch the others: the setting is the whole list, so the
// command reads what is on before it writes.
func TestDNSBlockEnableLeavesTheOtherListsWhereTheyWere(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"enable"}, "work"), h.env()); err != nil {
		t.Fatalf("dns block enable work: %v", err)
	}

	got := state()
	on := map[string]bool{}
	for _, l := range got.Lists {
		on[l.ID] = l.Enabled
	}
	if !on["work"] || !on["hagezi-pro"] {
		t.Errorf("lists on = %v, want the named list switched on and the others untouched", on)
	}
}

func TestDNSBlockDisableTakesOneListOffAndKeepsTheRest(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"disable"}, "Hagezi Pro"), h.env()); err != nil {
		t.Fatalf("dns block disable: %v", err)
	}

	for _, l := range state().Lists {
		if l.ID == "hagezi-pro" && l.Enabled {
			t.Error("the named list is still on after being disabled")
		}
	}
}

// A shipped list is not the user's to remove, and the refusal has to name what to do
// instead or it reads as the command being broken.
func TestDNSBlockRemoveRefusesAListThatShipsWithAppTail(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"rm"}, "hagezi-pro"), h.env())

	if err == nil {
		t.Fatal("a shipped list was removed")
	}
	if !strings.Contains(err.Error(), "switch it off instead") {
		t.Errorf("the refusal reads %q, which does not say what to do instead", err)
	}
	if len(state().Lists) != 2 {
		t.Error("a shipped list was deleted by a refused command")
	}
}

func TestDNSBlockRemoveDeletesOneOfTheUsersOwnLists(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"rm"}, "Work list"), h.env()); err != nil {
		t.Fatalf("dns block rm: %v", err)
	}

	got := state()
	if len(got.Lists) != 1 || got.Lists[0].ID != "hagezi-pro" {
		t.Errorf("lists = %+v, want the named list removed and nothing else", got.Lists)
	}
}

// Refreshing prints what the download produced, because a command that downloads and
// reports nothing gives a user no way to tell a working list from a failing one.
func TestDNSBlockRefreshDownloadsAndPrintsWhatCameBack(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"refresh"}), h.env()); err != nil {
		t.Fatalf("dns block refresh: %v", err)
	}

	refreshes := 0
	for _, req := range h.recorded() {
		if req.Method == http.MethodPost && req.Path == "/api/dns/block/refresh" {
			refreshes++
		}
	}
	if refreshes != 1 {
		t.Errorf("the lists were downloaded %d times, want exactly once", refreshes)
	}
	if !strings.Contains(h.out(), "152403") {
		t.Errorf("dns block refresh prints nothing about what is in force:\n%s", h.out())
	}
}

// A pause is typed the way a duration is written, and anything under a minute would be a
// pause that ends before the browser has finished loading the page it was taken for.
func TestDNSBlockPauseSendsTheLengthThatWasTypedInWholeMinutes(t *testing.T) {
	tests := []struct {
		about string
		arg   string
		want  int
	}{
		{about: "the default with no length at all", arg: "", want: 15},
		{about: "minutes", arg: "15m", want: 15},
		{about: "an hour", arg: "1h", want: 60},
		{about: "seconds rounded up to a whole minute", arg: "90s", want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.about, func(t *testing.T) {
			routes, _ := blockAgent(t, blockingView())
			h := newHarness(t, routes)

			args := blockArgs(h, []string{"pause"})
			if tt.arg != "" {
				args = append(args, tt.arg)
			}
			if err := Run(t.Context(), args, h.env()); err != nil {
				t.Fatalf("dns block pause %s: %v", tt.arg, err)
			}

			var sent struct {
				Minutes int `json:"minutes"`
			}
			for _, req := range h.recorded() {
				if req.Method == http.MethodPost && req.Path == "/api/dns/block/pause" {
					if err := json.Unmarshal([]byte(req.Body), &sent); err != nil {
						t.Fatalf("parse the pause request %q: %v", req.Body, err)
					}
				}
			}
			if sent.Minutes != tt.want {
				t.Errorf("paused for %d minutes, want %d", sent.Minutes, tt.want)
			}
			if !strings.Contains(h.out(), "paused until") {
				t.Errorf("dns block pause never says when blocking comes back:\n%s", h.out())
			}
		})
	}
}

// A length nothing can read must not become a pause of some other length.
func TestDNSBlockPauseRefusesALengthItCannotRead(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"pause"}, "a while"), h.env())

	if err == nil {
		t.Fatal("a length nothing can read was accepted")
	}
	for _, req := range h.recorded() {
		if req.Method == http.MethodPost && req.Path == "/api/dns/block/pause" {
			t.Errorf("a refused length still paused blocking: %s", req.Body)
		}
	}
}

func TestDNSBlockResumeEndsThePauseAndSaysWhatIsBackInForce(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"resume"}), h.env()); err != nil {
		t.Fatalf("dns block resume: %v", err)
	}

	resumes := 0
	for _, req := range h.recorded() {
		if req.Method == http.MethodPost && req.Path == "/api/dns/block/resume" {
			resumes++
		}
	}
	if resumes != 1 {
		t.Errorf("blocking was resumed %d times, want exactly once", resumes)
	}
	if !strings.Contains(h.out(), "152403") {
		t.Errorf("dns block resume does not say how many names are back in force:\n%s", h.out())
	}
}

// The allow list is the escape hatch for a name a list gets wrong, and the write keeps
// the entries that were already on it.
func TestDNSBlockAllowAddKeepsTheNamesAlreadyOnTheList(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"allow", "add"}, "Metrics.Example.COM."), h.env()); err != nil {
		t.Fatalf("dns block allow add: %v", err)
	}

	got := state().Allow
	if len(got) != 2 || got[0] != "ads.example.com" || got[1] != "metrics.example.com" {
		t.Errorf("allow = %v, want the name added in the form a resolver matches on", got)
	}
}

func TestDNSBlockDenyAddPutsANameOnTheAlwaysBlockedList(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"deny", "add"}, "tracker.example"), h.env()); err != nil {
		t.Fatalf("dns block deny add: %v", err)
	}

	if got := state().Deny; len(got) != 1 || got[0] != "tracker.example" {
		t.Errorf("deny = %v, want the one name that was typed", got)
	}
}

func TestDNSBlockAllowRemoveTakesTheNameBackOff(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"allow", "rm"}, "ads.example.com"), h.env()); err != nil {
		t.Fatalf("dns block allow rm: %v", err)
	}

	if got := state().Allow; len(got) != 0 {
		t.Errorf("allow = %v, want the name removed", got)
	}
}

// Removing a name that is not there has to fail: reporting it removed leaves the user
// believing a name is blocked again when nothing changed.
func TestDNSBlockAllowRemoveRefusesANameThatIsNotOnTheList(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"allow", "rm"}, "nothing.example"), h.env())

	if err == nil {
		t.Fatal("removing a name that is not on the list was reported as done")
	}
	if patches := settingsPatches(t, h); len(patches) != 0 {
		t.Errorf("a refused removal still wrote settings: %v", patches)
	}
}

func TestDNSBlockAllowRefusesACommandThatIsNeitherAddNorRemove(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"allow", "purge"}, "ads.example.com"), h.env())

	if err == nil {
		t.Fatal("an unknown allow command was accepted")
	}
	if !strings.Contains(err.Error(), "add or rm") {
		t.Errorf("the refusal reads %q, which does not say what the command takes", err)
	}
}

// The question people actually ask. Naming the list is what makes the answer actionable:
// it is the list they go and switch off.
func TestDNSBlockCheckNamesTheListThatStopsAName(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"check"}, "doubleclick.net"), h.env()); err != nil {
		t.Fatalf("dns block check: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "is blocked") || !strings.Contains(out, "Hagezi Pro") {
		t.Errorf("dns block check does not say what stops the name:\n%s", out)
	}
}

func TestDNSBlockCheckSaysWhyANameIsNotBlocked(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"check"}, "example.com"), h.env()); err != nil {
		t.Fatalf("dns block check: %v", err)
	}
	out := h.out()
	if !strings.Contains(out, "is not blocked") || !strings.Contains(out, "no list carries it") {
		t.Errorf("dns block check gives no reason for a name that resolves:\n%s", out)
	}
}

func TestDNSBlockRefusesACommandItDoesNotHave(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"frobnicate"}), h.env())

	if err == nil {
		t.Fatal("an unknown blocking command was accepted")
	}
	if !strings.Contains(err.Error(), "unknown dns block command") {
		t.Errorf("the refusal reads %q, which does not name the problem", err)
	}
}

// Lists are named by whatever the user calls them, and an id is what a script uses. A
// name carried by two lists is refused rather than guessed at, because guessing switches
// off the wrong one.
func TestResolvingAListAcceptsAnIdOrANameAndRefusesAnAmbiguousOne(t *testing.T) {
	lists := []httpapi.DNSBlockListView{
		{ID: "hagezi-pro", Name: "Hagezi Pro"},
		{ID: "work", Name: "Shared"},
		{ID: "home", Name: "shared"},
	}

	tests := []struct {
		about  string
		wanted string
		wantID string
		says   string
	}{
		{about: "an id", wanted: "work", wantID: "work"},
		{about: "the name the user gave it", wanted: "Hagezi Pro", wantID: "hagezi-pro"},
		{about: "a name in any case", wanted: "HAGEZI PRO", wantID: "hagezi-pro"},
		{about: "a name two lists carry", wanted: "shared", says: "more than one"},
		{about: "a name nothing carries", wanted: "ghost", says: "no blocklist called"},
	}
	for _, tt := range tests {
		t.Run(tt.about, func(t *testing.T) {
			got, err := resolveDNSBlockList(lists, tt.wanted)

			if tt.says != "" {
				if err == nil {
					t.Fatalf("resolveDNSBlockList(%q) = %+v, want a refusal", tt.wanted, got)
				}
				if !strings.Contains(err.Error(), tt.says) {
					t.Errorf("the refusal reads %q, want it to say %q", err, tt.says)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveDNSBlockList(%q): %v", tt.wanted, err)
			}
			if got.ID != tt.wantID {
				t.Errorf("resolveDNSBlockList(%q) = %q, want %q", tt.wanted, got.ID, tt.wantID)
			}
		})
	}
}

// The ladder is chosen by reading it, so the table has to carry what each rung blocks and
// which one is in force -- an id list alone gives nobody a basis to pick.
func TestDNSBlockLevelPrintsTheLadderAndMarksTheOneInForce(t *testing.T) {
	routes, _ := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	if err := Run(t.Context(), blockArgs(h, []string{"level"}), h.env()); err != nil {
		t.Fatalf("dns block level: %v", err)
	}
	out := h.out()
	for _, want := range []string{
		"minimum", "medium", "high", "Everything that costs nothing to block.", "The everyday tier.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the ladder is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "*  medium") {
		t.Errorf("the level in force is not marked:\n%s", out)
	}
	// Six rungs and no default is a research project. The one the agent recommends says so
	// in the table, and the rungs beside it stay unmarked or the mark means nothing.
	if !strings.Contains(out, "high (recommended)") {
		t.Errorf("the recommended level is not marked:\n%s", out)
	}
	if strings.Contains(out, "medium (recommended)") || strings.Contains(out, "minimum (recommended)") {
		t.Errorf("a level the agent did not recommend is marked as one:\n%s", out)
	}
	if !strings.Contains(out, "leaves the ones you added alone") {
		t.Errorf("the ladder does not say a level spares the user's own lists:\n%s", out)
	}
}

// Naming a rung switches to it, and the reply printed back is what is on now rather than
// what was on when the command started.
func TestDNSBlockLevelSwitchesToTheRungNamedByEitherIdOrName(t *testing.T) {
	tests := []struct{ about, typed string }{
		{about: "by id", typed: "high"},
		{about: "by the name in the table", typed: "High"},
	}
	for _, tt := range tests {
		t.Run(tt.about, func(t *testing.T) {
			routes, state := blockAgent(t, blockingView())
			h := newHarness(t, routes)

			if err := Run(t.Context(), blockArgs(h, []string{"level"}, tt.typed), h.env()); err != nil {
				t.Fatalf("dns block level %s: %v", tt.typed, err)
			}

			var sent []string
			for _, req := range h.recorded() {
				if req.Method == http.MethodPost && req.Path == "/api/dns/block/preset" {
					sent = append(sent, req.Body)
				}
			}
			if len(sent) != 1 {
				t.Fatalf("the command made %d preset requests, want 1: %v", len(sent), sent)
			}
			if !strings.Contains(sent[0], `"preset":"high"`) {
				t.Errorf("the request body is %s, want it to name high", sent[0])
			}
			if got := state().Preset; got != "high" {
				t.Errorf("the agent is on level %q, want high", got)
			}
			if out := h.out(); !strings.Contains(out, "Level") || !strings.Contains(out, "High") {
				t.Errorf("the command does not print the level it switched to:\n%s", out)
			}
		})
	}
}

// A typo must not silently leave the machine on whatever it had; it is refused before any
// request is made, and the refusal names the rungs that exist.
func TestDNSBlockLevelRefusesANameTheLadderDoesNotCarry(t *testing.T) {
	routes, state := blockAgent(t, blockingView())
	h := newHarness(t, routes)

	err := Run(t.Context(), blockArgs(h, []string{"level"}, "paranoid"), h.env())

	if err == nil {
		t.Fatal("dns block level paranoid was accepted, want a refusal")
	}
	if !strings.Contains(err.Error(), "minimum") {
		t.Errorf("the refusal reads %q, want it to name the levels", err)
	}
	for _, req := range h.recorded() {
		if req.Path == "/api/dns/block/preset" {
			t.Errorf("a refused level still reached the agent: %s", req.Body)
		}
	}
	if got := state().Preset; got != "medium" {
		t.Errorf("the level moved to %q, want it left at medium", got)
	}
}
