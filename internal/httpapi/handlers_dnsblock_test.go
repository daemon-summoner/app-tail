// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/dnsblock"
)

// The card renders exactly this. Both switches, what each list contributed and what the
// machine has actually refused are separate fields because they answer separate questions,
// and a view that merged any of them would leave the card guessing.
func TestTheBlockingViewCarriesBothSwitchesTheListsAndTheCounters(t *testing.T) {
	h := newHarness(t)

	view := decode[DNSBlockView](t, h.do(t, http.MethodGet, "/api/dns/block", nil))

	if !view.Enabled || !view.Own || !view.System {
		t.Errorf("enabled = %v own = %v system = %v, want the switches reported apart",
			view.Enabled, view.Own, view.System)
	}
	if view.Rules != 152403 || view.Blocked != 87 {
		t.Errorf("rules = %d blocked = %d, want what is in force and what has been refused",
			view.Rules, view.Blocked)
	}
	if len(view.Lists) != 1 {
		t.Fatalf("lists = %+v, want the one list the catalog holds", view.Lists)
	}
	list := view.Lists[0]
	if !list.BuiltIn || !list.Enabled || list.Rules != 152403 || list.Skipped != 12 {
		t.Errorf("list = %+v, want it shipped, switched on, and reporting what it contributed and dropped", list)
	}
	if view.Answer != "nxdomain" || view.RefreshHours != 24 {
		t.Errorf("answer = %q refreshHours = %d, want the two settings the card shows beside the lists",
			view.Answer, view.RefreshHours)
	}
}

// Refreshing answers with the view because what the caller wants to know is what the
// download produced, and asking a second time is how they would otherwise find out.
func TestRefreshingTheListsAnswersWithWhatTheDownloadProduced(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/block/refresh", nil)

	requireStatus(t, rec, http.StatusOK)
	if h.dnsBlock.refreshes != 1 {
		t.Errorf("the lists were downloaded %d times, want exactly once", h.dnsBlock.refreshes)
	}
	if view := decode[DNSBlockView](t, rec); view.Rules == 0 {
		t.Error("the answer carries no state, so the client learned nothing from the round trip")
	}
}

// A list that will not download is the ordinary outcome of a network that is down, not an
// internal fault: it has to reach the card as a stated refusal.
func TestARefreshThatCouldNotDownloadAnythingIsReportedRatherThanSwallowed(t *testing.T) {
	h := newHarness(t)
	h.dnsBlock.refreshErr = &config.ValidationError{
		Field: "dnsBlock.lists", Message: "lists.example could not be reached",
	}

	rec := h.do(t, http.MethodPost, "/api/dns/block/refresh", nil)

	body := requireError(t, rec, http.StatusBadRequest, "could not be reached")
	if body.Field != "dnsBlock.lists" {
		t.Errorf("field = %q, want the refusal attributed to the lists", body.Field)
	}
}

// The card offers six levels and writes the one that was clicked. It answers with the view
// so the card shows the lists that level turned on without asking a second time.
func TestSwitchingToALevelAppliesItAndAnswersWithWhatIsOnNow(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/block/preset", map[string]string{"preset": "high"})

	requireStatus(t, rec, http.StatusOK)
	if h.dnsBlock.applied != "high" {
		t.Errorf("the agent was asked for %q, want the level the request named", h.dnsBlock.applied)
	}
	if view := decode[DNSBlockView](t, rec); view.Preset != "high" {
		t.Errorf("preset = %q, want the answer to say which level is on", view.Preset)
	}
}

// A level nothing carries has to be refused: applied as the empty set it would switch every
// list off, so a typo would read as blocking having been turned on.
func TestALevelTheLadderDoesNotCarryIsRefusedAndChangesNothing(t *testing.T) {
	h := newHarness(t)

	for _, body := range []map[string]string{{"preset": "paranoid"}, {"preset": ""}, {}} {
		rec := h.do(t, http.MethodPost, "/api/dns/block/preset", body)

		requireError(t, rec, http.StatusBadRequest, "level")
		if h.dnsBlock.applied != "" {
			t.Fatalf("the agent applied %q for %v, want nothing applied", h.dnsBlock.applied, body)
		}
	}
}

func TestPausingBlockingLastsForTheMinutesAskedFor(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/block/pause", map[string]int{"minutes": 15})

	requireStatus(t, rec, http.StatusOK)
	if h.dnsBlock.paused != 15*time.Minute {
		t.Errorf("paused for %s, want 15m", h.dnsBlock.paused)
	}
}

// A pause is meant to get one site loaded. A pause of a day, or of nothing at all, is a
// blocker somebody finds switched off next week without having chosen that.
func TestAPauseOutsideWhatAPauseIsForIsRefused(t *testing.T) {
	tests := map[string]string{
		"no minutes at all":   `{}`,
		"zero":                `{"minutes":0}`,
		"negative":            `{"minutes":-5}`,
		"longer than a day":   `{"minutes":1441}`,
		"not a number at all": `{"minutes":"fifteen"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			rec := h.doRaw(t, http.MethodPost, "/api/dns/block/pause", body)

			requireStatus(t, rec, http.StatusBadRequest)
			if h.dnsBlock.paused != 0 {
				t.Errorf("blocking was paused for %s by a refused request", h.dnsBlock.paused)
			}
		})
	}
}

func TestResumingEndsThePauseAndAnswersWithTheState(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/block/resume", nil)

	requireStatus(t, rec, http.StatusOK)
	if h.dnsBlock.resumes != 1 {
		t.Errorf("blocking was resumed %d times, want exactly once", h.dnsBlock.resumes)
	}
	if view := decode[DNSBlockView](t, rec); view.PausedUntil != "" {
		t.Errorf("pausedUntil = %q, want nothing after a resume", view.PausedUntil)
	}
}

// The question people actually ask, and the one the list of lists cannot answer.
func TestCheckingANameAnswersWhichListStopsIt(t *testing.T) {
	h := newHarness(t)

	view := decode[DNSBlockCheckView](t, h.do(t, http.MethodGet, "/api/dns/block/check?name=doubleclick.net", nil))

	if !view.Blocked || view.List != "Hagezi Pro" {
		t.Errorf("check = %+v, want it blocked with the list named", view)
	}
	if view.Reason == "" {
		t.Error("no reason is given, so a name that is not blocked would say nothing at all")
	}
}

func TestCheckingNothingIsRefusedRatherThanAnsweredAbout(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/dns/block/check", nil)

	body := requireError(t, rec, http.StatusBadRequest, "name a domain")
	if body.Field != "name" {
		t.Errorf("field = %q, want the refusal attributed to the missing name", body.Field)
	}
}

func TestAddingAListStoresItAndAnswersWithWhatWasStored(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/block/lists", config.Blocklist{
		Name: "Work list", URL: "https://lists.example/work.txt", Format: "hosts",
	})

	requireStatus(t, rec, http.StatusCreated)
	created := decode[config.Blocklist](t, rec)
	if created.ID == "" || created.Name != "Work list" {
		t.Errorf("created = %+v, want the stored list with an id of its own", created)
	}
	if len(h.dnsBlock.user) != 1 {
		t.Errorf("stored %+v, want the one list that was added", h.dnsBlock.user)
	}
}

// BuiltIn is the catalog's to decide. A client that could mint a shipped list would have
// made one nothing can edit or delete.
func TestAClientCannotMintAListThatShipsWithAppTail(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/block/lists", config.Blocklist{
		Name: "Mine", URL: "https://lists.example/mine.txt", BuiltIn: true,
	})

	requireStatus(t, rec, http.StatusCreated)
	if created := decode[config.Blocklist](t, rec); created.BuiltIn {
		t.Error("a client minted a list that claims to ship with app-tail")
	}
}

func TestAListNothingCouldDownloadIsRefusedByTheRoute(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/dns/block/lists", config.Blocklist{
		Name: "Mine", URL: "ftp://lists.example/mine.txt",
	})

	body := requireError(t, rec, http.StatusBadRequest, "http")
	if body.Field != "blocklist" {
		t.Errorf("field = %q, want the refusal attributed to the list", body.Field)
	}
	if len(h.dnsBlock.user) != 0 {
		t.Errorf("stored %+v, want nothing written for a refused list", h.dnsBlock.user)
	}
}

// A body that is not JSON names no list at all, so nothing may be stored from it. Reading
// it as an empty list would create one called nothing, or blank the list being edited.
func TestABodyThatIsNotJSONStoresNothingOnEitherRoute(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
	}{
		{"adding a list", http.MethodPost, "/api/dns/block/lists"},
		{"editing one", http.MethodPut, "/api/dns/block/lists/work"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			stored := []config.Blocklist{{ID: "work", Name: "Work list", URL: "https://lists.example/work.txt"}}
			h.dnsBlock.user = stored

			rec := h.doRaw(t, tc.method, tc.target, "{not json")

			requireError(t, rec, http.StatusBadRequest, "")
			if len(h.dnsBlock.user) != 1 || h.dnsBlock.user[0] != stored[0] {
				t.Errorf("stored %+v, want the lists untouched by a body nothing could read", h.dnsBlock.user)
			}
		})
	}
}

func TestEditingAListKeepsTheIdTheRouteNames(t *testing.T) {
	h := newHarness(t)
	h.dnsBlock.user = []config.Blocklist{{ID: "work", Name: "Work list", URL: "https://lists.example/work.txt"}}

	rec := h.do(t, http.MethodPut, "/api/dns/block/lists/work", config.Blocklist{
		ID: "something-else", Name: "Work list", URL: "https://lists.example/v2.txt",
	})

	requireStatus(t, rec, http.StatusOK)
	updated := decode[config.Blocklist](t, rec)
	if updated.ID != "work" {
		t.Errorf("id = %q, want the id in the path rather than the one in the body", updated.ID)
	}
	if h.dnsBlock.user[0].URL != "https://lists.example/v2.txt" {
		t.Errorf("stored %+v, want the edited address", h.dnsBlock.user[0])
	}
}

func TestAShippedListIsRefusedAnEditAndADeleteByTheRoutes(t *testing.T) {
	h := newHarness(t)

	edit := h.do(t, http.MethodPut, "/api/dns/block/lists/"+dnsblock.DefaultListID, config.Blocklist{
		Name: "Not Hagezi", URL: "https://lists.example/mine.txt",
	})
	remove := h.do(t, http.MethodDelete, "/api/dns/block/lists/"+dnsblock.DefaultListID, nil)

	requireError(t, edit, http.StatusBadRequest, "cannot be edited")
	requireError(t, remove, http.StatusBadRequest, "cannot be deleted")
	if len(h.dnsBlock.deletes) != 0 {
		t.Errorf("deleted %v, want a shipped list left alone", h.dnsBlock.deletes)
	}
}

func TestDeletingAListRemovesItAndAnswersWithNothing(t *testing.T) {
	h := newHarness(t)
	h.dnsBlock.user = []config.Blocklist{{ID: "work", Name: "Work list", URL: "https://lists.example/work.txt"}}

	rec := h.do(t, http.MethodDelete, "/api/dns/block/lists/work", nil)

	requireStatus(t, rec, http.StatusNoContent)
	if len(h.dnsBlock.user) != 0 {
		t.Errorf("stored %+v, want the list removed", h.dnsBlock.user)
	}
	if len(h.dnsBlock.deletes) != 1 || h.dnsBlock.deletes[0] != "work" {
		t.Errorf("deletes = %v, want the one id that was asked for", h.dnsBlock.deletes)
	}
}

func TestDeletingAListThatIsNotThereIsRefusedRatherThanReportedDone(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodDelete, "/api/dns/block/lists/ghost", nil)

	requireStatus(t, rec, http.StatusNotFound)
}
