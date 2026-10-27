// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/ipsfeed"
)

// The card renders exactly this. The mode, the two signals and the counters are separate
// fields because they answer separate questions: what would happen to a match, what is
// being looked at, and what has already been seen.
func TestTheInspectionViewCarriesTheModeTheSignalsAndTheCounters(t *testing.T) {
	h := newHarness(t)

	view := decode[IPSView](t, h.do(t, http.MethodGet, "/api/ips", nil))

	if !view.Enabled || view.Mode != "prevent" {
		t.Errorf("enabled = %v mode = %q, want inspection on and refusing", view.Enabled, view.Mode)
	}
	if !view.Names || !view.Destinations {
		t.Errorf("names = %v destinations = %v, want the two signals reported apart",
			view.Names, view.Destinations)
	}
	if view.Rules != 3 || view.Matched != 4 || view.Refused != 2 {
		t.Errorf("rules = %d matched = %d refused = %d, want what is in force, what matched "+
			"and what was turned away", view.Rules, view.Matched, view.Refused)
	}
	if view.CompiledAt == "" {
		t.Error("nothing says when the rules were compiled, so a stale set reads as a fresh one")
	}
	if len(view.Recent) != 1 {
		t.Fatalf("recent = %+v, want the one match the ring holds", view.Recent)
	}
	match := view.Recent[0]
	if match.Signal != "name" || match.Value != "bad.example" || !match.Refused {
		t.Errorf("match = %+v, want it to say what matched, on what, and what happened next", match)
	}
	if match.Where == "" || match.Protocol == "" {
		t.Errorf("match = %+v, want it to say where the flow was and what it carried", match)
	}
	if len(view.Feeds) != 1 {
		t.Fatalf("feeds = %+v, want the one feed the catalog holds", view.Feeds)
	}
	feed := view.Feeds[0]
	if !feed.BuiltIn || !feed.Enabled || feed.Rules != 4231 || feed.Skipped != 18 {
		t.Errorf("feed = %+v, want it shipped, switched on, and reporting what it contributed "+
			"and left out", feed)
	}
	if view.RefreshHours != 24 || view.NextRefresh == "" {
		t.Errorf("refreshHours = %d nextRefresh = %q, want when the feeds are fetched again",
			view.RefreshHours, view.NextRefresh)
	}
}

// Refreshing answers with the view because what the caller wants to know is what the
// download produced, and asking a second time is how they would otherwise find out.
func TestRefreshingTheFeedsAnswersWithWhatTheDownloadProduced(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/ips/refresh", nil)

	requireStatus(t, rec, http.StatusOK)
	if h.ips.refreshes != 1 {
		t.Errorf("the feeds were downloaded %d times, want exactly once", h.ips.refreshes)
	}
	if view := decode[IPSView](t, rec); view.Rules == 0 {
		t.Error("the answer carries no state, so the client learned nothing from the round trip")
	}
}

// A feed that will not download is the ordinary outcome of a network that is down, not an
// internal fault: it has to reach the card as a stated refusal.
func TestARefreshOfTheFeedsThatFailedIsReportedRatherThanSwallowed(t *testing.T) {
	h := newHarness(t)
	h.ips.refreshErr = &config.ValidationError{
		Field: "ips.lists", Message: "feeds.example could not be reached",
	}

	rec := h.do(t, http.MethodPost, "/api/ips/refresh", nil)

	body := requireError(t, rec, http.StatusBadRequest, "could not be reached")
	if body.Field != "ips.lists" {
		t.Errorf("field = %q, want the refusal attributed to the feeds", body.Field)
	}
}

// Removing the root answers with the view, so the caller sees no root is left without asking
// a second time.
func TestRemovingTheInterceptionRootAnswersWithNoRootLeft(t *testing.T) {
	h := newHarness(t)
	h.ips.view.Intercept.Fingerprint = "ab12"

	rec := h.do(t, http.MethodPost, "/api/ips/intercept/remove-root", nil)

	requireStatus(t, rec, http.StatusOK)
	if h.ips.rootRemovals != 1 {
		t.Errorf("the root was removed %d times, want exactly once", h.ips.rootRemovals)
	}
	if view := decode[IPSView](t, rec); view.Intercept.Fingerprint != "" {
		t.Errorf("the answer still shows root %q", view.Intercept.Fingerprint)
	}
}

// A removal refused because interception is on reaches the caller as a stated refusal naming
// the setting to change, not as an internal fault.
func TestRemovingTheInterceptionRootWhileItIsOnIsRefusedWithTheSettingNamed(t *testing.T) {
	h := newHarness(t)
	h.ips.removeErr = &config.ValidationError{
		Field: "ips.intercept", Message: "switch traffic interception off before removing its root",
	}

	rec := h.do(t, http.MethodPost, "/api/ips/intercept/remove-root", nil)

	body := requireError(t, rec, http.StatusBadRequest, "switch traffic interception off")
	if body.Field != "ips.intercept" {
		t.Errorf("field = %q, want the refusal attributed to the interception setting", body.Field)
	}
}

func TestAddingAFeedStoresItAndAnswersWithWhatWasStored(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/ips/feeds", config.IPSFeed{
		Name: "Work feed", URL: "https://feeds.example/work.txt",
	})

	requireStatus(t, rec, http.StatusCreated)
	created := decode[config.IPSFeed](t, rec)
	if created.ID == "" || created.Name != "Work feed" {
		t.Errorf("created = %+v, want the stored feed with an id of its own", created)
	}
	if len(h.ips.user) != 1 {
		t.Errorf("stored %+v, want the one feed that was added", h.ips.user)
	}
}

// BuiltIn is the catalog's to decide. A client that could mint a shipped feed would have
// made one nothing can edit or delete.
func TestAClientCannotMintAFeedThatShipsWithAppTail(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/ips/feeds", config.IPSFeed{
		Name: "Mine", URL: "https://feeds.example/mine.txt", BuiltIn: true,
	})

	requireStatus(t, rec, http.StatusCreated)
	if created := decode[config.IPSFeed](t, rec); created.BuiltIn {
		t.Error("a client minted a feed that claims to ship with app-tail")
	}
}

// What a feed holds decides which connections are refused, so anyone able to rewrite it in
// transit would decide that instead: http is refused rather than upgraded.
func TestAFeedTheRouteCannotFetchSafelyIsRefused(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/ips/feeds", config.IPSFeed{
		Name: "Mine", URL: "http://feeds.example/mine.txt",
	})

	body := requireError(t, rec, http.StatusBadRequest, "https")
	if body.Field != "ipsFeed" {
		t.Errorf("field = %q, want the refusal attributed to the feed", body.Field)
	}
	if len(h.ips.user) != 0 {
		t.Errorf("stored %+v, want nothing written for a refused feed", h.ips.user)
	}
}

// Every scheme the downloader cannot or must not follow is refused at entry on both
// routes, so the catalog never holds a URL that would fail only at refresh time.
func TestASchemeTheDownloaderCannotFollowIsRefusedOnEitherRoute(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
	}{
		{"adding a feed", http.MethodPost, "/api/ips/feeds"},
		{"editing one", http.MethodPut, "/api/ips/feeds/work"},
	}
	schemes := []struct{ name, url string }{
		{"file", "file:///etc/passwd"},
		{"ftp", "ftp://feeds.example/work.txt"},
		{"gopher", "gopher://feeds.example/work.txt"},
		{"javascript", "javascript:alert(1)"},
	}
	for _, tc := range tests {
		for _, sc := range schemes {
			t.Run(tc.name+"/"+sc.name, func(t *testing.T) {
				h := newHarness(t)
				h.ips.user = []config.IPSFeed{{ID: "work", Name: "Work feed", URL: "https://feeds.example/work.txt"}}

				rec := h.do(t, tc.method, tc.target, config.IPSFeed{Name: "Mine", URL: sc.url})

				body := requireError(t, rec, http.StatusBadRequest, "https")
				if body.Field != "ipsFeed" {
					t.Errorf("field = %q, want the refusal attributed to the feed", body.Field)
				}
				if got := h.ips.user[0].URL; got != "https://feeds.example/work.txt" {
					t.Errorf("stored URL = %q, want the existing feed untouched by a refused scheme", got)
				}
			})
		}
	}
}

// A body that is not JSON names no feed at all, so nothing may be stored from it. Reading
// it as an empty feed would create one called nothing, or blank the feed being edited.
func TestABodyThatIsNotJSONStoresNoFeedOnEitherRoute(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
	}{
		{"adding a feed", http.MethodPost, "/api/ips/feeds"},
		{"editing one", http.MethodPut, "/api/ips/feeds/work"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			stored := []config.IPSFeed{{ID: "work", Name: "Work feed", URL: "https://feeds.example/work.txt"}}
			h.ips.user = stored

			rec := h.doRaw(t, tc.method, tc.target, "{not json")

			requireError(t, rec, http.StatusBadRequest, "")
			if len(h.ips.user) != 1 || h.ips.user[0] != stored[0] {
				t.Errorf("stored %+v, want the feeds untouched by a body nothing could read", h.ips.user)
			}
		})
	}
}

func TestEditingAFeedKeepsTheIdTheRouteNames(t *testing.T) {
	h := newHarness(t)
	h.ips.user = []config.IPSFeed{{ID: "work", Name: "Work feed", URL: "https://feeds.example/work.txt"}}

	rec := h.do(t, http.MethodPut, "/api/ips/feeds/work", config.IPSFeed{
		ID: "something-else", Name: "Work feed", URL: "https://feeds.example/v2.txt",
	})

	requireStatus(t, rec, http.StatusOK)
	updated := decode[config.IPSFeed](t, rec)
	if updated.ID != "work" {
		t.Errorf("id = %q, want the id in the path rather than the one in the body", updated.ID)
	}
	if h.ips.user[0].URL != "https://feeds.example/v2.txt" {
		t.Errorf("stored %+v, want the edited address", h.ips.user[0])
	}
}

func TestAShippedFeedIsRefusedAnEditAndADeleteByTheRoutes(t *testing.T) {
	h := newHarness(t)

	edit := h.do(t, http.MethodPut, "/api/ips/feeds/"+ipsfeed.DefaultFeedID, config.IPSFeed{
		Name: "Not FireHOL", URL: "https://feeds.example/mine.txt",
	})
	remove := h.do(t, http.MethodDelete, "/api/ips/feeds/"+ipsfeed.DefaultFeedID, nil)

	requireError(t, edit, http.StatusBadRequest, "cannot be edited")
	requireError(t, remove, http.StatusBadRequest, "cannot be deleted")
	if len(h.ips.deletes) != 0 {
		t.Errorf("deleted %v, want a shipped feed left alone", h.ips.deletes)
	}
}

func TestDeletingAFeedRemovesItAndAnswersWithNothing(t *testing.T) {
	h := newHarness(t)
	h.ips.user = []config.IPSFeed{{ID: "work", Name: "Work feed", URL: "https://feeds.example/work.txt"}}

	rec := h.do(t, http.MethodDelete, "/api/ips/feeds/work", nil)

	requireStatus(t, rec, http.StatusNoContent)
	if len(h.ips.user) != 0 {
		t.Errorf("stored %+v, want the feed removed", h.ips.user)
	}
	if len(h.ips.deletes) != 1 || h.ips.deletes[0] != "work" {
		t.Errorf("deletes = %v, want the one id that was asked for", h.ips.deletes)
	}
}

func TestDeletingAFeedThatIsNotThereIsRefusedRatherThanReportedDone(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodDelete, "/api/ips/feeds/ghost", nil)

	requireStatus(t, rec, http.StatusNotFound)
}

// The card offers six levels and writes the one that was clicked. It answers with the view so
// the card shows the feeds that level turned on without asking a second time.
func TestSwitchingInspectionToALevelAppliesItAndAnswersWithWhatIsOnNow(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/ips/preset", map[string]string{"preset": "high"})

	requireStatus(t, rec, http.StatusOK)
	if h.ips.applied != "high" {
		t.Errorf("the agent was asked for %q, want the level the request named", h.ips.applied)
	}
	if view := decode[IPSView](t, rec); view.Preset != "high" {
		t.Errorf("preset = %q, want the answer to say which level is on", view.Preset)
	}
}

// A level nothing carries has to be refused: applied as the empty set it would switch every
// feed off, so a typo would read as inspection having been turned on.
func TestALevelOfInspectionTheLadderDoesNotCarryIsRefusedAndChangesNothing(t *testing.T) {
	h := newHarness(t)

	for _, body := range []map[string]string{{"preset": "paranoid"}, {"preset": ""}, {}} {
		rec := h.do(t, http.MethodPost, "/api/ips/preset", body)

		requireError(t, rec, http.StatusBadRequest, "level")
		if h.ips.applied != "" {
			t.Fatalf("the agent applied %q for %v, want nothing applied", h.ips.applied, body)
		}
	}
}

func TestPausingInspectionLastsForTheMinutesAskedFor(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/ips/pause", map[string]int{"minutes": 15})

	requireStatus(t, rec, http.StatusOK)
	if h.ips.paused != 15*time.Minute {
		t.Errorf("paused for %s, want 15m", h.ips.paused)
	}
	if view := decode[IPSView](t, rec); view.Rules == 0 {
		t.Error("the answer carries no state, so the client learned nothing from the round trip")
	}
}

// A pause is meant to get one connection through. A pause of a day, or of nothing at all,
// is inspection somebody finds switched off next week without having chosen that.
func TestAPauseOfInspectionOutsideWhatAPauseIsForIsRefused(t *testing.T) {
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

			rec := h.doRaw(t, http.MethodPost, "/api/ips/pause", body)

			requireStatus(t, rec, http.StatusBadRequest)
			if h.ips.paused != 0 {
				t.Errorf("inspection was paused for %s by a refused request", h.ips.paused)
			}
		})
	}
}

func TestResumingInspectionEndsThePauseAndAnswersWithTheState(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/ips/resume", nil)

	requireStatus(t, rec, http.StatusOK)
	if h.ips.resumes != 1 {
		t.Errorf("inspection was resumed %d times, want exactly once", h.ips.resumes)
	}
	if view := decode[IPSView](t, rec); view.PausedUntil != "" {
		t.Errorf("pausedUntil = %q, want nothing after a resume", view.PausedUntil)
	}
}

// The question the rule count cannot answer: whether the entry someone typed reaches the
// thing they meant. An address inside a denied network is the case they get wrong.
func TestCheckingADestinationSaysWhichEntryStopsIt(t *testing.T) {
	h := newHarness(t)

	view := decode[IPSCheckView](t, h.do(t, http.MethodGet, "/api/ips/check?dest=10.1.2.9", nil))

	if h.ips.checked != "10.1.2.9" {
		t.Errorf("the agent was asked about %q, want the destination the query named", h.ips.checked)
	}
	if !view.Matched || !view.Refused {
		t.Errorf("check = %+v, want the address matched and refused", view)
	}
	if view.Signal != "destination" || view.Value != "10.1.2.0/24" {
		t.Errorf("check = %+v, want it to name the entry that matched rather than only that one did", view)
	}
	if view.Reason == "" {
		t.Error("no reason is given, so a destination nothing matches would say nothing at all")
	}
}

func TestCheckingNoDestinationIsRefusedRatherThanAnsweredAbout(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/ips/check", nil)

	body := requireError(t, rec, http.StatusBadRequest, "name a domain")
	if body.Field != "dest" {
		t.Errorf("field = %q, want the refusal attributed to the destination", body.Field)
	}
	if h.ips.checked != "" {
		t.Errorf("the agent was asked about %q by a request that named nothing", h.ips.checked)
	}
}
