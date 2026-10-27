// SPDX-License-Identifier: MIT

package httpapi

// The per-destination routing rules over HTTP: reading the list, replacing it, and asking
// which way one destination goes.

import (
	"errors"
	"net/http"
	"testing"

	"github.com/sellitus/app-tail/internal/routing"
)

func TestTheRuleListIsServedWithTheVocabularyToRenderIt(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/routing", nil)

	requireStatus(t, rec, http.StatusOK)
	view := decode[RoutingView](t, rec)
	if len(view.Rules) != 1 || view.Rules[0].ID != "rt_1" {
		t.Errorf("rules = %+v, want the one stored rule", view.Rules)
	}
	// A client that held its own action list would offer a value the agent refuses, so the
	// list is served beside the rules rather than assumed.
	if len(view.Actions) != len(routing.Actions) {
		t.Errorf("actions = %v, want the whole vocabulary %v", view.Actions, routing.Actions)
	}
	if len(view.Tunnels) != 1 || !view.Tunnels[0].Running {
		t.Errorf("tunnels = %+v, want the connections a rule may name", view.Tunnels)
	}
	if len(view.Limits) == 0 {
		t.Error("limits = none, want what these rules do not do stated up front")
	}
}

// The list is replaced whole, in order, because order is the meaning: the first matching
// rule decides.
func TestReplacingTheListSendsTheWholeOrderedListThrough(t *testing.T) {
	h := newHarness(t)
	sent := []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
		{ID: "rt_2", Action: routing.Via, Tunnel: "tn_office", Host: "**.corp.example"},
	}

	rec := h.do(t, http.MethodPut, "/api/routing/rules", map[string]any{"rules": sent})

	requireStatus(t, rec, http.StatusOK)
	if len(h.routing.written) != 1 {
		t.Fatalf("wrote %d lists, want exactly one", len(h.routing.written))
	}
	got := h.routing.written[0]
	if len(got) != 2 || got[0].ID != "rt_1" || got[1].ID != "rt_2" {
		t.Errorf("wrote %+v, want both rules in the order they were sent", got)
	}
	if view := decode[RoutingView](t, rec); len(view.Rules) != 2 {
		t.Errorf("read back %+v, want the list that was just written", view.Rules)
	}
}

// A refused list is the agent's answer, not a silent partial write: a rule naming a
// connection that does not exist has to come back as the refusal it is.
func TestARefusedListIsReportedRatherThanStored(t *testing.T) {
	h := newHarness(t)
	h.routing.setErr = badRequest("routes.tunnel: rule 1 sends traffic through connection %q, "+
		"which does not exist", "tn_gone")

	rec := h.do(t, http.MethodPut, "/api/routing/rules", map[string]any{
		"rules": []routing.Rule{{ID: "rt_1", Action: routing.Via, Tunnel: "tn_gone", Host: "a.example"}},
	})

	requireError(t, rec, http.StatusBadRequest, "does not exist")
}

func TestCheckingADestinationNamesTheRuleThatDecided(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/routing/check", RoutingCheckRequest{
		Destination: "db.corp.example",
	})

	requireStatus(t, rec, http.StatusOK)
	got := decode[RoutingCheckResult](t, rec)
	if !got.Decided || got.RuleIndex != 1 || got.TunnelName != "Office" {
		t.Errorf("check = %+v, want the first rule sending it through Office", got)
	}
	if got.Destination != "db.corp.example" {
		t.Errorf("destination = %q, want the one that was asked about", got.Destination)
	}
}

// An empty destination is refused rather than decided: every rule that states no host and
// no range is already refused by the document, so an empty check would answer for nothing.
func TestCheckingNothingIsRefused(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/routing/check", RoutingCheckRequest{Destination: "  "})

	requireError(t, rec, http.StatusBadRequest, "destination is required")
}

func TestACheckThatCouldNotBeAnsweredIsReported(t *testing.T) {
	h := newHarness(t)
	h.routing.checkErr = errors.New("the rules could not be read")

	rec := h.do(t, http.MethodPost, "/api/routing/check", RoutingCheckRequest{Destination: "a.example"})

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for a check that failed", rec.Code)
	}
}
