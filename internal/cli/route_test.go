// SPDX-License-Identifier: MIT

package cli

// The routing rules on the command line. The list is edited a rule at a time here and
// replaced whole over HTTP, so most of these are about that translation: what the CLI sends
// after reading what is already there.

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/routing"
)

// routingAgent is a stand-in agent holding a rule list the CLI can read and replace, plus
// the connections a rule may name.
type routingAgent struct {
	mu      sync.Mutex
	rules   []routing.Rule
	written int
}

func (a *routingAgent) view() httpapi.RoutingView {
	a.mu.Lock()
	defer a.mu.Unlock()
	rules := routing.Clone(a.rules)
	if rules == nil {
		rules = []routing.Rule{}
	}
	describe := make([]string, 0, len(rules))
	for _, rule := range rules {
		describe = append(describe, rule.DescribeWith(func(id string) string {
			if id == "tn_office" {
				return "Office"
			}
			return ""
		}))
	}
	return httpapi.RoutingView{
		Rules:      rules,
		Describe:   describe,
		Shadowed:   routing.Shadowed(rules),
		Actions:    routing.Actions,
		Tunnels:    []httpapi.RoutingTunnel{{ID: "tn_office", Name: "Office", Running: true}},
		Limits:     httpapi.RoutingLimits(),
		Capability: httpapi.Capability{Available: true, Limits: httpapi.RoutingLimits()},
	}
}

func (a *routingAgent) stored() []routing.Rule {
	a.mu.Lock()
	defer a.mu.Unlock()
	return routing.Clone(a.rules)
}

// routingRoutes serves the three endpoints the route commands use, against one stored list.
func routingRoutes(t *testing.T, agent *routingAgent) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/routing": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, agent.view())
		},
		"PUT /api/routing/rules": func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Rules []routing.Rule `json:"rules"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode the rule list: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			agent.mu.Lock()
			agent.rules = body.Rules
			agent.written++
			agent.mu.Unlock()
			writeJSONResponse(t, w, http.StatusOK, agent.view())
		},
		"POST /api/routing/check": func(w http.ResponseWriter, r *http.Request) {
			var body httpapi.RoutingCheckRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode the check: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			decided := routing.Decide(agent.stored(), routing.Request{Host: body.Destination})
			result := httpapi.RoutingCheckResult{
				Destination: body.Destination,
				Decided:     decided.Decided,
				Action:      string(decided.Action),
				Tunnel:      decided.Tunnel,
				TunnelName:  "Office",
				Rule:        decided.Rule,
				RuleIndex:   decided.Index + 1,
				Reason:      decided.Reason,
			}
			if !decided.Decided {
				result.Reason = "no rule names this destination"
			}
			writeJSONResponse(t, w, http.StatusOK, result)
		},
		"GET /api/tunnels": func(w http.ResponseWriter, _ *http.Request) {
			writeJSONResponse(t, w, http.StatusOK, map[string]any{
				"tunnels": []httpapi.TunnelView{{ID: "tn_office", Name: "Office", Slug: "office"}},
			})
		},
	}
}

// A rule is added by name, and the connection it names is resolved the way every other
// command resolves one: a person writes "office", not an id they have never seen.
func TestAddingARuleNamesTheConnectionTheWayAPersonDoes(t *testing.T) {
	agent := &routingAgent{}
	h := newHarness(t, routingRoutes(t, agent))

	args := append([]string{"route", "add", "--host", "**.corp.example", "--via", "office"}, h.cfg()...)
	if err := h.exec(args...); err != nil {
		t.Fatalf("route add: %v", err)
	}

	stored := agent.stored()
	if len(stored) != 1 {
		t.Fatalf("stored %d rules, want the one that was added", len(stored))
	}
	if stored[0].Action != routing.Via || stored[0].Tunnel != "tn_office" {
		t.Errorf("stored %+v, want it sent through the office connection by id", stored[0])
	}
	if stored[0].Host != "**.corp.example" {
		t.Errorf("host = %q, want the pattern as written", stored[0].Host)
	}
}

// The list is read before it is written, so adding one exception keeps the ones already
// there -- and keeps them in front of it, which is what decides the destinations they cover.
func TestAddingARuleKeepsTheOnesAlreadyThereAhead(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_first", Action: routing.Direct, Host: "bank.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	args := append([]string{"route", "add", "--range", "192.0.2.0/24", "--block"}, h.cfg()...)
	if err := h.exec(args...); err != nil {
		t.Fatalf("route add: %v", err)
	}

	stored := agent.stored()
	if len(stored) != 2 || stored[0].ID != "rt_first" {
		t.Fatalf("stored %+v, want the existing rule kept in front", stored)
	}
	if stored[1].Action != routing.Block || stored[1].CIDR.String() != "192.0.2.0/24" {
		t.Errorf("stored %+v, want the new rule refusing that range", stored[1])
	}
}

// Order is the meaning, so a rule can be put where it decides: an exception belongs above
// the broad rule it is an exception to.
func TestARuleCanBePutAheadOfTheOneItIsAnExceptionTo(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_broad", Action: routing.Via, Tunnel: "tn_office", Host: "**.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	args := append([]string{"route", "add", "--host", "bank.example", "--direct", "--at", "1"}, h.cfg()...)
	if err := h.exec(args...); err != nil {
		t.Fatalf("route add: %v", err)
	}

	stored := agent.stored()
	if len(stored) != 2 || stored[0].Host != "bank.example" || stored[1].ID != "rt_broad" {
		t.Errorf("stored %+v, want the exception first", stored)
	}
}

// A position past the end is refused rather than clamped: a rule quietly landing somewhere
// other than where it was asked for decides the wrong destinations.
func TestAPositionOutsideTheListIsRefused(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	args := append([]string{"route", "add", "--host", "a.example", "--direct", "--at", "9"}, h.cfg()...)
	err := h.exec(args...)

	if err == nil {
		t.Fatal("a position past the end was accepted")
	}
	if !strings.Contains(err.Error(), "outside the list") {
		t.Errorf("refusal = %v, want it to say the position is outside the list", err)
	}
	if agent.written != 0 {
		t.Errorf("wrote the list %d times after a refusal, want none", agent.written)
	}
}

// A rule with no action is refused rather than guessed: the action is where somebody's
// traffic goes.
func TestARuleWithNoActionIsRefused(t *testing.T) {
	h := newHarness(t, routingRoutes(t, &routingAgent{}))

	err := h.exec(append([]string{"route", "add", "--host", "a.example"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("a rule that says nothing about where the traffic goes was accepted")
	}
	if !strings.Contains(err.Error(), "--via") {
		t.Errorf("refusal = %v, want it to name the actions available", err)
	}
}

// A rule naming two actions is refused for the same reason.
func TestARuleNamingTwoActionsIsRefused(t *testing.T) {
	h := newHarness(t, routingRoutes(t, &routingAgent{}))

	err := h.exec(append([]string{"route", "add", "--host", "a.example", "--direct", "--block"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("a rule doing two things was accepted")
	}
	if !strings.Contains(err.Error(), "one thing") {
		t.Errorf("refusal = %v, want it to say a rule does one thing", err)
	}
}

// A range written with host bits below its prefix is refused with the form that works,
// because it is a typo with a silent consequence: 192.0.2.5/24 covers a whole network.
func TestARangeWithHostBitsIsRefusedWithTheFormThatWorks(t *testing.T) {
	h := newHarness(t, routingRoutes(t, &routingAgent{}))

	err := h.exec(append([]string{"route", "add", "--range", "192.0.2.5/24", "--block"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("a range carrying host bits was accepted")
	}
	if !strings.Contains(err.Error(), "192.0.2.0/24") {
		t.Errorf("refusal = %v, want it to show the form that works", err)
	}
}

func TestARuleIsRemovedByItsPosition(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
		{ID: "rt_2", Action: routing.Block, CIDR: netip.MustParsePrefix("192.0.2.0/24")},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	if err := h.exec(append([]string{"route", "rm", "1"}, h.cfg()...)...); err != nil {
		t.Fatalf("route rm: %v", err)
	}

	stored := agent.stored()
	if len(stored) != 1 || stored[0].ID != "rt_2" {
		t.Errorf("stored %+v, want only the second rule left", stored)
	}
}

func TestARuleIsRemovedByItsID(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
		{ID: "rt_2", Action: routing.Block, CIDR: netip.MustParsePrefix("192.0.2.0/24")},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	if err := h.exec(append([]string{"route", "rm", "rt_2"}, h.cfg()...)...); err != nil {
		t.Fatalf("route rm: %v", err)
	}

	stored := agent.stored()
	if len(stored) != 1 || stored[0].ID != "rt_1" {
		t.Errorf("stored %+v, want only the first rule left", stored)
	}
}

// Removing something that is not there writes nothing: a list one rule short of what
// somebody expected is a routing table nobody wrote.
func TestRemovingARuleThatIsNotThereWritesNothing(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	err := h.exec(append([]string{"route", "rm", "rt_absent"}, h.cfg()...)...)

	if err == nil {
		t.Fatal("removing a rule that is not in the list was accepted")
	}
	if agent.written != 0 {
		t.Errorf("wrote the list %d times, want none", agent.written)
	}
}

func TestARuleIsMovedToThePositionItWasGiven(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Via, Tunnel: "tn_office", Host: "**.example"},
		{ID: "rt_2", Action: routing.Direct, Host: "bank.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	if err := h.exec(append([]string{"route", "move", "rt_2", "1"}, h.cfg()...)...); err != nil {
		t.Fatalf("route move: %v", err)
	}

	stored := agent.stored()
	if len(stored) != 2 || stored[0].ID != "rt_2" || stored[1].ID != "rt_1" {
		t.Errorf("stored %+v, want the moved rule first and the other kept", stored)
	}
}

// The table names the row a rule sits at, because that number is what `route rm` and
// `route move` take and what a decision reports back.
func TestTheListNumbersEveryRuleAndSaysWhatItDoes(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Via, Tunnel: "tn_office", Host: "**.corp.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	if err := h.exec(append([]string{"route"}, h.cfg()...)...); err != nil {
		t.Fatalf("route: %v", err)
	}

	out := h.out()
	if !strings.Contains(out, "rt_1") || !strings.Contains(out, "Office") {
		t.Errorf("output = %q, want the rule's id and the connection it names", out)
	}
}

// An empty list says what happens instead, because a blank table reads as a page that
// failed to load rather than as a machine with no exceptions.
func TestAnEmptyListSaysEveryDestinationGoesTheUsualWay(t *testing.T) {
	h := newHarness(t, routingRoutes(t, &routingAgent{}))

	if err := h.exec(append([]string{"route"}, h.cfg()...)...); err != nil {
		t.Fatalf("route: %v", err)
	}

	if out := h.out(); !strings.Contains(out, "internet traffic setting") {
		t.Errorf("output = %q, want it to say where destinations go with no rules", out)
	}
}

// A rule that decides nothing on the network interface is named, rather than sitting in the
// table looking like it works.
func TestAShadowedRuleIsNamedUnderTheTable(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_wide", Action: routing.Block, CIDR: netip.MustParsePrefix("192.0.2.0/24")},
		{ID: "rt_inner", Action: routing.Direct, CIDR: netip.MustParsePrefix("192.0.2.128/25")},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	if err := h.exec(append([]string{"route"}, h.cfg()...)...); err != nil {
		t.Fatalf("route: %v", err)
	}

	out := h.out()
	if !strings.Contains(out, "rt_inner") || !strings.Contains(out, "decide nothing") {
		t.Errorf("output = %q, want the shadowed rule named", out)
	}
}

func TestCheckingADestinationSaysWhichConnectionCarriesIt(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Via, Tunnel: "tn_office", Host: "**.corp.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	if err := h.exec(append([]string{"route", "check", "db.corp.example"}, h.cfg()...)...); err != nil {
		t.Fatalf("route check: %v", err)
	}

	out := h.out()
	if !strings.Contains(out, "goes through Office") {
		t.Errorf("output = %q, want it to name the connection carrying the destination", out)
	}
}

func TestClearingTheListLeavesNoRules(t *testing.T) {
	agent := &routingAgent{rules: []routing.Rule{
		{ID: "rt_1", Action: routing.Direct, Host: "bank.example"},
	}}
	h := newHarness(t, routingRoutes(t, agent))

	if err := h.exec(append([]string{"route", "clear"}, h.cfg()...)...); err != nil {
		t.Fatalf("route clear: %v", err)
	}

	if stored := agent.stored(); len(stored) != 0 {
		t.Errorf("stored %+v after clearing, want nothing", stored)
	}
}
