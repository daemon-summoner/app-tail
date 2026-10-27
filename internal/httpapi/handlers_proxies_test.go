// SPDX-License-Identifier: MIT

package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/access"
	"github.com/sellitus/app-tail/internal/config"
)

// The instance list is the access screen. A client reads permissions and status from one
// answer, so a listener's rules can never be shown beside a status from a different poll.
func TestTheProxyListCarriesBothWhatIsGrantedAndWhatIsHappening(t *testing.T) {
	h := newHarness(t)

	body := decode[struct {
		Proxies []ProxyInstanceView `json:"proxies"`
	}](t, h.do(t, http.MethodGet, "/api/proxies", nil))

	if len(body.Proxies) != 1 {
		t.Fatalf("got %d instances, want the one every install has", len(body.Proxies))
	}
	held := body.Proxies[0]
	if held.ID != config.DefaultProxyID || held.Slug != config.DefaultProxySlug {
		t.Errorf("instance = %+v, want the default one", held)
	}
	if len(held.Rules) == 0 {
		t.Error("the instance carries no rules, so the grants list has nothing to show")
	}
	if len(held.Reach) == 0 {
		t.Error("the instance carries no reach sentences, so a person who does not read rule " +
			"tables never learns what they have granted")
	}
	if held.Listening == "" {
		t.Error("the instance carries no bound address, so a card cannot say where to point a program")
	}
}

// The instance card is the only place a user is told how to point a program at a listener, so
// every instance has to arrive carrying the ways to do it. A card with an address and no
// commands leaves the user assembling a socks5h URL by hand.
func TestEveryInstanceCarriesTheWaysToPointAProgramAtIt(t *testing.T) {
	h := newHarness(t)
	h.do(t, http.MethodPost, "/api/proxies", map[string]any{"name": "psql"})

	body := decode[struct {
		Proxies []ProxyInstanceView `json:"proxies"`
	}](t, h.do(t, http.MethodGet, "/api/proxies", nil))

	if len(body.Proxies) != 2 {
		t.Fatalf("got %d instances, want the default one and the added one", len(body.Proxies))
	}
	for _, view := range body.Proxies {
		if len(view.Snippets) == 0 {
			t.Errorf("%q carries no commands, so its card cannot say how to use it", view.Name)
		}
	}
}

// The auto-configuration script and the commands that go back through app-tail itself answer
// for the one instance the command line reaches. Offering them on another instance would
// point a browser at the default proxy's permissions from a card describing a different set.
func TestOnlyTheDefaultInstanceIsOfferedTheAutoConfigurationRoute(t *testing.T) {
	h := newHarness(t)
	added := decode[ProxyInstanceView](t, h.do(t, http.MethodPost, "/api/proxies",
		map[string]any{"name": "psql"}))

	if added.PACURL != "" {
		t.Errorf("pacUrl = %q on an added instance, want none: the script answers for the default one",
			added.PACURL)
	}
	for _, s := range added.Snippets {
		switch s.ID {
		case "exec", "ssh", "chromium", "firefox":
			t.Errorf("%q is offered for an added instance, which would point a program at the "+
				"default proxy's permissions", s.ID)
		}
	}

	held := decode[ProxyInstanceView](t, h.do(t, http.MethodGet, "/api/proxies/"+config.DefaultProxyID, nil))
	if held.PACURL == "" {
		t.Error("the default instance carries no pacUrl, so no browser can be auto-configured")
	}
}

// An instance with no commands must serialize as an array, for the reason the list does: a nil
// reaches a client as null, which a list renderer treats as a failure rather than as "none".
func TestAnInstanceWithNoCommandsCarriesAnArray(t *testing.T) {
	h := newHarness(t)
	h.proxies.held[0].Listening = ""

	rec := h.do(t, http.MethodGet, "/api/proxies/"+config.DefaultProxyID, nil)

	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"snippets":[]`) {
		t.Errorf("body = %q, want an empty array where the commands go", rec.Body.String())
	}
}

// An empty list must serialize as an array. A nil would reach a client as null, which every
// list renderer treats as a failure rather than as "no instances yet".
func TestAnEmptyProxyListIsAnArray(t *testing.T) {
	h := newHarness(t)
	h.proxies.held = nil

	rec := h.do(t, http.MethodGet, "/api/proxies", nil)

	if got := rec.Body.String(); got != "{\"proxies\":[]}\n" {
		t.Errorf("body = %q, want an empty array", got)
	}
}

func TestOneProxyIsFetchedByItsID(t *testing.T) {
	h := newHarness(t)

	view := decode[ProxyInstanceView](t, h.do(t, http.MethodGet, "/api/proxies/"+config.DefaultProxyID, nil))

	if view.ID != config.DefaultProxyID {
		t.Errorf("id = %q, want %q", view.ID, config.DefaultProxyID)
	}
}

func TestAProxyThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodGet, "/api/proxies/px_absent", nil), http.StatusNotFound)
}

// servedProxySchema is the schema as it reaches a client. The field metadata is decoded as
// maps because it is serialized with named kinds a client reads and the Go type does not
// parse back -- reading it as a map is what a client actually does.
type servedProxySchema struct {
	Fields    []map[string]any  `json:"fields"`
	Groups    []map[string]any  `json:"groups"`
	Modules   []map[string]any  `json:"modules"`
	Actions   []access.Action   `json:"actions"`
	Protocols []access.Protocol `json:"protocols"`
}

// The rule editor's dropdowns are built from what the agent offers, so a client never holds
// its own list -- which is how one ends up offering a verdict or a transport the agent
// refuses the moment it is saved.
func TestTheProxySchemaCarriesTheVocabularyOfARule(t *testing.T) {
	h := newHarness(t)

	served := decode[servedProxySchema](t, h.do(t, http.MethodGet, "/api/proxies/schema", nil))

	if len(served.Actions) != len(access.Actions) {
		t.Errorf("actions = %v, want every verdict a rule can carry", served.Actions)
	}
	if len(served.Protocols) != len(access.Protocols) {
		t.Errorf("protocols = %v, want every transport a rule can name", served.Protocols)
	}
	for _, offered := range served.Actions {
		if offered != access.Allow && offered != access.Deny {
			t.Errorf("action %q is offered, which is not a verdict the matcher decides by", offered)
		}
	}
}

// The form is rendered from the schema, so the schema has to carry the sections its fields
// name -- otherwise a client knows a field belongs to "proxy" and has no way to label it.
func TestTheProxySchemaCarriesItsSections(t *testing.T) {
	h := newHarness(t)

	served := decode[servedProxySchema](t, h.do(t, http.MethodGet, "/api/proxies/schema", nil))

	if len(served.Fields) == 0 {
		t.Fatal("the schema is empty, so the instance form would render nothing")
	}
	named := make(map[string]bool, len(served.Groups))
	for _, g := range served.Groups {
		named[g["id"].(string)] = true
	}
	for _, f := range served.Fields {
		if group, _ := f["group"].(string); !named[group] {
			t.Errorf("field %q is in section %q, which the schema does not describe", f["key"], group)
		}
	}
}

// And nothing but its sections: a section no instance field is in would put an empty panel
// on the form, and serving the whole settings list would put every settings section there.
func TestTheProxySchemaCarriesNoSectionWithoutAField(t *testing.T) {
	h := newHarness(t)

	served := decode[servedProxySchema](t, h.do(t, http.MethodGet, "/api/proxies/schema", nil))

	if len(served.Groups) == 0 {
		t.Fatal("the schema names no sections, so the form has nothing to head its fields with")
	}
	filled := make(map[string]bool, len(served.Fields))
	for _, f := range served.Fields {
		group, _ := f["group"].(string)
		filled[group] = true
	}
	for _, g := range served.Groups {
		if id, _ := g["id"].(string); !filled[id] {
			t.Errorf("section %q is served with no field in it", id)
		}
	}
}

// A field with no label and no kind renders as a bare box with no way to know what goes in
// it, which is the failure a schema-driven form has instead of a compile error.
func TestEveryServedProxyFieldCarriesWhatAFormNeeds(t *testing.T) {
	h := newHarness(t)

	served := decode[servedProxySchema](t, h.do(t, http.MethodGet, "/api/proxies/schema", nil))

	for _, f := range served.Fields {
		for _, needed := range []string{"key", "kind", "label", "help", "group"} {
			if value, _ := f[needed].(string); value == "" {
				t.Errorf("served field %v is missing %q", f["key"], needed)
			}
		}
	}
}

// The schema path must not be read as an instance id. Both are under /api/proxies/, and a
// mux that preferred the wildcard would answer a form request with "not found".
func TestTheProxySchemaPathIsNotMistakenForAnInstance(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/proxies/schema", nil)

	requireStatus(t, rec, http.StatusOK)
	if len(decode[servedProxySchema](t, rec).Fields) == 0 {
		t.Error("the schema route answered with an instance lookup")
	}
}

// Adding an instance answers with 201 rather than 200: a client that has just been handed a
// new id has to be able to tell it was created rather than matched against something there.
func TestAddingAProxyReturnsItAsCreated(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPost, "/api/proxies", map[string]any{"name": "psql"})

	requireStatus(t, rec, http.StatusCreated)
	view := decode[ProxyInstanceView](t, rec)
	if view.ID == "" || view.Name != "psql" {
		t.Errorf("created %+v, want the instance that was added", view)
	}
	if h.proxies.created == nil || h.proxies.created.Name != "psql" {
		t.Errorf("the module was asked for %+v, want the name the request named", h.proxies.created)
	}
	if len(h.proxies.List()) != 2 {
		t.Errorf("the list holds %d instances, want the one that was there plus the new one",
			len(h.proxies.List()))
	}
}

// A new instance reaches nothing until somebody grants it something, which is the only safe
// state for a listener to be created in -- and the answer has to say so rather than leave a
// blank where a grant list goes.
func TestANewProxyIsCreatedReachingNothing(t *testing.T) {
	h := newHarness(t)

	view := decode[ProxyInstanceView](t, h.do(t, http.MethodPost, "/api/proxies",
		map[string]any{"name": "psql"}))

	if len(view.Rules) != 0 {
		t.Errorf("rules = %+v, want a new instance to be granted nothing", view.Rules)
	}
	if len(view.Reach) != 1 || !strings.Contains(view.Reach[0], "nothing") {
		t.Errorf("reach = %v, want it to say the instance carries nothing yet", view.Reach)
	}
}

// An instance with no name is the caller's mistake, so it arrives as a rejection naming the
// control rather than as a fault in the agent.
func TestAddingAProxyWithoutANameIsRefused(t *testing.T) {
	h := newHarness(t)
	h.proxies.createErr = &config.ValidationError{
		Field:   "name",
		Message: "give this proxy a name; it is what the program you point at it is listed under",
	}

	rec := h.do(t, http.MethodPost, "/api/proxies", map[string]any{"name": ""})

	requireStatus(t, rec, http.StatusBadRequest)
	if body := decode[errorBody](t, rec); body.Field != "name" {
		t.Errorf("field = %q, want the rejected control named so the form can mark it", body.Field)
	}
}

func TestAMalformedProxyCreateIsRejected(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.doRaw(t, http.MethodPost, "/api/proxies", "{not json"),
		http.StatusBadRequest, "")
}

func TestRenamingAProxyReturnsItAsItNowStands(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPut, "/api/proxies/"+config.DefaultProxyID,
		map[string]any{"name": "Browser"})

	requireStatus(t, rec, http.StatusOK)
	if _, carried := h.proxies.patched["name"]; !carried {
		t.Errorf("the patch reached the module as %v, want the name key carried through",
			h.proxies.patched)
	}
	if len(h.proxies.patched) != 1 {
		t.Errorf("the patch carried %d keys, want only the one the request named",
			len(h.proxies.patched))
	}
}

func TestWritingToAProxyThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodPut, "/api/proxies/px_absent",
		map[string]any{"name": "Browser"}), http.StatusNotFound)
}

// Two instances asking for one address is refused whole, and the refusal is the user's to
// fix, so it arrives as a rejection with a reason rather than as a fault in the agent.
func TestAProxyMovedOntoATakenPortIsReportedAsABadRequest(t *testing.T) {
	h := newHarness(t)
	h.proxies.updateErr = &config.ValidationError{
		Field:   "proxy.listenAddr",
		Message: `127.0.0.1:1080 is already asked for by the proxy "psql"`,
	}

	rec := h.do(t, http.MethodPut, "/api/proxies/"+config.DefaultProxyID,
		map[string]any{"proxy.listenAddr": "127.0.0.1:1080"})

	requireStatus(t, rec, http.StatusBadRequest)
	body := decode[errorBody](t, rec)
	if body.Field != "proxy.listenAddr" {
		t.Errorf("field = %q, want the rejected control named so the form can mark it", body.Field)
	}
	if !strings.Contains(body.Error, "already asked for") {
		t.Errorf("error = %q, want it to say what the address is taken by", body.Error)
	}
}

func TestAMalformedProxyWriteIsRejected(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.doRaw(t, http.MethodPut, "/api/proxies/"+config.DefaultProxyID, "{not json"),
		http.StatusBadRequest, "")
}

// Rules are replaced whole and in order, because order is the meaning: the first matching
// rule decides. A write that reordered them on the way would move a deny below the allow it
// was written to except, and nothing on the page would show it had happened.
func TestSettingRulesReplacesTheWholeListInTheOrderItWasSent(t *testing.T) {
	h := newHarness(t)
	sent := []access.Rule{
		{ID: "ar_deny", Action: access.Deny, Tunnel: config.PrimaryTunnelID, Ports: []string{"22"}},
		{ID: "ar_allow", Action: access.Allow, Tunnel: config.PrimaryTunnelID},
	}

	rec := h.do(t, http.MethodPut, "/api/proxies/"+config.DefaultProxyID+"/rules",
		map[string]any{"rules": sent})

	requireStatus(t, rec, http.StatusOK)
	if len(h.proxies.rules) != 2 {
		t.Fatalf("the module was given %d rules, want both of them", len(h.proxies.rules))
	}
	if h.proxies.rules[0].ID != "ar_deny" || h.proxies.rules[1].ID != "ar_allow" {
		t.Errorf("rules reached the module as %+v, want them in the order they were sent",
			h.proxies.rules)
	}
	if view := decode[ProxyInstanceView](t, rec); len(view.Rules) != 2 {
		t.Errorf("the answer carries %d rules, want the list as it now stands", len(view.Rules))
	}
}

// An empty list is a grant of nothing, not a missing field: an instance whose rules were all
// removed reaches nothing, and refusing the write would leave no way to say so.
func TestAnEmptyRuleListIsAGrantOfNothing(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodPut, "/api/proxies/"+config.DefaultProxyID+"/rules",
		map[string]any{"rules": []access.Rule{}})

	requireStatus(t, rec, http.StatusOK)
	if len(h.proxies.rules) != 0 {
		t.Errorf("the module was given %+v, want the empty list the request carried",
			h.proxies.rules)
	}
}

// A rule naming a connection that is not configured is refused whole, so the instance keeps
// the permissions it had rather than being left with a list half of which cannot be matched.
func TestARuleNamingAConnectionThatIsNotConfiguredIsRefused(t *testing.T) {
	h := newHarness(t)
	h.proxies.rulesErr = &config.ValidationError{
		Field:   "rules",
		Message: `rule 1 names connection "tn_absent", which is not configured`,
	}

	rec := h.do(t, http.MethodPut, "/api/proxies/"+config.DefaultProxyID+"/rules",
		map[string]any{"rules": []access.Rule{{Action: access.Allow, Tunnel: "tn_absent"}}})

	requireStatus(t, rec, http.StatusBadRequest)
	body := decode[errorBody](t, rec)
	if body.Field != "rules" {
		t.Errorf("field = %q, want the rejected control named so the editor can mark it", body.Field)
	}
	if !strings.Contains(body.Error, "tn_absent") {
		t.Errorf("error = %q, want it to name the connection the rule could not be matched against",
			body.Error)
	}
}

func TestSettingRulesOnAProxyThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodPut, "/api/proxies/px_absent/rules",
		map[string]any{"rules": []access.Rule{}}), http.StatusNotFound)
}

func TestAMalformedRuleListIsRejected(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.doRaw(t, http.MethodPut,
		"/api/proxies/"+config.DefaultProxyID+"/rules", "{not json"), http.StatusBadRequest, "")
}

// Removing one answers with no content: there is no instance left to describe, and a body
// would have to invent one.
func TestRemovingAProxyAnswersWithNoContent(t *testing.T) {
	h := newHarness(t)
	added := decode[ProxyInstanceView](t, h.do(t, http.MethodPost, "/api/proxies",
		map[string]any{"name": "psql"}))

	requireStatus(t, h.do(t, http.MethodDelete, "/api/proxies/"+added.ID, nil), http.StatusNoContent)

	if len(h.proxies.deleted) != 1 || h.proxies.deleted[0] != added.ID {
		t.Errorf("the module was asked to remove %v, want the instance the path named",
			h.proxies.deleted)
	}
	if len(h.proxies.List()) != 1 {
		t.Errorf("the list holds %d instances, want the added one gone", len(h.proxies.List()))
	}
}

// The one instance every install has cannot be removed, because it is where this
// installation's own proxy settings are applied. The refusal is a rejection naming the
// control, not a fault.
func TestRemovingTheDefaultProxyIsRefused(t *testing.T) {
	h := newHarness(t)
	h.proxies.deleteErr = &config.ValidationError{
		Field:   "id",
		Message: "the default proxy cannot be removed: it is where this installation's own proxy settings are applied",
	}

	rec := h.do(t, http.MethodDelete, "/api/proxies/"+config.DefaultProxyID, nil)

	requireStatus(t, rec, http.StatusBadRequest)
	if body := decode[errorBody](t, rec); body.Field != "id" {
		t.Errorf("field = %q, want the refusal to name what it is about", body.Field)
	}
}

func TestRemovingAProxyThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodDelete, "/api/proxies/px_absent", nil), http.StatusNotFound)
}

// The test endpoint is what makes rule order visible: it names the line that decided, which
// is what somebody editing rules needs in order to know which one they are changing.
func TestTestingADestinationNamesTheRuleThatDecided(t *testing.T) {
	h := newHarness(t)
	h.proxies.verdict = ProxyTestResult{
		Allowed: true, Resolved: "10.0.0.5:5432",
		Tunnel: config.PrimaryTunnelID, TunnelName: "Tailnet",
		Rule: "ar_db", RuleIndex: 2,
		Reason: "rule 2 allows port 5432 on Tailnet",
	}

	result := decode[ProxyTestResult](t, h.do(t, http.MethodPost,
		"/api/proxies/"+config.DefaultProxyID+"/test",
		map[string]any{"address": "db.corp.internal:5432", "protocol": "tcp"}))

	if !result.Allowed || result.Rule != "ar_db" || result.RuleIndex != 2 {
		t.Errorf("result = %+v, want the verdict with the rule that decided", result)
	}
	if result.Address != "db.corp.internal:5432" {
		t.Errorf("address = %q, want the destination that was asked about", result.Address)
	}
	if len(h.proxies.tested) != 1 || h.proxies.tested[0].Protocol != "tcp" {
		t.Errorf("the module was asked %+v, want the destination and transport the request named",
			h.proxies.tested)
	}
}

// A refusal is the answer, not the request's failure. Reporting it as an error would put a
// correctly-refused destination on the page as a broken proxy.
func TestARefusedDestinationIsTheAnswerRatherThanAnError(t *testing.T) {
	h := newHarness(t)
	h.proxies.verdict = ProxyTestResult{
		Allowed: false, Resolved: "10.0.0.5:22", Tunnel: config.PrimaryTunnelID,
		Reason: "no rule allows it, so it is refused",
	}

	rec := h.do(t, http.MethodPost, "/api/proxies/"+config.DefaultProxyID+"/test",
		map[string]any{"address": "10.0.0.5:22"})

	requireStatus(t, rec, http.StatusOK)
	result := decode[ProxyTestResult](t, rec)
	if result.Allowed {
		t.Error("the destination came back allowed, want the refusal the module decided")
	}
	if result.Reason == "" {
		t.Error("the refusal carries no reason, so the page has nothing to show for it")
	}
}

// An address with no port is a question the matcher cannot answer -- ports are part of what
// a rule decides -- so it is refused before the module is asked.
func TestTestingAnAddressWithNoPortIsRefused(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.do(t, http.MethodPost, "/api/proxies/"+config.DefaultProxyID+"/test",
		map[string]any{"address": "db.corp.internal"}), http.StatusBadRequest, "host:port")

	if len(h.proxies.tested) != 0 {
		t.Errorf("the module was asked %+v, want the malformed destination refused first",
			h.proxies.tested)
	}
}

func TestTestingWithNoAddressIsRefused(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.do(t, http.MethodPost, "/api/proxies/"+config.DefaultProxyID+"/test",
		map[string]any{"address": "   "}), http.StatusBadRequest, "address is required")
}

// A transport the matcher does not decide by is refused rather than read as "any": the two
// readings are opposite, and guessing would answer for a protocol nobody asked about.
func TestTestingOverATransportTheMatcherDoesNotKnowIsRefused(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.do(t, http.MethodPost, "/api/proxies/"+config.DefaultProxyID+"/test",
		map[string]any{"address": "10.0.0.5:22", "protocol": "sctp"}), http.StatusBadRequest, "tcp or udp")

	if len(h.proxies.tested) != 0 {
		t.Errorf("the module was asked %+v, want the unknown transport refused first",
			h.proxies.tested)
	}
}

// An unnamed transport is tcp, which is what a proxy carries unless the caller says
// otherwise, so leaving it out must not be refused.
func TestTestingWithNoTransportNamedIsAllowedThrough(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodPost, "/api/proxies/"+config.DefaultProxyID+"/test",
		map[string]any{"address": "10.0.0.5:22"}), http.StatusOK)
}

func TestTestingAProxyThatDoesNotExistIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(t, http.MethodPost, "/api/proxies/px_absent/test",
		map[string]any{"address": "10.0.0.5:22"}), http.StatusNotFound)
}

// A broken instance is a fault rather than a verdict: it could not decide, and answering
// "refused" would report a working refusal where there was none.
func TestAProxyThatCouldNotDecideIsReportedAsAFault(t *testing.T) {
	h := newHarness(t)
	h.proxies.testErr = fmt.Errorf("the resolver is not running")

	requireStatus(t, h.do(t, http.MethodPost, "/api/proxies/"+config.DefaultProxyID+"/test",
		map[string]any{"address": "10.0.0.5:22"}), http.StatusInternalServerError)
}

func TestAMalformedProxyTestIsRejected(t *testing.T) {
	h := newHarness(t)

	requireError(t, h.doRaw(t, http.MethodPost,
		"/api/proxies/"+config.DefaultProxyID+"/test", "{not json"), http.StatusBadRequest, "")
}
