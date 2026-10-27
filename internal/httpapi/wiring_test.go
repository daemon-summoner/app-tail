// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

type declaredRoute struct {
	method string
	path   string
}

// declaredRoutes is the server's own route table, so a route added without a require()
// guard is covered by the tests below the moment it is written, which is the only way
// this stays true a year from now. A table that yields nothing is a failure, not an
// empty pass: silently covering zero routes is exactly the outcome this guards.
func declaredRoutes(t *testing.T) []declaredRoute {
	t.Helper()

	var routes []declaredRoute
	for _, rt := range New(Options{Auth: testKeys}).routeTable() {
		method, path := http.MethodGet, rt.pattern
		if verb, rest, found := strings.Cut(rt.pattern, " "); found {
			method, path = verb, rest
		}
		// Path wildcards need a concrete value; the id is never found, which is the
		// point -- these tests are about the guard, not the lookup.
		path = strings.NewReplacer("{id}", "f_absent").Replace(path)
		routes = append(routes, declaredRoute{method: method, path: path})
	}
	if len(routes) < 20 {
		t.Fatalf("found only %d routes in the route table; these tests are no longer covering it", len(routes))
	}
	return routes
}

// An agent whose dependencies are not wired yet -- the window between the HTTP listener
// binding and the node coming up -- must answer every route with a clear 503. A route
// added without its require() guard dereferences a nil interface instead, which the
// panic barrier turns into a 500 and, without that barrier, would kill the agent.
func TestEveryRouteAnswers503WhenItsDependencyIsNotWired(t *testing.T) {
	for _, r := range declaredRoutes(t) {
		// The sign-in routes answer from the authenticator New requires, so they have no
		// optional dependency to be missing; their own tests cover them.
		if strings.HasPrefix(r.path, "/api/auth/") {
			continue
		}
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			h := newHarness(t)
			h.server.deps = Deps{Version: "test"}

			rec := h.doRaw(t, r.method, r.path, "{}")

			if rec.Code == http.StatusInternalServerError {
				t.Fatalf("answered 500 with nothing wired: %s\nthis route is missing its "+
					"require() guard and only the panic barrier kept the agent alive",
					rec.Body.String())
			}
			// The dashboard route is the one exception: with no embedded UI it reports
			// its own unavailability, and it is not an API endpoint.
			if r.path == "/" {
				if rec.Code != http.StatusServiceUnavailable {
					t.Errorf("dashboard route = %d with no UI embedded, want 503", rec.Code)
				}
				return
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503: %s", rec.Code, rec.Body.String())
			}
			// The readiness probe answers in the shape a supervisor parses rather than
			// the API error envelope; its own test below covers that body.
			if r.path == "/healthz" {
				return
			}
			// The message has to name what is missing; "service unavailable" alone
			// leaves an operator with nothing to act on.
			if body := decode[errorBody](t, rec); body.Error == "" {
				t.Errorf("503 carried an empty reason: %s", rec.Body.String())
			}
		})
	}
}

// Each dependency guards its own routes. Wiring the node but not the forwards -- the
// real order the agent starts in -- must leave the node routes working rather than
// failing everything together.
func TestOneMissingDependencyDoesNotTakeTheOtherRoutesDown(t *testing.T) {
	h := newHarness(t)
	h.server.deps.Forwards = nil

	if rec := h.do(t, http.MethodGet, "/api/status", nil); rec.Code != http.StatusOK {
		t.Errorf("GET /api/status = %d with only the forwards missing, want 200: %s",
			rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodGet, "/api/settings", nil); rec.Code != http.StatusOK {
		t.Errorf("GET /api/settings = %d with only the forwards missing, want 200: %s",
			rec.Code, rec.Body.String())
	}

	rec := h.do(t, http.MethodGet, "/api/forwards", nil)
	requireStatus(t, rec, http.StatusServiceUnavailable)
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "forwards") {
		t.Errorf("error = %q, want it to name the missing dependency", body.Error)
	}
}

// The readiness probe has its own guard rather than require(), because a probe must
// answer in the shape a supervisor parses even when nothing is wired.
func TestHealthzAnswersInItsOwnShapeWhileTheAgentIsStillStartingUp(t *testing.T) {
	h := newHarness(t)
	h.server.deps = Deps{Version: "test"}

	rec := h.do(t, http.MethodGet, "/healthz", nil)
	requireStatus(t, rec, http.StatusServiceUnavailable)

	body := decode[struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}](t, rec)
	if body.Status != "unhealthy" {
		t.Errorf("status = %q, want %q", body.Status, "unhealthy")
	}
	if body.Reason == "" {
		t.Error("the probe gave no reason; an operator watching a 503 cannot act on it")
	}
}

// The schema endpoint is what lets a client render settings without hardcoding the
// field list, and it is the same registry the dashboard's generated types come from.
// Serving a subset would leave fields the API accepts but no client can discover.
func TestTheSettingsSchemaEndpointServesTheWholeRegistry(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/settings/schema", nil)
	requireStatus(t, rec, http.StatusOK)

	type schemaBody struct {
		Fields  []map[string]any `json:"fields"`
		Groups  []map[string]any `json:"groups"`
		Modules []map[string]any `json:"modules"`
	}
	served := decode[schemaBody](t, rec)
	want := h.settings.Schema()
	if len(served.Fields) != len(want) {
		t.Fatalf("served %d fields, the registry has %d", len(served.Fields), len(want))
	}

	servedKeys := make(map[string]bool, len(served.Fields))
	for _, f := range served.Fields {
		key, _ := f["key"].(string)
		if key == "" {
			t.Fatalf("a served field has no key: %+v", f)
		}
		servedKeys[key] = true
	}
	for _, f := range want {
		if !servedKeys[f.Key] {
			t.Errorf("field %q is in the registry but not in the served schema", f.Key)
		}
	}

	// The metadata is the payload: a schema without it renders every field as a bare
	// text box, including the secrets.
	first := served.Fields[0]
	for _, field := range []string{"key", "viewKey", "kind", "secret", "readOnly", "restart", "write", "label", "group", "tier", "module", "help"} {
		if _, ok := first[field]; !ok {
			t.Errorf("served schema entry is missing %q: %+v", field, first)
		}
	}

	// Fields name their section and their module by id. Without the tables a client
	// has an id it cannot turn into a heading or a switch, so it drops the control.
	if len(served.Groups) == 0 {
		t.Error("the schema serves no sections, so every field names a heading the client cannot label")
	}
	if len(served.Modules) == 0 {
		t.Error("the schema serves no modules, so a client cannot offer the switch that reveals one")
	}
	for _, m := range served.Modules {
		if key, _ := m["switchKey"].(string); key == "" {
			t.Errorf("module %+v names no switch key, so nothing can turn it on", m)
		}
	}
}
