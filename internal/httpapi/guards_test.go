// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The panic barrier is the difference between one bad handler returning a 500 and the
// whole agent dying: net/http would otherwise kill the connection, and a panic in a
// goroutine the handler spawned would take the process with it. Every forward the user
// runs stops with it, so this is the guard with the widest blast radius in the package.
func TestAPanickingHandlerAnswers500RatherThanKillingTheAgent(t *testing.T) {
	h := newHarness(t)
	h.server.deps.Forwards = &panickingForwards{panicOn: "hunter2"}

	rec := h.do(t, http.MethodGet, "/api/forwards", nil)

	requireStatus(t, rec, http.StatusInternalServerError)

	body := rec.Body.String()
	// The panic value carries whatever the handler happened to be holding -- here a
	// credential. Echoing it turns a crash into a disclosure, so the barrier must
	// answer with a fixed message and leave the detail in the log.
	for _, leak := range []string{"hunter2", "exploded", "panic"} {
		if strings.Contains(body, leak) {
			t.Errorf("the 500 body leaked %q from the panic value: %s", leak, body)
		}
	}
	if got := decode[errorBody](t, rec).Error; got != "internal error" {
		t.Errorf("error = %q, want the fixed %q", got, "internal error")
	}
}

// The readiness probe is what a supervisor polls. A panic there that took the process
// down would make the agent look unhealthy by dying, which is the one failure mode a
// health endpoint must never cause.
func TestAPanicInTheReadinessProbeIsContained(t *testing.T) {
	h := newHarness(t)
	h.server.deps.Forwards = &panickingForwards{panicOn: "readiness"}

	rec := h.do(t, http.MethodGet, "/healthz", nil)

	requireStatus(t, rec, http.StatusInternalServerError)
	if got := decode[errorBody](t, rec).Error; got != "internal error" {
		t.Errorf("error = %q, want the fixed %q", got, "internal error")
	}
}

// A handler that panics after committing its status line cannot have that status
// rewritten -- the bytes are already on the wire. The barrier still has to swallow the
// panic, because the alternative is the connection being torn down and the agent
// exiting; the client sees a truncated 200 and retries, which is survivable.
func TestAPanicAfterTheResponseBeganStillDoesNotEscape(t *testing.T) {
	h := newHarness(t)

	guarded := h.server.withGuards(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"forwards":[`)); err != nil {
			t.Errorf("write partial body: %v", err)
		}
		panic("handler blew up halfway through the list")
	}))

	rec := httptest.NewRecorder()
	// A panic escaping here fails the test by crashing it, which is the point.
	guarded.ServeHTTP(rec, newAPIRequest(http.MethodGet, "/api/forwards", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; a status line already sent cannot be taken back", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `{"forwards":[`) {
		t.Errorf("the partial body was lost: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "blew up halfway") {
		t.Errorf("the panic value reached the client: %s", rec.Body.String())
	}
}

// The hardening headers are set before the handler runs, so they must survive a panic
// too: a 500 is exactly the response a hostile page can most easily provoke, and it
// would otherwise be the one response served without a CSP or nosniff.
func TestA500FromThePanicBarrierStillCarriesTheHardeningHeaders(t *testing.T) {
	h := newHarness(t)
	h.server.deps.Forwards = &panickingForwards{panicOn: "headers"}

	rec := h.do(t, http.MethodGet, "/api/forwards", nil)
	requireStatus(t, rec, http.StatusInternalServerError)

	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q on a panic response, want %q", header, got, want)
		}
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("a panic response carries no Content-Security-Policy")
	}
}

// A page on another site can reach a loopback address, and the browser says so on the
// request. Nothing this agent serves is ever a cross-site subresource.
func TestACrossSiteRequestIsRefused(t *testing.T) {
	h := newHarness(t)

	req := newAPIRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want the request refused (body: %s)", rec.Code, rec.Body.String())
	}

	// The values a browser sends for its own page, and the absence every other caller
	// sends, all still reach the handler.
	for _, site := range []string{"same-origin", "same-site", "none", ""} {
		req := newAPIRequest(http.MethodGet, "/api/status", nil)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		rec := httptest.NewRecorder()
		h.server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Sec-Fetch-Site %q was refused with %d", site, rec.Code)
		}
	}
}

// A failure nothing anticipated carries whatever the operating system put in it, and on a
// real machine that is the account name and the directories this agent keeps its state and
// its privileged socket in. The sentence is what makes the failure actionable and stays; the
// description of the machine goes, and the reference is how the whole of it is found again.
func TestAnUnanticipatedFailureNamesNoPathAndCarriesAReference(t *testing.T) {
	h := newHarness(t)
	h.node.loginErr = errors.New(
		`open /Users/someone/Library/Application Support/app-tail/config.json: permission denied`)

	rec := h.do(t, http.MethodPost, "/api/login", nil)
	requireStatus(t, rec, http.StatusInternalServerError)

	body := decode[errorBody](t, rec)
	for _, leak := range []string{"/Users", "someone", "Application Support"} {
		if strings.Contains(body.Error, leak) {
			t.Errorf("the 500 body leaked %q, which describes the machine rather than the failure: %s", leak, body.Error)
		}
	}
	// What went wrong survives it, or the caller is left with a reference and no idea
	// what happened.
	for _, kept := range []string{"config.json", "permission denied"} {
		if !strings.Contains(body.Error, kept) {
			t.Errorf("the 500 body dropped %q, so nothing says what failed: %s", kept, body.Error)
		}
	}
	if body.Ref == "" {
		t.Error("the 500 body carries no reference, so the full sentence in the log cannot be found")
	}
}

// The redaction runs over every message, so what it must never do is mangle the parts of a
// sentence that are not paths at all.
func TestRedactingPathsLeavesTheRestOfTheSentenceAlone(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"no paths here at all", "no paths here at all"},
		{"port 18100 is already in use", "port 18100 is already in use"},
		{
			"open /Users/someone/.state/config.json: permission denied",
			"open .../config.json: permission denied",
		},
		{
			`dial unix /var/run/app-tail/helper.sock: connect: no such file or directory`,
			`dial unix .../helper.sock: connect: no such file or directory`,
		},
		{
			`C:\Users\someone\AppData\Local\app-tail\config.json is not readable`,
			`.../config.json is not readable`,
		},
		{
			"a directory: /Users/someone/.state/",
			"a directory: .../.state/",
		},
		// A URL is not a filesystem path, and the one this app shows most is the login
		// URL somebody has to be able to read and open.
		{
			"visit https://login.example/auth/abc to finish",
			"visit https://login.example/auth/abc to finish",
		},
		{
			"resolve https://dns.example/dns-query/token: no such host",
			"resolve https://dns.example/dns-query/token: no such host",
		},
		// A bare filename is already as short as it goes.
		{"config.json is not readable", "config.json is not readable"},
		{"/etc: permission denied", "/etc: permission denied"},
	}
	for _, tt := range tests {
		if got := redactMachinePaths(tt.in); got != tt.want {
			t.Errorf("redactMachinePaths(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
