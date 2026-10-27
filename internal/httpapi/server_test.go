// SPDX-License-Identifier: MIT

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// The management API speaks plain HTTP. Binding it anywhere but loopback would put
// its token and every answer on the local network, so the refusal is a security
// boundary, not a preference.
func TestListenRefusesNonLoopbackAddresses(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:8377",
		"[::]:8377",
		"192.168.1.10:8377",
		":8377",
	} {
		t.Run(addr, func(t *testing.T) {
			s := New(Options{Auth: testKeys})
			bound, err := s.Listen(addr)
			if err == nil {
				s.Shutdown(context.Background())
				t.Fatalf("Listen(%q) succeeded and bound %v, want a refusal", addr, bound)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("Listen(%q) failed with %v, which does not explain the loopback rule", addr, err)
			}
			if s.Addr() != nil {
				t.Fatalf("a refused Listen still recorded an address: %v", s.Addr())
			}
		})
	}
}

func TestListenAcceptsLoopbackAddresses(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		t.Run(addr, func(t *testing.T) {
			s := New(Options{Auth: testKeys})
			bound, err := s.Listen(addr)
			if err != nil {
				// IPv4 loopback is universally available, so a failure there is a
				// regression in Listen. The IPv6 forms genuinely are absent on some
				// hosts and containers, and only those may be skipped.
				if addr == "127.0.0.1:0" {
					t.Fatalf("Listen(%q) failed: %v", addr, err)
				}
				t.Skipf("IPv6 loopback %q is not available on this host: %v", addr, err)
			}
			defer s.Shutdown(context.Background())

			host, _, err := net.SplitHostPort(bound.String())
			if err != nil {
				t.Fatalf("parse bound address %q: %v", bound, err)
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				t.Fatalf("bound to %q, which is not loopback", bound)
			}
		})
	}
}

// A server can bind its port and then fail before it ever serves -- that is exactly
// what happens when the tailnet node refuses to start. Shutdown has to release the
// port anyway, or the next attempt to bind it fails and the dashboard is lost until
// the process is killed.
func TestShutdownReleasesThePortEvenWhenServeNeverRan(t *testing.T) {
	s := New(Options{Auth: testKeys})
	bound, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := bound.String()

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %s was still held after Shutdown: %v", addr, err)
	}
	ln.Close()
}

// Shutting down a server that did serve must stay clean: net/http closes the
// listener itself there, so the second close has to be tolerated rather than
// reported as a failure.
func TestShutdownAfterServingReportsNoError(t *testing.T) {
	s := New(Options{Auth: testKeys})
	bound, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	served := make(chan error, 1)
	go func() { served <- s.Serve() }()

	// Serve must be inside the accept loop before Shutdown, or this proves nothing.
	conn, err := net.DialTimeout("tcp", bound.String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial the served address: %v", err)
	}
	conn.Close()

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown after serving: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("Serve returned %v, want a clean stop", err)
	}
	ln, err := net.Listen("tcp", bound.String())
	if err != nil {
		t.Fatalf("port %s was still held after Shutdown: %v", bound, err)
	}
	ln.Close()
}

func TestListenRejectsAnUnparsableAddress(t *testing.T) {
	s := New(Options{Auth: testKeys})
	if _, err := s.Listen("not-an-address"); err == nil {
		t.Fatal("Listen accepted an address with no port")
	}
}

func TestServeBeforeListenFails(t *testing.T) {
	s := New(Options{Auth: testKeys})
	if err := s.Serve(); err == nil {
		t.Fatal("Serve succeeded without a listener")
	}
}

// End-to-end over a real socket: the routed handler must answer on the port the
// agent will persist.
func TestServeAnswersOverTheBoundSocket(t *testing.T) {
	h := newHarness(t)
	addr, err := h.server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- h.server.Serve() }()
	t.Cleanup(func() {
		if err := h.server.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/api/status", addr), nil)
	if err != nil {
		t.Fatalf("build GET /api/status: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), `"backendState"`) {
		t.Fatalf("body = %s", body)
	}
}

func TestShutdownBeforeListenIsANoOp(t *testing.T) {
	if err := New(Options{Auth: testKeys}).Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before Listen returned %v", err)
	}
}

// --- cross-origin protection ---------------------------------------------

// --- host guard -----------------------------------------------------------

// DNS rebinding: an attacker's page loads from a name they control, then that name
// is re-resolved to 127.0.0.1. Every subsequent request is *same-origin*, so the
// Origin guard below never fires -- the dialed Host is the only remaining signal.
// What is at stake is concrete: /api/status hands out the pending Tailscale auth
// URL, which is a bearer capability to enroll a device into the user's tailnet.
func TestRebindingHostsAreRefusedAndLeakNothing(t *testing.T) {
	for _, host := range []string{
		"attacker.example",
		"attacker.example:8377",
		// A suffix match rather than a label match would let both of these through.
		"evil.localhost.attacker.example",
		"notlocalhost",
		"192.168.1.10:8377",
	} {
		t.Run(host, func(t *testing.T) {
			h := newHarness(t)
			h.node.status.AuthURL = "https://login.example/auth/secret-capability"

			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)

			requireStatus(t, rec, http.StatusForbidden)
			if body := rec.Body.String(); strings.Contains(body, "secret-capability") {
				t.Fatalf("refused response still disclosed the auth URL: %s", body)
			}
		})
	}
}

// The guard must not reject the names the dashboard is actually reached by. The
// port is deliberately unchecked: the Vite dev proxy forwards the browser's own
// "localhost:5173" verbatim.
func TestLoopbackHostsAreServed(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1:8377",
		"127.0.0.1",
		"localhost:5173",
		"localhost",
		"localhost.",
		"app-tail.localhost:8377",
		"[::1]:8377",
		"[::1]",
		"127.99.4.2:8377",
	} {
		t.Run(host, func(t *testing.T) {
			h := newHarness(t)
			req := newAPIRequest(http.MethodGet, "/api/status", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)

			requireStatus(t, rec, http.StatusOK)
		})
	}
}

// Go rejects an HTTP/1.1 request without a Host before any handler runs, and no
// browser omits one, so refusing an empty Host blocks no rebinding attack -- it
// only breaks HTTP/1.0 probes and hand-rolled health checks.
func TestAnEmptyHostIsServed(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = ""
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	// The probe has to be answered, not merely not-forbidden: a 500 or a 404 would
	// also clear a "not 403" check while leaving the healthcheck permanently red.
	requireStatus(t, rec, http.StatusOK)

	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("healthz body %s is not the readiness document: %v", rec.Body.String(), err)
	}
	if body.Status != "ok" {
		t.Errorf("healthz reported %q (%s) over a healthy harness", body.Status, body.Reason)
	}
}

// The guard covers the SPA too: rebinding to read index.html is how an attacker
// gets same-origin script into the page in the first place.
func TestTheHostGuardCoversDashboardRoutes(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	requireStatus(t, rec, http.StatusForbidden)
}

// A user who reached the agent over "ssh -L" under a machine name has no other
// clue what went wrong, so the refusal has to name the address that does work.
func TestTheHostRefusalNamesTheAddressThatWorks(t *testing.T) {
	h := newHarness(t)
	if _, err := h.server.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h.server.Shutdown(ctx)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Host = "workstation.internal"
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	requireStatus(t, rec, http.StatusForbidden)
	bound := "http://" + h.server.ln.Addr().String() + "/"
	if body := rec.Body.String(); !strings.Contains(body, bound) {
		t.Fatalf("refusal did not point at %s: %s", bound, body)
	}
}

// --- origin guard ---------------------------------------------------------

// Loopback means any page in the user's browser can reach this API. Without an
// origin check, a visited website could silently create a forward exposing a local
// service to the tailnet.
func TestCrossOriginWritesAreRefused(t *testing.T) {
	h := newHarness(t)
	for _, origin := range []string{
		"https://evil.example",
		"http://attacker.test:8080",
		"null",
	} {
		t.Run(origin, func(t *testing.T) {
			req := newAPIRequest(http.MethodDelete, "/api/forwards/anything", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)

			requireStatus(t, rec, http.StatusForbidden)
		})
	}
}

// Every loopback spelling a user can reach the dashboard by has to keep working,
// including the Vite dev server, which forwards its own authority verbatim.
func TestWritesFromThePageTheAgentServedAreAllowed(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1:8377",
		"localhost:5173",
		"[::1]:8377",
		"app-tail.localhost:8377",
	} {
		t.Run(host, func(t *testing.T) {
			h := newHarness(t)
			req := newAPIRequest(http.MethodPost, "/api/login", nil)
			req.Host = host
			req.Header.Set("Origin", "http://"+host)
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)

			requireStatus(t, rec, http.StatusOK)
		})
	}
}

// A loopback-looking name is not proof of who controls the page behind it: a
// resolver that forwards *.localhost upstream hands a remote attacker an origin that
// any loopback allowlist would accept. Only the agent's own authority may write.
func TestAWriteFromAnotherLoopbackNameIsRefused(t *testing.T) {
	for _, origin := range []string{
		"http://evil.localhost",
		"http://evil.localhost:8377",
		"http://localhost:8377",
		"http://[::1]:8377",
	} {
		t.Run(origin, func(t *testing.T) {
			h := newHarness(t)
			// The dashboard here was served from 127.0.0.1:8377, so none of these is
			// the page the agent handed out, however loopback-shaped they look.
			// A fully valid spec on purpose: a body the handler would reject anyway
			// proves nothing about whether the guard stopped it.
			body, err := json.Marshal(llmForward())
			if err != nil {
				t.Fatalf("marshal spec: %v", err)
			}
			req := newAPIRequest(http.MethodPost, "/api/forwards", bytes.NewReader(body))
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)

			requireStatus(t, rec, http.StatusForbidden)
			if h.forwards.createCalled != 0 {
				t.Fatalf("the refused write still reached Create %d time(s)", h.forwards.createCalled)
			}
		})
	}
}

// The three body types an HTML form can send, none of which this API takes. A form
// needs no preflight, so it is the one way a hostile page reaches a write without the
// browser first asking permission -- and the Origin and Sec-Fetch-Site checks are
// header-based, so a client that sends neither leaves them nothing to compare. What
// the form cannot do is declare its body as JSON, which is why the declaration is
// what is required.
func TestAWriteDeclaringAFormBodyIsRefused(t *testing.T) {
	for _, contentType := range []string{
		"text/plain",
		"text/plain;charset=UTF-8",
		"application/x-www-form-urlencoded",
		"multipart/form-data; boundary=----x",
	} {
		t.Run(contentType, func(t *testing.T) {
			h := newHarness(t)
			// A spec the handler would accept, so a refusal is the guard's doing and
			// not the body failing validation further in.
			body, err := json.Marshal(llmForward())
			if err != nil {
				t.Fatalf("marshal spec: %v", err)
			}
			req := newAPIRequest(http.MethodPost, "/api/forwards", bytes.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)

			requireStatus(t, rec, http.StatusUnsupportedMediaType)
			if h.forwards.createCalled != 0 {
				t.Fatalf("the refused write still reached Create %d time(s)", h.forwards.createCalled)
			}
		})
	}
}

// A header nothing can be read out of is refused rather than passed over. The guard's
// question is whether the body is JSON, and an unreadable header is not an answer to it --
// treating it as one would put the form bodies above back within reach of anything that can
// make the header unparseable.
func TestAWriteWhoseContentTypeCannotBeReadIsRefused(t *testing.T) {
	h := newHarness(t)
	body, err := json.Marshal(llmForward())
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	req := newAPIRequest(http.MethodPost, "/api/forwards", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset")
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	requireStatus(t, rec, http.StatusUnsupportedMediaType)
	if h.forwards.createCalled != 0 {
		t.Fatalf("the refused write still reached Create %d time(s)", h.forwards.createCalled)
	}
}

// The dashboard and the CLI both declare JSON, with and without a charset, and a write
// that does so has to go through: a guard that refuses the callers it exists to protect
// is an outage, not a defence.
func TestAWriteDeclaringJSONIsAccepted(t *testing.T) {
	for _, contentType := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"APPLICATION/JSON",
	} {
		t.Run(contentType, func(t *testing.T) {
			h := newHarness(t)
			body, err := json.Marshal(llmForward())
			if err != nil {
				t.Fatalf("marshal spec: %v", err)
			}
			req := newAPIRequest(http.MethodPost, "/api/forwards", bytes.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)

			requireStatus(t, rec, http.StatusCreated)
			if h.forwards.createCalled != 1 {
				t.Fatalf("Create was reached %d time(s), want once", h.forwards.createCalled)
			}
		})
	}
}

// Half the CLI's writes carry no body -- logout, restart, every delete -- and so declare
// no type at all. Requiring the header unconditionally would refuse every one of them.
func TestAWriteWithNoBodyNeedsNoContentType(t *testing.T) {
	h := newHarness(t)
	req := newAPIRequest(http.MethodPost, "/api/login", nil)
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	requireStatus(t, rec, http.StatusOK)
}

// Reads are safe to serve regardless of origin; the browser's own CORS rules stop
// the response from being read cross-origin.
func TestCrossOriginReadsAreNotRefused(t *testing.T) {
	h := newHarness(t)
	req := newAPIRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	requireStatus(t, rec, http.StatusOK)
}

// Same-origin requests from the dashboard carry no Origin header on some browsers;
// refusing them would break the app itself.
func TestWritesWithNoOriginHeaderAreAllowed(t *testing.T) {
	h := newHarness(t)
	requireStatus(t, h.do(t, http.MethodPost, "/api/login", nil), http.StatusOK)
}

// --- caching --------------------------------------------------------------

// Status is polled continuously; a cached response would freeze the dashboard on a
// stale state.
func TestAPIResponsesAreNotCached(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodGet, "/api/status", nil)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

// --- response hardening ---------------------------------------------------

// These do not stop DNS rebinding -- a rebound request is same-origin, so nothing
// header-based can see it. They bound what a bug elsewhere could turn into.
func TestResponsesCarryTheHardeningHeaders(t *testing.T) {
	hardening := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}

	// A refusal is the one response a hostile page can reliably provoke, so it is the
	// response that most needs these -- headers set only on the success path invert
	// the intent.
	cases := map[string]func(*testing.T) *httptest.ResponseRecorder{
		"served": func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t)
			return h.do(t, http.MethodGet, "/api/status", nil)
		},
		"refused for its host": func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t)
			req := newAPIRequest(http.MethodGet, "/api/status", nil)
			req.Host = "attacker.example"
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)
			requireStatus(t, rec, http.StatusForbidden)
			return rec
		},
		"refused for its origin": func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t)
			req := newAPIRequest(http.MethodPost, "/api/login", nil)
			req.Header.Set("Origin", "https://evil.example")
			rec := httptest.NewRecorder()
			h.server.Handler().ServeHTTP(rec, req)
			requireStatus(t, rec, http.StatusForbidden)
			return rec
		},
	}

	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			rec := respond(t)
			for header, want := range hardening {
				if got := rec.Header().Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			if rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("Content-Security-Policy is absent")
			}
		})
	}
}

// Shutdown closes only the listener it knows about, so a second bind over a live one
// would strand the first socket for the rest of the process's life.
func TestListeningTwiceIsRefusedRatherThanLeakingTheFirstListener(t *testing.T) {
	s := New(Options{Auth: testKeys})
	first, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	if _, err := s.Listen("127.0.0.1:0"); err == nil {
		t.Fatal("second Listen succeeded, silently replacing the bound listener")
	}
	if s.Addr() == nil || s.Addr().String() != first.String() {
		t.Fatalf("Addr() = %v after the refused rebind, want the original %v", s.Addr(), first)
	}
}

// The dashboard sets inline style attributes from React style props in several
// components, and React emits those verbatim. Tightening style-src to 'self' ships
// an unstyled page, so the allowance is a requirement, not an oversight.
func TestTheContentSecurityPolicyMatchesWhatTheDashboardNeeds(t *testing.T) {
	h := newHarness(t)
	csp := h.do(t, http.MethodGet, "/api/status", nil).Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy was set")
	}
	for _, directive := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"object-src 'none'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("policy is missing %q: %s", directive, csp)
		}
	}
	// A nonce-free 'unsafe-inline' in script-src would defeat the whole policy; the
	// built index.html has no inline script, so it is never needed.
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("script-src allows inline script: %s", csp)
	}
}

// Two routes are legitimately slow -- /api/restart rebuilds a tsnet node and
// /api/policy/apply makes two control-plane round trips. A write timeout sized for
// the typical request cuts both off mid-flight and breaks the smoke test.
func TestServerTimeoutsAccommodateTheSlowRoutes(t *testing.T) {
	s := New(Options{Auth: testKeys})
	if s.http.ReadTimeout <= 0 || s.http.IdleTimeout <= 0 {
		t.Fatalf("read/idle timeouts unset: read=%v idle=%v", s.http.ReadTimeout, s.http.IdleTimeout)
	}
	// policy/apply is the worst case: three round trips at 30s apiece. No "unset is
	// fine" escape -- an unbounded handler is the thing this budget replaced.
	if s.http.WriteTimeout < 90*time.Second {
		t.Fatalf("WriteTimeout %v would cut off /api/policy/apply", s.http.WriteTimeout)
	}
	if s.http.ReadTimeout < s.http.ReadHeaderTimeout {
		t.Fatalf("ReadTimeout %v is below ReadHeaderTimeout %v", s.http.ReadTimeout, s.http.ReadHeaderTimeout)
	}
}

// --- embedded dashboard ---------------------------------------------------

func uiFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                &fstest.MapFile{Data: []byte("<!doctype html><div id=root></div>")},
		"assets/index-a1b2c3.js":    &fstest.MapFile{Data: []byte("console.log('app-tail')")},
		"assets/index-d4e5f6.css":   &fstest.MapFile{Data: []byte(":root{color-scheme:dark}")},
		"favicon.svg":               &fstest.MapFile{Data: []byte("<svg/>")},
		"assets/Inter-9f8e7d.woff2": &fstest.MapFile{Data: []byte("wOF2")},
	}
}

func newUIHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.server = New(Options{
		Auth: testKeys,
		Deps: Deps{
			Node:      h.node,
			Forwards:  h.forwards,
			Presets:   h.presets,
			Settings:  h.settings,
			Autostart: h.autostart,
		},
		UI: uiFS(),
	})
	return h
}

func TestDashboardRootServesIndexHTML(t *testing.T) {
	h := newUIHarness(t)
	rec := h.do(t, http.MethodGet, "/", nil)
	requireStatus(t, rec, http.StatusOK)

	if !strings.Contains(rec.Body.String(), "id=root") {
		t.Fatalf("root did not serve the SPA shell: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestDashboardServesHashedAssets(t *testing.T) {
	h := newUIHarness(t)

	js := h.do(t, http.MethodGet, "/assets/index-a1b2c3.js", nil)
	requireStatus(t, js, http.StatusOK)
	if !strings.Contains(js.Body.String(), "app-tail") {
		t.Fatalf("asset body = %s", js.Body.String())
	}
	if ct := js.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("js Content-Type = %q", ct)
	}
	// A content-hashed name can never go stale, so it is safe to cache hard.
	if cc := js.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("hashed asset Cache-Control = %q, want immutable", cc)
	}

	css := h.do(t, http.MethodGet, "/assets/index-d4e5f6.css", nil)
	requireStatus(t, css, http.StatusOK)
	if ct := css.Header().Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Errorf("css Content-Type = %q", ct)
	}

	// The bundled typefaces: Go's mime table has no woff2 entry of its own, and a font
	// served as application/octet-stream is refused by the browser.
	font := h.do(t, http.MethodGet, "/assets/Inter-9f8e7d.woff2", nil)
	requireStatus(t, font, http.StatusOK)
	if ct := font.Header().Get("Content-Type"); ct != "font/woff2" {
		t.Errorf("woff2 Content-Type = %q, want font/woff2", ct)
	}
}

// The shell must be revalidated or a rebuilt dashboard would keep loading the old
// asset names out of cache.
func TestTheSPAShellIsNotCachedHard(t *testing.T) {
	h := newUIHarness(t)
	if cc := h.do(t, http.MethodGet, "/", nil).Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("index Cache-Control = %q, want no-cache", cc)
	}
}

// Reloading the browser on a client-side route must not 404.
func TestUnknownRoutesFallBackToTheSPAShell(t *testing.T) {
	h := newUIHarness(t)
	for _, path := range []string{"/settings", "/forwards/fwd_1", "/deeply/nested/route"} {
		t.Run(path, func(t *testing.T) {
			rec := h.do(t, http.MethodGet, path, nil)
			requireStatus(t, rec, http.StatusOK)
			if !strings.Contains(rec.Body.String(), "id=root") {
				t.Fatalf("%s did not fall back to the SPA shell: %s", path, rec.Body.String())
			}
		})
	}
}

// A missing asset is a build problem. Answering it with HTML turns a broken build
// into a baffling "unexpected token <" in the browser console.
func TestMissingAssetsDoNotFallBackToHTML(t *testing.T) {
	h := newUIHarness(t)
	for _, path := range []string{"/assets/index-deadbeef.js", "/missing.css", "/nope.svg"} {
		t.Run(path, func(t *testing.T) {
			rec := h.do(t, http.MethodGet, path, nil)
			requireStatus(t, rec, http.StatusNotFound)
			if strings.Contains(rec.Body.String(), "id=root") {
				t.Fatalf("%s was answered with the SPA shell", path)
			}
		})
	}
}

// A mistyped API path must stay JSON so a client bug surfaces as a 404 rather than
// as a parse error on an HTML body.
func TestUnknownAPIPathsReturnJSONNotTheSPAShell(t *testing.T) {
	h := newUIHarness(t)
	rec := h.do(t, http.MethodGet, "/api/nonexistent", nil)
	requireError(t, rec, http.StatusNotFound, "API")
	if strings.Contains(rec.Body.String(), "id=root") {
		t.Fatal("an unknown API path was answered with the SPA shell")
	}
}

func TestDashboardRejectsNonReadMethods(t *testing.T) {
	h := newUIHarness(t)
	requireError(t, h.do(t, http.MethodPut, "/some/route", nil), http.StatusMethodNotAllowed, "")
}

// A binary built without the UI must say so instead of 404-ing ambiguously.
func TestDashboardWithNoEmbeddedUIExplainsItself(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.do(t, http.MethodGet, "/", nil), http.StatusServiceUnavailable, "dashboard")
}

// A UI directory missing its shell is a build failure; the message must point at it
// rather than silently serving nothing.
func TestDashboardWithNoIndexReportsTheBrokenBuild(t *testing.T) {
	h := newHarness(t)
	h.server = New(Options{
		Auth: testKeys,
		Deps: Deps{Node: h.node, Forwards: h.forwards},
		UI:   fstest.MapFS{"assets/index-a1b2c3.js": &fstest.MapFile{Data: []byte("x")}},
	})
	requireError(t, h.do(t, http.MethodGet, "/", nil), http.StatusServiceUnavailable, "index.html")
}

// Path traversal must not escape the served filesystem. The dashboard is served
// from a real directory here, with a sentinel file one level above it, so an escape
// would actually surface content rather than merely failing a string match.
func TestDashboardRefusesPathTraversal(t *testing.T) {
	const sentinel = "TOP-SECRET-ESCAPED-CONTENT"

	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte(sentinel), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	root := filepath.Join(parent, "ui")
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatalf("make ui dir: %v", err)
	}
	for name, data := range map[string]string{
		"index.html":             "<!doctype html><div id=root></div>",
		"assets/index-a1b2c3.js": "console.log(1)",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	h := newHarness(t)
	h.server = New(Options{
		Auth: testKeys,
		Deps: Deps{Node: h.node, Forwards: h.forwards},
		UI:   os.DirFS(root),
	})

	// Percent-encoded dot segments survive the mux's path cleaning, so they are what
	// actually reaches the handler's own guard. Deleting that guard turns this 400
	// into a 200 SPA fallback, which is what makes the assertion bite.
	t.Run("encoded dot segments are refused", func(t *testing.T) {
		for _, target := range []string{
			"/%2e%2e/secret.txt",
			"/%2e%2e/%2e%2e/secret.txt",
			"/assets/%2e%2e/%2e%2e/secret.txt",
		} {
			rec := h.do(t, http.MethodGet, target, nil)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("GET %s = %d, want 400", target, rec.Code)
			}
			if strings.Contains(rec.Body.String(), sentinel) {
				t.Errorf("GET %s leaked content from outside the served tree", target)
			}
		}
	})

	// Literal dot segments are normalized by the mux before routing, so they never
	// name a file outside the tree in the first place.
	t.Run("literal dot segments are normalized away", func(t *testing.T) {
		for _, target := range []string{"/../../../etc/passwd", "/assets/../../secret.txt"} {
			rec := h.do(t, http.MethodGet, target, nil)
			if rec.Code != http.StatusTemporaryRedirect {
				t.Errorf("GET %s = %d, want a 307 to the cleaned path", target, rec.Code)
			}
			if loc := rec.Header().Get("Location"); strings.Contains(loc, "..") {
				t.Errorf("GET %s redirected to %q, which still escapes", target, loc)
			}
			if strings.Contains(rec.Body.String(), sentinel) {
				t.Errorf("GET %s leaked content from outside the served tree", target)
			}
		}
	})

	// The guard must reject traversal, not everything: an in-bounds asset still serves.
	t.Run("in-bounds assets still serve", func(t *testing.T) {
		rec := h.do(t, http.MethodGet, "/assets/index-a1b2c3.js", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /assets/index-a1b2c3.js = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "console.log") {
			t.Errorf("asset body = %q, want the file's contents", rec.Body.String())
		}
	})
}

// stubListener stands in for a listener whose Close fails. Only Close is ever reached
// by Shutdown, so Accept and Addr exist to satisfy net.Listener.
type stubListener struct{ closeErr error }

func (stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l stubListener) Close() error            { return l.closeErr }
func (stubListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8377} }

// net/http only tracks listeners it was handed via Serve, so Shutdown closes the
// listener itself. A close that fails means the port is still held, and the agent's
// next restart fails with a bare "address already in use" -- surfacing it here is what
// puts the cause next to that effect. An already-closed listener is the ordinary case
// and must stay silent, or every clean shutdown would report a spurious error.
func TestShutdownReportsAListenerThatWouldNotClose(t *testing.T) {
	tests := []struct {
		name     string
		closeErr error
		wantErr  string
	}{
		{"a listener that will not close", fmt.Errorf("device busy"), "device busy"},
		{"a listener already closed", net.ErrClosed, ""},
		{"a listener that closed cleanly", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Options{Auth: testKeys, Deps: Deps{}})
			s.ln = stubListener{closeErr: tt.closeErr}

			err := s.Shutdown(context.Background())

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Shutdown = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Shutdown = nil, want it to report %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Shutdown = %q, want it to carry %q", err, tt.wantErr)
			}
		})
	}
}
