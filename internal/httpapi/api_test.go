// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/traffic"
	"github.com/sellitus/app-tail/internal/tsnode"
	"github.com/sellitus/app-tail/internal/tsproxy"
	"time"
)

func ptr[T any](v T) *T { return &v }

// llmForward is the design doc's motivating case: a remote model server reached at
// a local loopback port.
func llmForward() ForwardSpec {
	return ForwardSpec{
		Name:       ptr("LLM"),
		Direction:  ptr(config.ToLocal),
		Protocol:   ptr(config.TCP),
		BindAddr:   ptr("127.0.0.1"),
		ListenPort: ptr(18100),
		Target:     ptr("100.64.0.5:8100"),
		Enabled:    ptr(true),
	}
}

// --- status, login, peers -------------------------------------------------

func TestStatusReportsNodeState(t *testing.T) {
	h := newHarness(t)
	h.node.status = tsnode.Status{
		BackendState: tsnode.StateRunning,
		Hostname:     "app-tail-laptop",
		DNSName:      "app-tail-laptop.tail1234.ts.net",
		TailscaleIPs: []string{"100.64.0.9"},
		LoginName:    "user@example.com",
		Tags:         []string{"tag:app-tail"},
		AuthMode:     tsnode.AuthOAuth,
	}

	rec := h.do(t, http.MethodGet, "/api/status", nil)
	requireStatus(t, rec, http.StatusOK)

	got := decode[StatusView](t, rec)
	if !got.Running {
		t.Error("Running = false for a Running backend state")
	}
	if got.DNSName != "app-tail-laptop.tail1234.ts.net" {
		t.Errorf("DNSName = %q", got.DNSName)
	}
	if len(got.TailscaleIPs) != 1 || got.TailscaleIPs[0] != "100.64.0.9" {
		t.Errorf("TailscaleIPs = %v", got.TailscaleIPs)
	}
	if got.AuthMode != string(tsnode.AuthOAuth) {
		t.Errorf("AuthMode = %q, want %q", got.AuthMode, tsnode.AuthOAuth)
	}
	if got.Version != "test" {
		t.Errorf("Version = %q, want %q", got.Version, "test")
	}
}

// The status says a login is waiting and nothing more. The URL that completes it enrolls
// this machine on a tailnet, so whoever holds it can finish an enrolment somebody else
// started -- and a read is the one request the same-origin guard does not cover.
func TestStatusSaysALoginIsPendingWithoutHandingOverTheURL(t *testing.T) {
	h := newHarness(t)
	h.node.status = tsnode.Status{
		BackendState: tsnode.StateNeedsLogin,
		AuthURL:      "https://login.example/auth/abc",
		Problem:      "no auth key configured",
	}

	rec := h.do(t, http.MethodGet, "/api/status", nil)
	if strings.Contains(rec.Body.String(), "login.example") {
		t.Errorf("the status carried the login URL: %s", rec.Body.String())
	}
	got := decode[StatusView](t, rec)
	if got.Running {
		t.Error("Running = true for NeedsLogin")
	}
	if !got.AuthPending {
		t.Error("AuthPending = false while a login is waiting, so nothing tells the user to finish it")
	}
	if got.Problem == "" {
		t.Error("Problem was dropped from the status view")
	}

	// The state-changing request is where it is handed over, and it hands over the login
	// already in progress rather than starting another.
	pending := decode[map[string]string](t, h.do(t, http.MethodPost, "/api/login/url", nil))
	if pending["authURL"] != "https://login.example/auth/abc" {
		t.Errorf("the pending login URL was %q, want the one the node is waiting on", pending["authURL"])
	}
	if h.node.loginCalls != 0 {
		t.Errorf("asking for the pending URL started %d logins, which invalidates the code the user is looking at", h.node.loginCalls)
	}
}

// A stale auth URL sends the user to a dead page, so login must always re-invoke
// the backend rather than replay what status already holds.
func TestLoginAlwaysReInvokesTheBackend(t *testing.T) {
	h := newHarness(t)
	h.node.status = tsnode.Status{
		BackendState: tsnode.StateNeedsLogin,
		AuthURL:      "https://login.example/auth/stale",
	}

	first := decode[map[string]string](t, h.do(t, http.MethodPost, "/api/login", nil))
	if h.node.loginCalls != 1 {
		t.Fatalf("StartLogin called %d times, want 1", h.node.loginCalls)
	}
	if first["authURL"] == "https://login.example/auth/stale" {
		t.Fatal("login replayed the cached auth URL instead of requesting a fresh one")
	}

	second := decode[map[string]string](t, h.do(t, http.MethodPost, "/api/login", nil))
	if h.node.loginCalls != 2 {
		t.Fatalf("StartLogin called %d times, want 2", h.node.loginCalls)
	}
	if second["authURL"] == first["authURL"] {
		t.Fatal("a second login returned the first login's URL")
	}
}

func TestLoginFailureIsReportedNotSwallowed(t *testing.T) {
	h := newHarness(t)
	h.node.loginErr = errors.New("control plane unreachable")

	rec := h.do(t, http.MethodPost, "/api/login", nil)
	requireError(t, rec, http.StatusInternalServerError, "control plane unreachable")
}

// A node that is down or mid-restart is a retryable condition, so it must not be
// reported as a fault in the agent: a 500 tells the dashboard to give up and tells
// an operator to go looking for a bug that is not there.
func TestOperationsAgainstADownNodeAre503(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		arm    func(*fakeNode)
	}{
		{"login", http.MethodPost, "/api/login", func(n *fakeNode) { n.loginErr = tsnode.ErrNotRunning }},
		{"logout", http.MethodPost, "/api/logout", func(n *fakeNode) { n.logoutErr = tsnode.ErrNotRunning }},
		{"peers", http.MethodGet, "/api/peers", func(n *fakeNode) { n.peersErr = tsnode.ErrNotRunning }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.arm(h.node)
			requireError(t, h.do(t, tc.method, tc.path, nil),
				http.StatusServiceUnavailable, "not running")
		})
	}
}

func TestLogoutInvokesTheBackend(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodPost, "/api/logout", nil)
	requireStatus(t, rec, http.StatusOK)
	if h.node.logoutCall != 1 {
		t.Fatalf("Logout called %d times, want 1", h.node.logoutCall)
	}
	if got := decode[map[string]string](t, rec); got["backendState"] != tsnode.StateNeedsLogin {
		t.Errorf("backendState = %q, want %q", got["backendState"], tsnode.StateNeedsLogin)
	}
}

func TestPeersReturnsThePickerShape(t *testing.T) {
	h := newHarness(t)
	h.node.peers = []tsnode.Peer{{
		ID:       "n123",
		HostName: "llm-box",
		DNSName:  "llm-box.tail1234.ts.net",
		IPs:      []string{"100.64.0.5", "fd7a:115c:a1e0::5"},
		Online:   true,
		OS:       "linux",
		Tags:     []string{"tag:llm"},
	}}

	rec := h.do(t, http.MethodGet, "/api/peers", nil)
	requireStatus(t, rec, http.StatusOK)

	got := decode[struct {
		Peers []tsnode.Peer `json:"peers"`
	}](t, rec)
	if len(got.Peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(got.Peers))
	}
	p := got.Peers[0]
	if p.HostName != "llm-box" || p.DNSName != "llm-box.tail1234.ts.net" {
		t.Errorf("peer names = %q / %q", p.HostName, p.DNSName)
	}
	if len(p.IPs) != 2 || !p.Online || p.OS != "linux" {
		t.Errorf("peer = %+v", p)
	}
}

// An empty peer list must serialize as [] rather than null, or the dashboard's
// .map() blows up on first render before login completes.
func TestPeersSerializesEmptyAsAnArray(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodGet, "/api/peers", nil)
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"peers":[]`) {
		t.Fatalf("empty peers serialized as %s", rec.Body.String())
	}
}

func TestPeersFailureIsReported(t *testing.T) {
	h := newHarness(t)
	h.node.peersErr = errors.New("backend not running")
	requireError(t, h.do(t, http.MethodGet, "/api/peers", nil),
		http.StatusInternalServerError, "backend not running")
}

// --- healthz --------------------------------------------------------------

func TestHealthzTruthTable(t *testing.T) {
	tests := []struct {
		name       string
		state      string
		problem    string
		allRunning bool
		wantStatus int
		wantReason string
	}{
		{"running and all forwards up", tsnode.StateRunning, "", true, http.StatusOK, ""},
		{"running but a forward is down", tsnode.StateRunning, "", false, http.StatusServiceUnavailable, "forwards"},
		{"needs login", tsnode.StateNeedsLogin, "", true, http.StatusServiceUnavailable, "not running"},
		{"needs machine auth", tsnode.StateNeedsMachineAuth, "device approval required", true, http.StatusServiceUnavailable, "device approval required"},
		{"starting", tsnode.StateStarting, "", false, http.StatusServiceUnavailable, "not running"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.node.status = tsnode.Status{BackendState: tt.state, Problem: tt.problem}
			h.forwards.allRunning = tt.allRunning

			rec := h.do(t, http.MethodGet, "/healthz", nil)
			requireStatus(t, rec, tt.wantStatus)

			got := decode[map[string]string](t, rec)
			if tt.wantStatus == http.StatusOK {
				if got["status"] != "ok" {
					t.Fatalf("status = %q, want ok", got["status"])
				}
				return
			}
			if got["status"] != "unhealthy" {
				t.Fatalf("status = %q, want unhealthy", got["status"])
			}
			if !strings.Contains(got["reason"], tt.wantReason) {
				t.Fatalf("reason %q does not mention %q", got["reason"], tt.wantReason)
			}
		})
	}
}

// Before the agent finishes wiring, /healthz must still answer rather than panic.
func TestHealthzOnAPartiallyWiredAgent(t *testing.T) {
	s := New(Options{Auth: testKeys})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newAPIRequest(http.MethodGet, "/healthz", nil))

	requireStatus(t, rec, http.StatusServiceUnavailable)
	if got := decode[map[string]string](t, rec); got["reason"] == "" {
		t.Fatal("healthz gave no reason while the agent was unwired")
	}
}

// --- forwards CRUD --------------------------------------------------------

func TestForwardCreateReadUpdateDelete(t *testing.T) {
	h := newHarness(t)

	created := decode[ForwardView](t, func() *httptest.ResponseRecorder {
		rec := h.do(t, http.MethodPost, "/api/forwards", llmForward())
		requireStatus(t, rec, http.StatusCreated)
		return rec
	}())
	if created.ID == "" {
		t.Fatal("created forward has no id")
	}
	if created.ListenPort != 18100 || created.Target != "100.64.0.5:8100" {
		t.Fatalf("created forward = %+v", created)
	}
	if created.Endpoint == "" {
		t.Error("created forward has no rendered endpoint label")
	}

	listed := decode[struct {
		Forwards []ForwardView `json:"forwards"`
	}](t, h.do(t, http.MethodGet, "/api/forwards", nil))
	if len(listed.Forwards) != 1 || listed.Forwards[0].ID != created.ID {
		t.Fatalf("list = %+v", listed.Forwards)
	}

	fetched := decode[ForwardView](t, h.do(t, http.MethodGet, "/api/forwards/"+created.ID, nil))
	if fetched.ID != created.ID {
		t.Fatalf("get returned %q, want %q", fetched.ID, created.ID)
	}

	updated := decode[ForwardView](t, func() *httptest.ResponseRecorder {
		rec := h.do(t, http.MethodPut, "/api/forwards/"+created.ID,
			ForwardSpec{Target: ptr("100.64.0.6:8100")})
		requireStatus(t, rec, http.StatusOK)
		return rec
	}())
	if updated.Target != "100.64.0.6:8100" {
		t.Fatalf("target = %q, want the updated value", updated.Target)
	}
	if updated.Name != "LLM" {
		t.Fatalf("name = %q; an absent spec field must leave the stored value alone", updated.Name)
	}

	requireStatus(t, h.do(t, http.MethodDelete, "/api/forwards/"+created.ID, nil), http.StatusNoContent)
	after := decode[struct {
		Forwards []ForwardView `json:"forwards"`
	}](t, h.do(t, http.MethodGet, "/api/forwards", nil))
	if len(after.Forwards) != 0 {
		t.Fatalf("forward survived deletion: %+v", after.Forwards)
	}
}

func TestForwardsSerializesEmptyAsAnArray(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodGet, "/api/forwards", nil)
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"forwards":[]`) {
		t.Fatalf("empty forwards serialized as %s", rec.Body.String())
	}
}

func TestInvalidForwardIsRejectedWith400(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		name string
		spec ForwardSpec
	}{
		{"no target", ForwardSpec{Direction: ptr(config.ToLocal), Protocol: ptr(config.TCP), ListenPort: ptr(18100)}},
		{"port zero", ForwardSpec{Direction: ptr(config.ToLocal), Protocol: ptr(config.TCP), ListenPort: ptr(0), Target: ptr("host:80")}},
		{"port too high", ForwardSpec{Direction: ptr(config.ToLocal), Protocol: ptr(config.TCP), ListenPort: ptr(70000), Target: ptr("host:80")}},
		{"bogus protocol", ForwardSpec{Direction: ptr(config.ToLocal), Protocol: ptr(config.Protocol("sctp")), ListenPort: ptr(18100), Target: ptr("host:80")}},
		{"bogus direction", ForwardSpec{Direction: ptr(config.Direction("sideways")), Protocol: ptr(config.TCP), ListenPort: ptr(18100), Target: ptr("host:80")}},
		{"target without port", ForwardSpec{Direction: ptr(config.ToLocal), Protocol: ptr(config.TCP), ListenPort: ptr(18100), Target: ptr("host")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireError(t, h.do(t, http.MethodPost, "/api/forwards", tt.spec), http.StatusBadRequest, "")
		})
	}
}

func TestMalformedJSONIsRejectedWith400(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.doRaw(t, http.MethodPost, "/api/forwards", "{not json"),
		http.StatusBadRequest, "JSON")
	if h.forwards.createCalled != 0 {
		t.Fatal("a malformed body reached the store")
	}
}

// A typo in a field name must fail loudly; silently dropping it would leave the
// user staring at a setting that never took.
func TestUnknownFieldIsRejectedWith400(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.doRaw(t, http.MethodPost, "/api/forwards",
		`{"listenPrt": 18100, "target": "host:80"}`), http.StatusBadRequest, "")
	if h.forwards.createCalled != 0 {
		t.Fatal("a body with an unknown field reached the store")
	}
}

func TestUnknownForwardIDIs404(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/forwards/nope", nil},
		{http.MethodPut, "/api/forwards/nope", ForwardSpec{Name: ptr("x")}},
		{http.MethodDelete, "/api/forwards/nope", nil},
		{http.MethodPost, "/api/forwards/nope/toggle", toggleRequest{Enabled: ptr(true)}},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			requireError(t, h.do(t, tc.method, tc.path, tc.body), http.StatusNotFound, "nope")
		})
	}
}

// The 409 must name the forward already holding the endpoint; "port in use" alone
// leaves the user hunting for which of their forwards it collides with.
func TestPortConflictIs409AndNamesTheOtherForward(t *testing.T) {
	h := newHarness(t)
	requireStatus(t, h.do(t, http.MethodPost, "/api/forwards", llmForward()), http.StatusCreated)

	second := llmForward()
	second.Name = ptr("Second LLM")
	second.Target = ptr("100.64.0.7:8100")

	rec := h.do(t, http.MethodPost, "/api/forwards", second)
	body := requireError(t, rec, http.StatusConflict, "")

	if body.Conflict == nil {
		t.Fatal("409 response carried no conflict detail")
	}
	if body.Conflict.ForwardID == "" {
		t.Error("conflict detail names no forward id")
	}
	if body.Conflict.Name != "LLM" {
		t.Errorf("conflict names %q, want the existing forward %q", body.Conflict.Name, "LLM")
	}
	if !strings.Contains(body.Conflict.Endpoint, "18100") {
		t.Errorf("conflict endpoint %q does not name the contested port", body.Conflict.Endpoint)
	}
}

// --- toggle ---------------------------------------------------------------

func TestToggleWithAnExplicitValue(t *testing.T) {
	h := newHarness(t)
	created := decode[ForwardView](t, h.do(t, http.MethodPost, "/api/forwards", llmForward()))

	off := decode[ForwardView](t, h.do(t, http.MethodPost,
		"/api/forwards/"+created.ID+"/toggle", toggleRequest{Enabled: ptr(false)}))
	if off.Enabled {
		t.Fatal("forward is still enabled after an explicit disable")
	}

	on := decode[ForwardView](t, h.do(t, http.MethodPost,
		"/api/forwards/"+created.ID+"/toggle", toggleRequest{Enabled: ptr(true)}))
	if !on.Enabled {
		t.Fatal("forward is still disabled after an explicit enable")
	}
}

func TestToggleWithNoBodyFlipsTheCurrentValue(t *testing.T) {
	h := newHarness(t)
	created := decode[ForwardView](t, h.do(t, http.MethodPost, "/api/forwards", llmForward()))
	if !created.Enabled {
		t.Fatal("test setup: forward should start enabled")
	}

	first := decode[ForwardView](t, h.do(t, http.MethodPost, "/api/forwards/"+created.ID+"/toggle", nil))
	if first.Enabled {
		t.Fatal("toggle with no body did not disable an enabled forward")
	}

	second := decode[ForwardView](t, h.do(t, http.MethodPost, "/api/forwards/"+created.ID+"/toggle", nil))
	if !second.Enabled {
		t.Fatal("toggle with no body did not re-enable a disabled forward")
	}
}

// --- suggest-port ---------------------------------------------------------

func TestSuggestPortDerivesThePreferredPortFromTheTarget(t *testing.T) {
	h := newHarness(t)
	h.forwards.suggestPort = 8100

	rec := h.do(t, http.MethodGet, "/api/forwards/suggest-port?protocol=tcp&target=100.64.0.5:8100", nil)
	requireStatus(t, rec, http.StatusOK)

	if got := decode[map[string]int](t, rec); got["port"] != 8100 {
		t.Fatalf("port = %d, want 8100", got["port"])
	}
	if h.forwards.lastSuggest.preferred != 8100 {
		t.Errorf("preferred = %d, want the target's port 8100", h.forwards.lastSuggest.preferred)
	}
	if h.forwards.lastSuggest.protocol != config.TCP {
		t.Errorf("protocol = %q, want tcp", h.forwards.lastSuggest.protocol)
	}
}

// The doc's headline flow: the port the user would naturally want is taken, so the
// API hands back a different one rather than failing.
func TestSuggestPortReturnsAnAlternativeWhenThePreferredIsOccupied(t *testing.T) {
	h := newHarness(t)
	h.forwards.suggestPort = 18101

	rec := h.do(t, http.MethodGet, "/api/forwards/suggest-port?protocol=tcp&preferred=18100", nil)
	requireStatus(t, rec, http.StatusOK)

	if h.forwards.lastSuggest.preferred != 18100 {
		t.Errorf("preferred = %d, want 18100", h.forwards.lastSuggest.preferred)
	}
	if got := decode[map[string]int](t, rec); got["port"] != 18101 {
		t.Fatalf("port = %d, want the alternative 18101", got["port"])
	}
}

func TestSuggestPortPassesBindAddrAndProtocolThrough(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodGet,
		"/api/forwards/suggest-port?protocol=udp&bindAddr=127.0.0.2&target=host:53", nil)
	requireStatus(t, rec, http.StatusOK)

	if h.forwards.lastSuggest.protocol != config.UDP {
		t.Errorf("protocol = %q, want udp", h.forwards.lastSuggest.protocol)
	}
	if h.forwards.lastSuggest.bindAddr != "127.0.0.2" {
		t.Errorf("bindAddr = %q, want 127.0.0.2", h.forwards.lastSuggest.bindAddr)
	}
}

func TestSuggestPortAcceptsTheBothProtocol(t *testing.T) {
	h := newHarness(t)
	h.forwards.suggestPort = 5353

	rec := h.do(t, http.MethodGet,
		"/api/forwards/suggest-port?protocol=both&target=dns-box:53", nil)
	requireStatus(t, rec, http.StatusOK)

	if h.forwards.lastSuggest.protocol != config.Both {
		t.Errorf("protocol = %q, want both", h.forwards.lastSuggest.protocol)
	}
	if got := decode[map[string]int](t, rec); got["port"] != 5353 {
		t.Fatalf("port = %d, want 5353", got["port"])
	}
}

func TestSuggestPortRejectsBadParameters(t *testing.T) {
	h := newHarness(t)
	for _, query := range []string{
		"?protocol=sctp",
		"?preferred=abc",
		"?preferred=0",
		"?preferred=70000",
	} {
		t.Run(query, func(t *testing.T) {
			requireError(t, h.do(t, http.MethodGet, "/api/forwards/suggest-port"+query, nil),
				http.StatusBadRequest, "")
		})
	}
}

func TestSuggestPortFailureIsReported(t *testing.T) {
	h := newHarness(t)
	h.forwards.suggestErr = errors.New("no free port available")
	requireError(t, h.do(t, http.MethodGet, "/api/forwards/suggest-port?target=host:80", nil),
		http.StatusInternalServerError, "no free port")
}

// --- settings -------------------------------------------------------------

// boolField and strField read a typed value from a settings view/response map,
// failing loudly when the key is missing or the wrong type.
func boolField(t *testing.T, m map[string]any, key string) bool {
	t.Helper()
	v, ok := m[key].(bool)
	if !ok {
		t.Fatalf("field %q = %#v, want a bool", key, m[key])
	}
	return v
}

func strField(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q = %#v, want a string", key, m[key])
	}
	return v
}

func TestSettingsNeverLeakSecrets(t *testing.T) {
	h := newHarness(t)
	h.settings.tailnet(t).AuthKey = "tskey-auth-super-secret"
	h.settings.tailnet(t).OAuthClientSecret = "tskey-client-also-secret"
	h.settings.tailnet(t).Hostname = "app-tail-laptop"

	rec := h.do(t, http.MethodGet, "/api/settings", nil)
	requireStatus(t, rec, http.StatusOK)

	raw := rec.Body.String()
	for _, secret := range []string{"tskey-auth-super-secret", "tskey-client-also-secret"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("settings response leaked %q: %s", secret, raw)
		}
	}

	got := decode[map[string]any](t, rec)
	if !boolField(t, got, "hasAuthKey") || !boolField(t, got, "hasOAuthClientSecret") {
		t.Fatalf("stored secrets are not reported as present: %+v", got)
	}
	if h := strField(t, got, "hostname"); h != "app-tail-laptop" {
		t.Errorf("hostname = %q", h)
	}
}

func TestSettingsReportAbsentSecretsAsAbsent(t *testing.T) {
	h := newHarness(t)
	got := decode[map[string]any](t, h.do(t, http.MethodGet, "/api/settings", nil))
	if boolField(t, got, "hasAuthKey") || boolField(t, got, "hasOAuthClientSecret") {
		t.Fatalf("no secrets are stored but the view claims otherwise: %+v", got)
	}
}

// The dashboard shows what the {id} hostname token renders to, so the settings
// view must carry the read-only machine id.
func TestSettingsExposeMachineID(t *testing.T) {
	h := newHarness(t)
	h.settings.stored().MachineID = "a1b2c3"

	got := decode[map[string]any](t, h.do(t, http.MethodGet, "/api/settings", nil))
	if id := strField(t, got, "machineId"); id != "a1b2c3" {
		t.Fatalf("machineId = %q, want the stored id", id)
	}
}

// The dashboard reads settings, edits one field, and PUTs the whole document back.
// If the redaction mask were stored as the secret, the node would fail to
// authenticate on next start.
func TestUpdatingSettingsDoesNotWipeSecretsTheClientNeverSaw(t *testing.T) {
	h := newHarness(t)
	h.settings.tailnet(t).AuthKey = "tskey-auth-super-secret"
	h.settings.tailnet(t).OAuthClientSecret = "tskey-client-also-secret"

	rec := h.do(t, http.MethodPut, "/api/settings", map[string]any{
		"hostname":          "renamed-node",
		"authKey":           config.RedactedSecret,
		"oauthClientSecret": config.RedactedSecret,
	})
	requireStatus(t, rec, http.StatusOK)

	if h.settings.tailnet(t).AuthKey != "tskey-auth-super-secret" {
		t.Fatalf("stored auth key = %q, want it untouched", h.settings.tailnet(t).AuthKey)
	}
	if h.settings.tailnet(t).OAuthClientSecret != "tskey-client-also-secret" {
		t.Fatalf("stored OAuth secret = %q, want it untouched", h.settings.tailnet(t).OAuthClientSecret)
	}
	if h.settings.tailnet(t).Hostname != "renamed-node" {
		t.Fatalf("hostname = %q, want the edited value", h.settings.tailnet(t).Hostname)
	}
}

// Omitting a field entirely is the other half of the same contract.
func TestOmittedSettingsFieldsAreLeftAlone(t *testing.T) {
	h := newHarness(t)
	h.settings.tailnet(t).AuthKey = "tskey-auth-super-secret"
	h.settings.stored().ShowTray = true

	requireStatus(t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"hostname": "renamed-node"}), http.StatusOK)

	if h.settings.tailnet(t).AuthKey != "tskey-auth-super-secret" {
		t.Fatalf("auth key = %q after a patch that never mentioned it", h.settings.tailnet(t).AuthKey)
	}
	if !h.settings.stored().ShowTray {
		t.Fatal("showTray was cleared by a patch that never mentioned it")
	}
}

// A real new secret must still get through; the redaction guard keys on the mask
// value alone.
func TestANewSecretIsStored(t *testing.T) {
	h := newHarness(t)
	h.settings.tailnet(t).AuthKey = "tskey-auth-old"

	requireStatus(t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"authKey": "tskey-auth-new"}), http.StatusOK)

	if h.settings.tailnet(t).AuthKey != "tskey-auth-new" {
		t.Fatalf("auth key = %q, want the newly submitted value", h.settings.tailnet(t).AuthKey)
	}
}

// Clearing a secret is an explicit empty string, which must not be confused with
// "unchanged".
func TestAnEmptyStringClearsASecret(t *testing.T) {
	h := newHarness(t)
	h.settings.tailnet(t).AuthKey = "tskey-auth-old"

	requireStatus(t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"authKey": ""}), http.StatusOK)

	if h.settings.tailnet(t).AuthKey != "" {
		t.Fatalf("auth key = %q, want it cleared", h.settings.tailnet(t).AuthKey)
	}
}

// A key that is not a known setting is rejected by name rather than silently ignored.
func TestUnknownSettingKeyIsRejected(t *testing.T) {
	h := newHarness(t)
	body := requireError(t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"notARealSetting": "x"}), http.StatusBadRequest, "notARealSetting")
	if !strings.Contains(body.Error, "not a known setting") {
		t.Errorf("error %q does not explain the unknown key", body.Error)
	}
}

// startAtLogin is managed through the autostart control, so the settings patch must
// refuse it rather than store a bool that diverges from the real login item.
func TestStartAtLoginIsNotPatchable(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"startAtLogin": true}), http.StatusBadRequest, "autostart")
}

func TestSettingsUpdateReportsWhenARestartIsRequired(t *testing.T) {
	h := newHarness(t)
	h.settings.nodeRestart = true

	rec := h.do(t, http.MethodPut, "/api/settings", map[string]any{"hostname": "renamed"})
	requireStatus(t, rec, http.StatusOK)

	got := decode[map[string]any](t, rec)
	if !boolField(t, got, "restartRequired") {
		t.Fatal("restartRequired was not reported to the client")
	}

	h.settings.nodeRestart = false
	quiet := decode[map[string]any](t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"showTray": false}))
	if boolField(t, quiet, "restartRequired") {
		t.Fatal("restartRequired reported for a change that does not need one")
	}
}

// The mirror is the only place a setting stored here and not in force on the tailnet
// shows up. Every part of it is load-bearing on screen -- both values, whether they
// agree, and why they do not -- so the whole shape is asserted, not just the status.
func TestPrefsMirrorPutsBothValuesAndTheReasonOnTheWire(t *testing.T) {
	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/prefs", nil)
	requireStatus(t, rec, http.StatusOK)
	got := decode[map[string]any](t, rec)

	if got["nodeUp"] != true || got["known"] != true {
		t.Errorf("nodeUp=%v known=%v, want both reported", got["nodeUp"], got["known"])
	}
	fields, ok := got["fields"].([]any)
	if !ok || len(fields) != 1 {
		t.Fatalf("fields = %#v, want the one setting the mirror holds", got["fields"])
	}
	field, ok := fields[0].(map[string]any)
	if !ok {
		t.Fatalf("field = %#v, want an object", fields[0])
	}
	if field["key"] != "routes.accept" || field["label"] == "" {
		t.Errorf("field = %#v, want the setting named as the form names it", field)
	}
	if field["stored"] != true {
		t.Errorf("stored = %#v, want what this app has saved", field["stored"])
	}
	// A live value of false has to survive the encoder: dropped as empty, the dashboard
	// could not tell "the node says no" from "the node has not said".
	live, present := field["live"]
	if !present || live != false {
		t.Errorf("live = %#v (present=%v), want the node's own value", live, present)
	}
	if field["inForce"] != false {
		t.Errorf("inForce = %#v, want the disagreement reported", field["inForce"])
	}

	conflict, ok := got["conflict"].([]any)
	if !ok || len(conflict) != 1 || conflict[0] != "routes.accept" {
		t.Errorf("conflict = %#v, want the setting that is stuck", got["conflict"])
	}
	capability, ok := got["capability"].(map[string]any)
	if !ok || capability["degraded"] != true || capability["reason"] == "" {
		t.Errorf("capability = %#v, want it degraded with a reason", got["capability"])
	}
}

// A configuration where no pref-backed setting is available leaves the slice nil, and a
// nil slice encodes as null. The dashboard reads the length of this field, so null blanked
// the whole page: the field is documented as an array and the empty case has to be [].
func TestPrefsMirrorSendsAnEmptyFieldListRatherThanNull(t *testing.T) {
	h := newHarness(t)
	h.prefs.view = PrefsView{
		NodeUp: false, Known: true,
		Capability: Capability{Reason: "No settings are kept on the tailnet node in this configuration."},
	}

	rec := h.do(t, http.MethodGet, "/api/prefs", nil)
	requireStatus(t, rec, http.StatusOK)

	if body := rec.Body.String(); strings.Contains(body, `"fields":null`) {
		t.Errorf("the response carries a null field list, which the dashboard cannot read: %s", body)
	}
	got := decode[map[string]any](t, rec)
	fields, ok := got["fields"].([]any)
	if !ok {
		t.Fatalf("fields = %#v, want an array for the empty case", got["fields"])
	}
	if len(fields) != 0 {
		t.Errorf("fields = %#v, want it empty", fields)
	}
}

// A setting stored but not yet in force is not a successful save. It reaches the client
// as its own list, with each setting's reason, so a client says what is waiting instead
// of showing a change nothing has applied as done.
func TestSettingsUpdateReportsWhatIsStoredButNotYetInForce(t *testing.T) {
	h := newHarness(t)
	h.settings.deferred = []DeferredField{{
		Key:    "routes.accept",
		Label:  "Reach networks other devices advertise",
		Reason: "stored; it will be applied when the tailnet node is running",
	}}

	got := decode[map[string]any](t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"hostname": "renamed"}))

	raw, ok := got["deferred"]
	if !ok {
		t.Fatal("a setting that is stored but not in force was reported as an ordinary save")
	}
	list, ok := raw.([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("deferred = %#v, want the one setting that is waiting", raw)
	}
	entry, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("deferred entry = %#v, want an object", list[0])
	}
	if entry["key"] != "routes.accept" || entry["label"] == "" {
		t.Errorf("deferred entry = %#v, want the setting named as the form names it", entry)
	}
	reason, _ := entry["reason"].(string)
	if !strings.Contains(reason, "tailnet node") {
		t.Errorf("reason = %q, want it to say what is being waited on", reason)
	}

	// A save with nothing waiting must not carry an empty list a client would have to
	// tell apart from a real one.
	h.settings.deferred = nil
	quiet := decode[map[string]any](t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"showTray": false}))
	if _, present := quiet["deferred"]; present {
		t.Errorf("a save with nothing waiting reported deferred = %#v", quiet["deferred"])
	}
}

// The dashboard needs to tell a node-identity change (offer an in-process restart)
// apart from a dashboard-address change (only a full process restart moves it).
func TestSettingsUpdateSplitsNodeRestartFromUIRelisten(t *testing.T) {
	h := newHarness(t)

	h.settings.nodeRestart, h.settings.uiRelisten = true, false
	nodeChange := decode[map[string]any](t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"hostname": "renamed"}))
	if !boolField(t, nodeChange, "nodeRestart") || boolField(t, nodeChange, "uiRelisten") {
		t.Fatalf("node change flags = %+v, want nodeRestart only", nodeChange)
	}
	if !boolField(t, nodeChange, "restartRequired") {
		t.Fatal("a node-restart change must still set the coarse restartRequired flag")
	}

	h.settings.nodeRestart, h.settings.uiRelisten = false, true
	uiChange := decode[map[string]any](t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"uiListenAddr": "127.0.0.1:9999"}))
	if boolField(t, uiChange, "nodeRestart") || !boolField(t, uiChange, "uiRelisten") {
		t.Fatalf("ui change flags = %+v, want uiRelisten only", uiChange)
	}
}

// A change needing administrator rights is its own case: the rights are taken when the
// process starts, so the dashboard has to be able to offer a restart that asks for them.
// appRestart would say the value merely waits for the next start, which understates a
// setting that will not work at all until somebody answers a prompt.
func TestSettingsUpdateReportsAChangeNeedingAdministratorRights(t *testing.T) {
	h := newHarness(t)
	h.settings.adminRestart = true

	change := decode[map[string]any](t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"showTray": false}))
	if !boolField(t, change, "adminRestart") {
		t.Fatalf("rights change flags = %+v, want adminRestart", change)
	}
	if boolField(t, change, "nodeRestart") || boolField(t, change, "uiRelisten") ||
		boolField(t, change, "appRestart") {
		t.Fatalf("rights change flags = %+v, want adminRestart alone", change)
	}
	if !boolField(t, change, "restartRequired") {
		t.Fatal("a change waiting on administrator rights must still set the coarse restartRequired flag")
	}
}

// A setting the process reads once at start is a third case, and it has to reach the
// dashboard as its own flag: nodeRestart would have the dashboard offer a node rebuild
// that changes nothing, and no flag at all would report a live change that is not.
func TestSettingsUpdateReportsASettingReadOnlyAtStart(t *testing.T) {
	h := newHarness(t)
	h.settings.appRestart = true

	change := decode[map[string]any](t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"showTray": false}))
	if !boolField(t, change, "appRestart") {
		t.Fatalf("start-read change flags = %+v, want appRestart", change)
	}
	if boolField(t, change, "nodeRestart") || boolField(t, change, "uiRelisten") {
		t.Fatalf("start-read change flags = %+v, want appRestart alone", change)
	}
	if !boolField(t, change, "restartRequired") {
		t.Fatal("a start-read change must still set the coarse restartRequired flag")
	}
}

func TestRestartRebuildsTheNode(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodPost, "/api/restart", nil)
	requireStatus(t, rec, http.StatusOK)
	if h.restart.calls != 1 {
		t.Fatalf("restart calls = %d, want 1", h.restart.calls)
	}
}

// A rebuild that fails must surface, not report a false success the user would only
// discover when forwards never come back.
func TestRestartFailureIsReported(t *testing.T) {
	h := newHarness(t)
	h.restart.err = fmt.Errorf("restart tailnet node: bind: address already in use")
	requireError(t, h.do(t, http.MethodPost, "/api/restart", nil),
		http.StatusInternalServerError, "address already in use")
}

func TestRestartUnavailableWithoutTheDependencyIs503(t *testing.T) {
	s := New(Options{Auth: testKeys, Deps: Deps{Node: &fakeNode{}, Forwards: &fakeForwards{}}})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newAPIRequest(http.MethodPost, "/api/restart", nil))
	requireError(t, rec, http.StatusServiceUnavailable, "node restart")
}

// The restart endpoint changes state, so the same-origin guard must cover it.
func TestRestartRejectsACrossOriginRequest(t *testing.T) {
	h := newHarness(t)
	req := newAPIRequest(http.MethodPost, "/api/restart", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	requireStatus(t, rec, http.StatusForbidden)
	if h.restart.calls != 0 {
		t.Fatal("a cross-origin request still triggered a restart")
	}
}

func TestInvalidSettingsAreRejectedWith400(t *testing.T) {
	h := newHarness(t)
	h.settings.err = &config.ValidationError{Field: "uiListenAddr", Message: "must be loopback"}

	body := requireError(t, h.do(t, http.MethodPut, "/api/settings",
		map[string]any{"uiListenAddr": "0.0.0.0:8377"}), http.StatusBadRequest, "loopback")
	if !strings.Contains(body.Error, "uiListenAddr") {
		t.Errorf("error %q does not name the offending field", body.Error)
	}
}

// --- presets --------------------------------------------------------------

func TestPresetsListIncludesBuiltInsAndUserEntries(t *testing.T) {
	h := newHarness(t)
	created := decode[config.Preset](t, func() *httptest.ResponseRecorder {
		rec := h.do(t, http.MethodPost, "/api/presets",
			config.Preset{Name: "Grafana", Protocol: config.TCP, RemotePort: 3000})
		requireStatus(t, rec, http.StatusCreated)
		return rec
	}())
	if created.ID == "" {
		t.Fatal("created preset has no id")
	}
	if created.BuiltIn {
		t.Fatal("a user-created preset was flagged as built-in")
	}

	list := decode[struct {
		Presets []config.Preset `json:"presets"`
	}](t, h.do(t, http.MethodGet, "/api/presets", nil))

	var sawSSH, sawGrafana bool
	for _, p := range list.Presets {
		if p.ID == "ssh" && p.RemotePort == 22 && p.BuiltIn {
			sawSSH = true
		}
		if p.ID == created.ID && p.Name == "Grafana" {
			sawGrafana = true
		}
	}
	if !sawSSH {
		t.Error("built-in ssh preset is missing from the list")
	}
	if !sawGrafana {
		t.Error("the created user preset is missing from the list")
	}

	requireStatus(t, h.do(t, http.MethodDelete, "/api/presets/"+created.ID, nil), http.StatusNoContent)
	after := decode[struct {
		Presets []config.Preset `json:"presets"`
	}](t, h.do(t, http.MethodGet, "/api/presets", nil))
	for _, p := range after.Presets {
		if p.ID == created.ID {
			t.Fatal("preset survived deletion")
		}
	}
}

// A client cannot mint a shipped preset by setting the flag itself.
func TestCreatedPresetsCannotClaimBuiltInStatus(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodPost, "/api/presets",
		config.Preset{Name: "Fake", Protocol: config.TCP, RemotePort: 1234, BuiltIn: true})
	requireStatus(t, rec, http.StatusCreated)

	if decode[config.Preset](t, rec).BuiltIn {
		t.Fatal("client-supplied builtIn flag was honored")
	}
}

func TestInvalidPresetIsRejectedWith400(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.do(t, http.MethodPost, "/api/presets",
		config.Preset{Protocol: config.TCP, RemotePort: 3000}), http.StatusBadRequest, "name")
}

func TestDeletingAnUnknownPresetIs404(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.do(t, http.MethodDelete, "/api/presets/nope", nil), http.StatusNotFound, "nope")
}

// --- autostart ------------------------------------------------------------

func TestAutostartReadsAndWritesTheLoginItem(t *testing.T) {
	h := newHarness(t)

	if got := decode[map[string]bool](t, h.do(t, http.MethodGet, "/api/autostart", nil)); got["enabled"] {
		t.Fatal("autostart reported enabled before anything was installed")
	}

	rec := h.do(t, http.MethodPost, "/api/autostart", autostartRequest{Enabled: ptr(true)})
	requireStatus(t, rec, http.StatusOK)
	if h.autostart.setCalls != 1 || !h.autostart.lastWanted {
		t.Fatalf("SetEnabled calls = %d, lastWanted = %v", h.autostart.setCalls, h.autostart.lastWanted)
	}
	if got := decode[map[string]bool](t, rec); !got["enabled"] {
		t.Fatal("response did not report the login item as installed")
	}

	off := decode[map[string]bool](t, h.do(t, http.MethodPost, "/api/autostart",
		autostartRequest{Enabled: ptr(false)}))
	if off["enabled"] {
		t.Fatal("response did not report the login item as removed")
	}
}

func TestAutostartRequiresAnExplicitEnabledFlag(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.doRaw(t, http.MethodPost, "/api/autostart", `{}`),
		http.StatusBadRequest, "enabled")
	if h.autostart.setCalls != 0 {
		t.Fatal("a body with no enabled flag still changed the login item")
	}
}

// Installing a login item can genuinely fail. The API must say so rather than
// reporting success the user would only discover was false after a reboot.
func TestAutostartFailureIsReported(t *testing.T) {
	h := newHarness(t)
	h.autostart.setErr = fmt.Errorf("write LaunchAgent plist: permission denied")

	requireError(t, h.do(t, http.MethodPost, "/api/autostart", autostartRequest{Enabled: ptr(true)}),
		http.StatusInternalServerError, "permission denied")
}

// A login item can be installed and still be wrong: it starts app-tail with the rights
// of the other network mode, or names a binary that has moved. The switch reads as on
// either way, so the fault has to travel with it.
func TestALoginItemThatWillNotStartAppTailIsReportedWithTheSwitch(t *testing.T) {
	h := newHarness(t)
	h.autostart.enabled = true
	h.autostart.problem = "It no longer matches this machine: it was installed for the other network mode."

	got := decode[autostartView](t, h.do(t, http.MethodGet, "/api/autostart", nil))
	if !got.Enabled {
		t.Fatal("an installed login item was reported as absent")
	}
	if got.Problem != h.autostart.problem {
		t.Fatalf("the fault was not served with the switch: %q", got.Problem)
	}
}

// The check reads the machine, so asking about a login item nobody installed is both
// pointless and a way to report a fault about something that is not there.
func TestNoLoginItemMeansNothingToReportAboutOne(t *testing.T) {
	h := newHarness(t)
	h.autostart.enabled = false
	h.autostart.problem = "this must not be served: there is no login item to be wrong"

	got := decode[autostartView](t, h.do(t, http.MethodGet, "/api/autostart", nil))
	if got.Problem != "" {
		t.Fatalf("a machine with no login item reported a fault with one: %q", got.Problem)
	}
}

func TestAutostartUnavailableOnAnUnsupportedPlatformIs503(t *testing.T) {
	s := New(Options{Auth: testKeys, Deps: Deps{Node: &fakeNode{}, Forwards: &fakeForwards{}}})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newAPIRequest(http.MethodGet, "/api/autostart", nil))
	requireError(t, rec, http.StatusServiceUnavailable, "autostart")
}

func policyRequest() PolicyBootstrapRequest {
	return PolicyBootstrapRequest{
		ClientID:     "tskey-client-id",
		ClientSecret: "tskey-client-secret-value-do-not-echo",
		Tags:         []string{"tag:app-tail"},
	}
}

func TestPolicyPreviewReturnsThePlanWithoutApplying(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodPost, "/api/policy/preview", policyRequest())
	requireStatus(t, rec, http.StatusOK)

	got := decode[PolicyPlanView](t, rec)
	if !got.AddTagOwner || !got.Changed {
		t.Fatalf("preview view = %+v, want the fake's canned plan", got)
	}
	if h.policy.previewCalls != 1 || h.policy.applyCalls != 0 {
		t.Fatalf("preview calls = %d, apply calls = %d; preview must not apply",
			h.policy.previewCalls, h.policy.applyCalls)
	}
	if h.policy.lastReq.ClientID != "tskey-client-id" {
		t.Fatalf("facade saw client id %q, want it forwarded intact", h.policy.lastReq.ClientID)
	}
}

func TestPolicyApplyInvokesApply(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, http.MethodPost, "/api/policy/apply", policyRequest())
	requireStatus(t, rec, http.StatusOK)

	if h.policy.applyCalls != 1 || h.policy.previewCalls != 0 {
		t.Fatalf("apply calls = %d, preview calls = %d; apply must not preview",
			h.policy.applyCalls, h.policy.previewCalls)
	}
}

// The OAuth secret is the strongest credential app-tail ever handles. It flows to
// the facade but must never appear in the HTTP response the browser can read.
func TestPolicyResponseNeverEchoesTheCredential(t *testing.T) {
	h := newHarness(t)
	req := policyRequest()
	rec := h.do(t, http.MethodPost, "/api/policy/preview", req)
	requireStatus(t, rec, http.StatusOK)

	if strings.Contains(rec.Body.String(), req.ClientSecret) {
		t.Fatalf("the response body echoed the OAuth secret: %s", rec.Body.String())
	}
	// The facade still received it, so this is a response-shape guarantee, not a
	// broken flow.
	if h.policy.lastReq.ClientSecret != req.ClientSecret {
		t.Fatal("the facade never received the secret; the handler dropped it")
	}
}

func TestPolicyUnavailableWithoutTheDependencyIs503(t *testing.T) {
	s := New(Options{Auth: testKeys, Deps: Deps{Node: &fakeNode{}, Forwards: &fakeForwards{}}})
	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"clientId":"x","clientSecret":"y"}`)
	req := newAPIRequest(http.MethodPost, "/api/policy/preview", body)
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)
	requireError(t, rec, http.StatusServiceUnavailable, "policy")
}

func TestPolicyRejectsUnknownFields(t *testing.T) {
	h := newHarness(t)
	requireError(t, h.doRaw(t, http.MethodPost, "/api/policy/preview",
		`{"clientId":"x","clientSecret":"y","apiUrl":"https://evil.example"}`),
		http.StatusBadRequest, "")
	if h.policy.previewCalls != 0 {
		t.Fatal("an unknown field still reached the policy facade")
	}
}

func TestPolicyValidationErrorsBecome400(t *testing.T) {
	h := newHarness(t)
	h.policy.err = &config.ValidationError{Field: "tags", Message: "at least one tag is required"}
	requireError(t, h.do(t, http.MethodPost, "/api/policy/apply", policyRequest()),
		http.StatusBadRequest, "at least one tag")
}

// A node that could not run on a network interface comes up contained instead, and every
// other field on this view then reads exactly like a node that did what was asked: it is
// Running, it has an address, it has no problem. These two fields are the only thing that
// says otherwise, so dropping them at this boundary leaves the dashboard, the tray and
// `app-tail status` all reporting a healthy node quietly in the wrong mode.
func TestTheStatusViewSaysWhichStackTheNodeIsOnAndWhyItIsNotTheOneAskedFor(t *testing.T) {
	h := newHarness(t)
	h.node.status = tsnode.Status{
		BackendState:    tsnode.StateRunning,
		TailscaleIPs:    []string{"100.64.0.9"},
		Network:         config.NetworkUserspace,
		NetworkFallback: "the privileged helper is not running: run `sudo app-tail tun install-helper`",
	}

	got := decode[StatusView](t, h.do(t, http.MethodGet, "/api/status", nil))
	if !got.Running {
		t.Fatal("the node under test is not running, so this is not the case the fields exist for")
	}
	if got.Network != string(config.NetworkUserspace) {
		t.Errorf("Network = %q, so nothing says which stack the machine is really on", got.Network)
	}
	if !strings.Contains(got.NetworkFallback, "install-helper") {
		t.Errorf("NetworkFallback = %q, which does not carry what the user has to do about it", got.NetworkFallback)
	}
}

// The interface mode in force is the ordinary case, and it must not be reported as a
// substitution: a reason on a node that is doing exactly what was asked would send someone
// to install a helper that is already working.
func TestAStackThatIsTheOneAskedForIsReportedWithNoReason(t *testing.T) {
	h := newHarness(t)
	h.node.status = tsnode.Status{BackendState: tsnode.StateRunning, Network: config.NetworkTUN}

	got := decode[StatusView](t, h.do(t, http.MethodGet, "/api/status", nil))
	if got.Network != string(config.NetworkTUN) {
		t.Errorf("Network = %q, want the interface mode", got.Network)
	}
	if got.NetworkFallback != "" {
		t.Errorf("a node on the stack it was asked for reported the substitution %q", got.NetworkFallback)
	}
}

// Restarting the whole process is a different event from rebuilding the node: this one
// takes the dashboard down with everything else. The answer therefore has to be sent
// before any of it begins, because the connection it travels on goes away too.
func TestRestartingTheProcessIsAcceptedRatherThanCompleted(t *testing.T) {
	h := newHarness(t)

	res := h.do(t, http.MethodPost, "/api/restart-app", nil)

	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: a completed 200 would claim a restart that has not happened", res.Code, http.StatusAccepted)
	}
	if h.lifecycle.calls != 1 {
		t.Errorf("RestartProcess called %d times, want 1", h.lifecycle.calls)
	}
	// The node restart is the other route entirely; confusing the two would rebuild the
	// node and leave the user waiting for a process that never went away.
	if h.restart.calls != 0 {
		t.Errorf("the node was rebuilt %d times by a process restart", h.restart.calls)
	}
}

// Stopping is the restart's sibling, and the difference matters: the caller is a second copy
// of app-tail that has already taken this one's place, so starting a replacement would undo
// the takeover. The answer is 202 for the same reason the restart's is -- nothing has
// happened yet, and the listener answering is part of what goes away.
func TestBeingAskedToQuitIsAcceptedRatherThanCompleted(t *testing.T) {
	h := newHarness(t)

	res := h.do(t, http.MethodPost, "/api/quit", nil)

	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusAccepted)
	}
	if h.lifecycle.stopCalls != 1 {
		t.Errorf("StopProcess called %d times, want 1", h.lifecycle.stopCalls)
	}
	if h.lifecycle.calls != 0 {
		t.Errorf("a request to stop restarted the process %d times, which would start a rival to the agent taking over", h.lifecycle.calls)
	}
}

// An agent already shutting down cannot honour the request, and the caller has to hear it:
// a refusal read as success ends its wait and starts a second agent beside this one.
func TestARefusedQuitIsReported(t *testing.T) {
	h := newHarness(t)
	h.lifecycle.stopErr = errors.New("agent is already shutting down")

	res := h.do(t, http.MethodPost, "/api/quit", nil)

	if res.Code < 400 {
		t.Fatalf("status = %d, want a failure: a refused shutdown reported as success starts two agents", res.Code)
	}
}

// An agent already shutting down cannot honour the request, and saying so is the only
// way the page knows not to sit waiting for a process that is not coming back.
func TestARefusedProcessRestartIsReported(t *testing.T) {
	h := newHarness(t)
	h.lifecycle.err = errors.New("agent is already shutting down")

	res := h.do(t, http.MethodPost, "/api/restart-app", nil)

	if res.Code < 400 {
		t.Fatalf("status = %d, want a failure: a refused restart reported as success leaves the page waiting forever", res.Code)
	}
	if body := res.Body.String(); !strings.Contains(body, "already shutting down") {
		t.Errorf("body = %q, want the agent's own reason", body)
	}
}

// Every route degrades to a clear 503 rather than a panic when its dependency is absent.
func TestProcessRestartWithoutTheCapabilityIsUnavailable(t *testing.T) {
	server := New(Options{Auth: testKeys, Deps: Deps{Version: "test"}})
	req := newAPIRequest(http.MethodPost, "/api/restart-app", nil)
	res := httptest.NewRecorder()

	server.Handler().ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusServiceUnavailable)
	}
}

// The traffic view is the dashboard's fastest poll, so it has to be a plain read of what
// the agent already holds rather than anything that reaches out.
func TestTheTrafficViewIsServedFromWhatTheAgentAlreadyHas(t *testing.T) {
	h := newHarness(t)
	h.traffic.view = TrafficView{
		IntervalSec: 1,
		WindowSec:   300,
		Points: []traffic.Point{
			{At: time.Unix(1, 0), ProxyUp: 1024, ProxyDown: 4096, Connections: 3},
		},
		Current: traffic.Point{ProxyUp: 1024, ProxyDown: 4096, Connections: 3},
		Peers: []TrafficPeer{
			{ID: "n1", Label: "nas", Online: true, RxBytes: 900, TxBytes: 120, Direct: true},
		},
		Destinations: []tsproxy.DestCounters{{Address: "nas:445", BytesUp: 120, BytesDown: 900}},
	}

	res := h.do(t, http.MethodGet, "/api/traffic", nil)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	got := decode[TrafficView](t, res)
	if got.IntervalSec != 1 || got.WindowSec != 300 {
		t.Errorf("interval/window = %d/%d, want 1/300 -- the axis the agent measured", got.IntervalSec, got.WindowSec)
	}
	if len(got.Points) != 1 || got.Points[0].ProxyUp != 1024 {
		t.Errorf("points = %+v, want the sampled series", got.Points)
	}
	if len(got.Peers) != 1 || got.Peers[0].Label != "nas" {
		t.Errorf("peers = %+v, want the device the tailnet carried to", got.Peers)
	}
	if len(got.Destinations) != 1 || got.Destinations[0].Address != "nas:445" {
		t.Errorf("destinations = %+v, want where the proxy's traffic went", got.Destinations)
	}
}

// A gap is the one thing a chart must not draw through: it means the interval could not
// be measured, not that nothing moved. It has to survive the wire as a flag rather than
// arriving as a plausible-looking zero.
func TestAGapSurvivesTheWireAsAGap(t *testing.T) {
	h := newHarness(t)
	h.traffic.view = TrafficView{
		IntervalSec: 1,
		Points:      []traffic.Point{{At: time.Unix(1, 0), Gap: true, Connections: 2}},
	}

	got := decode[TrafficView](t, h.do(t, http.MethodGet, "/api/traffic", nil))

	if len(got.Points) != 1 {
		t.Fatalf("got %d points, want 1", len(got.Points))
	}
	if !got.Points[0].Gap {
		t.Error("the gap flag was lost, so a chart would draw a floor nobody measured")
	}
	if got.Points[0].Connections != 2 {
		t.Errorf("connections = %d across the gap, want 2 -- a gauge is still true", got.Points[0].Connections)
	}
}

// The breakdown carries a series per key, and a null is the same fact the flat view's gap
// flag carries: this interval could not be measured. A JSON encoding that turned it into a
// zero would draw a floor nobody observed, on the one lane that says which device did it.
func TestABreakdownCarriesItsSeriesAndItsGaps(t *testing.T) {
	h := newHarness(t)
	rate := 1024.0
	h.traffic.lanes = map[string]TrafficBreakdown{
		"devices": {
			Lane:        "devices",
			IntervalSec: 1,
			WindowSec:   300,
			Folded:      2,
			Series: []TrafficSeries{{
				Key: "t1/n1", Label: "nas", Detail: "direct", Via: "t1", Peer: "n1",
				Up:   []*float64{&rate, nil},
				Down: []*float64{nil, &rate},
			}},
		},
	}

	got := decode[TrafficBreakdown](t, h.do(t, http.MethodGet, "/api/traffic/devices", nil))

	if got.Lane != "devices" || got.IntervalSec != 1 || got.WindowSec != 300 {
		t.Errorf("lane/interval/window = %q/%d/%d, want devices/1/300",
			got.Lane, got.IntervalSec, got.WindowSec)
	}
	if len(got.Series) != 1 {
		t.Fatalf("got %d series, want the one device", len(got.Series))
	}
	line := got.Series[0]
	if line.Key != "t1/n1" || line.Label != "nas" || line.Via != "t1" || line.Peer != "n1" {
		t.Errorf("series = %+v, want the device's key, name and what it hangs off", line)
	}
	if len(line.Up) != 2 || line.Up[0] == nil || *line.Up[0] != 1024 || line.Up[1] != nil {
		t.Errorf("up = %+v, want a measured second then a gap", line.Up)
	}
	if len(line.Down) != 2 || line.Down[0] != nil || line.Down[1] == nil {
		t.Errorf("down = %+v, want a gap then a measured second", line.Down)
	}
	if got.Folded != 2 {
		t.Errorf("folded = %d, want 2 -- a list cut short has to say so", got.Folded)
	}
}

// A route naming a lane this build does not have is a mistake somebody has to find. An
// empty breakdown would draw a blank chart, which reads as a network with nothing on it.
func TestABreakdownForAnUnknownLaneIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.traffic.lanes = map[string]TrafficBreakdown{"devices": {Lane: "devices"}}

	requireError(t, h.do(t, http.MethodGet, "/api/traffic/sockets", nil),
		http.StatusNotFound, "sockets")
}

// Every route degrades to a clear 503 rather than a panic when its dependency is absent.
func TestTheTrafficViewWithoutTheCapabilityIsUnavailable(t *testing.T) {
	server := New(Options{Auth: testKeys, Deps: Deps{Version: "test"}})
	req := newAPIRequest(http.MethodGet, "/api/traffic", nil)
	res := httptest.NewRecorder()

	server.Handler().ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusServiceUnavailable)
	}
}
