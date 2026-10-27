// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sellitus/app-tail/internal/config"
)

// Every write route decodes a body. A decoder failure that fell through to the handler
// would apply a zero-valued spec -- blanking a forward's target, or clearing every
// setting -- instead of refusing the request.
func TestEveryWriteRouteRefusesAMalformedBodyWithoutApplyingAnything(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"create forward, truncated json", http.MethodPost, "/api/forwards", `{"name":`},
		{"create forward, not an object", http.MethodPost, "/api/forwards", `["nope"]`},
		{"create forward, unknown field", http.MethodPost, "/api/forwards", `{"noSuchField":"x"}`},
		{"update forward", http.MethodPut, "/api/forwards/fwd_1", `{"listenPort":`},
		{"toggle forward", http.MethodPost, "/api/forwards/fwd_1/toggle", `{"enabled":"yes"}`},
		{"update settings", http.MethodPut, "/api/settings", `{"hostname":`},
		{"set autostart", http.MethodPost, "/api/autostart", `{"enabled":`},
		{"create preset", http.MethodPost, "/api/presets", `{"name":`},
		{"policy preview", http.MethodPost, "/api/policy/preview", `{"clientId":`},
		{"policy apply", http.MethodPost, "/api/policy/apply", `{"clientId":`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.forwards.items = []ForwardView{viewOf(config.Forward{
				ID: "fwd_1", Name: "Existing", Direction: config.ToLocal, Protocol: config.TCP,
				BindAddr: "127.0.0.1", ListenPort: 2222, Target: "box:22", Enabled: true,
			})}
			before := h.forwards.items[0]

			rec := h.doRaw(t, tc.method, tc.path, tc.body)

			requireStatus(t, rec, http.StatusBadRequest)
			if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "JSON") {
				t.Errorf("error = %q, want it to say the body could not be parsed", body.Error)
			}
			if h.forwards.items[0] != before {
				t.Errorf("a rejected request still mutated the forward:\n before %+v\n  after %+v",
					before, h.forwards.items[0])
			}
			if h.forwards.createCalled != 0 {
				t.Errorf("a rejected request reached Create %d times", h.forwards.createCalled)
			}
			if h.autostart.setCalls != 0 {
				t.Errorf("a rejected request reached SetEnabled %d times", h.autostart.setCalls)
			}
		})
	}
}

// A body larger than the cap has to be refused rather than buffered. Without the limit
// a single request can make the agent allocate until the machine swaps, and the agent
// listens on loopback where any local process can reach it.
func TestABodyOverTheSizeCapIsRefused(t *testing.T) {
	h := newHarness(t)

	oversized := `{"name":"` + strings.Repeat("x", maxRequestBytes+1) + `"}`
	rec := h.doRaw(t, http.MethodPost, "/api/forwards", oversized)

	requireStatus(t, rec, http.StatusBadRequest)
	if h.forwards.createCalled != 0 {
		t.Error("an oversized body still reached Create")
	}
}

// The dashboard's switch posts a toggle with no body at all, meaning "flip whatever it
// is now". That is a different code path from the explicit {"enabled":false} the tests
// already cover, and it is the one every user hits.
func TestAToggleWithNoBodyFlipsTheCurrentValue(t *testing.T) {
	h := newHarness(t)
	h.forwards.items = []ForwardView{viewOf(config.Forward{
		ID: "fwd_1", Direction: config.ToLocal, Protocol: config.TCP,
		BindAddr: "127.0.0.1", ListenPort: 2222, Target: "box:22", Enabled: true,
	})}

	rec := h.doRaw(t, http.MethodPost, "/api/forwards/fwd_1/toggle", "")
	requireStatus(t, rec, http.StatusOK)
	if view := decode[ForwardView](t, rec); view.Enabled {
		t.Error("an empty toggle left an enabled forward enabled")
	}

	rec = h.doRaw(t, http.MethodPost, "/api/forwards/fwd_1/toggle", "")
	requireStatus(t, rec, http.StatusOK)
	if view := decode[ForwardView](t, rec); !view.Enabled {
		t.Error("a second empty toggle did not switch the forward back on")
	}
}

// Toggling a forward that is not there must report which forward, not fall through to
// a flip of the zero value and create one.
func TestAnEmptyToggleForAnUnknownForwardIs404(t *testing.T) {
	h := newHarness(t)

	rec := h.doRaw(t, http.MethodPost, "/api/forwards/fwd_absent/toggle", "")

	requireStatus(t, rec, http.StatusNotFound)
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "fwd_absent") {
		t.Errorf("error = %q, want it to name the forward that was not found", body.Error)
	}
}

// A login item the platform cannot read about is not the same as one that is off. If a
// read failure came back as false the dashboard would show the switch off, the user
// would flip it on, and the write would fail for the same underlying reason.
func TestAnAutostartReadFailureIsReportedRatherThanReadAsOff(t *testing.T) {
	h := newHarness(t)
	h.autostart.queryErr = errors.New("launch agent directory is not readable")

	rec := h.do(t, http.MethodGet, "/api/autostart", nil)

	if rec.Code == http.StatusOK {
		t.Fatalf("a failed query answered 200: %s", rec.Body.String())
	}
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "not readable") {
		t.Errorf("error = %q, want the underlying failure", body.Error)
	}
}

// The write succeeds but the read-back fails: the handler reports what the system says
// rather than what was asked for, so it must surface that failure instead of claiming
// the state the caller wanted.
func TestAnAutostartWriteWhoseReadBackFailsDoesNotClaimSuccess(t *testing.T) {
	h := newHarness(t)
	h.autostart.queryErr = errors.New("login item vanished after the write")

	rec := h.do(t, http.MethodPost, "/api/autostart", map[string]bool{"enabled": true})

	if rec.Code == http.StatusOK {
		t.Fatalf("a failed read-back answered 200: %s", rec.Body.String())
	}
	if h.autostart.setCalls != 1 {
		t.Errorf("SetEnabled was called %d times, want 1", h.autostart.setCalls)
	}
}

// An autostart request with no enabled key is a client bug, not a request to turn it
// off. Defaulting to false would silently disable a user's login item on a malformed
// request.
func TestAnAutostartRequestWithoutAnEnabledKeyIsRefused(t *testing.T) {
	h := newHarness(t)
	h.autostart.enabled = true

	rec := h.doRaw(t, http.MethodPost, "/api/autostart", `{}`)

	requireStatus(t, rec, http.StatusBadRequest)
	if h.autostart.setCalls != 0 {
		t.Error("a request with no enabled key still wrote the login item")
	}
	if !h.autostart.enabled {
		t.Error("the login item was switched off by a request that never asked for it")
	}
}

// The dashboard iterates whatever this returns. A JSON null instead of an empty array
// makes the preset picker throw rather than render an empty list, and the whole
// add-forward dialog fails to open.
func TestAnEmptyPresetListIsAnEmptyArrayNotNull(t *testing.T) {
	h := newHarness(t)
	h.server.deps.Presets = nilPresets{}

	rec := h.do(t, http.MethodGet, "/api/presets", nil)
	requireStatus(t, rec, http.StatusOK)

	if got := strings.TrimSpace(rec.Body.String()); !strings.Contains(got, `"presets":[]`) {
		t.Errorf("body = %s, want an empty array for presets", got)
	}
}

// Same contract on the other two list endpoints, for the same reason.
func TestAnEmptyForwardAndPeerListAreEmptyArraysNotNull(t *testing.T) {
	h := newHarness(t)
	h.forwards.items = nil
	h.node.peers = nil

	rec := h.do(t, http.MethodGet, "/api/forwards", nil)
	requireStatus(t, rec, http.StatusOK)
	if got := strings.TrimSpace(rec.Body.String()); !strings.Contains(got, `"forwards":[]`) {
		t.Errorf("forwards body = %s, want an empty array", got)
	}

	rec = h.do(t, http.MethodGet, "/api/peers", nil)
	requireStatus(t, rec, http.StatusOK)
	if got := strings.TrimSpace(rec.Body.String()); !strings.Contains(got, `"peers":[]`) {
		t.Errorf("peers body = %s, want an empty array", got)
	}
}

// nilPresets returns a nil slice, which is what a store with nothing in it does.
type nilPresets struct{ Presets }

func (nilPresets) List() []config.Preset { return nil }

// The suggest-port endpoint feeds the add-forward wizard. A protocol it cannot honor
// has to be refused rather than silently treated as TCP, which would suggest a port
// already taken by a UDP forward.
func TestSuggestPortValidatesItsQueryParameters(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		wantStatus  int
		wantMessage string
	}{
		{"no protocol defaults to tcp", "", http.StatusOK, ""},
		{"unknown protocol", "?protocol=sctp", http.StatusBadRequest, "protocol must be"},
		{"preferred is not a number", "?preferred=eighty", http.StatusBadRequest, "port number"},
		{"preferred is out of range", "?preferred=70000", http.StatusBadRequest, "1-65535"},
		{"preferred is zero", "?preferred=0", http.StatusBadRequest, "1-65535"},
		{"preferred is negative", "?preferred=-1", http.StatusBadRequest, "1-65535"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			rec := h.do(t, http.MethodGet, "/api/forwards/suggest-port"+tc.query, nil)
			requireStatus(t, rec, tc.wantStatus)
			if tc.wantMessage != "" {
				if body := decode[errorBody](t, rec); !strings.Contains(body.Error, tc.wantMessage) {
					t.Errorf("error = %q, want it to contain %q", body.Error, tc.wantMessage)
				}
			}
		})
	}
}

// The wizard passes the chosen target and lets its port become the preferred local
// port, unless it asks for a specific one. Getting that precedence backwards would
// ignore whatever the user typed.
func TestSuggestPortPrefersAnExplicitPortOverTheTargetsOwn(t *testing.T) {
	h := newHarness(t)

	h.do(t, http.MethodGet, "/api/forwards/suggest-port?target=box%3A8080", nil)
	if got := h.forwards.lastSuggest.preferred; got != 8080 {
		t.Errorf("preferred = %d, want the target's own port 8080", got)
	}

	h.do(t, http.MethodGet, "/api/forwards/suggest-port?target=box%3A8080&preferred=9999", nil)
	if got := h.forwards.lastSuggest.preferred; got != 9999 {
		t.Errorf("preferred = %d, want the explicit 9999 to win over the target's port", got)
	}
}

// --- the embedded dashboard ------------------------------------------------

// A path traversal must never reach outside the embedded filesystem. The agent listens
// on loopback, so any local process can ask.
func TestTheDashboardRefusesPathsThatEscapeTheEmbeddedFilesystem(t *testing.T) {
	h := newUIHarnessOver(t, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
	})

	for _, path := range []string{"/../server.go", "/assets/../../etc/passwd"} {
		rec := h.do(t, http.MethodGet, path, nil)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "package httpapi") {
			t.Errorf("%s escaped the embedded filesystem: %s", path, rec.Body.String())
		}
	}
}

// A damaged embedded filesystem is not a missing route: the difference between "this
// asset was never built in" and "reading it failed" is the difference between a build
// bug and a corrupt binary, and only the latter is worth logging loudly.
func TestADamagedEmbeddedFilesystemFallsBackToTheShellRatherThanCrashing(t *testing.T) {
	base := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<!doctype html>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	}
	h := newUIHarnessOver(t, brokenFS{FS: base, err: errors.New("input/output error")})

	// An extension-less path still gets the shell, because index.html is readable.
	rec := h.do(t, http.MethodGet, "/some/route", nil)
	requireStatus(t, rec, http.StatusOK)

	// A real asset whose read fails is a 404 rather than a crash or a truncated body.
	rec = h.do(t, http.MethodGet, "/assets/app.js", nil)
	requireStatus(t, rec, http.StatusNotFound)
}

// http.ServeContent needs to seek. A file that cannot must be refused rather than
// served as an empty 200, which under nosniff renders as a blank dashboard with no
// error anywhere.
func TestAnUnseekableAssetIsNotServedAsAnEmptyResponse(t *testing.T) {
	base := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<!doctype html>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	}
	h := newUIHarnessOver(t, unseekableFS{FS: base})

	rec := h.do(t, http.MethodGet, "/assets/app.js", nil)

	requireStatus(t, rec, http.StatusNotFound)
	if strings.Contains(rec.Body.String(), "console.log") {
		t.Error("an unseekable asset was served anyway")
	}
}

// The dashboard answers HEAD because that is what health checks and link previewers
// send. Refusing it would make an ordinary probe look like an outage.
func TestTheDashboardAnswersHeadButNotWrites(t *testing.T) {
	h := newUIHarnessOver(t, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
	})

	rec := h.do(t, http.MethodHead, "/", nil)
	requireStatus(t, rec, http.StatusOK)

	rec = h.do(t, http.MethodDelete, "/", nil)
	requireStatus(t, rec, http.StatusMethodNotAllowed)
}

// An invalid path must be refused before it reaches the filesystem at all.
func TestTheDashboardRefusesAnInvalidPath(t *testing.T) {
	h := newUIHarnessOver(t, fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
	})

	rec := h.do(t, http.MethodGet, "/%2e%2e%2f", nil)
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "package") {
		t.Errorf("an invalid path was served: %s", rec.Body.String())
	}
}

// --- listener lifecycle ----------------------------------------------------

// A dashboard port already in use is the most common startup failure there is: a second
// agent, or a first one that did not exit. The message has to name the address, because
// a bare "bind failed" leaves the user with nothing to look for.
func TestListenReportsAPortThatIsAlreadyTaken(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the blocking listener: %v", err)
	}
	defer blocker.Close()

	s := New(Options{Auth: testKeys, Deps: Deps{}})
	addr, err := s.Listen(blocker.Addr().String())

	if err == nil {
		t.Fatalf("Listen succeeded on a taken port and returned %v", addr)
	}
	if !strings.Contains(err.Error(), blocker.Addr().String()) {
		t.Errorf("error = %q, want it to name the address that could not be bound", err)
	}
	if s.Addr() != nil {
		t.Errorf("Addr = %v after a failed Listen, want nil", s.Addr())
	}
}

// A listener that fails for a reason other than shutdown must surface it. Swallowing it
// would leave Run waiting on a server that stopped serving, and the dashboard would be
// silently unreachable for the rest of the process's life.
func TestServeSurfacesARealListenerFailure(t *testing.T) {
	fatal := errors.New("too many open files")
	s := New(Options{Auth: testKeys, Deps: Deps{}})
	s.ln = failingAcceptListener{err: fatal}

	err := s.Serve()

	if err == nil {
		t.Fatal("Serve returned nil for a listener that failed permanently")
	}
	if !errors.Is(err, fatal) {
		t.Errorf("Serve = %v, want it to carry %v", err, fatal)
	}
}

// The status line goes out before the body is encoded, so an encoder failure cannot be
// turned into an error response. It must be logged and survived: panicking here would
// take down the connection mid-body and, without the guard, the whole handler.
func TestABodyThatCannotBeEncodedIsLoggedRatherThanPanicking(t *testing.T) {
	var logged strings.Builder
	s := New(Options{
		Auth:   testKeys,
		Deps:   Deps{Version: "test"},
		Logger: slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	rec := httptest.NewRecorder()
	// A channel has no JSON representation, which is what a response struct that grew
	// an unmarshalable field looks like at runtime.
	s.writeJSON(rec, http.StatusOK, map[string]any{"stream": make(chan int)})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the 200 that was already committed before the encode", rec.Code)
	}
	if got := logged.String(); !strings.Contains(got, "writing http response body failed") {
		t.Errorf("the encoder failure was not logged; the agent would return a truncated "+
			"body with no trace of why. log:\n%s", got)
	}
}

// failingAcceptListener fails Accept permanently, which is what a descriptor exhaustion
// or a revoked socket looks like to net/http.
type failingAcceptListener struct{ err error }

func (l failingAcceptListener) Accept() (net.Conn, error) { return nil, l.err }
func (failingAcceptListener) Close() error                { return nil }
func (failingAcceptListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8377}
}

// --- error classification --------------------------------------------------

// classify is the whole contract between the agent's error types and the status codes
// the dashboard branches on. A conflict answered as a 500 loses the "which forward"
// detail the add dialog shows, and a validation error answered as a 500 makes the
// dashboard offer "retry" for something that will never succeed.
func TestClassifyMapsEachErrorKindToTheStatusTheDashboardExpects(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"conflict", &config.ConflictError{Endpoint: "TCP 127.0.0.1:2222", OtherID: "fwd_1"}, http.StatusConflict},
		{"wrapped conflict", fmt.Errorf("create: %w",
			&config.ConflictError{Endpoint: "TCP 127.0.0.1:2222"}), http.StatusConflict},
		{"validation", &config.ValidationError{Field: "target", Message: "is required"}, http.StatusBadRequest},
		{"wrapped validation", fmt.Errorf("update: %w",
			&config.ValidationError{Field: "target", Message: "is required"}), http.StatusBadRequest},
		{"not found", config.ErrNotFound, http.StatusNotFound},
		{"wrapped not found", fmt.Errorf("forward %q: %w", "fwd_1", config.ErrNotFound), http.StatusNotFound},
		{"unavailable", Unavailable("forwards", "not wired"), http.StatusServiceUnavailable},
		{"anything else", errors.New("something broke"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, body := classify(tc.err)
			if status != tc.want {
				t.Errorf("classify(%v) = %d, want %d", tc.err, status, tc.want)
			}
			if body.Error == "" {
				t.Error("the response body carries no message")
			}
		})
	}
}

// A conflict must carry the other forward's identity, not just a sentence. The add
// dialog uses those fields to point at the rule the user already has.
func TestAConflictCarriesTheOtherForwardsIdentity(t *testing.T) {
	_, body := classify(&config.ConflictError{
		Endpoint: "TCP 127.0.0.1:2222", OtherID: "fwd_ssh", OtherName: "SSH to buildbox",
	})

	if body.Conflict == nil {
		t.Fatal("a conflict response carries no conflict detail; the dialog cannot name the clash")
	}
	if body.Conflict.ForwardID != "fwd_ssh" || body.Conflict.Name != "SSH to buildbox" {
		t.Errorf("conflict detail = %+v, want the other forward's id and name", body.Conflict)
	}
	if body.Conflict.Endpoint != "TCP 127.0.0.1:2222" {
		t.Errorf("conflict endpoint = %q, want the endpoint that clashed", body.Conflict.Endpoint)
	}
}

// An unavailable error with no reason still has to name the dependency, or the 503 says
// nothing at all.
func TestAnUnavailableErrorWithNoReasonStillNamesTheDependency(t *testing.T) {
	status, body := classify(Unavailable("forwards", ""))

	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", status)
	}
	if !strings.Contains(body.Error, "forwards") {
		t.Errorf("error = %q, want it to name the dependency", body.Error)
	}
}

// newUIHarnessOver builds a server serving ui over the same fakes as newHarness. The
// sibling in server_test.go serves the realistic asset set; this one takes a filesystem
// that is deliberately damaged.
func newUIHarnessOver(t *testing.T, ui fs.FS) *harness {
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
			Policy:    h.policy,
			Restart:   h.restart,
			Version:   "test",
		},
		UI: ui,
	})
	return h
}
