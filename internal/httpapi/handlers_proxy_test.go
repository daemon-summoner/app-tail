// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsproxy"
)

// The URLs are the product: a user copies them into a shell profile or a browser
// setting. socks5h rather than socks5 is the one that matters -- with socks5 the client
// resolves the name itself and every MagicDNS name fails.
func TestTheProxyViewCarriesUrlsAClientCanActuallyUse(t *testing.T) {
	h := newHarness(t)

	view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))

	if !strings.HasPrefix(view.SocksURL, "socks5h://") {
		t.Errorf("socksUrl = %q, want the socks5h scheme so the proxy resolves names", view.SocksURL)
	}
	if !strings.Contains(view.SocksURL, "127.0.0.1:1080") {
		t.Errorf("socksUrl = %q, want it to name the bound address", view.SocksURL)
	}
	if !strings.HasPrefix(view.HTTPURL, "http://") {
		t.Errorf("httpUrl = %q, want an http URL, which is what HTTP_PROXY takes", view.HTTPURL)
	}
	// The auto-config URL has to name the host the browser dialed. Any other name is
	// one that browser may not be able to fetch.
	if want := "http://" + testHost + "/proxy.pac"; view.PACURL != want {
		t.Errorf("pacUrl = %q, want %q", view.PACURL, want)
	}
}

// A shell command assembled in the dashboard is a command nothing tests. They are
// rendered here so the quoting and the flags are covered.
func TestTheProxyViewCarriesRunnableCommands(t *testing.T) {
	h := newHarness(t)

	view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))

	if len(view.Snippets) == 0 {
		t.Fatal("the view carries no commands, so the dashboard has to build them itself")
	}
	byID := map[string]tsproxy.Snippet{}
	for _, s := range view.Snippets {
		if s.Command == "" {
			t.Errorf("snippet %q has no command", s.ID)
		}
		if s.Label == "" {
			t.Errorf("snippet %q has no label", s.ID)
		}
		byID[s.ID] = s
	}

	for _, id := range []string{"exec", "ssh", "curl", "env"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("no %q command was offered", id)
		}
	}
	// --socks5 resolves locally and fails on a MagicDNS name; --socks5-hostname is the
	// flag that leaves the name for the proxy.
	if got := byID["curl"].Command; !strings.Contains(got, "--socks5-hostname") {
		t.Errorf("the curl command is %q, want --socks5-hostname", got)
	}
	// Without the dashboard in NO_PROXY, a program started from that shell that calls
	// the app-tail API sends the call through the proxy back to this same machine.
	if got := byID["env"].Command; !strings.Contains(got, testHost) {
		t.Errorf("the environment command is %q, want the dashboard address excluded via NO_PROXY", got)
	}
}

// Every state the proxy can be in has to produce one unambiguous verdict, because the
// dashboard, the tray and the CLI all read this rather than each deciding for itself.
func TestTheCapabilityDistinguishesEveryStateTheProxyCanBeIn(t *testing.T) {
	tests := []struct {
		name      string
		status    tsproxy.Status
		available bool
		degraded  bool
		reason    string
	}{
		{
			name:   "the module above it is switched off",
			status: tsproxy.Status{},
			reason: "the proxy module is switched off",
		},
		{
			// Both switches read as off here, and only one of them is: naming the module
			// while it is on sends the reader to a switch that is already on and never
			// mentions the one that is not.
			name:   "the module is on and this instance is switched off",
			status: tsproxy.Status{ModuleOn: true},
			reason: "this proxy is switched off",
		},
		{
			name:   "on but it could not bind",
			status: tsproxy.Status{Enabled: true, Error: "bind the proxy to 127.0.0.1:1080: address already in use"},
			reason: "address already in use",
		},
		{
			name:      "bound while no connection is running",
			status:    tsproxy.Status{Enabled: true, Listening: "127.0.0.1:1080", ConfiguredAddr: "127.0.0.1:1080"},
			available: true,
			degraded:  true,
			reason:    "no connection is running",
		},
		{
			name: "moved off the configured port",
			status: tsproxy.Status{
				Enabled: true, NetworksUp: true, Listening: "127.0.0.1:54321",
				ConfiguredAddr: "127.0.0.1:1080", MovedFromConfig: true,
			},
			available: true,
			degraded:  true,
			reason:    "1080",
		},
		{
			// The configured address is whatever was stored, and the sentence has to name
			// a port either way: "port  was taken" leaves the user with nothing to change.
			name: "moved off a configured address that is not host:port",
			status: tsproxy.Status{
				Enabled: true, NetworksUp: true, Listening: "127.0.0.1:54321",
				ConfiguredAddr: "1080", MovedFromConfig: true,
			},
			available: true,
			degraded:  true,
			reason:    "port 1080 was taken",
		},
		{
			name: "working",
			status: tsproxy.Status{
				Enabled: true, NetworksUp: true, Listening: "127.0.0.1:1080", ConfiguredAddr: "127.0.0.1:1080",
			},
			available: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.proxy.status = tt.status

			view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))
			capability := view.Capability

			if capability.Available != tt.available {
				t.Errorf("available = %v, want %v", capability.Available, tt.available)
			}
			if capability.Degraded != tt.degraded {
				t.Errorf("degraded = %v, want %v", capability.Degraded, tt.degraded)
			}
			if tt.reason != "" && !strings.Contains(capability.Reason, tt.reason) {
				t.Errorf("reason = %q, want it to mention %q", capability.Reason, tt.reason)
			}
			if tt.available && !tt.degraded && capability.Reason != "" {
				t.Errorf("a working proxy explained itself anyway: %q", capability.Reason)
			}
		})
	}
}

// The exposure is a property of the feature, not a transient state: a 127.0.0.1 bind
// restricts by host, not by user, and there is no portable way to tighten it. A user
// who learns that by discovering it was misled by this API.
func TestTheExposureIsStatedInEveryProxyState(t *testing.T) {
	for _, status := range []tsproxy.Status{
		{},
		{Enabled: true, Listening: "127.0.0.1:1080", NetworksUp: true, ConfiguredAddr: "127.0.0.1:1080"},
	} {
		h := newHarness(t)
		h.proxy.status = status

		view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))
		if len(view.Capability.Limits) == 0 {
			t.Fatalf("no limits were stated for status %+v", status)
		}
		if !strings.Contains(strings.Join(view.Capability.Limits, " "), "any local user") {
			t.Errorf("the limits do not state who can reach the tailnet: %v", view.Capability.Limits)
		}
	}
}

// Requiring a password turns the browser path off, because a PAC result line has
// nowhere to put one. Saying so is what stops a user concluding the file is broken.
func TestRequiringAPasswordIsReportedAsTheLimitItIs(t *testing.T) {
	h := newHarness(t)
	h.proxy.status.RequiresToken = true

	view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))

	if !view.RequiresPassword {
		t.Error("the view does not report that a password is required")
	}
	limits := strings.Join(view.Capability.Limits, " ")
	if !strings.Contains(limits, "auto-config") {
		t.Errorf("the limits do not mention the auto-config script: %v", view.Capability.Limits)
	}
	// The credential has to appear in the commands, or a user pastes one that fails
	// authentication with nothing to go on.
	var env string
	for _, s := range view.Snippets {
		if s.ID == "env" {
			env = s.Command
		}
	}
	if !strings.Contains(env, tsproxy.ProxyUser) {
		t.Errorf("the environment command is %q, want it to carry the proxy user", env)
	}
}

// The stored password is a secret redacted everywhere else in this API, so a command
// the dashboard displays must carry a stand-in the user substitutes rather than the
// real value. The commands are built from the proxy's status, which deliberately has
// nowhere to put a password -- this pins that, since the fix for "the pasted command
// does not authenticate" is exactly the change that would break it.
func TestCommandsCarryAStandInForThePasswordRatherThanTheRealOne(t *testing.T) {
	const stored = "hunter2-the-real-proxy-password"
	h := newHarness(t)
	h.proxy.status.RequiresToken = true
	h.settings.proxyInstance(t).Token = stored

	rec := h.do(t, http.MethodGet, "/api/proxy", nil)
	if strings.Contains(rec.Body.String(), stored) {
		t.Fatalf("the proxy view leaked the stored proxy password:\n%s", rec.Body.String())
	}

	// The credential form is "app-tail:<something>@". Matching the user name alone
	// would also match the binary in "app-tail exec", which carries no credential.
	credential := tsproxy.ProxyUser + ":"
	found := false
	view := decode[ProxyView](t, rec)
	for _, s := range view.Snippets {
		if !strings.Contains(s.Command, credential) {
			continue
		}
		found = true
		if !strings.Contains(s.Command, "PASSWORD") {
			t.Errorf("the %q command carries a credential with no stand-in for the password: %q",
				s.ID, s.Command)
		}
	}
	if !found {
		t.Error("no command carried the credential, so a user pasting one gets an authentication failure")
	}
	if !strings.Contains(view.SocksURL, "PASSWORD") {
		t.Errorf("socksUrl = %q, want a stand-in a user replaces", view.SocksURL)
	}
}

// Nothing is listening, so there is nothing to point at. Offering a command naming a
// port that is closed wastes the user's time and reads as a bug in the command.
func TestNoCommandsAreOfferedWhileNothingIsListening(t *testing.T) {
	h := newHarness(t)
	h.proxy.status = tsproxy.Status{Enabled: true}

	view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))

	if len(view.Snippets) != 0 {
		t.Errorf("commands were offered with nothing bound: %+v", view.Snippets)
	}
	if view.SocksURL != "" || view.PACURL != "" {
		t.Errorf("urls were offered with nothing bound: socks=%q pac=%q", view.SocksURL, view.PACURL)
	}
}

// What a proxy carries is the security boundary, and "tailnet" means nothing to someone
// who has not read the source. The view says what it does in words -- including the state
// worth naming loudest, an instance whose rules cover nothing.
func TestWhatTheProxyCarriesIsExplainedRatherThanNamed(t *testing.T) {
	h := newHarness(t)
	view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))
	if !strings.Contains(view.ScopeCarries, "refused") {
		t.Errorf("scopeCarries = %q, want it to say what happens to everything else", view.ScopeCarries)
	}

	h = newHarness(t)
	h.proxy.status.Scope = config.ScopeAll
	view = decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))
	if !strings.Contains(view.ScopeCarries, "this machine's own network") {
		t.Errorf("scopeCarries = %q for the wider grant, want it to say the machine's own "+
			"network is reachable too", view.ScopeCarries)
	}

	// No rules at all is not a narrow scope, it is nothing at all -- and an instance that
	// reaches nothing looks identical to a working one on every other field here.
	h = newHarness(t)
	h.proxy.status.Rules = 0
	view = decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))
	if !strings.Contains(view.ScopeCarries, "nothing") {
		t.Errorf("scopeCarries = %q with no rules, want it to say the proxy reaches nothing",
			view.ScopeCarries)
	}
}

// "A name resolves in my browser and fails through the proxy" is answered by which
// resolver the proxy asks and by nothing else on the page. Both modes have to say so:
// the default explains why a split-DNS domain fails, and the other explains why it now
// works -- and a mode that reported the wrong sentence would send someone hunting a
// resolver failure that is a setting.
func TestWhichResolverNamesGoToIsExplainedInBothModes(t *testing.T) {
	for _, tc := range []struct {
		via  config.ProxyResolveVia
		want string
	}{
		{via: config.ResolveViaNetmap, want: "this machine's resolver"},
		{via: config.ResolveViaTailnet, want: "split-DNS"},
	} {
		t.Run(string(tc.via), func(t *testing.T) {
			h := newHarness(t)
			h.proxy.status.ResolveVia = tc.via

			view := decode[ProxyView](t, h.do(t, http.MethodGet, "/api/proxy", nil))
			if view.ResolveVia != string(tc.via) {
				t.Errorf("resolveVia = %q, want %q", view.ResolveVia, tc.via)
			}
			if !strings.Contains(view.ResolveExplains, tc.want) {
				t.Errorf("resolveExplains = %q, want it to mention %q", view.ResolveExplains, tc.want)
			}
		})
	}
}

// Browsers refuse an auto-config script served as anything else.
func TestTheAutoConfigScriptIsServedAsAPacFile(t *testing.T) {
	h := newHarness(t)
	h.proxy.script = "function FindProxyForURL(url, host) { return \"SOCKS5 127.0.0.1:1080\"; }\n"

	rec := h.do(t, http.MethodGet, "/proxy.pac", nil)
	requireStatus(t, rec, http.StatusOK)

	if got := rec.Header().Get("Content-Type"); got != pacContentType {
		t.Errorf("Content-Type = %q, want %q", got, pacContentType)
	}
	if rec.Body.String() != h.proxy.script {
		t.Errorf("body = %q, want the script verbatim", rec.Body.String())
	}
	// The script is derived from live tailnet state, so a cached copy describes a
	// tailnet that has moved on.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// A browser fetching the script sends no Origin and asks for a loopback name, so it
// must pass the guards that protect the rest of the API.
func TestABrowserCanFetchTheAutoConfigScript(t *testing.T) {
	h := newHarness(t)

	req := newAPIRequest(http.MethodGet, "/proxy.pac", nil)
	req.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	requireStatus(t, rec, http.StatusOK)
}

// A script that cannot be built must not be served as an empty or partial file: a
// browser would take it and send everything the wrong way without complaint.
func TestAScriptThatCannotBeBuiltIsAnErrorRatherThanAnEmptyFile(t *testing.T) {
	h := newHarness(t)
	h.proxy.pacErr = errors.New("read the routes this tailnet reaches: backend is not running")

	rec := h.do(t, http.MethodGet, "/proxy.pac", nil)

	if rec.Code == http.StatusOK {
		t.Fatalf("a failed build was served as a script: %s", rec.Body.String())
	}
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "routes") {
		t.Errorf("error = %q, want the reason the script could not be built", body.Error)
	}
}

// "The proxy is listening" and "the proxy can reach that peer" are different questions.
// A destination that is refused or unreachable is the probe's answer, not a failure of
// the request -- answering 500 would make the dashboard show an error banner for a
// working proxy and a wrong hostname.
func TestAProbeReportsAnUnreachableDestinationAsAResultNotAFailure(t *testing.T) {
	h := newHarness(t)
	h.proxy.probe = ProxyProbeResult{Error: "no route to nope:22", ElapsedMs: 12}

	rec := h.do(t, http.MethodPost, "/api/proxy/probe", map[string]string{"address": "nope:22"})
	requireStatus(t, rec, http.StatusOK)

	result := decode[ProxyProbeResult](t, rec)
	if result.Reachable {
		t.Error("an unreachable destination was reported as reachable")
	}
	if result.Error == "" {
		t.Error("the probe reported no reason for the failure")
	}
	if result.Address != "nope:22" {
		t.Errorf("address = %q, want the destination that was probed", result.Address)
	}
}

func TestAProbeReportsHowADestinationWasReached(t *testing.T) {
	h := newHarness(t)
	h.proxy.probe = ProxyProbeResult{Reachable: true, ViaTailnet: true, ResolvedAddr: "100.64.1.5:22"}

	result := decode[ProxyProbeResult](t, h.do(t, http.MethodPost, "/api/proxy/probe",
		map[string]string{"address": "peer.tail1a2b3c.ts.net:22"}))

	if !result.Reachable || !result.ViaTailnet {
		t.Errorf("result = %+v, want a destination reached through the tailnet", result)
	}
	if result.ResolvedAddr != "100.64.1.5:22" {
		t.Errorf("resolvedAddr = %q, want the address actually dialed", result.ResolvedAddr)
	}
}

// A probe dials whatever it is given, so the input is checked before anything acts on
// it rather than surfacing as a dial error the user cannot interpret.
func TestAProbeRefusesAnAddressItCannotDial(t *testing.T) {
	tests := []struct {
		name string
		body map[string]string
	}{
		{"no address at all", map[string]string{}},
		{"an empty address", map[string]string{"address": "   "}},
		{"a host with no port", map[string]string{"address": "peer.tail1a2b3c.ts.net"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)

			rec := h.do(t, http.MethodPost, "/api/proxy/probe", tt.body)
			requireStatus(t, rec, http.StatusBadRequest)

			if len(h.proxy.probed) != 0 {
				t.Errorf("a rejected address was dialed anyway: %v", h.proxy.probed)
			}
		})
	}
}

// A probe that could not run at all is not a destination that could not be reached. The
// first is the proxy being broken and the second is the address being wrong, and only one
// of them is fixed by typing a different name.
func TestAProbeThatCouldNotRunIsAFailureRatherThanAnUnreachableDestination(t *testing.T) {
	h := newHarness(t)
	h.proxy.probeErr = errors.New("the proxy is not listening")

	rec := h.do(t, http.MethodPost, "/api/proxy/probe", map[string]string{"address": "peer:22"})

	if rec.Code == http.StatusOK {
		t.Fatalf("a probe that never ran was reported as a result: %s", rec.Body.String())
	}
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "not listening") {
		t.Errorf("error = %q, want the reason the probe could not run", body.Error)
	}
}

// A body that is not JSON has no address in it, so nothing may be dialled from it. Reading
// a zero value out of a failed decode would probe the empty string.
func TestAProbeRefusesABodyItCouldNotRead(t *testing.T) {
	h := newHarness(t)

	rec := h.doRaw(t, http.MethodPost, "/api/proxy/probe", "{not json")

	requireStatus(t, rec, http.StatusBadRequest)
	if len(h.proxy.probed) != 0 {
		t.Errorf("something was dialled out of an unreadable body: %v", h.proxy.probed)
	}
	// Falling through on a decode failure reaches the same 400 by way of an empty
	// address, and tells a caller whose JSON has one typo in it that they sent no
	// address at all.
	if body := decode[errorBody](t, rec); !strings.Contains(body.Error, "JSON") {
		t.Errorf("error = %q, want it to say the body could not be read", body.Error)
	}
}

// hangUpWriter is a client that went away after the response header. The status is
// already committed by then, so the write is the only place the loss can surface.
type hangUpWriter struct {
	header http.Header
	codes  []int
}

func (w *hangUpWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *hangUpWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

func (w *hangUpWriter) WriteHeader(code int) { w.codes = append(w.codes, code) }

// A browser that stops reading the auto-config script is not an agent failure, and by
// then there is nothing to answer with: the 200 is already on the wire. It has to be
// logged and survived, with no second status behind it -- a second one would corrupt the
// response on a connection the server is still holding open.
func TestAnAutoConfigScriptTheBrowserStoppedReadingIsLoggedRatherThanAnswered(t *testing.T) {
	var logged strings.Builder
	s := New(Options{
		Auth: testKeys,
		Deps: Deps{
			Proxy:   &fakeProxy{script: "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n"},
			Version: "test",
		},
		Logger: slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	w := &hangUpWriter{}
	s.handlePAC(w, newAPIRequest(http.MethodGet, "/proxy.pac", nil))

	if len(w.codes) != 1 || w.codes[0] != http.StatusOK {
		t.Errorf("statuses written = %v, want only the 200 that was already committed", w.codes)
	}
	if got := logged.String(); !strings.Contains(got, "auto-config") {
		t.Errorf("the browser losing the script was not logged, so a user reporting that "+
			"their proxy settings never applied leaves no trace here. log:\n%s", got)
	}
}
