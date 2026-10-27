// SPDX-License-Identifier: MIT

package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/peeraccount"
)

// testKeys is the authenticator every test server is built with, and testToken the token
// newAPIRequest presents. They are real keys over a real token file, so the tests below
// exercise the authentication the agent ships rather than a stand-in for it.
var (
	testKeys  *apiauth.Keys
	testToken string
)

func TestMain(m *testing.M) {
	os.Exit(runWithTestKeys(m))
}

func runWithTestKeys(m *testing.M) int {
	dir, err := os.MkdirTemp("", "httpapi-keys-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create the test key directory: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)
	if testKeys, err = apiauth.LoadOrCreate(dir); err != nil {
		fmt.Fprintf(os.Stderr, "create the test keys: %v\n", err)
		return 1
	}
	if testToken, err = apiauth.Read(dir); err != nil {
		fmt.Fprintf(os.Stderr, "read the test token: %v\n", err)
		return 1
	}
	return m.Run()
}

// testClock is a settable time source for keys whose expiries a test steps through.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ownKeys gives a harness keys of its own, for a test that rotates them or moves their
// clock, and returns the token they accept.
func ownKeys(t *testing.T, h *harness, opts ...apiauth.Option) (*apiauth.Keys, string) {
	t.Helper()
	dir := t.TempDir()
	keys, err := apiauth.LoadOrCreate(dir, opts...)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	token, err := apiauth.Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	h.server.auth = keys
	return keys, token
}

// doAs issues a request carrying exactly the Authorization value given, "" for none.
func (h *harness) doAs(t *testing.T, authorization, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = newAPIRequest(method, target, nil)
	} else {
		req = newAPIRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Del("Authorization")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	return rec
}

func requireSignInRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	requireError(t, rec, http.StatusUnauthorized, "app-tail dashboard")
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="app-tail"` {
		t.Errorf("WWW-Authenticate = %q, want the bearer challenge", got)
	}
}

var pathWildcard = regexp.MustCompile(`\{[^}]+\}`)

// The table is walked rather than listed so a route added to the server without thought
// for authentication fails here on the day it is added.
func TestEveryAPIRouteRefusesARequestWithoutAToken(t *testing.T) {
	h := newHarness(t)
	h.node.status.AuthURL = "https://login.example/auth/secret-capability"
	other, _ := ownKeys(t, newHarness(t))
	foreign, err := other.MintLaunch(apiauth.ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	foreignSession, err := other.RedeemLaunch(foreign)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}

	walked := 0
	for _, rt := range h.server.routeTable() {
		method, target, ok := strings.Cut(rt.pattern, " ")
		if !ok || !strings.HasPrefix(target, "/api/") {
			continue
		}
		if method == http.MethodPost && (target == sessionPath || target == helloPath) {
			continue
		}
		walked++
		target = pathWildcard.ReplaceAllString(target, "x")
		for name, authorization := range map[string]string{
			"no header":                "",
			"a wrong token":            "Bearer atk1_" + strings.Repeat("A", 43),
			"the token as Basic":       "Basic " + testToken,
			"another agent's session":  "Bearer " + foreignSession,
			"a bare token, no scheme":  testToken,
			"an empty bearer":          "Bearer ",
			"a launch token as bearer": "Bearer " + foreign,
		} {
			t.Run(rt.pattern+"/"+name, func(t *testing.T) {
				rec := h.doAs(t, authorization, method, target, "{}")
				requireSignInRefusal(t, rec)
				if strings.Contains(rec.Body.String(), "secret-capability") {
					t.Fatalf("the refusal disclosed the auth URL: %s", rec.Body.String())
				}
			})
		}
	}
	// A walk that found nothing would pass on any server, the one with no guard included.
	if walked < 50 {
		t.Fatalf("walked only %d authenticated routes; the route table walk is broken", walked)
	}
	if h.node.loginCalls != 0 || h.node.logoutCall != 0 {
		t.Errorf("a refused request still reached a handler: %d logins, %d logouts",
			h.node.loginCalls, h.node.logoutCall)
	}
}

// An unclean spelling of an API path is judged as the route the mux would send it to.
func TestAnUncleanAPIPathStillNeedsAToken(t *testing.T) {
	h := newHarness(t)
	for _, target := range []string{"/x/../api/status", "/api/./status", "/api"} {
		rec := h.doAs(t, "", http.MethodGet, target, "")
		requireSignInRefusal(t, rec)
	}
}

func TestThePACAndAssetsNeedNoToken(t *testing.T) {
	h := newUIHarness(t)
	h.server.deps.SysProxy = newHarness(t).sysProxy
	for _, target := range []string{"/", "/assets/index-a1b2c3.js", "/favicon.svg", "/healthz", "/proxy.pac", "/settings"} {
		rec := h.doAs(t, "", http.MethodGet, target, "")
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("GET %s without a token = %d, want it served: %s", target, rec.Code, rec.Body.String())
		}
	}
}

func TestASessionFromALaunchTokenWorksOnce(t *testing.T) {
	h := newHarness(t)
	_, token := ownKeys(t, h)

	rec := h.doAs(t, "Bearer "+token, http.MethodPost, "/api/auth/launch", "")
	requireStatus(t, rec, http.StatusOK)
	link, err := url.Parse(decode[launchResponse](t, rec).URL)
	if err != nil {
		t.Fatalf("parse the launch URL: %v", err)
	}
	if link.Scheme != "http" || link.Host != testHost || link.Path != "/" {
		t.Errorf("launch URL = %s, want http://%s/?launch=...", link, testHost)
	}
	launch := link.Query().Get("launch")
	if launch == "" {
		t.Fatalf("launch URL %s carries no launch token", link)
	}

	body := fmt.Sprintf(`{"launch":%q}`, launch)
	rec = h.doAs(t, "", http.MethodPost, sessionPath, body)
	requireStatus(t, rec, http.StatusOK)
	session := decode[sessionResponse](t, rec).Session

	requireStatus(t, h.doAs(t, "Bearer "+session, http.MethodGet, "/api/status", ""), http.StatusOK)

	requireSignInRefusal(t, h.doAs(t, "", http.MethodPost, sessionPath, body))
	requireError(t, h.doAs(t, "", http.MethodPost, sessionPath, `{}`), http.StatusBadRequest, "launch")
}

// mintLaunch asks the server for a sign-in link with the body given and returns its token.
func mintLaunch(t *testing.T, h *harness, token, body string) string {
	t.Helper()
	rec := h.doAs(t, "Bearer "+token, http.MethodPost, "/api/auth/launch", body)
	requireStatus(t, rec, http.StatusOK)
	link, err := url.Parse(decode[launchResponse](t, rec).URL)
	if err != nil {
		t.Fatalf("parse the launch URL: %v", err)
	}
	launch := link.Query().Get("launch")
	if launch == "" {
		t.Fatalf("launch URL %s carries no launch token", link)
	}
	return launch
}

// A link the tray opens crossed a command line any account can read. Whoever reads it there
// must not get a session with it, and the browser it was opened in must still get one.
func TestASignInLinkRedeemedFromAnotherAccountIsRefusedAndLeftForTheBrowser(t *testing.T) {
	h := newHarness(t)
	_, token := ownKeys(t, h)
	launch := mintLaunch(t, h, token, "")

	var gotPeer, gotServer netip.AddrPort
	h.callerAccount = func(peer, server netip.AddrPort) error {
		gotPeer, gotServer = peer, server
		return peeraccount.ErrOtherAccount
	}
	body := fmt.Sprintf(`{"launch":%q}`, launch)
	requireError(t, h.doAs(t, "", http.MethodPost, sessionPath, body), http.StatusForbidden, "account")
	if gotPeer != netip.MustParseAddrPort("192.0.2.1:1234") || gotServer != netip.MustParseAddrPort(testHost) {
		t.Errorf("checked %v -> %v, want the caller's address and the address it reached", gotPeer, gotServer)
	}

	h.callerAccount = func(netip.AddrPort, netip.AddrPort) error { return nil }
	requireStatus(t, h.doAs(t, "", http.MethodPost, sessionPath, body), http.StatusOK)
}

// `app-tail dashboard --print` shows the link to a person, who may open it from another
// account: a Docker container's host or the far end of an SSH tunnel.
func TestALinkAskedForAnyAccountIsNotCheckedAgainstTheCaller(t *testing.T) {
	h := newHarness(t)
	_, token := ownKeys(t, h)
	launch := mintLaunch(t, h, token, `{"anyAccount":true}`)

	h.callerAccount = func(netip.AddrPort, netip.AddrPort) error {
		t.Error("the caller's account was checked for a link meant for any account")
		return peeraccount.ErrOtherAccount
	}
	requireStatus(t, h.doAs(t, "", http.MethodPost, sessionPath, fmt.Sprintf(`{"launch":%q}`, launch)), http.StatusOK)

	requireError(t, h.doAs(t, "Bearer "+token, http.MethodPost, "/api/auth/launch", `{"anyAccount":"yes"}`),
		http.StatusBadRequest, "")
}

// Over a real connection the real check finds this test's own socket, so the browser
// running as the agent's account signs in.
func TestABrowserRunningAsThisAccountSignsInOverARealConnection(t *testing.T) {
	h := newHarness(t)
	_, token := ownKeys(t, h)
	srv := httptest.NewServer(h.server.Handler())
	t.Cleanup(srv.Close)
	launch := mintLaunch(t, h, token, "")

	req, err := http.NewRequest(http.MethodPost, srv.URL+sessionPath, strings.NewReader(fmt.Sprintf(`{"launch":%q}`, launch)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = testHost
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("redeem over a real connection = %d: %s", resp.StatusCode, raw)
	}
}

// The link names whatever loopback host the caller reached the agent by, which is what
// makes `app-tail dashboard` open through the Vite dev server or an SSH tunnel.
func TestALaunchLinkNamesTheHostTheCallerDialed(t *testing.T) {
	h := newHarness(t)
	req := newAPIRequest(http.MethodPost, "/api/auth/launch", nil)
	req.Host = "localhost:5173"
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	requireStatus(t, rec, http.StatusOK)
	if got := decode[launchResponse](t, rec).URL; !strings.HasPrefix(got, "http://localhost:5173/?launch=") {
		t.Errorf("launch URL = %q, want it on localhost:5173", got)
	}
}

func TestAnExpiredSessionIsRefused(t *testing.T) {
	h := newHarness(t)
	clock := &testClock{now: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}
	keys, _ := ownKeys(t, h, apiauth.WithClock(clock.Now))
	launch, err := keys.MintLaunch(apiauth.ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	session, err := keys.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}
	requireStatus(t, h.doAs(t, "Bearer "+session, http.MethodGet, "/api/status", ""), http.StatusOK)

	clock.advance(apiauth.SessionLifetime)
	requireSignInRefusal(t, h.doAs(t, "Bearer "+session, http.MethodGet, "/api/status", ""))
}

func TestAnExpiredLaunchTokenGetsNoSession(t *testing.T) {
	h := newHarness(t)
	clock := &testClock{now: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}
	keys, _ := ownKeys(t, h, apiauth.WithClock(clock.Now))
	launch, err := keys.MintLaunch(apiauth.ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	clock.advance(apiauth.LaunchLifetime)
	requireSignInRefusal(t, h.doAs(t, "", http.MethodPost, sessionPath, fmt.Sprintf(`{"launch":%q}`, launch)))
}

func TestRotationEndsEverySession(t *testing.T) {
	h := newHarness(t)
	keys, token := ownKeys(t, h)
	launch, err := keys.MintLaunch(apiauth.ThisAccount)
	if err != nil {
		t.Fatalf("MintLaunch: %v", err)
	}
	session, err := keys.RedeemLaunch(launch)
	if err != nil {
		t.Fatalf("RedeemLaunch: %v", err)
	}

	requireStatus(t, h.doAs(t, "Bearer "+session, http.MethodPost, "/api/auth/rotate", ""), http.StatusNoContent)

	requireSignInRefusal(t, h.doAs(t, "Bearer "+session, http.MethodGet, "/api/status", ""))
	requireSignInRefusal(t, h.doAs(t, "Bearer "+token, http.MethodGet, "/api/status", ""))
}

// The proof covers the address the connection arrived on, so a Host header a relaying
// squatter writes cannot steer it onto the squatter's own port.
func TestTheHelloProofNamesTheAddressTheConnectionArrivedOn(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.server.Handler())
	t.Cleanup(srv.Close)
	local := strings.TrimPrefix(srv.URL, "http://")

	nonce, err := apiauth.NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+helloPath, strings.NewReader(fmt.Sprintf(`{"nonce":%q}`, nonce)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:1"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hello status = %d", resp.StatusCode)
	}
	var got helloResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode hello: %v", err)
	}
	if !apiauth.VerifyProof(testToken, nonce, local, got.Proof) {
		t.Errorf("the proof does not verify for the listener's own address %s", local)
	}
	if apiauth.VerifyProof(testToken, nonce, "127.0.0.1:1", got.Proof) {
		t.Error("the proof verified for the address the Host header claimed")
	}
}

func TestAHelloWithAnUnusableNonceIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{`{"nonce":"short"}`, `{"nonce":""}`, `{"nonce":"` + strings.Repeat("A", 100) + `"}`, `{}`} {
		rec := h.doAs(t, "", http.MethodPost, helloPath, body)
		requireError(t, rec, http.StatusBadRequest, "nonce")
	}
}

func TestARefusedRequestIsLoggedWithoutItsToken(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t)
	h.server.logger = slog.New(slog.NewTextHandler(&logs, nil))

	requireSignInRefusal(t, h.doAs(t, "Bearer atk1_not-the-right-secret", http.MethodGet, "/api/forwards", ""))

	line := logs.String()
	if !strings.Contains(line, "/api/forwards") || !strings.Contains(line, "GET") {
		t.Errorf("the refusal was not logged with its method and path: %q", line)
	}
	if strings.Contains(line, "not-the-right-secret") {
		t.Errorf("the log carries the presented token: %q", line)
	}
}

func TestNewRefusesToBuildAServerWithoutAuthentication(t *testing.T) {
	defer func() {
		rec := recover()
		if rec == nil || !strings.Contains(fmt.Sprint(rec), "Auth") {
			t.Errorf("New without Auth recovered %v, want a panic naming Auth", rec)
		}
	}()
	New(Options{})
}
