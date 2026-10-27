// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/config"
)

// impostor is a listener on the agent's recorded port that is not the agent. It answers
// the identity check with whatever proof it is given and records every request, so a
// test can show the token never reached it.
type impostor struct {
	server *httptest.Server
	proof  func(nonce, local string) string

	mu       sync.Mutex
	requests []*http.Request
}

func newImpostor(t *testing.T, proof func(nonce, local string) string) *impostor {
	t.Helper()
	imp := &impostor{proof: proof}
	imp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imp.mu.Lock()
		imp.requests = append(imp.requests, r.Clone(context.Background()))
		imp.mu.Unlock()
		if r.URL.Path != "/api/auth/hello" {
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(`{"state":"Running"}`)); err != nil {
				t.Errorf("write reply: %v", err)
			}
			return
		}
		var req struct {
			Nonce string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode the identity check: %v", err)
		}
		local := r.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"proof": imp.proof(req.Nonce, local)}); err != nil {
			t.Errorf("answer the identity check: %v", err)
		}
	}))
	t.Cleanup(imp.server.Close)
	return imp
}

func (imp *impostor) seen() []*http.Request {
	imp.mu.Lock()
	defer imp.mu.Unlock()
	return append([]*http.Request(nil), imp.requests...)
}

// The dashboard-address record outlives a crashed agent, so whatever binds that port next
// is who the CLI dials. It must be challenged before the token goes anywhere: an answer
// from the wrong key, or the right key's answer for a different port -- what a squatter
// relaying the challenge to the real agent gets back -- both have to stop the command
// before a single request carries the token.
func TestTheCLIDoesNotSendItsTokenToAListenerThatCannotProveItself(t *testing.T) {
	realKeys, token := agentKeys(t, t.TempDir())
	otherKeys, _ := agentKeys(t, t.TempDir())

	tests := []struct {
		name  string
		proof func(nonce, local string) string
	}{
		{"a listener with no proof at all", func(string, string) string { return "" }},
		{"a listener holding some other token", func(nonce, local string) string {
			return otherKeys.Proof(nonce, local)
		}},
		{"a relay passing on the real agent's answer for another port", func(nonce, _ string) string {
			return realKeys.Proof(nonce, "127.0.0.1:8377")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imp := newImpostor(t, tt.proof)
			client := NewAuthenticatedClient(imp.server.URL, token)

			_, err := client.Status(context.Background())

			addr := strings.TrimPrefix(imp.server.URL, "http://")
			want := "something other than your app-tail agent is listening on " + addr +
				"; refusing to send it your credentials"
			if err == nil || err.Error() != want {
				t.Errorf("err = %v, want %q", err, want)
			}
			for _, r := range imp.seen() {
				if got := r.Header.Get("Authorization"); got != "" {
					t.Errorf("%s %s reached the impostor carrying Authorization %q", r.Method, r.URL.Path, got)
				}
				if r.URL.Path != "/api/auth/hello" {
					t.Errorf("the CLI went on to %s %s after a failed identity check", r.Method, r.URL.Path)
				}
			}
		})
	}
}

// The check costs a round trip, so a client makes it once and reuses the answer for every
// request after it -- `settings menu` makes dozens.
func TestAClientProvesTheAgentOnceAndThenSendsItsToken(t *testing.T) {
	var hellos int
	var mu sync.Mutex
	keys, token := agentKeys(t, t.TempDir())
	inner := answerHello(t, keys, token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"state":"Running"}`)); err != nil {
			t.Errorf("write reply: %v", err)
		}
	}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/hello" {
			mu.Lock()
			hellos++
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	client := NewAuthenticatedClient(srv.URL, token)

	for range 3 {
		if _, err := client.Status(context.Background()); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if hellos != 1 {
		t.Errorf("the client checked the agent's identity %d times for three requests, want once", hellos)
	}
}

// The token lives beside the config, written by the agent at start. A machine where the
// agent has never run has no token yet, and the CLI has to say so in the same words as
// any other sign that the agent is not running.
func TestDiscoverWithoutATokenSaysTheAgentIsNotRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := config.Open(path)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = "127.0.0.1:18377"
		return nil
	}); err != nil {
		t.Fatalf("seed the address: %v", err)
	}

	_, err = Discover(store)

	if !errors.Is(err, ErrNoAgent) {
		t.Errorf("err = %v, want ErrNoAgent", err)
	}
	if err == nil || !strings.Contains(err.Error(), "no API token") {
		t.Errorf("err = %v, want it to say there is no API token", err)
	}
}

func launchRoute(t *testing.T, link string) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"POST /api/auth/launch": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]string{"url": link}); err != nil {
				t.Errorf("write reply: %v", err)
			}
		},
	}
}

// stubBrowser records what the command would open instead of opening it.
func stubBrowser(t *testing.T, fail error) *[]string {
	t.Helper()
	var opened []string
	before := openBrowser
	openBrowser = func(u string) error {
		opened = append(opened, u)
		return fail
	}
	t.Cleanup(func() { openBrowser = before })
	return &opened
}

func TestDashboardPrintShowsTheSignInLinkTheAgentMinted(t *testing.T) {
	h := newHarness(t, launchRoute(t, "http://127.0.0.1:8377/?launch=abc"))
	opened := stubBrowser(t, nil)

	if err := h.run("dashboard", "--print"); err != nil {
		t.Fatalf("dashboard --print: %v", err)
	}

	if got := strings.TrimSpace(h.out()); got != "http://127.0.0.1:8377/?launch=abc" {
		t.Errorf("printed %q, want the minted link and nothing else", got)
	}
	if len(*opened) != 0 {
		t.Errorf("--print still opened a browser at %v", *opened)
	}
	reqs := h.recorded()
	if len(reqs) != 1 || reqs[0].Method != http.MethodPost || reqs[0].Path != "/api/auth/launch" {
		t.Fatalf("requests = %+v, want one POST /api/auth/launch", reqs)
	}
	// A printed link is for a person, who may open it from another account (a Docker host,
	// the far end of an SSH tunnel), so it has to be asked for as such.
	if got := strings.TrimSpace(reqs[0].Body); got != `{"anyAccount":true}` {
		t.Errorf("launch request body = %q, want a link any account may open", got)
	}
}

// The Vite dev server and an SSH tunnel both reach the agent through another address. The
// link has to open there, carrying the agent's path and token unchanged.
func TestDashboardBaseMovesTheLinkToAnotherAddress(t *testing.T) {
	h := newHarness(t, launchRoute(t, "http://127.0.0.1:8377/?launch=abc"))

	if err := h.run("dashboard", "--print", "--base", "http://localhost:5173"); err != nil {
		t.Fatalf("dashboard --base: %v", err)
	}

	if got := strings.TrimSpace(h.out()); got != "http://localhost:5173/?launch=abc" {
		t.Errorf("printed %q, want the link moved to the dev server", got)
	}
}

func TestDashboardRefusesABaseThatIsNotJustAnAddress(t *testing.T) {
	for _, base := range []string{"localhost:5173", "ftp://localhost:5173", "http://localhost:5173/app", "http://localhost:5173/?x=1"} {
		t.Run(base, func(t *testing.T) {
			h := newHarness(t, launchRoute(t, "http://127.0.0.1:8377/?launch=abc"))

			err := h.run("dashboard", "--print", "--base", base)

			if !errors.Is(err, ErrUsage) {
				t.Errorf("--base %q = %v, want a usage error", base, err)
			}
			if reqs := h.recorded(); len(reqs) != 0 {
				t.Errorf("a bad --base still minted a link: %+v", reqs)
			}
		})
	}
}

func TestDashboardOpensTheLinkInTheBrowser(t *testing.T) {
	h := newHarness(t, launchRoute(t, "http://127.0.0.1:8377/?launch=abc"))
	opened := stubBrowser(t, nil)

	if err := h.run("dashboard"); err != nil {
		t.Fatalf("dashboard: %v", err)
	}

	if len(*opened) != 1 || (*opened)[0] != "http://127.0.0.1:8377/?launch=abc" {
		t.Errorf("opened %v, want the minted link once", *opened)
	}
	if strings.Contains(h.out(), "launch=") {
		t.Errorf("the command printed the sign-in link it opened: %q", h.out())
	}
	// The opened link crossed a command line other accounts can read; only this account
	// may redeem it.
	if reqs := h.recorded(); len(reqs) != 1 || strings.TrimSpace(reqs[0].Body) != `{"anyAccount":false}` {
		t.Errorf("requests = %+v, want one launch asked for this account only", reqs)
	}
}

// A machine with no browser -- a server reached over SSH -- has to be told what to do
// instead, not left wondering why nothing opened.
func TestDashboardWithNoBrowserSaysToPrintTheLink(t *testing.T) {
	h := newHarness(t, launchRoute(t, "http://127.0.0.1:8377/?launch=abc"))
	stubBrowser(t, errors.New("no browser here"))

	err := h.run("dashboard")

	if err == nil || !strings.Contains(err.Error(), "no browser here") || !strings.Contains(err.Error(), "--print") {
		t.Errorf("err = %v, want the browser's failure and a pointer to --print", err)
	}
}

func TestAuthRotateAsksTheRunningAgentForANewToken(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/auth/rotate": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	})

	if err := h.run("auth", "rotate"); err != nil {
		t.Fatalf("auth rotate: %v", err)
	}

	reqs := h.recorded()
	if len(reqs) != 1 || reqs[0].Method != http.MethodPost || reqs[0].Path != "/api/auth/rotate" {
		t.Errorf("requests = %+v, want one POST /api/auth/rotate", reqs)
	}
	if !strings.Contains(h.out(), "signed out") {
		t.Errorf("output %q, want it to say every dashboard was signed out", h.out())
	}
}

// With no agent running nothing holds the token in memory, so deleting the file is the
// whole rotation: the next agent writes a fresh one.
func TestAuthRotateWithTheAgentStoppedRemovesTheTokenFile(t *testing.T) {
	h := newHarness(t, nil)
	h.stopAgent()
	tokenPath := filepath.Join(filepath.Dir(h.configPath), apiauth.TokenFileName)

	if err := h.run("auth", "rotate"); err != nil {
		t.Fatalf("auth rotate: %v", err)
	}

	if _, err := os.Stat(tokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the token file is still there after rotating offline: %v", err)
	}
	if !strings.Contains(h.out(), "No agent is running") {
		t.Errorf("output %q, want it to say no agent was running", h.out())
	}
}

// An agent that answers but refuses is not the same as no agent: deleting the token from
// under a running agent would lock the CLI out until it restarted.
func TestAuthRotateKeepsTheTokenWhenTheAgentRefuses(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/auth/rotate": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"disk full"}`, http.StatusInternalServerError)
		},
	})
	tokenPath := filepath.Join(filepath.Dir(h.configPath), apiauth.TokenFileName)

	err := h.run("auth", "rotate")

	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("err = %v, want the agent's refusal", err)
	}
	if _, statErr := os.Stat(tokenPath); statErr != nil {
		t.Errorf("a refused rotation removed the token file: %v", statErr)
	}
}

// An agent too busy to answer before the deadline is still running and still holds the
// token in memory. Deleting the file under it would leave every later command saying to
// start an agent that is already running, so the timeout is reported and the file stays.
func TestAuthRotateKeepsTheTokenWhenTheAgentIsTooBusyToAnswer(t *testing.T) {
	dir := t.TempDir()
	agentKeys(t, dir)
	tokenPath := filepath.Join(dir, apiauth.TokenFileName)

	// Accepts every connection and never says a word, the way an agent stuck behind a
	// slow request looks from outside.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var held sync.WaitGroup
	t.Cleanup(func() {
		busy.Close()
		held.Wait()
	})
	held.Add(1)
	go func() {
		defer held.Done()
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		for {
			conn, err := busy.Accept()
			if err != nil {
				return
			}
			conns = append(conns, conn)
		}
	}()

	configPath := filepath.Join(dir, "config.json")
	store, err := config.Open(configPath)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Settings.UIListen = busy.Addr().String()
		return nil
	}); err != nil {
		t.Fatalf("record the agent address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out, errOut strings.Builder
	err = Run(ctx, []string{"auth", "rotate", "--config", configPath},
		Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})

	if err == nil {
		t.Errorf("an agent that did not answer in time was reported as rotated; output %q", out.String())
	}
	if _, statErr := os.Stat(tokenPath); statErr != nil {
		t.Errorf("a timeout against a running agent removed the token file: %v", statErr)
	}
	if strings.Contains(out.String(), "No agent is running") {
		t.Errorf("output %q claims no agent is running, but one accepted the connection", out.String())
	}
}

func TestAuthNeedsTheRotateSubcommand(t *testing.T) {
	for _, args := range [][]string{{"auth"}, {"auth", "renew"}} {
		var out, errOut strings.Builder
		err := Run(context.Background(), args, Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }})
		if !errors.Is(err, ErrUsage) {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
		if err == nil || !strings.Contains(err.Error(), "auth rotate") {
			t.Errorf("%v = %v, want it to name `auth rotate`", args, err)
		}
	}
}

// A connection dropped after the rotate request was sent leaves it unknown whether the
// agent already wrote a new token. Treating that as "no agent" and deleting the file would
// lock the CLI out of an agent that is still running.
func TestAuthRotateKeepsTheTokenWhenTheAgentDropsTheRequest(t *testing.T) {
	h := newHarness(t, map[string]http.HandlerFunc{
		"POST /api/auth/rotate": func(w http.ResponseWriter, _ *http.Request) {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			if err := conn.Close(); err != nil {
				t.Errorf("drop the connection: %v", err)
			}
		},
	})
	tokenPath := filepath.Join(filepath.Dir(h.configPath), apiauth.TokenFileName)

	if err := h.run("auth", "rotate"); err == nil {
		t.Error("a dropped rotate request was reported as a rotation")
	}

	if _, err := os.Stat(tokenPath); err != nil {
		t.Errorf("a rotate request the agent may have acted on removed the token file: %v", err)
	}
}
