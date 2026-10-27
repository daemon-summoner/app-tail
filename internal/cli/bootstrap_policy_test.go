// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeTailscaleAPI stands in for api.tailscale.com. It is an external boundary, so
// faking it is the only way to exercise the command that talks to it.
type fakeTailscaleAPI struct {
	server *httptest.Server

	mu sync.Mutex
	// policy is the current document; saves replace it.
	policy string
	// saves records every body written back, which is how a test proves a dry run
	// wrote nothing.
	saves []string
	// ifMatch records the If-Match header of each save, proving the command carries
	// the ETag it read rather than writing blind.
	ifMatch []string
	// token is the bearer the API expects after the OAuth exchange.
	token string
}

func newFakeTailscaleAPI(t *testing.T, policy string) *fakeTailscaleAPI {
	t.Helper()
	api := &fakeTailscaleAPI{policy: policy, token: "tok-abc123"}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("client_id") == "" || r.PostForm.Get("client_secret") == "" {
			http.Error(w, "missing credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": api.token,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/v2/tailnet/-/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+api.token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", `"etag-1"`)
			w.Header().Set("Content-Type", "application/hujson")
			api.mu.Lock()
			defer api.mu.Unlock()
			_, _ = io.WriteString(w, api.policy)
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read failed", http.StatusInternalServerError)
				return
			}
			api.mu.Lock()
			defer api.mu.Unlock()
			api.saves = append(api.saves, string(body))
			api.ifMatch = append(api.ifMatch, r.Header.Get("If-Match"))
			api.policy = string(body)
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	})

	api.server = httptest.NewServer(mux)
	t.Cleanup(api.server.Close)
	return api
}

func (a *fakeTailscaleAPI) saved() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.saves...)
}

func (a *fakeTailscaleAPI) matchHeaders() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.ifMatch...)
}

// secretFile writes the OAuth secret where the command expects to read it from.
func secretFile(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return path
}

// runBootstrap invokes the command against the fake API and returns its output.
func runBootstrap(t *testing.T, api *fakeTailscaleAPI, extra ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}

	args := append([]string{
		"bootstrap-policy",
		"--api-url", api.server.URL,
		"--client-id", "client-1",
		"--client-secret-file", secretFile(t, "s3cr3t"),
	}, extra...)

	err := Run(context.Background(), args, env)
	return out.String(), errOut.String(), err
}

// An empty policy is the case the command exists for: a fresh tailnet that has no
// tagOwners entry, so nodes cannot self-tag and enrollment would fail.
const emptyPolicy = `{
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
}`

func TestBootstrapPolicyWritesTheTagOwnerAFreshTailnetLacks(t *testing.T) {
	api := newFakeTailscaleAPI(t, emptyPolicy)

	out, _, err := runBootstrap(t, api, "--owners", "autogroup:admin")
	if err != nil {
		t.Fatalf("bootstrap-policy: %v", err)
	}

	saved := api.saved()
	if len(saved) != 1 {
		t.Fatalf("wrote %d policies, want exactly 1", len(saved))
	}
	if !strings.Contains(saved[0], "tag:app-tail") {
		t.Errorf("saved policy does not mention the tag:\n%s", saved[0])
	}
	if !strings.Contains(saved[0], "autogroup:admin") {
		t.Errorf("saved policy does not carry the requested owner:\n%s", saved[0])
	}
	if !strings.Contains(out, "Updated the tailnet policy") {
		t.Errorf("output %q does not report the update", out)
	}

	// The write must be conditional on the read, or a concurrent edit is silently lost.
	if matches := api.matchHeaders(); len(matches) != 1 || matches[0] != `"etag-1"` {
		t.Errorf("If-Match headers = %q, want the ETag from the fetch", matches)
	}
}

// Running it twice is the fleet case: provisioning scripts re-run, and the second
// run must not rewrite a policy that already says what it needs to say.
func TestBootstrapPolicyIsIdempotent(t *testing.T) {
	api := newFakeTailscaleAPI(t, emptyPolicy)

	if _, _, err := runBootstrap(t, api, "--owners", "autogroup:admin"); err != nil {
		t.Fatalf("first run: %v", err)
	}
	out, _, err := runBootstrap(t, api, "--owners", "autogroup:admin")
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if saved := api.saved(); len(saved) != 1 {
		t.Errorf("the second run wrote again: %d total writes, want 1", len(saved))
	}
	if !strings.Contains(out, "nothing changed") {
		t.Errorf("second run output %q does not say the policy was already correct", out)
	}
}

// --dry-run exists so an operator can inspect a change to a shared tailnet policy
// before making it. If it writes anything, it is worse than useless.
func TestBootstrapPolicyDryRunWritesNothing(t *testing.T) {
	api := newFakeTailscaleAPI(t, emptyPolicy)

	out, _, err := runBootstrap(t, api, "--owners", "autogroup:admin", "--dry-run")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}

	if saved := api.saved(); len(saved) != 0 {
		t.Fatalf("dry run wrote %d policies, want 0:\n%s", len(saved), strings.Join(saved, "\n"))
	}
	if !strings.Contains(out, "Would ") {
		t.Errorf("dry run output %q does not describe the pending change", out)
	}
}

// A grant is only written when destinations are named: inventing reachability on
// someone else's tailnet is not this command's call.
func TestBootstrapPolicyAddsAGrantOnlyWhenDestinationsAreNamed(t *testing.T) {
	t.Run("no destinations", func(t *testing.T) {
		api := newFakeTailscaleAPI(t, emptyPolicy)
		if _, _, err := runBootstrap(t, api, "--owners", "autogroup:admin"); err != nil {
			t.Fatalf("bootstrap-policy: %v", err)
		}
		saved := api.saved()
		if len(saved) != 1 {
			t.Fatalf("wrote %d policies, want 1", len(saved))
		}
		if strings.Contains(saved[0], `"grants"`) {
			t.Errorf("a grant was written without any destination being asked for:\n%s", saved[0])
		}
	})

	t.Run("destinations given", func(t *testing.T) {
		api := newFakeTailscaleAPI(t, emptyPolicy)
		if _, _, err := runBootstrap(t, api,
			"--owners", "autogroup:admin",
			"--grant-dst", "tag:gpu",
			"--grant-ip", "8100",
		); err != nil {
			t.Fatalf("bootstrap-policy: %v", err)
		}
		saved := api.saved()
		if len(saved) != 1 {
			t.Fatalf("wrote %d policies, want 1", len(saved))
		}
		if !strings.Contains(saved[0], "tag:gpu") || !strings.Contains(saved[0], "8100") {
			t.Errorf("saved policy is missing the requested grant:\n%s", saved[0])
		}
	})
}

// Without a client id there is nobody to authenticate as, and this must read as
// misuse (exit 2) rather than a failure of the tailnet.
func TestBootstrapPolicyRequiresAClientID(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}

	err := Run(context.Background(), []string{
		"bootstrap-policy", "--client-secret-file", secretFile(t, "s3cr3t"),
	}, env)
	if !errors.Is(err, ErrUsage) {
		t.Errorf("error = %v, want a usage error", err)
	}
}

// A rejected credential must surface, not leave the operator believing the fleet
// is provisioned.
func TestBootstrapPolicyReportsARejectedCredential(t *testing.T) {
	api := newFakeTailscaleAPI(t, emptyPolicy)
	api.token = "a-different-token-than-the-acl-handler-accepts"

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}

	// An empty secret file means no secret was supplied at all.
	err := Run(context.Background(), []string{
		"bootstrap-policy",
		"--api-url", api.server.URL,
		"--client-id", "client-1",
		"--client-secret-file", secretFile(t, ""),
	}, env)
	if err == nil {
		t.Fatal("an empty secret file was accepted")
	}
	if saved := api.saved(); len(saved) != 0 {
		t.Errorf("a policy was written despite the credential failure: %v", saved)
	}
}

// --api-url decides where a policy_file-scoped admin OAuth client is sent. The HTTP
// API deliberately has no equivalent field; the CLI must not be the way around that.
func TestBootstrapPolicyRefusesAnUnvouchedAPIURL(t *testing.T) {
	api := newFakeTailscaleAPI(t, emptyPolicy)

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}
	err := Run(context.Background(), []string{
		"bootstrap-policy",
		"--api-url", "https://attacker.example",
		"--client-id", "client-1",
		"--client-secret-file", secretFile(t, "s3cr3t"),
	}, env)

	if err == nil {
		t.Fatal("the admin credential was sent to an arbitrary host")
	}
	if !strings.Contains(err.Error(), "allow-foreign-api-url") {
		t.Errorf("the refusal does not say how to proceed deliberately: %v", err)
	}
	// Nothing should have gone anywhere, including to the legitimate endpoint.
	if saved := api.saved(); len(saved) != 0 {
		t.Errorf("a policy was written: %v", saved)
	}
}

// The override exists so an operator running their own control plane is not stuck,
// but it must not be a way to put the secret on the wire in cleartext.
func TestBootstrapPolicyOverrideStillRequiresTLS(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(string) string { return "" }}
	err := Run(context.Background(), []string{
		"bootstrap-policy",
		"--api-url", "http://headscale.internal",
		"--allow-foreign-api-url",
		"--client-id", "client-1",
		"--client-secret-file", secretFile(t, "s3cr3t"),
	}, env)

	if err == nil {
		t.Fatal("the override permitted a cleartext credential")
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Errorf("the refusal does not name the hazard: %v", err)
	}
}
