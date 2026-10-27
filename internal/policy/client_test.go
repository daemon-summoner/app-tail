// SPDX-License-Identifier: MIT

package policy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeControl is a stand-in for the Tailscale control API: it holds one policy
// document, hands out ETags, and enforces If-Match the way the real API does.
type fakeControl struct {
	mu          sync.Mutex
	policy      string
	etag        string
	saves       int
	lastBody    string
	lastIfMatch string

	clientID     string
	clientSecret string

	tokenStatus int
	fetchStatus int
	saveStatus  int
	omitETag    bool
	// concurrentWrite runs before a save is validated, modelling another admin
	// changing the policy between our read and our write.
	concurrentWrite func(c *fakeControl)
}

func newFakeControl(policy string) *fakeControl {
	return &fakeControl{
		policy:       policy,
		etag:         `"v1"`,
		clientID:     "client-id",
		clientSecret: "client-secret-with-policy-file-scope",
	}
}

func (c *fakeControl) start(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "example.com", srv.Client())
	if err := client.Authenticate(context.Background(), c.clientID, c.clientSecret); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return client
}

func (c *fakeControl) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/v2/oauth/token":
		c.serveToken(w, r)
	case strings.HasSuffix(r.URL.Path, "/acl"):
		c.serveACL(w, r)
	default:
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}
}

func (c *fakeControl) serveToken(w http.ResponseWriter, r *http.Request) {
	if c.tokenStatus != 0 {
		http.Error(w, `{"message":"invalid client"}`, c.tokenStatus)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("client_id") != c.clientID || r.PostForm.Get("client_secret") != c.clientSecret {
		http.Error(w, `{"message":"bad credentials"}`, http.StatusUnauthorized)
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		http.Error(w, `{"message":"bad grant type"}`, http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, `{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}`)
}

func (c *fakeControl) serveACL(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer tok-abc" {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		if c.fetchStatus != 0 {
			http.Error(w, `{"message":"forbidden: requires policy_file scope"}`, c.fetchStatus)
			return
		}
		if !c.omitETag {
			w.Header().Set("ETag", c.etag)
		}
		w.Header().Set("Content-Type", "application/hujson")
		fmt.Fprint(w, c.policy)

	case http.MethodPost:
		if c.concurrentWrite != nil {
			c.concurrentWrite(c)
			c.concurrentWrite = nil
		}
		if c.saveStatus != 0 {
			http.Error(w, `{"message":"policy rejected"}`, c.saveStatus)
			return
		}
		c.lastIfMatch = r.Header.Get("If-Match")
		if c.lastIfMatch != c.etag {
			http.Error(w, `{"message":"etag mismatch"}`, http.StatusPreconditionFailed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		c.saves++
		c.lastBody = string(body)
		c.policy = string(body)
		c.etag = fmt.Sprintf(`"v%d"`, c.saves+1)
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

func (c *fakeControl) current() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.policy
}

// saveCount reports how many writes reached the control plane, read under the lock so
// a test can check it while a request is still in flight.
func (c *fakeControl) saveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saves
}

// --- tests ----------------------------------------------------------------

func TestBootstrapWritesTheTagOwnerThroughTheAPI(t *testing.T) {
	control := newFakeControl(`{
	// Hand-maintained policy.
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`)
	client := control.start(t)

	result, err := Bootstrap(context.Background(), client, Options{Tag: appTailTag})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !result.Changed {
		t.Fatal("Bootstrap reported no change on a policy with no app-tail entries")
	}
	if control.saves != 1 {
		t.Fatalf("policy saved %d times, want 1", control.saves)
	}
	if !strings.Contains(control.current(), appTailTag) {
		t.Fatalf("the saved policy has no app-tail tag:\n%s", control.current())
	}
	if !strings.Contains(control.current(), "Hand-maintained policy") {
		t.Fatalf("the admin's comment was lost:\n%s", control.current())
	}
}

// Writing without If-Match would let this command clobber a concurrent edit.
func TestSaveSendsTheETagItFetchedWith(t *testing.T) {
	control := newFakeControl(`{}`)
	client := control.start(t)

	if _, err := Bootstrap(context.Background(), client, Options{Tag: appTailTag}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if control.lastIfMatch != `"v1"` {
		t.Fatalf("If-Match = %q, want the fetched ETag %q", control.lastIfMatch, `"v1"`)
	}
}

// Somebody else editing the policy mid-run must abort the write, not overwrite it.
func TestConcurrentPolicyEditAbortsTheWrite(t *testing.T) {
	control := newFakeControl(`{}`)
	control.concurrentWrite = func(c *fakeControl) {
		c.policy = `{"tagOwners": {"tag:other": ["group:sre"]}}`
		c.etag = `"v99"`
	}
	client := control.start(t)

	_, err := Bootstrap(context.Background(), client, Options{Tag: appTailTag})
	if err == nil {
		t.Fatal("Bootstrap overwrote a policy that changed underneath it")
	}
	if !strings.Contains(err.Error(), "changed while this bootstrap was running") {
		t.Fatalf("error %v does not explain the concurrent edit", err)
	}
	if control.saves != 0 {
		t.Fatalf("policy was saved %d times despite the conflict", control.saves)
	}
	if !strings.Contains(control.current(), "tag:other") {
		t.Fatalf("the concurrent edit was clobbered:\n%s", control.current())
	}
}

// An idempotent re-run must not even issue a write.
func TestBootstrapMakesNoWriteWhenNothingIsMissing(t *testing.T) {
	control := newFakeControl(`{"tagOwners": {"tag:app-tail": ["autogroup:admin"]}}`)
	client := control.start(t)

	result, err := Bootstrap(context.Background(), client, Options{Tag: appTailTag})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if result.Changed {
		t.Fatal("Bootstrap reported a change on an already-bootstrapped policy")
	}
	if control.saves != 0 {
		t.Fatalf("policy was written %d times when nothing was missing", control.saves)
	}
}

// Without an ETag there is no optimistic concurrency, so a write would be a blind
// overwrite of whatever is there.
func TestFetchRefusesAResponseWithNoETag(t *testing.T) {
	control := newFakeControl(`{}`)
	control.omitETag = true
	client := control.start(t)

	_, err := Bootstrap(context.Background(), client, Options{Tag: appTailTag})
	if err == nil {
		t.Fatal("Bootstrap proceeded without an ETag")
	}
	if !strings.Contains(err.Error(), "ETag") {
		t.Fatalf("error %v does not name the missing ETag", err)
	}
	if control.saves != 0 {
		t.Fatal("a write was attempted without an ETag")
	}
}

// The policy_file scope is a much stronger credential than the per-node one; being
// refused it must surface, not be swallowed.
func TestInsufficientScopeIsReported(t *testing.T) {
	control := newFakeControl(`{}`)
	control.fetchStatus = http.StatusForbidden
	client := control.start(t)

	_, err := Bootstrap(context.Background(), client, Options{Tag: appTailTag})
	if err == nil {
		t.Fatal("Bootstrap succeeded despite a 403 from the API")
	}
	if !strings.Contains(err.Error(), "policy_file") {
		t.Fatalf("error %v does not pass through the API's explanation", err)
	}
}

func TestSaveFailureIsReported(t *testing.T) {
	control := newFakeControl(`{}`)
	control.saveStatus = http.StatusBadRequest
	client := control.start(t)

	_, err := Bootstrap(context.Background(), client, Options{Tag: appTailTag})
	if err == nil {
		t.Fatal("Bootstrap reported success despite a rejected save")
	}
	if !strings.Contains(err.Error(), "policy rejected") {
		t.Fatalf("error %v does not pass through the API's reason", err)
	}
}

func TestAuthenticateRejectsBadCredentials(t *testing.T) {
	control := newFakeControl(`{}`)
	srv := httptest.NewServer(http.HandlerFunc(control.serve))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "example.com", srv.Client())
	err := client.Authenticate(context.Background(), "client-id", "wrong-secret")
	if err == nil {
		t.Fatal("Authenticate accepted a wrong secret")
	}
	if !strings.Contains(err.Error(), "bad credentials") {
		t.Fatalf("error %v does not pass through the API's reason", err)
	}
}

func TestAuthenticateRequiresBothHalvesOfTheCredential(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "example.com", nil)
	if err := client.Authenticate(context.Background(), "", "secret"); err == nil {
		t.Error("Authenticate accepted an empty client id")
	}
	if err := client.Authenticate(context.Background(), "id", "  "); err == nil {
		t.Error("Authenticate accepted a blank client secret")
	}
}

// Every request must carry the bearer token; an unauthenticated client must fail
// before it reaches the network.
func TestRequestsBeforeAuthenticationFail(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "example.com", nil)
	if _, err := client.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch succeeded on an unauthenticated client")
	}
}

func TestSaveWithoutAnETagIsRefused(t *testing.T) {
	control := newFakeControl(`{}`)
	client := control.start(t)

	err := client.Save(context.Background(), Document{Raw: []byte(`{}`)}, []byte(`{}`))
	if err == nil {
		t.Fatal("Save proceeded with no ETag")
	}
	if control.saves != 0 {
		t.Fatal("a write reached the API without an ETag")
	}
}

// BootstrapAll must fold every tag into a single write, under the ETag it fetched
// with, leaving unrelated policy content and comments intact.
func TestBootstrapAllWritesEveryTagInOneSave(t *testing.T) {
	control := newFakeControl(`{
	// operator policy
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`)
	client := control.start(t)

	result, err := BootstrapAll(context.Background(), client, []Options{
		{Tag: "tag:app-tail"},
		{Tag: "tag:app-tail-edge"},
	}, false)
	if err != nil {
		t.Fatalf("BootstrapAll: %v", err)
	}
	if !result.Changed {
		t.Fatal("BootstrapAll reported no change on a policy with no app-tail entries")
	}
	if control.saves != 1 {
		t.Fatalf("policy saved %d times, want exactly one write for both tags", control.saves)
	}
	cur := control.current()
	for _, tag := range []string{"tag:app-tail", "tag:app-tail-edge"} {
		if !strings.Contains(cur, tag) {
			t.Errorf("saved policy is missing %s:\n%s", tag, cur)
		}
	}
	if !strings.Contains(cur, "operator policy") {
		t.Errorf("the operator's comment was lost:\n%s", cur)
	}
}

// A dry run reports whether an apply would change the policy but must write nothing.
func TestBootstrapAllDryRunWritesNothing(t *testing.T) {
	control := newFakeControl(`{}`)
	client := control.start(t)

	result, err := BootstrapAll(context.Background(), client, []Options{{Tag: appTailTag}}, true)
	if err != nil {
		t.Fatalf("BootstrapAll dry run: %v", err)
	}
	if !result.Changed {
		t.Error("a dry run against a fresh policy must report that an apply would change it")
	}
	if control.saves != 0 {
		t.Fatalf("a dry run wrote the policy %d times", control.saves)
	}
}

// An idempotent re-run must not even issue a write.
func TestBootstrapAllMakesNoWriteWhenNothingIsMissing(t *testing.T) {
	control := newFakeControl(`{"tagOwners": {"tag:app-tail": ["autogroup:admin"]}}`)
	client := control.start(t)

	result, err := BootstrapAll(context.Background(), client, []Options{{Tag: appTailTag}}, false)
	if err != nil {
		t.Fatalf("BootstrapAll: %v", err)
	}
	if result.Changed {
		t.Error("BootstrapAll reported a change on an already-satisfied policy")
	}
	if control.saves != 0 {
		t.Fatalf("policy was written %d times when nothing was missing", control.saves)
	}
}

// A policy edited between the fetch and the write must abort, not clobber, exactly
// as the single-tag Bootstrap does.
func TestBootstrapAllAbortsOnAConcurrentEdit(t *testing.T) {
	control := newFakeControl(`{}`)
	control.concurrentWrite = func(c *fakeControl) {
		c.policy = `{"tagOwners": {"tag:other": ["group:sre"]}}`
		c.etag = `"v99"`
	}
	client := control.start(t)

	_, err := BootstrapAll(context.Background(), client, []Options{{Tag: appTailTag}}, false)
	if err == nil {
		t.Fatal("BootstrapAll overwrote a policy that changed underneath it")
	}
	if control.saves != 0 {
		t.Fatalf("policy was saved %d times despite the conflict", control.saves)
	}
	if !strings.Contains(control.current(), "tag:other") {
		t.Fatalf("the concurrent edit was clobbered:\n%s", control.current())
	}
}

func TestNewClientFillsInDefaults(t *testing.T) {
	c := NewClient("", "", nil)
	if c.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, DefaultBaseURL)
	}
	if c.Tailnet != DefaultTailnet {
		t.Errorf("Tailnet = %q, want %q", c.Tailnet, DefaultTailnet)
	}
	if c.HTTP == nil {
		t.Error("HTTP client was left nil")
	}
	if got := NewClient("https://api.example.com/", "x", nil).BaseURL; got != "https://api.example.com" {
		t.Errorf("BaseURL = %q, want the trailing slash trimmed", got)
	}
}

// --- api url guard --------------------------------------------------------

// recordingTransport answers every request successfully and counts them. A test
// that asserts zero calls against it is asserting the secret never went anywhere,
// not merely that the call failed.
type recordingTransport struct {
	mu    sync.Mutex
	calls int
}

func (rt *recordingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.calls++
	rt.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"leaked"}`)),
		Header:     http.Header{},
	}, nil
}

func (rt *recordingTransport) count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.calls
}

// The OAuth client this carries has policy_file scope over the whole tailnet.
// Sending it to a host the operator did not vouch for is credential exfiltration,
// so the refusal has to happen before the request, not after a failed response.
func TestAuthenticateRefusesToSendTheSecretToAnUnvouchedHost(t *testing.T) {
	for _, tt := range []struct {
		name         string
		baseURL      string
		allowForeign bool
	}{
		{"foreign https host", "https://attacker.example", false},
		{"cleartext off-loopback", "http://198.51.100.7:8080", false},
		// The acknowledgement relaxes the host rule, never the transport.
		{"cleartext with the override", "http://attacker.example", true},
		// Label-boundary lookalikes must not read as tailscale.com.
		{"suffix lookalike", "https://tailscale.com.attacker.example", false},
		{"prefix lookalike", "https://nottailscale.com", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			c := NewClient(tt.baseURL, "-", &http.Client{Transport: rt})
			c.AllowForeignHost = tt.allowForeign

			err := c.Authenticate(context.Background(), "client-id", "s3cr3t")
			if err == nil {
				t.Fatal("the credential was sent to an unvouched host")
			}
			if n := rt.count(); n != 0 {
				t.Fatalf("%d request(s) reached the wire; the secret left the process", n)
			}
		})
	}
}

// The guard must not break the hosts the command legitimately talks to, or every
// operator learns to pass the override reflexively.
func TestAuthenticateAcceptsVouchedHosts(t *testing.T) {
	for _, tt := range []struct {
		name         string
		baseURL      string
		allowForeign bool
	}{
		{"the real control plane", DefaultBaseURL, false},
		{"a tailscale subdomain", "https://api.eu.tailscale.com", false},
		{"loopback over cleartext", "http://127.0.0.1:8080", false},
		{"loopback by name", "http://localhost:8080", false},
		{"ipv6 loopback", "http://[::1]:8080", false},
		{"a self-hosted control plane, acknowledged", "https://headscale.internal", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			c := NewClient(tt.baseURL, "-", &http.Client{Transport: rt})
			c.AllowForeignHost = tt.allowForeign

			if err := c.Authenticate(context.Background(), "client-id", "s3cr3t"); err != nil {
				t.Fatalf("a legitimate endpoint was refused: %v", err)
			}
			if n := rt.count(); n != 1 {
				t.Fatalf("token exchange made %d requests, want 1", n)
			}
		})
	}
}

// A redirect is the one way past ValidateBaseURL: Go replays the request body on 307
// and 308, so a host that answers with a Location pointing off-box would hand the
// OAuth client secret to whatever named it. Every hop is held to the same rule.
func TestAuthenticateRefusesToFollowARedirectOffBox(t *testing.T) {
	for _, target := range []string{
		"https://attacker.example/oauth/token",
		"http://attacker.example/oauth/token",
		"https://api.tailscale.com.attacker.example/oauth/token",
	} {
		for _, code := range []int{
			http.StatusMovedPermanently,
			http.StatusFound,
			http.StatusSeeOther,
			http.StatusTemporaryRedirect,
			http.StatusPermanentRedirect,
		} {
			t.Run(fmt.Sprintf("%s/%d", target, code), func(t *testing.T) {
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target, code)
				}))
				defer origin.Close()

				c := NewClient(origin.URL, "-", nil)
				err := c.Authenticate(context.Background(), "tskey-client-id", "tskey-client-secret")
				if err == nil {
					t.Fatal("authenticate followed the redirect and reported success")
				}
				// The refusal message, not a dial or DNS error, is what proves the hop
				// was stopped before a connection to attacker.example was ever opened.
				if !strings.Contains(err.Error(), "refusing to send the admin OAuth secret") &&
					!strings.Contains(err.Error(), "cleartext") {
					t.Fatalf("redirect was stopped by something other than the URL guard: %v", err)
				}
			})
		}
	}
}

// The loopback carve-out has to survive redirects too, or a control plane behind a
// local reverse proxy stops working. Nothing leaves the machine on this path.
func TestAuthenticateStillFollowsALoopbackRedirect(t *testing.T) {
	control := newFakeControl(`{}`)
	real := httptest.NewServer(http.HandlerFunc(control.serve))
	defer real.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, real.URL+"/api/v2/oauth/token", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c := NewClient(origin.URL, "-", nil)
	if err := c.Authenticate(context.Background(), control.clientID, control.clientSecret); err != nil {
		t.Fatalf("loopback redirect was refused: %v", err)
	}
}

// ValidateBaseURL is the one place that decides where an admin OAuth secret with
// policy_file scope over the whole tailnet may be sent. Its host rules only mean
// anything if a URL that names no usable host, or no host at all, is refused before
// they are consulted -- otherwise "" or a bare path would sail past the loopback and
// tailscale.com checks on an empty string.
func TestValidateBaseURLRefusesAURLThatNamesNoUsableEndpoint(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"no scheme", "api.tailscale.com", "must use http or https"},
		{"a scheme that is not http", "ftp://api.tailscale.com", "must use http or https"},
		{"a file url", "file:///etc/passwd", "must use http or https"},
		{"a scheme that could exfiltrate elsewhere", "gopher://attacker.example", "must use http or https"},
		{"https with no host", "https://", "names no host"},
		{"https with only a path", "https:///api/v2", "names no host"},
		{"empty", "", "must use http or https"},
		// A URL url.Parse itself rejects never reaches the scheme and host rules, so
		// without its own refusal the zero-value URL those rules would then inspect
		// reads as "no scheme" rather than as the malformed input it is.
		{"an unclosed IPv6 host", "https://[::1", "parse policy api url"},
		{"a control character in the host", "https://exa\x7fmple.com", "parse policy api url"},
		{"an invalid percent escape", "%%", "parse policy api url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Checked with the override on as well: --allow-foreign-api-url relaxes the
			// host rule, and nothing else. A malformed URL stays malformed.
			for _, allowForeign := range []bool{false, true} {
				err := ValidateBaseURL(tt.url, allowForeign)
				if err == nil {
					t.Fatalf("ValidateBaseURL(%q, allowForeign=%v) = nil, want a refusal", tt.url, allowForeign)
				}
				if !strings.Contains(err.Error(), tt.want) {
					t.Errorf("ValidateBaseURL(%q, allowForeign=%v) = %q, want it to mention %q",
						tt.url, allowForeign, err, tt.want)
				}
			}
		})
	}
}
