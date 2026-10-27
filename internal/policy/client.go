// SPDX-License-Identifier: MIT

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the Tailscale control API. Tests point this at an httptest
// server instead.
const DefaultBaseURL = "https://api.tailscale.com"

// DefaultTailnet asks the API for the tailnet the credential itself belongs to.
const DefaultTailnet = "-"

const requestTimeout = 30 * time.Second

// Client talks to the Tailscale policy API using an OAuth client credential that
// carries the policy_file scope. That credential is far stronger than the per-node
// auth_keys one and must never ship with the fleet.
type Client struct {
	BaseURL string
	Tailnet string
	HTTP    *http.Client
	// AllowForeignHost is the operator's explicit acknowledgement that BaseURL points
	// at a control plane they run themselves. It never permits cleartext.
	AllowForeignHost bool

	token string
}

// NewClient builds a client. An empty baseURL or tailnet falls back to the defaults.
func NewClient(baseURL, tailnet string, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if tailnet == "" {
		tailnet = DefaultTailnet
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	c := &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Tailnet: tailnet,
		HTTP:    httpClient,
	}
	// Vetting only the base URL leaves one way out: Go replays the request body on a
	// 307 or 308, so a redirect to an attacker-named host resends the OAuth client
	// secret verbatim. Every hop is held to the same rule the base URL passed, which
	// is why this reads AllowForeignHost through c -- callers set it after
	// construction. The policy is installed on a caller-supplied client too: this
	// client carries a credential whose handling it cannot delegate.
	c.HTTP.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return ValidateBaseURL(req.URL.String(), c.AllowForeignHost)
	}
	return c
}

// ValidateBaseURL reports whether a base URL may be handed the admin OAuth
// credential. That credential carries policy_file scope over the entire tailnet, so
// an unchecked base URL is credential exfiltration in one flag.
//
// allowForeign is the operator's explicit acknowledgement that they run their own
// control plane. It relaxes the host rule and nothing else: cleartext off-loopback
// stays refused, because there is no acknowledgement that makes a secret on the wire
// safe.
func ValidateBaseURL(baseURL string, allowForeign bool) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse policy api url %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("policy api url %q must use http or https", baseURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("policy api url %q names no host", baseURL)
	}

	// A loopback endpoint cannot exfiltrate anything -- the secret never leaves the
	// machine -- which is also what lets tests point this at an httptest server.
	if isLoopbackHost(host) {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf(
			"policy api url %q would send the admin OAuth secret in cleartext; use https", baseURL)
	}
	if isTailscaleHost(host) || allowForeign {
		return nil
	}
	return fmt.Errorf(
		"refusing to send the admin OAuth secret to %q, which is not a tailscale.com host; "+
			"pass --allow-foreign-api-url if you run your own control plane", host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isTailscaleHost compares whole labels, so a lookalike that merely contains the
// name ("tailscale.com.attacker.example", "nottailscale.com") does not pass.
func isTailscaleHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "tailscale.com" || strings.HasSuffix(h, ".tailscale.com")
}

// Authenticate exchanges the OAuth client credential for an access token.
func (c *Client) Authenticate(ctx context.Context, clientID, clientSecret string) error {
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("oauth client id is required")
	}
	if strings.TrimSpace(clientSecret) == "" {
		return fmt.Errorf("oauth client secret is required")
	}
	// Checked here, at the one point the secret leaves the process, so no caller can
	// route around it by building a Client directly.
	if err := ValidateBaseURL(c.BaseURL, c.AllowForeignHost); err != nil {
		return err
	}

	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("request oauth token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read oauth token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth token request failed (%s): %s",
			resp.Status, summarize(body))
	}

	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return fmt.Errorf("parse oauth token response: %w", err)
	}
	if token.AccessToken == "" {
		return fmt.Errorf("oauth token response contained no access token")
	}
	c.token = token.AccessToken
	return nil
}

// Document is a policy file plus the ETag needed to write it back safely.
type Document struct {
	Raw  []byte
	ETag string
}

// maxResponseBytes caps how much of an API response is read. Policy files are
// human-authored documents, so anything past this is a malfunction.
const maxResponseBytes = 8 << 20

// Fetch reads the current policy file, keeping its HuJSON comments intact.
func (c *Client) Fetch(ctx context.Context) (Document, error) {
	req, err := c.newRequest(ctx, http.MethodGet, c.aclPath(), nil)
	if err != nil {
		return Document{}, err
	}
	req.Header.Set("Accept", "application/hujson")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Document{}, fmt.Errorf("fetch tailnet policy: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Document{}, fmt.Errorf("read tailnet policy: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Document{}, fmt.Errorf("fetch tailnet policy failed (%s): %s",
			resp.Status, summarize(body))
	}

	etag := resp.Header.Get("ETag")
	if etag == "" {
		// Without an ETag there is no optimistic concurrency, and a blind write
		// could clobber a change made between the read and the write.
		return Document{}, fmt.Errorf(
			"tailnet policy response carried no ETag; refusing to write without optimistic concurrency")
	}
	return Document{Raw: body, ETag: etag}, nil
}

// Save writes the policy back, refusing the write if the policy changed since it
// was fetched.
func (c *Client) Save(ctx context.Context, doc Document, updated []byte) error {
	if doc.ETag == "" {
		return fmt.Errorf("cannot save the tailnet policy without the ETag it was fetched with")
	}
	req, err := c.newRequest(ctx, http.MethodPost, c.aclPath(), strings.NewReader(string(updated)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/hujson")
	req.Header.Set("If-Match", doc.ETag)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("save tailnet policy: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read tailnet policy save response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return nil
	case http.StatusPreconditionFailed:
		return fmt.Errorf(
			"the tailnet policy changed while this bootstrap was running; nothing was written, re-run to retry")
	default:
		return fmt.Errorf("save tailnet policy failed (%s): %s", resp.Status, summarize(body))
	}
}

func (c *Client) aclPath() string {
	return fmt.Sprintf("/api/v2/tailnet/%s/acl", url.PathEscape(c.Tailnet))
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	if c.token == "" {
		return nil, fmt.Errorf("policy client is not authenticated; call Authenticate first")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("build %s %s request: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return req, nil
}

// Result describes what Bootstrap did, for the CLI to report.
type Result struct {
	Plan    Plan
	Changed bool
	// Updated is the document that was written, empty when nothing changed.
	Updated []byte
}

// Bootstrap fetches the policy, plans the additions, and writes them back under
// optimistic concurrency. It is idempotent: a second run finds nothing to do.
func Bootstrap(ctx context.Context, c *Client, opts Options) (Result, error) {
	doc, err := c.Fetch(ctx)
	if err != nil {
		return Result{}, err
	}
	plan, err := PlanBootstrap(doc.Raw, opts)
	if err != nil {
		return Result{}, err
	}
	if plan.Empty() {
		return Result{Plan: plan}, nil
	}
	updated, err := Apply(doc.Raw, plan)
	if err != nil {
		return Result{}, err
	}
	if err := c.Save(ctx, doc, updated); err != nil {
		return Result{}, err
	}
	return Result{Plan: plan, Changed: true, Updated: updated}, nil
}

// BootstrapAll fetches the policy once, plans every option set against it, and,
// unless dryRun, writes the combined result back under the ETag it was fetched
// with. It is idempotent: when the policy already satisfies every option it writes
// nothing and reports Changed false. With dryRun, Changed reports whether an apply
// would change anything, and nothing is written.
func BootstrapAll(ctx context.Context, c *Client, opts []Options, dryRun bool) (Result, error) {
	doc, err := c.Fetch(ctx)
	if err != nil {
		return Result{}, err
	}
	updated, plans, err := PlanAll(doc.Raw, opts)
	if err != nil {
		return Result{}, err
	}
	summary := CombinePlans(plans)

	changed := false
	for _, p := range plans {
		if !p.Empty() {
			changed = true
			break
		}
	}
	if !changed || dryRun {
		return Result{Plan: summary, Changed: changed}, nil
	}
	if err := c.Save(ctx, doc, updated); err != nil {
		return Result{}, err
	}
	return Result{Plan: summary, Changed: true, Updated: updated}, nil
}

// summarize trims an error body to something readable in a terminal.
func summarize(body []byte) string {
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "(empty response body)"
	}
	const limit = 500
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}
