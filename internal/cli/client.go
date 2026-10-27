// SPDX-License-Identifier: MIT

// Package cli implements the app-tail command-line surface.
//
// Everything except the agent itself is a thin client over the same loopback API
// the dashboard uses, so a scripted `app-tail add` and a click in the browser go
// through exactly one implementation.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sellitus/app-tail/internal/apiauth"
	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/httpapi"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// requestTimeout bounds a single API call. The agent is on loopback, so anything
// slower than this is a wedged agent rather than a slow network.
const requestTimeout = 15 * time.Second

// maxResponseBytes caps what a reply may be. The agent is trusted, but an
// unbounded read would turn a runaway response into an out-of-memory kill.
const maxResponseBytes = 8 << 20

// Client talks to a running agent's management API.
type Client struct {
	baseURL string
	token   string
	http    *http.Client

	// proven records that the listener at baseURL answered the challenge for token, which
	// it must before the token is sent there.
	mu     sync.Mutex
	proven bool
}

// NewClient builds a client for an agent listening at baseURL that holds no API token. It
// reaches only what the agent answers without one -- the readiness probe -- and refuses
// every other call before sending it.
func NewClient(baseURL string) *Client {
	return NewAuthenticatedClient(baseURL, "")
}

// NewAuthenticatedClient builds a client that presents token, once the listener at baseURL
// has proven it holds the same token.
func NewAuthenticatedClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: requestTimeout},
	}
}

// BaseURL is where this client sends its requests.
func (c *Client) BaseURL() string { return c.baseURL }

// ErrNoAgent reports that no running agent could be located.
var ErrNoAgent = errors.New("no running app-tail agent was found")

// Discover finds the running agent from the address it recorded at startup, falling back
// to the configured one, and reads the API token the agent wrote beside it.
//
// The agent writes where it bound into a record beside the config precisely so the CLI and
// tray do not have to guess a port, which matters because the default is an OS-assigned one.
// That record is preferred because it is the only thing that names the port an agent that
// could not have the configured one is actually on.
func Discover(store *config.Store) (*Client, error) {
	addr := config.ReadDashboardAddr(store.Path())
	if addr == "" {
		addr = strings.TrimSpace(store.Settings().UIListen)
	}
	if addr == "" {
		return nil, fmt.Errorf("%w: %s records no dashboard address; start the agent first", ErrNoAgent, store.Path())
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// config.Open validates uiListenAddr on load and refuses every malformed form,
		// so nothing reaches here today; it stays as the guard for the day that
		// validation is relaxed. Both errors are wrapped: callers branch on
		// ErrNoAgent, and the split error names which half of host:port was bad.
		return nil, fmt.Errorf("%w: %s records an unusable dashboard address %q: %w", ErrNoAgent, store.Path(), addr, err)
	}
	if port == "0" {
		return nil, fmt.Errorf("%w: %s records no bound port yet; start the agent first", ErrNoAgent, store.Path())
	}
	token, err := apiauth.Read(filepath.Dir(store.Path()))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no API token beside %s; start the agent first", ErrNoAgent, store.Path())
	}
	if err != nil {
		return nil, fmt.Errorf("read the API token: %w", err)
	}
	// The host needs no rewriting: config validation refuses any uiListenAddr that
	// is not a loopback IP, so a wildcard bind can never be stored.
	return NewAuthenticatedClient("http://"+net.JoinHostPort(host, port), token), nil
}

// prove challenges the listener to show it holds the token before the token is sent to
// it. The dashboard-address record outlives a crashed agent, and whatever binds the port
// next would otherwise receive the token and every request carrying it.
//
// The proof is checked against the address the connection actually reached, which the
// agent signs from its own side of the same socket, so a squatter relaying the challenge
// to the real agent on another port gets back an answer naming that other port.
func (c *Client) prove(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proven {
		return nil
	}

	nonce, err := apiauth.NewNonce()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(map[string]string{"nonce": nonce})
	if err != nil {
		return fmt.Errorf("encode the identity check: %w", err)
	}
	var reached string
	traced := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reached = info.Conn.RemoteAddr().String() },
	})
	req, err := http.NewRequestWithContext(traced, http.MethodPost, c.baseURL+"/api/auth/hello", bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("build the identity check: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w at %s: %w", ErrNoAgent, c.baseURL, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read the agent's identity check: %w", err)
	}

	var answer struct {
		Proof string `json:"proof"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(payload, &answer) != nil ||
		!apiauth.VerifyProof(c.token, nonce, reached, answer.Proof) {
		return fmt.Errorf("something other than your app-tail agent is listening on %s; "+
			"refusing to send it your credentials", strings.TrimPrefix(c.baseURL, "http://"))
	}
	c.proven = true
	return nil
}

// APIError is a non-2xx reply, carrying the agent's own explanation.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the agent returned HTTP %d", e.Status)
	}
	return e.Message
}

// do performs one authenticated request and decodes the reply into out, which may be nil.
// The first call proves the listener before the token is sent anywhere.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if c.token == "" {
		return fmt.Errorf("no API token for the agent at %s; run this from the account the agent runs as", c.baseURL)
	}
	if err := c.prove(ctx); err != nil {
		return err
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode the request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w at %s: %w", ErrNoAgent, c.baseURL, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read the agent's reply: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Message: errorMessage(resp.StatusCode, payload)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode the agent's reply: %w", err)
	}
	return nil
}

// errorMessage pulls the agent's explanation out of an error body, falling back to
// the raw payload so a proxy's HTML error is still visible rather than swallowed.
func errorMessage(status int, payload []byte) string {
	var envelope struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err == nil && envelope.Error != "" {
		return envelope.Error
	}
	text := strings.TrimSpace(string(payload))
	if text == "" {
		return fmt.Sprintf("the agent returned HTTP %d with no explanation", status)
	}
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return fmt.Sprintf("the agent returned HTTP %d: %s", status, text)
}

// Status returns the node's current state.
func (c *Client) Status(ctx context.Context) (httpapi.StatusView, error) {
	var out httpapi.StatusView
	err := c.do(ctx, http.MethodGet, "/api/status", nil, &out)
	return out, err
}

// LoginResult is what the agent reports after an interactive login is started.
type LoginResult struct {
	AuthURL      string `json:"authURL"`
	BackendState string `json:"backendState"`
}

// Login starts an interactive login and returns the URL to visit, if one is needed.
func (c *Client) Login(ctx context.Context) (LoginResult, error) {
	var out LoginResult
	err := c.do(ctx, http.MethodPost, "/api/login", nil, &out)
	return out, err
}

// LoginURL asks for the login already in progress, without starting another. The status
// reports only that one is pending: the URL that completes an enrolment is handed over by a
// request the agent's same-origin guard covers, and a read is not one.
func (c *Client) LoginURL(ctx context.Context) (LoginResult, error) {
	var out LoginResult
	err := c.do(ctx, http.MethodPost, "/api/login/url", nil, &out)
	return out, err
}

// DashboardLink asks the agent for a one-time link that opens the dashboard signed in.
// anyAccount is for a link shown to a person rather than handed to a program on its command
// line, which every account on the machine can read; only that kind may be opened from
// another account.
func (c *Client) DashboardLink(ctx context.Context, anyAccount bool) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	body := struct {
		AnyAccount bool `json:"anyAccount"`
	}{anyAccount}
	if err := c.do(ctx, http.MethodPost, "/api/auth/launch", body, &out); err != nil {
		return "", err
	}
	return out.URL, nil
}

// RotateToken has the agent write a new API token, ending every dashboard session.
func (c *Client) RotateToken(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/auth/rotate", nil, nil)
}

// Logout disconnects the node from the tailnet.
func (c *Client) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/logout", nil, nil)
}

// Restart rebuilds the tailnet node in place so node-identity settings take effect,
// without restarting the agent process. The dashboard address is unaffected.
func (c *Client) Restart(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/restart", nil, nil)
}

// Forwards lists every configured forward with its live status.
func (c *Client) Forwards(ctx context.Context) ([]httpapi.ForwardView, error) {
	var out struct {
		Forwards []httpapi.ForwardView `json:"forwards"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/forwards", nil, &out); err != nil {
		return nil, err
	}
	return out.Forwards, nil
}

// CreateForward adds a forward.
func (c *Client) CreateForward(ctx context.Context, spec httpapi.ForwardSpec) (httpapi.ForwardView, error) {
	var out httpapi.ForwardView
	err := c.do(ctx, http.MethodPost, "/api/forwards", spec, &out)
	return out, err
}

// DeleteForward removes a forward by id.
func (c *Client) DeleteForward(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/forwards/"+url.PathEscape(id), nil, nil)
}

// SuggestPort asks the agent for a free local port, preferring the target's own.
func (c *Client) SuggestPort(ctx context.Context, protocol config.Protocol, target string) (int, error) {
	query := url.Values{}
	query.Set("protocol", string(protocol))
	if target != "" {
		query.Set("target", target)
	}
	var out struct {
		Port int `json:"port"`
	}
	err := c.do(ctx, http.MethodGet, "/api/forwards/suggest-port?"+query.Encode(), nil, &out)
	return out.Port, err
}

// GetForward returns one forward with its live status.
func (c *Client) GetForward(ctx context.Context, id string) (httpapi.ForwardView, error) {
	var out httpapi.ForwardView
	err := c.do(ctx, http.MethodGet, "/api/forwards/"+url.PathEscape(id), nil, &out)
	return out, err
}

// UpdateForward changes the fields the spec carries, leaving absent ones untouched.
func (c *Client) UpdateForward(ctx context.Context, id string, spec httpapi.ForwardSpec) (httpapi.ForwardView, error) {
	var out httpapi.ForwardView
	err := c.do(ctx, http.MethodPut, "/api/forwards/"+url.PathEscape(id), spec, &out)
	return out, err
}

// ToggleForward enables or disables a forward.
func (c *Client) ToggleForward(ctx context.Context, id string, enabled bool) (httpapi.ForwardView, error) {
	var out httpapi.ForwardView
	err := c.do(ctx, http.MethodPost, "/api/forwards/"+url.PathEscape(id)+"/toggle",
		map[string]bool{"enabled": enabled}, &out)
	return out, err
}

// Peers lists the tailnet devices this node can see.
func (c *Client) Peers(ctx context.Context) ([]tsnode.Peer, error) {
	var out struct {
		Peers []tsnode.Peer `json:"peers"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/peers", nil, &out); err != nil {
		return nil, err
	}
	return out.Peers, nil
}

// Presets lists the built-in and user-defined service templates.
func (c *Client) Presets(ctx context.Context) ([]config.Preset, error) {
	var out struct {
		Presets []config.Preset `json:"presets"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/presets", nil, &out); err != nil {
		return nil, err
	}
	return out.Presets, nil
}

// CreatePreset adds a user-defined preset.
func (c *Client) CreatePreset(ctx context.Context, preset config.Preset) (config.Preset, error) {
	var out config.Preset
	err := c.do(ctx, http.MethodPost, "/api/presets", preset, &out)
	return out, err
}

// DeletePreset removes a user-defined preset by id. Built-ins are refused by the agent.
func (c *Client) DeletePreset(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/presets/"+url.PathEscape(id), nil, nil)
}

// Settings returns the agent's current settings view, with secrets reduced to
// presence booleans.
func (c *Client) Settings(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodGet, "/api/settings", nil, &out)
	return out, err
}

// SettingsResult is the outcome of a settings write: the refreshed view, what a
// restart is still needed for, and what was stored without taking effect.
type SettingsResult struct {
	View        map[string]any
	NodeRestart bool
	UIRelisten  bool
	// AppRestart marks a setting the process reads once at start. It is stored and correct
	// now, and nothing acts on it until the next start, which is the one thing a bare
	// "Saved." would misreport.
	AppRestart bool
	// AdminRestart marks a change needing administrator rights this process does not hold.
	// They are taken when app-tail starts, so the change is stored and inert until it is
	// started again -- which a bare "Saved." would misreport just as badly.
	AdminRestart bool
	// AdminRelaunch marks that the agent is restarting itself to take those rights, which is
	// how Windows is made to ask for them. Everything else outstanding is applied by that
	// start, so nothing more is offered.
	AdminRelaunch   bool
	RestartRequired bool
	// Deferred are the settings the tailnet node holds that could not be handed to it,
	// because it is not running. Reporting a bare "Saved." for one of these would be
	// reporting a change nothing has applied.
	Deferred []DeferredSetting
}

// DeferredSetting is one stored-but-not-in-force setting and why.
type DeferredSetting struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
}

// UpdateSettings applies a patch and reports the refreshed view and restart needs. The
// patch is the wire form: a present key changes that field.
func (c *Client) UpdateSettings(ctx context.Context, patch map[string]json.RawMessage) (SettingsResult, error) {
	var merged map[string]any
	if err := c.do(ctx, http.MethodPut, "/api/settings", patch, &merged); err != nil {
		return SettingsResult{}, err
	}
	deferred, err := deferredFrom(merged)
	if err != nil {
		return SettingsResult{}, err
	}
	return SettingsResult{
		View:            merged,
		NodeRestart:     boolFrom(merged, "nodeRestart"),
		UIRelisten:      boolFrom(merged, "uiRelisten"),
		AppRestart:      boolFrom(merged, "appRestart"),
		AdminRestart:    boolFrom(merged, "adminRestart"),
		AdminRelaunch:   boolFrom(merged, "adminRelaunch"),
		RestartRequired: boolFrom(merged, "restartRequired"),
		Deferred:        deferred,
	}, nil
}

// deferredFrom reads the deferred-settings list out of the merged response. The write
// itself succeeded, so a list this client cannot read is reported rather than dropped:
// silently losing it would turn "stored but not in force" into "saved".
func deferredFrom(m map[string]any) ([]DeferredSetting, error) {
	raw, ok := m["deferred"]
	if !ok {
		return nil, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-encode the deferred settings the agent reported: %w", err)
	}
	var out []DeferredSetting
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("read the deferred settings the agent reported: %w", err)
	}
	return out, nil
}

// boolFrom reads a boolean field from a decoded JSON object, defaulting to false when
// the key is absent or not a bool.
func boolFrom(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

// HealthView is what /healthz reports. It is the agent's own readiness verdict:
// the node is Running and every enabled forward is listening.
type HealthView struct {
	Status       string `json:"status"`
	BackendState string `json:"backendState,omitempty"`
	Reason       string `json:"reason,omitempty"`
	// Healthy mirrors the HTTP status, because the body alone cannot distinguish a
	// 503 health report from a 200 one once it is decoded.
	Healthy bool `json:"-"`
}

// Health asks the agent whether it is ready to carry traffic.
//
// Unlike every other call, a 503 is a successful answer rather than an error: it is
// the agent reporting that it is not ready, and its reason is the whole point of
// asking. Anything else -- an unreachable agent, an unexpected status -- is still an
// error, so a wedged agent never reads as a confident "unhealthy".
func (c *Client) Health(ctx context.Context) (HealthView, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return HealthView{}, fmt.Errorf("build the request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return HealthView{}, fmt.Errorf("%w at %s: %w", ErrNoAgent, c.baseURL, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return HealthView{}, fmt.Errorf("read the agent's reply: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return HealthView{}, &APIError{Status: resp.StatusCode, Message: errorMessage(resp.StatusCode, payload)}
	}

	var out HealthView
	if err := json.Unmarshal(payload, &out); err != nil {
		return HealthView{}, fmt.Errorf("decode the agent's reply: %w", err)
	}
	out.Healthy = resp.StatusCode == http.StatusOK
	return out, nil
}
