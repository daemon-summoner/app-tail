// SPDX-License-Identifier: MIT

package tsnode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2/clientcredentials"
)

// An OAuth client secret is not a credential a node can enrol with. It is exchanged, once
// per start, for a single-use auth key scoped to the tags this node advertises.
//
// tsnet does this itself, through a hook registered from tailscale.com/internal/..., which
// a build outside that module cannot reach or call. The interface mode does not go through
// tsnet at all, so it would have no credential path without this. Doing it here for both
// modes means one implementation, exercised on every start rather than only in the mode
// fewer people run, and testable against a real HTTP server for the first time.

// oauthSecretPrefix is what a Tailscale OAuth client secret starts with. Anything else is
// already an auth key and is passed through untouched.
const oauthSecretPrefix = "tskey-client-"

// defaultAPIBase is the control plane's API, overridable per secret for a self-hosted
// coordination server.
const defaultAPIBase = "https://api.tailscale.com"

// ResolveCredential exchanges an OAuth client secret for an auth key, returning parameters
// the node can enrol with.
//
// Parameters carrying anything else come back unchanged, so every caller can call this
// unconditionally rather than deciding first whether it applies.
func ResolveCredential(ctx context.Context, p ServerParams) (ServerParams, error) {
	// The auth key field is checked too, because pasting an OAuth secret into it is a
	// thing people do and the control plane's rejection of it says nothing useful.
	secret := p.ClientSecret
	if secret == "" {
		secret = p.AuthKey
	}
	if !strings.HasPrefix(secret, oauthSecretPrefix) {
		return p, nil
	}
	if len(p.AdvertiseTags) == 0 {
		return ServerParams{}, fmt.Errorf("an OAuth client secret can only create a tagged node, so at least one tag is required")
	}

	req, err := parseOAuthSecret(secret)
	if err != nil {
		return ServerParams{}, err
	}
	req.tags = p.AdvertiseTags
	key, err := mintAuthKey(ctx, req)
	if err != nil {
		return ServerParams{}, err
	}
	p.AuthKey = key
	// Cleared so nothing downstream tries the exchange a second time with a secret that
	// has already been spent.
	p.ClientSecret = ""
	return p, nil
}

// keyRequest is one exchange: the secret to authenticate with, the properties of the key
// to ask for, and where to ask.
type keyRequest struct {
	secret        string
	baseURL       string
	ephemeral     bool
	preauthorized bool
	tags          []string
}

// parseOAuthSecret reads the properties a secret may carry after a question mark:
//
//	tskey-client-xxxx[?ephemeral=BOOL&preauthorized=BOOL&baseURL=URL]
//
// The defaults match the ones the tailscale client uses, because a secret written for one
// must mean the same thing to the other.
func parseOAuthSecret(raw string) (keyRequest, error) {
	secret, query, _ := strings.Cut(raw, "?")
	attrs, err := url.ParseQuery(query)
	if err != nil {
		return keyRequest{}, fmt.Errorf("read the options on the OAuth client secret: %w", err)
	}
	req := keyRequest{secret: secret, baseURL: defaultAPIBase, ephemeral: true}
	for name := range attrs {
		switch name {
		case "ephemeral", "preauthorized", "baseURL":
		default:
			return keyRequest{}, fmt.Errorf("the OAuth client secret carries an option this app does not know: %q", name)
		}
	}
	if req.ephemeral, err = boolAttr(attrs, "ephemeral", true); err != nil {
		return keyRequest{}, err
	}
	if req.preauthorized, err = boolAttr(attrs, "preauthorized", false); err != nil {
		return keyRequest{}, err
	}
	if v := attrs.Get("baseURL"); v != "" {
		req.baseURL = strings.TrimSuffix(v, "/")
	}
	return req, nil
}

func boolAttr(attrs url.Values, name string, def bool) (bool, error) {
	v := attrs.Get(name)
	if v == "" {
		return def, nil
	}
	got, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("the %s option on the OAuth client secret is %q, which is not true or false", name, v)
	}
	return got, nil
}

// The body the control plane's key endpoint expects. The nesting is the API's, not this
// app's, so it is spelled out rather than flattened: a name that does not match theirs is
// silently ignored by the server and produces a key with the wrong properties.
type keyCreateRequest struct {
	Capabilities keyCapabilities `json:"capabilities"`
}

type keyCapabilities struct {
	Devices keyDeviceCapabilities `json:"devices"`
}

type keyDeviceCapabilities struct {
	Create keyCreateCapabilities `json:"create"`
}

type keyCreateCapabilities struct {
	// Reusable is deliberately always false and always sent: one key is minted per node
	// start, so a reusable one is a credential with a longer life than its purpose.
	Reusable      bool     `json:"reusable"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
	Tags          []string `json:"tags,omitempty"`
}

// mintAuthKey performs the exchange: an OAuth token, then one key scoped to these tags.
func mintAuthKey(ctx context.Context, req keyRequest) (string, error) {
	cfg := clientcredentials.Config{
		// The client id is carried inside the secret, so the control plane ignores this
		// field. It is not empty because an empty one is rejected before the request is
		// ever sent, which would report a local encoding problem for a remote refusal.
		ClientID:     "app-tail",
		ClientSecret: req.secret,
		TokenURL:     req.baseURL + "/api/v2/oauth/token",
	}

	body, err := json.Marshal(keyCreateRequest{
		Capabilities: keyCapabilities{
			Devices: keyDeviceCapabilities{
				Create: keyCreateCapabilities{
					Ephemeral:     req.ephemeral,
					Preauthorized: req.preauthorized,
					Tags:          req.tags,
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("build the request for an auth key: %w", err)
	}

	// "-" is the control plane's name for "the tailnet this credential belongs to",
	// which is the only one an OAuth client secret can create a key in.
	endpoint := req.baseURL + "/api/v2/tailnet/-/keys"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build the request for an auth key: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := cfg.Client(ctx).Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("exchange the OAuth client secret for an auth key: %w", err)
	}
	defer resp.Body.Close()

	// Bounded because the answer is a small JSON object and the reader is a network peer.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read the control plane's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the control plane refused to create an auth key (%s): %s",
			resp.Status, strings.TrimSpace(string(raw)))
	}

	var answer struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return "", fmt.Errorf("read the control plane's answer: %w", err)
	}
	if answer.Key == "" {
		return "", fmt.Errorf("the control plane created an auth key and did not return it")
	}
	return answer.Key, nil
}
