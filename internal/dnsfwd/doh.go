// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sellitus/app-tail/internal/dnsprofiles"
)

// dohMediaType is the wire format RFC 8484 defines: a DNS message, unchanged, as the body.
const dohMediaType = "application/dns-message"

// dohUpstream carries DNS over HTTPS (RFC 8484).
//
// This is the protocol most filtering resolvers hand out, because it is the one that
// survives networks that block everything but HTTPS.
type dohUpstream struct {
	label  string
	url    string
	client *http.Client
}

func newDoHUpstream(u dnsprofiles.Upstream, tlsConfig *tls.Config) (*dohUpstream, error) {
	addr, ok := u.Endpoint()
	if !ok {
		return nil, fmt.Errorf("%s has not been resolved to an address", u.Text)
	}
	cfg := tlsConfig.Clone()
	cfg.ServerName = u.ServerName
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}

	transport := &http.Transport{
		TLSClientConfig: cfg,
		// Every connection goes to the address the profile was resolved to, and the
		// address http asks for is discarded. Without this the transport would look the
		// hostname up through the system resolver -- which is this process, waiting on
		// this request. That is not a slow path, it is a deadlock.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			d.Timeout = dialTimeout
			return d.DialContext(ctx, network, addr.String())
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     idleTimeout,
		TLSHandshakeTimeout: dialTimeout,
	}
	return &dohUpstream{
		label:  u.Text,
		url:    u.URL,
		client: &http.Client{Transport: transport, Timeout: queryTimeout},
	}, nil
}

func (d *dohUpstream) Label() string { return d.label }

func (d *dohUpstream) Close() error {
	d.client.CloseIdleConnections()
	return nil
}

// Exchange posts the query and returns the body. The stream hint means nothing here: an
// HTTPS response is not length-limited, so there is no truncated form to retry.
func (d *dohUpstream) Exchange(ctx context.Context, query []byte, _ bool) ([]byte, error) {
	body := make([]byte, len(query))
	copy(body, query)
	clientID, _ := queryID(body)
	// RFC 8484 §4.1: the id is zero on the wire, so two clients asking the same question
	// produce byte-identical requests and any cache in between can serve both.
	setID(body, 0)

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build a request to %s: %w", d.label, err)
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ask %s: %w", d.label, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %s", d.label, resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !isDoHMedia(ct) {
		return nil, fmt.Errorf("%s answered %s, which is not a DNS message", d.label, ct)
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxStreamAnswer))
	if err != nil {
		return nil, fmt.Errorf("read the answer from %s: %w", d.label, err)
	}
	if len(answer) < 12 {
		return nil, fmt.Errorf("%s answered %d bytes, which is not a DNS message", d.label, len(answer))
	}
	setID(answer, clientID)
	return answer, nil
}

// isDoHMedia compares a Content-Type against the DNS media type, ignoring parameters and
// case, which is how a header value is allowed to vary.
func isDoHMedia(value string) bool {
	base, _, _ := strings.Cut(value, ";")
	return strings.ToLower(strings.TrimSpace(base)) == dohMediaType
}
