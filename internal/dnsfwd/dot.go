// SPDX-License-Identifier: MIT

package dnsfwd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/sellitus/app-tail/internal/dnsprofiles"
)

// dotUpstream carries DNS over TLS (RFC 7858).
//
// The connection is long-lived and pipelined, which is what makes DoT usable: a handshake
// per query would add two round trips to every name on a page.
type dotUpstream struct {
	label  string
	stream *streamClient
}

func newDoTUpstream(u dnsprofiles.Upstream, tlsConfig *tls.Config) (*dotUpstream, error) {
	addr, ok := u.Endpoint()
	if !ok {
		return nil, fmt.Errorf("%s has not been resolved to an address", u.Text)
	}
	cfg := tlsConfig.Clone()
	// The name the user wrote is what the certificate has to match. When they wrote an
	// address instead, that address is the name, and the certificate has to carry it as
	// an IP entry -- which the providers who publish an address for DoT do.
	cfg.ServerName = u.ServerName
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}

	d := &dotUpstream{label: u.Text}
	d.stream = newStreamClient(u.Text, func(ctx context.Context) (net.Conn, error) {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: cfg}
		// A literal address, so nothing here asks a resolver where the resolver is.
		return dialer.DialContext(ctx, "tcp", addr.String())
	}, idleTimeout)
	return d, nil
}

func (d *dotUpstream) Label() string { return d.label }

func (d *dotUpstream) Close() error { return d.stream.Close() }

// Exchange ignores the stream hint: TLS is already a stream, so a truncated answer is not
// a thing this upstream produces and there is nothing to retry differently.
func (d *dotUpstream) Exchange(ctx context.Context, query []byte, _ bool) ([]byte, error) {
	return d.stream.Exchange(ctx, query)
}
