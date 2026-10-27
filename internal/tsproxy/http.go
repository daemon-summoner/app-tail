// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/sellitus/app-tail/internal/inspect"
	"github.com/sellitus/app-tail/internal/netpipe"
	"github.com/sellitus/app-tail/internal/tlsmint"
)

// ConnectErrorHeader carries the proxy's own reason for a refusal, so a client that
// only reports the status code still leaves the reason somewhere a user can find it.
const ConnectErrorHeader = "Tailscale-Connect-Error"

// hopByHop are the headers that describe the connection to this proxy rather than the
// request being carried, and which RFC 9110 requires an intermediary to drop. Passing
// one through makes the next hop honour a keep-alive or an upgrade this proxy is the
// endpoint of.
var hopByHop = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// httpHandler builds the handler for the HTTP half of the split listener. The
// credential is bound here rather than read live because it belongs to the listener
// that was bound with it, exactly as the SOCKS5 server's does.
func (p *Instance) httpHandler(spec listenerSpec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(spec, r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="app-tail"`)
			http.Error(w, "the app-tail proxy requires a password", http.StatusProxyAuthRequired)
			return
		}
		if r.Method == http.MethodConnect {
			p.serveConnect(w, r)
			return
		}
		p.serveForward(w, r)
	})
}

// authorized checks the proxy credential. A spec with no password accepts everything,
// which is the documented default: a proxy auto-config file has no slot for a
// credential, so requiring one makes the browser case impossible.
func authorized(spec listenerSpec, r *http.Request) bool {
	if !spec.authenticates() {
		return true
	}
	user, pass, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	// Constant time, because the password is a secret and a proxy is reachable by
	// every process on this machine -- including one timing it.
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(spec.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(spec.password)) == 1
	return userOK && passOK
}

func parseProxyAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	return user, pass, found
}

// serveConnect tunnels bytes to the requested destination once the scope allows it.
func (p *Instance) serveConnect(w http.ResponseWriter, r *http.Request) {
	flow := inspect.Flow{
		Name:     nameAsked(r.Host),
		Port:     portAsked(r.Host),
		Where:    "the proxy",
		Protocol: "tcp",
	}
	watch := p.set.watches(flow)
	open := func(ctx context.Context, client, upstream net.Conn) (net.Conn, net.Conn, error) {
		return p.set.opens(ctx, flow, client, upstream)
	}
	tunnelCONNECT(w, r, p.dial, p.tunnelContext(), p.logger(), watch, open)
}

// tunnelCONNECT carries a CONNECT request through dial and then owns the connection.
//
// tunnels is the context a hijacked tunnel lives under, which is never the request's:
// net/http cancels that as soon as the handler returns, and the handler returns the moment
// the tunnel is established.
//
// watch reads the opening bytes of the tunnel, and is nil when nothing is reading them. open
// decides whether the tunnel is opened first so that watch has something to read, and answers
// the pair to carry it between; nil opens nothing, which is what a relay carrying one command
// through the agent's own proxy wants.
func tunnelCONNECT(
	w http.ResponseWriter,
	r *http.Request,
	dial func(ctx context.Context, network, address string) (net.Conn, error),
	tunnels context.Context,
	logger *slog.Logger,
	watch netpipe.Stream,
	open func(ctx context.Context, client, upstream net.Conn) (net.Conn, net.Conn, error),
) {
	upstream, err := dial(r.Context(), "tcp", r.Host)
	if err != nil {
		writeRefusal(w, err)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		// Unreachable with net/http's own server, which is the only one that serves
		// this handler. It stays because a tunnel that silently became a normal
		// response would corrupt whatever the client sent next.
		writeRefusal(w, errors.New("this server cannot take over the connection a tunnel needs"))
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		logger.Warn("could not take over a connection for a CONNECT tunnel", "error", err)
		return
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	// A client that pipelined its first bytes behind the CONNECT line has them sitting
	// in the server's reader, not in the socket. Dropping them loses the TLS ClientHello
	// on most tunnels, and the handshake then hangs until something times out.
	//
	// They are put back in front of the connection rather than written straight across,
	// because these are exactly the bytes inspection exists to read: a client that pipelines
	// its hello behind the CONNECT line would otherwise be the one client whose handshake
	// nothing here sees, and the copy below reads them from the connection like any others.
	if n := buffered.Reader.Buffered(); n > 0 {
		prelude := make([]byte, n)
		if _, err := io.ReadFull(buffered.Reader, prelude); err != nil {
			client.Close()
			upstream.Close()
			if watch != nil {
				watch.Close()
			}
			logger.Warn("could not take the bytes a client pipelined behind its CONNECT line", "error", err)
			return
		}
		client = tlsmint.Replay(client, prelude)
	}

	opened, openedUpstream, err := client, upstream, error(nil)
	if open != nil {
		opened, openedUpstream, err = open(tunnels, client, upstream)
	}
	if err != nil {
		// Cut rather than closed, for the reason netpipe cuts a stopped connection that way:
		// an orderly close here is the shape of a tunnel that finished.
		netpipe.Reset(client)
		netpipe.Reset(upstream)
		if watch != nil {
			watch.Close()
		}
		logger.Warn("a tunnel was stopped rather than carried unread", "destination", r.Host, "error", err)
		return
	}
	client, upstream = opened, openedUpstream

	if err := netpipe.CopyWith(tunnels, client, upstream, nil, nil, watch); err != nil {
		logger.Debug("a proxy tunnel ended with an error", "destination", r.Host, "error", err)
	}
}

// serveForward carries an ordinary proxied request -- the absolute-form GET a client
// sends for an http:// URL when HTTP_PROXY names this proxy. Without it every plain
// HTTP fetch through the proxy fails, since only https:// is tunnelled with CONNECT.
func (p *Instance) serveForward(w http.ResponseWriter, r *http.Request) {
	forwardRequest(w, r, p.transport, p.logger())
}

// forwardRequest carries one proxied request through transport and copies the answer back.
func forwardRequest(w http.ResponseWriter, r *http.Request, transport http.RoundTripper, logger *slog.Logger) {
	if !r.URL.IsAbs() {
		http.Error(w, "this is a proxy: send an absolute URL, or CONNECT for a tunnel", http.StatusBadRequest)
		return
	}

	outbound := r.Clone(r.Context())
	// RequestURI is set on a received request and rejected on one being sent.
	outbound.RequestURI = ""
	stripHopByHop(outbound.Header, r.Header.Get("Connection"))

	resp, err := transport.RoundTrip(outbound)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	defer resp.Body.Close()

	stripHopByHop(resp.Header, resp.Header.Get("Connection"))
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		logger.Debug("a proxied response ended early", "url", r.URL.String(), "error", err)
	}
}

// stripHopByHop removes the connection-scoped headers, including the ones the
// Connection header itself names -- which is how a hop-by-hop header that is not on the
// standard list is declared.
func stripHopByHop(h http.Header, connection string) {
	for _, name := range strings.Split(connection, ",") {
		if name = strings.TrimSpace(name); name != "" {
			h.Del(name)
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// writeRefusal answers with the status that says which kind of refusal this was, and
// with the reason in a header as well as the body: a browser shows its own error page
// for a failed CONNECT and never displays the body at all.
func writeRefusal(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, ErrUnreachable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ErrRefused):
		status = http.StatusForbidden
	}
	w.Header().Set(ConnectErrorHeader, oneLine(err.Error()))
	http.Error(w, err.Error(), status)
}

// oneLine makes a message safe to put in a header value. An error carrying a newline
// would otherwise end the header block and let the rest of it be read as a response.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}

// tunnelContext returns the context a hijacked tunnel lives under. It is the listener's
// own, not the request's: net/http cancels a request context once its handler returns,
// and the handler returns as soon as the tunnel is established.
func (p *Instance) tunnelContext() context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tunnels == nil {
		return context.Background()
	}
	return p.tunnels
}
