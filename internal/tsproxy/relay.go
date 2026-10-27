// SPDX-License-Identifier: MIT

package tsproxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"
)

// Relay is a proxy that stands in front of another one and carries a credential of its
// own, minted for as long as it runs.
//
// Pointing a program at a proxy means putting the proxy's URL in that program's
// environment, and a proxy that requires a password needs the password in that URL. The
// stored password opens this account's proxy until someone changes it, and an environment
// is not a private place: a crash reporter, a build log or a `ps` on some systems carries
// it off, and it is inherited by every process the program starts. A relay is what goes
// into the environment instead. It listens on loopback, accepts one credential that was
// generated when it started and that opens nothing else on the machine, presents the real
// password to the proxy behind it, and stops existing when it is closed.
//
// It speaks both halves of what it fronts, because the two environment variables a program
// reads name different protocols on the same address.
type Relay struct {
	addr     string
	password string

	ln      net.Listener
	httpSrv *http.Server
	// tunnels outlives each request, because a CONNECT tunnel is hijacked out of the
	// server and carries bytes long after the handler that made it returned.
	tunnels context.Context
	cancel  context.CancelFunc
	logger  *slog.Logger
	// closing separates a listener this relay closed from one that failed.
	closing atomic.Bool
	wg      sync.WaitGroup
}

// StartRelay opens a loopback proxy in front of the one at upstream, which it reaches with
// password. The credential callers must present to it is minted here and is readable from
// Password; nothing else on the machine accepts it, and it is gone once Close returns.
func StartRelay(upstream, password string, logger *slog.Logger) (*Relay, error) {
	if upstream == "" {
		return nil, errors.New("a relay needs the address of the proxy it stands in front of")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	// SOCKS5 is what the relay speaks to the proxy behind it, in both directions of its
	// own front end: it carries the destination as the client wrote it, so a name is still
	// resolved by the proxy on the network that reaches it rather than by this machine.
	through, err := proxy.SOCKS5("tcp", upstream, &proxy.Auth{User: ProxyUser, Password: password}, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("reach the proxy at %s: %w", upstream, err)
	}
	dialer, ok := through.(proxy.ContextDialer)
	if !ok {
		// The SOCKS5 dialer has carried a context for as long as this package has existed;
		// without one, a connection could not be ended when the relay closes.
		return nil, errors.New("the SOCKS5 dialer cannot carry a context")
	}

	credential, err := relayCredential()
	if err != nil {
		return nil, err
	}

	// Loopback and an OS-assigned port: this listener is for one command, so a configured
	// address would be a second thing to keep out of the way of the proxy's own.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open a loopback proxy in front of %s: %w", upstream, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{
		addr:     ln.Addr().String(),
		password: credential,
		ln:       ln,
		tunnels:  ctx,
		cancel:   cancel,
		logger:   logger,
	}
	transport := &http.Transport{DialContext: dialer.DialContext}
	r.httpSrv = &http.Server{
		Handler:           r.handler(dialer, transport),
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	socksSrv := &socks5.Server{
		Logf:     func(format string, args ...any) { logger.Debug(fmt.Sprintf(format, args...)) },
		Dialer:   dialer.DialContext,
		Username: ProxyUser,
		Password: credential,
	}

	socksLn, httpLn := proxymux.SplitSOCKSAndHTTP(ln)
	r.wg.Add(2)
	go r.serve("SOCKS5", func() error { return socksSrv.Serve(socksLn) })
	go r.serve("HTTP", func() error { return r.httpSrv.Serve(httpLn) })
	return r, nil
}

// Addr is where the relay listens, in host:port form.
func (r *Relay) Addr() string { return r.addr }

// Password is the credential the relay accepts, which is not the one it presents upstream.
func (r *Relay) Password() string { return r.password }

// Close stops the relay and ends everything it was carrying. The credential it accepted
// opens nothing afterwards, because nothing is listening to accept it.
func (r *Relay) Close() {
	r.closing.Store(true)
	// Closing the raw listener is what unblocks both split halves; proxymux's own Close
	// does not reach it.
	if err := r.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		r.logger.Warn("closing the proxy for this command failed", "error", err)
	}
	if err := r.httpSrv.Close(); err != nil {
		r.logger.Warn("closing the HTTP side of the proxy for this command failed", "error", err)
	}
	// Tunnels are hijacked out of the HTTP server and survive its close, so this is what
	// ends the ones still carrying traffic.
	r.cancel()
	r.wg.Wait()
}

// handler answers both shapes of HTTP proxying, once the caller has proved it holds this
// relay's own credential.
func (r *Relay) handler(dialer proxy.ContextDialer, transport http.RoundTripper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.authorized(req) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="app-tail"`)
			http.Error(w, "this proxy carries one command and requires that command's credential",
				http.StatusProxyAuthRequired)
			return
		}
		if req.Method == http.MethodConnect {
			// Nothing reads these bytes here, and nothing opens them: this relay carries one
			// command through the agent's own proxy, which inspects what it carries. A second
			// reader would be a second window over the same connection and a second copy of
			// every finding, and a second interception would be one this end could not
			// present a certificate for anyway.
			tunnelCONNECT(w, req, dialer.DialContext, r.tunnels, r.logger, nil, nil)
			return
		}
		forwardRequest(w, req, transport, r.logger)
	})
}

// authorized checks the relay's own credential, in constant time: it is a secret, and
// every process on this machine can reach the port it opens.
func (r *Relay) authorized(req *http.Request) bool {
	user, pass, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(ProxyUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(r.password)) == 1
	return userOK && passOK
}

// serve runs one half of the split listener and reports why it stopped, unless this relay
// is what stopped it.
func (r *Relay) serve(name string, run func() error) {
	defer r.wg.Done()
	if err := run(); err != nil && !r.closing.Load() {
		r.logger.Error("the proxy for this command stopped", "protocol", name, "error", err)
	}
}

// relayCredential mints the password this relay accepts. It is 32 bytes because it stands
// in for a stored password of unknown strength and is guessed at over loopback by anything
// on this machine that cares to.
func relayCredential() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate a credential for this command's proxy: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
