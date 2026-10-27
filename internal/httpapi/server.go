// SPDX-License-Identifier: MIT

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/sellitus/app-tail/internal/peeraccount"
)

const (
	// maxRequestBytes caps a request body. Every payload this API accepts is a small
	// JSON object, so anything larger is a mistake or an attack.
	maxRequestBytes = 1 << 20

	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	idleTimeout       = 120 * time.Second
	// WriteTimeout bounds the whole handler, so it is sized by the two slowest
	// routes, not by the typical one: POST /api/restart rebuilds a real tsnet node,
	// and POST /api/policy/apply makes three control-plane round trips -- authenticate,
	// fetch, save -- each behind a 30s per-request client timeout, so 90s worst case.
	// Anything near 30s cuts both off mid-flight, and a cut during save leaves the
	// tailnet ACL committed while the caller sees a reset connection.
	//
	// Exported because work that has to finish inside the answer carrying it bounds
	// itself against this value rather than against a number of its own.
	WriteTimeout  = 120 * time.Second
	shutdownGrace = 5 * time.Second

	// contentSecurityPolicy locks the dashboard to assets served from this origin.
	//
	// style-src needs 'unsafe-inline': the dashboard sets inline style attributes
	// from React style props across several components, and React emits those as
	// literal style="" attributes. Dropping it ships an unstyled page. script-src
	// needs no nonce -- the built index.html carries no inline script.
	contentSecurityPolicy = "default-src 'self'; script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
		"object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

// Server is the loopback management API and dashboard host.
type Server struct {
	deps   Deps
	auth   Auth
	logger *slog.Logger
	// callerAccount checks that a connection is held by this account's own process.
	callerAccount func(peer, server netip.AddrPort) error
	ui            fs.FS

	http *http.Server
	ln   net.Listener
}

// Options configures a Server. UI may be nil, in which case dashboard routes
// report that no UI was built into this binary rather than 404-ing ambiguously.
type Options struct {
	Deps Deps
	// Auth decides which callers the API answers. Required: there is no setting that
	// turns authentication off.
	Auth   Auth
	Logger *slog.Logger
	UI     fs.FS
	// CallerAccount checks that the connection a sign-in link is redeemed on is held by a
	// process of this account. Nil is the platform's own check, peeraccount.Check.
	CallerAccount func(peer, server netip.AddrPort) error
}

// New builds the server and its route table. It does not bind a socket.
//
// It panics without an Auth, rather than serving an API every local process could drive:
// that is a wiring mistake no caller can recover from at runtime.
func New(opts Options) *Server {
	if opts.Auth == nil {
		panic("httpapi.New: Options.Auth is nil; the management API cannot be served without authentication")
	}
	logger := opts.Logger
	if logger == nil {
		logger = discardLogger()
	}
	callerAccount := opts.CallerAccount
	if callerAccount == nil {
		callerAccount = peeraccount.Check
	}
	s := &Server{deps: opts.Deps, auth: opts.Auth, logger: logger, ui: opts.UI, callerAccount: callerAccount}
	s.http = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	return s
}

// Handler exposes the routed handler for tests and for embedding.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routeTable() {
		mux.HandleFunc(rt.pattern, rt.handler)
	}
	return s.withGuards(mux)
}

// route is one pattern the server answers and the handler that answers it.
type route struct {
	pattern string
	handler http.HandlerFunc
}

// routeTable is every route the server registers. It is a table rather than a run of
// HandleFunc calls so the guard tests can walk every route and prove none of them answers
// without a token -- a list kept by hand in a test would miss the next route added here.
func (s *Server) routeTable() []route {
	return []route{
		// The two routes a caller reaches before it has a credential: a browser trading
		// a launch token for a session, and the CLI asking the listener to prove it holds
		// the token before handing it over. The guard lets exactly these through.
		{"POST " + sessionPath, s.handleAuthSession},
		{"POST " + helloPath, s.handleAuthHello},
		{"POST /api/auth/launch", s.handleAuthLaunch},
		{"POST /api/auth/rotate", s.handleAuthRotate},

		{"GET /api/status", s.handleStatus},
		{"POST /api/login", s.handleLogin},
		{"POST /api/login/url", s.handleLoginURL},
		{"POST /api/logout", s.handleLogout},
		{"POST /api/restart", s.handleRestart},
		{"POST /api/restart-app", s.handleRestartApp},
		{"POST /api/quit", s.handleQuit},
		{"GET /api/peers", s.handlePeers},

		{"GET /api/presets", s.handleListPresets},
		{"POST /api/presets", s.handleCreatePreset},
		{"DELETE /api/presets/{id}", s.handleDeletePreset},

		{"GET /api/forwards", s.handleListForwards},
		{"POST /api/forwards", s.handleCreateForward},
		{"GET /api/forwards/suggest-port", s.handleSuggestPort},
		{"GET /api/forwards/{id}", s.handleGetForward},
		{"PUT /api/forwards/{id}", s.handleUpdateForward},
		{"DELETE /api/forwards/{id}", s.handleDeleteForward},
		{"POST /api/forwards/{id}/toggle", s.handleToggleForward},

		{"GET /api/tunnels", s.handleListTunnels},
		{"POST /api/tunnels", s.handleCreateTunnel},
		{"GET /api/tunnels/schema", s.handleGetTunnelSchema},
		{"GET /api/tunnels/{id}", s.handleGetTunnel},
		{"GET /api/tunnels/{id}/peers", s.handleListTunnelPeers},
		{"PUT /api/tunnels/{id}", s.handleUpdateTunnel},
		{"POST /api/tunnels/{id}/import", s.handleImportTunnel},
		{"POST /api/tunnels/{id}/retry", s.handleRetryTunnel},
		{"DELETE /api/tunnels/{id}", s.handleDeleteTunnel},

		{"GET /api/settings", s.handleGetSettings},
		{"PUT /api/settings", s.handleUpdateSettings},
		{"GET /api/settings/schema", s.handleGetSettingsSchema},
		{"GET /api/prefs", s.handleGetPrefs},

		{"GET /api/tun", s.handleGetInterface},
		{"POST /api/tun/setup", s.handleInterfaceSetup},
		{"POST /api/tun/approve", s.handleApprove},

		{"GET /api/autostart", s.handleGetAutostart},
		{"POST /api/autostart", s.handleSetAutostart},

		{"POST /api/policy/preview", s.handlePolicyPreview},
		{"POST /api/policy/apply", s.handlePolicyApply},

		{"GET /api/traffic", s.handleGetTraffic},
		{"GET /api/traffic/{lane}", s.handleGetTrafficBreakdown},
		// The singular routes answer for the instance every install has, which is what the
		// surfaces written while there could be only one proxy still mean.
		{"GET /api/proxy", s.handleGetProxy},
		{"POST /api/proxy/probe", s.handleProxyProbe},

		{"GET /api/proxies", s.handleListProxies},
		{"POST /api/proxies", s.handleCreateProxy},
		{"GET /api/proxies/schema", s.handleGetProxySchema},
		{"GET /api/proxies/{id}", s.handleGetProxyInstance},
		{"PUT /api/proxies/{id}", s.handleUpdateProxy},
		{"PUT /api/proxies/{id}/rules", s.handleSetProxyRules},
		{"POST /api/proxies/{id}/test", s.handleTestProxy},
		{"DELETE /api/proxies/{id}", s.handleDeleteProxy},

		{"GET /api/telemetry", s.handleGetTelemetry},
		{"GET /api/telemetry/events", s.handleGetTelemetryEvents},

		{"GET /api/automap", s.handleGetAutoMap},
		{"POST /api/automap/forget", s.handleAutoMapForget},

		{"GET /api/exitnode", s.handleGetExitNode},
		{"POST /api/exitnode/suggest", s.handleExitNodeSuggest},

		{"GET /api/routes", s.handleGetRoutes},
		{"POST /api/routes/check", s.handleRoutesCheck},

		// The per-destination exceptions, which are not the tailnet's subnet routes above: those
		// report the networks peers carry here, these decide which connection a destination
		// nothing else claims leaves through.
		{"GET /api/routing", s.handleGetRouting},
		{"PUT /api/routing/rules", s.handleSetRoutingRules},
		{"POST /api/routing/check", s.handleRoutingCheck},

		{"GET /api/fabric", s.handleGetFabric},

		{"GET /api/egress", s.handleGetEgress},

		{"GET /api/lock", s.handleGetLock},
		{"GET /api/lock/log", s.handleGetLockLog},
		{"POST /api/lock/sign", s.handleLockSign},
		{"POST /api/lock/disable-local", s.handleLockDisableLocal},

		{"GET /api/dns", s.handleGetDNS},
		{"POST /api/dns/setup", s.handleDNSSetup},
		{"GET /api/dns/profiles", s.handleListDNSProfiles},
		{"POST /api/dns/profiles", s.handleCreateDNSProfile},
		{"PUT /api/dns/profiles/{id}", s.handleUpdateDNSProfile},
		{"DELETE /api/dns/profiles/{id}", s.handleDeleteDNSProfile},
		{"GET /api/dns/block", s.handleGetDNSBlock},
		{"POST /api/dns/block/refresh", s.handleRefreshDNSBlock},
		{"POST /api/dns/block/pause", s.handlePauseDNSBlock},
		{"POST /api/dns/block/resume", s.handleResumeDNSBlock},
		{"POST /api/dns/block/preset", s.handlePresetDNSBlock},
		{"GET /api/dns/block/check", s.handleCheckDNSBlock},
		{"POST /api/dns/block/lists", s.handleCreateDNSBlockList},
		{"PUT /api/dns/block/lists/{id}", s.handleUpdateDNSBlockList},
		{"DELETE /api/dns/block/lists/{id}", s.handleDeleteDNSBlockList},

		{"GET /api/ips", s.handleGetIPS},
		{"POST /api/ips/refresh", s.handleRefreshIPS},
		{"POST /api/ips/pause", s.handlePauseIPS},
		{"POST /api/ips/resume", s.handleResumeIPS},
		{"POST /api/ips/preset", s.handlePresetIPS},
		{"GET /api/ips/check", s.handleCheckIPS},
		{"POST /api/ips/intercept/remove-root", s.handleRemoveInterceptRoot},
		{"POST /api/ips/feeds", s.handleCreateIPSFeed},
		{"PUT /api/ips/feeds/{id}", s.handleUpdateIPSFeed},
		{"DELETE /api/ips/feeds/{id}", s.handleDeleteIPSFeed},

		{"GET /api/proxy/system", s.handleGetSystemProxy},
		// The auto-config script is not under /api: a browser fetches it by URL, and that
		// URL goes into a proxy setting a user reads and types.
		{"GET /proxy.pac", s.handlePAC},

		{"GET /healthz", s.handleHealthz},

		// Anything not matched above is a dashboard route.
		{"/", s.handleUI},
	}
}

// withGuards applies the cross-cutting concerns every route needs: rebinding
// protection on every request, a bearer token on every API request, same-origin
// protection for state-changing requests, no-store on API responses, and a panic barrier
// so one bad handler cannot take the agent down.
func (s *Server) withGuards(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic serving api request",
					"method", r.Method, "path", r.URL.Path, "panic", rec)
				s.writeJSON(w, http.StatusInternalServerError,
					errorBody{Error: "internal error"})
			}
		}()

		// Set before the guards below, not after: a refusal is the one response a
		// hostile page can reliably provoke, so it is the response that most needs
		// these. They are defense in depth behind the Host guard -- none of them stops
		// rebinding, since a rebound request is same-origin by definition. They contain
		// the damage a bug elsewhere could do: no MIME sniffing, no framing the
		// dashboard, no leaking loopback URLs to sites the user clicks through to.
		header := w.Header()
		header.Set("Cache-Control", "no-store")
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")

		// A Host the agent does not answer to means the browser was pointed at a name
		// that now resolves to loopback but is not ours: DNS rebinding. After the
		// rebind every request is same-origin, so the Origin check below cannot see
		// it, and /api/status would hand out the pending tailnet auth URL. The dialed
		// name is the only signal left, so this applies to reads and to the dashboard
		// routes too -- serving index.html is how the attacker gets script in-page.
		if !allowedHost(r.Host) {
			s.writeJSON(w, http.StatusForbidden, errorBody{Error: s.wrongHostMessage(r.Host)})
			return
		}

		// The browser's own account of where the request came from, which it sets and
		// no page can. It covers what Origin does not: a form post and a navigation
		// carry no Origin a check can compare, and both arrive here as cross-site.
		// Absent on every non-browser caller, which is why only the one value is
		// refused rather than anything but "same-origin".
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			s.writeJSON(w, http.StatusForbidden,
				errorBody{Error: "cross-site request refused; the dashboard answers only its own pages"})
			return
		}

		// Loopback is reachable by every process on the machine, other accounts' included,
		// so the API answers only a caller holding the token in this account's state
		// directory, or a session a browser got by trading a launch token the tray or the
		// CLI minted from it.
		if needsToken(r) && !s.authorized(r) {
			s.logger.Warn("refused an api request without a valid token",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="app-tail"`)
			s.writeJSON(w, http.StatusUnauthorized, errorBody{Error: signInMessage})
			return
		}

		// A browser holding a session still runs pages from other sites, so rejecting
		// cross-origin writes stays: it is what stops a random site from riding a
		// signed-in dashboard's requests.
		if isStateChanging(r.Method) {
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
				s.writeJSON(w, http.StatusForbidden,
					errorBody{Error: fmt.Sprintf("cross-origin request from %s refused", origin)})
				return
			}
			if err := jsonBodyType(r.Header.Get("Content-Type")); err != nil {
				s.writeJSON(w, http.StatusUnsupportedMediaType, errorBody{Error: err.Error()})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// jsonBodyType refuses a write whose body is declared as anything but JSON.
//
// This is what makes a form post structurally unable to reach a handler, rather than
// merely unlikely to. An HTML form can only send its body as one of three types --
// urlencoded, multipart, or text/plain -- and none of them is this one; a page that
// wants any other type has to ask permission first, through a preflight this API
// answers for no cross-origin caller. So the header a browser will not let a hostile
// page forge is the header required here, and the Origin and Sec-Fetch-Site checks
// stop being the only thing standing between a form and a write.
//
// An absent type is allowed because it is what a write with no body looks like: the
// dashboard and the CLI both set this header exactly when they send a body, and half
// the CLI's writes -- logout, restart, every delete -- send none. Nothing is given
// away by that, since a body-less form does not exist and a browser sending no body
// still sends the Origin the check above reads.
func jsonBodyType(header string) error {
	if header == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return fmt.Errorf("could not read the Content-Type %q: %w", header, err)
	}
	if !strings.EqualFold(mediaType, "application/json") {
		return fmt.Errorf("this API takes application/json, not %s", mediaType)
	}
	return nil
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// allowedHost reports whether a Host header names this agent.
//
// The port is deliberately not checked. The Vite dev proxy forwards the browser's
// own "localhost:5173" verbatim, the agent's port moves when the configured one is
// taken, and a port number carries no rebinding protection anyway -- an attacker
// who picks the name picks the port with it.
func allowedHost(host string) bool {
	// Go rejects an HTTP/1.1 request that omits Host before any handler runs, and no
	// browser omits it, so refusing an empty value blocks no rebinding attack; it
	// only breaks HTTP/1.0 probes.
	if host == "" {
		return true
	}
	return isLoopbackName(hostWithoutPort(host))
}

// wrongHostMessage explains the refusal in terms the user can act on. Someone who
// reached the agent over "ssh -L" under a machine name has no other clue.
func (s *Server) wrongHostMessage(host string) string {
	msg := fmt.Sprintf("request for host %q refused; the dashboard answers only to loopback names", host)
	if s.ln != nil {
		msg += fmt.Sprintf(", so open http://%s/ instead", s.ln.Addr().String())
	}
	return msg
}

// hostWithoutPort strips the optional port from an authority, handling the
// bracketed IPv6 literal form in both its ported and bare spellings.
func hostWithoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

// sameOrigin reports whether a write came from the page the agent itself served.
//
// The comparison is against the request's own Host rather than against a list of
// loopback names, because a name being loopback says nothing about who controls the
// page behind it: a resolver that forwards *.localhost upstream instead of pinning
// it to 127.0.0.1 -- RFC 6761 makes that a SHOULD, not a MUST -- lets a genuinely
// remote page present an origin any loopback allowlist would trust. Requiring the
// authorities to match makes that irrelevant, and it is what keeps the dashboard
// working under whichever loopback name the user actually dialed.
//
// The Vite dev proxy is the case that pins this: it sets changeOrigin:false so both
// the browser's Host and its Origin arrive verbatim as "localhost:5173". Flipping
// that to true rewrites Host alone and dev writes start failing here.
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// isLoopbackHost reports whether a host is one the agent may bind. It is stricter
// than isLoopbackName on purpose: a name under .localhost goes through the resolver,
// and a listen address must never depend on what the resolver says.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isLoopbackName reports whether a host a client dialed refers to this machine.
func isLoopbackName(host string) bool {
	// A Host may carry the FQDN's trailing dot.
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	// RFC 6761 reserves "localhost" and everything beneath it for the loopback. The
	// leading dot makes this a label comparison, so neither a name that merely ends
	// in the string ("notlocalhost") nor one that buries it mid-name
	// ("evil.localhost.attacker.example") passes.
	if strings.HasSuffix(name, ".localhost") {
		return true
	}
	return isLoopbackHost(name)
}

// Listen binds the management socket. It refuses any address that is not loopback: the
// token keeps other local accounts out, but the API speaks plain HTTP, so on a routable
// interface every credential and every answer would cross the network readable.
func (s *Server) Listen(addr string) (net.Addr, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse ui listen address %q: %w", addr, err)
	}
	if !isLoopbackHost(host) {
		return nil, fmt.Errorf(
			"ui listen address %q is not loopback; the management API speaks plain HTTP and must not be reachable off-host", addr)
	}

	// Shutdown closes s.ln, so a second Listen over a live one would strand the first
	// socket for the process lifetime -- the leak Shutdown was changed to prevent.
	if s.ln != nil {
		return nil, fmt.Errorf("ui listener is already bound to %s; Shutdown it before binding %s", s.ln.Addr(), addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind ui listener on %s: %w", addr, err)
	}
	s.ln = ln
	return ln.Addr(), nil
}

// Serve runs the accept loop until Shutdown is called. Listen must have succeeded.
func (s *Server) Serve() error {
	if s.ln == nil {
		return errors.New("Serve called before Listen")
	}
	if err := s.http.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Addr reports the bound address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Shutdown stops accepting and waits for in-flight requests, bounded by ctx or by
// a default grace period.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.ln == nil {
		return nil
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, shutdownGrace)
		defer cancel()
	}
	err := s.http.Shutdown(ctx)

	// net/http only tracks listeners handed to Serve, so a server that bound its
	// port and then failed before serving would hold it until the process exits --
	// and the agent could never rebind it on the next attempt.
	if closeErr := s.ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		err = errors.Join(err, closeErr)
	}
	return err
}
