// SPDX-License-Identifier: MIT

package httpapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"github.com/sellitus/app-tail/internal/apiauth"
)

// Auth decides who the API answers, and mints the credentials a browser and the CLI
// present. *apiauth.Keys implements it.
type Auth interface {
	// CheckBearer reports whether a bearer value is the API token or a live session.
	CheckBearer(token string) bool
	// MintLaunch issues a one-time token a browser trades for a session, redeemable by
	// whom scope says.
	MintLaunch(scope apiauth.LaunchScope) (string, error)
	// LaunchScopeOf reports who may redeem an outstanding launch token, consuming nothing.
	LaunchScopeOf(launch string) (apiauth.LaunchScope, bool)
	// RedeemLaunch trades a launch token for a session, failing with
	// apiauth.ErrLaunchRefused for one that is unknown, expired or used.
	RedeemLaunch(launch string) (string, error)
	// Proof answers a client's challenge for the address it connected to.
	Proof(nonce, authority string) string
	// Rotate replaces the token, ending every session.
	Rotate() error
}

const (
	sessionPath = "/api/auth/session"
	helloPath   = "/api/auth/hello"

	// signInMessage is what a caller without a credential is told. A browser lands here
	// from a bookmark or an old tab; the way back in is one of the two things that mint a
	// launch token.
	signInMessage = "open the dashboard from the app-tail menu or run `app-tail dashboard`"
)

// needsToken reports whether a request must carry a credential: everything under /api/
// except the two routes a caller uses to get one. The dashboard's own files, /healthz
// and /proxy.pac stay open -- the first two say nothing worth guarding, and the
// auto-config script is fetched by the operating system, which has no token to send.
//
// The path is cleaned first so a spelling the mux would redirect to an API route is
// judged as that route.
func needsToken(r *http.Request) bool {
	p := path.Clean("/" + r.URL.Path)
	if p != "/api" && !strings.HasPrefix(p, "/api/") {
		return false
	}
	if r.Method == http.MethodPost && (p == sessionPath || p == helloPath) {
		return false
	}
	return true
}

// authorized reports whether the request carries a bearer credential the keys accept.
func (s *Server) authorized(r *http.Request) bool {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return s.auth.CheckBearer(strings.TrimSpace(token))
}

type sessionRequest struct {
	Launch string `json:"launch"`
}

type sessionResponse struct {
	Session string `json:"session"`
}

// handleAuthSession trades the launch token from a tray or CLI link for a session the
// dashboard keeps.
func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	var req sessionRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if req.Launch == "" {
		s.writeError(w, r, badRequest("launch is required"))
		return
	}
	// Checked before the token is spent: a refused caller leaves it for the browser it was
	// opened in.
	if scope, ok := s.auth.LaunchScopeOf(req.Launch); ok && scope == apiauth.ThisAccount {
		if err := s.callerIsThisAccount(r); err != nil {
			s.logger.Warn("refused a sign-in link from another account", "remote", r.RemoteAddr, "err", err)
			s.writeJSON(w, http.StatusForbidden, errorBody{Error: "this sign-in link can only be opened by the account app-tail runs as; " +
				"for a link another account can open, run `app-tail dashboard --print` as that account"})
			return
		}
	}
	session, err := s.auth.RedeemLaunch(req.Launch)
	if errors.Is(err, apiauth.ErrLaunchRefused) {
		s.logger.Warn("refused an expired or unknown sign-in link", "remote", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", `Bearer realm="app-tail"`)
		s.writeJSON(w, http.StatusUnauthorized, errorBody{Error: err.Error() + "; " + signInMessage})
		return
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, sessionResponse{Session: session})
}

type helloRequest struct {
	Nonce string `json:"nonce"`
}

type helloResponse struct {
	Proof string `json:"proof"`
}

// handleAuthHello proves to the CLI that this listener holds the token before the CLI
// sends it. The proof covers the local address the connection arrived on -- not the Host
// header, which a relaying squatter writes -- so an answer obtained by forwarding the
// challenge to this agent from another port names this port and fails there.
func (s *Server) handleAuthHello(w http.ResponseWriter, r *http.Request) {
	var req helloRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if !apiauth.ValidNonce(req.Nonce) {
		s.writeError(w, r, badRequest("nonce must be %d to %d bytes of unpadded base64url",
			apiauth.MinNonceBytes, apiauth.MaxNonceBytes))
		return
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		s.writeError(w, r, errors.New("could not tell which address this request arrived on"))
		return
	}
	s.writeJSON(w, http.StatusOK, helloResponse{Proof: s.auth.Proof(req.Nonce, local.String())})
}

type launchRequest struct {
	// AnyAccount asks for a link that may be opened from another account, for a caller
	// that will show it to a person rather than start a program with it.
	AnyAccount bool `json:"anyAccount"`
}

type launchResponse struct {
	URL string `json:"url"`
}

// callerIsThisAccount checks that the connection r arrived on is held by a process of the
// account the agent runs as.
func (s *Server) callerIsThisAccount(r *http.Request) error {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return errors.New("could not tell which address this request arrived on")
	}
	server, err := netip.ParseAddrPort(local.String())
	if err != nil {
		return fmt.Errorf("read the local address %q: %w", local, err)
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("read the caller's address %q: %w", r.RemoteAddr, err)
	}
	return s.callerAccount(peer, server)
}

// handleAuthLaunch mints a sign-in link for the dashboard, for `app-tail dashboard`. The
// link names the host the caller dialed, which the Host guard has already held to a
// loopback name, so it opens wherever this request reached the agent -- the Vite dev
// server's port included.
func (s *Server) handleAuthLaunch(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" && s.ln != nil {
		host = s.ln.Addr().String()
	}
	if host == "" {
		s.writeError(w, r, errors.New("could not tell which address the dashboard is on"))
		return
	}
	var req launchRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	scope := apiauth.ThisAccount
	if req.AnyAccount {
		scope = apiauth.AnyAccount
	}
	launch, err := s.auth.MintLaunch(scope)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	link := url.URL{Scheme: "http", Host: host, Path: "/", RawQuery: url.Values{"launch": {launch}}.Encode()}
	s.writeJSON(w, http.StatusOK, launchResponse{URL: link.String()})
}

// handleAuthRotate replaces the token. Every session ends with it, the caller's included
// if it was one; the CLI reads the new token from the file on its next run.
func (s *Server) handleAuthRotate(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Rotate(); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.logger.Info("rotated the api token; every dashboard session has ended")
	s.writeJSON(w, http.StatusNoContent, nil)
}
