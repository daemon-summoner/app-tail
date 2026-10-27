// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"strings"

	"github.com/sellitus/app-tail/internal/routing"
)

func (s *Server) handleGetRouting(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Routing, "routing rules"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Routing.View())
}

// handleSetRoutingRules replaces the whole ordered rule list.
//
// The body is the list rather than an edit to it for the reason the proxy's rules are:
// order is semantics, the first matching rule decides, and a caller sending what the list
// should be gets a list it recognises rather than an interleaving of two clients' edits.
func (s *Server) handleSetRoutingRules(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Routing, "routing rules"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		Rules []routing.Rule `json:"rules"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Routing.SetRules(r.Context(), body.Rules)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

// handleRoutingCheck answers which way one destination goes, without dialling it.
//
// It is a POST for the reason the proxy's test is: the destination is the caller's input
// rather than part of the resource's address, and a routing table nobody can question is
// one nobody trusts -- this is what makes rule order visible.
func (s *Server) handleRoutingCheck(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Routing, "routing rules"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body RoutingCheckRequest
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	body.Destination = strings.TrimSpace(body.Destination)
	if body.Destination == "" {
		s.writeError(w, r, badRequest("destination is required, as a host name or an address"))
		return
	}
	result, err := s.deps.Routing.Check(body)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
