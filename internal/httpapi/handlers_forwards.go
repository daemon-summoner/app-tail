// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"strconv"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/ports"
)

func (s *Server) handleListForwards(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Forwards, "forwards"); err != nil {
		s.writeError(w, r, err)
		return
	}
	list := s.deps.Forwards.List()
	if list == nil {
		list = []ForwardView{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"forwards": list})
}

func (s *Server) handleGetForward(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Forwards, "forwards"); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Forwards.Get(r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleCreateForward(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Forwards, "forwards"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var spec ForwardSpec
	if err := decodeJSON(r, &spec); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Forwards.Create(r.Context(), spec)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, view)
}

func (s *Server) handleUpdateForward(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Forwards, "forwards"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var spec ForwardSpec
	if err := decodeJSON(r, &spec); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Forwards.Update(r.Context(), r.PathValue("id"), spec)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleDeleteForward(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Forwards, "forwards"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Forwards.Delete(r.Context(), r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}

// toggleRequest carries the desired enabled state. A nil Enabled flips the current
// value, which is what the dashboard's switch sends.
type toggleRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleToggleForward(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Forwards, "forwards"); err != nil {
		s.writeError(w, r, err)
		return
	}
	id := r.PathValue("id")

	var req toggleRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, r, err)
			return
		}
	}

	enabled := false
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else {
		current, err := s.deps.Forwards.Get(id)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		enabled = !current.Enabled
	}

	view, err := s.deps.Forwards.SetEnabled(r.Context(), id, enabled)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

// handleSuggestPort answers the add-forward wizard's "what local port should I use"
// question. protocol and target are required; bindAddr defaults to loopback.
func (s *Server) handleSuggestPort(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Forwards, "forwards"); err != nil {
		s.writeError(w, r, err)
		return
	}
	q := r.URL.Query()

	protocol := config.Protocol(q.Get("protocol"))
	if protocol == "" {
		protocol = config.TCP
	}
	if protocol != config.TCP && protocol != config.UDP && protocol != config.Both {
		s.writeError(w, r, badRequest("protocol must be %q, %q or %q, got %q",
			config.TCP, config.UDP, config.Both, protocol))
		return
	}

	// The wizard normally passes the chosen target and lets its port become the
	// preferred local port; an explicit preferred overrides that.
	preferred := ports.TargetPort(q.Get("target"))
	if raw := q.Get("preferred"); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			s.writeError(w, r, badRequest("preferred must be a port number, got %q", raw))
			return
		}
		if port < 1 || port > 65535 {
			s.writeError(w, r, badRequest("preferred must be 1-65535, got %d", port))
			return
		}
		preferred = port
	}

	port, err := s.deps.Forwards.SuggestPort(protocol, q.Get("bindAddr"), preferred)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"port": port})
}
