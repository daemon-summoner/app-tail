// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

// maxPauseMinutes bounds a pause. A pause is meant to get one site loaded, and a blocker
// paused for a day is a blocker somebody will find switched off next week without ever
// having chosen that.
const maxPauseMinutes = 24 * 60

func (s *Server) handleGetDNSBlock(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.DNSBlock.View())
}

// handleRefreshDNSBlock downloads every enabled list now. It answers with the view because
// what the caller wants to know is what the download produced.
func (s *Server) handleRefreshDNSBlock(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.DNSBlock.Refresh(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.DNSBlock.View())
}

func (s *Server) handlePauseDNSBlock(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		Minutes int `json:"minutes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	if body.Minutes < 1 || body.Minutes > maxPauseMinutes {
		s.writeError(w, r, &config.ValidationError{
			Field:   "minutes",
			Message: "a pause lasts between 1 minute and 24 hours",
		})
		return
	}
	s.deps.DNSBlock.Pause(time.Duration(body.Minutes) * time.Minute)
	s.writeJSON(w, http.StatusOK, s.deps.DNSBlock.View())
}

func (s *Server) handleResumeDNSBlock(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.deps.DNSBlock.Resume()
	s.writeJSON(w, http.StatusOK, s.deps.DNSBlock.View())
}

// handlePresetDNSBlock switches the shipped lists to one rung of the curated ladder. It
// answers with the view, because what the caller wants to know is what is on now.
func (s *Server) handlePresetDNSBlock(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		Preset string `json:"preset"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	if body.Preset == "" {
		s.writeError(w, r, &config.ValidationError{
			Field:   "preset",
			Message: "name a level to switch to",
		})
		return
	}
	if err := s.deps.DNSBlock.ApplyPreset(r.Context(), body.Preset); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.DNSBlock.View())
}

// handleCheckDNSBlock answers whether one name is blocked and by what. It is the one
// question the list of lists cannot answer, and the one people actually ask.
func (s *Server) handleCheckDNSBlock(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		s.writeError(w, r, &config.ValidationError{
			Field:   "name",
			Message: "name a domain to check",
		})
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.DNSBlock.Check(name))
}

func (s *Server) handleCreateDNSBlockList(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var l config.Blocklist
	if err := decodeJSON(r, &l); err != nil {
		s.writeError(w, r, err)
		return
	}
	// BuiltIn is owned by the catalog: a client cannot mint a shipped list, which is what
	// would otherwise make it undeletable.
	l.BuiltIn = false

	created, err := s.deps.DNSBlock.CreateList(l)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateDNSBlockList(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var l config.Blocklist
	if err := decodeJSON(r, &l); err != nil {
		s.writeError(w, r, err)
		return
	}
	l.BuiltIn = false

	updated, err := s.deps.DNSBlock.UpdateList(r.PathValue("id"), l)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteDNSBlockList(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNSBlock, "DNS blocking"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.DNSBlock.DeleteList(r.Context(), r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}
