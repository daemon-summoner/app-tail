// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"

	"github.com/sellitus/app-tail/internal/config"
)

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNS, "DNS"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.DNS.View(r.Context()))
}

// handleDNSSetup arranges the administrator rights the machine-wide resolver needs. It
// answers with the view rather than with nothing, because the interesting part of the
// answer is what the machine can do now that it could not before.
func (s *Server) handleDNSSetup(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.DNS, "DNS"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.DNS.SetUpSystem(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.DNS.View(r.Context()))
}

func (s *Server) handleListDNSProfiles(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Profiles, "DNS profiles"); err != nil {
		s.writeError(w, r, err)
		return
	}
	list := s.deps.Profiles.List()
	if list == nil {
		list = []config.DNSProfile{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"profiles": list})
}

func (s *Server) handleCreateDNSProfile(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Profiles, "DNS profiles"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var p config.DNSProfile
	if err := decodeJSON(r, &p); err != nil {
		s.writeError(w, r, err)
		return
	}
	// BuiltIn is owned by the catalog: a client cannot mint a shipped profile, which is
	// what would otherwise make it undeletable.
	p.BuiltIn = false

	created, err := s.deps.Profiles.Create(p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateDNSProfile(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Profiles, "DNS profiles"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var p config.DNSProfile
	if err := decodeJSON(r, &p); err != nil {
		s.writeError(w, r, err)
		return
	}
	p.BuiltIn = false

	updated, err := s.deps.Profiles.Update(r.PathValue("id"), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteDNSProfile(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Profiles, "DNS profiles"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Profiles.Delete(r.Context(), r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}
