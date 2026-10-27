// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"

	"github.com/sellitus/app-tail/internal/config"
)

func (s *Server) handleListPresets(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Presets, "presets"); err != nil {
		s.writeError(w, r, err)
		return
	}
	list := s.deps.Presets.List()
	if list == nil {
		list = []config.Preset{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"presets": list})
}

func (s *Server) handleCreatePreset(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Presets, "presets"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var p config.Preset
	if err := decodeJSON(r, &p); err != nil {
		s.writeError(w, r, err)
		return
	}
	// BuiltIn is owned by the catalog; a client cannot mint a shipped preset.
	p.BuiltIn = false

	created, err := s.deps.Presets.Create(p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeletePreset(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Presets, "presets"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Presets.Delete(r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}
