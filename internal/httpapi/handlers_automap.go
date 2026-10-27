// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

func (s *Server) handleGetAutoMap(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.AutoMap, "automatic ports"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.AutoMap.View())
}

// handleAutoMapForget drops the assignments for devices that are gone. It answers with
// the module's state afterwards rather than only a count, so a client renders the
// result without a second request racing the reconcile that follows.
func (s *Server) handleAutoMapForget(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.AutoMap, "automatic ports"); err != nil {
		s.writeError(w, r, err)
		return
	}
	removed, err := s.deps.AutoMap.Forget(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, autoMapForgetResult{Removed: removed, AutoMap: s.deps.AutoMap.View()})
}

type autoMapForgetResult struct {
	Removed int         `json:"removed"`
	AutoMap AutoMapView `json:"automap"`
}
