// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

func (s *Server) handleGetEgress(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Egress, "internet traffic"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Egress.View(r.Context()))
}
