// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

func (s *Server) handleGetFabric(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Fabric, "network addressing"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Fabric.View(r.Context()))
}
