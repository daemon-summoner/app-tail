// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

// handleGetSystemProxy reports this machine's own proxy configuration.
//
// It is read-only. The switch that drives it is an ordinary settings field, so it is
// written through PUT /api/settings and inherits that route's validation, availability
// rejection and restart classification rather than growing a second write path.
func (s *Server) handleGetSystemProxy(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.SysProxy, "system proxy"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.SysProxy.View())
}
