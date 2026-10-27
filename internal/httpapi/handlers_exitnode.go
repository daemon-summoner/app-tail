// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

func (s *Server) handleGetExitNode(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.ExitNode, "exit node"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.ExitNode.View())
}

// handleExitNodeSuggest asks the tailnet which exit node it recommends. It is a POST
// because the answer is produced by a round trip to the control plane rather than read
// from state, and a client must not have it retried by a cache or a prefetch.
func (s *Server) handleExitNodeSuggest(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.ExitNode, "exit node"); err != nil {
		s.writeError(w, r, err)
		return
	}
	suggestion, err := s.deps.ExitNode.Suggest(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, suggestion)
}
