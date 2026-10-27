// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

// handleGetTraffic serves the rolling activity view: what has crossed recently, at what
// rate, and which machines and destinations it went to.
//
// It is a GET on the dashboard's fast poll because everything in it is already in memory
// -- the window is sampled on the agent's own tick, and the counters behind it are
// atomics. The one part that reaches the backend is the peer list, and that is shared
// with every other view through a short-lived cache rather than fetched again here.
func (s *Server) handleGetTraffic(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Traffic, "traffic"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Traffic.View(r.Context()))
}

// handleGetTrafficBreakdown serves one lane of the same window, split by what that lane
// names. It is a separate route per lane so a dashboard pays only for the split it is
// drawing: the series are most of the payload, and only one lane is ever on screen.
func (s *Server) handleGetTrafficBreakdown(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Traffic, "traffic"); err != nil {
		s.writeError(w, r, err)
		return
	}
	out, err := s.deps.Traffic.Breakdown(r.Context(), r.PathValue("lane"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}
