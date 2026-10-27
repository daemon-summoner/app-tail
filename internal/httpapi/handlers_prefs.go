// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

// handleGetPrefs reports the settings this app keeps on the tailnet node itself,
// beside what the node says they are. That comparison is the whole point of the route:
// these are the only settings whose value lives somewhere this app does not control,
// so a save that stored fine and never reached the tailnet is otherwise invisible.
func (s *Server) handleGetPrefs(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Prefs, "node preferences"); err != nil {
		s.writeError(w, r, err)
		return
	}
	view := s.deps.Prefs.View()
	// A configuration where no pref-backed setting is available leaves Fields nil, which
	// marshals to null. The field is documented as an array and the dashboard reads its
	// length, so the empty case is sent as [].
	if view.Fields == nil {
		view.Fields = []PrefFieldView{}
	}
	s.writeJSON(w, http.StatusOK, view)
}
