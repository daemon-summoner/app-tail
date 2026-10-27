// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

// handlePolicyPreview reports what the ACL bootstrap would change, writing nothing.
func (s *Server) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	s.runPolicy(w, r, false)
}

// handlePolicyApply performs the ACL bootstrap, writing the tagOwners (and grant)
// the fleet needs under optimistic concurrency.
func (s *Server) handlePolicyApply(w http.ResponseWriter, r *http.Request) {
	s.runPolicy(w, r, true)
}

func (s *Server) runPolicy(w http.ResponseWriter, r *http.Request, apply bool) {
	if err := require(s.deps.Policy, "policy setup"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var req PolicyBootstrapRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	var (
		view PolicyPlanView
		err  error
	)
	if apply {
		view, err = s.deps.Policy.Apply(r.Context(), req)
	} else {
		view, err = s.deps.Policy.Preview(r.Context(), req)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}
