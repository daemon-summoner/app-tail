// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

// handleGetInterface reports what this machine can do about the network-interface mode
// and what it is doing now.
//
// It reads the machine on every call rather than the state the node started with, because
// the state that matters is the one somebody just changed: a helper installed in a
// terminal has to show up here without restarting anything.
func (s *Server) handleGetInterface(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Interface, "network interface"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Interface.View(r.Context()))
}

// handleInterfaceSetup arranges for this machine to be able to carry the
// network-interface mode.
//
// It is the dashboard's half of the same thing `app-tail tun setup` does, and exists
// because the surface that reports the mode is not in force is the surface somebody is
// looking at when they want it fixed -- sending them to a terminal to run one command is
// the step this removes.
func (s *Server) handleInterfaceSetup(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Interface, "network-interface setup"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Interface.SetUpInterface(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	// The node still has to be rebuilt to use it, and the client that asked for this is
	// the one that knows whether to. Saying so here is what stops a dashboard reporting
	// success beside a card that still says the mode is not in force.
	s.writeJSON(w, http.StatusOK, map[string]bool{"restartNeeded": true})
}

// handleApprove asks an administrator to approve the changes this machine refused, and
// answers with what is still waiting once the refused features have been tried again.
//
// It takes no body. What is approved is the agent's own list of refusals, so a caller can
// only ask for the prompt, never put a change of its own in front of the administrator.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Approvals, "approving network changes"); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Approvals.Approve(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}
