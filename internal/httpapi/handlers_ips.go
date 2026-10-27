// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"time"

	"github.com/sellitus/app-tail/internal/config"
)

func (s *Server) handleGetIPS(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.IPS.View())
}

// handleRefreshIPS downloads every enabled feed now. It answers with the view because what
// the caller wants to know is what the download produced.
func (s *Server) handleRefreshIPS(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.IPS.Refresh(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.IPS.View())
}

// handlePauseIPS stops inspection for a while. It answers with the view because what the
// caller wants to know is that inspection is now paused and until when.
func (s *Server) handlePauseIPS(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		Minutes int `json:"minutes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	if body.Minutes < 1 || body.Minutes > maxPauseMinutes {
		s.writeError(w, r, &config.ValidationError{
			Field:   "minutes",
			Message: "a pause lasts between 1 minute and 24 hours",
		})
		return
	}
	s.deps.IPS.Pause(time.Duration(body.Minutes) * time.Minute)
	s.writeJSON(w, http.StatusOK, s.deps.IPS.View())
}

func (s *Server) handleResumeIPS(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.deps.IPS.Resume()
	s.writeJSON(w, http.StatusOK, s.deps.IPS.View())
}

// handleRemoveInterceptRoot deletes the traffic-interception root's files. It answers with the
// view, because what the caller wants to know is that no root is left. Taking the root out of
// the machine's trust store is not done here: the agent cannot change what the machine trusts,
// so `app-tail ips remove-root` does that in the user's own terminal before calling this.
func (s *Server) handleRemoveInterceptRoot(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.IPS.RemoveInterceptRoot(); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.IPS.View())
}

// handlePresetIPS switches the shipped feeds to one rung of the curated ladder. It answers
// with the view, because what the caller wants to know is what is on now.
func (s *Server) handlePresetIPS(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		Preset string `json:"preset"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	if body.Preset == "" {
		s.writeError(w, r, &config.ValidationError{
			Field:   "preset",
			Message: "name a level to switch to",
		})
		return
	}
	if err := s.deps.IPS.ApplyPreset(r.Context(), body.Preset); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.IPS.View())
}

// handleCheckIPS answers what the rules say about one destination. It is the question the
// rule counts cannot answer: whether the entry someone typed reaches the thing they meant.
func (s *Server) handleCheckIPS(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	dest := r.URL.Query().Get("dest")
	if dest == "" {
		s.writeError(w, r, &config.ValidationError{
			Field:   "dest",
			Message: "name a domain or an address to check",
		})
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.IPS.Check(dest))
}

func (s *Server) handleCreateIPSFeed(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var f config.IPSFeed
	if err := decodeJSON(r, &f); err != nil {
		s.writeError(w, r, err)
		return
	}
	// BuiltIn is owned by the catalog: a client cannot mint a shipped feed, which is what
	// would otherwise make it undeletable.
	f.BuiltIn = false

	created, err := s.deps.IPS.CreateFeed(f)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateIPSFeed(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var f config.IPSFeed
	if err := decodeJSON(r, &f); err != nil {
		s.writeError(w, r, err)
		return
	}
	f.BuiltIn = false

	updated, err := s.deps.IPS.UpdateFeed(r.PathValue("id"), f)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteIPSFeed(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.IPS, "traffic inspection"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.IPS.DeleteFeed(r.Context(), r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}
