// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"
	"strings"
)

// signRequest authorizes one device for a locked tailnet. Both keys are the text that
// device reports; the rotation key is optional and is what lets it re-sign itself after a
// key rotation without an administrator present.
type signRequest struct {
	NodeKey     string `json:"nodeKey"`
	RotationKey string `json:"rotationKey"`
}

// disableLocalRequest is the typed confirmation forgetting local lock state requires.
//
// It is not a modal in a client: a client is free to skip its own dialog, and the word
// travelling over the wire is what makes the intent unambiguous at the only layer that
// cannot be bypassed.
type disableLocalRequest struct {
	Confirm string `json:"confirm"`
}

// disableLocalWord is what a caller must send to forget this device's lock state.
const disableLocalWord = "forget"

func (s *Server) handleGetLock(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Lock, "tailnet lock"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Lock.View(r.Context()))
}

// handleGetLockLog reads the tailnet's key authority log, which is the only record of
// who changed lock and when. It is its own call rather than part of the view because it
// is read when someone opens it, not on every dashboard poll.
func (s *Server) handleGetLockLog(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Lock, "tailnet lock"); err != nil {
		s.writeError(w, r, err)
		return
	}
	entries, err := s.deps.Lock.Log(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if entries == nil {
		// The dashboard iterates the reply unconditionally, so an empty log has to be
		// `[]` rather than `null`.
		entries = []LockUpdate{}
	}
	s.writeJSON(w, http.StatusOK, entries)
}

// handleLockSign authorizes another device for a locked tailnet.
func (s *Server) handleLockSign(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Lock, "tailnet lock"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var req signRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	req.NodeKey = strings.TrimSpace(req.NodeKey)
	req.RotationKey = strings.TrimSpace(req.RotationKey)
	if req.NodeKey == "" {
		s.writeError(w, r, badRequest("nodeKey is required: it is the nodekey:... text the "+
			"device being authorized reports"))
		return
	}
	if err := s.deps.Lock.Sign(r.Context(), req.NodeKey, req.RotationKey); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Lock.View(r.Context()))
}

// handleLockDisableLocal forgets this device's copy of the tailnet lock state.
//
// It affects this device alone: the tailnet's lock stays on, every other device is
// untouched, and this one rebuilds its copy from the control plane. It is offered because
// the alternative for a device whose copy has diverged is deleting the state directory,
// which also throws away its identity on the tailnet.
func (s *Server) handleLockDisableLocal(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Lock, "tailnet lock"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var req disableLocalRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if req.Confirm != disableLocalWord {
		s.writeError(w, r, badRequest("send {%q:%q} to forget this device's copy of the tailnet "+
			"lock state. Your tailnet's lock stays on and no other device is affected; this "+
			"device rebuilds its copy from the control plane.", "confirm", disableLocalWord))
		return
	}
	if err := s.deps.Lock.DisableLocal(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Lock.View(r.Context()))
}
