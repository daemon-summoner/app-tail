// SPDX-License-Identifier: MIT

package httpapi

import (
	"net/http"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Node, "tailnet node"); err != nil {
		s.writeError(w, r, err)
		return
	}
	st := s.deps.Node.Status()
	// Optional, like every other dependency the server holds: a build that wires no
	// dashboard reporter answers the status without this field rather than failing.
	var moved *DashboardMovedView
	if s.deps.Dashboard != nil {
		moved = s.deps.Dashboard.Moved()
	}
	var approvals *ApprovalsView
	if s.deps.Approvals != nil {
		approvals = s.deps.Approvals.Pending()
	}
	s.writeJSON(w, http.StatusOK, StatusView{
		TunnelID:     config.PrimaryTunnelID,
		BackendState: st.BackendState,
		Running:      st.Running(),
		AuthPending:  st.AuthURL != "",
		Hostname:     st.Hostname,
		DNSName:      st.DNSName,
		TailscaleIPs: st.TailscaleIPs,
		LoginName:    st.LoginName,
		Tags:         st.Tags,
		AuthMode:     string(st.AuthMode),
		Problem:      st.Problem,
		Version:      s.deps.Version,

		Network:         string(st.Network),
		NetworkFallback: st.NetworkFallback,

		ConfigQuarantine: s.deps.ConfigQuarantine,
		DashboardMoved:   moved,
		Approvals:        approvals,
	})
}

// handleLogin always re-invokes interactive login rather than replaying a cached
// URL: a stale auth URL sends the user to a dead page.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Node, "tailnet node"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Node.StartLogin(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	st := s.deps.Node.Status()
	s.writeJSON(w, http.StatusOK, map[string]string{
		"authURL":      st.AuthURL,
		"backendState": st.BackendState,
	})
}

// handleLoginURL hands over the login already in progress, without starting another.
//
// It is a POST because of what it returns rather than what it changes: the URL enrolls this
// machine on a tailnet, and the same-origin guard applies to state-changing methods only. A
// page the user did not open therefore cannot read it, while the dashboard -- which reloads
// while a login is pending and has to draw the code again -- can.
func (s *Server) handleLoginURL(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Node, "tailnet node"); err != nil {
		s.writeError(w, r, err)
		return
	}
	st := s.deps.Node.Status()
	s.writeJSON(w, http.StatusOK, map[string]string{
		"authURL":      st.AuthURL,
		"backendState": st.BackendState,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Node, "tailnet node"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Node.Logout(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{
		"backendState": s.deps.Node.Status().BackendState,
	})
}

// handleRestart rebuilds the tailnet node in place so node-identity settings take
// effect without restarting the process. The dashboard listener serving this request
// is deliberately left alone; a dashboard-address change still needs a full restart.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Restart, "node restart"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Restart.RestartNode(r.Context()); err != nil {
		s.writeError(w, r, err)
		return
	}
	backendState := ""
	if s.deps.Node != nil {
		backendState = s.deps.Node.Status().BackendState
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"backendState": backendState})
}

// handleRestartApp stops the whole process and starts it again. Unlike the node restart
// above, the listener serving this request goes away with everything else, so the answer
// is sent before any of that begins: 202, not 200, because nothing here has happened yet.
func (s *Server) handleRestartApp(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Lifecycle, "process restart"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Lifecycle.RestartProcess(); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusAccepted, map[string]bool{"restarting": true})
}

// handleQuit stops the whole process without starting a replacement. The caller is a second
// copy of app-tail taking this one's place, and it waits for the process to go rather than
// for this reply, so the answer is 202 for the same reason the restart above is: the
// shutdown has not happened yet, and the listener answering will be part of it.
func (s *Server) handleQuit(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Lifecycle, "process shutdown"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Lifecycle.StopProcess(); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusAccepted, map[string]bool{"stopping": true})
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Node, "tailnet node"); err != nil {
		s.writeError(w, r, err)
		return
	}
	peers, err := s.deps.Node.Peers(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if peers == nil {
		peers = []tsnode.Peer{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
}

// handleHealthz is the readiness probe: 200 only when the node is up and every
// enabled forward is actually listening. The body always names the reason so an
// operator watching a 503 knows which half is wrong.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	type health struct {
		Status       string `json:"status"`
		BackendState string `json:"backendState,omitempty"`
		Reason       string `json:"reason,omitempty"`
	}

	if s.deps.Node == nil || s.deps.Forwards == nil {
		s.writeJSON(w, http.StatusServiceUnavailable, health{
			Status: "unhealthy",
			Reason: "agent is still starting up",
		})
		return
	}

	st := s.deps.Node.Status()
	switch {
	case !st.Running():
		reason := "tailnet node is not running"
		if st.Problem != "" {
			reason = st.Problem
		}
		s.writeJSON(w, http.StatusServiceUnavailable, health{
			Status:       "unhealthy",
			BackendState: st.BackendState,
			Reason:       reason,
		})
	case !s.deps.Forwards.AllRunning():
		s.writeJSON(w, http.StatusServiceUnavailable, health{
			Status:       "unhealthy",
			BackendState: st.BackendState,
			Reason:       "one or more enabled forwards are not listening",
		})
	default:
		s.writeJSON(w, http.StatusOK, health{Status: "ok", BackendState: st.BackendState})
	}
}
