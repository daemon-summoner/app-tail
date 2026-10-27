// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/sellitus/app-tail/internal/config"
)

// SettingsSchemaView is the whole vocabulary a client needs to render a settings form:
// the fields, plus the sections and optional modules those fields reference by id.
// Serving the fields alone would leave a client naming a section it cannot label and a
// module it cannot offer a switch for.
type SettingsSchemaView struct {
	Fields  []config.FieldSchema `json:"fields"`
	Groups  []config.GroupInfo   `json:"groups"`
	Modules []config.ModuleInfo  `json:"modules"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Settings, "settings"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.deps.Settings.Get())
}

// handleGetSettingsSchema serves the registry's field metadata so a browser or a
// third-party client can render and drive settings without hardcoding the field list.
func (s *Server) handleGetSettingsSchema(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Settings, "settings"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, SettingsSchemaView{
		Fields:  s.deps.Settings.Schema(),
		Groups:  config.SettingsGroups(),
		Modules: config.FeatureModules(),
	})
}

// restart status keys merged into the settings response. RestartRequired stays for a
// client's coarse check, while nodeRestart, uiRelisten and appRestart let the dashboard
// offer an in-process restart for node-identity changes, a manual-restart note for a
// dashboard-address change, a restart-the-app offer for a setting the process reads
// only at start, and an elevated-restart offer for one that needs administrator rights.
// deferred names the settings stored but not yet handed to the node, so a client can
// say a save landed without claiming it took effect.
const (
	keyRestartRequired = "restartRequired"
	keyNodeRestart     = "nodeRestart"
	keyUIRelisten      = "uiRelisten"
	keyAppRestart      = "appRestart"
	keyAdminRestart    = "adminRestart"
	keyAdminRelaunch   = "adminRelaunch"
	keyDeferred        = "deferred"
)

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Settings, "settings"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var patch map[string]json.RawMessage
	if err := decodeJSON(r, &patch); err != nil {
		s.writeError(w, r, err)
		return
	}

	view, impact, err := s.deps.Settings.Update(r.Context(), patch)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	resp := make(map[string]any, len(view)+7)
	for k, v := range view {
		resp[k] = v
	}
	resp[keyRestartRequired] = impact.RestartNeeded()
	resp[keyNodeRestart] = impact.NodeRestart
	resp[keyUIRelisten] = impact.UIRelisten
	resp[keyAppRestart] = impact.AppRestart
	resp[keyAdminRestart] = impact.AdminRestart
	resp[keyAdminRelaunch] = impact.AdminRelaunch
	if len(impact.Deferred) > 0 {
		resp[keyDeferred] = impact.Deferred
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetAutostart(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Autostart, "autostart"); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeAutostart(w, r)
}

// autostartView is the login item's state: whether one is installed, and what is wrong
// with the one that is.
type autostartView struct {
	Enabled bool   `json:"enabled"`
	Problem string `json:"problem,omitempty"`
}

// writeAutostart reports what the system says, which is what both routes answer with.
func (s *Server) writeAutostart(w http.ResponseWriter, r *http.Request) {
	enabled, err := s.deps.Autostart.Enabled()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	view := autostartView{Enabled: enabled}
	if enabled {
		// Only meaningful about an item that exists: the check reports nothing wrong with
		// a machine that has no login item, and asking anyway costs a registry read.
		view.Problem = s.deps.Autostart.Problem()
	}
	s.writeJSON(w, http.StatusOK, view)
}

type autostartRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handleSetAutostart(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Autostart, "autostart"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var req autostartRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if req.Enabled == nil {
		s.writeError(w, r, badRequest("enabled is required"))
		return
	}
	if err := s.deps.Autostart.SetEnabled(*req.Enabled); err != nil {
		s.writeError(w, r, err)
		return
	}
	// Report what the system says, not what was asked for.
	s.writeAutostart(w, r)
}
