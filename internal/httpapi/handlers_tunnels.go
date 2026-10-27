// SPDX-License-Identifier: MIT

package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/sellitus/app-tail/internal/config"
	"github.com/sellitus/app-tail/internal/tsnode"
)

// TunnelSchemaView is the whole vocabulary a client needs to render a connection form and
// offer a new one: the fields, the sections those fields reference by id, and the kinds of
// network a connection can be added as. Serving the fields alone would leave a client
// naming a section it cannot label and inventing its own list of protocols.
type TunnelSchemaView struct {
	Fields []config.FieldSchema `json:"fields"`
	Groups []config.GroupInfo   `json:"groups"`
	// Modules are the switches these fields are gated on. They are the installation's
	// rather than the connection's, so a client holding only this schema would have no way
	// to tell that a field is hidden because a switch is off -- and no way to show it the
	// moment that switch is turned on, which is when someone is looking for it.
	Modules []config.ModuleInfo `json:"modules"`
	Types   []TunnelTypeInfo    `json:"types"`
}

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	list := s.deps.Tunnels.List()
	if list == nil {
		list = []TunnelView{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"tunnels": list})
}

func (s *Server) handleGetTunnel(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Tunnels.Get(r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

// handleListTunnelPeers serves the devices on one connection, which is what a form
// targeting something inside it offers. It is answered per connection because a device id
// only means anything on the network that issued it.
func (s *Server) handleListTunnelPeers(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	peers, err := s.deps.Tunnels.Peers(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if peers == nil {
		peers = []tsnode.Peer{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
}

// handleGetTunnelSchema serves the connection form's field metadata so a client renders
// and drives a connection without hardcoding the field list, exactly as it does for
// settings.
func (s *Server) handleGetTunnelSchema(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	fields := s.deps.Tunnels.Schema()
	types := s.deps.Tunnels.Types()
	if types == nil {
		types = []TunnelTypeInfo{}
	}
	s.writeJSON(w, http.StatusOK, TunnelSchemaView{
		Fields:  fields,
		Groups:  config.GroupsFor(fields),
		Modules: config.ModulesFor(fields),
		Types:   types,
	})
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var spec TunnelSpec
	if err := decodeJSON(r, &spec); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Tunnels.Create(r.Context(), spec)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, view)
}

func (s *Server) handleUpdateTunnel(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var patch map[string]json.RawMessage
	if err := decodeJSON(r, &patch); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Tunnels.Update(r.Context(), r.PathValue("id"), patch)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

// handleImportTunnel takes the configuration file a server issued and writes it onto one
// connection. It replaces that connection's settings rather than merging: a configuration
// file describes a whole connection, and merging it with what was there before would leave
// a resolver or a carried network from a previous server still in place.
func (s *Server) handleImportTunnel(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	var body TunnelImport
	if err := decodeJSON(r, &body); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Tunnels.Import(r.Context(), r.PathValue("id"), body.File)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

// handleRetryTunnel builds one connection again now. It is a POST rather than a PUT because
// it changes nothing about the connection: it asks for work, and asking twice asks twice.
func (s *Server) handleRetryTunnel(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	view, err := s.deps.Tunnels.Retry(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	if err := require(s.deps.Tunnels, "connections"); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.deps.Tunnels.Delete(r.Context(), r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}
